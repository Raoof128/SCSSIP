"""
Elasticsearch/Elastic Stack adapter.
Connects to Elasticsearch and retrieves security events.
"""

from typing import AsyncIterator, Dict, Any, Optional
from datetime import datetime
from elasticsearch import AsyncElasticsearch
from elasticsearch.helpers import async_scan
from loguru import logger

from .base_adapter import BaseAdapter, SecurityEvent, EventType


class ElasticAdapter(BaseAdapter):
    """Adapter for Elasticsearch/Elastic Security."""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Elasticsearch adapter.

        Args:
            config: Configuration dictionary with:
                - hosts: List of Elasticsearch hosts
                - api_key: API key for authentication
                - indices: List of index patterns to query
                - verify_ssl: SSL verification (default: True)
        """
        super().__init__("elastic", config)
        self.hosts = config.get('hosts', ['https://localhost:9200'])
        self.api_key = config.get('api_key')
        self.indices = config.get('indices', ['logs-*', 'security-*'])
        self.verify_ssl = config.get('verify_ssl', True)
        self.client = None

    async def connect(self) -> bool:
        """Establish connection to Elasticsearch."""
        try:
            self.client = AsyncElasticsearch(
                self.hosts,
                api_key=self.api_key,
                verify_certs=self.verify_ssl
            )

            # Test connection
            info = await self.client.info()
            self.is_connected = True
            logger.info(f"Connected to Elasticsearch cluster: {info['cluster_name']}")
            return True

        except Exception as e:
            logger.error(f"Failed to connect to Elasticsearch: {e}")
            self.is_connected = False
            return False

    async def disconnect(self) -> None:
        """Close Elasticsearch connection."""
        if self.client:
            await self.client.close()
            self.client = None
        self.is_connected = False
        logger.info("Disconnected from Elasticsearch")

    async def fetch_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        query: Optional[str] = None,
        limit: Optional[int] = 1000
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Fetch events from Elasticsearch.

        Args:
            start_time: Start time for search
            end_time: End time for search
            query: Elasticsearch Query DSL (JSON string or dict)
            limit: Maximum events to retrieve

        Yields:
            Raw Elasticsearch documents
        """
        if not self.is_connected:
            await self.connect()

        # Build query
        if query is None:
            query_body = {"match_all": {}}
        elif isinstance(query, str):
            query_body = {"query_string": {"query": query}}
        else:
            query_body = query

        # Add time range filter
        if start_time or end_time:
            time_range = {}
            if start_time:
                time_range['gte'] = start_time.isoformat()
            if end_time:
                time_range['lte'] = end_time.isoformat()

            full_query = {
                "bool": {
                    "must": [query_body],
                    "filter": [
                        {"range": {"@timestamp": time_range}}
                    ]
                }
            }
        else:
            full_query = query_body

        # Execute search
        try:
            search_body = {
                "query": full_query,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }

            if limit and limit <= 10000:
                # Use regular search for small result sets
                response = await self.client.search(
                    index=','.join(self.indices),
                    body=search_body,
                    size=limit
                )

                for hit in response['hits']['hits']:
                    yield hit['_source']
            else:
                # Use scroll API for large result sets
                count = 0
                async for doc in async_scan(
                    self.client,
                    index=','.join(self.indices),
                    query=search_body
                ):
                    yield doc['_source']
                    count += 1
                    if limit and count >= limit:
                        break

        except Exception as e:
            logger.error(f"Failed to fetch events from Elasticsearch: {e}")
            raise

    def normalize_event(self, raw_event: Dict[str, Any]) -> SecurityEvent:
        """
        Normalize Elasticsearch event to SecurityEvent format.

        Args:
            raw_event: Raw Elasticsearch document

        Returns:
            Normalized SecurityEvent
        """
        # Parse timestamp
        timestamp_str = raw_event.get('@timestamp', raw_event.get('timestamp', datetime.utcnow().isoformat()))
        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))

        # Determine event type from event.category or event.type (ECS)
        event_category = raw_event.get('event', {}).get('category', '')
        event_type = self._determine_event_type(event_category, raw_event)

        # Extract fields using ECS (Elastic Common Schema) field names
        return SecurityEvent(
            timestamp=timestamp,
            event_type=event_type,
            source_system='elastic',
            raw_data=raw_event,
            source_ip=self._get_nested(raw_event, ['source.ip', 'client.ip', 'src_ip']),
            dest_ip=self._get_nested(raw_event, ['destination.ip', 'server.ip', 'dest_ip']),
            source_port=self._get_nested_int(raw_event, ['source.port', 'client.port']),
            dest_port=self._get_nested_int(raw_event, ['destination.port', 'server.port']),
            protocol=self._get_nested(raw_event, ['network.protocol', 'protocol']),
            user_name=self._get_nested(raw_event, ['user.name', 'user.id', 'username']),
            host_name=self._get_nested(raw_event, ['host.name', 'host.hostname', 'hostname']),
            process_name=self._get_nested(raw_event, ['process.name', 'process.executable']),
            process_path=self._get_nested(raw_event, ['process.executable', 'process.path']),
            file_path=self._get_nested(raw_event, ['file.path', 'file.name']),
            file_hash=self._get_nested(raw_event, ['file.hash.sha256', 'file.hash.md5']),
            command_line=self._get_nested(raw_event, ['process.command_line', 'process.args']),
            parent_process=self._get_nested(raw_event, ['process.parent.name', 'process.parent.executable']),
            domain=self._get_nested(raw_event, ['dns.question.name', 'url.domain']),
            url=self._get_nested(raw_event, ['url.full', 'url.original']),
            status_code=self._get_nested_int(raw_event, ['http.response.status_code', 'status_code']),
            bytes_sent=self._get_nested_int(raw_event, ['source.bytes', 'bytes_sent']),
            bytes_received=self._get_nested_int(raw_event, ['destination.bytes', 'bytes_received']),
            action=self._get_nested(raw_event, ['event.action', 'action']),
            result=self._get_nested(raw_event, ['event.outcome', 'result']),
            event_id=self._get_nested(raw_event, ['event.id', 'event.code']),
            severity=self._get_nested(raw_event, ['event.severity', 'log.level']),
            tags=raw_event.get('tags', [])
        )

    def _determine_event_type(self, category: str, event: Dict[str, Any]) -> EventType:
        """Determine event type from ECS category."""
        if category in ['authentication', 'iam']:
            return EventType.AUTHENTICATION
        elif category == 'network':
            return EventType.NETWORK
        elif category == 'file':
            return EventType.FILE_ACCESS
        elif category == 'process':
            return EventType.PROCESS
        elif 'dns' in str(event.get('event', {}).get('type', '')):
            return EventType.DNS
        elif category in ['web', 'http']:
            return EventType.HTTP
        else:
            return EventType.OTHER

    def _get_nested(self, data: Dict[str, Any], paths: list) -> Optional[str]:
        """Get value from nested dictionary using dot notation paths."""
        for path in paths:
            value = data
            for key in path.split('.'):
                if isinstance(value, dict) and key in value:
                    value = value[key]
                else:
                    break
            else:
                if value is not None:
                    return str(value)
        return None

    def _get_nested_int(self, data: Dict[str, Any], paths: list) -> Optional[int]:
        """Get integer value from nested dictionary."""
        value_str = self._get_nested(data, paths)
        if value_str:
            try:
                return int(value_str)
            except ValueError:
                pass
        return None
