"""
Splunk data source adapter.
Connects to Splunk via REST API and retrieves security events.
"""

import asyncio
from typing import AsyncIterator, Dict, Any, Optional
from datetime import datetime
import requests
from urllib.parse import urljoin
from loguru import logger

from .base_adapter import BaseAdapter, SecurityEvent, EventType


class SplunkAdapter(BaseAdapter):
    """Adapter for Splunk SIEM."""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Splunk adapter.

        Args:
            config: Configuration dictionary with:
                - url: Splunk instance URL
                - token: Splunk API token
                - indexes: List of indexes to query
                - verify_ssl: SSL verification (default: True)
        """
        super().__init__("splunk", config)
        self.base_url = config.get('url', 'https://localhost:8089')
        self.token = config.get('token')
        self.indexes = config.get('indexes', ['main'])
        self.verify_ssl = config.get('verify_ssl', True)
        self.session = None

    async def connect(self) -> bool:
        """Establish connection to Splunk."""
        try:
            self.session = requests.Session()
            self.session.headers.update({
                'Authorization': f'Bearer {self.token}',
                'Content-Type': 'application/json'
            })

            # Test connection
            response = self.session.get(
                urljoin(self.base_url, '/services/server/info'),
                verify=self.verify_ssl,
                timeout=10
            )
            response.raise_for_status()

            self.is_connected = True
            logger.info(f"Connected to Splunk at {self.base_url}")
            return True

        except Exception as e:
            logger.error(f"Failed to connect to Splunk: {e}")
            self.is_connected = False
            return False

    async def disconnect(self) -> None:
        """Close Splunk connection."""
        if self.session:
            self.session.close()
            self.session = None
        self.is_connected = False
        logger.info("Disconnected from Splunk")

    async def fetch_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        query: Optional[str] = None,
        limit: Optional[int] = 1000
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Fetch events from Splunk.

        Args:
            start_time: Start time for search
            end_time: End time for search
            query: SPL (Search Processing Language) query
            limit: Maximum events to retrieve

        Yields:
            Raw Splunk events
        """
        if not self.is_connected:
            await self.connect()

        # Build SPL query
        if query is None:
            index_clause = " OR ".join([f'index="{idx}"' for idx in self.indexes])
            query = f"search {index_clause}"

        # Add time range
        if start_time:
            query += f' earliest="{start_time.isoformat()}"'
        if end_time:
            query += f' latest="{end_time.isoformat()}"'

        # Execute search
        try:
            search_url = urljoin(self.base_url, '/services/search/jobs')

            # Create search job
            job_response = self.session.post(
                search_url,
                data={'search': query, 'output_mode': 'json'},
                verify=self.verify_ssl
            )
            job_response.raise_for_status()
            job_data = job_response.json()
            sid = job_data.get('sid')

            logger.debug(f"Created Splunk search job: {sid}")

            # Poll for completion
            job_status_url = urljoin(self.base_url, f'/services/search/jobs/{sid}')
            while True:
                status_response = self.session.get(
                    job_status_url,
                    params={'output_mode': 'json'},
                    verify=self.verify_ssl
                )
                status_response.raise_for_status()
                status = status_response.json()

                if status['entry'][0]['content']['isDone']:
                    break

                await asyncio.sleep(1)

            # Retrieve results
            results_url = urljoin(self.base_url, f'/services/search/jobs/{sid}/results')
            results_response = self.session.get(
                results_url,
                params={'output_mode': 'json', 'count': limit or 10000},
                verify=self.verify_ssl
            )
            results_response.raise_for_status()
            results = results_response.json()

            # Yield events
            for event in results.get('results', []):
                yield event

        except Exception as e:
            logger.error(f"Failed to fetch events from Splunk: {e}")
            raise

    def normalize_event(self, raw_event: Dict[str, Any]) -> SecurityEvent:
        """
        Normalize Splunk event to SecurityEvent format.

        Args:
            raw_event: Raw Splunk event

        Returns:
            Normalized SecurityEvent
        """
        # Determine event type based on sourcetype or fields
        sourcetype = raw_event.get('sourcetype', '').lower()
        event_type = self._determine_event_type(sourcetype, raw_event)

        # Parse timestamp
        timestamp = datetime.fromisoformat(raw_event.get('_time', datetime.utcnow().isoformat()))

        # Extract common fields with various field name patterns
        return SecurityEvent(
            timestamp=timestamp,
            event_type=event_type,
            source_system='splunk',
            raw_data=raw_event,
            source_ip=self._extract_field(raw_event, ['src_ip', 'src', 'source_ip', 'clientip']),
            dest_ip=self._extract_field(raw_event, ['dest_ip', 'dest', 'destination_ip', 'dst']),
            source_port=self._extract_int(raw_event, ['src_port', 'sport']),
            dest_port=self._extract_int(raw_event, ['dest_port', 'dport', 'port']),
            protocol=self._extract_field(raw_event, ['protocol', 'proto']),
            user_name=self._extract_field(raw_event, ['user', 'username', 'User', 'UserName']),
            host_name=self._extract_field(raw_event, ['host', 'hostname', 'Computer', 'ComputerName']),
            process_name=self._extract_field(raw_event, ['process', 'process_name', 'ProcessName']),
            process_path=self._extract_field(raw_event, ['process_path', 'Image']),
            file_path=self._extract_field(raw_event, ['file_path', 'TargetFilename', 'FilePath']),
            command_line=self._extract_field(raw_event, ['command_line', 'CommandLine']),
            domain=self._extract_field(raw_event, ['domain', 'query']),
            url=self._extract_field(raw_event, ['url', 'uri']),
            event_id=self._extract_field(raw_event, ['event_id', 'EventID', 'EventCode']),
            severity=self._extract_field(raw_event, ['severity', 'Level']),
            tags=[sourcetype] if sourcetype else []
        )

    def _determine_event_type(self, sourcetype: str, event: Dict[str, Any]) -> EventType:
        """Determine event type from sourcetype and fields."""
        if any(x in sourcetype for x in ['windows:security', 'linux:auth', 'authentication', 'login']):
            return EventType.AUTHENTICATION
        elif any(x in sourcetype for x in ['firewall', 'network', 'connection', 'flow']):
            return EventType.NETWORK
        elif any(x in sourcetype for x in ['file', 'fim']):
            return EventType.FILE_ACCESS
        elif any(x in sourcetype for x in ['process', 'sysmon', 'edr']):
            return EventType.PROCESS
        elif 'dns' in sourcetype:
            return EventType.DNS
        elif any(x in sourcetype for x in ['http', 'web', 'proxy']):
            return EventType.HTTP
        else:
            return EventType.OTHER

    def _extract_field(self, event: Dict[str, Any], field_names: list) -> Optional[str]:
        """Extract first matching field from event."""
        for field in field_names:
            if field in event and event[field]:
                return str(event[field])
        return None

    def _extract_int(self, event: Dict[str, Any], field_names: list) -> Optional[int]:
        """Extract first matching integer field from event."""
        for field in field_names:
            if field in event:
                try:
                    return int(event[field])
                except (ValueError, TypeError):
                    continue
        return None
