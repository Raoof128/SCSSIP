"""
osquery adapter for endpoint visibility.
Collects security telemetry from osquery agents.
"""

from typing import AsyncIterator, Dict, Any, Optional
from datetime import datetime
import asyncio
import json
from loguru import logger

from .base_adapter import BaseAdapter, SecurityEvent, EventType


class OsqueryAdapter(BaseAdapter):
    """Adapter for osquery endpoint telemetry."""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize osquery adapter.

        Args:
            config: Configuration dictionary with:
                - tls_hostname: osquery TLS server hostname
                - enroll_secret: Enrollment secret for osquery agents
                - results_path: Path to osquery result logs
        """
        super().__init__("osquery", config)
        self.tls_hostname = config.get('tls_hostname', 'localhost')
        self.enroll_secret = config.get('enroll_secret')
        self.results_path = config.get('results_path', '/var/log/osquery/osqueryd.results.log')

    async def connect(self) -> bool:
        """Verify osquery results path exists."""
        try:
            # In production, this would connect to osquery TLS server
            # For now, we check if results log file exists
            import os
            if not os.path.exists(self.results_path):
                logger.warning(f"osquery results file not found: {self.results_path}")
                # Still mark as connected for testing

            self.is_connected = True
            logger.info(f"Connected to osquery results at {self.results_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to connect to osquery: {e}")
            self.is_connected = False
            return False

    async def disconnect(self) -> None:
        """Disconnect from osquery."""
        self.is_connected = False
        logger.info("Disconnected from osquery")

    async def fetch_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        query: Optional[str] = None,
        limit: Optional[int] = None
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Fetch events from osquery results.

        Args:
            start_time: Start time for filtering
            end_time: End time for filtering
            query: Query name filter
            limit: Maximum events to retrieve

        Yields:
            Raw osquery result entries
        """
        if not self.is_connected:
            await self.connect()

        event_count = 0

        try:
            # Read osquery results log
            import os
            if not os.path.exists(self.results_path):
                logger.warning(f"osquery results file not found: {self.results_path}")
                return

            with open(self.results_path, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line)

                        # Filter by query name if specified
                        if query and event.get('name') != query:
                            continue

                        # Filter by time range if specified
                        if start_time or end_time:
                            event_time = datetime.fromtimestamp(event.get('unixTime', 0))
                            if start_time and event_time < start_time:
                                continue
                            if end_time and event_time > end_time:
                                continue

                        yield event
                        event_count += 1

                        if limit and event_count >= limit:
                            return

                    except json.JSONDecodeError:
                        continue

                    # Yield control to event loop
                    await asyncio.sleep(0)

        except Exception as e:
            logger.error(f"Error reading osquery results: {e}")
            raise

    def normalize_event(self, raw_event: Dict[str, Any]) -> SecurityEvent:
        """
        Normalize osquery event to SecurityEvent format.

        Args:
            raw_event: Raw osquery result entry

        Returns:
            Normalized SecurityEvent
        """
        # Parse timestamp
        unix_time = raw_event.get('unixTime', 0)
        timestamp = datetime.fromtimestamp(unix_time)

        # Determine event type based on query name
        query_name = raw_event.get('name', '')
        event_type = self._determine_event_type(query_name)

        # Extract host information
        host_identifier = raw_event.get('hostIdentifier', '')

        # Parse columns (osquery data)
        columns = raw_event.get('columns', {})

        return SecurityEvent(
            timestamp=timestamp,
            event_type=event_type,
            source_system='osquery',
            raw_data=raw_event,
            host_name=host_identifier,
            user_name=columns.get('username', columns.get('user')),
            process_name=columns.get('name', columns.get('process_name')),
            process_path=columns.get('path', columns.get('process_path')),
            command_line=columns.get('cmdline'),
            parent_process=columns.get('parent'),
            file_path=columns.get('target_path', columns.get('path')),
            file_hash=columns.get('sha256', columns.get('md5')),
            source_ip=columns.get('local_address', columns.get('local_ip')),
            dest_ip=columns.get('remote_address', columns.get('remote_ip')),
            source_port=self._safe_int(columns.get('local_port')),
            dest_port=self._safe_int(columns.get('remote_port')),
            protocol=columns.get('protocol'),
            tags=[query_name]
        )

    def _determine_event_type(self, query_name: str) -> EventType:
        """Determine event type from osquery query name."""
        query_name_lower = query_name.lower()

        if any(x in query_name_lower for x in ['process', 'proc']):
            return EventType.PROCESS
        elif any(x in query_name_lower for x in ['file', 'fim']):
            return EventType.FILE_ACCESS
        elif any(x in query_name_lower for x in ['network', 'socket', 'connection']):
            return EventType.NETWORK
        elif any(x in query_name_lower for x in ['user', 'login', 'auth']):
            return EventType.AUTHENTICATION
        elif 'registry' in query_name_lower:
            return EventType.REGISTRY
        else:
            return EventType.OTHER

    def _safe_int(self, value: Any) -> Optional[int]:
        """Safely convert value to integer."""
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
