"""
Zeek (formerly Bro) network security monitor adapter.
Reads Zeek log files and converts them to security events.
"""

import os
import asyncio
import json
from typing import AsyncIterator, Dict, Any, Optional
from datetime import datetime
from pathlib import Path
from loguru import logger

from .base_adapter import BaseAdapter, SecurityEvent, EventType


class ZeekAdapter(BaseAdapter):
    """Adapter for Zeek network security monitoring logs."""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Zeek adapter.

        Args:
            config: Configuration dictionary with:
                - log_path: Path to Zeek log directory
                - file_patterns: List of log file patterns to read
                - json_format: Whether logs are in JSON format (default: True)
        """
        super().__init__("zeek", config)
        self.log_path = Path(config.get('log_path', '/var/log/zeek'))
        self.file_patterns = config.get('file_patterns', [
            'conn.log', 'dns.log', 'http.log', 'ssl.log', 'files.log'
        ])
        self.json_format = config.get('json_format', True)

    async def connect(self) -> bool:
        """Verify Zeek log path exists."""
        try:
            if not self.log_path.exists():
                logger.error(f"Zeek log path does not exist: {self.log_path}")
                return False

            if not self.log_path.is_dir():
                logger.error(f"Zeek log path is not a directory: {self.log_path}")
                return False

            self.is_connected = True
            logger.info(f"Connected to Zeek logs at {self.log_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to connect to Zeek logs: {e}")
            self.is_connected = False
            return False

    async def disconnect(self) -> None:
        """No-op for file-based adapter."""
        self.is_connected = False
        logger.info("Disconnected from Zeek logs")

    async def fetch_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        query: Optional[str] = None,
        limit: Optional[int] = None
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Fetch events from Zeek log files.

        Args:
            start_time: Start time for filtering
            end_time: End time for filtering
            query: Log file pattern to read (overrides default patterns)
            limit: Maximum events to retrieve

        Yields:
            Raw Zeek log entries
        """
        if not self.is_connected:
            await self.connect()

        # Determine which log files to read
        if query:
            log_files = list(self.log_path.glob(query))
        else:
            log_files = []
            for pattern in self.file_patterns:
                log_files.extend(self.log_path.glob(pattern))

        event_count = 0

        for log_file in log_files:
            try:
                logger.debug(f"Reading Zeek log file: {log_file}")

                with open(log_file, 'r') as f:
                    for line in f:
                        # Skip comment lines
                        if line.startswith('#'):
                            continue

                        try:
                            if self.json_format:
                                event = json.loads(line)
                            else:
                                # Parse TSV format (tab-separated)
                                event = self._parse_tsv_line(line, log_file.stem)

                            # Filter by time range if specified
                            if start_time or end_time:
                                event_time = datetime.fromtimestamp(float(event.get('ts', 0)))
                                if start_time and event_time < start_time:
                                    continue
                                if end_time and event_time > end_time:
                                    continue

                            yield event
                            event_count += 1

                            if limit and event_count >= limit:
                                return

                        except (json.JSONDecodeError, ValueError) as e:
                            logger.debug(f"Failed to parse line: {e}")
                            continue

            except Exception as e:
                logger.error(f"Error reading Zeek log file {log_file}: {e}")
                continue

            # Yield control to event loop
            await asyncio.sleep(0)

    def normalize_event(self, raw_event: Dict[str, Any]) -> SecurityEvent:
        """
        Normalize Zeek event to SecurityEvent format.

        Args:
            raw_event: Raw Zeek log entry

        Returns:
            Normalized SecurityEvent
        """
        # Parse timestamp (Zeek uses epoch time)
        ts = float(raw_event.get('ts', 0))
        timestamp = datetime.fromtimestamp(ts)

        # Determine log type and event type
        log_type = raw_event.get('_path', 'unknown')
        event_type = self._determine_event_type(log_type)

        # Extract common Zeek fields
        return SecurityEvent(
            timestamp=timestamp,
            event_type=event_type,
            source_system='zeek',
            raw_data=raw_event,
            source_ip=raw_event.get('id.orig_h'),
            dest_ip=raw_event.get('id.resp_h'),
            source_port=self._safe_int(raw_event.get('id.orig_p')),
            dest_port=self._safe_int(raw_event.get('id.resp_p')),
            protocol=raw_event.get('proto', raw_event.get('service')),
            domain=raw_event.get('query', raw_event.get('host')),
            url=self._build_url(raw_event),
            bytes_sent=self._safe_int(raw_event.get('orig_bytes')),
            bytes_received=self._safe_int(raw_event.get('resp_bytes')),
            status_code=self._safe_int(raw_event.get('status_code')),
            file_path=raw_event.get('filename'),
            file_hash=raw_event.get('md5', raw_event.get('sha1', raw_event.get('sha256'))),
            tags=[log_type]
        )

    def _determine_event_type(self, log_type: str) -> EventType:
        """Determine event type from Zeek log type."""
        log_type_map = {
            'conn': EventType.NETWORK,
            'dns': EventType.DNS,
            'http': EventType.HTTP,
            'ssl': EventType.NETWORK,
            'files': EventType.FILE_ACCESS,
            'weird': EventType.OTHER,
            'notice': EventType.OTHER,
        }
        return log_type_map.get(log_type, EventType.OTHER)

    def _build_url(self, event: Dict[str, Any]) -> Optional[str]:
        """Build URL from HTTP log fields."""
        if 'host' in event and 'uri' in event:
            return f"http://{event['host']}{event['uri']}"
        return None

    def _safe_int(self, value: Any) -> Optional[int]:
        """Safely convert value to integer."""
        if value is None or value == '-':
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None

    def _parse_tsv_line(self, line: str, log_type: str) -> Dict[str, Any]:
        """
        Parse TSV-formatted Zeek log line.

        Args:
            line: TSV line from log file
            log_type: Type of log file (conn, dns, http, etc.)

        Returns:
            Parsed event dictionary
        """
        fields = line.strip().split('\t')

        # Field mappings for different log types
        field_maps = {
            'conn': ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
                     'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes',
                     'conn_state', 'local_orig', 'local_resp'],
            'dns': ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
                    'proto', 'trans_id', 'query', 'qclass', 'qclass_name', 'qtype',
                    'qtype_name', 'rcode', 'rcode_name'],
            'http': ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
                     'trans_depth', 'method', 'host', 'uri', 'version', 'user_agent',
                     'request_body_len', 'response_body_len', 'status_code', 'status_msg'],
        }

        field_names = field_maps.get(log_type, [])
        event = {'_path': log_type}

        for i, value in enumerate(fields):
            if i < len(field_names):
                if value != '-':  # Zeek uses '-' for empty fields
                    event[field_names[i]] = value

        return event
