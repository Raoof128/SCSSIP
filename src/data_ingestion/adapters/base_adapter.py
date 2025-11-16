"""
Base adapter interface for security data sources.
All data source adapters must implement this interface.
"""

from abc import ABC, abstractmethod
from typing import AsyncIterator, Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass
from enum import Enum
from loguru import logger


class EventType(Enum):
    """Standard event types for normalization."""
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    FILE_ACCESS = "file_access"
    PROCESS = "process"
    REGISTRY = "registry"
    DNS = "dns"
    HTTP = "http"
    OTHER = "other"


@dataclass
class SecurityEvent:
    """Normalized security event structure."""
    timestamp: datetime
    event_type: EventType
    source_system: str
    raw_data: Dict[str, Any]

    # Common normalized fields
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    user_name: Optional[str] = None
    host_name: Optional[str] = None
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    command_line: Optional[str] = None
    parent_process: Optional[str] = None
    domain: Optional[str] = None
    url: Optional[str] = None
    status_code: Optional[int] = None
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None
    action: Optional[str] = None
    result: Optional[str] = None

    # Metadata
    event_id: Optional[str] = None
    severity: Optional[str] = None
    tags: List[str] = None

    def __post_init__(self):
        """Validate and set defaults."""
        if self.tags is None:
            self.tags = []

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for storage/transmission."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.value,
            'source_system': self.source_system,
            'source_ip': self.source_ip,
            'dest_ip': self.dest_ip,
            'source_port': self.source_port,
            'dest_port': self.dest_port,
            'protocol': self.protocol,
            'user_name': self.user_name,
            'host_name': self.host_name,
            'process_name': self.process_name,
            'process_path': self.process_path,
            'file_path': self.file_path,
            'file_hash': self.file_hash,
            'command_line': self.command_line,
            'parent_process': self.parent_process,
            'domain': self.domain,
            'url': self.url,
            'status_code': self.status_code,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'action': self.action,
            'result': self.result,
            'event_id': self.event_id,
            'severity': self.severity,
            'tags': self.tags,
            'raw_data': self.raw_data
        }


class BaseAdapter(ABC):
    """
    Abstract base class for data source adapters.

    All adapters must implement:
    - connect(): Establish connection to data source
    - disconnect(): Clean up connection
    - fetch_events(): Retrieve events from source
    - normalize_event(): Convert to standard SecurityEvent format
    """

    def __init__(self, name: str, config: Dict[str, Any]):
        """
        Initialize adapter.

        Args:
            name: Adapter name (e.g., 'splunk', 'elastic')
            config: Adapter-specific configuration
        """
        self.name = name
        self.config = config
        self.is_connected = False
        logger.info(f"Initialized {self.name} adapter")

    @abstractmethod
    async def connect(self) -> bool:
        """
        Establish connection to data source.

        Returns:
            True if connection successful, False otherwise
        """
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection and cleanup resources."""
        pass

    @abstractmethod
    async def fetch_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        query: Optional[str] = None,
        limit: Optional[int] = None
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Fetch events from data source.

        Args:
            start_time: Start of time range
            end_time: End of time range
            query: Source-specific query string
            limit: Maximum number of events to fetch

        Yields:
            Raw event dictionaries
        """
        pass

    @abstractmethod
    def normalize_event(self, raw_event: Dict[str, Any]) -> SecurityEvent:
        """
        Convert raw event to normalized SecurityEvent.

        Args:
            raw_event: Raw event from data source

        Returns:
            Normalized SecurityEvent
        """
        pass

    async def stream_normalized_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        query: Optional[str] = None,
        limit: Optional[int] = None
    ) -> AsyncIterator[SecurityEvent]:
        """
        Stream normalized events from data source.

        Args:
            start_time: Start of time range
            end_time: End of time range
            query: Source-specific query string
            limit: Maximum number of events to fetch

        Yields:
            Normalized SecurityEvents
        """
        if not self.is_connected:
            await self.connect()

        event_count = 0
        try:
            async for raw_event in self.fetch_events(start_time, end_time, query, limit):
                try:
                    normalized = self.normalize_event(raw_event)
                    yield normalized
                    event_count += 1
                except Exception as e:
                    logger.error(f"Failed to normalize event from {self.name}: {e}")
                    logger.debug(f"Raw event: {raw_event}")
                    continue

        except Exception as e:
            logger.error(f"Error fetching events from {self.name}: {e}")
            raise
        finally:
            logger.info(f"Fetched {event_count} events from {self.name}")

    async def health_check(self) -> Dict[str, Any]:
        """
        Check adapter health and connectivity.

        Returns:
            Health status dictionary
        """
        try:
            if not self.is_connected:
                await self.connect()

            return {
                'adapter': self.name,
                'status': 'healthy' if self.is_connected else 'unhealthy',
                'connected': self.is_connected,
                'config': {k: v for k, v in self.config.items() if 'password' not in k.lower() and 'token' not in k.lower()}
            }
        except Exception as e:
            logger.error(f"Health check failed for {self.name}: {e}")
            return {
                'adapter': self.name,
                'status': 'unhealthy',
                'connected': False,
                'error': str(e)
            }
