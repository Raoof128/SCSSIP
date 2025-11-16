"""
Sample data generator for testing the threat hunting platform.
Generates realistic security events for development and testing.
"""

import random
from typing import AsyncIterator, Dict, Any, Optional, List
from datetime import datetime, timedelta
from loguru import logger

from .base_adapter import BaseAdapter, SecurityEvent, EventType


class SampleDataGenerator(BaseAdapter):
    """Generates sample security events for testing."""

    def __init__(self, config: Dict[str, Any] = None):
        """Initialize sample data generator."""
        super().__init__("sample_generator", config or {})

        # Sample data for realistic events
        self.usernames = ['alice', 'bob', 'charlie', 'admin', 'service_account', 'analyst01']
        self.hostnames = ['DESKTOP-001', 'SERVER-WEB01', 'DB-PRIMARY', 'WORKSTATION-42', 'JUMPBOX']
        self.internal_ips = ['10.0.1.10', '10.0.1.20', '10.0.2.15', '192.168.1.100', '172.16.0.50']
        self.external_ips = ['203.0.113.1', '198.51.100.42', '192.0.2.123', '8.8.8.8']
        self.processes = ['chrome.exe', 'powershell.exe', 'cmd.exe', 'python.exe', 'svchost.exe', 'explorer.exe']
        self.domains = ['google.com', 'microsoft.com', 'suspicious-domain.xyz', 'malware-c2.net']

    async def connect(self) -> bool:
        """No connection needed for generator."""
        self.is_connected = True
        logger.info("Sample data generator ready")
        return True

    async def disconnect(self) -> None:
        """No disconnection needed."""
        self.is_connected = False

    async def fetch_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        query: Optional[str] = None,
        limit: Optional[int] = 100
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Generate sample events.

        Args:
            start_time: Start time for events
            end_time: End time for events
            query: Event type filter (e.g., 'network', 'authentication')
            limit: Number of events to generate

        Yields:
            Generated event dictionaries
        """
        if start_time is None:
            start_time = datetime.utcnow() - timedelta(hours=1)
        if end_time is None:
            end_time = datetime.utcnow()

        num_events = limit or 100
        time_delta = (end_time - start_time) / num_events

        for i in range(num_events):
            event_time = start_time + (time_delta * i)

            # Determine event type
            if query:
                event_type = query
            else:
                event_type = random.choice(['network', 'authentication', 'process', 'file_access', 'dns'])

            # Generate event based on type
            if event_type == 'network':
                event = self._generate_network_event(event_time)
            elif event_type == 'authentication':
                event = self._generate_auth_event(event_time)
            elif event_type == 'process':
                event = self._generate_process_event(event_time)
            elif event_type == 'file_access':
                event = self._generate_file_event(event_time)
            elif event_type == 'dns':
                event = self._generate_dns_event(event_time)
            else:
                event = self._generate_generic_event(event_time)

            # Add some anomalous events (10% probability)
            if random.random() < 0.1:
                event = self._inject_anomaly(event)

            yield event

    def normalize_event(self, raw_event: Dict[str, Any]) -> SecurityEvent:
        """Convert generated event to SecurityEvent."""
        timestamp = datetime.fromisoformat(raw_event['timestamp'])
        event_type_str = raw_event.get('event_type', 'other')

        # Map string to EventType enum
        event_type_map = {
            'network': EventType.NETWORK,
            'authentication': EventType.AUTHENTICATION,
            'process': EventType.PROCESS,
            'file_access': EventType.FILE_ACCESS,
            'dns': EventType.DNS,
            'http': EventType.HTTP,
        }
        event_type = event_type_map.get(event_type_str, EventType.OTHER)

        return SecurityEvent(
            timestamp=timestamp,
            event_type=event_type,
            source_system='sample_generator',
            raw_data=raw_event,
            source_ip=raw_event.get('source_ip'),
            dest_ip=raw_event.get('dest_ip'),
            source_port=raw_event.get('source_port'),
            dest_port=raw_event.get('dest_port'),
            protocol=raw_event.get('protocol'),
            user_name=raw_event.get('user_name'),
            host_name=raw_event.get('host_name'),
            process_name=raw_event.get('process_name'),
            file_path=raw_event.get('file_path'),
            domain=raw_event.get('domain'),
            action=raw_event.get('action'),
            result=raw_event.get('result'),
            tags=raw_event.get('tags', [])
        )

    def _generate_network_event(self, timestamp: datetime) -> Dict[str, Any]:
        """Generate a network connection event."""
        return {
            'timestamp': timestamp.isoformat(),
            'event_type': 'network',
            'source_ip': random.choice(self.internal_ips),
            'dest_ip': random.choice(self.external_ips),
            'source_port': random.randint(49152, 65535),
            'dest_port': random.choice([80, 443, 22, 3389, 445]),
            'protocol': random.choice(['TCP', 'UDP']),
            'bytes_sent': random.randint(100, 10000),
            'bytes_received': random.randint(100, 50000),
            'host_name': random.choice(self.hostnames)
        }

    def _generate_auth_event(self, timestamp: datetime) -> Dict[str, Any]:
        """Generate an authentication event."""
        success = random.random() > 0.05  # 95% success rate
        return {
            'timestamp': timestamp.isoformat(),
            'event_type': 'authentication',
            'user_name': random.choice(self.usernames),
            'host_name': random.choice(self.hostnames),
            'source_ip': random.choice(self.internal_ips),
            'action': 'login',
            'result': 'success' if success else 'failure',
            'auth_method': random.choice(['password', 'certificate', 'kerberos'])
        }

    def _generate_process_event(self, timestamp: datetime) -> Dict[str, Any]:
        """Generate a process execution event."""
        process = random.choice(self.processes)
        return {
            'timestamp': timestamp.isoformat(),
            'event_type': 'process',
            'host_name': random.choice(self.hostnames),
            'user_name': random.choice(self.usernames),
            'process_name': process,
            'process_path': f'C:\\Windows\\System32\\{process}',
            'command_line': f'{process} --flag value',
            'parent_process': 'explorer.exe',
            'action': 'create'
        }

    def _generate_file_event(self, timestamp: datetime) -> Dict[str, Any]:
        """Generate a file access event."""
        return {
            'timestamp': timestamp.isoformat(),
            'event_type': 'file_access',
            'host_name': random.choice(self.hostnames),
            'user_name': random.choice(self.usernames),
            'file_path': f'C:\\Users\\{random.choice(self.usernames)}\\Documents\\file_{random.randint(1, 100)}.txt',
            'action': random.choice(['create', 'modify', 'delete', 'read']),
            'process_name': random.choice(self.processes)
        }

    def _generate_dns_event(self, timestamp: datetime) -> Dict[str, Any]:
        """Generate a DNS query event."""
        return {
            'timestamp': timestamp.isoformat(),
            'event_type': 'dns',
            'source_ip': random.choice(self.internal_ips),
            'domain': random.choice(self.domains),
            'query_type': random.choice(['A', 'AAAA', 'MX', 'TXT']),
            'result': 'success',
            'host_name': random.choice(self.hostnames)
        }

    def _generate_generic_event(self, timestamp: datetime) -> Dict[str, Any]:
        """Generate a generic event."""
        return {
            'timestamp': timestamp.isoformat(),
            'event_type': 'other',
            'host_name': random.choice(self.hostnames),
            'action': 'generic_action'
        }

    def _inject_anomaly(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Inject anomalous behavior into event."""
        event_type = event.get('event_type')

        if event_type == 'network':
            # Unusual port or large data transfer
            event['dest_port'] = random.choice([4444, 8888, 31337])  # Suspicious ports
            event['bytes_sent'] = random.randint(100000, 1000000)  # Large transfer
            event['tags'] = ['anomaly', 'suspicious_port']

        elif event_type == 'authentication':
            # Failed login or unusual time
            event['result'] = 'failure'
            event['tags'] = ['anomaly', 'failed_auth']

        elif event_type == 'process':
            # Suspicious process or command
            event['process_name'] = 'powershell.exe'
            event['command_line'] = 'powershell.exe -encodedCommand <base64>'
            event['tags'] = ['anomaly', 'suspicious_command']

        elif event_type == 'dns':
            # Suspicious domain
            event['domain'] = random.choice(['malware-c2.net', 'phishing-site.xyz'])
            event['tags'] = ['anomaly', 'suspicious_domain']

        return event
