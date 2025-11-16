"""
Cross-event correlation engine.
Links related security events to identify attack chains and patterns.
"""

from typing import List, Dict, Any, Set, Optional
from datetime import datetime, timedelta
from collections import defaultdict
from loguru import logger

from ...data_ingestion.adapters.base_adapter import SecurityEvent


class CorrelationRule:
    """Represents a correlation rule."""

    def __init__(
        self,
        rule_id: str,
        name: str,
        conditions: Dict[str, Any],
        time_window_minutes: int = 60
    ):
        """Initialize correlation rule."""
        self.rule_id = rule_id
        self.name = name
        self.conditions = conditions
        self.time_window_minutes = time_window_minutes


class AttackChain:
    """Represents a detected attack chain."""

    def __init__(self, chain_id: str):
        """Initialize attack chain."""
        self.chain_id = chain_id
        self.steps: List[Dict[str, Any]] = []
        self.entities: Set[str] = set()
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.confidence = 0.0

    def add_step(self, step: Dict[str, Any]):
        """Add a step to the attack chain."""
        self.steps.append(step)

        if 'timestamp' in step:
            timestamp = step['timestamp']
            if self.start_time is None or timestamp < self.start_time:
                self.start_time = timestamp
            if self.end_time is None or timestamp > self.end_time:
                self.end_time = timestamp

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'chain_id': self.chain_id,
            'steps': self.steps,
            'entities': list(self.entities),
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_minutes': (self.end_time - self.start_time).total_seconds() / 60 if self.start_time and self.end_time else 0,
            'confidence': self.confidence
        }


class CorrelationEngine:
    """
    Correlation engine for linking related security events.
    Identifies attack chains and multi-stage attacks.
    """

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize correlation engine.

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}

        self.time_window_hours = self.config.get('time_window_hours', 24)
        self.max_correlation_depth = self.config.get('max_correlation_depth', 3)
        self.entity_types = self.config.get('entity_types', ['user', 'host', 'ip', 'process'])

        self.correlation_rules = self._load_correlation_rules()

        logger.info(f"Correlation engine initialized with {len(self.correlation_rules)} rules")

    def _load_correlation_rules(self) -> List[CorrelationRule]:
        """Load correlation rules."""
        # Predefined correlation rules for common attack patterns

        rules = [
            CorrelationRule(
                'CR001',
                'Credential Access → Lateral Movement',
                {
                    'sequence': [
                        {'type': 'authentication', 'result': 'success'},
                        {'type': 'network', 'protocol': 'SMB'}
                    ],
                    'same_user': True
                },
                time_window_minutes=30
            ),
            CorrelationRule(
                'CR002',
                'Reconnaissance → Exploitation',
                {
                    'sequence': [
                        {'type': 'network', 'action': 'scan'},
                        {'type': 'process', 'suspicious': True}
                    ],
                    'same_source_ip': True
                },
                time_window_minutes=60
            ),
            CorrelationRule(
                'CR003',
                'Privilege Escalation → Persistence',
                {
                    'sequence': [
                        {'type': 'process', 'privilege_change': True},
                        {'type': 'file_access', 'startup_location': True}
                    ],
                    'same_host': True
                },
                time_window_minutes=15
            ),
        ]

        return rules

    def correlate_events(
        self,
        events: List[Dict[str, Any]],
        entity_ids: Optional[List[str]] = None
    ) -> List[AttackChain]:
        """
        Correlate events to identify attack chains.

        Args:
            events: List of security events
            entity_ids: Optional list of entity IDs to focus correlation

        Returns:
            List of detected attack chains
        """
        if not events:
            return []

        # Filter events by entity if specified
        if entity_ids:
            events = [
                e for e in events
                if any(entity_id in str(e.get('user_name', '')) or
                       entity_id in str(e.get('host_name', '')) or
                       entity_id in str(e.get('source_ip', ''))
                       for entity_id in entity_ids)
            ]

        # Group events by entity
        entity_events = self._group_events_by_entity(events)

        # Find correlations
        attack_chains = []

        for entity_id, entity_event_list in entity_events.items():
            # Sort events by timestamp
            sorted_events = sorted(entity_event_list, key=lambda x: x.get('timestamp', datetime.utcnow()))

            # Find sequential patterns
            chains = self._find_attack_chains(sorted_events, entity_id)
            attack_chains.extend(chains)

        logger.info(f"Found {len(attack_chains)} attack chains")

        return attack_chains

    def _group_events_by_entity(self, events: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group events by entity (user, host, IP)."""
        entity_events = defaultdict(list)

        for event in events:
            # Group by primary entity
            entity_id = (
                event.get('user_name') or
                event.get('host_name') or
                event.get('source_ip') or
                'unknown'
            )

            entity_events[entity_id].append(event)

        return entity_events

    def _find_attack_chains(self, events: List[Dict[str, Any]], entity_id: str) -> List[AttackChain]:
        """Find attack chains in event sequence."""
        chains = []

        # Look for common attack patterns
        chains.extend(self._detect_lateral_movement_chain(events, entity_id))
        chains.extend(self._detect_privilege_escalation_chain(events, entity_id))
        chains.extend(self._detect_exfiltration_chain(events, entity_id))

        return chains

    def _detect_lateral_movement_chain(self, events: List[Dict[str, Any]], entity_id: str) -> List[AttackChain]:
        """Detect lateral movement patterns."""
        chains = []

        # Pattern: Auth success → Multiple SMB connections → Process execution
        auth_events = [e for e in events if e.get('event_type') == 'authentication']
        network_events = [e for e in events if e.get('event_type') == 'network']

        for auth_event in auth_events:
            if auth_event.get('result') != 'success':
                continue

            auth_time = auth_event.get('timestamp', datetime.utcnow())

            # Look for network activity within time window
            related_network = [
                e for e in network_events
                if abs((e.get('timestamp', datetime.utcnow()) - auth_time).total_seconds()) < 3600
            ]

            if len(related_network) >= 3:  # Multiple connections indicate potential lateral movement
                chain = AttackChain(f"LM-{entity_id}-{auth_time.strftime('%Y%m%d%H%M')}")
                chain.entities.add(entity_id)

                chain.add_step({
                    'step': 1,
                    'technique': 'T1078',
                    'description': 'Initial Access via Valid Accounts',
                    'timestamp': auth_time,
                    'event': auth_event
                })

                chain.add_step({
                    'step': 2,
                    'technique': 'T1021.002',
                    'description': f'Lateral Movement via SMB ({len(related_network)} connections)',
                    'timestamp': related_network[0].get('timestamp'),
                    'event': related_network[0]
                })

                chain.confidence = 0.75 + (min(len(related_network), 10) * 0.02)
                chains.append(chain)

        return chains

    def _detect_privilege_escalation_chain(self, events: List[Dict[str, Any]], entity_id: str) -> List[AttackChain]:
        """Detect privilege escalation patterns."""
        chains = []

        # Pattern: Process execution → File modification in system paths
        process_events = [e for e in events if e.get('event_type') == 'process']
        file_events = [e for e in events if e.get('event_type') == 'file_access']

        for proc_event in process_events:
            proc_time = proc_event.get('timestamp', datetime.utcnow())

            # Look for subsequent file access in system directories
            suspicious_files = [
                e for e in file_events
                if abs((e.get('timestamp', datetime.utcnow()) - proc_time).total_seconds()) < 900 and
                   ('system32' in str(e.get('file_path', '')).lower() or
                    'startup' in str(e.get('file_path', '')).lower())
            ]

            if suspicious_files:
                chain = AttackChain(f"PE-{entity_id}-{proc_time.strftime('%Y%m%d%H%M')}")
                chain.entities.add(entity_id)

                chain.add_step({
                    'step': 1,
                    'technique': 'T1068',
                    'description': 'Potential Privilege Escalation',
                    'timestamp': proc_time,
                    'event': proc_event
                })

                chain.add_step({
                    'step': 2,
                    'technique': 'T1547',
                    'description': 'Persistence via Autostart',
                    'timestamp': suspicious_files[0].get('timestamp'),
                    'event': suspicious_files[0]
                })

                chain.confidence = 0.80
                chains.append(chain)

        return chains

    def _detect_exfiltration_chain(self, events: List[Dict[str, Any]], entity_id: str) -> List[AttackChain]:
        """Detect data exfiltration patterns."""
        chains = []

        # Pattern: File access → Large network transfer
        file_events = [e for e in events if e.get('event_type') == 'file_access']
        network_events = [e for e in events if e.get('event_type') == 'network']

        for file_event in file_events:
            file_time = file_event.get('timestamp', datetime.utcnow())

            # Look for large data transfers shortly after
            large_transfers = [
                e for e in network_events
                if (e.get('bytes_sent', 0) > 10000000) and  # >10MB
                   abs((e.get('timestamp', datetime.utcnow()) - file_time).total_seconds()) < 1800
            ]

            if large_transfers:
                chain = AttackChain(f"EX-{entity_id}-{file_time.strftime('%Y%m%d%H%M')}")
                chain.entities.add(entity_id)

                chain.add_step({
                    'step': 1,
                    'technique': 'T1005',
                    'description': 'Data Collection from Local System',
                    'timestamp': file_time,
                    'event': file_event
                })

                chain.add_step({
                    'step': 2,
                    'technique': 'T1041',
                    'description': f'Data Exfiltration ({large_transfers[0].get("bytes_sent", 0) / 1000000:.1f} MB)',
                    'timestamp': large_transfers[0].get('timestamp'),
                    'event': large_transfers[0]
                })

                chain.confidence = 0.85
                chains.append(chain)

        return chains

    def calculate_correlation_score(
        self,
        event1: Dict[str, Any],
        event2: Dict[str, Any]
    ) -> float:
        """
        Calculate correlation score between two events.

        Args:
            event1: First event
            event2: Second event

        Returns:
            Correlation score (0-1)
        """
        score = 0.0

        # Same user
        if event1.get('user_name') and event1.get('user_name') == event2.get('user_name'):
            score += 0.3

        # Same host
        if event1.get('host_name') and event1.get('host_name') == event2.get('host_name'):
            score += 0.3

        # Same source IP
        if event1.get('source_ip') and event1.get('source_ip') == event2.get('source_ip'):
            score += 0.2

        # Temporal proximity (within 1 hour)
        time_diff = abs(
            (event1.get('timestamp', datetime.utcnow()) - event2.get('timestamp', datetime.utcnow())).total_seconds()
        )
        if time_diff < 3600:
            score += 0.2 * (1 - time_diff / 3600)

        return min(score, 1.0)
