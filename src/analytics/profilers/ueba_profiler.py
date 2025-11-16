"""
User and Entity Behavioral Analytics (UEBA) profiling framework.
Creates behavioral baselines and detects deviations for users, hosts, and IPs.
"""

import numpy as np
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict
from loguru import logger

from ...data_ingestion.adapters.base_adapter import SecurityEvent, EventType
from ..feature_extractor import FeatureExtractor


class EntityProfile:
    """Behavioral profile for an entity."""

    def __init__(self, entity_id: str, entity_type: str):
        """
        Initialize entity profile.

        Args:
            entity_id: Entity identifier
            entity_type: Entity type (user, host, ip, application)
        """
        self.entity_id = entity_id
        self.entity_type = entity_type
        self.baseline_start: Optional[datetime] = None
        self.baseline_end: Optional[datetime] = None
        self.event_count = 0
        self.feature_vector: Optional[np.ndarray] = None
        self.behavioral_patterns: Dict[str, Any] = {}
        self.risk_score = 0.0
        self.last_updated: Optional[datetime] = None
        self.peer_group_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert profile to dictionary."""
        return {
            'entity_id': self.entity_id,
            'entity_type': self.entity_type,
            'baseline_start': self.baseline_start.isoformat() if self.baseline_start else None,
            'baseline_end': self.baseline_end.isoformat() if self.baseline_end else None,
            'event_count': self.event_count,
            'behavioral_patterns': self.behavioral_patterns,
            'risk_score': self.risk_score,
            'last_updated': self.last_updated.isoformat() if self.last_updated else None,
            'peer_group_id': self.peer_group_id
        }


class UEBAProfiler:
    """
    UEBA profiling framework.
    Tracks behavioral baselines and identifies anomalous entity behavior.
    """

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize UEBA profiler.

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}

        self.baseline_period_days = self.config.get('baseline_period_days', 30)
        self.min_events_for_profile = self.config.get('min_events_for_profile', 100)
        self.update_interval_hours = self.config.get('update_interval_hours', 6)
        self.peer_group_size = self.config.get('peer_group_size', 10)

        self.profiles: Dict[str, EntityProfile] = {}
        self.feature_extractor = FeatureExtractor(lookback_hours=24)

        logger.info("UEBA profiler initialized")

    def create_profile(
        self,
        entity_id: str,
        entity_type: str,
        events: List[SecurityEvent]
    ) -> EntityProfile:
        """
        Create behavioral profile for an entity.

        Args:
            entity_id: Entity identifier
            entity_type: Entity type
            events: Historical events for the entity

        Returns:
            EntityProfile object
        """
        if len(events) < self.min_events_for_profile:
            logger.warning(
                f"Insufficient events for {entity_id} ({len(events)} < {self.min_events_for_profile})"
            )

        profile = EntityProfile(entity_id, entity_type)
        profile.event_count = len(events)

        if events:
            profile.baseline_start = min(e.timestamp for e in events)
            profile.baseline_end = max(e.timestamp for e in events)

            # Extract features
            profile.feature_vector = self.feature_extractor.extract_features(
                events, entity_id, entity_type
            )

            # Calculate behavioral patterns
            profile.behavioral_patterns = self._calculate_behavioral_patterns(events, entity_type)

            # Calculate risk score
            profile.risk_score = self._calculate_risk_score(profile)

        profile.last_updated = datetime.utcnow()

        self.profiles[entity_id] = profile

        logger.info(f"Created profile for {entity_type} {entity_id} with {len(events)} events")

        return profile

    def update_profile(self, entity_id: str, new_events: List[SecurityEvent]) -> EntityProfile:
        """
        Update existing profile with new events.

        Args:
            entity_id: Entity identifier
            new_events: New events to incorporate

        Returns:
            Updated EntityProfile
        """
        if entity_id not in self.profiles:
            raise ValueError(f"Profile not found for {entity_id}")

        profile = self.profiles[entity_id]

        # Re-extract features with updated events
        profile.feature_vector = self.feature_extractor.extract_features(
            new_events, entity_id, profile.entity_type
        )

        profile.behavioral_patterns = self._calculate_behavioral_patterns(
            new_events, profile.entity_type
        )

        profile.event_count += len(new_events)
        profile.risk_score = self._calculate_risk_score(profile)
        profile.last_updated = datetime.utcnow()

        logger.debug(f"Updated profile for {entity_id}")

        return profile

    def get_profile(self, entity_id: str) -> Optional[EntityProfile]:
        """Get entity profile."""
        return self.profiles.get(entity_id)

    def _calculate_behavioral_patterns(
        self,
        events: List[SecurityEvent],
        entity_type: str
    ) -> Dict[str, Any]:
        """Calculate behavioral patterns from events."""
        patterns = {
            'authentication': self._analyze_authentication_patterns(events),
            'network': self._analyze_network_patterns(events),
            'temporal': self._analyze_temporal_patterns(events)
        }

        if entity_type == 'user':
            patterns['file_access'] = self._analyze_file_access_patterns(events)

        return patterns

    def _analyze_authentication_patterns(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Analyze authentication behavior."""
        auth_events = [e for e in events if e.event_type == EventType.AUTHENTICATION]

        if not auth_events:
            return {}

        success_count = sum(1 for e in auth_events if e.result == 'success')
        failure_count = len(auth_events) - success_count

        source_ips = set(e.source_ip for e in auth_events if e.source_ip)

        return {
            'total_attempts': len(auth_events),
            'success_rate': success_count / len(auth_events),
            'failure_count': failure_count,
            'unique_source_ips': len(source_ips),
            'common_source_ips': list(source_ips)[:5]
        }

    def _analyze_network_patterns(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Analyze network behavior."""
        network_events = [e for e in events if e.event_type == EventType.NETWORK]

        if not network_events:
            return {}

        dest_ips = set(e.dest_ip for e in network_events if e.dest_ip)
        dest_ports = set(e.dest_port for e in network_events if e.dest_port)

        total_bytes_sent = sum(e.bytes_sent or 0 for e in network_events)
        total_bytes_received = sum(e.bytes_received or 0 for e in network_events)

        return {
            'connection_count': len(network_events),
            'unique_destinations': len(dest_ips),
            'unique_ports': len(dest_ports),
            'total_bytes_sent': total_bytes_sent,
            'total_bytes_received': total_bytes_received
        }

    def _analyze_temporal_patterns(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Analyze temporal patterns."""
        if not events:
            return {}

        hours = [e.timestamp.hour for e in events]
        days = [e.timestamp.weekday() for e in events]

        # Business hours (9-17, weekdays)
        business_hours_count = sum(
            1 for e in events
            if 9 <= e.timestamp.hour <= 17 and e.timestamp.weekday() < 5
        )

        return {
            'typical_hours': list(set(hours)),
            'typical_days': list(set(days)),
            'business_hours_ratio': business_hours_count / len(events)
        }

    def _analyze_file_access_patterns(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Analyze file access behavior."""
        file_events = [e for e in events if e.event_type == EventType.FILE_ACCESS]

        if not file_events:
            return {}

        paths = [e.file_path for e in file_events if e.file_path]

        return {
            'files_accessed': len(file_events),
            'unique_paths': len(set(paths)),
            'common_paths': list(set(paths))[:10]
        }

    def _calculate_risk_score(self, profile: EntityProfile) -> float:
        """
        Calculate risk score for entity.

        Args:
            profile: Entity profile

        Returns:
            Risk score (0-1)
        """
        risk_score = 0.0

        # Authentication risk
        auth_patterns = profile.behavioral_patterns.get('authentication', {})
        success_rate = auth_patterns.get('success_rate', 1.0)
        if success_rate < 0.8:
            risk_score += 0.2

        # After-hours activity risk
        temporal_patterns = profile.behavioral_patterns.get('temporal', {})
        business_hours_ratio = temporal_patterns.get('business_hours_ratio', 1.0)
        if business_hours_ratio < 0.5:
            risk_score += 0.15

        # Network activity risk (placeholder)
        network_patterns = profile.behavioral_patterns.get('network', {})
        unique_destinations = network_patterns.get('unique_destinations', 0)
        if unique_destinations > 100:
            risk_score += 0.1

        return min(risk_score, 1.0)

    def find_peer_group(self, entity_id: str) -> List[str]:
        """
        Find similar entities (peer group).

        Args:
            entity_id: Entity identifier

        Returns:
            List of similar entity IDs
        """
        if entity_id not in self.profiles:
            return []

        target_profile = self.profiles[entity_id]

        if target_profile.feature_vector is None:
            return []

        # Calculate similarity to all other entities
        similarities = []

        for other_id, other_profile in self.profiles.items():
            if other_id == entity_id or other_profile.feature_vector is None:
                continue

            if other_profile.entity_type != target_profile.entity_type:
                continue

            # Cosine similarity
            similarity = np.dot(target_profile.feature_vector, other_profile.feature_vector) / (
                np.linalg.norm(target_profile.feature_vector) *
                np.linalg.norm(other_profile.feature_vector) + 1e-10
            )

            similarities.append((other_id, similarity))

        # Sort by similarity and return top N
        similarities.sort(key=lambda x: x[1], reverse=True)
        peer_ids = [entity_id for entity_id, _ in similarities[:self.peer_group_size]]

        return peer_ids

    def get_all_profiles(self) -> List[EntityProfile]:
        """Get all entity profiles."""
        return list(self.profiles.values())

    def get_high_risk_entities(self, threshold: float = 0.7) -> List[EntityProfile]:
        """
        Get high-risk entities.

        Args:
            threshold: Risk score threshold

        Returns:
            List of high-risk profiles
        """
        return [
            profile for profile in self.profiles.values()
            if profile.risk_score >= threshold
        ]
