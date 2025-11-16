"""
Feature extraction and engineering for behavioral analytics.
Transforms security events into ML-ready feature vectors.
"""

import numpy as np
import pandas as pd
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict
from loguru import logger

from data_ingestion.adapters.base_adapter import SecurityEvent, EventType


class FeatureExtractor:
    """
    Extracts behavioral features from security events.
    Supports temporal, statistical, and categorical features.
    """

    def __init__(self, lookback_hours: int = 24):
        """
        Initialize feature extractor.

        Args:
            lookback_hours: Hours of historical data to consider for features
        """
        self.lookback_hours = lookback_hours
        self.feature_names: List[str] = []

    def extract_features(self, events: List[SecurityEvent], entity_id: str, entity_type: str) -> np.ndarray:
        """
        Extract feature vector for an entity.

        Args:
            events: List of security events for the entity
            entity_id: Entity identifier
            entity_type: Entity type (user, host, ip)

        Returns:
            Feature vector as numpy array
        """
        if not events:
            return np.zeros(self._get_feature_count())

        # Convert to DataFrame for easier manipulation
        df = self._events_to_dataframe(events)

        # Extract different feature categories
        temporal_features = self._extract_temporal_features(df)
        statistical_features = self._extract_statistical_features(df)
        categorical_features = self._extract_categorical_features(df)
        behavioral_features = self._extract_behavioral_features(df, entity_type)

        # Combine all features
        all_features = {
            **temporal_features,
            **statistical_features,
            **categorical_features,
            **behavioral_features
        }

        # Build feature names list (first time)
        if not self.feature_names:
            self.feature_names = sorted(all_features.keys())

        # Convert to ordered array
        feature_vector = np.array([all_features.get(name, 0.0) for name in self.feature_names])

        return feature_vector

    def _events_to_dataframe(self, events: List[SecurityEvent]) -> pd.DataFrame:
        """Convert events to pandas DataFrame."""
        data = []
        for event in events:
            data.append({
                'timestamp': event.timestamp,
                'event_type': event.event_type.value,
                'source_ip': event.source_ip,
                'dest_ip': event.dest_ip,
                'source_port': event.source_port,
                'dest_port': event.dest_port,
                'user_name': event.user_name,
                'host_name': event.host_name,
                'process_name': event.process_name,
                'bytes_sent': event.bytes_sent or 0,
                'bytes_received': event.bytes_received or 0,
                'result': event.result
            })

        df = pd.DataFrame(data)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        return df

    def _extract_temporal_features(self, df: pd.DataFrame) -> Dict[str, float]:
        """Extract time-based features."""
        features = {}

        if df.empty:
            return features

        # Hour of day statistics
        df['hour'] = df['timestamp'].dt.hour
        features['hour_mean'] = df['hour'].mean()
        features['hour_std'] = df['hour'].std() if len(df) > 1 else 0.0
        features['hour_min'] = df['hour'].min()
        features['hour_max'] = df['hour'].max()

        # Day of week statistics
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        features['day_of_week_mean'] = df['day_of_week'].mean()
        features['day_of_week_std'] = df['day_of_week'].std() if len(df) > 1 else 0.0

        # Business hours indicator (9 AM - 5 PM, weekdays)
        business_hours = (df['hour'] >= 9) & (df['hour'] <= 17) & (df['day_of_week'] < 5)
        features['business_hours_ratio'] = business_hours.sum() / len(df)

        # After hours indicator
        after_hours = (df['hour'] < 6) | (df['hour'] > 22)
        features['after_hours_ratio'] = after_hours.sum() / len(df)

        # Weekend activity
        weekend = df['day_of_week'] >= 5
        features['weekend_ratio'] = weekend.sum() / len(df)

        # Time since last event (in minutes)
        if len(df) > 1:
            df_sorted = df.sort_values('timestamp')
            time_diffs = df_sorted['timestamp'].diff().dt.total_seconds() / 60
            features['time_since_last_event_mean'] = time_diffs.mean()
            features['time_since_last_event_std'] = time_diffs.std()
            features['time_since_last_event_max'] = time_diffs.max()
        else:
            features['time_since_last_event_mean'] = 0.0
            features['time_since_last_event_std'] = 0.0
            features['time_since_last_event_max'] = 0.0

        return features

    def _extract_statistical_features(self, df: pd.DataFrame) -> Dict[str, float]:
        """Extract statistical features."""
        features = {}

        if df.empty:
            return features

        # Event counts over different time windows
        now = datetime.utcnow()
        features['event_count_total'] = len(df)
        features['event_count_1h'] = len(df[df['timestamp'] >= now - timedelta(hours=1)])
        features['event_count_24h'] = len(df[df['timestamp'] >= now - timedelta(hours=24)])

        # Unique source IPs
        features['unique_source_ips'] = df['source_ip'].nunique()
        features['unique_dest_ips'] = df['dest_ip'].nunique()

        # Port statistics
        features['unique_source_ports'] = df['source_port'].nunique()
        features['unique_dest_ports'] = df['dest_port'].nunique()

        # Data volume statistics
        features['bytes_sent_total'] = df['bytes_sent'].sum()
        features['bytes_received_total'] = df['bytes_received'].sum()
        features['bytes_sent_mean'] = df['bytes_sent'].mean()
        features['bytes_received_mean'] = df['bytes_received'].mean()
        features['bytes_sent_std'] = df['bytes_sent'].std() if len(df) > 1 else 0.0
        features['bytes_received_std'] = df['bytes_received'].std() if len(df) > 1 else 0.0

        # Process diversity
        features['unique_processes'] = df['process_name'].nunique()
        features['unique_hosts'] = df['host_name'].nunique()

        return features

    def _extract_categorical_features(self, df: pd.DataFrame) -> Dict[str, float]:
        """Extract categorical features (one-hot encoded)."""
        features = {}

        if df.empty:
            return features

        # Event type distribution
        event_type_counts = df['event_type'].value_counts()
        total_events = len(df)

        for event_type in ['authentication', 'network', 'process', 'file_access', 'dns', 'http']:
            features[f'event_type_{event_type}_ratio'] = event_type_counts.get(event_type, 0) / total_events

        # Success/failure ratio
        if 'result' in df.columns:
            success_count = (df['result'] == 'success').sum()
            features['success_ratio'] = success_count / total_events
            features['failure_ratio'] = 1 - (success_count / total_events)

        return features

    def _extract_behavioral_features(self, df: pd.DataFrame, entity_type: str) -> Dict[str, float]:
        """Extract behavioral pattern features."""
        features = {}

        if df.empty:
            return features

        # Connection pattern features
        if entity_type == 'user':
            # User-specific features
            features['unique_login_hosts'] = df[df['event_type'] == 'authentication']['host_name'].nunique()
            features['failed_login_ratio'] = (
                (df['event_type'] == 'authentication') & (df['result'] == 'failure')
            ).sum() / max(1, (df['event_type'] == 'authentication').sum())

        elif entity_type == 'host':
            # Host-specific features
            features['unique_users'] = df['user_name'].nunique()
            features['unique_processes'] = df['process_name'].nunique()

        elif entity_type == 'ip':
            # IP-specific features
            features['unique_dest_ips'] = df['dest_ip'].nunique()
            features['unique_dest_ports'] = df['dest_port'].nunique()

        # Entropy-based features (measure of randomness)
        features['source_ip_entropy'] = self._calculate_entropy(df['source_ip'])
        features['dest_ip_entropy'] = self._calculate_entropy(df['dest_ip'])
        features['dest_port_entropy'] = self._calculate_entropy(df['dest_port'])

        return features

    def _calculate_entropy(self, series: pd.Series) -> float:
        """Calculate Shannon entropy of a series."""
        if series.empty:
            return 0.0

        value_counts = series.value_counts()
        probabilities = value_counts / len(series)
        entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))

        return float(entropy)

    def _get_feature_count(self) -> int:
        """Get total number of features."""
        # Approximate feature count (will be exact after first extraction)
        return 50  # Placeholder

    def get_feature_names(self) -> List[str]:
        """Get ordered list of feature names."""
        return self.feature_names.copy()


class FeatureStore:
    """
    Stores and manages extracted features for entities.
    Provides caching and batch operations.
    """

    def __init__(self):
        """Initialize feature store."""
        self.features: Dict[str, np.ndarray] = {}
        self.metadata: Dict[str, Dict[str, Any]] = {}

    def store_features(self, entity_id: str, features: np.ndarray, metadata: Dict[str, Any] = None):
        """
        Store features for an entity.

        Args:
            entity_id: Entity identifier
            features: Feature vector
            metadata: Optional metadata (timestamp, version, etc.)
        """
        self.features[entity_id] = features
        self.metadata[entity_id] = metadata or {'timestamp': datetime.utcnow()}

        logger.debug(f"Stored features for entity {entity_id}")

    def get_features(self, entity_id: str) -> Optional[np.ndarray]:
        """
        Retrieve features for an entity.

        Args:
            entity_id: Entity identifier

        Returns:
            Feature vector or None if not found
        """
        return self.features.get(entity_id)

    def get_all_features(self) -> np.ndarray:
        """
        Get all features as a matrix.

        Returns:
            2D numpy array where each row is an entity's features
        """
        if not self.features:
            return np.array([])

        return np.vstack(list(self.features.values()))

    def get_entity_ids(self) -> List[str]:
        """Get list of entity IDs with stored features."""
        return list(self.features.keys())

    def clear(self):
        """Clear all stored features."""
        self.features.clear()
        self.metadata.clear()
