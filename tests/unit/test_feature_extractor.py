"""Unit tests for feature extractor."""

import pytest
import numpy as np
from datetime import datetime, timedelta

from analytics.feature_extractor import FeatureExtractor, FeatureStore
from data_ingestion.adapters.base_adapter import SecurityEvent, EventType


class TestFeatureExtractor:
    """Test feature extraction functionality."""

    @pytest.fixture
    def extractor(self):
        """Create feature extractor instance."""
        return FeatureExtractor(lookback_hours=24)

    @pytest.fixture
    def sample_events(self):
        """Create sample security events."""
        events = []
        base_time = datetime.utcnow()

        for i in range(100):
            event = SecurityEvent(
                timestamp=base_time - timedelta(hours=i),
                event_type=EventType.AUTHENTICATION,
                source_system='test',
                raw_data={'test': 'data'},
                user_name='alice',
                host_name='WORKSTATION-01',
                source_ip='10.0.1.20',
                result='success'
            )
            events.append(event)

        return events

    def test_extract_features(self, extractor, sample_events):
        """Test feature extraction."""
        features = extractor.extract_features(sample_events, 'alice', 'user')

        assert isinstance(features, np.ndarray)
        assert features.shape[0] > 0
        assert not np.isnan(features).any()

    def test_temporal_features(self, extractor, sample_events):
        """Test temporal feature extraction."""
        features = extractor.extract_features(sample_events, 'alice', 'user')

        assert features is not None
        assert len(extractor.get_feature_names()) > 0

    def test_empty_events(self, extractor):
        """Test handling of empty event list."""
        features = extractor.extract_features([], 'test', 'user')

        assert isinstance(features, np.ndarray)
        assert features.shape[0] > 0

    def test_feature_names(self, extractor, sample_events):
        """Test feature names are generated."""
        extractor.extract_features(sample_events, 'alice', 'user')

        names = extractor.get_feature_names()
        assert len(names) > 0
        assert all(isinstance(name, str) for name in names)


class TestFeatureStore:
    """Test feature store functionality."""

    @pytest.fixture
    def store(self):
        """Create feature store instance."""
        return FeatureStore()

    def test_store_and_retrieve(self, store):
        """Test storing and retrieving features."""
        features = np.array([1.0, 2.0, 3.0])
        store.store_features('entity1', features)

        retrieved = store.get_features('entity1')
        assert np.array_equal(retrieved, features)

    def test_get_all_features(self, store):
        """Test getting all features as matrix."""
        store.store_features('entity1', np.array([1.0, 2.0, 3.0]))
        store.store_features('entity2', np.array([4.0, 5.0, 6.0]))

        all_features = store.get_all_features()
        assert all_features.shape == (2, 3)

    def test_clear(self, store):
        """Test clearing feature store."""
        store.store_features('entity1', np.array([1.0, 2.0, 3.0]))
        store.clear()

        assert len(store.get_entity_ids()) == 0
