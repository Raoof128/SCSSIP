"""
Integration tests for data ingestion and processing pipeline.

Tests the complete data flow from ingestion through detection.
"""

import pytest
import pandas as pd
from datetime import datetime, timedelta
from typing import List

from src.data_ingestion.adapters.base_adapter import SecurityEvent, EventType
from src.data_ingestion.adapters.sample_data_generator import SampleDataGenerator
from src.analytics.feature_extractor import FeatureExtractor, FeatureStore
from src.analytics.models.isolation_forest_detector import IsolationForestDetector
from src.analytics.models.statistical_detector import StatisticalDetector


@pytest.fixture
def sample_generator():
    """Fixture providing sample data generator."""
    return SampleDataGenerator()


@pytest.fixture
def feature_extractor():
    """Fixture providing feature extractor."""
    return FeatureExtractor()


@pytest.fixture
def feature_store():
    """Fixture providing feature store."""
    return FeatureStore()


@pytest.fixture
def sample_events(sample_generator) -> List[SecurityEvent]:
    """Generate sample security events for testing."""
    return sample_generator.generate_events(num_events=1000)


class TestDataIngestionPipeline:
    """Test data ingestion from various sources."""

    def test_sample_data_generation(self, sample_generator):
        """Test sample data generator produces valid events."""
        events = sample_generator.generate_events(num_events=100)

        assert len(events) == 100
        assert all(isinstance(e, SecurityEvent) for e in events)
        assert all(e.timestamp is not None for e in events)
        assert all(e.event_id is not None for e in events)

    def test_event_type_distribution(self, sample_generator):
        """Test that generated events have realistic type distribution."""
        events = sample_generator.generate_events(num_events=1000)

        event_types = [e.event_type for e in events]
        type_counts = pd.Series(event_types).value_counts()

        # Should have multiple event types
        assert len(type_counts) > 3

        # No single type should dominate more than 50%
        assert all(count < 500 for count in type_counts.values)

    def test_event_validation(self, sample_events):
        """Test that all generated events are valid."""
        for event in sample_events[:10]:  # Check first 10
            assert event.event_id is not None
            assert isinstance(event.timestamp, datetime)
            assert isinstance(event.event_type, EventType)
            assert event.severity >= 0 and event.severity <= 10
            assert isinstance(event.raw_data, dict)


class TestFeatureExtractionPipeline:
    """Test feature extraction from events."""

    def test_single_event_feature_extraction(self, feature_extractor, sample_events):
        """Test feature extraction from a single event."""
        event = sample_events[0]
        features = feature_extractor.extract_from_single_event(event)

        assert isinstance(features, dict)
        assert len(features) > 0

        # Check for expected feature categories
        assert any("count" in k for k in features.keys())

    def test_batch_feature_extraction(self, feature_extractor, sample_events):
        """Test batch feature extraction from multiple events."""
        features_df = feature_extractor.extract_features(
            events=sample_events[:100],
            window_size=10
        )

        assert isinstance(features_df, pd.DataFrame)
        assert len(features_df) > 0
        assert features_df.shape[1] >= 10  # At least 10 features

        # Check for no NaN in critical features
        critical_features = [col for col in features_df.columns if 'count' in col]
        for col in critical_features[:5]:  # Check first 5
            if col in features_df.columns:
                assert features_df[col].notna().all()

    def test_user_aggregation_features(self, feature_extractor, sample_events):
        """Test user-level aggregation features."""
        # Filter events for a specific user
        user_events = [e for e in sample_events if e.user == "alice"]

        if len(user_events) > 10:
            features_df = feature_extractor.extract_features(
                events=user_events,
                window_size=5
            )

            assert len(features_df) > 0

            # Should have time-based features
            hour_features = [col for col in features_df.columns if 'hour' in col.lower()]
            assert len(hour_features) > 0

    def test_feature_store_operations(self, feature_store, sample_events):
        """Test feature store storage and retrieval."""
        # Store features for a user
        test_user = "test_user_001"
        test_features = {
            "event_count_1h": 10,
            "failed_auth_count": 2,
            "unique_ips": 3
        }

        feature_store.store_features(
            entity_id=test_user,
            features=test_features,
            timestamp=datetime.utcnow()
        )

        # Retrieve features
        retrieved = feature_store.get_features(
            entity_id=test_user,
            lookback_hours=1
        )

        assert retrieved is not None
        assert "event_count_1h" in retrieved


class TestAnomalyDetectionPipeline:
    """Test anomaly detection on extracted features."""

    def test_isolation_forest_training_and_detection(self, feature_extractor, sample_events):
        """Test training and detection with Isolation Forest."""
        # Extract features
        features_df = feature_extractor.extract_features(
            events=sample_events,
            window_size=50
        )

        if len(features_df) < 100:
            pytest.skip("Not enough features generated for training")

        # Initialize and train detector
        detector = IsolationForestDetector(contamination=0.1)

        # Prepare training data
        X_train = features_df.select_dtypes(include=['float64', 'int64']).fillna(0)

        if X_train.shape[1] == 0:
            pytest.skip("No numeric features available")

        detector.train(X_train.values)

        # Test detection
        predictions = detector.detect(X_train.values[:50])

        assert len(predictions) == 50
        assert all(p in [0, 1] for p in predictions)

        # Should detect some anomalies (with 10% contamination)
        anomaly_rate = sum(predictions) / len(predictions)
        assert 0.0 <= anomaly_rate <= 0.5  # Reasonable range

    def test_statistical_detector_baseline(self, feature_extractor, sample_events):
        """Test statistical detector baseline creation."""
        # Extract features
        features_df = feature_extractor.extract_features(
            events=sample_events,
            window_size=50
        )

        if len(features_df) < 100:
            pytest.skip("Not enough features generated")

        # Initialize statistical detector
        detector = StatisticalDetector(
            methods=['zscore', 'iqr'],
            threshold=3.0
        )

        # Prepare data
        X_train = features_df.select_dtypes(include=['float64', 'int64']).fillna(0)

        if X_train.shape[1] == 0:
            pytest.skip("No numeric features available")

        # Train (create baseline)
        detector.train(X_train.values)

        # Detect on new data
        X_test = X_train.values[:20]
        predictions = detector.detect(X_test)

        assert len(predictions) == 20
        assert all(p in [0, 1] for p in predictions)


class TestEndToEndPipeline:
    """Test complete pipeline from ingestion to detection."""

    def test_complete_detection_pipeline(
        self,
        sample_generator,
        feature_extractor
    ):
        """
        Test complete pipeline:
        Data Generation → Feature Extraction → Model Training → Detection
        """
        # Step 1: Generate events
        events = sample_generator.generate_events(num_events=1000)
        assert len(events) == 1000

        # Step 2: Extract features
        features_df = feature_extractor.extract_features(
            events=events,
            window_size=50
        )

        if len(features_df) < 100:
            pytest.skip("Not enough features for pipeline test")

        # Step 3: Prepare data
        X = features_df.select_dtypes(include=['float64', 'int64']).fillna(0)

        if X.shape[1] == 0:
            pytest.skip("No numeric features available")

        # Step 4: Train detector
        detector = IsolationForestDetector(contamination=0.1)
        detector.train(X.values)

        # Step 5: Generate new events and detect
        new_events = sample_generator.generate_events(num_events=100)
        new_features = feature_extractor.extract_features(
            events=new_events,
            window_size=10
        )

        if len(new_features) == 0:
            pytest.skip("No features extracted from new events")

        X_new = new_features.select_dtypes(include=['float64', 'int64']).fillna(0)

        # Align columns with training data
        for col in X.columns:
            if col not in X_new.columns:
                X_new[col] = 0

        X_new = X_new[X.columns]

        # Detect anomalies
        predictions = detector.detect(X_new.values)

        # Verify pipeline completed successfully
        assert len(predictions) == len(X_new)
        assert all(p in [0, 1] for p in predictions)

        # Calculate detection metrics
        anomaly_count = sum(predictions)
        anomaly_rate = anomaly_count / len(predictions)

        print(f"\nPipeline Results:")
        print(f"  Events processed: {len(events) + len(new_events)}")
        print(f"  Features extracted: {X.shape[1]}")
        print(f"  Anomalies detected: {anomaly_count}/{len(predictions)}")
        print(f"  Anomaly rate: {anomaly_rate:.2%}")

    def test_user_behavioral_profiling_pipeline(
        self,
        sample_generator,
        feature_extractor
    ):
        """
        Test user behavioral profiling pipeline:
        Generate user events → Extract user features → Create baseline → Detect deviations
        """
        # Generate events for specific user
        events = sample_generator.generate_events(num_events=500)
        user_events = [e for e in events if e.user is not None]

        if len(user_events) < 50:
            pytest.skip("Not enough user events")

        # Group by user
        users = set(e.user for e in user_events)
        assert len(users) > 0

        # Pick one user for profiling
        target_user = list(users)[0]
        target_events = [e for e in user_events if e.user == target_user]

        if len(target_events) < 20:
            pytest.skip(f"Not enough events for user {target_user}")

        # Split into baseline and test periods
        split_point = int(len(target_events) * 0.7)
        baseline_events = target_events[:split_point]
        test_events = target_events[split_point:]

        # Extract features for baseline
        baseline_features = feature_extractor.extract_features(
            events=baseline_events,
            window_size=5
        )

        if len(baseline_features) == 0:
            pytest.skip("No baseline features extracted")

        # Extract features for test period
        test_features = feature_extractor.extract_features(
            events=test_events,
            window_size=5
        )

        if len(test_features) == 0:
            pytest.skip("No test features extracted")

        # Train on baseline
        detector = StatisticalDetector(methods=['zscore'], threshold=2.0)

        X_baseline = baseline_features.select_dtypes(include=['float64', 'int64']).fillna(0)
        if X_baseline.shape[1] == 0:
            pytest.skip("No numeric features in baseline")

        detector.train(X_baseline.values)

        # Detect deviations in test period
        X_test = test_features.select_dtypes(include=['float64', 'int64']).fillna(0)

        # Align columns
        for col in X_baseline.columns:
            if col not in X_test.columns:
                X_test[col] = 0
        X_test = X_test[X_baseline.columns]

        predictions = detector.detect(X_test.values)

        # Verify profiling pipeline worked
        assert len(predictions) == len(X_test)

        deviation_rate = sum(predictions) / len(predictions)
        print(f"\nUser Profiling Results for {target_user}:")
        print(f"  Baseline events: {len(baseline_events)}")
        print(f"  Test events: {len(test_events)}")
        print(f"  Behavioral deviations: {sum(predictions)}/{len(predictions)}")
        print(f"  Deviation rate: {deviation_rate:.2%}")


class TestPipelinePerformance:
    """Test pipeline performance and scalability."""

    @pytest.mark.slow
    def test_large_batch_processing(self, sample_generator, feature_extractor):
        """Test processing of large event batches."""
        import time

        # Generate large batch
        start_time = time.time()
        events = sample_generator.generate_events(num_events=10000)
        generation_time = time.time() - start_time

        # Extract features
        start_time = time.time()
        features_df = feature_extractor.extract_features(
            events=events,
            window_size=100
        )
        extraction_time = time.time() - start_time

        print(f"\nPerformance Metrics:")
        print(f"  Event generation: {generation_time:.2f}s ({10000/generation_time:.0f} events/s)")
        print(f"  Feature extraction: {extraction_time:.2f}s ({10000/extraction_time:.0f} events/s)")

        # Should complete in reasonable time
        assert generation_time < 10.0  # 10 seconds max
        assert extraction_time < 30.0  # 30 seconds max

    def test_detection_latency(self, feature_extractor, sample_generator):
        """Test detection latency for real-time requirements."""
        import time

        # Generate and prepare data
        events = sample_generator.generate_events(num_events=1000)
        features_df = feature_extractor.extract_features(events=events, window_size=50)

        if len(features_df) < 100:
            pytest.skip("Not enough features")

        X = features_df.select_dtypes(include=['float64', 'int64']).fillna(0)

        if X.shape[1] == 0:
            pytest.skip("No numeric features")

        # Train detector
        detector = IsolationForestDetector(contamination=0.1)
        detector.train(X.values)

        # Measure detection latency
        test_samples = X.values[:100]

        start_time = time.time()
        predictions = detector.detect(test_samples)
        detection_time = time.time() - start_time

        latency_per_sample = (detection_time / len(test_samples)) * 1000  # ms

        print(f"\nDetection Performance:")
        print(f"  Total time: {detection_time:.3f}s")
        print(f"  Latency per sample: {latency_per_sample:.2f}ms")
        print(f"  Throughput: {len(test_samples)/detection_time:.0f} predictions/s")

        # Should meet real-time requirements (<100ms per sample)
        assert latency_per_sample < 100.0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
