"""Performance benchmarks for threat hunting platform."""

import pytest
import numpy as np
from datetime import datetime, timedelta

from src.analytics.feature_extractor import FeatureExtractor
from src.analytics.models.isolation_forest_detector import IsolationForestDetector
from src.analytics.models.ensemble_detector import EnsembleDetector
from src.data_ingestion.adapters.base_adapter import SecurityEvent, EventType


class TestPerformanceBenchmarks:
    """Performance benchmarks for platform components."""

    @pytest.fixture
    def large_dataset(self):
        """Create large dataset for benchmarking."""
        np.random.seed(42)
        return np.random.randn(10000, 50)

    @pytest.fixture
    def many_events(self):
        """Create many security events."""
        events = []
        base_time = datetime.utcnow()

        for i in range(1000):
            event = SecurityEvent(
                timestamp=base_time - timedelta(seconds=i),
                event_type=EventType.NETWORK,
                source_system='test',
                raw_data={},
                source_ip=f'10.0.{i % 255}.{i % 100}',
                bytes_sent=np.random.randint(100, 100000)
            )
            events.append(event)

        return events

    def test_feature_extraction_performance(self, benchmark, many_events):
        """Benchmark feature extraction."""
        extractor = FeatureExtractor()

        result = benchmark(extractor.extract_features, many_events, 'test', 'user')

        assert result.shape[0] > 0

    def test_isolation_forest_training_performance(self, benchmark, large_dataset):
        """Benchmark Isolation Forest training."""
        detector = IsolationForestDetector()

        benchmark(detector.train, large_dataset)

        assert detector.is_trained

    def test_isolation_forest_prediction_performance(self, benchmark, large_dataset):
        """Benchmark Isolation Forest prediction."""
        detector = IsolationForestDetector()
        detector.train(large_dataset[:5000])  # Train on half

        test_data = large_dataset[5000:6000]  # Test on 1000 samples

        predictions, scores = benchmark(detector.predict, test_data)

        assert len(predictions) == 1000

    def test_ensemble_prediction_performance(self, benchmark, large_dataset):
        """Benchmark ensemble prediction."""
        config = {
            'voting_strategy': 'weighted',
            'isolation_forest': {'enabled': True},
            'statistical': {'enabled': True},
            'autoencoder': {'enabled': False}  # Disable for speed
        }

        detector = EnsembleDetector(config)
        detector.train(large_dataset[:5000])

        test_data = large_dataset[5000:6000]

        predictions, scores = benchmark(detector.predict, test_data)

        assert len(predictions) == 1000


class TestThroughputBenchmarks:
    """Throughput benchmarks."""

    def test_event_processing_throughput(self, benchmark):
        """Measure events processed per second."""
        extractor = FeatureExtractor()

        # Create 100 events
        events = []
        for i in range(100):
            event = SecurityEvent(
                timestamp=datetime.utcnow(),
                event_type=EventType.NETWORK,
                source_system='test',
                raw_data={}
            )
            events.append(event)

        benchmark(extractor.extract_features, events, 'test', 'user')

    def test_anomaly_detection_latency(self, benchmark):
        """Measure anomaly detection latency."""
        detector = IsolationForestDetector()

        # Train
        train_data = np.random.randn(1000, 50)
        detector.train(train_data)

        # Single sample detection
        sample = np.random.randn(1, 50)

        predictions, scores = benchmark(detector.predict, sample)

        # Target: sub-second latency
        assert benchmark.stats.stats.mean < 1.0  # <1 second
