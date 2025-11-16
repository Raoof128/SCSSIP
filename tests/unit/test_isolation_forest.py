"""Unit tests for Isolation Forest detector."""

import pytest
import numpy as np

from analytics.models.isolation_forest_detector import IsolationForestDetector


class TestIsolationForestDetector:
    """Test Isolation Forest anomaly detector."""

    @pytest.fixture
    def detector(self):
        """Create detector instance."""
        config = {
            'n_estimators': 100,
            'contamination': 0.02,
            'random_state': 42
        }
        return IsolationForestDetector(config)

    @pytest.fixture
    def training_data(self):
        """Create training data."""
        # Normal data (clustered)
        np.random.seed(42)
        normal = np.random.randn(200, 10)

        # Anomalies (far from cluster)
        anomalies = np.random.randn(4, 10) * 5 + 10

        X = np.vstack([normal, anomalies])
        return X

    def test_training(self, detector, training_data):
        """Test model training."""
        metadata = detector.train(training_data)

        assert detector.is_trained
        assert 'n_samples' in metadata
        assert metadata['n_samples'] == 204

    def test_prediction(self, detector, training_data):
        """Test anomaly prediction."""
        detector.train(training_data)

        # Test on new data
        test_data = np.random.randn(10, 10)
        predictions, scores = detector.predict(test_data)

        assert len(predictions) == 10
        assert len(scores) == 10
        assert all(pred in [-1, 1] for pred in predictions)
        assert all(0 <= score <= 1 for score in scores)

    def test_detect_anomalies(self, detector, training_data):
        """Test anomaly detection with details."""
        detector.train(training_data)

        anomalies = detector.detect_anomalies(training_data, threshold=0.95)

        assert isinstance(anomalies, list)
        assert all('anomaly_score' in a for a in anomalies)

    def test_save_load(self, detector, training_data, tmp_path):
        """Test model save and load."""
        detector.train(training_data)

        # Save model
        model_path = tmp_path / "model.pkl"
        detector.save(str(model_path))

        # Load into new detector
        new_detector = IsolationForestDetector()
        new_detector.load(str(model_path))

        assert new_detector.is_trained

        # Predictions should be similar
        test_data = np.random.randn(5, 10)
        pred1, scores1 = detector.predict(test_data)
        pred2, scores2 = new_detector.predict(test_data)

        assert np.array_equal(pred1, pred2)
