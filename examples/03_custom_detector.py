"""
Example 3: Creating a Custom Anomaly Detector

This example demonstrates:
- Creating a custom anomaly detector
- Implementing the detector interface
- Integrating with the platform
- Using ensemble detection with custom models

Requirements:
- Understanding of Python classes and inheritance
- Basic knowledge of machine learning concepts
"""

from typing import List, Dict, Any
import numpy as np
from sklearn.preprocessing import StandardScaler

from src.analytics.models.base_detector import BaseDetector
from src.data_ingestion.adapters.sample_data_generator import SampleDataGenerator
from src.analytics.feature_extractor import FeatureExtractor


class SimpleThresholdDetector(BaseDetector):
    """
    Custom anomaly detector using simple threshold-based rules.

    This detector identifies anomalies based on configurable thresholds
    for specific features. Useful for known attack patterns.
    """

    def __init__(self, thresholds: Dict[str, float] = None):
        """
        Initialize the threshold detector.

        Args:
            thresholds: Dictionary mapping feature names to threshold values
        """
        super().__init__()
        self.thresholds = thresholds or {
            'failed_auth_count': 5,
            'unique_ips_count': 10,
            'off_hours_count': 3
        }
        self.scaler = StandardScaler()
        self.feature_names = None

    def train(self, X: np.ndarray, y: np.ndarray = None) -> None:
        """
        Train the detector (learns data distribution for normalization).

        Args:
            X: Training feature matrix
            y: Optional labels (not used for unsupervised detection)
        """
        # Fit scaler to learn feature distributions
        self.scaler.fit(X)
        self._is_trained = True
        print(f"✓ Threshold detector trained on {len(X)} samples")

    def detect(self, X: np.ndarray) -> np.ndarray:
        """
        Detect anomalies using threshold rules.

        Args:
            X: Feature matrix to analyze

        Returns:
            Array of predictions (1 = anomaly, 0 = normal)
        """
        if not self.is_trained():
            raise ValueError("Detector must be trained before detection")

        predictions = np.zeros(len(X), dtype=int)

        # Normalize features
        X_scaled = self.scaler.transform(X)

        # Apply threshold rules
        for i, sample in enumerate(X_scaled):
            # Check if any feature exceeds its threshold
            anomaly_score = 0

            # Simple rule: if multiple features are unusual, flag as anomaly
            unusual_features = np.abs(sample) > 2.0  # 2 standard deviations
            if np.sum(unusual_features) >= 2:
                anomaly_score = 1

            predictions[i] = anomaly_score

        return predictions

    def get_anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        """
        Get anomaly scores (number of unusual features).

        Args:
            X: Feature matrix

        Returns:
            Array of anomaly scores
        """
        if not self.is_trained():
            raise ValueError("Detector must be trained before scoring")

        X_scaled = self.scaler.transform(X)

        # Score based on number of features beyond threshold
        scores = np.sum(np.abs(X_scaled) > 2.0, axis=1) / X_scaled.shape[1]

        return scores


class AdvancedFrequencyDetector(BaseDetector):
    """
    Advanced detector based on frequency analysis.

    Identifies anomalies based on rare or unusual event patterns.
    """

    def __init__(self, rare_threshold: float = 0.01):
        """
        Initialize frequency detector.

        Args:
            rare_threshold: Threshold for considering a pattern rare
        """
        super().__init__()
        self.rare_threshold = rare_threshold
        self.frequency_baselines = {}

    def train(self, X: np.ndarray, y: np.ndarray = None) -> None:
        """Train by building frequency baselines for each feature."""
        # Calculate frequency distributions for each feature
        for feature_idx in range(X.shape[1]):
            feature_values = X[:, feature_idx]

            # Calculate value frequencies
            unique_values, counts = np.unique(feature_values, return_counts=True)
            frequencies = counts / len(feature_values)

            # Store baseline
            self.frequency_baselines[feature_idx] = {
                'values': unique_values,
                'frequencies': frequencies
            }

        self._is_trained = True
        print(f"✓ Frequency detector trained on {len(X)} samples")

    def detect(self, X: np.ndarray) -> np.ndarray:
        """Detect anomalies based on rare patterns."""
        if not self.is_trained():
            raise ValueError("Detector must be trained before detection")

        predictions = np.zeros(len(X), dtype=int)

        for i, sample in enumerate(X):
            rare_feature_count = 0

            # Check each feature
            for feature_idx in range(len(sample)):
                value = sample[feature_idx]
                baseline = self.frequency_baselines[feature_idx]

                # Find value frequency in baseline
                value_freq = 0.0
                if value in baseline['values']:
                    idx = np.where(baseline['values'] == value)[0][0]
                    value_freq = baseline['frequencies'][idx]

                # If value is rare, count it
                if value_freq < self.rare_threshold:
                    rare_feature_count += 1

            # If multiple rare features, flag as anomaly
            if rare_feature_count >= 2:
                predictions[i] = 1

        return predictions

    def get_anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        """Get anomaly scores based on rarity."""
        if not self.is_trained():
            raise ValueError("Detector must be trained before scoring")

        scores = np.zeros(len(X))

        for i, sample in enumerate(X):
            rarity_scores = []

            for feature_idx in range(len(sample)):
                value = sample[feature_idx]
                baseline = self.frequency_baselines[feature_idx]

                # Calculate rarity score (1 - frequency)
                if value in baseline['values']:
                    idx = np.where(baseline['values'] == value)[0][0]
                    freq = baseline['frequencies'][idx]
                    rarity = 1.0 - freq
                else:
                    rarity = 1.0  # Completely unseen value

                rarity_scores.append(rarity)

            # Average rarity across features
            scores[i] = np.mean(rarity_scores)

        return scores


def demonstrate_custom_detectors():
    """Demonstrate usage of custom detectors."""
    print("="*70)
    print("Custom Anomaly Detector Examples")
    print("="*70)

    # Generate sample data
    print("\n[1] Generating sample data...")
    generator = SampleDataGenerator()
    events = generator.generate_events(num_events=1000)
    print(f"✓ Generated {len(events)} events")

    # Extract features
    print("\n[2] Extracting features...")
    extractor = FeatureExtractor()
    features_df = extractor.extract_features(events, window_size=50)
    X = features_df.select_dtypes(include=['float64', 'int64']).fillna(0)
    print(f"✓ Extracted {X.shape[1]} features from {X.shape[0]} samples")

    # Split data
    split_point = int(len(X) * 0.7)
    X_train = X.iloc[:split_point]
    X_test = X.iloc[split_point:]

    # Test Simple Threshold Detector
    print("\n[3] Testing Simple Threshold Detector...")
    threshold_detector = SimpleThresholdDetector()
    threshold_detector.train(X_train.values)

    predictions = threshold_detector.detect(X_test.values)
    scores = threshold_detector.get_anomaly_scores(X_test.values)

    anomaly_count = np.sum(predictions)
    print(f"  Anomalies detected: {anomaly_count}/{len(predictions)}")
    print(f"  Average anomaly score: {np.mean(scores):.4f}")

    # Test Advanced Frequency Detector
    print("\n[4] Testing Advanced Frequency Detector...")
    freq_detector = AdvancedFrequencyDetector(rare_threshold=0.05)
    freq_detector.train(X_train.values)

    predictions = freq_detector.detect(X_test.values)
    scores = freq_detector.get_anomaly_scores(X_test.values)

    anomaly_count = np.sum(predictions)
    print(f"  Anomalies detected: {anomaly_count}/{len(predictions)}")
    print(f"  Average rarity score: {np.mean(scores):.4f}")

    # Compare detectors
    print("\n[5] Comparing detector performance...")
    print("\n  Detector          | Anomalies | Avg Score")
    print("  " + "-"*50)

    for detector_name, detector in [
        ("Threshold", threshold_detector),
        ("Frequency", freq_detector)
    ]:
        preds = detector.detect(X_test.values)
        scores = detector.get_anomaly_scores(X_test.values)
        count = np.sum(preds)
        avg_score = np.mean(scores)
        print(f"  {detector_name:16} | {count:9} | {avg_score:9.4f}")

    print("\n" + "="*70)
    print("Custom Detector Examples Completed")
    print("="*70)

    print("\nKey Takeaways:")
    print("  • Custom detectors extend BaseDetector class")
    print("  • Implement train() and detect() methods")
    print("  • Can be combined with existing detectors in ensembles")
    print("  • Useful for domain-specific detection logic")

    print("\nNext steps:")
    print("  1. Implement your own detector for specific attack types")
    print("  2. Tune threshold values based on your environment")
    print("  3. Combine custom detectors with ML models for better results")
    print("  4. Integrate with the ensemble detector for production use")


if __name__ == "__main__":
    demonstrate_custom_detectors()
