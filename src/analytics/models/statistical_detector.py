"""
Statistical baseline anomaly detection.
Uses z-scores, IQR, and time-series analysis for anomaly detection.
"""

import numpy as np
import pickle
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from scipy import stats
from loguru import logger


class StatisticalDetector:
    """
    Statistical baseline anomaly detector.
    Combines multiple statistical methods for robust detection.
    """

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize Statistical detector.

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}

        # Configuration
        self.methods = self.config.get('methods', ['z_score', 'modified_z_score', 'iqr'])
        self.confidence_level = self.config.get('confidence_level', 0.99)
        self.iqr_multiplier = self.config.get('iqr_multiplier', 1.5)

        # Baseline statistics
        self.mean: Optional[np.ndarray] = None
        self.std: Optional[np.ndarray] = None
        self.median: Optional[np.ndarray] = None
        self.mad: Optional[np.ndarray] = None  # Median Absolute Deviation
        self.q1: Optional[np.ndarray] = None  # First quartile
        self.q3: Optional[np.ndarray] = None  # Third quartile

        self.is_trained = False
        self.feature_names: List[str] = []
        self.training_metadata: Dict[str, Any] = {}

    def train(self, X: np.ndarray, feature_names: List[str] = None) -> Dict[str, Any]:
        """
        Calculate baseline statistics.

        Args:
            X: Training data (n_samples, n_features)
            feature_names: Optional feature names

        Returns:
            Training metadata
        """
        logger.info(f"Training Statistical detector with {X.shape[0]} samples, {X.shape[1]} features")

        if X.shape[0] < 30:
            logger.warning(f"Small training set ({X.shape[0]} samples), statistical methods may be unreliable")

        # Store feature names
        self.feature_names = feature_names or [f"feature_{i}" for i in range(X.shape[1])]

        # Calculate baseline statistics
        self.mean = X.mean(axis=0)
        self.std = X.std(axis=0) + 1e-10  # Add small constant to avoid division by zero
        self.median = np.median(X, axis=0)
        self.mad = np.median(np.abs(X - self.median), axis=0) + 1e-10
        self.q1 = np.percentile(X, 25, axis=0)
        self.q3 = np.percentile(X, 75, axis=0)

        self.is_trained = True

        # Calculate z-score threshold based on confidence level
        z_threshold = stats.norm.ppf((1 + self.confidence_level) / 2)

        # Store metadata
        self.training_metadata = {
            'trained_at': datetime.utcnow(),
            'n_samples': X.shape[0],
            'n_features': X.shape[1],
            'methods': self.methods,
            'confidence_level': self.confidence_level,
            'z_threshold': float(z_threshold)
        }

        logger.info(f"Training complete: z_threshold={z_threshold:.2f} for {self.confidence_level} confidence")

        return self.training_metadata

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict anomalies using statistical methods.

        Args:
            X: Input data (n_samples, n_features)

        Returns:
            Tuple of (predictions, anomaly_scores)
        """
        if not self.is_trained:
            raise ValueError("Model not trained. Call train() first.")

        # Collect anomaly indicators from different methods
        method_predictions = []
        method_scores = []

        if 'z_score' in self.methods:
            z_pred, z_scores = self._z_score_method(X)
            method_predictions.append(z_pred)
            method_scores.append(z_scores)

        if 'modified_z_score' in self.methods:
            mz_pred, mz_scores = self._modified_z_score_method(X)
            method_predictions.append(mz_pred)
            method_scores.append(mz_scores)

        if 'iqr' in self.methods:
            iqr_pred, iqr_scores = self._iqr_method(X)
            method_predictions.append(iqr_pred)
            method_scores.append(iqr_scores)

        if 'grubbs_test' in self.methods and X.shape[0] < 1000:  # Grubbs only for small samples
            grubbs_pred, grubbs_scores = self._grubbs_test(X)
            method_predictions.append(grubbs_pred)
            method_scores.append(grubbs_scores)

        # Combine predictions (voting)
        method_predictions = np.array(method_predictions)
        method_scores = np.array(method_scores)

        # Anomaly if majority of methods agree
        predictions = np.where(np.mean(method_predictions == -1, axis=0) >= 0.5, -1, 1)

        # Average scores across methods
        anomaly_scores = np.mean(method_scores, axis=0)

        return predictions, anomaly_scores

    def _z_score_method(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Z-score method for anomaly detection.

        Args:
            X: Input data

        Returns:
            Tuple of (predictions, scores)
        """
        # Calculate z-scores
        z_scores = np.abs((X - self.mean) / self.std)

        # Maximum z-score across features
        max_z_scores = np.max(z_scores, axis=1)

        # Threshold based on confidence level
        z_threshold = stats.norm.ppf((1 + self.confidence_level) / 2)

        # Predictions
        predictions = np.where(max_z_scores > z_threshold, -1, 1)

        # Normalize scores to 0-1
        scores = np.clip(max_z_scores / (z_threshold * 2), 0, 1)

        return predictions, scores

    def _modified_z_score_method(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Modified z-score using MAD (more robust to outliers).

        Args:
            X: Input data

        Returns:
            Tuple of (predictions, scores)
        """
        # Modified z-scores using median and MAD
        modified_z_scores = 0.6745 * np.abs((X - self.median) / self.mad)

        # Maximum modified z-score across features
        max_modified_z = np.max(modified_z_scores, axis=1)

        # Threshold (typically 3.5 for modified z-score)
        threshold = 3.5

        # Predictions
        predictions = np.where(max_modified_z > threshold, -1, 1)

        # Normalize scores
        scores = np.clip(max_modified_z / (threshold * 2), 0, 1)

        return predictions, scores

    def _iqr_method(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Interquartile Range (IQR) method.

        Args:
            X: Input data

        Returns:
            Tuple of (predictions, scores)
        """
        # Calculate IQR
        iqr = self.q3 - self.q1

        # Define bounds
        lower_bound = self.q1 - self.iqr_multiplier * iqr
        upper_bound = self.q3 + self.iqr_multiplier * iqr

        # Check if values are outside bounds
        outliers = (X < lower_bound) | (X > upper_bound)

        # Count outlier features per sample
        outlier_counts = np.sum(outliers, axis=1)

        # Predictions (anomaly if >10% features are outliers)
        predictions = np.where(outlier_counts > 0.1 * X.shape[1], -1, 1)

        # Calculate distance from bounds for score
        distances_lower = np.maximum(0, lower_bound - X)
        distances_upper = np.maximum(0, X - upper_bound)
        distances = np.maximum(distances_lower, distances_upper)

        # Normalize by IQR
        normalized_distances = distances / (iqr + 1e-10)
        max_distances = np.max(normalized_distances, axis=1)

        # Normalize scores to 0-1
        scores = np.clip(max_distances / (self.iqr_multiplier * 2), 0, 1)

        return predictions, scores

    def _grubbs_test(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Grubbs' test for outliers (works best on small samples).

        Args:
            X: Input data

        Returns:
            Tuple of (predictions, scores)
        """
        # Simplified Grubbs test on maximum z-scores
        z_scores = np.abs((X - self.mean) / self.std)
        max_z_scores = np.max(z_scores, axis=1)

        # Grubbs statistic
        n = len(max_z_scores)
        t_dist = stats.t.ppf(1 - 0.05 / (2 * n), n - 2)
        grubbs_threshold = ((n - 1) / np.sqrt(n)) * np.sqrt(t_dist**2 / (n - 2 + t_dist**2))

        # Predictions
        predictions = np.where(max_z_scores > grubbs_threshold, -1, 1)

        # Scores
        scores = np.clip(max_z_scores / (grubbs_threshold * 2), 0, 1)

        return predictions, scores

    def detect_anomalies(
        self,
        X: np.ndarray,
        threshold: float = 0.95
    ) -> List[Dict[str, Any]]:
        """
        Detect anomalies with detailed information.

        Args:
            X: Input data (n_samples, n_features)
            threshold: Anomaly score threshold (0-1)

        Returns:
            List of anomaly dictionaries
        """
        predictions, scores = self.predict(X)

        anomalies = []
        for idx, (pred, score) in enumerate(zip(predictions, scores)):
            if score >= threshold:
                # Calculate per-feature deviations
                feature_deviations = self._calculate_feature_deviations(X[idx])

                anomalies.append({
                    'index': idx,
                    'anomaly_score': float(score),
                    'prediction': int(pred),
                    'is_anomaly': pred == -1,
                    'confidence': float(score),
                    'feature_importance': feature_deviations,
                    'methods_triggered': self._get_triggered_methods(X[idx])
                })

        logger.info(f"Detected {len(anomalies)} anomalies (threshold: {threshold})")

        return anomalies

    def _calculate_feature_deviations(self, sample: np.ndarray) -> Dict[str, float]:
        """Calculate feature-wise deviations from baseline."""
        deviations = {}

        z_scores = np.abs((sample - self.mean) / self.std)

        for feature_name, z_score in zip(self.feature_names, z_scores):
            deviations[feature_name] = float(z_score)

        # Sort and return top 10
        deviations = dict(sorted(deviations.items(), key=lambda x: x[1], reverse=True))
        return dict(list(deviations.items())[:10])

    def _get_triggered_methods(self, sample: np.ndarray) -> List[str]:
        """Get list of methods that flagged this sample as anomaly."""
        triggered = []

        sample_reshaped = sample.reshape(1, -1)

        if 'z_score' in self.methods:
            pred, _ = self._z_score_method(sample_reshaped)
            if pred[0] == -1:
                triggered.append('z_score')

        if 'modified_z_score' in self.methods:
            pred, _ = self._modified_z_score_method(sample_reshaped)
            if pred[0] == -1:
                triggered.append('modified_z_score')

        if 'iqr' in self.methods:
            pred, _ = self._iqr_method(sample_reshaped)
            if pred[0] == -1:
                triggered.append('iqr')

        return triggered

    def save(self, path: str) -> None:
        """Save model to disk."""
        if not self.is_trained:
            raise ValueError("Cannot save untrained model")

        model_data = {
            'mean': self.mean,
            'std': self.std,
            'median': self.median,
            'mad': self.mad,
            'q1': self.q1,
            'q3': self.q3,
            'feature_names': self.feature_names,
            'training_metadata': self.training_metadata,
            'config': self.config
        }

        Path(path).parent.mkdir(parents=True, exist_ok=True)

        with open(path, 'wb') as f:
            pickle.dump(model_data, f)

        logger.info(f"Model saved to {path}")

    def load(self, path: str) -> None:
        """Load model from disk."""
        with open(path, 'rb') as f:
            model_data = pickle.load(f)

        self.mean = model_data['mean']
        self.std = model_data['std']
        self.median = model_data['median']
        self.mad = model_data['mad']
        self.q1 = model_data['q1']
        self.q3 = model_data['q3']
        self.feature_names = model_data['feature_names']
        self.training_metadata = model_data['training_metadata']
        self.config = model_data['config']
        self.is_trained = True

        logger.info(f"Model loaded from {path}")

    def get_model_info(self) -> Dict[str, Any]:
        """Get model information."""
        return {
            'model_type': 'statistical',
            'is_trained': self.is_trained,
            'n_features': len(self.feature_names),
            'config': self.config,
            'training_metadata': self.training_metadata
        }
