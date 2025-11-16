"""
Isolation Forest anomaly detection model.
Unsupervised algorithm for detecting outliers in high-dimensional data.
"""

import numpy as np
import pickle
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from loguru import logger


class IsolationForestDetector:
    """
    Isolation Forest-based anomaly detector.
    Achieves high accuracy with low false positive rates.
    """

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize Isolation Forest detector.

        Args:
            config: Configuration dictionary with hyperparameters
        """
        self.config = config or {}

        # Hyperparameters
        self.n_estimators = self.config.get('n_estimators', 200)
        self.max_samples = self.config.get('max_samples', 'auto')
        self.contamination = self.config.get('contamination', 0.02)  # 2% anomaly rate
        self.max_features = self.config.get('max_features', 1.0)
        self.bootstrap = self.config.get('bootstrap', False)
        self.n_jobs = self.config.get('n_jobs', -1)
        self.random_state = self.config.get('random_state', 42)

        # Model components
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names: List[str] = []
        self.training_metadata: Dict[str, Any] = {}

    def train(self, X: np.ndarray, feature_names: List[str] = None) -> Dict[str, Any]:
        """
        Train Isolation Forest model.

        Args:
            X: Training data (n_samples, n_features)
            feature_names: Optional feature names

        Returns:
            Training metadata and performance metrics
        """
        logger.info(f"Training Isolation Forest with {X.shape[0]} samples, {X.shape[1]} features")

        # Validate input
        if X.shape[0] < 100:
            logger.warning(f"Small training set ({X.shape[0]} samples), results may be unreliable")

        # Store feature names
        self.feature_names = feature_names or [f"feature_{i}" for i in range(X.shape[1])]

        # Scale features
        X_scaled = self.scaler.fit_transform(X)

        # Train Isolation Forest
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            max_samples=self.max_samples,
            contamination=self.contamination,
            max_features=self.max_features,
            bootstrap=self.bootstrap,
            n_jobs=self.n_jobs,
            random_state=self.random_state,
            verbose=0
        )

        self.model.fit(X_scaled)
        self.is_trained = True

        # Calculate training metrics
        predictions = self.model.predict(X_scaled)
        anomaly_count = (predictions == -1).sum()
        anomaly_rate = anomaly_count / len(predictions)

        # Get anomaly scores
        scores = self.model.score_samples(X_scaled)
        score_threshold = np.percentile(scores, self.contamination * 100)

        # Store metadata
        self.training_metadata = {
            'trained_at': datetime.utcnow(),
            'n_samples': X.shape[0],
            'n_features': X.shape[1],
            'n_estimators': self.n_estimators,
            'contamination': self.contamination,
            'anomaly_count': int(anomaly_count),
            'anomaly_rate': float(anomaly_rate),
            'score_threshold': float(score_threshold),
            'score_mean': float(scores.mean()),
            'score_std': float(scores.std())
        }

        logger.info(f"Training complete: {anomaly_count} anomalies detected ({anomaly_rate:.2%})")

        return self.training_metadata

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict anomalies in new data.

        Args:
            X: Input data (n_samples, n_features)

        Returns:
            Tuple of (predictions, anomaly_scores)
            predictions: -1 for anomalies, 1 for normal
            anomaly_scores: Normalized scores (0-1, higher = more anomalous)
        """
        if not self.is_trained:
            raise ValueError("Model not trained. Call train() first.")

        # Scale features
        X_scaled = self.scaler.transform(X)

        # Get predictions and scores
        predictions = self.model.predict(X_scaled)
        raw_scores = self.model.score_samples(X_scaled)

        # Normalize scores to 0-1 range (invert so higher = more anomalous)
        # Isolation Forest gives negative scores, more negative = more anomalous
        anomaly_scores = self._normalize_scores(raw_scores)

        return predictions, anomaly_scores

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
            List of anomaly dictionaries with details
        """
        predictions, scores = self.predict(X)

        anomalies = []
        for idx, (pred, score) in enumerate(zip(predictions, scores)):
            if score >= threshold:
                # Calculate feature contributions
                feature_importance = self._calculate_feature_importance(X[idx])

                anomalies.append({
                    'index': idx,
                    'anomaly_score': float(score),
                    'prediction': int(pred),
                    'is_anomaly': pred == -1,
                    'confidence': float(score),
                    'feature_importance': feature_importance
                })

        logger.info(f"Detected {len(anomalies)} anomalies (threshold: {threshold})")

        return anomalies

    def _normalize_scores(self, scores: np.ndarray) -> np.ndarray:
        """
        Normalize anomaly scores to 0-1 range.

        Args:
            scores: Raw Isolation Forest scores

        Returns:
            Normalized scores (0-1, higher = more anomalous)
        """
        # Invert scores (more negative = more anomalous)
        inverted_scores = -scores

        # Normalize to 0-1 using min-max scaling
        min_score = inverted_scores.min()
        max_score = inverted_scores.max()

        if max_score - min_score == 0:
            return np.zeros_like(scores)

        normalized = (inverted_scores - min_score) / (max_score - min_score)

        return normalized

    def _calculate_feature_importance(self, sample: np.ndarray) -> Dict[str, float]:
        """
        Calculate feature importance for a specific sample.

        Args:
            sample: Single sample feature vector

        Returns:
            Dictionary mapping feature names to importance scores
        """
        # Simplified feature importance based on deviation from mean
        # In production, could use SHAP values or other methods

        importance = {}

        sample_scaled = self.scaler.transform(sample.reshape(1, -1))[0]

        for idx, (feature_name, value) in enumerate(zip(self.feature_names, sample_scaled)):
            # Importance is absolute deviation from 0 (scaled mean)
            importance[feature_name] = abs(float(value))

        # Sort by importance
        importance = dict(sorted(importance.items(), key=lambda x: x[1], reverse=True))

        # Return top 10 features
        return dict(list(importance.items())[:10])

    def save(self, path: str) -> None:
        """
        Save model to disk.

        Args:
            path: Path to save model
        """
        if not self.is_trained:
            raise ValueError("Cannot save untrained model")

        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'training_metadata': self.training_metadata,
            'config': self.config
        }

        Path(path).parent.mkdir(parents=True, exist_ok=True)

        with open(path, 'wb') as f:
            pickle.dump(model_data, f)

        logger.info(f"Model saved to {path}")

    def load(self, path: str) -> None:
        """
        Load model from disk.

        Args:
            path: Path to saved model
        """
        with open(path, 'rb') as f:
            model_data = pickle.load(f)

        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_names = model_data['feature_names']
        self.training_metadata = model_data['training_metadata']
        self.config = model_data['config']
        self.is_trained = True

        logger.info(f"Model loaded from {path}")

    def get_model_info(self) -> Dict[str, Any]:
        """Get model information and metadata."""
        return {
            'model_type': 'isolation_forest',
            'is_trained': self.is_trained,
            'n_features': len(self.feature_names),
            'config': self.config,
            'training_metadata': self.training_metadata
        }
