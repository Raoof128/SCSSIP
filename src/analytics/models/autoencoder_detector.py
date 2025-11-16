"""
Autoencoder-based anomaly detection model.
Deep learning approach for detecting complex behavioral patterns.
"""

import numpy as np
import pickle
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from loguru import logger

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers, Model
    from tensorflow.keras.callbacks import EarlyStopping
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False
    logger.warning("TensorFlow not available, Autoencoder detector disabled")


class AutoencoderDetector:
    """
    Autoencoder-based anomaly detector.
    Uses reconstruction error to identify anomalies.
    """

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize Autoencoder detector.

        Args:
            config: Configuration dictionary
        """
        if not TF_AVAILABLE:
            raise ImportError("TensorFlow required for Autoencoder detector")

        self.config = config or {}

        # Hyperparameters
        self.input_dim = self.config.get('input_dim', 50)
        self.encoding_dims = self.config.get('encoding_dims', [128, 64, 32])
        self.activation = self.config.get('activation', 'relu')
        self.optimizer = self.config.get('optimizer', 'adam')
        self.loss = self.config.get('loss', 'mse')
        self.epochs = self.config.get('epochs', 50)
        self.batch_size = self.config.get('batch_size', 256)
        self.validation_split = self.config.get('validation_split', 0.2)

        # Model components
        self.model: Optional[Model] = None
        self.is_trained = False
        self.feature_names: List[str] = []
        self.training_metadata: Dict[str, Any] = {}
        self.reconstruction_threshold: float = 0.0

    def _build_model(self, input_dim: int) -> Model:
        """
        Build autoencoder architecture.

        Args:
            input_dim: Input dimension

        Returns:
            Keras Model
        """
        # Input layer
        input_layer = layers.Input(shape=(input_dim,))

        # Encoder
        encoded = input_layer
        for dim in self.encoding_dims:
            encoded = layers.Dense(dim, activation=self.activation)(encoded)

        # Decoder (mirror of encoder)
        decoded = encoded
        for dim in reversed(self.encoding_dims[:-1]):
            decoded = layers.Dense(dim, activation=self.activation)(decoded)

        # Output layer (reconstruct input)
        output_layer = layers.Dense(input_dim, activation='linear')(decoded)

        # Create model
        model = Model(inputs=input_layer, outputs=output_layer)
        model.compile(optimizer=self.optimizer, loss=self.loss)

        return model

    def train(self, X: np.ndarray, feature_names: List[str] = None) -> Dict[str, Any]:
        """
        Train Autoencoder model.

        Args:
            X: Training data (n_samples, n_features)
            feature_names: Optional feature names

        Returns:
            Training metadata and performance metrics
        """
        logger.info(f"Training Autoencoder with {X.shape[0]} samples, {X.shape[1]} features")

        # Validate input
        if X.shape[0] < 1000:
            logger.warning(f"Small training set ({X.shape[0]} samples) for deep learning")

        # Store feature names
        self.feature_names = feature_names or [f"feature_{i}" for i in range(X.shape[1])]
        self.input_dim = X.shape[1]

        # Normalize data
        self.mean = X.mean(axis=0)
        self.std = X.std(axis=0) + 1e-10
        X_normalized = (X - self.mean) / self.std

        # Build model
        self.model = self._build_model(self.input_dim)

        # Early stopping to prevent overfitting
        early_stop = EarlyStopping(
            monitor='val_loss',
            patience=5,
            restore_best_weights=True
        )

        # Train model
        history = self.model.fit(
            X_normalized,
            X_normalized,
            epochs=self.epochs,
            batch_size=self.batch_size,
            validation_split=self.validation_split,
            callbacks=[early_stop],
            verbose=0
        )

        self.is_trained = True

        # Calculate reconstruction errors on training data
        X_reconstructed = self.model.predict(X_normalized, verbose=0)
        reconstruction_errors = np.mean(np.square(X_normalized - X_reconstructed), axis=1)

        # Set threshold at 95th percentile of training errors
        self.reconstruction_threshold = np.percentile(reconstruction_errors, 95)

        # Calculate metrics
        final_train_loss = history.history['loss'][-1]
        final_val_loss = history.history['val_loss'][-1]

        # Store metadata
        self.training_metadata = {
            'trained_at': datetime.utcnow(),
            'n_samples': X.shape[0],
            'n_features': X.shape[1],
            'epochs_trained': len(history.history['loss']),
            'final_train_loss': float(final_train_loss),
            'final_val_loss': float(final_val_loss),
            'reconstruction_threshold': float(self.reconstruction_threshold),
            'encoding_dims': self.encoding_dims
        }

        logger.info(f"Training complete: val_loss={final_val_loss:.4f}, threshold={self.reconstruction_threshold:.4f}")

        return self.training_metadata

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict anomalies in new data.

        Args:
            X: Input data (n_samples, n_features)

        Returns:
            Tuple of (predictions, anomaly_scores)
        """
        if not self.is_trained:
            raise ValueError("Model not trained. Call train() first.")

        # Normalize
        X_normalized = (X - self.mean) / self.std

        # Get reconstructions
        X_reconstructed = self.model.predict(X_normalized, verbose=0)

        # Calculate reconstruction errors
        reconstruction_errors = np.mean(np.square(X_normalized - X_reconstructed), axis=1)

        # Predictions: -1 for anomaly, 1 for normal
        predictions = np.where(reconstruction_errors > self.reconstruction_threshold, -1, 1)

        # Normalize scores to 0-1 range
        anomaly_scores = self._normalize_scores(reconstruction_errors)

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
            List of anomaly dictionaries
        """
        predictions, scores = self.predict(X)

        # Normalize
        X_normalized = (X - self.mean) / self.std
        X_reconstructed = self.model.predict(X_normalized, verbose=0)

        anomalies = []
        for idx, (pred, score) in enumerate(zip(predictions, scores)):
            if score >= threshold:
                # Calculate per-feature reconstruction errors
                feature_errors = np.square(X_normalized[idx] - X_reconstructed[idx])
                feature_importance = self._calculate_feature_importance(feature_errors)

                anomalies.append({
                    'index': idx,
                    'anomaly_score': float(score),
                    'prediction': int(pred),
                    'is_anomaly': pred == -1,
                    'confidence': float(score),
                    'feature_importance': feature_importance,
                    'reconstruction_error': float(feature_errors.mean())
                })

        logger.info(f"Detected {len(anomalies)} anomalies (threshold: {threshold})")

        return anomalies

    def _normalize_scores(self, errors: np.ndarray) -> np.ndarray:
        """Normalize reconstruction errors to 0-1 range."""
        # Clip extreme values
        errors_clipped = np.clip(errors, 0, self.reconstruction_threshold * 3)

        # Normalize
        max_error = errors_clipped.max()
        if max_error == 0:
            return np.zeros_like(errors)

        normalized = errors_clipped / max_error

        return normalized

    def _calculate_feature_importance(self, feature_errors: np.ndarray) -> Dict[str, float]:
        """Calculate feature importance based on reconstruction error."""
        importance = {}

        for feature_name, error in zip(self.feature_names, feature_errors):
            importance[feature_name] = float(error)

        # Sort and return top 10
        importance = dict(sorted(importance.items(), key=lambda x: x[1], reverse=True))
        return dict(list(importance.items())[:10])

    def save(self, path: str) -> None:
        """Save model to disk."""
        if not self.is_trained:
            raise ValueError("Cannot save untrained model")

        Path(path).parent.mkdir(parents=True, exist_ok=True)

        # Save Keras model
        model_path = Path(path).with_suffix('.h5')
        self.model.save(model_path)

        # Save metadata
        metadata = {
            'mean': self.mean,
            'std': self.std,
            'feature_names': self.feature_names,
            'training_metadata': self.training_metadata,
            'reconstruction_threshold': self.reconstruction_threshold,
            'config': self.config
        }

        metadata_path = Path(path).with_suffix('.pkl')
        with open(metadata_path, 'wb') as f:
            pickle.dump(metadata, f)

        logger.info(f"Model saved to {path}")

    def load(self, path: str) -> None:
        """Load model from disk."""
        # Load Keras model
        model_path = Path(path).with_suffix('.h5')
        self.model = keras.models.load_model(model_path)

        # Load metadata
        metadata_path = Path(path).with_suffix('.pkl')
        with open(metadata_path, 'rb') as f:
            metadata = pickle.load(f)

        self.mean = metadata['mean']
        self.std = metadata['std']
        self.feature_names = metadata['feature_names']
        self.training_metadata = metadata['training_metadata']
        self.reconstruction_threshold = metadata['reconstruction_threshold']
        self.config = metadata['config']
        self.is_trained = True

        logger.info(f"Model loaded from {path}")

    def get_model_info(self) -> Dict[str, Any]:
        """Get model information."""
        return {
            'model_type': 'autoencoder',
            'is_trained': self.is_trained,
            'n_features': len(self.feature_names),
            'config': self.config,
            'training_metadata': self.training_metadata
        }
