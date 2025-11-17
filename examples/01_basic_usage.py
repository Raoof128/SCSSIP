"""
Example 1: Basic Usage - Generating Sample Data and Detecting Anomalies

This example demonstrates:
- Generating sample security events
- Extracting features from events
- Training an anomaly detection model
- Detecting anomalies in new data

Requirements:
- Install dependencies: pip install -r requirements.txt
"""

from datetime import datetime
from src.data_ingestion.adapters.sample_data_generator import SampleDataGenerator
from src.analytics.feature_extractor import FeatureExtractor
from src.analytics.models.isolation_forest_detector import IsolationForestDetector


def main():
    print("="*70)
    print("Advanced Threat Hunting Platform - Basic Usage Example")
    print("="*70)

    # Step 1: Generate sample security events
    print("\n[1] Generating sample security events...")
    generator = SampleDataGenerator()
    events = generator.generate_events(num_events=1000)
    print(f"✓ Generated {len(events)} security events")

    # Display first few events
    print("\nSample events:")
    for event in events[:3]:
        print(f"  - {event.timestamp} | {event.event_type.value} | "
              f"User: {event.user} | Severity: {event.severity}")

    # Step 2: Extract behavioral features
    print("\n[2] Extracting behavioral features...")
    extractor = FeatureExtractor()
    features_df = extractor.extract_features(events, window_size=50)
    print(f"✓ Extracted features: {features_df.shape}")
    print(f"  - Samples: {features_df.shape[0]}")
    print(f"  - Features: {features_df.shape[1]}")

    # Display feature names
    print("\nTop features extracted:")
    for feature in list(features_df.columns)[:5]:
        print(f"  - {feature}")

    # Step 3: Prepare data for training
    print("\n[3] Preparing data for machine learning...")
    X = features_df.select_dtypes(include=['float64', 'int64']).fillna(0)
    print(f"✓ Training data shape: {X.shape}")

    # Split into train/test
    split_point = int(len(X) * 0.7)
    X_train = X.iloc[:split_point]
    X_test = X.iloc[split_point:]
    print(f"  - Training samples: {len(X_train)}")
    print(f"  - Testing samples: {len(X_test)}")

    # Step 4: Train anomaly detector
    print("\n[4] Training Isolation Forest anomaly detector...")
    detector = IsolationForestDetector(
        contamination=0.1,  # Expect 10% anomalies
        n_estimators=100,
        random_state=42
    )
    detector.train(X_train.values)
    print("✓ Model trained successfully")

    # Step 5: Detect anomalies
    print("\n[5] Detecting anomalies in test data...")
    predictions = detector.detect(X_test.values)
    anomaly_scores = detector.get_anomaly_scores(X_test.values)

    # Calculate metrics
    num_anomalies = sum(predictions)
    anomaly_rate = (num_anomalies / len(predictions)) * 100

    print(f"✓ Detection complete")
    print(f"  - Anomalies detected: {num_anomalies}/{len(predictions)}")
    print(f"  - Anomaly rate: {anomaly_rate:.2f}%")

    # Display top anomalies
    print("\nTop 5 anomalies (by score):")
    import numpy as np
    top_indices = np.argsort(anomaly_scores)[:5]

    for i, idx in enumerate(top_indices, 1):
        score = anomaly_scores[idx]
        print(f"  {i}. Sample {idx} - Anomaly score: {score:.4f}")

    # Step 6: Get feature importance
    print("\n[6] Analyzing feature importance...")
    feature_importance = detector.get_feature_importance()

    if feature_importance is not None and len(feature_importance) > 0:
        print("Top 10 most important features:")
        sorted_features = sorted(
            feature_importance.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]

        for feature, importance in sorted_features:
            print(f"  - {feature}: {importance:.4f}")
    else:
        print("  (Feature importance not available for this model)")

    # Step 7: Save model
    print("\n[7] Saving trained model...")
    model_path = "models/trained/example_isolation_forest.pkl"
    detector.save_model(model_path)
    print(f"✓ Model saved to: {model_path}")

    print("\n" + "="*70)
    print("Example completed successfully!")
    print("="*70)

    # Summary
    print("\nSummary:")
    print(f"  • Processed {len(events)} security events")
    print(f"  • Extracted {X.shape[1]} behavioral features")
    print(f"  • Trained Isolation Forest model")
    print(f"  • Detected {num_anomalies} anomalies ({anomaly_rate:.2f}% rate)")
    print(f"  • Model saved to {model_path}")

    print("\nNext steps:")
    print("  1. Try different contamination values (contamination parameter)")
    print("  2. Experiment with other detectors (Autoencoder, Statistical)")
    print("  3. Use real data from your SIEM/EDR system")
    print("  4. Explore the API examples (02_api_client.py)")


if __name__ == "__main__":
    main()
