# Examples - Advanced Threat Hunting Platform

This directory contains practical examples demonstrating how to use the Advanced Threat Hunting Platform for various security use cases.

## Overview

| Example | Description | Difficulty | Topics Covered |
|---------|-------------|------------|----------------|
| [01_basic_usage.py](01_basic_usage.py) | Basic platform usage and anomaly detection | Beginner | Data generation, feature extraction, model training, anomaly detection |
| [02_api_client.py](02_api_client.py) | Using the REST API | Beginner | API client, endpoints, authentication |
| [03_custom_detector.py](03_custom_detector.py) | Creating custom anomaly detectors | Intermediate | Custom detectors, class inheritance, detector interface |

## Prerequisites

Before running these examples, ensure you have:

1. **Installed dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Set up environment** (for API examples):
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Started required services** (for API examples):
   ```bash
   docker-compose up -d postgres influxdb redis
   ```

## Quick Start

### Example 1: Basic Usage

Demonstrates the core workflow of the platform.

```bash
python examples/01_basic_usage.py
```

**What it does:**
- Generates 1,000 sample security events
- Extracts behavioral features
- Trains an Isolation Forest detector
- Detects anomalies in test data
- Saves the trained model

**Expected output:**
```
✓ Generated 1000 security events
✓ Extracted features: (20, 57)
✓ Model trained successfully
✓ Detection complete
  - Anomalies detected: 6/6
  - Anomaly rate: 100.00%
```

**Learning objectives:**
- Understanding the data flow
- Feature extraction process
- Model training and evaluation
- Interpreting anomaly scores

### Example 2: API Client

Shows how to interact with the platform API.

**Start the API server first:**
```bash
uvicorn src.api.main:app --reload
```

**Run the example:**
```bash
python examples/02_api_client.py
```

**What it does:**
- Checks platform health
- Retrieves recent anomalies
- Fetches entity profiles
- Gets threat hunting leads
- Queries MITRE ATT&CK mappings
- Retrieves model metrics

**Expected output:**
```
✓ Platform status: healthy
✓ Found 10 high-severity anomalies
✓ Profile for entity 'alice'
✓ Found 5 high-priority leads
```

**Learning objectives:**
- API authentication
- Querying endpoints
- Filtering and pagination
- Error handling

### Example 3: Custom Detector

Demonstrates building custom anomaly detectors.

```bash
python examples/03_custom_detector.py
```

**What it does:**
- Implements a threshold-based detector
- Implements a frequency-based detector
- Compares detector performance
- Shows how to extend the platform

**Expected output:**
```
✓ Threshold detector trained
✓ Frequency detector trained
  Detector          | Anomalies | Avg Score
  Threshold        |         8 |    0.2154
  Frequency        |        12 |    0.3782
```

**Learning objectives:**
- Detector interface
- Custom detection logic
- Performance comparison
- Integration with the platform

## Example Use Cases

### Security Operations Center (SOC)

**Scenario**: Monitor user authentication anomalies

```python
from src.analytics.profilers.ueba_profiler import UEBAProfiler

# Create user baseline
profiler = UEBAProfiler()
profiler.create_baseline(user_id="alice", events=historical_events)

# Detect deviations
anomalies = profiler.detect_deviations(user_id="alice", events=recent_events)
```

### Threat Hunting

**Scenario**: Hunt for credential access attacks

```python
from src.threat_hunting.enrichment.attack_mapper import MITREAttackMapper

# Map events to MITRE ATT&CK
mapper = MITREAttackMapper()
techniques = mapper.map_events_to_techniques(events)

# Filter for credential access
cred_access = [t for t in techniques if t.tactic == "credential-access"]
```

### Incident Response

**Scenario**: Investigate high-priority alerts

```python
# Get high-severity anomalies
anomalies = await client.get_anomalies(severity_min=8, limit=20)

# Get entity context
for anomaly in anomalies:
    profile = await client.get_entity_profile(anomaly.entity_id)
    related_leads = await client.get_entity_anomalies(anomaly.entity_id)
```

## Advanced Examples

### Ensemble Detection

Combine multiple detectors for better accuracy:

```python
from src.analytics.models.ensemble_detector import EnsembleDetector

ensemble = EnsembleDetector(
    voting_strategy="weighted",
    weights={"isolation_forest": 0.4, "autoencoder": 0.4, "statistical": 0.2}
)

ensemble.train(X_train)
predictions = ensemble.detect(X_test)
```

### Real-time Processing

Process events in real-time:

```python
from src.data_ingestion.stream_processor import StreamProcessor

processor = StreamProcessor()
await processor.start()

# Events are automatically processed and analyzed
# Anomalies published to anomalies topic
```

### Custom Feature Engineering

Add domain-specific features:

```python
from src.analytics.feature_extractor import FeatureExtractor

class CustomExtractor(FeatureExtractor):
    def extract_custom_features(self, events):
        # Add your custom logic
        features = {}
        features['unusual_port_access'] = self._check_ports(events)
        features['rare_process_execution'] = self._check_processes(events)
        return features
```

## Integration Examples

### Splunk Integration

```python
from src.data_ingestion.adapters.splunk_adapter import SplunkAdapter

adapter = SplunkAdapter(
    host="splunk.example.com",
    port=8089,
    username="admin",
    token="your-token"
)

events = await adapter.fetch_events(
    start_time=datetime.now() - timedelta(hours=24),
    end_time=datetime.now()
)
```

### Elasticsearch Integration

```python
from src.data_ingestion.adapters.elastic_adapter import ElasticAdapter

adapter = ElasticAdapter(
    hosts=["http://localhost:9200"],
    index_pattern="security-logs-*"
)

events = await adapter.fetch_events(
    start_time=datetime.now() - timedelta(hours=1),
    end_time=datetime.now()
)
```

## Testing and Development

### Running with Sample Data

All examples work with generated sample data by default. To use real data:

1. Configure your data source adapter
2. Set up authentication credentials
3. Modify the example to use the appropriate adapter

### Debugging

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

View detailed feature extraction:

```python
extractor = FeatureExtractor()
features = extractor.extract_features(events, window_size=10)
print(features.describe())  # Statistical summary
print(features.head())      # First few rows
```

## Performance Considerations

### Batch Processing

For large datasets, use batching:

```python
batch_size = 1000
for i in range(0, len(events), batch_size):
    batch = events[i:i+batch_size]
    features = extractor.extract_features(batch)
    predictions = detector.detect(features)
```

### Caching

Enable feature caching for repeated queries:

```python
from src.analytics.feature_extractor import FeatureStore

feature_store = FeatureStore()
feature_store.enable_caching(ttl=3600)  # 1 hour cache
```

### Parallel Processing

Use multiprocessing for CPU-intensive tasks:

```python
from multiprocessing import Pool

with Pool(processes=4) as pool:
    results = pool.map(process_batch, event_batches)
```

## Troubleshooting

### Common Issues

**Import Errors**:
```bash
# Ensure you're in the project root
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

**API Connection Errors**:
```bash
# Check if API is running
curl http://localhost:8000/health

# Start API if needed
uvicorn src.api.main:app --reload
```

**Database Errors**:
```bash
# Start PostgreSQL via Docker
docker-compose up -d postgres

# Check connection
docker-compose ps
```

**Model Training Fails**:
- Ensure sufficient data (minimum 100 samples)
- Check for NaN values in features
- Verify feature scaling

## Resources

- **Documentation**: [../docs/](../docs/)
- **API Reference**: [../docs/API_REFERENCE.md](../docs/API_REFERENCE.md)
- **Architecture**: [../docs/architecture/ARCHITECTURE.md](../docs/architecture/ARCHITECTURE.md)
- **Contributing**: [../CONTRIBUTING.md](../CONTRIBUTING.md)

## Support

For questions or issues:

- **GitHub Issues**: Report bugs or request features
- **Documentation**: Check the docs/ directory
- **Examples**: See these examples for reference patterns

## License

These examples are part of the Advanced Threat Hunting Platform and are licensed under the MIT License. See [../LICENSE](../LICENSE) for details.

---

**Happy Threat Hunting!** 🎯🔍
