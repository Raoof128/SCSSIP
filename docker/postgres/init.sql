-- Initialize TimescaleDB extension and create tables for threat hunting platform

-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- Create enum types
CREATE TYPE severity_level AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');
CREATE TYPE lead_status AS ENUM ('NEW', 'INVESTIGATING', 'CONFIRMED', 'FALSE_POSITIVE', 'RESOLVED');
CREATE TYPE event_type AS ENUM ('AUTHENTICATION', 'NETWORK', 'FILE_ACCESS', 'PROCESS', 'REGISTRY', 'OTHER');

-- Security events table (hypertable for time-series data)
CREATE TABLE IF NOT EXISTS security_events (
    id BIGSERIAL,
    event_time TIMESTAMPTZ NOT NULL,
    event_type event_type NOT NULL,
    source_system VARCHAR(100),
    raw_data JSONB,
    normalized_data JSONB,
    source_ip INET,
    dest_ip INET,
    user_name VARCHAR(255),
    host_name VARCHAR(255),
    process_name VARCHAR(500),
    event_count INTEGER DEFAULT 1,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (id, event_time)
);

-- Convert to hypertable
SELECT create_hypertable('security_events', 'event_time', if_not_exists => TRUE);

-- Create indexes for common queries
CREATE INDEX idx_security_events_user ON security_events (user_name, event_time DESC);
CREATE INDEX idx_security_events_host ON security_events (host_name, event_time DESC);
CREATE INDEX idx_security_events_source_ip ON security_events (source_ip, event_time DESC);
CREATE INDEX idx_security_events_type ON security_events (event_type, event_time DESC);
CREATE INDEX idx_security_events_raw_data ON security_events USING GIN (raw_data);

-- Behavioral profiles table
CREATE TABLE IF NOT EXISTS behavioral_profiles (
    id SERIAL PRIMARY KEY,
    entity_type VARCHAR(50) NOT NULL,  -- 'user', 'host', 'ip', 'application'
    entity_id VARCHAR(255) NOT NULL,
    profile_data JSONB NOT NULL,  -- Stores statistical baselines and patterns
    feature_vector FLOAT8[],  -- ML feature representation
    baseline_start TIMESTAMPTZ NOT NULL,
    baseline_end TIMESTAMPTZ NOT NULL,
    event_count INTEGER DEFAULT 0,
    last_updated TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(entity_type, entity_id)
);

CREATE INDEX idx_behavioral_profiles_entity ON behavioral_profiles (entity_type, entity_id);
CREATE INDEX idx_behavioral_profiles_updated ON behavioral_profiles (last_updated DESC);

-- Anomalies table (hypertable)
CREATE TABLE IF NOT EXISTS anomalies (
    id BIGSERIAL,
    detected_at TIMESTAMPTZ NOT NULL,
    event_id BIGINT,
    entity_type VARCHAR(50),
    entity_id VARCHAR(255),
    anomaly_type VARCHAR(100),
    anomaly_score FLOAT8 NOT NULL,
    model_name VARCHAR(100),
    model_confidence FLOAT8,
    baseline_value FLOAT8,
    observed_value FLOAT8,
    deviation_sigma FLOAT8,
    feature_importance JSONB,
    event_context JSONB,
    is_confirmed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (id, detected_at)
);

SELECT create_hypertable('anomalies', 'detected_at', if_not_exists => TRUE);

CREATE INDEX idx_anomalies_score ON anomalies (anomaly_score DESC, detected_at DESC);
CREATE INDEX idx_anomalies_entity ON anomalies (entity_type, entity_id, detected_at DESC);
CREATE INDEX idx_anomalies_type ON anomalies (anomaly_type, detected_at DESC);

-- Threat hunting leads table
CREATE TABLE IF NOT EXISTS threat_leads (
    id SERIAL PRIMARY KEY,
    lead_id VARCHAR(50) UNIQUE NOT NULL,  -- THL-YYYY-NNNNNN format
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    severity severity_level NOT NULL,
    status lead_status DEFAULT 'NEW',
    confidence FLOAT8 NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    anomaly_ids BIGINT[],  -- Array of related anomaly IDs
    entities JSONB,  -- Related users, hosts, IPs
    attack_techniques VARCHAR(20)[],  -- MITRE ATT&CK technique IDs
    timeline_start TIMESTAMPTZ,
    timeline_end TIMESTAMPTZ,
    event_count INTEGER DEFAULT 0,
    investigation_notes TEXT,
    recommended_actions JSONB,
    evidence JSONB,
    assigned_to VARCHAR(255),
    resolved_at TIMESTAMPTZ,
    resolution_notes TEXT
);

CREATE INDEX idx_threat_leads_severity ON threat_leads (severity, created_at DESC);
CREATE INDEX idx_threat_leads_status ON threat_leads (status, created_at DESC);
CREATE INDEX idx_threat_leads_confidence ON threat_leads (confidence DESC);
CREATE INDEX idx_threat_leads_techniques ON threat_leads USING GIN (attack_techniques);
CREATE INDEX idx_threat_leads_created ON threat_leads (created_at DESC);

-- Threat intelligence indicators table
CREATE TABLE IF NOT EXISTS threat_intel (
    id SERIAL PRIMARY KEY,
    indicator_type VARCHAR(50) NOT NULL,  -- 'ip', 'domain', 'hash', 'url'
    indicator_value VARCHAR(500) NOT NULL,
    source VARCHAR(100),  -- 'MISP', 'commercial_feed', 'internal'
    confidence FLOAT8,
    severity severity_level,
    tags VARCHAR(100)[],
    metadata JSONB,
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    valid_until TIMESTAMPTZ,
    UNIQUE(indicator_type, indicator_value)
);

CREATE INDEX idx_threat_intel_type_value ON threat_intel (indicator_type, indicator_value);
CREATE INDEX idx_threat_intel_tags ON threat_intel USING GIN (tags);
CREATE INDEX idx_threat_intel_valid ON threat_intel (valid_until) WHERE valid_until IS NOT NULL;

-- ML models metadata table
CREATE TABLE IF NOT EXISTS ml_models (
    id SERIAL PRIMARY KEY,
    model_name VARCHAR(100) NOT NULL,
    model_type VARCHAR(50) NOT NULL,  -- 'isolation_forest', 'autoencoder', 'statistical'
    model_version VARCHAR(50) NOT NULL,
    model_path VARCHAR(500),
    training_data_start TIMESTAMPTZ,
    training_data_end TIMESTAMPTZ,
    training_samples INTEGER,
    performance_metrics JSONB,  -- accuracy, precision, recall, f1, etc.
    hyperparameters JSONB,
    is_active BOOLEAN DEFAULT FALSE,
    trained_at TIMESTAMPTZ DEFAULT NOW(),
    created_by VARCHAR(255),
    notes TEXT,
    UNIQUE(model_name, model_version)
);

CREATE INDEX idx_ml_models_active ON ml_models (model_name, is_active);
CREATE INDEX idx_ml_models_trained ON ml_models (trained_at DESC);

-- Correlation rules table
CREATE TABLE IF NOT EXISTS correlation_rules (
    id SERIAL PRIMARY KEY,
    rule_name VARCHAR(255) UNIQUE NOT NULL,
    rule_type VARCHAR(50),  -- 'temporal', 'spatial', 'behavioral'
    conditions JSONB NOT NULL,
    time_window_minutes INTEGER,
    min_events INTEGER DEFAULT 2,
    severity severity_level,
    attack_techniques VARCHAR(20)[],
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Investigation timeline table
CREATE TABLE IF NOT EXISTS investigation_timeline (
    id SERIAL PRIMARY KEY,
    lead_id VARCHAR(50) REFERENCES threat_leads(lead_id),
    event_time TIMESTAMPTZ NOT NULL,
    event_type VARCHAR(100),
    actor VARCHAR(255),  -- analyst username or 'SYSTEM'
    action VARCHAR(500),
    details JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_investigation_timeline_lead ON investigation_timeline (lead_id, event_time DESC);

-- Create materialized view for dashboard metrics
CREATE MATERIALIZED VIEW IF NOT EXISTS dashboard_metrics AS
SELECT
    date_trunc('hour', detected_at) as hour,
    COUNT(*) as anomaly_count,
    AVG(anomaly_score) as avg_anomaly_score,
    COUNT(DISTINCT entity_id) as unique_entities,
    COUNT(*) FILTER (WHERE is_confirmed = TRUE) as confirmed_anomalies,
    COUNT(*) FILTER (WHERE is_confirmed = FALSE) as unconfirmed_anomalies
FROM anomalies
WHERE detected_at > NOW() - INTERVAL '7 days'
GROUP BY hour
ORDER BY hour DESC;

CREATE UNIQUE INDEX idx_dashboard_metrics_hour ON dashboard_metrics (hour);

-- Create retention policies (TimescaleDB feature)
-- Automatically drop old raw events after retention period
SELECT add_retention_policy('security_events', INTERVAL '90 days', if_not_exists => TRUE);
SELECT add_retention_policy('anomalies', INTERVAL '365 days', if_not_exists => TRUE);

-- Create continuous aggregates for performance
CREATE MATERIALIZED VIEW IF NOT EXISTS security_events_hourly
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', event_time) AS hour,
    event_type,
    user_name,
    host_name,
    COUNT(*) as event_count,
    COUNT(DISTINCT source_ip) as unique_source_ips,
    COUNT(DISTINCT dest_ip) as unique_dest_ips
FROM security_events
GROUP BY hour, event_type, user_name, host_name
WITH NO DATA;

SELECT add_continuous_aggregate_policy('security_events_hourly',
    start_offset => INTERVAL '3 hours',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists => TRUE);

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO threat_hunter;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO threat_hunter;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO threat_hunter;

-- Insert sample correlation rules
INSERT INTO correlation_rules (rule_name, rule_type, conditions, time_window_minutes, min_events, severity, attack_techniques)
VALUES
    ('Rapid SMB Share Enumeration', 'temporal', '{"event_type": "FILE_ACCESS", "min_unique_shares": 20}', 30, 20, 'HIGH', ARRAY['T1021.002', 'T1083']),
    ('Unusual Login Time Pattern', 'behavioral', '{"event_type": "AUTHENTICATION", "deviation_sigma": 3}', 60, 1, 'MEDIUM', ARRAY['T1078']),
    ('Privilege Escalation Sequence', 'temporal', '{"sequence": ["authentication", "privilege_change", "suspicious_process"]}', 15, 3, 'CRITICAL', ARRAY['T1068', 'T1134'])
ON CONFLICT (rule_name) DO NOTHING;

COMMIT;
