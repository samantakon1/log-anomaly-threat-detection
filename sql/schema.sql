CREATE SCHEMA IF NOT EXISTS analytics;

CREATE TABLE IF NOT EXISTS analytics.request_logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    module_id TEXT,
    version_id TEXT,
    method TEXT,
    status_code INTEGER,
    status_family TEXT,
    latency_ms DOUBLE PRECISION,
    response_size BIGINT,
    ip_hash TEXT,
    user_agent_category TEXT,
    endpoint_group TEXT,
    endpoint_template TEXT,
    path_depth INTEGER,
    path_length INTEGER,
    is_static_asset BOOLEAN,
    has_suspicious_path_pattern BOOLEAN,
    has_sensitive_query_key BOOLEAN,
    request_hash TEXT UNIQUE,
    raw_record JSONB NOT NULL,
    loaded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS analytics.app_logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    receive_timestamp TIMESTAMPTZ,
    module_id TEXT,
    version_id TEXT,
    level TEXT,
    event TEXT,
    method TEXT,
    status_code INTEGER,
    status_family TEXT,
    response_time_ms DOUBLE PRECISION,
    user_id_hash TEXT,
    tenant_hash TEXT,
    endpoint_group TEXT,
    endpoint_template TEXT,
    path_depth INTEGER,
    path_length INTEGER,
    is_static_asset BOOLEAN,
    has_suspicious_path_pattern BOOLEAN,
    has_error BOOLEAN,
    request_data_has_sensitive_key BOOLEAN,
    response_data_has_sensitive_key BOOLEAN,
    headers_has_sensitive_key BOOLEAN,
    request_hash TEXT,
    event_hash TEXT UNIQUE,
    raw_record JSONB NOT NULL,
    loaded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE analytics.app_logs ADD COLUMN IF NOT EXISTS event_hash TEXT;
ALTER TABLE analytics.app_logs DROP CONSTRAINT IF EXISTS app_logs_request_hash_key;
CREATE UNIQUE INDEX IF NOT EXISTS app_logs_event_hash_key ON analytics.app_logs (event_hash);

CREATE TABLE IF NOT EXISTS analytics.dataset_quality_metrics (
    id BIGSERIAL PRIMARY KEY,
    dataset TEXT NOT NULL,
    metric TEXT NOT NULL,
    value TEXT,
    loaded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (dataset, metric)
);

CREATE TABLE IF NOT EXISTS analytics.request_ip_window_features (
    window_start TIMESTAMPTZ NOT NULL,
    ip_hash TEXT NOT NULL,
    request_count INTEGER NOT NULL,
    unique_endpoint_count INTEGER NOT NULL,
    unique_endpoint_group_count INTEGER NOT NULL,
    unique_method_count INTEGER NOT NULL,
    unique_user_agent_category_count INTEGER NOT NULL,
    static_asset_count INTEGER NOT NULL,
    suspicious_path_count INTEGER NOT NULL,
    sensitive_query_count INTEGER NOT NULL,
    status_2xx_count INTEGER NOT NULL,
    status_3xx_count INTEGER NOT NULL,
    status_4xx_count INTEGER NOT NULL,
    status_5xx_count INTEGER NOT NULL,
    error_count INTEGER NOT NULL,
    error_rate DOUBLE PRECISION NOT NULL,
    avg_latency_ms DOUBLE PRECISION,
    p95_latency_ms DOUBLE PRECISION,
    max_latency_ms DOUBLE PRECISION,
    avg_response_size DOUBLE PRECISION,
    avg_endpoint_rarity DOUBLE PRECISION,
    off_hours BOOLEAN NOT NULL,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (window_start, ip_hash)
);

CREATE TABLE IF NOT EXISTS analytics.app_user_window_features (
    window_start TIMESTAMPTZ NOT NULL,
    user_id_hash TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    unique_tenant_count INTEGER NOT NULL,
    unique_endpoint_count INTEGER NOT NULL,
    unique_endpoint_group_count INTEGER NOT NULL,
    unique_method_count INTEGER NOT NULL,
    suspicious_path_count INTEGER NOT NULL,
    error_count INTEGER NOT NULL,
    error_rate DOUBLE PRECISION NOT NULL,
    status_2xx_count INTEGER NOT NULL,
    status_4xx_count INTEGER NOT NULL,
    avg_response_time_ms DOUBLE PRECISION,
    p95_response_time_ms DOUBLE PRECISION,
    max_response_time_ms DOUBLE PRECISION,
    request_sensitive_key_count INTEGER NOT NULL,
    response_sensitive_key_count INTEGER NOT NULL,
    header_sensitive_key_count INTEGER NOT NULL,
    off_hours BOOLEAN NOT NULL,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (window_start, user_id_hash)
);

CREATE TABLE IF NOT EXISTS analytics.request_ip_anomaly_scores (
    window_start TIMESTAMPTZ NOT NULL,
    ip_hash TEXT NOT NULL,
    model_name TEXT NOT NULL,
    model_version TEXT NOT NULL,
    anomaly_score DOUBLE PRECISION NOT NULL,
    raw_decision_score DOUBLE PRECISION NOT NULL,
    is_anomaly BOOLEAN NOT NULL,
    anomaly_rank INTEGER NOT NULL,
    scored_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (window_start, ip_hash, model_version)
);

CREATE TABLE IF NOT EXISTS analytics.request_ip_threat_scores (
    window_start TIMESTAMPTZ NOT NULL,
    ip_hash TEXT NOT NULL,
    model_version TEXT NOT NULL,
    threat_score DOUBLE PRECISION NOT NULL,
    threat_level TEXT NOT NULL,
    is_security_relevant BOOLEAN NOT NULL,
    reasons JSONB NOT NULL,
    anomaly_score DOUBLE PRECISION NOT NULL,
    anomaly_rank INTEGER NOT NULL,
    request_count INTEGER NOT NULL,
    suspicious_path_count INTEGER NOT NULL,
    error_count INTEGER NOT NULL,
    error_rate DOUBLE PRECISION NOT NULL,
    unique_endpoint_count INTEGER NOT NULL,
    static_asset_count INTEGER NOT NULL DEFAULT 0,
    off_hours BOOLEAN NOT NULL,
    scored_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (window_start, ip_hash, model_version)
);

CREATE TABLE IF NOT EXISTS analytics.synthetic_scenario_scores (
    evaluation_id TEXT NOT NULL,
    synthetic_id TEXT NOT NULL,
    scenario_name TEXT NOT NULL,
    is_attack_like BOOLEAN NOT NULL,
    model_version TEXT NOT NULL,
    anomaly_score DOUBLE PRECISION NOT NULL,
    is_anomaly BOOLEAN NOT NULL DEFAULT false,
    threat_score DOUBLE PRECISION NOT NULL,
    threat_level TEXT NOT NULL,
    is_security_relevant BOOLEAN NOT NULL,
    anomaly_rank INTEGER NOT NULL,
    threat_rank INTEGER NOT NULL,
    reasons JSONB NOT NULL,
    request_count INTEGER NOT NULL,
    suspicious_path_count INTEGER NOT NULL,
    error_count INTEGER NOT NULL,
    error_rate DOUBLE PRECISION NOT NULL,
    unique_endpoint_count INTEGER NOT NULL,
    static_asset_count INTEGER NOT NULL DEFAULT 0,
    off_hours BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (evaluation_id, synthetic_id)
);

ALTER TABLE analytics.request_ip_threat_scores ADD COLUMN IF NOT EXISTS static_asset_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE analytics.synthetic_scenario_scores ADD COLUMN IF NOT EXISTS static_asset_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE analytics.synthetic_scenario_scores ADD COLUMN IF NOT EXISTS is_anomaly BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS analytics.synthetic_scenario_metrics (
    evaluation_id TEXT NOT NULL,
    model_version TEXT NOT NULL,
    ranking_method TEXT NOT NULL,
    metric_name TEXT NOT NULL,
    k_value INTEGER NOT NULL,
    metric_value DOUBLE PRECISION NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (evaluation_id, ranking_method, metric_name, k_value)
);

CREATE TABLE IF NOT EXISTS analytics.demo_ingestion_state (
    source_name TEXT PRIMARY KEY,
    last_log_timestamp TIMESTAMPTZ,
    last_successful_run_id TEXT,
    last_successful_run_at TIMESTAMPTZ,
    last_rows_retrieved INTEGER NOT NULL DEFAULT 0,
    last_raw_path TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS request_logs_timestamp_idx ON analytics.request_logs (timestamp);
CREATE INDEX IF NOT EXISTS request_logs_ip_hash_idx ON analytics.request_logs (ip_hash);
CREATE INDEX IF NOT EXISTS request_logs_endpoint_group_idx ON analytics.request_logs (endpoint_group);
CREATE INDEX IF NOT EXISTS request_logs_status_family_idx ON analytics.request_logs (status_family);
CREATE INDEX IF NOT EXISTS request_logs_suspicious_idx ON analytics.request_logs (has_suspicious_path_pattern);

CREATE INDEX IF NOT EXISTS app_logs_timestamp_idx ON analytics.app_logs (timestamp);
CREATE INDEX IF NOT EXISTS app_logs_user_hash_idx ON analytics.app_logs (user_id_hash);
CREATE INDEX IF NOT EXISTS app_logs_tenant_hash_idx ON analytics.app_logs (tenant_hash);
CREATE INDEX IF NOT EXISTS app_logs_endpoint_group_idx ON analytics.app_logs (endpoint_group);
CREATE INDEX IF NOT EXISTS app_logs_has_error_idx ON analytics.app_logs (has_error);
CREATE INDEX IF NOT EXISTS app_logs_request_hash_idx ON analytics.app_logs (request_hash);

CREATE INDEX IF NOT EXISTS request_ip_window_features_ip_hash_idx ON analytics.request_ip_window_features (ip_hash);
CREATE INDEX IF NOT EXISTS request_ip_window_features_request_count_idx ON analytics.request_ip_window_features (request_count DESC);
CREATE INDEX IF NOT EXISTS request_ip_window_features_suspicious_idx ON analytics.request_ip_window_features (suspicious_path_count DESC);

CREATE INDEX IF NOT EXISTS app_user_window_features_user_hash_idx ON analytics.app_user_window_features (user_id_hash);
CREATE INDEX IF NOT EXISTS app_user_window_features_event_count_idx ON analytics.app_user_window_features (event_count DESC);
CREATE INDEX IF NOT EXISTS app_user_window_features_error_idx ON analytics.app_user_window_features (error_count DESC);

CREATE INDEX IF NOT EXISTS request_ip_anomaly_scores_score_idx ON analytics.request_ip_anomaly_scores (anomaly_score DESC);
CREATE INDEX IF NOT EXISTS request_ip_anomaly_scores_anomaly_idx ON analytics.request_ip_anomaly_scores (is_anomaly);

CREATE INDEX IF NOT EXISTS request_ip_threat_scores_score_idx ON analytics.request_ip_threat_scores (threat_score DESC);
CREATE INDEX IF NOT EXISTS request_ip_threat_scores_level_idx ON analytics.request_ip_threat_scores (threat_level);
CREATE INDEX IF NOT EXISTS request_ip_threat_scores_relevant_idx ON analytics.request_ip_threat_scores (is_security_relevant);

CREATE INDEX IF NOT EXISTS synthetic_scenario_scores_threat_idx ON analytics.synthetic_scenario_scores (evaluation_id, threat_score DESC);
CREATE INDEX IF NOT EXISTS synthetic_scenario_scores_anomaly_idx ON analytics.synthetic_scenario_scores (evaluation_id, anomaly_score DESC);
CREATE INDEX IF NOT EXISTS synthetic_scenario_metrics_eval_idx ON analytics.synthetic_scenario_metrics (evaluation_id);
