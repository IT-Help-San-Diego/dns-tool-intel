CREATE TABLE domain_analyses (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    ascii_domain VARCHAR(255) NOT NULL,
    basic_records JSON,
    authoritative_records JSON,
    spf_status VARCHAR(20),
    spf_records JSON,
    dmarc_status VARCHAR(20),
    dmarc_policy VARCHAR(20),
    dmarc_records JSON,
    dkim_status VARCHAR(20),
    dkim_selectors JSON,
    registrar_name VARCHAR(255),
    registrar_source VARCHAR(20),
    analysis_success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    analysis_duration DOUBLE PRECISION,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP,
    country_code VARCHAR(10),
    country_name VARCHAR(100),
    ct_subdomains JSON,
    full_results JSON NOT NULL,
    posture_hash VARCHAR(128),
    private BOOLEAN NOT NULL DEFAULT FALSE,
    has_user_selectors BOOLEAN NOT NULL DEFAULT FALSE,
    scan_flag BOOLEAN NOT NULL DEFAULT FALSE,
    scan_source VARCHAR(100),
    scan_ip VARCHAR(45),
    wayback_url TEXT
);

CREATE INDEX ix_domain_analyses_domain ON domain_analyses (domain);
CREATE INDEX ix_domain_analyses_ascii_domain ON domain_analyses (ascii_domain);
CREATE INDEX ix_domain_analyses_created_at ON domain_analyses (created_at);
CREATE INDEX ix_domain_analyses_success_results ON domain_analyses (analysis_success, created_at);

CREATE TABLE analysis_stats (
    id SERIAL PRIMARY KEY,
    date DATE NOT NULL UNIQUE,
    total_analyses INTEGER DEFAULT 0,
    successful_analyses INTEGER DEFAULT 0,
    failed_analyses INTEGER DEFAULT 0,
    unique_domains INTEGER DEFAULT 0,
    avg_analysis_time DOUBLE PRECISION DEFAULT 0.0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX ix_analysis_stats_date ON analysis_stats (date);

CREATE TABLE data_governance_events (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    description TEXT NOT NULL,
    scope TEXT,
    affected_count INTEGER,
    reason TEXT NOT NULL,
    operator VARCHAR(100) NOT NULL DEFAULT 'system',
    metadata JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL DEFAULT '',
    google_sub VARCHAR(255) NOT NULL UNIQUE,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX ix_users_email ON users (email);
CREATE INDEX ix_users_google_sub ON users (google_sub);

CREATE TABLE sessions (
    id VARCHAR(64) PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    last_seen_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX ix_sessions_user_id ON sessions (user_id);
CREATE INDEX ix_sessions_expires_at ON sessions (expires_at);

-- Intelligence Confidence Audit Engine (ICAE) tables

CREATE TABLE ice_protocols (
    id SERIAL PRIMARY KEY,
    protocol VARCHAR(20) NOT NULL UNIQUE,
    display_name VARCHAR(50) NOT NULL,
    rfc_refs TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE ice_test_runs (
    id SERIAL PRIMARY KEY,
    app_version VARCHAR(20) NOT NULL,
    git_commit VARCHAR(40) NOT NULL DEFAULT '',
    run_type VARCHAR(20) NOT NULL DEFAULT 'ci',
    total_cases INTEGER NOT NULL DEFAULT 0,
    total_passed INTEGER NOT NULL DEFAULT 0,
    total_failed INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX ix_ice_test_runs_created ON ice_test_runs (created_at);
CREATE INDEX ix_ice_test_runs_version ON ice_test_runs (app_version);

CREATE TABLE ice_results (
    id SERIAL PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES ice_test_runs(id) ON DELETE CASCADE,
    protocol VARCHAR(20) NOT NULL,
    layer VARCHAR(20) NOT NULL,
    case_id VARCHAR(100) NOT NULL,
    case_name VARCHAR(255) NOT NULL DEFAULT '',
    passed BOOLEAN NOT NULL,
    expected TEXT,
    actual TEXT,
    rfc_section VARCHAR(50),
    notes TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX ix_ice_results_run ON ice_results (run_id);
CREATE INDEX ix_ice_results_protocol ON ice_results (protocol, layer);
CREATE INDEX ix_ice_results_case ON ice_results (case_id);

CREATE TABLE ice_maturity (
    id SERIAL PRIMARY KEY,
    protocol VARCHAR(20) NOT NULL,
    layer VARCHAR(20) NOT NULL,
    maturity VARCHAR(20) NOT NULL DEFAULT 'development',
    total_runs INTEGER NOT NULL DEFAULT 0,
    consecutive_passes INTEGER NOT NULL DEFAULT 0,
    first_pass_at TIMESTAMP,
    last_regression_at TIMESTAMP,
    last_evaluated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT ice_maturity_unique UNIQUE (protocol, layer)
);

CREATE TABLE ice_regressions (
    id SERIAL PRIMARY KEY,
    protocol VARCHAR(20) NOT NULL,
    layer VARCHAR(20) NOT NULL,
    run_id INTEGER NOT NULL REFERENCES ice_test_runs(id) ON DELETE CASCADE,
    previous_maturity VARCHAR(20) NOT NULL,
    new_maturity VARCHAR(20) NOT NULL,
    failed_cases TEXT[] NOT NULL DEFAULT '{}',
    notes TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX ix_ice_regressions_protocol ON ice_regressions (protocol, layer, created_at);

-- Privacy-Respecting Site Analytics
-- No cookies, no PII, no IP addresses stored.
-- Unique visitors counted via daily-rotating salted hash (ephemeral, never persisted).

CREATE TABLE site_analytics (
    id SERIAL PRIMARY KEY,
    date DATE NOT NULL UNIQUE,
    pageviews INTEGER NOT NULL DEFAULT 0,
    unique_visitors INTEGER NOT NULL DEFAULT 0,
    analyses_run INTEGER NOT NULL DEFAULT 0,
    unique_domains_analyzed INTEGER NOT NULL DEFAULT 0,
    referrer_sources JSONB NOT NULL DEFAULT '{}',
    top_pages JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX ix_site_analytics_date ON site_analytics (date);

CREATE TABLE user_analyses (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    analysis_id INTEGER NOT NULL REFERENCES domain_analyses(id) ON DELETE CASCADE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT user_analyses_unique UNIQUE (user_id, analysis_id)
);

CREATE INDEX ix_user_analyses_user_id ON user_analyses (user_id, created_at DESC);
CREATE INDEX ix_user_analyses_analysis_id ON user_analyses (analysis_id);

CREATE TABLE zone_imports (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    sha256_hash VARCHAR(64) NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    file_size INTEGER NOT NULL,
    record_count INTEGER NOT NULL DEFAULT 0,
    retained BOOLEAN NOT NULL DEFAULT FALSE,
    zone_data TEXT,
    drift_summary JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX ix_zone_imports_user_domain ON zone_imports (user_id, domain, created_at DESC);

-- Drift Engine Phase 3: Drift Events (timeline persistence)
CREATE TABLE drift_events (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    analysis_id INTEGER NOT NULL REFERENCES domain_analyses(id) ON DELETE CASCADE,
    prev_analysis_id INTEGER NOT NULL REFERENCES domain_analyses(id) ON DELETE CASCADE,
    current_hash VARCHAR(128) NOT NULL,
    previous_hash VARCHAR(128) NOT NULL,
    diff_summary JSONB NOT NULL DEFAULT '[]',
    severity VARCHAR(20) NOT NULL DEFAULT 'info',
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX ix_drift_events_domain ON drift_events (domain, created_at DESC);
CREATE INDEX ix_drift_events_analysis ON drift_events (analysis_id);

-- Drift Engine Phase 4: Domain Watchlist
CREATE TABLE domain_watchlist (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    cadence VARCHAR(20) NOT NULL DEFAULT 'daily',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_run_at TIMESTAMP,
    next_run_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT domain_watchlist_unique UNIQUE (user_id, domain)
);

CREATE INDEX ix_domain_watchlist_next_run ON domain_watchlist (next_run_at) WHERE enabled = TRUE;
CREATE INDEX ix_domain_watchlist_user ON domain_watchlist (user_id);

-- Drift Engine Phase 4: Notification Endpoints
CREATE TABLE notification_endpoints (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    endpoint_type VARCHAR(20) NOT NULL DEFAULT 'webhook',
    url TEXT NOT NULL,
    secret VARCHAR(128),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX ix_notification_endpoints_user ON notification_endpoints (user_id);

-- Drift Engine Phase 4: Drift Notifications (delivery tracking)
CREATE TABLE drift_notifications (
    id SERIAL PRIMARY KEY,
    drift_event_id INTEGER NOT NULL REFERENCES drift_events(id) ON DELETE CASCADE,
    endpoint_id INTEGER NOT NULL REFERENCES notification_endpoints(id) ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    response_code INTEGER,
    response_body TEXT,
    delivered_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX ix_drift_notifications_event ON drift_notifications (drift_event_id);
CREATE INDEX ix_drift_notifications_status ON drift_notifications (status) WHERE status = 'pending';

-- ICuAE (Intelligence Currency Assurance Engine) tables
CREATE TABLE icuae_scan_scores (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    overall_score REAL NOT NULL DEFAULT 0,
    overall_grade VARCHAR(5) NOT NULL DEFAULT 'F',
    resolver_count INTEGER NOT NULL DEFAULT 0,
    record_count INTEGER NOT NULL DEFAULT 0,
    app_version VARCHAR(20) NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE icuae_dimension_scores (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES icuae_scan_scores(id) ON DELETE CASCADE,
    dimension VARCHAR(50) NOT NULL,
    score REAL NOT NULL DEFAULT 0,
    grade VARCHAR(5) NOT NULL DEFAULT 'F',
    record_types_evaluated TEXT[] NOT NULL DEFAULT '{}'
);

-- CT Subdomain Cache: persistent storage for Certificate Transparency discoveries.
-- CT logs (RFC 6962) are append-only, immutable historical records.
-- Caching them does NOT violate our "live data" promise — certificates are
-- historical facts that cannot be un-issued. DNS liveness is always checked fresh.
CREATE TABLE ct_subdomain_cache (
    domain        VARCHAR(255) PRIMARY KEY,
    subdomains    JSONB NOT NULL DEFAULT '[]',
    unique_count  INTEGER NOT NULL DEFAULT 0,
    source        VARCHAR(50) NOT NULL DEFAULT 'crt.sh',
    fetched_at    TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMP NOT NULL DEFAULT (NOW() + INTERVAL '24 hours')
);

CREATE INDEX ix_ct_cache_expires ON ct_subdomain_cache (expires_at);
CREATE INDEX ix_ct_cache_fetched ON ct_subdomain_cache (fetched_at DESC);

-- SecurityTrails monthly budget tracking (survives server restarts)
CREATE TABLE securitytrails_budget (
    month_key       VARCHAR(7) PRIMARY KEY,
    calls_used      INTEGER NOT NULL DEFAULT 0,
    domains_enriched JSONB NOT NULL DEFAULT '[]',
    last_called_at  TIMESTAMP,
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Domain index: historical registry of every domain ever scanned.
-- Enables intelligence trending, usage analytics, and enrichment targeting.
CREATE TABLE domain_index (
    domain        VARCHAR(255) PRIMARY KEY,
    first_seen    TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen     TIMESTAMP NOT NULL DEFAULT NOW(),
    total_scans   INTEGER NOT NULL DEFAULT 1,
    last_score    REAL,
    has_dane      BOOLEAN NOT NULL DEFAULT FALSE,
    has_dnssec    BOOLEAN NOT NULL DEFAULT FALSE,
    has_mta_sts   BOOLEAN NOT NULL DEFAULT FALSE,
    tags          TEXT[] NOT NULL DEFAULT '{}'
);

CREATE INDEX ix_domain_index_last_seen ON domain_index (last_seen DESC);
CREATE INDEX ix_domain_index_total_scans ON domain_index (total_scans DESC);
CREATE INDEX ix_domain_index_tags ON domain_index USING GIN (tags);

-- Priority domains: always enriched first in CT intelligence pipeline.
-- Domains with advanced DNS features (DANE, DNSSEC) that we track as
-- reference implementations and industry benchmarks.
CREATE TABLE priority_domains (
    domain        VARCHAR(255) PRIMARY KEY,
    reason        TEXT NOT NULL,
    added_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    enabled       BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE scan_phase_telemetry (
    id              SERIAL PRIMARY KEY,
    analysis_id     INT NOT NULL REFERENCES domain_analyses(id) ON DELETE CASCADE,
    phase_group     TEXT NOT NULL,
    phase_task      TEXT NOT NULL,
    started_at_ms   INT NOT NULL,
    duration_ms     INT NOT NULL,
    record_count    INT DEFAULT 0,
    error           TEXT,
    created_at      TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_spt_analysis ON scan_phase_telemetry(analysis_id);
CREATE INDEX idx_spt_phase ON scan_phase_telemetry(phase_group);

CREATE TABLE scan_telemetry_hash (
    analysis_id     INT PRIMARY KEY REFERENCES domain_analyses(id) ON DELETE CASCADE,
    total_duration_ms INT NOT NULL,
    phase_count     INT NOT NULL,
    sha3_512        TEXT NOT NULL,
    created_at      TIMESTAMP DEFAULT NOW()
);
