-- 015_confidence_scores_link_seed.sql — Wire confidence_scores for real use
-- "seed" in the filename means RunSeedMigrations applies this at EVERY startup,
-- so every statement here MUST be idempotent. This also self-heals environments
-- where 012 (non-seed, never auto-applied) was never run.

CREATE TABLE IF NOT EXISTS confidence_scores (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID,
    domain          TEXT NOT NULL,
    protocol        TEXT NOT NULL CHECK (protocol IN (
        'SPF','DKIM','DMARC','DNSSEC','DANE','CAA','MTA-STS','BIMI','TLS-RPT','MX','NS','SOA'
    )),
    score           NUMERIC(5,4) NOT NULL CHECK (score >= 0 AND score <= 1),
    grade           TEXT CHECK (grade IN ('A+','A','A-','B+','B','B-','C+','C','C-','D','F')),
    resolver_count  SMALLINT,
    resolver_agreement NUMERIC(5,4),
    evidence_factors    JSONB NOT NULL DEFAULT '{}'::jsonb,
    calibrated_score    NUMERIC(5,4),
    raw_score           NUMERIC(5,4),
    source          TEXT NOT NULL DEFAULT 'scan' CHECK (source IN ('scan','manual','import','recalibration')),
    scanned_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_confidence_scores_domain ON confidence_scores (domain);
CREATE INDEX IF NOT EXISTS idx_confidence_scores_protocol ON confidence_scores (protocol);
CREATE INDEX IF NOT EXISTS idx_confidence_scores_domain_protocol ON confidence_scores (domain, protocol);
CREATE INDEX IF NOT EXISTS idx_confidence_scores_scanned_at ON confidence_scores (scanned_at);
CREATE INDEX IF NOT EXISTS idx_confidence_scores_scan_id ON confidence_scores (scan_id);

-- Link to domain_analyses (SERIAL int PK — scan_id UUID can never reference it;
-- scan_id stays NULL and is retained only for schema compatibility).
ALTER TABLE confidence_scores
    ADD COLUMN IF NOT EXISTS analysis_id INTEGER REFERENCES domain_analyses(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_confidence_scores_analysis_id ON confidence_scores (analysis_id);

-- Idempotency anchor for the writer and the backfill job.
CREATE UNIQUE INDEX IF NOT EXISTS uq_confidence_scores_analysis_protocol
    ON confidence_scores (analysis_id, protocol) WHERE analysis_id IS NOT NULL;
