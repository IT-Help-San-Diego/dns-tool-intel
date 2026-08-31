-- +goose Up
-- 025_scan_api_keys.sql
-- Batch-scan authorization: operator-issued API keys (design doc
-- docs/DESIGN-batch-scans-api-keys-20260831.md). Keys unlock ONLY the batch
-- endpoint — no admin, no deletes. Plaintext is shown once at creation
-- (interactive-only); the table stores the SHA-256 hash, the same
-- sha256-compare pattern as the probe fleet's X-Probe-Key.

CREATE TABLE IF NOT EXISTS scan_api_keys (
    id SERIAL PRIMARY KEY,
    label TEXT NOT NULL,                    -- human description, e.g. "decay-battery-runner"
    key_hash TEXT NOT NULL UNIQUE,          -- sha256 hex of the plaintext key
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    use_count INTEGER NOT NULL DEFAULT 0,
    revoked_at TIMESTAMPTZ                   -- NULL = active; set = dead key
);

CREATE INDEX IF NOT EXISTS ix_scan_api_keys_hash ON scan_api_keys (key_hash) WHERE revoked_at IS NULL;

-- +goose Down
DROP TABLE IF EXISTS scan_api_keys;
