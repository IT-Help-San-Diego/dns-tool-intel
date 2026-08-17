-- +goose Up
-- 024_flux_observations.sql
-- Foundation for the two-signature threat model's FLUX signal: a narrow table
-- that persists the resolved-ASN set + TTL per scan, so ASN dispersion over time
-- (the actual fast-flux discriminator) is queryable without full-table JSONB
-- scans of domain_analyses.full_results.
--
-- One row = one observation: the set of ASNs a domain's A/AAAA records resolved
-- to on a single scan, plus the record TTL. The flux detector compares these
-- across consecutive scans — dispersion (the ASN set changing) is the signal,
-- and a short TTL is the co-signal (rapid rotation). A CDN-proxied observation is
-- gated OUT by the analyzer (asn_lookup.go sets flux_observable=false when all
-- addresses share one CDN ASN), so a CDN-proxied domain is never written here as
-- a stable-looking row it cannot prove.
--
-- asn_set is TEXT[] (not INTEGER[]) because the analyzer stores ASN numbers as
-- strings; the GIN index below gives O(1)-ish containment for "which domains
-- observed ASN X" without a full scan.
CREATE TABLE IF NOT EXISTS flux_observations (
    id SERIAL PRIMARY KEY,
    analysis_id INTEGER NOT NULL REFERENCES domain_analyses(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    observed_at TIMESTAMP NOT NULL DEFAULT NOW(),
    asn_set TEXT[] NOT NULL DEFAULT '{}',
    ttl INTEGER,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Domain-scoped: the flux detector queries "all observations for domain X" and
-- compares consecutive rows for dispersion.
CREATE INDEX IF NOT EXISTS ix_flux_obs_domain ON flux_observations (domain);
-- Time-scoped: "observations since T" for the dispersion window.
CREATE INDEX IF NOT EXISTS ix_flux_obs_observed_at ON flux_observations (observed_at);
-- GIN containment: "which domains observed ASN X" (cross-corpus, no full scan).
CREATE INDEX IF NOT EXISTS ix_flux_obs_asn_set ON flux_observations USING GIN (asn_set);

-- +goose Down
DROP TABLE IF EXISTS flux_observations;
