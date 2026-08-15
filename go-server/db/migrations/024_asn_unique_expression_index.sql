-- +goose Up
-- 024_asn_unique_expression_index.sql
-- Expression index on the unique ASN set computed by every scan
-- (asn_lookup.go LookupASN → full_results → asn_info → unique_asns).
--
-- The CDN-proxied gate (#362) works per-scan today because the data is in
-- full_results. What it cannot answer is the flux question: "has this domain's
-- ASN set changed across N observations?" That query currently parses
-- full_results per row — the same shape that made /stats take 24 seconds
-- before migration 021.
--
-- PLAIN CREATE INDEX, never CONCURRENTLY (see 021/022/023): migrate.go wraps
-- each migration in a transaction, and CREATE INDEX CONCURRENTLY is rejected
-- inside a transaction block.
CREATE INDEX IF NOT EXISTS ix_da_asn_unique
    ON domain_analyses ((full_results -> 'asn_info' -> 'unique_asns'));