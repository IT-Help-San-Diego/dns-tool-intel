-- +goose Up
-- 014_site_analytics_hll.sql — True unique-visitor counting via HyperLogLog++
--
-- Why this exists:
--   Prior to this migration, the "Total Unique Visitors" stat was computed as
--     SELECT SUM(unique_visitors) FROM site_analytics
--   which is mathematically WRONG. A visitor seen on N different days produces
--   N distinct daily pseudoIDs (because the salt rotates daily for forward
--   secrecy), so SUM double-counts every returning visitor.
--
-- The scientifically correct approach:
--   HyperLogLog (HLL) is the canonical streaming algorithm for distinct-count
--   estimation over arbitrary windows. HLL sketches are MERGEABLE: the union
--   of two sketches is itself a valid sketch over the union of the underlying
--   sets. So we can store one sketch per day and union them at query time to
--   compute the true number of distinct visitors across any date range.
--
-- Citations:
--   Flajolet, P., Fusy, É., Gandouet, O., & Meunier, F. (2007).
--     "HyperLogLog: the analysis of a near-optimal cardinality estimation
--     algorithm." DMTCS Proceedings, AH, 137–156.
--   Heule, S., Nunkesser, M., & Hall, A. (2013).
--     "HyperLogLog in Practice: Algorithmic Engineering of a State-of-the-Art
--     Cardinality Estimation Algorithm." EDBT '13, 683–692.
--
-- Implementation: github.com/axiomhq/hyperloglog v0.2.6, precision=14
--   m = 2^14 = 16384 registers
--   relative standard error ≈ 1.04 / sqrt(m) ≈ 0.81%
--   serialized dense size ≈ 12 KB per day
--
-- Privacy posture:
--   HLL sketches store only the per-register max leading-zero count, never
--   the underlying identifiers. They cannot be reversed to recover IPs, UAs,
--   or visitor IDs. The stable salt that mixes (ip, ua) before hashing is
--   server-side only; rotation is deliberately NEVER performed because doing
--   so would break union mergeability across the rotation boundary.

ALTER TABLE site_analytics
    ADD COLUMN IF NOT EXISTS hll_visitors BYTEA;

COMMENT ON COLUMN site_analytics.hll_visitors IS
    'HyperLogLog++ sketch (precision=14, m=16384) of stable-salted visitor hashes. Mergeable across days; expected relative standard error ~0.81%. Stores only register max values, no individual identifiers. Implementation: github.com/axiomhq/hyperloglog v0.2.6.';

CREATE TABLE IF NOT EXISTS analytics_meta (
    key         TEXT PRIMARY KEY,
    value       BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE analytics_meta IS
    'Server-side singleton config for analytics. Stores the stable HLL salt (key=hll_salt_v1, 32 bytes, generated once at first server start, never rotated) used to hash (ip, ua) tuples before insertion into HLL sketches. Stable salt enables mergeable HLL union across days for true unique-visitor counting.';
