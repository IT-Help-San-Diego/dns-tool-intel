-- +goose Up
-- 019_domain_analyses_app_version.sql
-- Give the main analysis table the producer attribution the score tables
-- have had since 001.
--
-- ice_test_runs and icuae_scan_scores record app_version on every row;
-- domain_analyses — the table the history and stats surfaces read — records
-- only created_at. Without the producing version, a local-vs-cloud statistic
-- over grader-semantic fields (verdicts, posture mixes, confidence) cannot
-- distinguish a real difference from two grader vocabularies: "local says
-- 40%, cloud says 55%" is uninterpretable. That makes those statistics
-- tier 3 (not comparable) in the stats-lever comparability spec, PERMANENTLY,
-- unless rows start carrying their producer. This column turns tier 3 into a
-- shrinking set: history stays unattributed ('' below), but every row from
-- 019 onward names the build that measured it.
--
-- TEXT, not VARCHAR(n) — the producer is `git describe --tags --always`
-- via ldflags, whose output GROWS with commit distance from the last tag and
-- has no maximum. Production measured 23 characters (26.50.05-473-ga9a88fad4)
-- the night this migration was written; VARCHAR(20) would have refused every
-- insert with SQLSTATE 22001 and, because InsertAnalysis binds the value,
-- dropped the ENTIRE analysis row — the VARCHAR(5) grade defect reproduced
-- one column over, in the migration written to prevent that class. Caught
-- pre-merge by the Courier, by counting. An unbounded producer gets an
-- unbounded column; truncating git-describe output to fit a width would
-- fabricate version identifiers. '' on existing rows is the honest value:
-- their producer was never recorded. The default is then DROPPED, 018's
-- reasoning: both write paths bind the value explicitly, so a default that
-- fires would be fabricating attribution — fail loudly instead.
ALTER TABLE domain_analyses ADD COLUMN app_version TEXT NOT NULL DEFAULT '';
ALTER TABLE domain_analyses ALTER COLUMN app_version DROP DEFAULT;

-- The SAME defect is not hypothetical for the score tables: it is live.
-- icuae_scan_scores.app_version and ice_test_runs.app_version are
-- VARCHAR(20) (001:120, 001:234), and production's ICuAE recording stopped
-- on 2026-06-20 — the last row carries 8-char '26.50.04', and every dev
-- ship since (git-describe suffixed, >20 chars) has failed its scan-score
-- insert with 22001 behind a background WARN. Six weeks of silent score
-- loss, measured 2026-08-01. Widen both to match the producer.
ALTER TABLE icuae_scan_scores ALTER COLUMN app_version TYPE TEXT;
ALTER TABLE ice_test_runs ALTER COLUMN app_version TYPE TEXT;
