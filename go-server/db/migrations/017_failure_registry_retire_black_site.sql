-- +goose Up
-- 017_failure_registry_retire_black_site.sql
-- Retires the "Black Site" vocabulary in favour of the Failure Registry.
--
-- The page publishes this project's own defects. Its framing described that
-- as a secret prison — findings were "detainees" held in "cells", processed
-- by "rendition" and "enhanced interrogation" (the literal euphemism for
-- torture). An institution that publishes its own failures is making a
-- checkable claim about its own reliability; the old vocabulary made a claim
-- about attitude instead. The adversarial stance is kept in full: the same 46
-- findings, their fingerprints, the five-tier severity scale with S0 for
-- regressions, the T001-T005 team designations, and the practice of
-- publishing defects against ourselves.
--
-- TWO INDEPENDENT CHANGES, both in this file because they retire one
-- vocabulary:
--
--   (A) DROP the black_site_detainees / black_site_renditions tables.
--
--       This project's standing rule is that a migration renames and never
--       drops, because a drop loses the ledger. That rule protects DATA, and
--       measurement (2026-07-30) shows there is none in the blast radius:
--
--         * 0 rows in both tables (dev database)
--         * 0 callers for all 12 generated query functions outside the
--           generated file itself
--         * no INSERT path anywhere in the repository or in any migration —
--           the only two INSERT statements are the unused sqlc query
--           definitions that generate those uncalled functions
--         * the live page reads `findings` (see blacksite.go ListFindings),
--           which migration 013 seeded with the 46 records
--
--       So the drop is defensible BECAUSE the ledger lives in `findings` and
--       neither table is read — not because dropping became acceptable. A
--       rename would preserve dead code under a better name and leave the
--       next reader unsure which table is authoritative.
--
--       "No write path exists" is an inference; a row count is a
--       measurement. The guard below takes the measurement at run time, on
--       whatever database this executes against, and aborts the whole
--       migration if either table holds a single row. It cannot be forgotten
--       the way a human pre-flight check can.
--
--   (B) REMAP the status vocabulary on `findings`.
--
--       DETAINED            -> OPEN            (38 rows at time of writing)
--       UNDER_INTERROGATION -> UNDER_ANALYSIS
--       RENDERED            -> RESOLVED        (8 rows at time of writing)
--       EXTRADITED          -> REFERRED        (handed to an upstream owner)
--       VERIFIED, CONTAINED, REGRESSED, DISMISSED unchanged — already
--       ordinary engineering terms, and REGRESSED carries the S0 concept.
--
--       No legacy_status column is added, deliberately. legacy_bsi_id
--       preserves an IDENTIFIER with external references (BSI-2026-0007 must
--       keep resolving); a status is a state value with no external
--       reference, so a legacy column would be a permanent consistency
--       obligation with no consumer. This migration file is the provenance
--       record — the mapping above is the durable answer to "what was this
--       row before", which is what the versioned migration system is for.

-- (A) Guard, then drop. RAISE EXCEPTION aborts the transaction goose runs
-- this in, so a non-empty table stops the migration with the count in the
-- message rather than destroying anything.
-- +goose StatementBegin
DO $$
DECLARE
    detainee_count integer := 0;
    rendition_count integer := 0;
BEGIN
    IF to_regclass('public.black_site_detainees') IS NOT NULL THEN
        EXECUTE 'SELECT count(*) FROM black_site_detainees' INTO detainee_count;
    END IF;
    IF to_regclass('public.black_site_renditions') IS NOT NULL THEN
        EXECUTE 'SELECT count(*) FROM black_site_renditions' INTO rendition_count;
    END IF;

    IF detainee_count > 0 OR rendition_count > 0 THEN
        -- USING MESSAGE with format(), not RAISE's own % placeholders: the
        -- counts are the entire point of this message, and they have to
        -- survive the trip through goose and the server's structured logger.
        -- RAISE's placeholders are substituted by Postgres but arrive at the
        -- operator's log still reading "=%" once the error is wrapped; baking
        -- the numbers in with format() makes the message self-contained.
        RAISE EXCEPTION USING MESSAGE = format(
            'Refusing to drop non-empty black-site tables: black_site_detainees=%s rows, black_site_renditions=%s rows. The drop was justified by these tables being empty and unread. They are not empty here — stop, inspect the rows, and decide deliberately (migrate them into findings, or export them) before removing this guard.',
            detainee_count, rendition_count);
    END IF;
END
$$;
-- +goose StatementEnd

DROP TABLE IF EXISTS black_site_renditions;
DROP TABLE IF EXISTS black_site_detainees;

-- (B) Status remap. The CHECK constraint is replaced before the values are
-- rewritten, since the old constraint would reject every new value.
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_status_check;

UPDATE findings SET status = 'OPEN'           WHERE status = 'DETAINED';
UPDATE findings SET status = 'UNDER_ANALYSIS' WHERE status = 'UNDER_INTERROGATION';
UPDATE findings SET status = 'RESOLVED'       WHERE status = 'RENDERED';
UPDATE findings SET status = 'REFERRED'       WHERE status = 'EXTRADITED';

ALTER TABLE findings ADD CONSTRAINT findings_status_check CHECK (
    status IN ('OPEN', 'VERIFIED', 'UNDER_ANALYSIS', 'CONTAINED',
               'RESOLVED', 'REGRESSED', 'REFERRED', 'DISMISSED')
);

UPDATE finding_events SET from_status = 'OPEN'           WHERE from_status = 'DETAINED';
UPDATE finding_events SET from_status = 'UNDER_ANALYSIS' WHERE from_status = 'UNDER_INTERROGATION';
UPDATE finding_events SET from_status = 'RESOLVED'       WHERE from_status = 'RENDERED';
UPDATE finding_events SET from_status = 'REFERRED'       WHERE from_status = 'EXTRADITED';
UPDATE finding_events SET to_status   = 'OPEN'           WHERE to_status   = 'DETAINED';
UPDATE finding_events SET to_status   = 'UNDER_ANALYSIS' WHERE to_status   = 'UNDER_INTERROGATION';
UPDATE finding_events SET to_status   = 'RESOLVED'       WHERE to_status   = 'RENDERED';
UPDATE finding_events SET to_status   = 'REFERRED'       WHERE to_status   = 'EXTRADITED';

-- +goose Down
-- Restores the prior vocabulary for the status columns. The dropped tables
-- are NOT recreated: they held no rows, had no readers, and no write path
-- ever existed, so recreating empty shells would restore the name without
-- restoring anything real.
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_status_check;

UPDATE findings SET status = 'DETAINED'            WHERE status = 'OPEN';
UPDATE findings SET status = 'UNDER_INTERROGATION' WHERE status = 'UNDER_ANALYSIS';
UPDATE findings SET status = 'RENDERED'            WHERE status = 'RESOLVED';
UPDATE findings SET status = 'EXTRADITED'          WHERE status = 'REFERRED';

ALTER TABLE findings ADD CONSTRAINT findings_status_check CHECK (
    status IN ('DETAINED', 'VERIFIED', 'UNDER_INTERROGATION', 'CONTAINED',
               'RENDERED', 'REGRESSED', 'EXTRADITED', 'DISMISSED')
);

UPDATE finding_events SET from_status = 'DETAINED'            WHERE from_status = 'OPEN';
UPDATE finding_events SET from_status = 'UNDER_INTERROGATION' WHERE from_status = 'UNDER_ANALYSIS';
UPDATE finding_events SET from_status = 'RENDERED'            WHERE from_status = 'RESOLVED';
UPDATE finding_events SET from_status = 'EXTRADITED'          WHERE from_status = 'REFERRED';
UPDATE finding_events SET to_status   = 'DETAINED'            WHERE to_status   = 'OPEN';
UPDATE finding_events SET to_status   = 'UNDER_INTERROGATION' WHERE to_status   = 'UNDER_ANALYSIS';
UPDATE finding_events SET to_status   = 'RENDERED'            WHERE to_status   = 'RESOLVED';
UPDATE finding_events SET to_status   = 'EXTRADITED'          WHERE to_status   = 'REFERRED';
