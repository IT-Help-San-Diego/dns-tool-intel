-- sqlc COMPILATION STUB ONLY — not part of the schema documentation.
--
-- schema.sql deliberately omits the version-ledger tables (they are created
-- by the migration runner, not by a migration — see its header). But
-- db/queries/icuae.sql scopes the Grade Distribution to the 018 adoption by
-- reading goose_db_version, so sqlc needs the table's SHAPE to compile that
-- query. This file exists solely for sqlc; regen-schema-doc.sh does not
-- touch it, and nothing executes it. Shape mirrors goose v3's table plus the
-- runner's checksum ledger (migrate.go).
CREATE TABLE goose_db_version (
    id SERIAL PRIMARY KEY,
    version_id BIGINT NOT NULL,
    is_applied BOOLEAN NOT NULL,
    tstamp TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE TABLE schema_migration_checksums (
    version_id BIGINT PRIMARY KEY,
    filename TEXT NOT NULL,
    sha256 TEXT NOT NULL
);
