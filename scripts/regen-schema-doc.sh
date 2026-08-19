#!/usr/bin/env bash
# Regenerate go-server/db/schema/schema.sql from the migration chain.
#
# schema.sql is DOCUMENTATION. Nothing executes it: the server builds and
# upgrades databases from go-server/db/migrations, embedded in the binary. This
# script exists so that the file stays a derivation of the chain rather than a
# second hand-maintained copy of it.
#
# It used to be that second copy, and it had already drifted: it was missing the
# COMMENT ON TABLE analytics_meta that migration 014 adds, and it recorded
# site_analytics.hll_visitors in a column position no real database has.
#
#   ./scripts/regen-schema-doc.sh
#
# Requires Docker. Spins up a disposable PostgreSQL 16, applies every migration
# in ascending order, dumps the result, and removes the container. It never
# touches any database you already have.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MIGRATIONS_DIR="$REPO_ROOT/go-server/db/migrations"
OUTPUT="$REPO_ROOT/go-server/db/schema/schema.sql"

# Must match the image Compose uses, or the dump documents a different server's
# formatting rather than ours.
PG_IMAGE="postgres:16-alpine"
CONTAINER="dnstool-schemadoc-$$"

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==> starting disposable $PG_IMAGE"
docker run -d --name "$CONTAINER" \
  -e POSTGRES_PASSWORD=schemadoc \
  -e POSTGRES_DB=schemadoc \
  "$PG_IMAGE" >/dev/null

for _ in $(seq 1 60); do
  docker exec "$CONTAINER" pg_isready -U postgres >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$CONTAINER" pg_isready -U postgres >/dev/null

echo "==> applying migration chain"
docker cp "$MIGRATIONS_DIR" "$CONTAINER:/migrations" >/dev/null
# `sort` here is what makes the dump reproducible: the chain is defined by
# ascending filename version, exactly as the Go runner orders it.
docker exec "$CONTAINER" sh -c '
  set -e
  for f in $(ls /migrations/*.sql | sort); do
    # Apply the Up section ONLY. The real migrator is goose (goose.UpContext),
    # which never executes anything after "-- +goose Down". Feeding the whole
    # file to psql runs the Down section too, so any migration with a live
    # Down was created-then-reverted inside this disposable database — 017'"'"'s
    # Down re-installed the retired findings_status_check vocabulary into
    # every dump, and a table added with a Down section would vanish from the
    # documentation entirely. The dump must document what goose builds.
    sed -n "/^-- +goose Down/q;p" "$f" | psql -U postgres -d schemadoc -v ON_ERROR_STOP=1 -q >/dev/null
    echo "    applied $(basename "$f") (Up section)"
  done'

echo "==> dumping schema"
{
  cat <<'HEADER'
-- GENERATED FILE — DO NOT EDIT, AND DO NOT RUN.
--
-- Regenerate with:  ./scripts/regen-schema-doc.sh
--
-- This is `pg_dump --schema-only` of a database built by applying every
-- migration in go-server/db/migrations in order. It exists so the schema can be
-- read in one place. It is NOT a bootstrap path:
--
--   * docker-compose does not mount it into docker-entrypoint-initdb.d
--   * the server does not execute it
--   * the handler tests do not apply it
--
-- All three now go through the same versioned migration chain, which is the
-- only thing that can both create a database AND upgrade an existing one.
-- Editing this file changes nothing except the documentation; schema changes
-- are made by adding a migration.
--
-- The version ledger tables (goose_db_version, schema_migration_checksums) are
-- deliberately absent: they are created by the runner, not by a migration, and
-- they describe bookkeeping rather than the application's data. See
-- go-server/internal/db/migrate.go.
HEADER
  # Strip the per-run \restrict/\unrestrict nonces so re-running this script
  # against an unchanged chain produces a byte-identical file and an empty diff.
  docker exec "$CONTAINER" pg_dump -U postgres --schema-only --no-owner --no-privileges -d schemadoc \
    | grep -vE '^\\(un)?restrict '
} > "$OUTPUT"

echo "==> wrote $OUTPUT ($(wc -l < "$OUTPUT" | tr -d ' ') lines)"
