# Database migrations

**Status: landed 2026-07-30.** Before this date there was no migration system.
This document is the deploy note for that change, and the standing reference for
how the schema moves.

---

## The production invariant, and what just changed about it

Every deploy and import brief written before 2026-07-30 carried this constraint
verbatim, and it was correct at the time:

> On the database, one more thing. There is no migration system in this project
> today — schema changes have only ever shipped as full schema.sql replacements
> against an empty database. The topology branch touches neither
> go-server/db/schema/ nor go-server/db/migrations/, so "code only" is a
> description of the diff, not a request. Treat it as a hard invariant for every
> import until a migration system exists: an import must never drop, rebuild, or
> re-initialise the production database. The production instance holds months of
> scan_phase_telemetry rows and has no upgrade path — losing them is
> unrecoverable.

**A migration system now exists, so the clause that was waiting on it —
"until a migration system exists" — has been satisfied.** Two things follow, and
they are not the same thing:

**What relaxes.** Schema changes no longer require a full `schema.sql`
replacement against an empty database, and an import that carries a schema
change is no longer a special event. Add a migration; the server applies it on
the next start. There is now a defined upgrade path for the production
instance, which is the thing that did not exist before.

**What does NOT relax.** *An import must still never drop, rebuild, or
re-initialise the production database.* That sentence was never a workaround for
the missing migration system — it protects irreplaceable rows, and those rows
are exactly as irreplaceable today. The upgrade path exists so that rebuilding
is unnecessary, not so that it is now safe.

If you are reading this because a brief told you "this import needs no schema
change": that is a description of the diff. It is not permission to rebuild the
database, and it never was.

---

## How the schema moves

`go-server/db/migrations/` holds the chain. It is embedded in the binary with
`go:embed` (`embed.go`), so the migrations that ship are the ones that were
compiled, and the server no longer depends on being started from the repository
root to find them.

At startup `db.Migrate` (`go-server/internal/db/migrate.go`):

1. applies **only pending versions**, in ascending order, **each in its own
   transaction**;
2. records them in `goose_db_version`, with per-file SHA-256 in
   `schema_migration_checksums`;
3. **exits non-zero on any failure.** The server never serves from a database
   whose shape it cannot vouch for. This is the deliberate opposite of the old
   loader, which logged a warning and continued.

### The four states it distinguishes

| Database | What happens |
|---|---|
| Empty | Full schema created from 001. This is how `docker compose up` provisions. |
| Behind the binary | Pending migrations applied. Existing data untouched. |
| Ahead of the binary | **Refuses to start**, naming both versions. Old code against a new schema returns wrong answers instead of errors. |
| Pre-ledger (no `goose_db_version`) | **Adopted**: the runner reads each migration's own SQL, checks which of its objects already exist, and stamps the versions the schema already reflects — executing nothing. Genuinely missing migrations then run normally. |

Adoption is the path every database that predates 2026-07-30 takes, including
production. It writes no DDL to a populated database. If it finds a database it
cannot account for — a populated schema matching nothing in the chain, or a
migration that is *half* applied — it refuses to start and says which objects
are missing, rather than guessing.

### Rules for changing the schema

- **Add a migration. Never edit an applied one.** Applied files are checksummed;
  editing one is caught at startup and refuses the boot. The database does not
  contain what an edited chain claims it contains.
- **Number sequentially from the current maximum.** The chain must stay
  contiguous from 001; `TestEmbeddedChainIsWellFormed` enforces it.
- **Start each file with `-- +goose Up`.**
- **If a statement contains `--` inside a string literal** (a shell flag in
  quoted evidence text, say), wrap it in `-- +goose StatementBegin` /
  `-- +goose StatementEnd`. goose's splitter is not quote-aware and will read it
  as a comment. `TestNoUnsplittableStatements` catches this without a database.
- **No down migrations.** Deliberate: a rollback that drops tables is the exact
  operation the production invariant forbids. Correct forward.

### schema.sql is documentation

`go-server/db/schema/schema.sql` is `pg_dump --schema-only` of the migrated
schema. **Nothing executes it** — not Compose, not the server, not the tests.
Regenerate it with `./scripts/regen-schema-doc.sh` after adding a migration;
`TestSchemaDocMatchesMigratedDatabase` fails if it drifts.

It used to be a hand-maintained second representation of the chain, and it had
already drifted: it was missing the `COMMENT ON TABLE analytics_meta` that
migration 014 adds, and it recorded `site_analytics.hll_visitors` in a column
position no real database has.

---

## Verification performed at landing (2026-07-30)

Against PostgreSQL 16, with the compiled server binary, not just the test suite:

- **Empty database** → 15 migrations applied, server serves.
- **Pre-ledger database** built from the *old* `schema.sql` plus the two `*seed*`
  migrations the old loader ran → adopted at version 15, 35 tables present,
  nothing executed, `scan_phase_telemetry` and `domain_analyses` rows intact,
  server serves.
- **Database behind the binary** (ledger rewound to 13, migration 014/015 objects
  removed) → exactly 2 migrations applied, objects restored, rows intact.
- **Database ahead of the binary** (version 16 stamped) → **exit 1**,
  `"database schema is at version 16, but this binary only knows up to version
  15"`, no port bound.
- **Compose, volume kept across a rebuild** → second boot logs `schema up to
  date`, inserted scan history still present.

`go test ./go-server/...` — exit 0.
