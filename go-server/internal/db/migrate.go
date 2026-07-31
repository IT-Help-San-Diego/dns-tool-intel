// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	migrations "dnstool/go-server/db/migrations"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
	"github.com/pressly/goose/v3"
)

// The schema is versioned in the database, not assumed from the binary.
//
// What this replaces: RunSeedMigrations, which read the migrations directory
// from a working-directory-relative path, skipped every file whose name did not
// contain "seed" (2 of 15), re-executed those two on every boot, and on failure
// logged a warning and let the server come up against a database in an unknown
// state. There was no version ledger anywhere in the project, so a kept
// dnstool-pgdata volume from an older build met a newer binary with nothing to
// upgrade it and nothing that could detect the mismatch.
//
// The contract now:
//   - the chain is embedded (go-server/db/migrations), so there is no path
//     dependency and the shipped migrations are the compiled ones;
//   - only PENDING versions run, in ascending order, each in its own
//     transaction, and any failure is returned — callers must exit non-zero;
//   - a database NEWER than the binary is refused, naming both versions,
//     because running old code against a new schema corrupts silently;
//   - already-applied migrations are checksummed, so editing one after it has
//     been applied is caught instead of being silently ignored;
//   - a pre-ledger database is ADOPTED (stamped, no DDL executed), never
//     rebuilt. Months of scan_phase_telemetry rows have no other copy.
const (
	// checksumTable records the SHA-256 of each migration as applied. goose has
	// no checksum support of its own, so this is ours, and it lives beside
	// goose_db_version rather than inside it.
	checksumTable = "schema_migration_checksums"

	// migrateTimeout bounds the whole run. 013_seed_findings_and_ede.sql is 72 KB
	// of INSERTs and is the slowest single step; on an empty database the full
	// chain completes in well under a second locally, so this is a hang guard,
	// not a budget.
	migrateTimeout = 120 * time.Second
)

// migrationFile is one embedded migration, identified by the version encoded in
// its filename prefix and fingerprinted by the SHA-256 of its bytes.
type migrationFile struct {
	Version  int64
	Filename string
	SHA256   string

	// Objects is what this migration creates, parsed from its own SQL. It is
	// what the adoption probe compares against a pre-ledger database.
	//
	// Derived from the producer on purpose. The alternative — a hand-written
	// list of "what a legacy database looks like" — is a second representation
	// of the same fact, and second representations drift. schema.sql was
	// exactly that, and it had already lost a COMMENT that migration 014 adds.
	Objects migrationObjects
}

// Migrate brings the database at databaseURL up to the version embedded in this
// binary. It returns an error for every condition that leaves the schema in a
// state the binary cannot vouch for; the caller must treat that as fatal.
func Migrate(ctx context.Context, databaseURL string) error {
	ctx, cancel := context.WithTimeout(ctx, migrateTimeout)
	defer cancel()

	files, err := loadEmbeddedMigrations()
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return errors.New("migrate: no migrations embedded in the binary — the build is broken")
	}
	embeddedMax := files[len(files)-1].Version

	sqlDB, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return fmt.Errorf("migrate: open database: %w", err)
	}
	defer sqlDB.Close()

	if err := sqlDB.PingContext(ctx); err != nil {
		return fmt.Errorf("migrate: database unreachable: %w", err)
	}

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("migrate: set dialect: %w", err)
	}
	goose.SetBaseFS(migrations.FS)
	goose.SetLogger(gooseSlogLogger{})

	ledgerPresent, err := relationExists(ctx, sqlDB, goose.TableName())
	if err != nil {
		return fmt.Errorf("migrate: probe version ledger: %w", err)
	}

	if !ledgerPresent {
		if err := bootstrapLedger(ctx, sqlDB, files); err != nil {
			return err
		}
	}

	// Creates the ledger for the empty-database case and is a no-op otherwise.
	// Everything below reads it, so it must exist by now.
	if _, err := goose.EnsureDBVersionContext(ctx, sqlDB); err != nil {
		return fmt.Errorf("migrate: create version ledger: %w", err)
	}

	applied, err := appliedVersions(ctx, sqlDB)
	if err != nil {
		return fmt.Errorf("migrate: read applied versions: %w", err)
	}

	if err := refuseIfNewerThanBinary(applied, files, embeddedMax); err != nil {
		return err
	}
	if err := verifyChecksums(ctx, sqlDB, applied, files); err != nil {
		return err
	}

	pending := pendingVersions(applied, files)
	if len(pending) == 0 {
		slog.Info("migrate: schema up to date", "version", maxVersion(applied), "migrations", len(files))
		return nil
	}

	slog.Info("migrate: applying pending migrations",
		"from_version", maxVersion(applied),
		"to_version", embeddedMax,
		"pending", len(pending),
	)

	// goose.UpContext applies each pending version in its own transaction, in
	// ascending order, and stops at the first failure. The migrations that did
	// succeed stay committed and stay stamped, so a rerun resumes rather than
	// repeating.
	if err := goose.UpContext(ctx, sqlDB, "."); err != nil {
		return fmt.Errorf("migrate: applying migrations failed at or after version %d: %w", maxVersion(applied), err)
	}

	if err := recordChecksums(ctx, sqlDB, pending); err != nil {
		return err
	}

	slog.Info("migrate: schema upgraded", "version", embeddedMax, "applied", len(pending))
	return nil
}

// loadEmbeddedMigrations reads the embedded chain and returns it in ascending
// version order, hashing each file so an edit after application can be caught.
func loadEmbeddedMigrations() ([]migrationFile, error) {
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		return nil, fmt.Errorf("migrate: read embedded migrations: %w", err)
	}

	var out []migrationFile
	seen := make(map[int64]string, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		version, err := versionFromFilename(name)
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[version]; dup {
			return nil, fmt.Errorf("migrate: duplicate migration version %d: %s and %s", version, prev, name)
		}
		seen[version] = name

		data, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			return nil, fmt.Errorf("migrate: read embedded migration %s: %w", name, err)
		}
		sum := sha256.Sum256(data)
		out = append(out, migrationFile{
			Version:  version,
			Filename: name,
			SHA256:   hex.EncodeToString(sum[:]),
			Objects:  parseMigrationObjects(string(data)),
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// versionFromFilename extracts the leading integer of a migration filename.
// Version 0 is rejected: goose reserves it for the empty-ledger sentinel, so a
// migration numbered 000 would never be seen as pending.
func versionFromFilename(name string) (int64, error) {
	base := path.Base(name)
	idx := strings.IndexByte(base, '_')
	if idx <= 0 {
		return 0, fmt.Errorf("migrate: migration %q has no NNN_ version prefix", name)
	}
	version, err := strconv.ParseInt(base[:idx], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("migrate: migration %q has an unparseable version prefix: %w", name, err)
	}
	if version <= 0 {
		return 0, fmt.Errorf("migrate: migration %q uses version %d; versions must start at 1 (goose reserves 0)", name, version)
	}
	return version, nil
}

// bootstrapLedger handles a database with no version ledger. An empty database
// falls through and is installed from 001 by the normal path. A populated one
// is ADOPTED: the migrations whose objects are already present are stamped, and
// nothing is executed against it.
//
// This is the case the whole exercise exists for. Every database that predates
// the ledger — the production instance with months of scan_phase_telemetry, a
// researcher's kept dnstool-pgdata volume, a long-lived dev database — arrives
// here, and none of them may be dropped, rebuilt, or re-initialised.
func bootstrapLedger(ctx context.Context, sqlDB *sql.DB, files []migrationFile) error {
	existing, err := inspectSchema(ctx, sqlDB)
	if err != nil {
		return fmt.Errorf("migrate: inspect existing schema: %w", err)
	}

	if len(existing.Tables) == 0 {
		slog.Info("migrate: empty database — installing schema from migration 001")
		return nil
	}

	stampThrough, err := adoptionCutoff(files, existing)
	if err != nil {
		return err
	}
	if stampThrough == 0 {
		return fmt.Errorf(
			"migrate: refusing to start — the database has %d table(s) and no version ledger, but none of them are objects "+
				"migration 001 creates, so there is no version that can honestly be stamped and no migration that can safely run. "+
				"If this database is disposable, drop it and let the server create it from scratch; if it is not, reconcile it "+
				"against the migration chain by hand before starting",
			len(existing.Tables))
	}

	slog.Warn("migrate: adopting pre-ledger database — stamping versions already present, executing nothing",
		"stamp_through", stampThrough,
		"tables_present", len(existing.Tables),
	)

	if _, err := goose.EnsureDBVersionContext(ctx, sqlDB); err != nil {
		return fmt.Errorf("migrate: create version ledger: %w", err)
	}
	if err := ensureChecksumTable(ctx, sqlDB); err != nil {
		return err
	}

	// One transaction: a half-stamped ledger is worse than no ledger, because
	// the next boot would see a partial version set and try to "finish" it by
	// running DDL against objects that already exist.
	tx, err := sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migrate: begin adoption transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stamped := 0
	for _, f := range files {
		if f.Version > stampThrough {
			break
		}
		if _, err := tx.ExecContext(ctx,
			fmt.Sprintf("INSERT INTO %s (version_id, is_applied) VALUES ($1, true)", goose.TableName()),
			f.Version,
		); err != nil {
			return fmt.Errorf("migrate: stamp version %d: %w", f.Version, err)
		}
		if _, err := tx.ExecContext(ctx,
			fmt.Sprintf(`INSERT INTO %s (version_id, filename, sha256) VALUES ($1, $2, $3)
			             ON CONFLICT (version_id) DO UPDATE SET filename = EXCLUDED.filename, sha256 = EXCLUDED.sha256`, checksumTable),
			f.Version, f.Filename, f.SHA256,
		); err != nil {
			return fmt.Errorf("migrate: record checksum for version %d: %w", f.Version, err)
		}
		stamped++
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migrate: commit adoption: %w", err)
	}

	slog.Info("migrate: pre-ledger database adopted", "version", stampThrough, "stamped", stamped)
	return nil
}

// adoptionCutoff returns the highest version that a pre-ledger database can be
// stamped at without executing anything: the longest run, from 001 up, of
// migrations whose objects are ALL already present.
//
// The three outcomes per migration are deliberate:
//
//	every object present → already applied out-of-band; stamp it
//	no object present    → genuinely pending; stop here and let it run
//	some objects present → refuse. A half-applied migration is the one state
//	                       where both stamping and running are wrong, and it is
//	                       not this program's place to guess which.
//
// A migration that creates no objects at all (013 is pure INSERTs) carries no
// evidence either way, so it inherits the run it sits in.
func adoptionCutoff(files []migrationFile, existing schemaObjects) (int64, error) {
	var cutoff int64
	for _, f := range files {
		present, absent := f.Objects.partition(existing)

		if len(present) == 0 && len(absent) == 0 {
			// No observable objects. Inside the adopted run, treat as applied.
			cutoff = f.Version
			continue
		}
		if len(absent) == 0 {
			cutoff = f.Version
			continue
		}
		if len(present) == 0 {
			// This migration and everything after it is pending.
			return cutoff, nil
		}
		return 0, fmt.Errorf(
			"migrate: refusing to start — pre-ledger database is HALF-WAY through migration %d (%s): "+
				"%d object(s) already exist (%s) and %d are missing (%s). "+
				"Stamping it would record work that was never done; running it would fail on the objects that exist. "+
				"Reconcile this migration by hand, then restart",
			f.Version, f.Filename,
			len(present), strings.Join(present, ", "),
			len(absent), strings.Join(absent, ", "))
	}
	return cutoff, nil
}

// refuseIfNewerThanBinary implements the one-way safety rule: an older database
// is upgraded, a newer one is refused. Running this binary's code against a
// schema it does not know produces wrong reads rather than loud failures, so it
// must not be allowed to start.
func refuseIfNewerThanBinary(applied map[int64]struct{}, files []migrationFile, embeddedMax int64) error {
	known := make(map[int64]struct{}, len(files))
	for _, f := range files {
		known[f.Version] = struct{}{}
	}

	var unknown []int64
	for v := range applied {
		if _, ok := known[v]; !ok {
			unknown = append(unknown, v)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Slice(unknown, func(i, j int) bool { return unknown[i] < unknown[j] })

	dbMax := maxVersion(applied)
	if dbMax > embeddedMax {
		return fmt.Errorf(
			"migrate: refusing to start — database schema is at version %d, but this binary only knows up to version %d. "+
				"Unknown applied version(s): %s. "+
				"The database was migrated by a newer build; downgrading the schema is not supported. Run the newer binary",
			dbMax, embeddedMax, joinVersions(unknown))
	}

	return fmt.Errorf(
		"migrate: refusing to start — the database records version(s) %s as applied, but no migration with those versions is embedded in this binary. "+
			"A migration file was renamed or deleted after it was applied; the chain and the database no longer describe the same schema",
		joinVersions(unknown))
}

// verifyChecksums catches a migration that was edited after it was applied —
// the change is invisible to a version-only ledger, because the version is
// already stamped and the file will never run again.
func verifyChecksums(ctx context.Context, sqlDB *sql.DB, applied map[int64]struct{}, files []migrationFile) error {
	if err := ensureChecksumTable(ctx, sqlDB); err != nil {
		return err
	}

	recorded, err := recordedChecksums(ctx, sqlDB)
	if err != nil {
		return err
	}

	var mismatches []string
	var backfill []migrationFile
	for _, f := range files {
		if _, isApplied := applied[f.Version]; !isApplied {
			continue
		}
		got, ok := recorded[f.Version]
		if !ok {
			// Applied with no checksum on record. That is not evidence of an
			// edit — it is a database stamped by something other than this
			// runner — so record what we see and say so, rather than refusing
			// to start over a gap that carries no information.
			backfill = append(backfill, f)
			continue
		}
		if got != f.SHA256 {
			mismatches = append(mismatches, fmt.Sprintf("%s (recorded %s…, embedded %s…)", f.Filename, got[:12], f.SHA256[:12]))
		}
	}

	if len(mismatches) > 0 {
		return fmt.Errorf(
			"migrate: refusing to start — %d already-applied migration(s) have been edited since they ran: %s. "+
				"The database does not contain what the chain now says it contains. "+
				"Restore the original file and express the change as a NEW migration",
			len(mismatches), strings.Join(mismatches, "; "))
	}

	if len(backfill) > 0 {
		slog.Warn("migrate: recording checksums for migrations applied without them",
			"count", len(backfill))
		if err := recordChecksums(ctx, sqlDB, backfill); err != nil {
			return err
		}
	}
	return nil
}

func ensureChecksumTable(ctx context.Context, sqlDB *sql.DB) error {
	_, err := sqlDB.ExecContext(ctx, fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			version_id  BIGINT PRIMARY KEY,
			filename    TEXT NOT NULL,
			sha256      CHAR(64) NOT NULL,
			recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`, checksumTable))
	if err != nil {
		return fmt.Errorf("migrate: create %s: %w", checksumTable, err)
	}
	return nil
}

func recordedChecksums(ctx context.Context, sqlDB *sql.DB) (map[int64]string, error) {
	rows, err := sqlDB.QueryContext(ctx, fmt.Sprintf("SELECT version_id, sha256 FROM %s", checksumTable))
	if err != nil {
		return nil, fmt.Errorf("migrate: read %s: %w", checksumTable, err)
	}
	defer rows.Close()

	out := make(map[int64]string)
	for rows.Next() {
		var version int64
		var sum string
		if err := rows.Scan(&version, &sum); err != nil {
			return nil, fmt.Errorf("migrate: scan %s: %w", checksumTable, err)
		}
		out[version] = sum
	}
	return out, rows.Err()
}

func recordChecksums(ctx context.Context, sqlDB *sql.DB, files []migrationFile) error {
	if err := ensureChecksumTable(ctx, sqlDB); err != nil {
		return err
	}
	for _, f := range files {
		if _, err := sqlDB.ExecContext(ctx, fmt.Sprintf(`
			INSERT INTO %s (version_id, filename, sha256) VALUES ($1, $2, $3)
			ON CONFLICT (version_id) DO UPDATE SET filename = EXCLUDED.filename, sha256 = EXCLUDED.sha256, recorded_at = NOW()`,
			checksumTable), f.Version, f.Filename, f.SHA256); err != nil {
			return fmt.Errorf("migrate: record checksum for %s: %w", f.Filename, err)
		}
	}
	return nil
}

// appliedVersions returns the versions the ledger currently reports as applied.
// goose keeps one row per up/down transition, so the newest row per version_id
// is the one that decides. Version 0 is goose's own sentinel, not a migration.
func appliedVersions(ctx context.Context, sqlDB *sql.DB) (map[int64]struct{}, error) {
	rows, err := sqlDB.QueryContext(ctx, fmt.Sprintf(`
		SELECT DISTINCT ON (version_id) version_id, is_applied
		  FROM %s
		 ORDER BY version_id, id DESC`, goose.TableName()))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[int64]struct{})
	for rows.Next() {
		var version int64
		var isApplied bool
		if err := rows.Scan(&version, &isApplied); err != nil {
			return nil, err
		}
		if isApplied && version > 0 {
			out[version] = struct{}{}
		}
	}
	return out, rows.Err()
}

func pendingVersions(applied map[int64]struct{}, files []migrationFile) []migrationFile {
	var out []migrationFile
	for _, f := range files {
		if _, ok := applied[f.Version]; !ok {
			out = append(out, f)
		}
	}
	return out
}

func maxVersion(applied map[int64]struct{}) int64 {
	var highest int64
	for v := range applied {
		if v > highest {
			highest = v
		}
	}
	return highest
}

func joinVersions(versions []int64) string {
	parts := make([]string, len(versions))
	for i, v := range versions {
		parts[i] = strconv.FormatInt(v, 10)
	}
	return strings.Join(parts, ", ")
}

// relationExists reports whether a relation is visible on the current
// search_path. to_regclass returns NULL rather than erroring when it is not.
func relationExists(ctx context.Context, sqlDB *sql.DB, name string) (bool, error) {
	var reg sql.NullString
	if err := sqlDB.QueryRowContext(ctx, "SELECT to_regclass($1)::text", name).Scan(&reg); err != nil {
		return false, err
	}
	return reg.Valid, nil
}

// gooseSlogLogger routes goose's own progress output into the structured log
// pipeline. Fatalf deliberately does not exit: goose returns its errors, and
// the decision to stop the process belongs to the caller of Migrate.
type gooseSlogLogger struct{}

func (gooseSlogLogger) Printf(format string, v ...interface{}) {
	slog.Info("migrate: " + strings.TrimRight(fmt.Sprintf(format, v...), "\n"))
}

func (gooseSlogLogger) Fatalf(format string, v ...interface{}) {
	slog.Error("migrate: " + strings.TrimRight(fmt.Sprintf(format, v...), "\n"))
}
