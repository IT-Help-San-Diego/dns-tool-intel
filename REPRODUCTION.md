# REPRODUCTION.md — Independent Build Record

This file records actual attempts to build and run published DNS Tool deposits
from a clean download. It exists so the reproducibility claim in `BUILD.md` and
on Zenodo is backed by dated tests rather than an assertion.

Each entry states what was verified **and what was not**.

---

## 2026-07-26 — Zenodo record 20777315

| Field | Value |
|---|---|
| Concept DOI | [10.5281/zenodo.19468134](https://doi.org/10.5281/zenodo.19468134) |
| Version DOI | 10.5281/zenodo.20777315 |
| Archive | `IT-Help-San-Diego/dns-tool-intel-v26.50.05.zip` (173,482,750 bytes) |
| SHA-256 | `e8f198f68defb9d75a65ea6d485c0fc0703cbacd7c40b8a71fad3f5962656222` |
| Extracted root | `IT-Help-San-Diego-dns-tool-intel-e2b0b31` |
| Toolchain | go1.25.11 darwin/arm64 |
| Tester | Claude Science (agent), commissioned by the author |

### Result: builds cleanly

```
$ go build ./go-server/cmd/server
exit 0 — 10.8 s, 65,122,658-byte Mach-O arm64 binary
```

32 module dependencies resolved from the default Go module proxy.

### Engine tests pass from the deposit

```
ok   dnstool/go-server/internal/icae      0.324s
ok   dnstool/go-server/internal/icuae     0.477s
ok   dnstool/go-server/internal/unified   0.254s
ok   dnstool/go-server/internal/zoneparse 0.505s
ok   dnstool/go-server/internal/citation  0.266s
```

### `--version` verified (after the fix in this release)

The deposit's `main.go` parsed no arguments, so the command `BUILD.md`
documented for verifying a build instead attempted to start the server and bind
a port. With `printVersionAndExit` applied to the deposit source and rebuilt:

```
$ ./server --version
DNS Tool dev
  commit:     dev
  built:      unknown
  go:         go1.25.11
  platform:   darwin/arm64

Built without version injection (plain `go build`).
For a version-stamped binary: bash build.sh
exit 0
```

Confirmed to require no database, no environment variables, and no bindable
port. `--help`, `-v`, and bare `version` behave equivalently.

### 2026-07-26, later the same day — container verified by the author

The `Dockerfile` was built and run on the author's machine (Docker legacy
builder, darwin/arm64). **All 23 steps succeeded**, image tagged
`dns-tool-test:latest`. This closes the container item below.

The run then produced a result that contradicted this project's own
documentation, which is the more valuable outcome:

```
INFO  Citation registry loaded entries=62
INFO  Early listener started — accepting healthchecks  address=0.0.0.0:5000
ERROR Failed to load config  error="DATABASE_URL environment variable is required"
[exit 1]
```

**The server does not run without a database.** `BUILD.md` had claimed it did,
on the strength of reading `runDegradedMode` in `main.go` without executing it.
Tracing the actual order of operations:

1. `config.Load()` runs **before** `db.Connect`, and returns an error when
   `DATABASE_URL` is unset — `main.go` then calls `os.Exit(1)`.
2. `SESSION_SECRET` is required by the same function, so it is a second hard
   dependency that was undocumented.
3. `runDegradedMode` is only reachable when `DATABASE_URL` **is** set but the
   database is unreachable. It serves a 503 maintenance page and retries every
   15 s. It is a production-outage resilience path, not an evaluation mode — no
   DNS analysis is available while it is active.

A third defect surfaced from the same trace: `RunSeedMigrations` only applies
migration files whose names contain `seed` (two of fifteen), so the base schema
is **not** created automatically on a fresh database.

Fixes: `BUILD.md` corrected on all three points, and `docker-compose.yml` added
so `docker compose up` provisions PostgreSQL, loads `schema.sql`, and supplies
both required variables.

**This is the value of running the thing.** Three defects — a false capability
claim, an undocumented required variable, and a schema-initialisation gap — none
of which were visible from reading the source, and all of which a researcher
would have hit within a minute of first launch.

### 2026-07-26, third run — `docker compose up`: the platform serves

`docker compose up` brought up both containers successfully. Verbatim from the
app log:

```
Database connected successfully
seed: migration applied  013_seed_findings_and_ede.sql
seed: migration applied  015_confidence_scores_link_seed.sql
Templates directory resolved  path=go-server/templates
Static directory resolved     path=static
SRI hashes computed  assets=13
Loaded IANA RDAP map  tld_count=1200
CISA IP list refreshed  entries=485
IETF metadata: bulk fetch complete  fetched=21 total=21
Full router ready — handler swapped  address=0.0.0.0:5000 version=compose-local
```

The database container executed `00-schema.sql` (all tables and indexes created)
and reported healthy before the app started. Both `*seed*` migrations applied.
The container-asset paths were correct: templates resolved from
`go-server/templates`, static from `static`.

**Two operational findings from this run:**

1. **Port 5000 is unusable on macOS.** An initial `curl localhost:5000` returned
   `403 Forbidden` — but not from DNS Tool. `lsof -iTCP:5000 -sTCP:LISTEN`
   showed `ControlCe` (Apple AirPlay Receiver) holding the port, and the
   response carried `Server: AirTunes/950.7.1` with
   `X-Apple-RequestReceivedTimestamp`. The request never reached the container.
   `docker-compose.yml` now publishes on host port **5055**.
2. **`mkdir logs: permission denied`** (WARN, non-fatal). The image runs as
   non-root uid 10001 with `WORKDIR /app` owned by root, so the structured
   logger cannot create `/app/logs` and falls back to stderr. Harmless for
   evaluation; worth fixing so container logs are complete.

### NOT verified in the 2026-07-26 build run

Stated plainly, because a reproduction record that only lists successes is not
evidence:

- **HTTP serving.** The test environment forbade binding sockets. Every attempt
  to start the server — `PORT=5000`, `8099`, `18080` — failed at
  `bind: operation not permitted` before reaching application logic. No page
  was ever served and no endpoint was reached.
- ~~**Degraded mode.**~~ **Resolved — the documented claim was false.** See
  above: it is a database-outage path, not a no-database mode, and reaching it
  requires `DATABASE_URL` to be set.
- ~~**Container image.**~~ **Now verified** — see the entry above. All 23 build
  steps completed and the binary started; the asset paths were correct.
- ~~**`docker-compose.yml` is untested.**~~ **Now run successfully** — see the
  third-run entry above.
- **An HTTP 200 from the application has still not been captured.** The stack
  reached "Full router ready", but the only curl attempts in this session hit
  the macOS AirPlay service on port 5000 rather than the container. A request to
  the corrected port (5055) has not yet been recorded.
- **Clean-room independence.** A remote host was dispatched first but was
  powered down (`connect ... Operation timed out`), so the build ran on the
  author's own machine with a project-adjacent toolchain. It is a build from a
  pristine Zenodo download, but not an unrelated-machine test.

### Defects found and fixed in this release

1. `./server --version` did not exist despite `BUILD.md` documenting it — fixed.
2. `BUILD.md` said `cd dns-tool` after cloning `dns-tool-intel` — fixed.
3. `BUILD.md` never mentioned `DATABASE_URL` or degraded mode — documented.
4. `BUILD.md` said "Go 1.25+" while `go.mod` requires ≥ 1.25.12 — corrected.
5. `.zenodo.json` claimed all `*_oss.go` build-tag stubs are included; the
   archive contains zero. **Resolved — the claim was stale, not the archive
   incomplete.** Git history shows `_oss.go` files did exist (added in the
   initial import) and `_intel.go` counterparts appear in 13 commits, but
   `docs/ARCHIVED_BUILD_TAG_HISTORY.md` records that v26.48 unified the two
   repositories, removed every build tag, and renamed each `_oss.go` stub to
   `_impl.go` carrying its full implementation. Eight `_impl.go` files are
   present in both the working tree and this deposit, and `grep` finds no
   `//go:build intel` tag anywhere. Nothing is withheld from the archive; the
   description was simply written for the previous architecture. Corrected.
6. Deposit metadata version read 26.46.14 while the archived file was
   `v26.50.05.zip`. Guarded going forward by
   `.github/workflows/guard_release_metadata.yml`.

### Zenodo access statistics at time of test

173 views (90 unique) · 0 downloads reported.

Treat the download figure as a lower bound: a re-query taken *after* this
test's completed 173 MB retrieval still reported 0, so the counter lags by an
unknown interval.

---

## How to add an entry

Anyone may append a result — independent reproductions are the point.

```bash
# 1. Resolve the concept DOI to the latest version record
curl -sSL https://zenodo.org/api/records/19468134 -o record.json

# 2. Download the archive named in that record, then checksum it
sha256sum <archive>.zip

# 3. Build
unzip -q <archive>.zip && cd IT-Help-San-Diego-dns-tool-intel-*
go build ./go-server/cmd/server

# 4. Verify — needs no database and opens no port
./server --version

# 5. Run it. BOTH variables are mandatory: the process exits 1 without either.
#    Against a fresh database, load the schema first — the server does not.
export DATABASE_URL="postgres://user:pass@localhost:5432/dnstool?sslmode=disable"
export SESSION_SECRET="$(openssl rand -hex 32)"
psql "$DATABASE_URL" -f go-server/db/schema/schema.sql
PORT=5000 ./server

# 6. Confirm it serves
curl -s localhost:5000/api/capacity
```

If you do not want to provision PostgreSQL by hand, `docker compose up` from
the repository root does steps 3-5 in one command.

Report the toolchain version, platform, elapsed build time, and anything that
failed. **Negative results are more useful than positive ones** — if it does not
build on your platform, that is the finding worth recording.
