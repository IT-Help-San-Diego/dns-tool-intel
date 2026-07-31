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

> **Superseded 2026-07-30.** `RunSeedMigrations` was replaced by a versioned
> migration system. The server now creates the schema on an empty database and
> upgrades an existing one, both from the chain embedded in the binary, and
> Compose no longer mounts `schema.sql` into `docker-entrypoint-initdb.d`. The
> log excerpts and findings below record the behaviour as it was on the dates
> shown; see BUILD.md for current behaviour.

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

### 2026-07-26, second-machine run (linux/amd64) — partly independent

The Replit agent ran the same tests on its own machine. **Its independence is
partial and the distinction matters:** the handoff note it was answering already
stated the central conclusion — "Compose is required: `DATABASE_URL` and
`SESSION_SECRET` are both mandatory and a bare `docker run` of the image exits 1
before serving." So its environment-variable result confirms a finding it was
handed, not one it discovered. Treat those two rows as corroboration on second
hardware, not as independent discovery.

What *is* independent of anything I told it: the build succeeding on a different
architecture, `--version` behaving correctly there, the retry timing, and the
maintenance-page behaviour — none of which appeared in the handoff.

| Test | Result |
|---|---|
| `docker build` from the PR head | PASS, first attempt; asset paths correct |
| `docker run --rm <image> --version` | PASS, exit 0, `go1.25.12 linux/amd64` |
| Run with no `DATABASE_URL` | FAIL — exits 1 at `config.go:72` |
| Run with `DATABASE_URL` only | exits 1 — `SESSION_SECRET environment variable is required` |
| Both set, database unreachable | degraded mode engages after 5 retries (~15 s) |

Two details this adds beyond my own run:

1. **Degraded mode's timing is bounded.** `db.Connect` retries 5 times at 3 s
   intervals (`connectWithRetry(databaseURL, defaultConnector, 5, 3*time.Second)`),
   so the maintenance page appears roughly 15 s after start, not immediately.
2. **Degraded mode serves the maintenance page on every route** — `/api/capacity`
   returns the 503 HTML, not JSON. So even a reachable-then-failed database does
   not yield a partially functional API.

**No fully independent reproduction of this deposit exists yet.** Both runs so
far were performed by agents working from my notes, on this project's own
machines. The build portability result is solid — two architectures, two
toolchains, same outcome — but a genuine independent reproduction means someone
outside this project downloading the Zenodo archive with no guidance from us.
That has not happened, and the deposit's 0 reported downloads says as much.

### 2026-07-26, fourth run — the deposit serves. Loop closed.

With the host port corrected to 5055, a client reached the application:

```
$ curl -s localhost:5055/api/capacity
{"available":20,"in_use":0,"ready":true,"status":"ok","total":20}

$ curl -s -o /dev/null -w '%{http_code}\n' localhost:5055/
200
```

This is the **first HTTP response recorded from this deposit**. The chain is now
verified end to end, each link by execution rather than by reading source:

| Link | Status | Evidence |
|---|---|---|
| Archive downloads from Zenodo | verified | 173,482,750 bytes, SHA-256 recorded above |
| Compiles from source | verified | `go build` exit 0, 10.8 s, 65 MB binary |
| Engine tests pass | verified | icae, icuae, unified, zoneparse, citation all `ok` |
| `--version` works | verified | exit 0, no database, no port |
| Container builds | verified | 23/24 steps, two machines, two architectures |
| Database provisions and schema loads | verified | `00-schema.sql` applied, both seed migrations |
| **Application serves HTTP** | **verified** | `/api/capacity` → JSON, `/` → 200 |

`/api/capacity` returning `total: 20, in_use: 0` also confirms the scan-slot
limiter initialised, i.e. the analysis pipeline is live rather than merely the
router.

### 2026-07-26, fifth run — the UI renders, but analysis was broken

Opening `http://localhost:5055/` in a browser rendered the full interface. Every
attempt to analyze a domain failed with a generic banner: "Network error — please
check your connection and try again."

The server log gave the real reason:

```
WARN  CSRF validation failed  event=csrf_reject  reason="missing CSRF cookie"
      method=POST  path=/analyze  remote_addr=172.19.0.1
INFO  Request completed  method=POST  path=/analyze  status=303
```

**Defect 7 — `Secure` cookies are discarded over plain HTTP.** `csrf.go` set
`Secure: true` unconditionally on the `_csrf` cookie (and `ratelimit.go` did the
same for the two flash cookies). A browser silently refuses to store a `Secure`
cookie delivered over `http://`, so the double-submit check had no cookie to
compare against and every POST was rejected with a 303 back to the form. The
frontend's `.catch()` in `main.js` reports any non-2xx as "Network error", which
is why the cause was invisible from the UI.

This is the defect that most directly answers "can a researcher use this?" —
the container serves, the interface renders, and **the primary function silently
does not work.** A researcher would reasonably conclude the tool was broken.

**Fix:** a new `CookieSecure(c)` helper returns `true` for every request that is
not provably a plaintext loopback request. Both conditions must hold to drop
`Secure`: no TLS (directly or via `X-Forwarded-Proto`, the same test the CSP
`upgrade-insecure-requests` directive already used) *and* a loopback `Host`.
Production traffic fails both tests, so a deployed cookie cannot be downgraded.

**Verification:** `go test ./go-server/internal/middleware/` — 13 table cases
plus two end-to-end handler tests, all passing, and the full existing middleware
suite still `ok`. The cases that matter are the ones asserting `Secure` is
*kept*: canonical host behind a TLS-terminating proxy, canonical host with direct
TLS, canonical host over plaintext, a loopback host that is nonetheless
TLS-terminated upstream, a LAN address, a hostname merely containing
"localhost", `evil.localhost`, and an empty `Host`.

Not yet confirmed in a browser — the fix is committed but the container has not
been rebuilt against it.

### Remaining open items

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
- ~~**An HTTP 200 from the application has still not been captured.**~~
  **Closed** — see the fourth-run entry above.
- **No analysis has completed through the container.** Serving is confirmed and
  the cookie defect that blocked submission is fixed and unit-tested, but no
  domain analysis has yet run end to end — so live outbound DNS from inside the
  container remains unverified.
- **Linux/amd64 serving is unconfirmed.** The Replit agent verified the build and
  `--version` on amd64 but did not bring up Compose there; the HTTP 200 above is
  from darwin/arm64.
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
#    An empty database is fine — the server migrates it on startup.
export DATABASE_URL="postgres://user:pass@localhost:5432/dnstool?sslmode=disable"
export SESSION_SECRET="$(openssl rand -hex 32)"
PORT=5000 ./server

# 6. Confirm it serves
curl -s localhost:5000/api/capacity
```

If you do not want to provision PostgreSQL by hand, `docker compose up` from
the repository root does steps 3-5 in one command.

Report the toolchain version, platform, elapsed build time, and anything that
failed. **Negative results are more useful than positive ones** — if it does not
build on your platform, that is the finding worth recording.
