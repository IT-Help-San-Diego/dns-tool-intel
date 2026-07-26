# Building DNS Tool from Source

## Fastest path — Docker, no toolchain required

The platform needs a PostgreSQL database. This brings up both with one command:

```bash
docker compose up
```

Open <http://localhost:5055> and analyze a domain.

**Why 5055 and not 5000:** on macOS the AirPlay Receiver service binds port 5000
and answers every request with `403 Forbidden` (`Server: AirTunes`), so a request
to `localhost:5000` never reaches the container. Compose publishes on 5055 to
avoid the collision. On Linux either port works; check with
`lsof -iTCP:5000 -sTCP:LISTEN` (macOS) or `ss -ltnp | grep 5000` (Linux). `docker-compose.yml`
provisions PostgreSQL 16, generates a throwaway `SESSION_SECRET`, applies the
schema, and starts the server.

Without Compose you must supply both required variables yourself — the server
**exits immediately** if either is missing:

```bash
docker build -t dns-tool .
docker run --rm -p 5000:5000 \
  -e DATABASE_URL="postgres://user:pass@host:5432/dbname?sslmode=require" \
  -e SESSION_SECRET="$(openssl rand -hex 32)" \
  dns-tool
```

(Adjust `-p` if port 5000 is taken on your host — see the AirPlay note above.)

### Required environment

| Variable | Required | Notes |
|---|---|---|
| `DATABASE_URL` | **yes** | `config.Load()` returns an error without it and the process exits 1 |
| `SESSION_SECRET` | **yes** | same — any random string works for local evaluation |
| `PORT` | no | defaults to 5000 |

There is no run-without-a-database mode. See *Degraded mode* below for what
that term actually means in this codebase.

## Building from source

### Prerequisites

- **Go 1.25.12 or newer** — [https://go.dev/dl/](https://go.dev/dl/)
  (the exact minimum is in `go.mod`; older toolchains refuse to build)
- **Git**

No database is required to **build**. Running the server does require one —
`DATABASE_URL` and `SESSION_SECRET` are both mandatory (see *Running* below).

### Quick Start

```bash
git clone https://github.com/IT-Help-San-Diego/dns-tool-intel.git
cd dns-tool-intel
go build ./go-server/cmd/server
```

This produces a `server` binary in the current directory. On a warm module
cache the compile takes roughly 10–15 seconds; the first build also downloads
about 30 dependencies.

For a **version-stamped** binary — what releases ship — use the build script
instead. It injects the git-derived version, commit, and build time via
`-ldflags`:

```bash
bash build.sh
```

A plain `go build` reports its version as `dev`, which is expected.

## Verifying your build

```bash
./server --version
```

Expected output:

```
DNS Tool 26.50.344
  commit:     a1b2c3d
  built:      2026-07-26T09:14:00Z
  go:         go1.25.12
  platform:   linux/amd64
```

This needs no database and opens no network port, so it works anywhere the
binary runs. `./server --help` lists the supported environment variables.

## Running

Both variables below are mandatory. `config.Load()` returns an error and the
process exits 1 if either is missing:

```bash
export DATABASE_URL="postgres://user:pass@localhost:5432/dnstool?sslmode=disable"
export SESSION_SECRET="$(openssl rand -hex 32)"
export PORT=5000        # optional, 5000 is the default
./server
```

The server is then available at <http://localhost:5000>.

Against a **fresh, empty** database, load the base schema first — the server
does not create it (see *Schema initialisation caveat* below):

```bash
psql "$DATABASE_URL" -f go-server/db/schema/schema.sql
```

If you do not want to provision PostgreSQL by hand, use `docker compose up`
instead — it does all of the above for you.

### Degraded mode — what it is, and what it is not

`main.go` has a `runDegradedMode` path, but it does **not** mean the server runs
without a database. The distinction matters:

- **`DATABASE_URL` absent** → `config.Load()` returns
  `"DATABASE_URL environment variable is required"` and the process **exits 1**.
  Degraded mode is never reached, because config loading happens first.
- **`DATABASE_URL` present but the database is unreachable** → `db.Connect`
  fails, `runDegradedMode` takes over, and the server serves a maintenance page
  (HTTP 503) plus `/healthz` returning
  `{"status":"degraded","reason":"database_unavailable"}`. It retries the
  connection every 15 s.

Degraded mode is a resilience feature for a database outage in production. It is
not an evaluation mode: no DNS analysis is available while it is active, only
the maintenance page. Use `docker compose up` to evaluate the tool.

### Database requirements

PostgreSQL 16 or newer is expected.

**Schema initialisation caveat.** `RunSeedMigrations` runs at startup but only
applies files whose names contain `seed` — currently
`013_seed_findings_and_ede.sql` and `015_confidence_scores_link_seed.sql`. The
base schema is **not** auto-applied. Against a fresh, empty database, load it
first:

```bash
psql "$DATABASE_URL" -f go-server/db/schema/schema.sql
```

`docker compose up` does this for you.

## Running the tests

```bash
go test ./go-server/internal/...
```

Some analyzer tests start local HTTP servers and perform outbound DNS
lookups, so they need loopback socket permission and network access. In a
restricted sandbox those fail with `bind: operation not permitted`; that is an
environment limitation, not a defect. The engine packages are self-contained
and pass without network:

```bash
go test ./go-server/internal/icae/... \
        ./go-server/internal/icuae/... \
        ./go-server/internal/unified/... \
        ./go-server/internal/zoneparse/... \
        ./go-server/internal/citation/...
```

The full handler suite is split across build tags for CI memory limits; see
`scripts/run-handler-tests-full.sh` and `replit.md` § "Test Build Tags".

## Reproducibility

Each tagged release corresponds to a Zenodo archive under concept DOI
[10.5281/zenodo.19468134](https://doi.org/10.5281/zenodo.19468134). The archive
contains the complete public source, and any archived version can be rebuilt
with the commands above.

`REPRODUCTION.md` records an independent build of a published deposit —
archive checksum, exact commands, timings, and results — so the claim on this
page is backed by a dated test rather than an assertion.
