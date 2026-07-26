# Building DNS Tool from Source

## Fastest path — Docker, no toolchain required

If you just want to see it run, this is the whole thing. No Go, no PostgreSQL,
no configuration:

```bash
docker run --rm -p 5000:5000 ghcr.io/it-help-san-diego/dns-tool:latest
```

Open <http://localhost:5000> and analyze a domain.

This starts in **degraded mode** — no database, so analysis history and
saved reports are unavailable, but live DNS analysis works. That is the
intended way to evaluate the tool.

To keep history across restarts, supply a PostgreSQL connection:

```bash
docker run --rm -p 5000:5000 \
  -e DATABASE_URL="postgres://user:pass@host:5432/dbname?sslmode=require" \
  ghcr.io/it-help-san-diego/dns-tool:latest
```

Build the image yourself instead of pulling it:

```bash
docker build -t dns-tool .
docker run --rm -p 5000:5000 dns-tool
```

## Building from source

### Prerequisites

- **Go 1.25.12 or newer** — [https://go.dev/dl/](https://go.dev/dl/)
  (the exact minimum is in `go.mod`; older toolchains refuse to build)
- **Git**

No database is required to build, and none is required to run — see
*Running without a database* below.

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

```bash
export PORT=5000        # optional, 5000 is the default
./server
```

The server is then available at <http://localhost:5000>.

### Running without a database

**DNS Tool runs without PostgreSQL.** If `DATABASE_URL` is unset or the
database is unreachable, the server logs the failure and enters **degraded
mode** rather than exiting: pages that need no persistence still render and
live DNS analysis still works. What you lose is anything requiring storage —
analysis history, saved reports, statistics, and the confidence trend pages.

This is the recommended way to try the tool for the first time.

### Running with a database

```bash
export DATABASE_URL="postgres://user:pass@localhost:5432/dnstool?sslmode=disable"
export PORT=5000
./server
```

Schema migrations under `go-server/db/migrations` are applied automatically at
startup. PostgreSQL 16 or newer is expected.

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
