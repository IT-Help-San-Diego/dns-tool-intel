# Building DNS Tool from Source

## Prerequisites

- **Go 1.25+** — [https://go.dev/dl/](https://go.dev/dl/)
- **Git** — to clone the repository

## Quick Start

```bash
git clone https://github.com/IT-Help-San-Diego/dns-tool-web.git
cd dns-tool-web
go build ./go-server/cmd/server
```

The resulting `server` binary is the DNS Tool web server.

## Open-Core Architecture

DNS Tool uses Go build tags to separate open-source and proprietary modules:

- **OSS build** (default): `go build ./go-server/cmd/server`
  - Uses `_oss.go` stub files that provide no-op implementations
  - All core DNS analysis functionality works
  - Confidence scoring, report generation, and web UI are fully functional

- **Intel build** (proprietary): `go build -tags intel ./go-server/cmd/server`
  - Requires access to the private `dns-tool-intel` repository
  - Adds additional intelligence modules and data sources
  - Not required for core functionality

## Running

```bash
# Set required environment variables
export PORT=5000

# Start the server
./server
```

The server will be available at `http://localhost:5000`.

## Verifying Your Build

After building, verify the binary works:

```bash
./server --version
```

## Reproducibility

Each tagged release on GitHub corresponds to a Zenodo archive
(DOI: [10.5281/zenodo.18854899](https://doi.org/10.5281/zenodo.18854899)).

The Zenodo archive contains the complete OSS source code including
all `_oss.go` build-tag stubs required for compilation. Scientists
can reproduce builds from any archived version.
