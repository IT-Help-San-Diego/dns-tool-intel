# Building DNS Tool from Source

## Prerequisites

- **Go 1.25+** — [https://go.dev/dl/](https://go.dev/dl/)
- **Git** — to clone the repository

## Quick Start

```bash
git clone https://github.com/IT-Help-San-Diego/dns-tool-intel.git
cd dns-tool
go build ./go-server/cmd/server
```

The resulting `server` binary is the DNS Tool web server.

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
(DOI: [10.5281/zenodo.19468134](https://doi.org/10.5281/zenodo.19468134)).

The Zenodo archive contains the complete source code.
Scientists can reproduce builds from any archived version.
