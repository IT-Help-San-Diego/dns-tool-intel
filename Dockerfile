# DNS Tool — container image
#
# Purpose: let a researcher run the platform without installing a Go toolchain.
#
# This image alone is NOT enough to serve: config.Load() requires both
# DATABASE_URL and SESSION_SECRET and exits 1 before any listener is usable, so
# a bare `docker run` of this image cannot serve a page. Use Compose, which
# provisions PostgreSQL, loads the schema, and supplies both variables:
#
#   docker compose up          # then http://localhost:5055
#
# Host port 5055, not 5000: on macOS the AirPlay Receiver (ControlCe) binds 5000
# and answers 403 for everything, so localhost:5000 never reaches the container.
#
# `docker run --rm <image> --version` DOES work standalone — it needs no
# database and opens no port.

# ---------- build ----------
# Pinned to the go.mod minimum. Bump both together.
FROM golang:1.25.12-bookworm AS build

WORKDIR /src

# Dependency layer first so source edits don't re-download the module graph.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Version metadata is git-derived in release builds (scripts/version.sh). The
# .git directory is excluded from the image context, so accept it as a build
# arg and fall back to "container" rather than the misleading "dev".
ARG VERSION=container
ARG GIT_COMMIT=unknown
ARG BUILD_TIME=unknown

RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w \
        -X dnstool/go-server/internal/config.Version=${VERSION} \
        -X dnstool/go-server/internal/config.GitCommit=${GIT_COMMIT} \
        -X dnstool/go-server/internal/config.BuildTime=${BUILD_TIME}" \
      -o /out/dns-tool-server ./go-server/cmd/server

# ---------- runtime ----------
FROM debian:bookworm-slim

# ca-certificates: outbound HTTPS (RDAP, Certificate Transparency, MTA-STS).
# dnsutils: dig, so a user can verify any DNS finding by hand inside the
#   container — the independent-verifiability claim in the README.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates dnsutils \
 && rm -rf /var/lib/apt/lists/*

# Unprivileged: the server binds 5000, never a privileged port.
RUN useradd --system --uid 10001 --create-home dnstool

WORKDIR /app

COPY --from=build /out/dns-tool-server /usr/local/bin/dns-tool-server

# Runtime-read assets — these paths are load-bearing, not cosmetic.
#
# loadTemplates() searches go-server/templates, then templates, then
# ../templates, and calls os.Exit(1) if the glob parses nothing. findStaticDir()
# searches static, then go-server/static. Both resolve relative to the working
# directory, so WORKDIR and these destinations must agree.
#
# The SQL migrations are NOT copied: they are compiled into the binary via
# go:embed (go-server/db/migrations/embed.go). That is deliberate — the schema
# the binary migrates to is now the schema it was built with, and there is no
# way to run the image against a stale copy on disk.
COPY --chown=dnstool:dnstool go-server/templates/     ./go-server/templates/
COPY --chown=dnstool:dnstool static/                  ./static/
COPY --chown=dnstool:dnstool docs/                    ./docs/

# The structured logger creates ./logs at startup. WORKDIR is root-owned, so
# without this the non-root user hits "mkdir logs: permission denied" and falls
# back to stderr (non-fatal, but it loses the structured log pipeline).
RUN mkdir -p /app/logs && chown dnstool:dnstool /app/logs

USER dnstool

ENV PORT=5000
EXPOSE 5000

# --version needs no port and no database, so it is a valid liveness probe
# that cannot be confused with application readiness.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/dns-tool-server", "--version"]

ENTRYPOINT ["/usr/local/bin/dns-tool-server"]
