# Launch DNS Tool locally — copy/paste

Two ways. Both assume you are in `~/Documents/GitHub/dns-tool-intel`.

---

> **Port 5000 is unusable on macOS.** AirPlay Receiver (`ControlCe`) binds it
> and answers every request with `403 Forbidden` and a `Server: AirTunes` header,
> so a curl to `localhost:5000` never reaches the container. These instructions
> use **5055** on the host side instead. (Verified 2026-07-26: `lsof -iTCP:5000
> -sTCP:LISTEN` showed `ControlCe`, not `docker`.)

## A. Docker Compose — the one-liner

```bash
cd ~/Documents/GitHub/dns-tool-intel
git fetch origin && git checkout science/researcher-onboarding
docker compose up
```

Compose is required, not a convenience: `DATABASE_URL` and `SESSION_SECRET` are
both mandatory and a bare `docker run` of the image exits 1 before serving.
Compose provisions PostgreSQL, loads `schema.sql`, and supplies both.

Then open <http://localhost:5055> and analyze a domain.

Three checks worth running in a second terminal:

```bash
# 1. Does it serve? (Compose always provides a database — the server
#    cannot run without one.)
curl -s localhost:5055/api/capacity

# 2. Does --version work in the container? (needs no database, no port)
docker compose run --rm --no-deps app --version

# 3. Can you verify a DNS finding by hand, inside the container?
docker compose run --rm --no-deps --entrypoint dig app TXT _dmarc.google.com +short
```

**If the container exits immediately**, the most likely cause is a template
path: `loadTemplates()` calls `os.Exit(1)` when its glob matches nothing. Grab
the output and send it to me:

```bash
docker run --rm dns-tool-test 2>&1 | head -30
```

---

## B. Native binary — no Docker needed

Your Go must be **1.25.12 or newer** (`go version` to check; `go.mod` refuses
older).

```bash
cd ~/Documents/GitHub/dns-tool-intel
git fetch origin && git checkout science/researcher-onboarding

# Version-stamped build (what releases ship)
bash build.sh

# Verify — needs no database, opens no port
./dns-tool-server --version
./dns-tool-server --help
```

Run it. Both variables are mandatory — the process exits 1 without either:

```bash
export DATABASE_URL='<your Neon connection string>'
export SESSION_SECRET="$(openssl rand -hex 32)"
PORT=5000 ./dns-tool-server
```

Against a fresh, empty database, load the base schema first — the server applies
only `*seed*` migrations, not `schema.sql`:

```bash
export DATABASE_URL='postgres://user:pass@localhost:5432/dnstool?sslmode=disable'
export SESSION_SECRET="$(openssl rand -hex 32)"
psql "$DATABASE_URL" -f go-server/db/schema/schema.sql
PORT=5000 ./dns-tool-server
```

Then <http://localhost:5055>.

---

## What I most want to know

1. **Does it serve a page?** No page has yet been retrieved from any build of
   this deposit.
2. **Does `/topology` render in the container?** If so it is a clean surface for
   reviewing the new engine without touching production.
3. **Anything in the startup log that looks wrong** — paste the first 30 lines
   and I will read them.

A failure here is more useful than a success. If it does not launch on your
machine, it will not launch for a researcher either, and that is exactly what we
are trying to find out before advertising it.
