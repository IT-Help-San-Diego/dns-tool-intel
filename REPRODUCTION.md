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

### NOT verified in this run

Stated plainly, because a reproduction record that only lists successes is not
evidence:

- **HTTP serving.** The test environment forbade binding sockets. Every attempt
  to start the server — `PORT=5000`, `8099`, `18080` — failed at
  `bind: operation not permitted` before reaching application logic. No page
  was ever served and no endpoint was reached.
- **Degraded mode.** `main.go` calls `runDegradedMode` when `db.Connect` fails,
  which should let the server run without PostgreSQL. This was read in source
  only, never executed. `BUILD.md` documents the behaviour on that basis and it
  needs confirmation on a machine that can open a port.
- **Container image.** The `Dockerfile` added in this release was not built —
  no Docker in the test environment. Asset paths in it were verified against
  `findTemplatesDir()` / `findStaticDir()` / `RunSeedMigrations()` by reading
  the source, not by running the image.
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
   archive contains zero. The build succeeds regardless, so the claim is
   obsolete rather than harmful — pending correction in the deposit metadata.
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

# 4. Verify
./server --version

# 5. Run it
PORT=5000 ./server        # degraded mode, no database needed
curl -s localhost:5000/api/capacity
```

Report the toolchain version, platform, elapsed build time, and anything that
failed. **Negative results are more useful than positive ones** — if it does not
build on your platform, that is the finding worth recording.
