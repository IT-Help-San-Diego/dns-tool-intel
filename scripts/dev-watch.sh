#!/usr/bin/env bash
# Dev loop automation: rebuild + restart the local server whenever a template,
# Go, or built static file changes. Exists because templates are binary-
# embedded (go:embed) — an edit needs a rebuild before restart — and the right
# answer is automating the loop, not forking a disk-reading dev path that lets
# dev and prod render from different sources. The rebuild also re-computes the
# boot-time SRI hashes, so it fixes the blank-canvas-after-JS-edit trap
# (real browsers silently refusing a changed min file under a running server)
# at the same time.
#
# Usage:
#   DATABASE_URL=… SESSION_SECRET=dev PORT=5050 bash scripts/dev-watch.sh
# Env passes straight through to the server (local recipe: docker postgres on
# 5433; PORT 5050 dodges macOS AirPlay).
#
# Deliberately NOT `set -e`: this loop's whole job is surviving failed builds
# and transient find errors, then retrying. Reviewed failure modes, each a
# panel finding against the first draft:
#   - change detection latches on a STAMP FILE mtime, not a filename compare,
#     so consecutive edits to the SAME file each rebuild; the stamp is
#     removed on build failure so the next tick retries and a fix to the
#     same file is picked up;
#   - `find -print -quit` emits at most one line — no `| head` SIGPIPE class;
#   - the watch loops run in the PARENT shell (process substitution, never a
#     pipeline subshell), so $PID stays visible to the EXIT trap and the
#     current server is never orphaned holding the port;
#   - every start is re-checked: an instant exit (port already bound, boot
#     error) reports loudly instead of claiming "restarted";
#   - /tmp cleanup of the binary or stamp self-heals (missing stamp means
#     "rebuild now").
set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

BIN="${DNSTOOL_DEV_BIN:-/tmp/dnstool-dev}"
STAMP="${BIN}.stamp"
PID=""

server_alive() { [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; }

build_and_restart() {
  echo "── rebuild $(date +%H:%M:%S)"
  touch "$STAMP" # BEFORE the build: edits landing mid-build stay newer than it
  if ! go build -o "$BIN" ./go-server/cmd/server; then
    rm -f "$STAMP" # next tick retries — fixing the SAME file must rebuild
    echo "── build FAILED — still serving the last good build; retrying on next change/tick"
    sleep 2
    return 0
  fi
  if server_alive; then
    kill "$PID" 2>/dev/null
    wait "$PID" 2>/dev/null
  fi
  "$BIN" &
  PID=$!
  sleep 0.7
  if server_alive; then
    echo "── restarted (pid $PID)"
  else
    echo "── SERVER EXITED IMMEDIATELY — port in use (orphan? manual ./server?) or boot error; see output above"
  fi
}

trap 'server_alive && kill "$PID" 2>/dev/null' EXIT

build_and_restart

changed_since_stamp() {
  [ -f "$STAMP" ] || return 0
  [ -n "$(find go-server static/js static/css \
      \( -name '*.go' -o -name '*.html' -o -name '*.min.js' -o -name '*.min.css' \) \
      -newer "$STAMP" -print -quit 2>/dev/null)" ]
}

if command -v fswatch >/dev/null 2>&1; then
  # Process substitution keeps this loop (and $PID) in the parent shell.
  # fswatch dying ends the loop → the script exits → the trap kills the
  # server instead of orphaning it.
  while read -r _; do
    build_and_restart
  done < <(fswatch -o --latency 0.5 go-server static/js static/css)
  echo "── fswatch exited; watcher stopping"
else
  echo "(fswatch not installed — 1s stamp-poll; brew install fswatch for the event version)"
  while true; do
    if changed_since_stamp; then
      build_and_restart
    elif ! server_alive; then
      echo "── server not running (crashed?) — restarting"
      build_and_restart
    fi
    sleep 1
  done
fi
