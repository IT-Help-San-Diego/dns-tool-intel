#!/bin/bash
# scan-battery.sh — run a named scan battery against the batch endpoint.
# Usage: scan-battery.sh <battery.json> [https://host]
# Key: ~/.dnstool-scan-key (mode 600; NEVER in the repo).
set -euo pipefail
BATTERY="${1:?usage: scan-battery.sh <battery.json> [host]}"
HOST="${2:-https://dnstool.it-help.tech}"
KEY_FILE="${HOME}/.dnstool-scan-key"
[ -f "$KEY_FILE" ] || { echo "no key at $KEY_FILE (create one on the box: go run ./scripts/scan-key-create -label ...)"; exit 1; }
KEY=$(cat "$KEY_FILE")
RESP=$(curl -sS -X POST "$HOST/api/batch" \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  --data @"$BATTERY" -w "\nHTTP %{http_code}")
echo "$RESP"
