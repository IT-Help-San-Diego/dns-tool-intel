#!/usr/bin/env bash
# version-files.sh — SINGLE PRODUCER for the deposit-version manifest.
#
# The deposit version (as opposed to the app version, which is git-derived in
# scripts/version.sh and injected at build time) is declared only in these
# files. A file is in this list because its version field IS the deposit
# version — not a package version, not a schema version, not a tool version.
#
# Two consumers read this list, so they can never drift:
#   - scripts/generate-methodology-pdf.sh  (stamps/verifies versions on PDF build)
#   - scripts/assert-version-strings.sh    (unconditional build gate)
#
# Adding a file here means "this file carries the deposit version." Do it only
# when a file genuinely declares the deposit version. A file that cites a past
# version (changelog, evolution/, archive) does NOT belong here — a citation is
# not a declaration.
#
# shellcheck shell=bash

DEPOSIT_VERSION_FILES=(
  docs/dns-tool-methodology.md
  docs/dns-tool-methodology.html
  docs/philosophical-foundations.md
  docs/philosophical-foundations.html
  docs/FOUNDERS_MANIFESTO.md
  docs/founders-manifesto.html
  docs/COMMUNICATION_STANDARDS.md
  docs/communication-standards.html
  .zenodo.json
  codemeta.json
  CITATION.cff
)
