// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package icae

// FixtureCaseDomains registers every real-world domain that appears as the
// classified subject inside hardcoded ICAE cases, mapped to the single check
// that is circular for it. Scans of these domains disclose that the named
// check validates against the very cases it was developed from; every other
// finding remains a live measurement.
//
// Scope rules:
//   - Real, registrable domains only. RFC 2606/6761 reserved names
//     (example.com, example.com.au, *.test, *.invalid) are not real-world
//     subjects and are never registered.
//   - Never add CAA record values (letsencrypt.org, digicert.com) — those
//     are parser inputs inside records, not classified domains. A false
//     disclosure badge is worse than none.
//
// The drift test in fixture_registry_test.go fails CI when a case
// classifies a real-world domain that is not registered here, and when a
// registered domain no longer appears in any case.
var FixtureCaseDomains = map[string]string{
	"apple.com": "enterprise DNS classification",
	"bbc.co.uk": "enterprise DNS classification",
}
