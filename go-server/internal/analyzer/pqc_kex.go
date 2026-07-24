// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science

// Post-quantum hybrid key-exchange readiness classification for observed TLS
// handshakes. The probe's TLS 1.3 ClientHello offers the hybrid group
// X25519MLKEM768 (X25519 + ML-KEM-768 per FIPS 203) by default (Go crypto/tls,
// Go >= 1.24), so the negotiated group is direct evidence of the server's
// post-quantum key-exchange posture toward a hybrid-capable client.
//
// Standards status (verified 2026-07-24):
//   - FIPS 203 (ML-KEM) — final, published 2024-08-13.
//   - draft-ietf-tls-ecdhe-mlkem — Standards Track Internet-Draft defining the
//     X25519MLKEM768 supported group for TLS 1.3 (not yet an RFC).
//   - draft-ietf-tls-hybrid-design — Informational Internet-Draft on hybrid
//     key exchange in TLS 1.3, IESG-approved (not yet an RFC).
//   - NIST IR 8547 (initial public draft) — projects quantum-vulnerable
//     algorithms deprecated after 2030 and disallowed after 2035.
//
// Tri-state honesty: a failed handshake is INDETERMINATE — it is never
// evidence that post-quantum key exchange is absent.
package analyzer

import "crypto/tls"

const (
	mapKeyKeyExchange  = "key_exchange"
	mapKeyPqcKexState  = "pqc_kex_state"
	mapKeyPqcKexDetail = "pqc_kex_detail"

	pqcKexNegotiated    = "negotiated"
	pqcKexNotSelected   = "not_selected"
	pqcKexUnavailable   = "unavailable"
	pqcKexIndeterminate = "indeterminate"
)

// classifyPQCKex maps an observed TLS handshake outcome to a post-quantum
// key-exchange readiness state plus an evidence-bounded detail string. The
// claim ceiling is deliberate: "not_selected" means only that the server did
// not negotiate X25519MLKEM768 with a client that offered it — it is never
// phrased as "the server does not support post-quantum cryptography," because
// the probe offers only the one hybrid group Go enables by default.
func classifyPQCKex(handshakeOK bool, version uint16, curve tls.CurveID) (string, string) {
	if !handshakeOK {
		return pqcKexIndeterminate,
			"TLS handshake did not complete; post-quantum key-exchange readiness cannot be determined from this probe."
	}
	if version < tls.VersionTLS13 {
		return pqcKexUnavailable,
			"Hybrid post-quantum key exchange (X25519MLKEM768) requires TLS 1.3; this endpoint negotiated an earlier protocol version."
	}
	if curve == tls.X25519MLKEM768 {
		return pqcKexNegotiated,
			"Hybrid post-quantum key exchange X25519MLKEM768 negotiated (X25519 + ML-KEM-768 per FIPS 203). Session key agreement resists harvest-now-decrypt-later attacks."
	}
	return pqcKexNotSelected,
		"Server selected classical key exchange although the probe's TLS 1.3 ClientHello offered the hybrid group X25519MLKEM768. Servers supporting only other hybrid groups also appear here."
}

// keyExchangeLabel renders the negotiated key-exchange group for display.
// CurveID zero means a legacy RSA key exchange (no ephemeral group).
func keyExchangeLabel(curve tls.CurveID) string {
	if curve == 0 {
		return "RSA (legacy key exchange)"
	}
	return curve.String()
}
