// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"strings"
	"testing"
)

// The entailment rule: a verdict string may assert a predicate only if an
// observation the tool actually performed entails it. A label carrying no
// reason is a predicate with no evidence attached — which is exactly how
// buildEnforcingEmailVerdict shipped "Protected" for p=quarantine with no
// answer and no reason at all.
//
// This test pins the class shut: every verdict a builder emits must name the
// observation behind it.
func representativeProtocolStates() map[string]protocolState {
	base := protocolState{spfOK: true, dmarcOK: true, dmarcHasRua: true}

	states := map[string]protocolState{}

	for _, policy := range []string{mapKeyReject, mapKeyQuarantine, statusNone} {
		for _, pct := range []int{100, 50} {
			ps := base
			ps.dmarcPolicy = policy
			ps.dmarcPct = pct
			states[policy+"/pct"+itoa(pct)] = ps
		}
	}

	// tri-state coverage: indeterminate must never yield a confident predicate
	ind := base
	ind.dmarcIndeterminate = true
	states["dmarc-indeterminate"] = ind

	spfInd := base
	spfInd.spfIndeterminate = true
	states["spf-indeterminate"] = spfInd

	missing := protocolState{}
	states["nothing-configured"] = missing

	dnssecStates := map[string]protocolState{
		"dnssec-validated":     {dnssecOK: true, dnssecADValidated: true},
		"dnssec-signed-no-ad":  {dnssecOK: true},
		"dnssec-broken":        {dnssecBroken: true},
		"dnssec-indeterminate": {dnssecIndeterminate: true},
	}
	for k, v := range dnssecStates {
		states[k] = v
	}

	return states
}

// Enumerated at c305045e6: of 36 verdict emissions in posture.go, 6 supplied no
// reason — five of them inside buildEmailVerdict. Both builders are exercised
// here so the class cannot reopen in the function where it was densest.
func TestEveryVerdictSuppliesItsEvidence(t *testing.T) {
	for name, ps := range representativeProtocolStates() {
		t.Run(name, func(t *testing.T) {
			verdicts := map[string]any{}
			buildDNSVerdict(ps, verdicts)
			for _, hasSPF := range []bool{true, false} {
				for _, hasDMARC := range []bool{true, false} {
					buildEmailVerdict(verdictInput{
						ps: ps, ds: DKIMAbsent, hasSPF: hasSPF, hasDMARC: hasDMARC,
					}, verdicts)
					v, _ := verdicts[mapKeyEmailSpoofing].(map[string]any)
					if v == nil {
						t.Fatalf("no email verdict for spf=%v dmarc=%v", hasSPF, hasDMARC)
					}
					if r, _ := v[mapKeyReason].(string); strings.TrimSpace(r) == "" {
						t.Errorf("email verdict %q (spf=%v dmarc=%v) supplies no reason",
							v[mapKeyLabel], hasSPF, hasDMARC)
					}
					if a, _ := v[mapKeyAnswer].(string); strings.TrimSpace(a) == "" {
						t.Errorf("email verdict %q (spf=%v dmarc=%v) supplies no answer",
							v[mapKeyLabel], hasSPF, hasDMARC)
					}
				}
			}
			delete(verdicts, mapKeyEmailSpoofing)

			for key, raw := range verdicts {
				v, ok := raw.(map[string]any)
				if !ok {
					t.Fatalf("verdict %q is not a map", key)
				}
				label, _ := v[mapKeyLabel].(string)
				if label == "" {
					t.Errorf("verdict %q has no label", key)
				}
				reason, _ := v[mapKeyReason].(string)
				if strings.TrimSpace(reason) == "" {
					t.Errorf("verdict %q labelled %q supplies no reason — a predicate with no evidence attached", key, label)
				}
			}
		})
	}
}

// p=reject and p=quarantine@100 are both fully enforcing and both green, but
// they are different answers to "can this domain be impersonated by email?".
// Reject asks receivers to refuse at the gateway; quarantine asks them to
// accept and set aside, so the message still reaches the mailbox.
func TestEnforcingEmailVerdictDistinguishesRejectFromQuarantine(t *testing.T) {
	get := func(policy string) map[string]any {
		ps := protocolState{spfOK: true, dmarcOK: true, dmarcHasRua: true, dmarcPolicy: policy, dmarcPct: 100}
		verdicts := map[string]any{}
		buildEnforcingEmailVerdict(ps, DKIMAbsent, verdicts)
		v, _ := verdicts[mapKeyEmailSpoofing].(map[string]any)
		if v == nil {
			t.Fatalf("no email verdict emitted for %s", policy)
		}
		return v
	}

	reject := get(mapKeyReject)
	quarantine := get(mapKeyQuarantine)

	if reject[mapKeyLabel] == quarantine[mapKeyLabel] {
		t.Errorf("reject and quarantine must not share a label; both were %q", reject[mapKeyLabel])
	}
	if reject[mapKeyLabel] != strProtected {
		t.Errorf("p=reject should be %q, got %q", strProtected, reject[mapKeyLabel])
	}
	if quarantine[mapKeyLabel] != strQuarantined {
		t.Errorf("p=quarantine should be %q, got %q", strQuarantined, quarantine[mapKeyLabel])
	}

	// Both are real enforcing postures — neither is scored down to a warning.
	for policy, v := range map[string]map[string]any{"reject": reject, "quarantine": quarantine} {
		if v[mapKeyColor] != mapKeySuccess {
			t.Errorf("%s should stay green (%q), got %q", policy, mapKeySuccess, v[mapKeyColor])
		}
		if strings.TrimSpace(v[mapKeyReason].(string)) == "" {
			t.Errorf("%s verdict supplies no reason", policy)
		}
		if v[mapKeyAnswer] == nil || v[mapKeyAnswer] == "" {
			t.Errorf("%s verdict supplies no answer", policy)
		}
	}

	// The quarantine reason must state that spoofed mail still arrives; the
	// hedge about deliberate choice must not be the only thing it says.
	qr := strings.ToLower(quarantine[mapKeyReason].(string))
	if !strings.Contains(qr, "still delivered") && !strings.Contains(qr, "reaches the mailbox") {
		t.Errorf("quarantine reason must say spoofed mail still arrives; got: %s", quarantine[mapKeyReason])
	}
	if !strings.Contains(qr, "spam") && !strings.Contains(qr, "junk") {
		t.Errorf("quarantine reason should name where it lands; got: %s", quarantine[mapKeyReason])
	}

	// Reject must NOT claim the message is merely set aside.
	rr := strings.ToLower(reject[mapKeyReason].(string))
	if !strings.Contains(rr, "refuse") && !strings.Contains(rr, "rejected") {
		t.Errorf("reject reason should say the message is refused; got: %s", reject[mapKeyReason])
	}
}
