// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Tests for this package cover the full product source.
package analyzer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The golden corpus existed to catch regressions, but every assertion over it
// checked STRUCTURE — that expected keys are present. A corpus of five
// reject-policy domains passes every structural check while being blind to
// whole classes of regression: nothing in it exercised p=quarantine, and
// nothing exercised a DANE-positive domain, so a change that broke either
// verdict path would have left the corpus green. Coverage of the state space
// is the property that makes a regression corpus worth running, and it is
// itself a claim that has to be checked — a corpus silently losing a state is
// exactly the failure this file exists to make loud.
//
// Each entry names a state, the reason it must stay covered, and a predicate
// read from the stored capture. Adding a state here without a domain that
// exhibits it fails the suite by design: that is the gap being visible
// instead of silent.
type fixtureState struct {
	name  string
	why   string
	holds func(fixtureFields) bool
}

// fixtureFields is the narrow projection of a capture this file reads. Values
// are pulled by path so a capture missing a section yields the zero value
// rather than panicking — an absent section is itself a state.
type fixtureFields struct {
	domain       string
	domainExists bool
	dmarcPolicy  string
	dmarcPct     float64
	hasDMARCPct  bool
	spoofDoor    string
	hasDANE      bool
	daneState    string
	dnssecStatus string
	postureState string
}

var requiredFixtureStates = []fixtureState{
	{
		name: "dmarc_reject",
		why:  "the strongest enforcement path — the verdict every 'Protected' claim rests on",
		holds: func(f fixtureFields) bool {
			return f.dmarcPolicy == "reject"
		},
	},
	{
		name: "dmarc_quarantine",
		why:  "quarantine is NOT reject: mail is set aside, not refused, and the verdict must keep saying so (was uncovered until cia.gov)",
		holds: func(f fixtureFields) bool {
			return f.dmarcPolicy == "quarantine"
		},
	},
	{
		name: "dmarc_monitor_only",
		why:  "p=none requests no enforcement — the open-door consequence axis reads danger here, and nothing exercised it",
		holds: func(f fixtureFields) bool {
			return f.dmarcPolicy == "none"
		},
	},
	{
		name: "spoof_door_open",
		why:  "the operational-consequence axis's severe end; a corpus of enforcing domains can never regress-test it",
		holds: func(f fixtureFields) bool {
			return f.spoofDoor == "open"
		},
	},
	{
		name: "spoof_door_closed",
		why:  "the benign end of the same axis — both ends or the axis is untested",
		holds: func(f fixtureFields) bool {
			return f.spoofDoor == "closed"
		},
	},
	{
		name: "dane_present",
		why:  "TLSA records present and validated (RFC 7672); zero-coverage until ietf.org, so every DANE verdict path was unexercised",
		holds: func(f fixtureFields) bool {
			return f.hasDANE
		},
	},
	{
		name: "dane_absent",
		why:  "the common case, and the one where absence must not read as failure",
		holds: func(f fixtureFields) bool {
			return f.domainExists && !f.hasDANE
		},
	},
	{
		name: "dnssec_signed",
		why:  "a validated chain of trust — the precondition DANE depends on",
		holds: func(f fixtureFields) bool {
			return f.dnssecStatus == "success"
		},
	},
	{
		name: "domain_absent",
		why:  "NXDOMAIN must produce an honest no-such-domain result, never a scored posture",
		holds: func(f fixtureFields) bool {
			return !f.domainExists
		},
	},
	{
		name: "spoof_door_no_mail",
		why:  "null MX (RFC 7505) takes its own grading branch — a domain that sends no mail must not be scored as if it did. Promoted from documentedUncoveredStates when refreshed captures showed example.com is null-MX; the drift test caught the stale claim.",
		holds: func(f fixtureFields) bool {
			return f.spoofDoor == "no_mail"
		},
	},
}

// Documented, deliberately uncovered by LIVE captures. These states are real
// and tested — by unit tests that construct the state directly — but no
// stable public domain exhibits them, and a fixture is a frozen capture of a
// domain that does. Listing them here keeps the gap stated rather than
// implied by silence; when a domain that exhibits one is found, it moves into
// requiredFixtureStates.
//
//	spoof_door=guarded — partial enforcement (pct<100, or DMARC-only with an
//	    enforcing policy). pct is vanishingly rare in the wild and unstable
//	    when present. Unit-tested in TestClassifySpoofDoor.
//	spoof_door=unknown — requires a transient resolver failure at capture
//	    time; a fixture of a transient state would be frozen noise, not a
//	    baseline. Unit-tested via the indeterminate tri-state paths.
//	registry/TLD grade — a bare TLD input takes classifyRegistryGrade;
//	    covered by TestClassifyGrade_TLD rather than a capture.
var documentedUncoveredStates = []string{
	"spoof_door=guarded", "spoof_door=unknown", "registry_tld",
}

func fixtureDirForCoverage() string {
	for _, dir := range []string{
		filepath.Join("..", "..", "..", "tests", "golden_fixtures"),
		filepath.Join("tests", "golden_fixtures"),
	} {
		if _, err := os.Stat(filepath.Join(dir, "manifest.json")); err == nil {
			return dir
		}
	}
	return filepath.Join("..", "..", "..", "tests", "golden_fixtures")
}

func str(m map[string]any, section, key string) string {
	sec, ok := m[section].(map[string]any)
	if !ok {
		return ""
	}
	s, _ := sec[key].(string)
	return s
}

func readFixtureFields(domain string, data map[string]any) fixtureFields {
	f := fixtureFields{domain: domain}
	f.domainExists, _ = data["domain_exists"].(bool)
	f.dmarcPolicy = str(data, "dmarc_analysis", "policy")
	f.spoofDoor = str(data, "posture", "spoof_door")
	f.daneState = str(data, "dane_analysis", "dane_state")
	f.dnssecStatus = str(data, "dnssec_analysis", "status")
	f.postureState = str(data, "posture", "state")
	if dane, ok := data["dane_analysis"].(map[string]any); ok {
		f.hasDANE, _ = dane["has_dane"].(bool)
	}
	if dmarc, ok := data["dmarc_analysis"].(map[string]any); ok {
		if pct, ok := dmarc["pct"].(float64); ok {
			f.dmarcPct, f.hasDMARCPct = pct, true
		}
	}
	return f
}

func loadFixtureFields(t *testing.T) []fixtureFields {
	t.Helper()
	dir := fixtureDirForCoverage()
	manifestData, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest struct {
		Domains []string `json:"domains"`
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}

	var out []fixtureFields
	for _, domain := range manifest.Domains {
		path := filepath.Join(dir, strings.ReplaceAll(domain, ".", "_")+".json")
		data, err := os.ReadFile(path)
		if err != nil {
			// A manifest entry without a capture is a corpus defect, not a
			// skip: the manifest is the source of truth for what the corpus
			// claims to hold.
			t.Errorf("manifest lists %s but %s is missing: %v", domain, path, err)
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			t.Errorf("parse %s: %v", path, err)
			continue
		}
		out = append(out, readFixtureFields(domain, m))
	}
	if len(out) == 0 {
		t.Fatal("no fixtures loaded")
	}
	return out
}

func TestGoldenFixtureStateCoverage(t *testing.T) {
	fixtures := loadFixtureFields(t)

	for _, state := range requiredFixtureStates {
		t.Run(state.name, func(t *testing.T) {
			var covering []string
			for _, f := range fixtures {
				if state.holds(f) {
					covering = append(covering, f.domain)
				}
			}
			if len(covering) == 0 {
				t.Errorf("NO fixture exhibits %q — the corpus cannot detect a regression in it.\n  Why this state matters: %s\n  Fix: add a domain that exhibits it (scan it, freeze the capture via scripts/refresh-golden-fixtures.sh), or move it to documentedUncoveredStates with the reason no live domain can supply it.",
					state.name, state.why)
				return
			}
			t.Logf("✓ %s covered by: %s", state.name, strings.Join(covering, ", "))
		})
	}
}

// The uncovered list is a claim too: each entry asserts that no live capture
// supplies the state. If a fixture starts exhibiting one, the documentation
// has drifted from the corpus and the entry belongs in the required set.
func TestDocumentedUncoveredStatesStayUncovered(t *testing.T) {
	fixtures := loadFixtureFields(t)
	probes := map[string]func(fixtureFields) bool{
		"spoof_door=guarded": func(f fixtureFields) bool { return f.spoofDoor == "guarded" },
		"spoof_door=no_mail": func(f fixtureFields) bool { return f.spoofDoor == "no_mail" },
		"spoof_door=unknown": func(f fixtureFields) bool { return f.spoofDoor == "unknown" },
		"registry_tld":       func(f fixtureFields) bool { return f.spoofDoor == "not_applicable" && f.domainExists },
	}
	for _, name := range documentedUncoveredStates {
		probe, ok := probes[name]
		if !ok {
			t.Errorf("documentedUncoveredStates lists %q with no probe — the claim is unverifiable", name)
			continue
		}
		for _, f := range fixtures {
			if probe(f) {
				t.Errorf("%s is documented as uncovered, but %s exhibits it — promote it to requiredFixtureStates so it is enforced", name, f.domain)
			}
		}
	}
}

// Coverage of a state is meaningless if the capture behind it is stale in the
// specific field that supplies the state. spoof_door is the newest axis and
// the one most likely to be missing from a capture frozen before it existed —
// a fixture without the key silently stops covering its door state.
func TestFixtureCapturesCarryConsequenceAxis(t *testing.T) {
	for _, f := range loadFixtureFields(t) {
		if !f.domainExists {
			continue
		}
		if f.spoofDoor == "" {
			t.Errorf("%s: capture predates posture.spoof_door — refresh it, or its door-state coverage is fictional", f.domain)
		}
	}
}

func TestFixtureCoverageReport(t *testing.T) {
	fixtures := loadFixtureFields(t)
	var b strings.Builder
	fmt.Fprintf(&b, "\ngolden corpus: %d domains\n", len(fixtures))
	for _, f := range fixtures {
		fmt.Fprintf(&b, "  %-28s dmarc=%-10s door=%-14s dane=%-5t dnssec=%-8s posture=%s\n",
			f.domain, orDash(f.dmarcPolicy), orDash(f.spoofDoor), f.hasDANE, orDash(f.dnssecStatus), orDash(f.postureState))
	}
	t.Log(b.String())
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
