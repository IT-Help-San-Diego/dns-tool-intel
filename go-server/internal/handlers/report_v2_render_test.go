// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func loadResultsV2Source(t *testing.T) string {
	t.Helper()
	candidates := []string{
		"go-server/templates/results_v2.html",
		"../../../go-server/templates/results_v2.html",
		"../../../../go-server/templates/results_v2.html",
	}
	for _, candidate := range candidates {
		body, err := os.ReadFile(filepath.Clean(candidate))
		if err == nil {
			return string(body)
		}
	}
	cwd, _ := os.Getwd()
	t.Fatalf("cannot find results_v2.html from cwd=%s", cwd)
	return ""
}

func TestResultsV2_EngineerWorkspaceContract(t *testing.T) {
	body := loadResultsV2Source(t)

	required := []string{
		`class="container my-4 v2-workspace"`,
		`aria-label="Report orientation"`,
		`aria-label="Engineer report workspace"`,
		`What changed`,
		`Evidence & Verification`,
		`data-v2-level="L0"`,
		`data-v2-level="L1"`,
		`data-v2-level="L2"`,
		`data-v2-level="L3"`,
	}
	for _, marker := range required {
		if !strings.Contains(body, marker) {
			t.Errorf("results_v2.html missing Engineer workspace marker %q", marker)
		}
	}

	forbidden := []string{
		"V2 STRUCTURAL PREVIEW",
		"zero visual design",
		"Ungrouped — pending contract",
	}
	for _, marker := range forbidden {
		if strings.Contains(body, marker) {
			t.Errorf("results_v2.html leaks prototype scaffolding %q", marker)
		}
	}
}

func TestResultsV2_CanonicalGroupsAndNavigation(t *testing.T) {
	body := loadResultsV2Source(t)

	groups := []string{
		"email-security",
		"domain-security",
		"transport-security",
		"brand-trust",
		"infrastructure-intel",
		"evidence-verification",
	}
	for _, id := range groups {
		groupPattern := regexp.MustCompile(`<details[^>]+id="` + regexp.QuoteMeta(id) + `"`)
		navPattern := regexp.MustCompile(`<a[^>]+href="#` + regexp.QuoteMeta(id) + `"`)
		if count := len(groupPattern.FindAllStringIndex(body, -1)); count != 1 {
			t.Errorf("group %q rendered %d times, want exactly 1", id, count)
		}
		if !navPattern.MatchString(body) {
			t.Errorf("workspace navigation has no canonical link to %q", id)
		}
	}

	if !strings.Contains(body, `href="#section-traffic"><span>MX &amp; Routing</span>`) {
		t.Error("hurry path missing direct MX & Routing destination")
	}
	if !strings.Contains(body, `href="#section-subdomains">Subdomains</a>`) {
		t.Error("hurry path missing direct Subdomains destination")
	}
	if !strings.Contains(body, `href="#section-dnssec"><span>DNSSEC</span>`) {
		t.Error("hurry path missing direct DNSSEC destination")
	}
}

func TestResultsV2_WorkspaceNavigationPrecedesLegacyL0Stack(t *testing.T) {
	body := loadResultsV2Source(t)

	orientation := strings.Index(body, `aria-label="Report orientation"`)
	command := strings.Index(body, `id="command-card"`)
	if orientation < 0 || command < 0 {
		t.Fatalf("missing orientation (%d) or command-card (%d)", orientation, command)
	}
	if orientation > command {
		t.Fatalf("workspace orientation appears after command-card; nav must frame the report before legacy L0 stack")
	}
}

func TestResultsV2_CAAHasOneCanonicalDomainSecurityHome(t *testing.T) {
	body := loadResultsV2Source(t)
	domainStart := strings.Index(body, `<details class="v2-group`)
	domainStart = strings.Index(body[domainStart:], `id="domain-security"`) + domainStart
	transportStart := strings.Index(body, `id="transport-security"`)
	if domainStart < 0 || transportStart <= domainStart {
		t.Fatal("cannot locate Domain Security and Transport Security boundaries")
	}
	domainSection := body[domainStart:transportStart]
	if !strings.Contains(domainSection, `id="section-caa"`) {
		t.Error("CAA canonical card is not inside Domain Security")
	}

	brandStart := strings.Index(body, `id="brand-trust"`)
	infraStart := strings.Index(body, `id="infrastructure-intel"`)
	if brandStart < 0 || infraStart <= brandStart {
		t.Fatal("cannot locate Brand & Trust and Infrastructure boundaries")
	}
	brandSection := body[brandStart:infraStart]
	if count := strings.Count(brandSection, `id="section-caa"`); count != 0 {
		t.Errorf("CAA canonical card is duplicated %d times inside Brand & Trust", count)
	}
	if !strings.Contains(brandSection, `data-edge="see-also" href="#section-caa"`) {
		t.Error("Brand & Trust lacks a typed see-also link to canonical CAA evidence")
	}
}

// TestResultsV2_RendersThroughRealTemplateEngine executes results_v2.html through
// the real html/template glob for all three domain-envelope states. The grep
// tests above inspect source bytes and would pass even if the manifest generator
// left an unbalanced {{if}}/{{end}} — this is the check that fails when the CAA
// relocation out of the Brand section's {{if not .IsPublicSuffix}} guard breaks
// template balance. A template parse/execute error, a truncated page (missing
// </html>), or a leaked scaffold string all fail here.
// TestNormalizeResultsRebucketsAchievablePosture: legacy rows persisted
// "Secure" as the achievable posture inside full_results; view-time
// rebucket must render them "Hardened" (map-on-read, never backfill),
// while any other value passes through untouched.
// TestPostureStripSixCells pins the c2b six-card scorecard: exactly six
// severity-ordered cells, including the two 2026-08-16 additions. The count
// is a both-directions ratchet — a seventh card or a lost card both fail.
func TestPostureStripSixCells(t *testing.T) {
	body := loadResultsV2Source(t)
	if n := strings.Count(body, `class="col-6 col-md-2 sev-order-`); n != 6 {
		t.Errorf("posture strip has %d severity-ordered cells, want exactly 6", n)
	}
	for _, title := range []string{
		`<div class="small text-muted text-uppercase mb-1">Monitoring</div>`,
		`<div class="small text-muted text-uppercase mb-1">DANE</div>`,
	} {
		if !strings.Contains(body, title) {
			t.Errorf("posture strip missing cell title %q", title)
		}
	}
}

func TestNormalizeResultsRebucketsAchievablePosture(t *testing.T) {
	legacy := NormalizeResults([]byte(`{"remediation":{"posture_achievable":"Secure"}}`))
	if legacy == nil {
		t.Fatal("expected non-nil result")
	}
	rem := legacy["remediation"].(map[string]interface{})
	if got := rem["posture_achievable"]; got != "Hardened" {
		t.Errorf("legacy Secure rebucketed to %q, want Hardened", got)
	}
	modern := NormalizeResults([]byte(`{"remediation":{"posture_achievable":"Low Risk"}}`))
	if got := modern["remediation"].(map[string]interface{})["posture_achievable"]; got != "Low Risk" {
		t.Errorf("non-legacy value mutated to %q, want Low Risk untouched", got)
	}
}

// TestResultsV2_AnchorIntegrity: every in-page link in the RENDERED
// output must resolve to an id in the same output, for every envelope.
// A section that renders conditionally must take its ToC chip with it —
// a link must never outlive its target (found live 2026-08-16:
// #section-dnssec-ops, #section-web-exposure and #section-web3 dangled
// on production because the chips were unconditional). Needs no
// browser: both sides are in the server-rendered HTML.
func TestResultsV2_AnchorIntegrity(t *testing.T) {
	hrefRe := regexp.MustCompile(`href="#([^"]+)"`)
	idRe := regexp.MustCompile(`id="([^"]+)"`)
	// knownDangling is a RATCHET, not an allowlist: the test fails on any
	// NEW dangling link AND on any entry that now resolves (remove it) —
	// the list can only shrink (the TestStaticMirrorsAgree pattern). These
	// are pre-existing envelope-specific gaps measured 2026-08-16: links
	// whose target sections need data this envelope never has. Fixing one
	// means gating the link with its section's condition, then deleting
	// the entry here.
	cases := []struct {
		name          string
		reportMode    string
		domainExists  bool
		publicSuffix  bool
		knownDangling []string
	}{
		{"normal domain", "E", true, false, []string{
			"confidencePanel", "currencyPanel", "report-integrity",
			"section-ai", "section-delegation-consistency", "section-infra",
			"section-securitytxt", "section-smtp", "verify-commands"}},
		{"non-existent domain", "E", false, false, []string{
			"brand-trust", "domain-security", "email-security",
			"evidence-verification", "infrastructure-intel", "report-integrity",
			"section-dns-diff", "section-dnssec", "section-subdomains",
			"section-traffic", "transport-security"}},
		{"registry zone", "Z", true, true, []string{
			"confidencePanel", "currencyPanel", "report-integrity",
			"section-ai", "section-brand", "section-dane",
			"section-delegation-consistency", "section-email", "section-infra",
			"section-securitytxt", "section-smtp", "section-subdomains",
			"section-traffic", "verify-commands"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmpl := mustLoadRealTemplates(t)
			c, cfg := resultsRenderContext(t)
			data := NewTemplateData(c, cfg, "")
			data["Domain"] = "example.com"
			data["AsciiDomain"] = "example.com"
			data["AnalysisID"] = "test-id"
			data["ReportMode"] = tc.reportMode
			data["CovertMode"] = false
			data["DomainExists"] = tc.domainExists
			data["IsPublicSuffix"] = tc.publicSuffix
			data["IsTLD"] = false
			data["SectionTuning"] = map[string]string{}
			data["Results"] = map[string]any{
				"posture":         map[string]any{"state": "Low Risk", "color": "success", "configured": []any{"SPF"}},
				"spf_analysis":    map[string]any{"status": "success", "spf_state": "present"},
				"dmarc_analysis":  map[string]any{"status": "success", "dmarc_state": "present", "policy": "reject"},
				"dkim_analysis":   map[string]any{"status": "success"},
				"caa_analysis":    map[string]any{"status": "success", "caa_state": "present"},
				"dnssec_analysis": map[string]any{"status": "secure"},
				"dane_analysis":   map[string]any{"status": "success", "has_dane": true},
				"bimi_analysis":   map[string]any{"status": "success"},
			}
			var buf strings.Builder
			if err := tmpl.ExecuteTemplate(&buf, "results_v2.html", data); err != nil {
				t.Fatalf("render failed: %v", err)
			}
			body := buf.String()
			ids := map[string]bool{}
			for _, m := range idRe.FindAllStringSubmatch(body, -1) {
				ids[m[1]] = true
			}
			var dangling []string
			seen := map[string]bool{}
			for _, m := range hrefRe.FindAllStringSubmatch(body, -1) {
				if !ids[m[1]] && !seen[m[1]] {
					seen[m[1]] = true
					dangling = append(dangling, m[1])
				}
			}
			sort.Strings(dangling)
			known := map[string]bool{}
			for _, k := range tc.knownDangling {
				known[k] = true
			}
			for _, d := range dangling {
				if !known[d] {
					t.Errorf("NEW dangling in-page link %q — gate the link with the same condition as its target section", d)
				}
			}
			stillDangling := map[string]bool{}
			for _, d := range dangling {
				stillDangling[d] = true
			}
			for _, k := range tc.knownDangling {
				if !stillDangling[k] {
					t.Errorf("knownDangling entry %q now resolves — delete it (the list only shrinks)", k)
				}
			}
		})
	}
}

func TestResultsV2_RendersThroughRealTemplateEngine(t *testing.T) {
	cases := []struct {
		name         string
		reportMode   string
		domainExists bool
		publicSuffix bool
		isTLD        bool
		wantCAAOnce  bool // CAA canonical card renders exactly once for normal domains
	}{
		{"normal domain", "E", true, false, false, true},
		{"non-existent domain", "E", false, false, false, false},
		{"registry zone", "Z", true, true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmpl := mustLoadRealTemplates(t)
			c, cfg := resultsRenderContext(t)

			data := NewTemplateData(c, cfg, "")
			data["Domain"] = "example.com"
			data["AsciiDomain"] = "example.com"
			data["AnalysisID"] = "test-id"
			data["ReportMode"] = tc.reportMode
			data["CovertMode"] = false
			data["DomainExists"] = tc.domainExists
			data["IsPublicSuffix"] = tc.publicSuffix
			data["IsTLD"] = tc.isTLD
			data["SectionTuning"] = map[string]string{}
			data["Results"] = map[string]any{
				"posture":         map[string]any{"state": "Low Risk", "color": "success", "configured": []any{"SPF"}},
				"spf_analysis":    map[string]any{"status": "success", "spf_state": "present"},
				"dmarc_analysis":  map[string]any{"status": "success", "dmarc_state": "present", "policy": "reject"},
				"dkim_analysis":   map[string]any{"status": "success"},
				"caa_analysis":    map[string]any{"status": "success", "caa_state": "present"},
				"dnssec_analysis": map[string]any{"status": "secure"},
				"dane_analysis":   map[string]any{"status": "success", "has_dane": true},
				"bimi_analysis":   map[string]any{"status": "success"},
			}

			var buf strings.Builder
			if err := tmpl.ExecuteTemplate(&buf, "results_v2.html", data); err != nil {
				t.Fatalf("results_v2.html failed to execute for %q: %v", tc.name, err)
			}
			body := buf.String()

			if !strings.Contains(body, "</html>") {
				t.Fatalf("render truncated for %q, missing </html>; len=%d", tc.name, len(body))
			}
			if !strings.Contains(body, `class="container my-4 v2-workspace"`) {
				t.Errorf("workspace frame missing from rendered output for %q", tc.name)
			}
			if !strings.Contains(body, `aria-label="Engineer report workspace"`) {
				t.Errorf("workspace navigation missing from rendered output for %q", tc.name)
			}
			for _, leak := range []string{"V2 STRUCTURAL PREVIEW", "Ungrouped — pending contract"} {
				if strings.Contains(body, leak) {
					t.Errorf("rendered output leaks scaffolding %q for %q", leak, tc.name)
				}
			}
			if tc.wantCAAOnce {
				if n := strings.Count(body, `id="section-caa"`); n != 1 {
					t.Errorf("normal domain rendered CAA card %d times, want 1 (relocation must keep it in the DomainExists envelope)", n)
				}
			}
		})
	}
}
