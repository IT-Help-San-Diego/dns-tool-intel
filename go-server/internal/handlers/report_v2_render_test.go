// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
	"os"
	"path/filepath"
	"regexp"
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
