// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
        "net/http"
        "net/http/httptest"
        "strings"
        "testing"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

// resultsRenderContext builds a minimal gin.Context + config sufficient to
// render the real results.html template through NewTemplateData.
func resultsRenderContext(t *testing.T) (*gin.Context, *config.Config) {
        t.Helper()
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/analysis/test-id/view/E", nil)
        c.Set("csp_nonce", "test-nonce")
        c.Set("csrf_token", "test-csrf")
        cfg := &config.Config{
                AppVersion:  "26.51.0-1-gabcdef",
                BetaPages:   map[string]bool{},
                SectionTuning: map[string]string{},
        }
        return c, cfg
}

// TestResultsIndeterminate_AuxProtocols_NoFabrication verifies that when the
// CAA / MTA-STS / TLS-RPT / BIMI lookups return an indeterminate result (a
// transient SERVFAIL/timeout), the results page renders honest "Inconclusive"
// badges rather than fabricating confident absence claims. Zero-Fabrication:
// absence may only be asserted from an authoritative answer.
func TestResultsIndeterminate_AuxProtocols_NoFabrication(t *testing.T) {
        tmpl := mustLoadRealTemplates(t)
        c, cfg := resultsRenderContext(t)

        data := NewTemplateData(c, cfg, "")
        data["Domain"] = "example.com"
        data["AsciiDomain"] = "example.com"
        data["AnalysisID"] = "test-id"
        data["ReportMode"] = "E"
        data["CovertMode"] = false
        data["DomainExists"] = true
        data["IsPublicSuffix"] = false
        data["IsTLD"] = false
        data["SectionTuning"] = map[string]string{}
        data["Results"] = map[string]any{
                "posture": map[string]any{
                        "issues":     []any{"MTA-STS"},
                        "monitoring": []any{},
                        "configured": []any{"SPF"},
                        "absent":     []any{},
                },
                "spf_analysis":   map[string]any{"status": "success", "spf_state": "present"},
                "dmarc_analysis": map[string]any{"status": "success", "dmarc_state": "present", "policy": "reject"},
                "dkim_analysis":  map[string]any{"status": "success"},
                "bimi_analysis": map[string]any{
                        "status":     "indeterminate",
                        "bimi_state": "indeterminate",
                        "message":    "BIMI could not be verified — the DNS lookup did not complete.",
                },
                "caa_analysis": map[string]any{
                        "status":    "indeterminate",
                        "caa_state": "indeterminate",
                        "message":   "CAA could not be verified — the DNS lookup did not complete.",
                },
                "mta_sts_analysis": map[string]any{
                        "status":        "indeterminate",
                        "mta_sts_state": "indeterminate",
                        "message":       "MTA-STS could not be verified — the DNS lookup did not complete.",
                },
                "tlsrpt_analysis": map[string]any{
                        "status":       "indeterminate",
                        "tlsrpt_state": "indeterminate",
                        "message":      "TLS-RPT could not be verified — the DNS lookup did not complete.",
                },
                "dane_analysis": map[string]any{
                        "status":          "indeterminate",
                        "has_dane":        false,
                        "dane_deployable": "unknown",
                },
        }

        var buf strings.Builder
        if err := tmpl.ExecuteTemplate(&buf, "results.html", data); err != nil {
                t.Fatalf("results.html render failed: %v", err)
        }
        body := buf.String()

        if !strings.Contains(body, "</html>") {
                t.Fatalf("render truncated, missing </html>; len=%d", len(body))
        }
        if !strings.Contains(body, "Inconclusive") {
                t.Error("expected an 'Inconclusive' badge for indeterminate aux protocols, none found")
        }

        // Fabricated-absence phrases that must NOT appear for an indeterminate result.
        for _, fab := range []string{
                "Not prevented",             // MTA-STS question badge
                "No reporting",              // TLS-RPT question badge
                "Not Setup",                 // BIMI overview scorecard badge
                "neither DANE nor MTA-STS",  // transport summary — asserts MTA-STS absence
        } {
                if strings.Contains(body, fab) {
                        t.Errorf("fabricated absence string %q rendered for an indeterminate protocol", fab)
                }
        }
}

// TestResultsIndeterminate_RegistryZone_CAA verifies the registry-zone health
// card does not label CAA as "Not Set" when the CAA lookup was indeterminate.
func TestResultsIndeterminate_RegistryZone_CAA(t *testing.T) {
        tmpl := mustLoadRealTemplates(t)
        c, cfg := resultsRenderContext(t)

        data := NewTemplateData(c, cfg, "")
        data["Domain"] = "example.co.uk"
        data["AsciiDomain"] = "example.co.uk"
        data["AnalysisID"] = "test-id"
        data["ReportMode"] = "Z"
        data["CovertMode"] = false
        data["DomainExists"] = true
        data["IsPublicSuffix"] = true
        data["IsTLD"] = false
        data["SectionTuning"] = map[string]string{}
        data["Results"] = map[string]any{
                "dnssec_analysis": map[string]any{"status": "secure"},
                "caa_analysis": map[string]any{
                        "status":    "indeterminate",
                        "caa_state": "indeterminate",
                        "message":   "CAA could not be verified — the DNS lookup did not complete.",
                },
        }

        var buf strings.Builder
        if err := tmpl.ExecuteTemplate(&buf, "results.html", data); err != nil {
                t.Fatalf("results.html render failed: %v", err)
        }
        body := buf.String()

        if strings.Contains(body, "CAA: Not Set") {
                t.Error("registry-zone card labelled CAA 'Not Set' despite an indeterminate lookup")
        }
        if !strings.Contains(body, "Inconclusive") {
                t.Error("expected 'Inconclusive' CAA label for indeterminate registry-zone lookup, none found")
        }
}
