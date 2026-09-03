package handlers

import (
	"dnstool/go-server/internal/config"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestNewRemediationHandler(t *testing.T) {
	h := NewRemediationHandler(nil, &config.Config{})
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestRemediationHandler_Store_NilDBAndStore(t *testing.T) {
	h := &RemediationHandler{Config: &config.Config{}}
	if h.store() != nil {
		t.Error("store() should return nil when both DB and lookupStore are nil")
	}
}

func TestBuildCopyableRecord_WithValue(t *testing.T) {
	result := buildCopyableRecord("TXT", "example.com", "v=spf1 -all")
	if result != "example.com  TXT  v=spf1 -all" {
		t.Errorf("result = %q", result)
	}
}

func TestBuildCopyableRecord_EmptyValue(t *testing.T) {
	result := buildCopyableRecord("TXT", "example.com", "")
	if result != "" {
		t.Error("expected empty result for empty value")
	}
}

func TestGetStr_Present(t *testing.T) {
	m := map[string]any{"key": "value"}
	if got := getStr(m, "key"); got != "value" {
		t.Errorf("getStr = %q, want 'value'", got)
	}
}

func TestGetStr_Missing(t *testing.T) {
	m := map[string]any{}
	if got := getStr(m, "key"); got != "" {
		t.Errorf("getStr = %q, want empty", got)
	}
}

func TestGetStr_NonString(t *testing.T) {
	m := map[string]any{"key": 42}
	result := getStr(m, "key")
	if result != fmt.Sprintf("%v", 42) {
		t.Errorf("getStr = %q, want '42'", result)
	}
}

func TestBuildRemediationItems_WithDNS(t *testing.T) {
	fixes := []any{
		map[string]any{
			"title":     "Add SPF Record",
			"fix":       "Configure SPF",
			"section":   "spf",
			"dns_host":  "example.com",
			"dns_type":  "TXT",
			"dns_value": "v=spf1 -all",
		},
	}
	items := buildRemediationItems(fixes)
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if !items[0].HasDNS {
		t.Error("expected HasDNS = true")
	}
	if items[0].DNSType != "TXT" {
		t.Errorf("DNSType = %q", items[0].DNSType)
	}
}

func TestBuildRemediationItems_WithDNSRecord(t *testing.T) {
	fixes := []any{
		map[string]any{
			"title":      "Add Record",
			"dns_record": "example.com TXT v=spf1 -all",
		},
	}
	items := buildRemediationItems(fixes)
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if !items[0].HasDNS {
		t.Error("expected HasDNS = true")
	}
	if items[0].CopyableRecord != "example.com TXT v=spf1 -all" {
		t.Errorf("CopyableRecord = %q", items[0].CopyableRecord)
	}
}

func TestBuildRemediationItems_InvalidType(t *testing.T) {
	fixes := []any{42}
	items := buildRemediationItems(fixes)
	if len(items) != 0 {
		t.Errorf("expected 0 items for non-map input, got %d", len(items))
	}
}

func TestRemediationSubmit_WithAnalysisID(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewRemediationHandler(nil, cfg)

	w := httptest.NewRecorder()
	router := gin.New()
	router.POST("/remediation", h.RemediationSubmit)

	form := url.Values{}
	form.Set("analysis_id", "42")
	req := httptest.NewRequest(http.MethodPost, "/remediation", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "analysis_id=42") {
		t.Errorf("redirect location = %q, expected analysis_id=42", loc)
	}
}

func TestRemediationSubmit_WithDomain(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewRemediationHandler(nil, cfg)

	w := httptest.NewRecorder()
	router := gin.New()
	router.POST("/remediation", h.RemediationSubmit)

	form := url.Values{}
	form.Set("domain", "EXAMPLE.COM")
	req := httptest.NewRequest(http.MethodPost, "/remediation", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "domain=example.com") {
		t.Errorf("redirect location = %q, expected lowercase domain", loc)
	}
}

func TestRemediationSubmit_Empty(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewRemediationHandler(nil, cfg)

	w := httptest.NewRecorder()
	router := gin.New()
	router.POST("/remediation", h.RemediationSubmit)

	req := httptest.NewRequest(http.MethodPost, "/remediation", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
}

func TestRemediationTemplate_Constant(t *testing.T) {
	if remediationTemplate != "remediation.html" {
		t.Errorf("remediationTemplate = %q", remediationTemplate)
	}
}

// THE TWO-VERDICTS PIN (2026-09-03): the same analysis row read "1 issue to fix"
// on /history (ICSAE RealFixCount) and "No Issues Found" on /remediation (the
// legacy all_fixes, which never receives NO_MAIL_HARDENED). The fix makes
// remediation render from the ICSAE queue when present. These tests pin:
// (1) the queue->items mapping shows the fix the history badge counted;
// (2) legacy-only rows still render from all_fixes (pre-ICSAE fallback);
// (3) description fields stay non-empty (no silent blank fixes).
// Built from the live 18692 shape (mx.dane.resolutionscope.com).
func TestBuildRemediationItemsFromICSAE_ShowsTheFixHistoryCounted(t *testing.T) {
	queue := map[string]any{
		"items": []any{
			map[string]any{
				"rank":            1,
				"control_id":      "NO_MAIL_HARDENED",
				"title":           "No-Mail Domain Hardening",
				"severity":        "medium",
				"exploit_class":   "unproven",
				"exploit_basis":   "No verified weakness mapping yet",
				"attacker_action": "Add a hardening record to close the spoofing surface",
				"confidence":      "moderate",
			},
		},
		"real_fix_count": 1,
	}
	items := buildRemediationItemsFromICSAE(queue)
	if len(items) != 1 {
		t.Fatalf("ICSAE queue with 1 real fix rendered %d items — history says 1, remediation must say 1 (the two-verdicts defect)", len(items))
	}
	it := items[0]
	if it.Title != "No-Mail Domain Hardening" {
		t.Errorf("title = %q", it.Title)
	}
	if !strings.Contains(it.Description, "spoofing surface") {
		t.Errorf("attacker action missing from description: %q", it.Description)
	}
	if it.SeverityColor != "warning" {
		t.Errorf("medium severity should map to warning color, got %q", it.SeverityColor)
	}
	if !strings.Contains(it.Section, "Real Fix") {
		t.Errorf("section should carry the exploit class, got %q", it.Section)
	}
}

func TestBuildRemediationItemsFromICSAE_ZeroFixesRendersZero(t *testing.T) {
	queue := map[string]any{"items": []any{}, "real_fix_count": 0}
	items := buildRemediationItemsFromICSAE(queue)
	if len(items) != 0 {
		t.Fatalf("empty queue rendered %d items", len(items))
	}
	// The template's FixCount will be len(items) = 0 → "No Issues Found"
	// ONLY when the queue itself is empty — the honest zero, matching history.
}

func TestSplitByDNS_ICSAEItemsAreManualByDefault(t *testing.T) {
	items := []remediationItem{{Title: "x"}}
	dns, manual := splitByDNS(items)
	if len(dns) != 0 || len(manual) != 1 {
		t.Fatalf("queue items without dns fields should be manual: dns=%d manual=%d", len(dns), len(manual))
	}
}
