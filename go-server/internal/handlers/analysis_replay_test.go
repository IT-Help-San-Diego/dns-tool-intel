package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dnstool/go-server/internal/dbq"

	"github.com/gin-gonic/gin"
)

func replayTelemetryRows() []dbq.ScanPhaseTelemetry {
	rc := int32(3)
	return []dbq.ScanPhaseTelemetry{
		{AnalysisID: 1, PhaseGroup: "dns_records", PhaseTask: "a_lookup", StartedAtMs: 0, DurationMs: 120, RecordCount: &rc},
		{AnalysisID: 1, PhaseGroup: "email_auth", PhaseTask: "spf", StartedAtMs: 130, DurationMs: 200},
	}
}

func replayTelemetryHash() dbq.ScanTelemetryHash {
	return dbq.ScanTelemetryHash{AnalysisID: 1, TotalDurationMs: 3300, PhaseCount: 2, Sha3512: "deadbeef"}
}

// replayAPIRouter registers /api/replay/:id twice: once unauthenticated
// and once behind a stub that simulates the auth middleware for user 7.
func replayAPIRouter(h *AnalysisHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/replay/:id", h.APIReplay)
	r.GET("/authed/api/replay/:id", func(c *gin.Context) {
		c.Set(mapKeyAuthenticated, true)
		c.Set(mapKeyUserId, int32(7))
		h.APIReplay(c)
	})
	return r
}

func replayMockStore(private bool, owner bool) *mockAnalysisStore {
	results := map[string]any{
		"spf_analysis":   map[string]any{"status": "success", "message": "SPF valid"},
		"dmarc_analysis": map[string]any{"status": "warning", "message": "p=none"},
	}
	resultsJSON, _ := json.Marshal(results)
	return &mockAnalysisStore{
		GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
			return dbq.DomainAnalysis{ID: id, Domain: "example.com", AsciiDomain: "example.com", Private: private, FullResults: resultsJSON}, nil
		},
		CheckAnalysisOwnershipFn: func(ctx context.Context, arg dbq.CheckAnalysisOwnershipParams) (bool, error) {
			return owner, nil
		},
		GetTelemetryHashFn: func(ctx context.Context, analysisID int32) (dbq.ScanTelemetryHash, error) {
			return replayTelemetryHash(), nil
		},
		GetTelemetryByAnalysisFn: func(ctx context.Context, analysisID int32) ([]dbq.ScanPhaseTelemetry, error) {
			return replayTelemetryRows(), nil
		},
	}
}

// TestAPIReplay_InvalidIDRejected: non-numeric IDs are rejected with 400
// before any store access.
func TestAPIReplay_InvalidIDRejected(t *testing.T) {
	called := false
	h := newViewModeHandler(&mockAnalysisStore{
		GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
			called = true
			return dbq.DomainAnalysis{}, nil
		},
	})
	r := replayAPIRouter(h)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/replay/abc", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", w.Code)
	}
	if called {
		t.Error("store must not be queried for an invalid ID")
	}
}

// TestAPIReplay_PublicAnalysisServed: a public analysis with recorded
// telemetry replays for anyone — v1 format, events, verdicts, hash.
func TestAPIReplay_PublicAnalysisServed(t *testing.T) {
	h := newViewModeHandler(replayMockStore(false, false))
	r := replayAPIRouter(h)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/replay/1", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if v, _ := body["v"].(float64); int(v) != replayFormatVersion {
		t.Errorf("v = %v, want %d", body["v"], replayFormatVersion)
	}
	if body["domain"] != "example.com" {
		t.Errorf("domain = %v", body["domain"])
	}
	if tm, _ := body["total_ms"].(float64); int(tm) != 3300 {
		t.Errorf("total_ms = %v, want 3300", body["total_ms"])
	}
	if body["sha3_512"] != "deadbeef" {
		t.Errorf("sha3_512 = %v", body["sha3_512"])
	}
	events, _ := body["events"].([]any)
	if len(events) != 2 {
		t.Fatalf("events len = %d, want 2", len(events))
	}
	ev0, _ := events[0].(map[string]any)
	if ev0["group"] != "dns_records" || ev0["task"] != "a_lookup" {
		t.Errorf("event0 = %v", ev0)
	}
	if rc, _ := ev0["rc"].(float64); int(rc) != 3 {
		t.Errorf("event0 rc = %v, want 3", ev0["rc"])
	}
	verdicts, _ := body["verdicts"].(map[string]any)
	if verdicts["spf"] != "success" || verdicts["dmarc"] != "warning" {
		t.Errorf("verdicts = %v", verdicts)
	}
}

// TestAPIReplay_PrivateUnauthenticatedGets404: an unauthenticated caller
// must receive the SAME 404 as a nonexistent analysis — the response
// must not reveal that a private analysis exists, nor its domain.
func TestAPIReplay_PrivateUnauthenticatedGets404(t *testing.T) {
	h := newViewModeHandler(replayMockStore(true, false))
	r := replayAPIRouter(h)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/replay/1", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", w.Code)
	}
	if strings.Contains(w.Body.String(), "example.com") {
		t.Error("404 body must not leak the private analysis domain")
	}
	if strings.Contains(w.Body.String(), "restricted") {
		t.Error("unauthenticated 404 must not reveal that the analysis is restricted")
	}
}

// TestAPIReplay_PrivateWrongUserGets403: a signed-in non-owner receives
// an explicit 403 with no replay payload and no domain leakage.
func TestAPIReplay_PrivateWrongUserGets403(t *testing.T) {
	h := newViewModeHandler(replayMockStore(true, false))
	r := replayAPIRouter(h)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/authed/api/replay/1", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "example.com") {
		t.Error("403 body must not leak the private analysis domain")
	}
	if strings.Contains(body, "events") || strings.Contains(body, "sha3_512") {
		t.Error("403 body must not contain replay payload fields")
	}
}

// TestAPIReplay_PrivateOwnerGets200: the owner replays their own private
// analysis normally.
func TestAPIReplay_PrivateOwnerGets200(t *testing.T) {
	h := newViewModeHandler(replayMockStore(true, true))
	r := replayAPIRouter(h)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/authed/api/replay/1", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "dns_records") {
		t.Error("owner response should contain replay events")
	}
}

// TestAPIReplay_NoTelemetryHonest404: analyses without a recorded
// timeline get an honest 404 explaining why — never a fabricated replay.
func TestAPIReplay_NoTelemetryHonest404(t *testing.T) {
	store := replayMockStore(false, false)
	store.GetTelemetryHashFn = func(ctx context.Context, analysisID int32) (dbq.ScanTelemetryHash, error) {
		return dbq.ScanTelemetryHash{}, fmt.Errorf("no rows")
	}
	h := newViewModeHandler(store)
	r := replayAPIRouter(h)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/replay/1", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", w.Code)
	}
	if !strings.Contains(w.Body.String(), "No replay available") {
		t.Errorf("expected honest no-replay message, got %s", w.Body.String())
	}
}

// TestAPIReplay_EmptyTelemetryRows404: a stored hash with zero telemetry
// rows is treated the same as no telemetry (honest 404, no synthesis).
func TestAPIReplay_EmptyTelemetryRows404(t *testing.T) {
	store := replayMockStore(false, false)
	store.GetTelemetryByAnalysisFn = func(ctx context.Context, analysisID int32) ([]dbq.ScanPhaseTelemetry, error) {
		return nil, nil
	}
	h := newViewModeHandler(store)
	r := replayAPIRouter(h)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/replay/1", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", w.Code)
	}
}

// TestReplayVerdicts_TriState: missing sections and missing statuses are
// reported as "indeterminate" — never collapsed into pass or fail.
func TestReplayVerdicts_TriState(t *testing.T) {
	results := map[string]any{
		"spf_analysis":    map[string]any{"status": "success"},
		"dane_analysis":   map[string]any{"status": "unknown"},
		"dnssec_analysis": map[string]any{"message": "no status field"},
	}
	raw, _ := json.Marshal(results)
	verdicts := replayVerdicts(raw)
	if len(verdicts) != 9 {
		t.Fatalf("verdicts len = %d, want 9 (all protocol slots present)", len(verdicts))
	}
	if verdicts["spf"] != "success" {
		t.Errorf("spf = %q", verdicts["spf"])
	}
	if verdicts["dane"] != "unknown" {
		t.Errorf("dane = %q, want stored status passed through verbatim", verdicts["dane"])
	}
	if verdicts["dnssec"] != "indeterminate" {
		t.Errorf("dnssec (missing status) = %q, want indeterminate", verdicts["dnssec"])
	}
	if verdicts["bimi"] != "indeterminate" {
		t.Errorf("bimi (missing section) = %q, want indeterminate", verdicts["bimi"])
	}
}

// TestReplayVerdictDetail pins the fixture-class case that motivated the
// field: a CD-confirmed bogus chain carries status "warning" beside
// display_severity "danger" in the same section, and the replay payload
// must surface the producer's derivation so the client ring never keys
// on the flattening status string.
func TestReplayVerdictDetail(t *testing.T) {
	results := map[string]any{
		"dnssec_analysis": map[string]any{
			"status":           "warning",
			"display_label":    "Broken",
			"display_severity": "danger",
			"dnssec_state":     "present",
			"chain_of_trust":   "broken",
			"ad_consensus":     "bogus",
		},
	}
	raw, _ := json.Marshal(results)
	detail := replayVerdictDetail(raw)
	if detail == nil {
		t.Fatal("detail = nil, want dnssec entry")
	}
	d := detail["dnssec"]
	want := map[string]string{
		"display_label":    "Broken",
		"display_severity": "danger",
		"dnssec_state":     "present",
		"chain_of_trust":   "broken",
		"ad_consensus":     "bogus",
	}
	for k, w := range want {
		if d[k] != w {
			t.Errorf("dnssec[%q] = %q, want %q", k, d[k], w)
		}
	}
}

// TestReplayVerdictDetail_LegacyAndInherited: rows without a
// display_severity produce NO detail (self-scoping — the client falls
// back to status rendering), and the inherited path's missing
// ad_consensus is omitted rather than fabricated as an empty string.
func TestReplayVerdictDetail_LegacyAndInherited(t *testing.T) {
	legacy, _ := json.Marshal(map[string]any{
		"dnssec_analysis": map[string]any{"status": "success", "chain_of_trust": "complete"},
	})
	if got := replayVerdictDetail(legacy); got != nil {
		t.Errorf("legacy row detail = %v, want nil", got)
	}
	if got := replayVerdictDetail([]byte("not json")); got != nil {
		t.Errorf("malformed detail = %v, want nil", got)
	}
	inherited, _ := json.Marshal(map[string]any{
		"dnssec_analysis": map[string]any{
			"status": "success", "display_label": "Inherited",
			"display_severity": "success", "dnssec_state": "present",
			"chain_of_trust": "inherited",
		},
	})
	d := replayVerdictDetail(inherited)
	if d == nil {
		t.Fatal("inherited row detail = nil, want dnssec entry")
	}
	if _, present := d["dnssec"]["ad_consensus"]; present {
		t.Error("inherited row must omit ad_consensus, not fabricate one")
	}
	if d["dnssec"]["display_severity"] != "success" {
		t.Errorf("inherited severity = %q", d["dnssec"]["display_severity"])
	}
}

// TestReplayVerdicts_MalformedResults: unparseable full_results yield
// all-indeterminate verdicts rather than an error or fabricated states.
func TestReplayVerdicts_MalformedResults(t *testing.T) {
	verdicts := replayVerdicts([]byte("not json"))
	if len(verdicts) != 9 {
		t.Fatalf("verdicts len = %d, want 9", len(verdicts))
	}
	for k, v := range verdicts {
		if v != "indeterminate" {
			t.Errorf("%s = %q, want indeterminate", k, v)
		}
	}
}

func replayPageRouter(h *AnalysisHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	tmpl := template.Must(template.New("").Parse(
		`{{define "index.html"}}TMPL:index{{end}}` +
			`{{define "topology.html"}}TMPL:topology ReplayID={{.ReplayID}} ReplayDomain={{.ReplayDomain}}{{end}}`,
	))
	r.SetHTMLTemplate(tmpl)
	topo := NewTopologyHandler(h.Config)
	r.GET("/replay/:id", h.ReplayPage(topo))
	r.GET("/authed/replay/:id", func(c *gin.Context) {
		c.Set(mapKeyAuthenticated, true)
		c.Set(mapKeyUserId, int32(7))
		h.ReplayPage(topo)(c)
	})
	return r
}

// TestReplayPage_PublicServed: the permalink renders the topology
// template in replay mode with the analysis domain bound.
func TestReplayPage_PublicServed(t *testing.T) {
	h := newViewModeHandler(replayMockStore(false, false))
	r := replayPageRouter(h)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/replay/1", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "TMPL:topology") {
		t.Errorf("expected topology template, got %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "ReplayDomain=example.com") {
		t.Errorf("expected replay domain in template data, got %s", w.Body.String())
	}
}

// TestReplayPage_PrivateUnauthenticated404: access control runs BEFORE
// template data is built — an unauthenticated caller gets a 404 page
// that never mentions the private domain (no OG metadata leak).
func TestReplayPage_PrivateUnauthenticated404(t *testing.T) {
	h := newViewModeHandler(replayMockStore(true, false))
	r := replayPageRouter(h)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/replay/1", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", w.Code)
	}
	if strings.Contains(w.Body.String(), "example.com") {
		t.Error("404 page must not leak the private analysis domain")
	}
	if strings.Contains(w.Body.String(), "TMPL:topology") {
		t.Error("private unauthenticated request must not render the replay page")
	}
}

// TestReplayPage_PrivateWrongUser403: a signed-in non-owner gets the
// restricted-access page, not the replay.
func TestReplayPage_PrivateWrongUser403(t *testing.T) {
	h := newViewModeHandler(replayMockStore(true, false))
	r := replayPageRouter(h)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/authed/replay/1", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", w.Code)
	}
	if strings.Contains(w.Body.String(), "TMPL:topology") {
		t.Error("non-owner must not receive the replay page")
	}
}

// TestReplayPage_NoTelemetry404: a permalink for an analysis without a
// recorded timeline gets the honest 404 — no empty player is rendered.
func TestReplayPage_NoTelemetry404(t *testing.T) {
	store := replayMockStore(false, false)
	store.GetTelemetryHashFn = func(ctx context.Context, analysisID int32) (dbq.ScanTelemetryHash, error) {
		return dbq.ScanTelemetryHash{}, fmt.Errorf("no rows")
	}
	h := newViewModeHandler(store)
	r := replayPageRouter(h)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/replay/1", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", w.Code)
	}
	if strings.Contains(w.Body.String(), "TMPL:topology") {
		t.Error("no-telemetry request must not render the replay page")
	}
}

// TestReplayBootstrapTemplateEscaping renders the real __TOPO_REPLAY bootstrap
// line from go-server/templates/topology.html through html/template and proves
// contextual autoescaping emits the domain as a quoted JS string literal —
// including under a hostile domain — so replay mode always receives a valid
// object. Regression guard for the replay permalink bootstrap.
func TestReplayBootstrapTemplateEscaping(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "templates", "topology.html"))
	if err != nil {
		t.Fatalf("read topology.html: %v", err)
	}
	var line string
	for _, l := range strings.Split(string(src), "\n") {
		if strings.Contains(l, "__TOPO_REPLAY") {
			line = strings.TrimSpace(l)
			break
		}
	}
	if line == "" {
		t.Fatal("topology.html no longer contains the __TOPO_REPLAY bootstrap line")
	}
	tmpl, err := template.New("boot").Parse(line)
	if err != nil {
		t.Fatalf("parse bootstrap line: %v", err)
	}

	render := func(domain string) string {
		var buf bytes.Buffer
		data := map[string]any{
			"CspNonce":      "test-nonce",
			"ReplayID":      int32(934),
			"ReplayDomain":  domain,
			"ReplayTotalMs": int64(9658),
		}
		if err := tmpl.Execute(&buf, data); err != nil {
			t.Fatalf("execute bootstrap line: %v", err)
		}
		return buf.String()
	}

	// Benign domain: must render as a quoted JS string literal, not a bare
	// identifier (domain:"ietf.org", never domain:ietf.org).
	out := render("ietf.org")
	if !strings.Contains(out, `domain:"ietf.org"`) {
		t.Errorf("domain not rendered as a quoted JS string literal: %s", out)
	}

	// Hostile domain: the embedded quote must be escaped (\") so it cannot
	// terminate the string literal and inject script.
	hostile := render(`evil.com";alert(1);//`)
	if strings.Contains(hostile, `evil.com";`) {
		t.Errorf("hostile domain broke out of the JS string literal: %s", hostile)
	}
	if !strings.Contains(hostile, `evil.com\";alert(1)`) {
		t.Errorf("hostile quote not escaped inside the JS string literal: %s", hostile)
	}
	if !strings.Contains(hostile, `domain:"`) {
		t.Errorf("hostile domain not rendered as a quoted JS string literal: %s", hostile)
	}
}
