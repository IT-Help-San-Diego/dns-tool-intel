// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"dnstool/go-server/internal/analyzer"
	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/dbq"
	"dnstool/go-server/internal/dnsclient"
	"dnstool/go-server/internal/icae"
	"dnstool/go-server/internal/icuae"

	"codeberg.org/miekg/dns"
	"github.com/gin-gonic/gin"
	"html/template"
)

// These tests pin the defect measured 2026-07-31 on the dev server: the sync
// POST /analyze path ran the scan AND its save on c.Request.Context(), so a
// client navigating away (there: a second submit's rate-limit redirect)
// cancelled every in-flight DNS query and then failed the save of 7.46s of
// completed analysis with "context canceled" at severity CRITICAL. A scan is
// not a page render — once measurement starts, its results must land
// regardless of what the browser does next.

func TestScanContextDetachesFromParentCancellation(t *testing.T) {
	type key struct{}
	parent, cancelParent := context.WithCancel(
		context.WithValue(context.Background(), key{}, "kept"))

	ctx, cancel := scanContext(parent)
	defer cancel()

	cancelParent()
	select {
	case <-ctx.Done():
		t.Fatal("scan context died with its parent — request cancellation would still kill scans")
	default:
	}

	if v, _ := ctx.Value(key{}).(string); v != "kept" {
		t.Errorf("parent values not preserved (got %q) — trace attribution would be lost", v)
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("scan context has no deadline — a hung scan would run forever")
	}
	if remaining := time.Until(deadline); remaining > scanTimeout || remaining < scanTimeout-5*time.Second {
		t.Errorf("deadline %v from now, want ~%v — the bound drifted from scanTimeout", remaining, scanTimeout)
	}
}

// blockingDNSStub answers every query with a benign record, but holds the
// FIRST wave of queries at a gate until the test releases them — the window
// in which the test cancels the originating request. ProbeExists reports the
// domain as existing so the scan reaches persistence (nonexistent domains
// are deliberately not persisted).
type blockingDNSStub struct {
	started   chan struct{}
	release   chan struct{}
	startOnce sync.Once
}

func (s *blockingDNSStub) gate(ctx context.Context) {
	s.startOnce.Do(func() { close(s.started) })
	select {
	case <-s.release:
	case <-ctx.Done():
	}
}

func (s *blockingDNSStub) QueryDNS(ctx context.Context, recordType, domain string) []string {
	s.gate(ctx)
	if ctx.Err() != nil {
		return nil
	}
	return []string{"192.0.2.10"}
}

func (s *blockingDNSStub) QueryDNSWithTTL(ctx context.Context, recordType, domain string) dnsclient.RecordWithTTL {
	s.gate(ctx)
	ttl := uint32(300)
	return dnsclient.RecordWithTTL{Records: s.QueryDNS(ctx, recordType, domain), TTL: &ttl}
}

func (s *blockingDNSStub) QueryDNSWithTTLStatus(ctx context.Context, recordType, domain string) (dnsclient.RecordWithTTL, dnsclient.LookupStatus) {
	return s.QueryDNSWithTTL(ctx, recordType, domain), dnsclient.LookupResolved
}

func (s *blockingDNSStub) QueryWithConsensus(ctx context.Context, recordType, domain string) dnsclient.ConsensusResult {
	s.gate(ctx)
	return dnsclient.ConsensusResult{Records: []string{"192.0.2.10"}}
}

func (s *blockingDNSStub) QuerySpecificResolver(ctx context.Context, recordType, domain, resolverIP string) ([]string, error) {
	s.gate(ctx)
	return []string{"192.0.2.10"}, nil
}

func (s *blockingDNSStub) QuerySpecificResolverAuth(ctx context.Context, recordType, domain, resolverIP string) ([]string, bool, string) {
	s.gate(ctx)
	return []string{"192.0.2.10"}, false, ""
}

func (s *blockingDNSStub) QueryWithTTLFromResolver(ctx context.Context, recordType, domain, resolverIP string) dnsclient.RecordWithTTL {
	return s.QueryDNSWithTTL(ctx, recordType, domain)
}

func (s *blockingDNSStub) CheckDNSSECADFlag(ctx context.Context, domain string) dnsclient.ADFlagResult {
	s.gate(ctx)
	return dnsclient.ADFlagResult{}
}

func (s *blockingDNSStub) ExchangeContext(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	s.gate(ctx)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	reply := new(dns.Msg)
	reply.ID = msg.ID
	reply.Response = true
	reply.Question = msg.Question
	return reply, nil
}

func (s *blockingDNSStub) ValidateResolverConsensus(ctx context.Context, domain string) map[string]any {
	s.gate(ctx)
	return map[string]any{}
}

func (s *blockingDNSStub) ProbeExists(ctx context.Context, domain string) (bool, string) {
	s.gate(ctx)
	return true, ""
}

// offlineHTTPStub fails every request immediately, keeping the scan off the
// network without slowing it down.
type offlineHTTPStub struct{}

var errOffline = errors.New("offline test stub")

func (offlineHTTPStub) Get(ctx context.Context, rawURL string) (*http.Response, error) {
	return nil, errOffline
}
func (offlineHTTPStub) GetDirect(ctx context.Context, rawURL string) (*http.Response, error) {
	return nil, errOffline
}
func (offlineHTTPStub) ReadBody(resp *http.Response, maxBytes int64) ([]byte, error) {
	return nil, errOffline
}

// ctxRecordingStore succeeds like a real store but refuses work on a
// cancelled context exactly as pgx would — the property the defect abused —
// and records the context state InsertAnalysis was called with.
type ctxRecordingStore struct {
	mu               sync.Mutex
	insertCalled     bool
	insertCtxErr     error
	insertAppVersion string
}

func (f *ctxRecordingStore) observeInsert(ctx context.Context, appVersion string) error {
	f.mu.Lock()
	f.insertCalled = true
	f.insertCtxErr = ctx.Err()
	f.insertAppVersion = appVersion
	f.mu.Unlock()
	return ctx.Err()
}

var errNoRows = errors.New("no rows in result set")

func (f *ctxRecordingStore) InsertAnalysis(ctx context.Context, arg dbq.InsertAnalysisParams) (dbq.InsertAnalysisRow, error) {
	if err := f.observeInsert(ctx, arg.AppVersion); err != nil {
		return dbq.InsertAnalysisRow{}, err
	}
	return dbq.InsertAnalysisRow{ID: 42}, nil
}

func (f *ctxRecordingStore) UpsertDomainIndex(ctx context.Context, arg dbq.UpsertDomainIndexParams) error {
	return ctx.Err()
}

func (f *ctxRecordingStore) GetPreviousAnalysisForDrift(ctx context.Context, domain string) (dbq.GetPreviousAnalysisForDriftRow, error) {
	return dbq.GetPreviousAnalysisForDriftRow{}, errNoRows
}

func (f *ctxRecordingStore) GetPreviousAnalysisForDriftBefore(ctx context.Context, arg dbq.GetPreviousAnalysisForDriftBeforeParams) (dbq.GetPreviousAnalysisForDriftBeforeRow, error) {
	return dbq.GetPreviousAnalysisForDriftBeforeRow{}, errNoRows
}

func (f *ctxRecordingStore) InsertDriftEvent(ctx context.Context, arg dbq.InsertDriftEventParams) (dbq.InsertDriftEventRow, error) {
	return dbq.InsertDriftEventRow{}, ctx.Err()
}

func (f *ctxRecordingStore) ListEndpointsForWatchedDomain(ctx context.Context, domain string) ([]dbq.ListEndpointsForWatchedDomainRow, error) {
	return nil, nil
}

func (f *ctxRecordingStore) InsertDriftNotification(ctx context.Context, arg dbq.InsertDriftNotificationParams) (int32, error) {
	return 0, ctx.Err()
}

func (f *ctxRecordingStore) InsertPhaseTelemetry(ctx context.Context, arg dbq.InsertPhaseTelemetryParams) error {
	return ctx.Err()
}

func (f *ctxRecordingStore) InsertTelemetryHash(ctx context.Context, arg dbq.InsertTelemetryHashParams) error {
	return ctx.Err()
}

func (f *ctxRecordingStore) InsertUserAnalysis(ctx context.Context, arg dbq.InsertUserAnalysisParams) error {
	return ctx.Err()
}

func (f *ctxRecordingStore) UpdateWaybackURL(ctx context.Context, arg dbq.UpdateWaybackURLParams) error {
	return ctx.Err()
}

func (f *ctxRecordingStore) CountHashedAnalyses(ctx context.Context) (int64, error) { return 0, nil }

func (f *ctxRecordingStore) ListHashedAnalyses(ctx context.Context, arg dbq.ListHashedAnalysesParams) ([]dbq.ListHashedAnalysesRow, error) {
	return nil, nil
}

func (f *ctxRecordingStore) GetAnalysisByID(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
	return dbq.DomainAnalysis{}, errNoRows
}

func (f *ctxRecordingStore) CheckAnalysisOwnership(ctx context.Context, arg dbq.CheckAnalysisOwnershipParams) (bool, error) {
	return false, nil
}

func (f *ctxRecordingStore) GetRecentAnalysisByDomain(ctx context.Context, domain string) (dbq.DomainAnalysis, error) {
	return dbq.DomainAnalysis{}, errNoRows
}

func (f *ctxRecordingStore) GetTelemetryByAnalysis(ctx context.Context, analysisID int32) ([]dbq.ScanPhaseTelemetry, error) {
	return nil, nil
}

func (f *ctxRecordingStore) GetTelemetryHash(ctx context.Context, analysisID int32) (dbq.ScanTelemetryHash, error) {
	return dbq.ScanTelemetryHash{}, errNoRows
}

// TestAnalyzeSyncScanSurvivesClientDisconnect drives the real sync handler:
// the request context is cancelled while the scan's first DNS queries are
// in flight, and the analysis must still complete and save. Before the
// scanContext fix this fails two ways at once: the queries die "context
// canceled" and InsertAnalysis is invoked on a dead context (or the failure
// branch renders without persisting anything).
//
// Note: side-effect goroutines gated on a successful save (wayback archive)
// may attempt one outbound HTTP call and fail harmlessly offline — the same
// behavior the existing coverage-tagged Analyze tests exhibit.
func TestAnalyzeSyncScanSurvivesClientDisconnect(t *testing.T) {
	stub := &blockingDNSStub{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	a := analyzer.New(analyzer.WithMaxConcurrent(2), analyzer.WithInitialIANAFetch(false))
	a.DNS = stub
	a.HTTP = offlineHTTPStub{}
	a.SlowHTTP = offlineHTTPStub{}
	a.RDAPHTTP = offlineHTTPStub{}
	a.SMTPProbeMode = "skip"

	store := &ctxRecordingStore{}
	h := &AnalysisHandler{
		Config: &config.Config{
			AppVersion: "26.40.19",
			BaseURL:    "https://dnstool.it-help.tech",
		},
		Analyzer:      a,
		Calibration:   icae.NewCalibrationEngine(),
		DimCharts:     icuae.NewDimensionCharts(),
		ProgressStore: NewProgressStore(),
		analysisStore: store,
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	tmpl := template.Must(template.New("index.html").Parse(`{{range .FlashMessages}}{{.Message}}{{end}}`))
	tmpl = template.Must(tmpl.New("analyze.html").Parse(`{{.Domain}}`))
	tmpl = template.Must(tmpl.New("analyze_covert.html").Parse(`{{.Domain}}`))
	r.SetHTMLTemplate(tmpl)
	r.POST("/analyze", h.Analyze)

	reqCtx, cancelReq := context.WithCancel(context.Background())
	req := httptest.NewRequest("POST", "/analyze", strings.NewReader("domain=ctx-detach-probe.example"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(reqCtx)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		r.ServeHTTP(w, req)
	}()

	select {
	case <-stub.started:
	case <-time.After(15 * time.Second):
		t.Fatal("scan never issued a DNS query")
	}

	// The client walks away mid-measurement.
	cancelReq()
	close(stub.release)

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("handler did not finish after the scan was released")
	}

	store.mu.Lock()
	called, ctxErr, appVer := store.insertCalled, store.insertCtxErr, store.insertAppVersion
	store.mu.Unlock()

	if !called {
		t.Fatal("InsertAnalysis was never called — the completed analysis was not persisted after client disconnect")
	}
	if ctxErr != nil {
		t.Fatalf("InsertAnalysis received an already-cancelled context (%v) — the save still rides the request lifecycle", ctxErr)
	}
	// Producer attribution (migration 019): every persisted analysis names the
	// build that measured it. Rows without it are tier-3 (not comparable) on
	// any local-vs-cloud statistics surface, permanently — so an empty value
	// here is a regression against the stats-lever comparability spec.
	if appVer != h.Config.AppVersion {
		t.Fatalf("InsertAnalysis carried app_version %q, want %q — the row lost its producer attribution", appVer, h.Config.AppVersion)
	}
}
