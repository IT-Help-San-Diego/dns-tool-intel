package handlers

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type mockDNSQuerier struct {
	responses map[string][]string
}

func (m *mockDNSQuerier) QueryDNS(_ context.Context, recordType, domain string) []string {
	key := recordType + ":" + domain
	if r, ok := m.responses[key]; ok {
		return r
	}
	return nil
}

func TestCoverageBoost17_ComputeSubdomainEmailScope_LocalSPFAndDMARC(t *testing.T) {
	dns := &mockDNSQuerier{responses: map[string][]string{
		"TXT:_dmarc.example.com": {"v=DMARC1; p=reject"},
	}}
	results := map[string]any{
		mapKeySpfAnalysis:   map[string]any{mapKeyStatus: mapKeySuccess},
		mapKeyDmarcAnalysis: map[string]any{mapKeyStatus: mapKeySuccess},
		"basic_records":     map[string]any{"MX": []any{"mx.sub.example.com"}},
	}
	scope := computeSubdomainEmailScope(context.Background(), dns, "sub.example.com", "example.com", results)
	if !scope.IsSubdomain {
		t.Error("expected IsSubdomain=true")
	}
	if scope.ParentDomain != "example.com" {
		t.Errorf("ParentDomain = %q", scope.ParentDomain)
	}
	if scope.SPFScope != "local" {
		t.Errorf("SPFScope = %q, want local", scope.SPFScope)
	}
	if scope.DMARCScope != "local" {
		t.Errorf("DMARCScope = %q, want local", scope.DMARCScope)
	}
	if !scope.HasLocalEmail {
		t.Error("expected HasLocalEmail=true")
	}
}

func TestCoverageBoost17_ComputeSubdomainEmailScope_InheritedDMARC(t *testing.T) {
	dns := &mockDNSQuerier{responses: map[string][]string{
		"TXT:_dmarc.example.com": {"v=DMARC1; p=quarantine"},
	}}
	results := map[string]any{
		mapKeySpfAnalysis:   map[string]any{mapKeyStatus: "danger"},
		mapKeyDmarcAnalysis: map[string]any{mapKeyStatus: "danger"},
	}
	scope := computeSubdomainEmailScope(context.Background(), dns, "sub.example.com", "example.com", results)
	if scope.SPFScope != "none" {
		t.Errorf("SPFScope = %q, want none", scope.SPFScope)
	}
	if scope.DMARCScope != "inherited" {
		t.Errorf("DMARCScope = %q, want inherited", scope.DMARCScope)
	}
	if scope.HasLocalEmail {
		t.Error("expected HasLocalEmail=false")
	}
}

func TestCoverageBoost17_ComputeSubdomainEmailScope_NoDMARC(t *testing.T) {
	dns := &mockDNSQuerier{responses: map[string][]string{}}
	results := map[string]any{}
	scope := computeSubdomainEmailScope(context.Background(), dns, "sub.example.com", "example.com", results)
	if scope.SPFScope != "none" {
		t.Errorf("SPFScope = %q, want none", scope.SPFScope)
	}
	if scope.DMARCScope != "none" {
		t.Errorf("DMARCScope = %q, want none", scope.DMARCScope)
	}
}

func TestCoverageBoost17_ComputeSubdomainEmailScope_MissingAnalysisKeys(t *testing.T) {
	dns := &mockDNSQuerier{responses: map[string][]string{}}
	results := map[string]any{
		mapKeySpfAnalysis:   "not a map",
		mapKeyDmarcAnalysis: 42,
	}
	scope := computeSubdomainEmailScope(context.Background(), dns, "sub.example.com", "example.com", results)
	if scope.SPFScope != "none" {
		t.Errorf("SPFScope = %q, want none", scope.SPFScope)
	}
	if scope.DMARCScope != "none" {
		t.Errorf("DMARCScope = %q, want none", scope.DMARCScope)
	}
}

func TestCoverageBoost17_ComputeSubdomainEmailScope_StatusNotString(t *testing.T) {
	dns := &mockDNSQuerier{responses: map[string][]string{}}
	results := map[string]any{
		mapKeySpfAnalysis:   map[string]any{mapKeyStatus: 123},
		mapKeyDmarcAnalysis: map[string]any{},
	}
	scope := computeSubdomainEmailScope(context.Background(), dns, "sub.example.com", "example.com", results)
	if scope.SPFScope != "none" {
		t.Errorf("SPFScope = %q, want none", scope.SPFScope)
	}
}

// When the analyzer applied the RFC 7489 §6.6.3 org-domain fallback, the DMARC
// status is success/warning even though NOTHING is published at the subdomain
// name — the scope badge must say "Inherited", never "Local".
func TestComputeSubdomainEmailScope_OrgFallbackIsInheritedNotLocal(t *testing.T) {
	dns := &mockDNSQuerier{responses: map[string][]string{}}
	results := map[string]any{
		mapKeySpfAnalysis: map[string]any{mapKeyStatus: mapKeySuccess},
		mapKeyDmarcAnalysis: map[string]any{
			mapKeyStatus:              mapKeySuccess,
			"org_domain_fallback":     true,
			"org_domain":              "example.com",
			"policy":                  "reject",
			"effective_policy_source": "sp",
		},
	}
	scope := computeSubdomainEmailScope(context.Background(), dns, "sub.example.com", "example.com", results)
	if scope.DMARCScope != "inherited" {
		t.Errorf("DMARCScope = %q, want inherited (nothing published at subdomain)", scope.DMARCScope)
	}
	if !strings.Contains(scope.DMARCNote, "example.com") || !strings.Contains(scope.DMARCNote, "sp=reject") || !strings.Contains(scope.DMARCNote, "6.6.3") {
		t.Errorf("DMARCNote should cite org domain, sp=reject and §6.6.3, got %q", scope.DMARCNote)
	}
}

func TestCoverageBoost17_NormalizeForCompare_MixedTypeArray(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"z": 1},
		map[string]interface{}{"a": 2},
	}
	got := normalizeForCompare(arr)
	sorted, ok := got.([]interface{})
	if !ok {
		t.Fatal("expected array result")
	}
	if len(sorted) != 2 {
		t.Fatalf("expected 2 elements, got %d", len(sorted))
	}
}

func TestCoverageBoost17_NormalizeForCompare_NilValue(t *testing.T) {
	got := normalizeForCompare(nil)
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestCoverageBoost17_NormalizeForCompare_EmptyArray(t *testing.T) {
	arr := []interface{}{}
	got := normalizeForCompare(arr)
	gotArr, ok := got.([]interface{})
	if !ok {
		t.Fatal("expected array result")
	}
	if len(gotArr) != 0 {
		t.Errorf("expected empty array, got %v", gotArr)
	}
}

func TestCoverageBoost17_NormalizeForCompare_NumberArray(t *testing.T) {
	arr := []interface{}{float64(3), float64(1), float64(2)}
	got := normalizeForCompare(arr)
	sorted, ok := got.([]interface{})
	if !ok {
		t.Fatal("expected array result")
	}
	if len(sorted) != 3 {
		t.Fatalf("expected 3 elements, got %d", len(sorted))
	}
	first, ok := sorted[0].(float64)
	if !ok || first != 1 {
		t.Errorf("first element = %v, want 1", sorted[0])
	}
}

func TestCoverageBoost17_NormalizeForCompare_BooleanValue(t *testing.T) {
	got := normalizeForCompare(true)
	if got != true {
		t.Errorf("expected true, got %v", got)
	}
}

func TestCoverageBoost17_NormalizeForCompare_MapValue(t *testing.T) {
	m := map[string]interface{}{"key": "val"}
	got := normalizeForCompare(m)
	gotMap, ok := got.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if gotMap["key"] != "val" {
		t.Errorf("expected val, got %v", gotMap["key"])
	}
}

func TestCoverageBoost17_NormalizeForCompare_NestedMapArray(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"name": "beta"},
		map[string]interface{}{"name": "alpha"},
	}
	got := normalizeForCompare(arr)
	sorted, ok := got.([]interface{})
	if !ok {
		t.Fatal("expected array result")
	}
	if len(sorted) != 2 {
		t.Fatalf("expected 2 elements, got %d", len(sorted))
	}
	b0, _ := json.Marshal(sorted[0])
	b1, _ := json.Marshal(sorted[1])
	if string(b0) >= string(b1) {
		t.Errorf("expected sorted order, got %s then %s", b0, b1)
	}
}

func TestCoverageBoost17_ParseOrgDMARC_SpaceDelimited(t *testing.T) {
	found, policy := parseOrgDMARC([]string{"v=DMARC1 p=reject"})
	if !found {
		t.Error("expected found=true")
	}
	if policy != "reject" {
		t.Errorf("policy = %q, want reject", policy)
	}
}

func TestCoverageBoost17_ParseOrgDMARC_WhitespaceAround(t *testing.T) {
	found, policy := parseOrgDMARC([]string{"  v=DMARC1; p=none  "})
	if !found {
		t.Error("expected found=true")
	}
	if policy != "none" {
		t.Errorf("policy = %q, want none", policy)
	}
}

func TestCoverageBoost17_ParseOrgDMARC_NoPolicyTag(t *testing.T) {
	found, policy := parseOrgDMARC([]string{"v=DMARC1; rua=mailto:a@b.com"})
	if !found {
		t.Error("expected found=true")
	}
	if policy != "" {
		t.Errorf("policy = %q, want empty", policy)
	}
}

func TestCoverageBoost17_HasLocalMXRecords_NilBasicRecords(t *testing.T) {
	got := hasLocalMXRecords(map[string]any{"basic_records": nil})
	if got {
		t.Error("expected false for nil basic_records")
	}
}

func TestCoverageBoost17_HasLocalMXRecords_IntMXValue(t *testing.T) {
	got := hasLocalMXRecords(map[string]any{"basic_records": map[string]any{"MX": 42}})
	if got {
		t.Error("expected false for int MX value")
	}
}

func TestCoverageBoost17_DetermineSPFScope_Details(t *testing.T) {
	scope, note := determineSPFScope(true)
	if scope != "local" {
		t.Errorf("scope = %q, want local", scope)
	}
	if note != "SPF record published at this subdomain" {
		t.Errorf("note = %q", note)
	}

	scope, note = determineSPFScope(false)
	if scope != "none" {
		t.Errorf("scope = %q, want none", scope)
	}
	if note != "No SPF record at this subdomain — SPF does not inherit from parent domains" {
		t.Errorf("note = %q", note)
	}
}

func TestCoverageBoost17_DetermineDMARCScope_AllPaths(t *testing.T) {
	scope, note := determineDMARCScope(true, true, "reject", "example.com")
	if scope != "local" {
		t.Errorf("expected local when sub has DMARC, got %q", scope)
	}
	if note != "DMARC record published at this subdomain" {
		t.Errorf("unexpected note for local: %q", note)
	}

	scope, note = determineDMARCScope(false, true, "quarantine", "example.com")
	if scope != "inherited" {
		t.Errorf("expected inherited, got %q", scope)
	}
	if note == "" {
		t.Error("expected non-empty note for inherited")
	}

	scope, note = determineDMARCScope(false, true, "", "example.com")
	if scope != "inherited" {
		t.Errorf("expected inherited, got %q", scope)
	}

	scope, note = determineDMARCScope(false, false, "", "example.com")
	if scope != "none" {
		t.Errorf("expected none, got %q", scope)
	}
	if note == "" {
		t.Error("expected non-empty note for none")
	}
}

func TestCoverageBoost17_ComputeSubdomainEmailScope_WarningStatus(t *testing.T) {
	dns := &mockDNSQuerier{responses: map[string][]string{
		"TXT:_dmarc.example.com": {},
	}}
	results := map[string]any{
		mapKeySpfAnalysis:   map[string]any{mapKeyStatus: mapKeyWarning},
		mapKeyDmarcAnalysis: map[string]any{mapKeyStatus: mapKeyWarning},
		"basic_records":     map[string]any{"MX": []string{"mx.sub.example.com"}},
	}
	scope := computeSubdomainEmailScope(context.Background(), dns, "sub.example.com", "example.com", results)
	if scope.SPFScope != "local" {
		t.Errorf("SPFScope = %q, want local (warning is active)", scope.SPFScope)
	}
	if scope.DMARCScope != "local" {
		t.Errorf("DMARCScope = %q, want local (warning is active)", scope.DMARCScope)
	}
	if !scope.HasLocalEmail {
		t.Error("expected HasLocalEmail=true with string MX")
	}
}

// TestExtractRootDomain_IndeterminateOnBareSuffix pins the Zero-Fabrication
// contract in the always-on (untagged) suite: when the Public Suffix List
// cannot derive a registrable eTLD+1 (a bare public suffix like com/co.uk),
// extractRootDomain must surface indeterminate=true, NOT the fabricated claim
// isSubdomain=false it previously returned. Absence in the local PSL snapshot
// is not absence in the world.
func TestExtractRootDomain_IndeterminateOnBareSuffix(t *testing.T) {
	for _, domain := range []string{"com", "co.uk", "web3", "localhost"} {
		isSub, root, indeterminate := extractRootDomain(domain)
		if !indeterminate {
			t.Errorf("extractRootDomain(%q): indeterminate = false, want true (no eTLD+1 derivable)", domain)
		}
		if isSub {
			t.Errorf("extractRootDomain(%q): isSub = true, want false (meaningless under indeterminate)", domain)
		}
		if root != "" {
			t.Errorf("extractRootDomain(%q): root = %q, want empty", domain, root)
		}
	}
}

// TestExtractRootDomain_DeterminateOnNormalDomains guards the regression: a
// normal registrable domain and its subdomain must NOT be flagged
// indeterminate — the third state is only for lookups that did not complete.
func TestExtractRootDomain_DeterminateOnNormalDomains(t *testing.T) {
	cases := []struct {
		domain   string
		wantSub  bool
		wantRoot string
	}{
		{"example.com", false, ""},
		{"www.example.com", true, "example.com"},
		{"a.b.example.co.uk", true, "example.co.uk"},
	}
	for _, tc := range cases {
		isSub, root, indeterminate := extractRootDomain(tc.domain)
		if indeterminate {
			t.Errorf("extractRootDomain(%q): indeterminate = true, want false", tc.domain)
		}
		if isSub != tc.wantSub {
			t.Errorf("extractRootDomain(%q): isSub = %v, want %v", tc.domain, isSub, tc.wantSub)
		}
		if root != tc.wantRoot {
			t.Errorf("extractRootDomain(%q): root = %q, want %q", tc.domain, root, tc.wantRoot)
		}
	}
}

// TestResolveEmailScope_IndeterminateReturnsScopedNil verifies the render
// contract: when PSL is indeterminate, resolveEmailScope must return a scope
// flagged Indeterminate (so the template says "not determinable") rather than
// nil (which would render nothing) or a populated scope (a fabricated claim).
func TestResolveEmailScope_IndeterminateReturnsScopedFlag(t *testing.T) {
	h := &AnalysisHandler{}
	results := map[string]any{}
	scope := h.resolveEmailScope(context.Background(), false, "", true, "com", results)
	if scope == nil {
		t.Fatal("resolveEmailScope(indeterminate) returned nil — template would render nothing instead of 'not determinable'")
	}
	if !scope.Indeterminate {
		t.Error("scope.Indeterminate = false, want true")
	}
	if scope.IsSubdomain {
		t.Error("scope.IsSubdomain = true under indeterminate — fabricated claim")
	}
	if scope.ParentDomain != "" {
		t.Errorf("scope.ParentDomain = %q under indeterminate, want empty", scope.ParentDomain)
	}
}

// TestResolveEmailScope_BareSuffixStillAnalyzedElsewhere documents the product
// invariant the user stated: entering a root TLD like com must still produce a
// report. extractRootDomain being indeterminate does NOT gate the analysis —
// the isPublicSuffixDomain / IsTLDInput paths drive the Registry Zone Health
// view independently. This test only asserts the email-scope derivation stays
// honest; it does not suppress the report.
func TestResolveEmailScope_BareSuffixStillAnalyzedElsewhere(t *testing.T) {
	if !isPublicSuffixDomain("com") {
		t.Error("com must remain a recognized public suffix (Registry Zone Health path)")
	}
	if !isPublicSuffixDomain("co.uk") {
		t.Error("co.uk must remain a recognized public suffix (Registry Zone Health path)")
	}
	if isPublicSuffixDomain("example.com") {
		t.Error("example.com must NOT be a public suffix")
	}
}
