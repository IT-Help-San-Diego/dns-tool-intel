package handlers

import (
	"strings"
	"testing"
)

func owlPart(t *testing.T, sem map[string]any, key string) map[string]any {
	t.Helper()
	part, ok := sem[key].(map[string]any)
	if !ok {
		t.Fatalf("owl %q missing or wrong type: %#v", key, sem[key])
	}
	return part
}

func owlLit(t *testing.T, sem map[string]any, key string) bool {
	t.Helper()
	lit, ok := owlPart(t, sem, key)["lit"].(bool)
	if !ok {
		t.Fatalf("owl %q lit missing", key)
	}
	return lit
}

func owlReason(t *testing.T, sem map[string]any, key string) string {
	t.Helper()
	reason, ok := owlPart(t, sem, key)["reason"].(string)
	if !ok {
		t.Fatalf("owl %q reason missing", key)
	}
	return reason
}

func TestComputeOwlSemaphore_NilOnNoSignals(t *testing.T) {
	if got := computeOwlSemaphore(nil); got != nil {
		t.Fatalf("nil input: expected nil, got %#v", got)
	}
	if got := computeOwlSemaphore("not a map"); got != nil {
		t.Fatalf("non-map input: expected nil, got %#v", got)
	}
	if got := computeOwlSemaphore(map[string]any{}); got != nil {
		t.Fatalf("empty map: expected nil, got %#v", got)
	}
	// Signal-free results (no sections, no posture, no confidence) stay absent.
	if got := computeOwlSemaphore(map[string]any{"domain": "example.com"}); got != nil {
		t.Fatalf("signal-free results: expected nil, got %#v", got)
	}
}

func TestComputeOwlSemaphore_AllFourLit(t *testing.T) {
	results := map[string]any{
		"spf_analysis":   map[string]any{"status": "success"},
		"dkim_analysis":  map[string]any{"status": "error"},
		"dmarc_analysis": map[string]any{"status": "indeterminate"},
		"bimi_analysis":  map[string]any{"status": "info"},
		"posture": map[string]any{
			"recommendations": []any{"rec one"},
			"monitoring":      []any{"mon one", "mon two"},
			"critical_issues": []any{"crit one"},
		},
		"remediation": map[string]any{
			"all_fixes": []any{
				map[string]any{"severity_label": "Critical"},
				map[string]any{"severity_label": "Low"},
			},
		},
		"calibrated_confidence": map[string]any{"DKIM": 0.30, "SPF": 0.95},
	}
	sem := computeOwlSemaphore(results)
	if sem == nil {
		t.Fatal("expected owl semaphore, got nil")
	}
	for _, key := range []string{"normative", "non_normative", "critical", "metacognitive"} {
		if !owlLit(t, sem, key) {
			t.Errorf("owl %q should be lit", key)
		}
	}
	if r := owlReason(t, sem, "normative"); !strings.Contains(r, "SPF") {
		t.Errorf("normative reason should name SPF: %q", r)
	}
	if r := owlReason(t, sem, "non_normative"); !strings.Contains(r, "1 advisory recommendation") || !strings.Contains(r, "2 monitoring notes") || !strings.Contains(r, "BIMI") {
		t.Errorf("non_normative reason incomplete: %q", r)
	}
	if r := owlReason(t, sem, "critical"); !strings.Contains(r, "1 critical issue") || !strings.Contains(r, "DKIM") || !strings.Contains(r, "1 Critical-severity remediation fix") {
		t.Errorf("critical reason incomplete: %q", r)
	}
	// DKIM's 0.30 is a confirmed error's outcome-valenced score — certainty,
	// not doubt. It belongs to the critical owl (asserted above) and must NOT
	// appear here; DMARC's indeterminate status is the doubt signal.
	if r := owlReason(t, sem, "metacognitive"); !strings.Contains(r, "DMARC") || strings.Contains(r, "DKIM") {
		t.Errorf("metacognitive must carry DMARC's doubt and exclude DKIM's confirmed outcome: %q", r)
	}
	if c, _ := owlPart(t, sem, "critical")["count"].(int); c != 3 {
		t.Errorf("critical count: want 3, got %d", c)
	}
	if v, _ := sem["version"].(int); v != 1 {
		t.Errorf("version: want 1, got %v", sem["version"])
	}
}

func TestComputeOwlSemaphore_AllDarkWithReasons(t *testing.T) {
	// A clean scan: everything passing, confident, nothing critical or
	// advisory — only the normative owl lights.
	results := map[string]any{
		"spf_analysis":          map[string]any{"status": "success"},
		"dmarc_analysis":        map[string]any{"status": "success"},
		"posture":               map[string]any{},
		"calibrated_confidence": map[string]any{"SPF": 0.92, "DMARC": 0.88},
	}
	sem := computeOwlSemaphore(results)
	if sem == nil {
		t.Fatal("expected owl semaphore, got nil")
	}
	if !owlLit(t, sem, "normative") {
		t.Error("normative should be lit")
	}
	for _, key := range []string{"non_normative", "critical", "metacognitive"} {
		if owlLit(t, sem, key) {
			t.Errorf("owl %q should be dark", key)
		}
		if r := owlReason(t, sem, key); !strings.Contains(r, "Not triggered") {
			t.Errorf("dark owl %q needs a not-triggered reason: %q", key, r)
		}
	}
}

func TestComputeOwlSemaphore_SpoofDoorOpenLightsCritical(t *testing.T) {
	// The wearetma.com shape: High Risk, open spoofing door, but no
	// critical_issues, no error statuses, no Critical fixes — the exact scan
	// that used to leave the Critical owl dark while history showed High
	// Risk. The stored spoof_door axis is the producer; the owl reads it.
	results := map[string]any{
		"dmarc_analysis": map[string]any{"status": "warning"},
		"posture": map[string]any{
			"critical_issues": []string{},
			"spoof_door":      "open",
		},
	}
	sem := computeOwlSemaphore(results)
	if sem == nil {
		t.Fatal("expected owl semaphore, got nil")
	}
	if !owlLit(t, sem, "critical") {
		t.Fatal("critical must light when the stored spoof_door is open")
	}
	if r := owlReason(t, sem, "critical"); !strings.Contains(r, "email-spoofing door as open") {
		t.Errorf("reason must state the open-door consequence, got %q", r)
	}
}

func TestComputeOwlSemaphore_SpoofDoorGuardedOrAbsentStaysDark(t *testing.T) {
	// guarded is not open, and old scans without the key must not light —
	// honestly absent, never inferred from record presence.
	for _, posture := range []map[string]any{
		{"critical_issues": []string{}, "spoof_door": "guarded"},
		{"critical_issues": []string{}},
	} {
		results := map[string]any{
			"dmarc_analysis": map[string]any{"status": "success"},
			"posture":        posture,
		}
		sem := computeOwlSemaphore(results)
		if sem == nil {
			t.Fatal("expected owl semaphore, got nil")
		}
		if owlLit(t, sem, "critical") {
			t.Errorf("critical must stay dark for posture %v: %q", posture, owlReason(t, sem, "critical"))
		}
	}
}

func TestComputeOwlSemaphore_TriStateIndeterminateLightsMetacognitive(t *testing.T) {
	// The cia.gov shape: DANE's stored tri-state records that the lookup did
	// not complete, while the section's top-level status says something else
	// entirely — genuine doubt the status bucket cannot see.
	results := map[string]any{
		"dane_analysis": map[string]any{"status": "info", "dane_state": "indeterminate"},
	}
	sem := computeOwlSemaphore(results)
	if sem == nil {
		t.Fatal("expected owl semaphore, got nil")
	}
	if !owlLit(t, sem, "metacognitive") {
		t.Fatal("metacognitive must light on a stored indeterminate tri-state")
	}
	if r := owlReason(t, sem, "metacognitive"); !strings.Contains(r, "DANE") || !strings.Contains(r, "could not be verified") {
		t.Errorf("reason must name the unverified protocol, got %q", r)
	}
}

func TestComputeOwlSemaphore_ConfirmedBadIsNotDoubt(t *testing.T) {
	// A corroborated failure carries low calibrated confidence because the
	// raw scale is outcome-valenced — that is certainty of badness, and it
	// must not light the doubt owl.
	results := map[string]any{
		"spf_analysis":          map[string]any{"status": "error"},
		"calibrated_confidence": map[string]any{"SPF": 0.30},
	}
	sem := computeOwlSemaphore(results)
	if sem == nil {
		t.Fatal("expected owl semaphore, got nil")
	}
	if owlLit(t, sem, "metacognitive") {
		t.Errorf("metacognitive must stay dark for a confirmed outcome: %q", owlReason(t, sem, "metacognitive"))
	}
	if !owlLit(t, sem, "critical") {
		t.Error("the confirmed failure belongs to the critical owl")
	}
}

func TestComputeOwlSemaphore_LowConfidenceOnPassingStatusIsDoubt(t *testing.T) {
	// A passing status whose calibrated confidence was dragged below
	// moderate (resolver disagreement) is genuine doubt — this input stays.
	results := map[string]any{
		"spf_analysis":          map[string]any{"status": "success"},
		"calibrated_confidence": map[string]any{"SPF": 0.41},
	}
	sem := computeOwlSemaphore(results)
	if sem == nil {
		t.Fatal("expected owl semaphore, got nil")
	}
	if !owlLit(t, sem, "metacognitive") {
		t.Error("metacognitive must light when a passing finding is below moderate confidence")
	}
}

func TestComputeOwlSemaphore_ThresholdBoundary(t *testing.T) {
	// Exactly 0.50 is NOT below the moderate threshold — must not trigger.
	results := map[string]any{
		"spf_analysis":          map[string]any{"status": "success"},
		"calibrated_confidence": map[string]any{"SPF": 0.50},
	}
	sem := computeOwlSemaphore(results)
	if sem == nil {
		t.Fatal("expected owl semaphore, got nil")
	}
	if owlLit(t, sem, "metacognitive") {
		t.Errorf("metacognitive must stay dark at exactly 0.50: %q", owlReason(t, sem, "metacognitive"))
	}
}

func TestComputeOwlSemaphore_LiveShapeSlices(t *testing.T) {
	// Live (non-round-tripped) posture slices are []string and confidence is
	// map[string]float64 — the dual-shape tolerance must hold.
	results := map[string]any{
		"dkim_analysis": map[string]any{"status": "warning"},
		"posture": map[string]any{
			"recommendations": []string{"a", "b"},
			"monitoring":      []string{"c"},
			"critical_issues": []string{},
		},
		"calibrated_confidence": map[string]float64{"DKIM": 0.41},
	}
	sem := computeOwlSemaphore(results)
	if sem == nil {
		t.Fatal("expected owl semaphore, got nil")
	}
	if !owlLit(t, sem, "non_normative") {
		t.Error("non_normative should be lit from []string advisory entries")
	}
	if owlLit(t, sem, "normative") {
		t.Error("normative should be dark — warning status is not a passing status")
	}
	if owlLit(t, sem, "critical") {
		t.Error("critical should be dark — warning status is not a failed status")
	}
	if !owlLit(t, sem, "metacognitive") {
		t.Error("metacognitive should be lit from calibrated confidence 0.41")
	}
}
