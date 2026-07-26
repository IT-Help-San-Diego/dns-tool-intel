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
	if r := owlReason(t, sem, "metacognitive"); !strings.Contains(r, "DMARC") || !strings.Contains(r, "DKIM (0.30)") {
		t.Errorf("metacognitive reason incomplete: %q", r)
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
