package handlers

import (
	"strings"
	"testing"
	"time"
)

func TestExtractPostureRisk(t *testing.T) {
	tests := []struct {
		name      string
		results   map[string]any
		wantLabel string
		wantColor string
	}{
		{"nil results", nil, "Unknown", ""},
		{"empty results", map[string]any{}, "Unknown", ""},
		{"no posture key", map[string]any{"other": "data"}, "Unknown", ""},
		{"posture not a map", map[string]any{"posture": "string"}, "Unknown", ""},
		{"posture with label", map[string]any{"posture": map[string]any{"label": "Secure", "color": "success"}}, "Secure", "success"},
		{"posture with grade fallback", map[string]any{"posture": map[string]any{"grade": "A+", "color": "success"}}, "A+", "success"},
		{"posture with empty label uses grade", map[string]any{"posture": map[string]any{"label": "", "grade": "B", "color": "warning"}}, "B", "warning"},
		{"posture with no label or grade", map[string]any{"posture": map[string]any{"color": "danger"}}, "Unknown", "danger"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			label, color := extractPostureRisk(tt.results)
			if label != tt.wantLabel {
				t.Errorf("label = %q, want %q", label, tt.wantLabel)
			}
			if color != tt.wantColor {
				t.Errorf("color = %q, want %q", color, tt.wantColor)
			}
		})
	}
}

func TestRiskColorToHex(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"success", "#3fb950"},
		{"warning", "#d29922"},
		{"danger", "#e05d44"},
		{"unknown", "#9f9f9f"},
		{"", "#9f9f9f"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := riskColorToHex(tt.input)
			if got != tt.want {
				t.Errorf("riskColorToHex(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRiskColorToShields(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"success", "brightgreen"},
		{"warning", "yellow"},
		{"danger", "red"},
		{"other", "lightgrey"},
		{"", "lightgrey"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := riskColorToShields(tt.input)
			if got != tt.want {
				t.Errorf("riskColorToShields(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBadgeSVG(t *testing.T) {
	svg := badgeSVG("example.com", "Low Risk (90/100)", "#3fb950")
	s := string(svg)
	if !strings.Contains(s, "<svg") {
		t.Error("expected SVG element")
	}
	if !strings.Contains(s, "example.com") {
		t.Error("expected domain label in SVG")
	}
	if !strings.Contains(s, "Low Risk (90/100)") {
		t.Error("expected risk value with score in SVG")
	}
	if !strings.Contains(s, "#3fb950") {
		t.Error("expected color in SVG")
	}
	if !strings.Contains(s, `role="img"`) {
		t.Error("expected role=img attribute")
	}
}

func TestBadgeSVGCovert(t *testing.T) {
	tests := []struct {
		name       string
		domain     string
		riskLabel  string
		riskHex    string
		wantLabel  string
		wantTagline string
	}{
		{"low risk", "example.com", "Low Risk", "#3fb950", "Hardened", "Good luck with that."},
		{"high risk", "bad-domain.com", "High Risk", "#f85149", "Exposed", "Door's open."},
		{"critical risk", "awful.com", "Critical Risk", "#f85149", "Wide Open", "Free real estate."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svg := badgeSVGCovert(tt.domain, tt.riskLabel, tt.riskHex)
			s := string(svg)
			if !strings.Contains(s, "<svg") {
				t.Error("expected SVG element")
			}
			if !strings.Contains(s, tt.domain) {
				t.Errorf("expected domain %q in SVG", tt.domain)
			}
			if !strings.Contains(s, tt.wantLabel) {
				t.Errorf("expected covert label %q in SVG", tt.wantLabel)
			}
			if !strings.Contains(s, tt.wantTagline) {
				t.Errorf("expected tagline %q in SVG", tt.wantTagline)
			}
		})
	}
}

func TestBadgeSVGDetailed(t *testing.T) {
	successResults := map[string]any{
		"posture": map[string]any{
			"label": "Low Risk",
			"color": "success",
			"score": float64(90),
		},
		"spf_analysis":     map[string]any{"status": "success"},
		"dkim_analysis":    map[string]any{"status": "success"},
		"dmarc_analysis":   map[string]any{"status": "success"},
		"dnssec_analysis":  map[string]any{"status": "success"},
		"dane_analysis":    map[string]any{"status": "missing"},
		"mta_sts_analysis": map[string]any{"status": "success"},
		"tls_rpt_analysis": map[string]any{"status": "success"},
		"bimi_analysis":    map[string]any{"status": "success"},
		"caa_analysis":     map[string]any{"status": "success"},
	}

	svg := badgeSVGDetailed("it-help.tech", successResults, time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC))
	s := string(svg)

	if !strings.Contains(s, "it-help.tech") {
		t.Error("expected domain in detailed badge")
	}
	if !strings.Contains(s, "90") {
		t.Error("expected score 90 in detailed badge")
	}
	if !strings.Contains(s, "Low Risk") {
		t.Error("expected risk label in detailed badge")
	}
	if !strings.Contains(s, "#238636") {
		t.Error("expected green border color for low risk")
	}
	if !strings.Contains(s, "1 of 9 missing") {
		t.Error("expected missing count (DANE missing)")
	}
	if !strings.Contains(s, `width="460"`) {
		t.Error("expected 460px width")
	}

	failResults := map[string]any{
		"posture": map[string]any{
			"label": "Critical Risk",
			"color": "danger",
			"score": float64(10),
		},
	}

	svgFail := badgeSVGDetailed("failing-domain.com", failResults, time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC))
	sf := string(svgFail)

	if !strings.Contains(sf, "failing-domain.com") {
		t.Error("expected domain in failing badge")
	}
	if !strings.Contains(sf, "#da3633") {
		t.Error("expected red border for critical risk")
	}
	if !strings.Contains(sf, "Critical Risk") {
		t.Error("expected Critical Risk label")
	}
	if !strings.Contains(sf, "9 of 9 missing") {
		t.Error("expected all 9 protocols missing in failing badge")
	}
}

func TestRiskBorderColor(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"success", "#238636"},
		{"warning", "#9e6a03"},
		{"danger", "#da3633"},
		{"", "#30363d"},
		{"other", "#30363d"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := riskBorderColor(tt.input)
			if got != tt.want {
				t.Errorf("riskBorderColor(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestCountMissing(t *testing.T) {
	nodes := []protocolNode{
		{status: "success"},
		{status: "success"},
		{status: "missing"},
		{status: "error"},
		{status: "success"},
	}
	got := countMissing(nodes)
	if got != 2 {
		t.Errorf("countMissing() = %d, want 2", got)
	}
}

func TestCovertLabels(t *testing.T) {
	tests := []struct {
		risk       string
		wantLabel  string
		wantTag    string
	}{
		{"Low Risk", "Hardened", "Good luck with that."},
		{"Medium Risk", "Patching", "Getting there."},
		{"High Risk", "Exposed", "Door's open."},
		{"Critical Risk", "Wide Open", "Free real estate."},
	}
	for _, tt := range tests {
		t.Run(tt.risk, func(t *testing.T) {
			if got := covertRiskLabel(tt.risk); got != tt.wantLabel {
				t.Errorf("covertRiskLabel(%q) = %q, want %q", tt.risk, got, tt.wantLabel)
			}
			if got := covertTagline(tt.risk); got != tt.wantTag {
				t.Errorf("covertTagline(%q) = %q, want %q", tt.risk, got, tt.wantTag)
			}
		})
	}
}

func TestUnmarshalResults(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		isNil bool
	}{
		{"nil input", nil, true},
		{"empty input", []byte{}, true},
		{"invalid JSON", []byte("not json"), true},
		{"valid JSON", []byte(`{"key":"value"}`), false},
		{"empty object", []byte(`{}`), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := unmarshalResults(tt.input, "Test")
			if tt.isNil && got != nil {
				t.Error("expected nil")
			}
			if !tt.isNil && got == nil {
				t.Error("expected non-nil")
			}
		})
	}
}

func TestNewBadgeHandler(t *testing.T) {
	h := NewBadgeHandler(nil, nil)
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
	if h.DB != nil {
		t.Error("expected nil DB")
	}
	if h.Config != nil {
		t.Error("expected nil Config")
	}
}

func TestScoreColor(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{90, "#3fb950"},
		{80, "#3fb950"},
		{50, "#d29922"},
		{79, "#d29922"},
		{49, "#f85149"},
		{0, "#f85149"},
		{-1, "#484f58"},
	}
	for _, tt := range tests {
		t.Run(strings.Join([]string{"score", strings.TrimSpace(strings.Replace(string(rune(tt.score+'0')), "\x00", "", -1))}, "_"), func(t *testing.T) {
			got := scoreColor(tt.score)
			if got != tt.want {
				t.Errorf("scoreColor(%d) = %q, want %q", tt.score, got, tt.want)
			}
		})
	}
}

func TestExtractPostureScore(t *testing.T) {
	tests := []struct {
		name    string
		results map[string]any
		want    int
	}{
		{"nil", nil, -1},
		{"no posture", map[string]any{}, -1},
		{"valid score", map[string]any{"posture": map[string]any{"score": float64(85)}}, 85},
		{"clamped high", map[string]any{"posture": map[string]any{"score": float64(150)}}, 100},
		{"clamped low", map[string]any{"posture": map[string]any{"score": float64(-10)}}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPostureScore(tt.results)
			if got != tt.want {
				t.Errorf("extractPostureScore() = %d, want %d", got, tt.want)
			}
		})
	}
}
