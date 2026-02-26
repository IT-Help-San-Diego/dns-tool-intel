package handlers

import (
	"strings"
	"testing"
)

func TestExtractPostureRisk(t *testing.T) {
	tests := []struct {
		name       string
		results    map[string]any
		wantLabel  string
		wantColor  string
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
		{"success", "#4c1"},
		{"warning", "#dfb317"},
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
	svg := badgeSVG("DNS Tool", "Secure", "#4c1")
	s := string(svg)
	if !strings.Contains(s, "<svg") {
		t.Error("expected SVG element")
	}
	if !strings.Contains(s, "DNS Tool") {
		t.Error("expected label in SVG")
	}
	if !strings.Contains(s, "Secure") {
		t.Error("expected value in SVG")
	}
	if !strings.Contains(s, "#4c1") {
		t.Error("expected color in SVG")
	}
	if !strings.Contains(s, `role="img"`) {
		t.Error("expected role=img attribute")
	}
}

func TestBadgeSVGCovert(t *testing.T) {
	svg := badgeSVGCovert("example.com", "Secure", "#4c1")
	s := string(svg)
	if !strings.Contains(s, "<svg") {
		t.Error("expected SVG element")
	}
	if !strings.Contains(s, "example.com") {
		t.Error("expected domain in SVG")
	}
	if !strings.Contains(s, "DNS Tool // example.com") {
		t.Error("expected covert label in SVG")
	}
	if !strings.Contains(s, "Secure") {
		t.Error("expected risk label in SVG")
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
