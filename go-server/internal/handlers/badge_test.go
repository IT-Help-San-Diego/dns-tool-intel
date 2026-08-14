package handlers

import (
	"dnstool/go-server/internal/handlers/badgepkg"
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
                {"nil results", nil, "Indeterminate", ""},
                {"empty results", map[string]any{}, "Indeterminate", ""},
                {"no posture key", map[string]any{"other": "data"}, "Indeterminate", ""},
                {"posture not a map", map[string]any{"posture": "string"}, "Indeterminate", ""},
                {"posture with label", map[string]any{"posture": map[string]any{"label": "Secure", "color": "success"}}, "Secure", "success"},
                {"posture with grade fallback", map[string]any{"posture": map[string]any{"grade": "A+", "color": "success"}}, "A+", "success"},
                {"posture with empty label uses grade", map[string]any{"posture": map[string]any{"label": "", "grade": "B", "color": "warning"}}, "B", "warning"},
                {"posture with no label or grade", map[string]any{"posture": map[string]any{"color": "danger"}}, "Indeterminate", "danger"},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        label, color := badgepkg.ExtractPostureRisk(tt.results)
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
                        got := badgepkg.RiskColorToHex(tt.input)
                        if got != tt.want {
                                t.Errorf("badgepkg.RiskColorToHex(%q) = %q, want %q", tt.input, got, tt.want)
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
                        got := badgepkg.RiskColorToShields(tt.input)
                        if got != tt.want {
                                t.Errorf("badgepkg.RiskColorToShields(%q) = %q, want %q", tt.input, got, tt.want)
                        }
                })
        }
}

func TestBadgeSVG(t *testing.T) {
        svg := badgepkg.BadgeSVG("example.com", "Low Risk (90/100)", "#3fb950")
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
        lowRiskResults := map[string]any{
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
                "tlsrpt_analysis": map[string]any{"status": "success"},
                "bimi_analysis":    map[string]any{"status": "success"},
                "caa_analysis":     map[string]any{"status": "success"},
        }

        svg := badgepkg.BadgeSVGCovert("example.com", lowRiskResults, time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC), 42, "abcd1234efgh5678", "https://dnstool.it-help.tech")
        s := string(svg)

        if !strings.Contains(s, "<svg") {
                t.Error("expected SVG element")
        }
        if !strings.Contains(s, "example.com") {
                t.Error("expected domain in SVG")
        }
        if !strings.Contains(s, "Hardened") {
                t.Error("expected covert label 'Hardened'")
        }
        if !strings.Contains(s, "Good luck with that.") {
                t.Error("expected tagline")
        }
        if !strings.Contains(s, "can't forge sender envelope") {
                t.Error("expected SPF hacker perspective line")
        }
        if !strings.Contains(s, "TLS downgrade possible") {
                t.Error("expected DANE missing hacker perspective")
        }
        if !strings.Contains(s, "kali") {
                t.Error("expected Kali terminal prompt")
        }

        critResults := map[string]any{
                "posture": map[string]any{
                        "label": "Critical Risk",
                        "color": "danger",
                        "score": float64(10),
                },
        }

        svgCrit := badgepkg.BadgeSVGCovert("failing.com", critResults, time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC), 99, "deadbeef12345678", "https://dnstool.it-help.tech")
        sc := string(svgCrit)

        if !strings.Contains(sc, "Wide Open") {
                t.Error("expected 'Wide Open' for critical risk")
        }
        if !strings.Contains(sc, "Free real estate.") {
                t.Error("expected critical tagline")
        }
        if !strings.Contains(sc, "9 of 10 attack vectors") {
                t.Error("expected 9 of 10 attack vectors for all-missing critical (Web3 defaults to info)")
        }

        warnResults := map[string]any{
                "posture": map[string]any{
                        "label": "Medium Risk",
                        "color": "warning",
                        "score": float64(50),
                },
                "spf_analysis":     map[string]any{"status": "success"},
                "dkim_analysis":    map[string]any{"status": "success"},
                "dmarc_analysis":   map[string]any{"status": "warning"},
                "dnssec_analysis":  map[string]any{"status": "warning"},
                "dane_analysis":    map[string]any{"status": "success"},
                "mta_sts_analysis": map[string]any{"status": "warning"},
                "tlsrpt_analysis":  map[string]any{"status": "missing"},
                "bimi_analysis":    map[string]any{"status": "warning"},
                "caa_analysis":     map[string]any{"status": "success"},
        }
        svgWarn := badgepkg.BadgeSVGCovert("mixed.com", warnResults, time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC), 77, "face0ff0babe1234", "https://dnstool.it-help.tech")
        sw := string(svgWarn)

        if !strings.Contains(sw, "[~]") {
                t.Error("expected [~] prefix for warning protocols")
        }
        if !strings.Contains(sw, "monitoring only") {
                t.Error("expected DMARC warning text 'monitoring only'")
        }
        if !strings.Contains(sw, "partial") {
                t.Error("expected DNSSEC warning text 'partial'")
        }
        if !strings.Contains(sw, "testing mode") {
                t.Error("expected MTA-STS warning text 'testing mode'")
        }
        if !strings.Contains(sw, "no VMC cert") {
                t.Error("expected BIMI warning text 'no VMC cert'")
        }
        if !strings.Contains(sw, "no transport monitoring") {
                t.Error("expected TLS-RPT missing text")
        }

        exposedResults := map[string]any{
                "posture": map[string]any{
                        "label": "Medium Risk",
                        "color": "warning",
                        "score": float64(50),
                },
                "spf_analysis":    map[string]any{"status": "success"},
                "dkim_analysis":   map[string]any{"status": "success"},
                "dmarc_analysis":  map[string]any{"status": "warning"},
                "dnssec_analysis": map[string]any{"status": "warning"},
                "dane_analysis":   map[string]any{"status": "success"},
                "secret_exposure": map[string]any{
                        "status":        "exposed",
                        "finding_count": float64(1),
                        "findings": []any{
                                map[string]any{
                                        "type":       "Google API Key",
                                        "severity":   "high",
                                        "redacted":   "AIza********17C8",
                                        "confidence": "high",
                                },
                        },
                },
        }
        svgExp := badgepkg.BadgeSVGCovert("exposed.com", exposedResults, time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC), 55, "cafebabe90ab1234", "https://dnstool.it-help.tech")
        se := string(svgExp)

        if !strings.Contains(se, "[!!]") {
                t.Error("expected [!!] prefix for exposed secrets")
        }
        if !strings.Contains(se, "SECRET EXPOSURE") {
                t.Error("expected SECRET EXPOSURE heading")
        }
        if !strings.Contains(se, "Google API Key") {
                t.Error("expected Google API Key finding type")
        }
        if !strings.Contains(se, "AIza") {
                t.Error("expected redacted key value")
        }
        if !strings.Contains(se, "credential") {
                t.Error("expected credential reference in exposure heading")
        }
}

func TestBadgeSVGDetailedExposure(t *testing.T) {
        exposedResults := map[string]any{
                "posture": map[string]any{
                        "label": "Medium Risk",
                        "color": "warning",
                        "score": float64(50),
                },
                "spf_analysis":  map[string]any{"status": "success"},
                "dkim_analysis": map[string]any{"status": "success"},
                "secret_exposure": map[string]any{
                        "status":        "exposed",
                        "finding_count": float64(2),
                        "findings": []any{
                                map[string]any{"type": "AWS Access Key", "severity": "critical", "redacted": "AKIA****ABCD"},
                                map[string]any{"type": "Stripe Key", "severity": "high", "redacted": "sk_live****wxyz"},
                        },
                },
        }
        svg := badgepkg.BadgeSVGDetailed("leaky.com", exposedResults, time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC), 42, "abc12345", "https://dnstool.it-help.tech")
        s := string(svg)

        if !strings.Contains(s, "secrets exposed") {
                t.Error("expected exposure warning in detailed badge")
        }
        if !strings.Contains(s, `height="260"`) {
                t.Error("expected 260px height when exposure is present")
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
                "tlsrpt_analysis": map[string]any{"status": "success"},
                "bimi_analysis":    map[string]any{"status": "success"},
                "caa_analysis":     map[string]any{"status": "success"},
                "web3_analysis":    map[string]any{"detected": false},
        }

        svg := badgepkg.BadgeSVGDetailed("it-help.tech", successResults, time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC), 99, "f2c73519", "https://dnstool.it-help.tech")
        s := string(svg)

        if !strings.Contains(s, "it-help.tech") {
                t.Error("expected domain in detailed badge")
        }
        if !strings.Contains(s, "owlGlow") {
                t.Error("expected owl glow gradient in detailed badge")
        }
        if !strings.Contains(s, "AUTH") || !strings.Contains(s, "TRANSPORT") || !strings.Contains(s, "DNS") {
                t.Error("expected AUTH/TRANSPORT/DNS lane labels in detailed badge")
        }
        if !strings.Contains(s, "ICIE") {
                t.Error("expected ICIE analysis engine node in detailed badge")
        }
        if !strings.Contains(s, "Resolvers") {
                t.Error("expected DNS Resolvers node in detailed badge")
        }
        if !strings.Contains(s, "alignment") {
                t.Error("expected 'alignment' edge label in detailed badge")
        }
        if !strings.Contains(s, "p=quarantine+") {
                t.Error("expected 'p=quarantine+' edge label (BIMI→DMARC)")
        }
        if !strings.Contains(s, "requires") {
                t.Error("expected 'requires' edge label (DANE→DNSSEC)")
        }
        if !strings.Contains(s, "strengthens") {
                t.Error("expected 'strengthens' edge label (CAA→DNSSEC)")
        }
        if !strings.Contains(s, "reports") {
                t.Error("expected 'reports' edge label (TLS-RPT→MTA-STS/DANE)")
        }
        if !strings.Contains(s, "Low Risk") {
                t.Error("expected risk label in detailed badge")
        }
        if !strings.Contains(s, "#238636") {
                t.Error("expected green border color for low risk")
        }
        if !strings.Contains(s, "1/10 controls missing") {
                t.Error("expected missing count (DANE missing, Web3 defaults to info)")
        }
        if !strings.Contains(s, `width="800"`) {
                t.Error("expected 800px rendered width (600 viewBox * 4/3 scale)")
        }

        failResults := map[string]any{
                "posture": map[string]any{
                        "label": "Critical Risk",
                        "color": "danger",
                        "score": float64(10),
                },
        }

        svgFail := badgepkg.BadgeSVGDetailed("failing-domain.com", failResults, time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC), 1, "deadbeef", "https://dnstool.it-help.tech")
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
        if !strings.Contains(sf, "9/10 controls missing") {
                t.Error("expected 9 of 10 protocols missing in failing badge (Web3 defaults to info)")
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
                        got := badgepkg.RiskBorderColor(tt.input)
                        if got != tt.want {
                                t.Errorf("badgepkg.RiskBorderColor(%q) = %q, want %q", tt.input, got, tt.want)
                        }
                })
        }
}

func TestCountMissing(t *testing.T) {
        nodes := []badgepkg.ProtocolNode{
                {Status: "success"},
                {Status: "success"},
                {Status: "missing"},
                {Status: "error"},
                {Status: "success"},
        }
        got := badgepkg.CountMissing(nodes)
        if got != 2 {
                t.Errorf("badgepkg.CountMissing() = %d, want 2", got)
        }
}

// Covert copy is keyed on the grade COLOUR (the operational-consequence
// channel), so the words can never contradict the colour rendered on the same
// badge line: a Medium Risk p=none domain (colour danger) reads "Exposed",
// and a guarded High Risk (colour warning) reads "Partial".
func TestCovertLabels(t *testing.T) {
        tests := []struct {
                name       string
                color      string
                risk       string
                wantLabel  string
                wantTag    string
        }{
                {"low", "success", "Low Risk", "Hardened", "Good luck with that."},
                {"guarded medium", "warning", "Medium Risk", "Partial", "Gaps in the armor."},
                {"guarded high (dmarc-only enforcing)", "warning", "High Risk", "Partial", "Gaps in the armor."},
                {"open medium (p=none with rua)", "danger", "Medium Risk", "Exposed", "Door's open."},
                {"open high (no spf, p=none)", "danger", "High Risk", "Exposed", "Door's open."},
                {"critical", "danger", "Critical Risk", "Wide Open", "Free real estate."},
                {"info tier", "info", "Medium Risk", "Partial", "Gaps in the armor."},
                {"indeterminate: no verdict invented", "secondary", "Medium Risk", "Medium Risk", ""},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        if got := badgepkg.CovertRiskLabel(tt.color, tt.risk); got != tt.wantLabel {
                                t.Errorf("badgepkg.CovertRiskLabel(%q, %q) = %q, want %q", tt.color, tt.risk, got, tt.wantLabel)
                        }
                        if got := badgepkg.CovertTagline(tt.color, tt.risk); got != tt.wantTag {
                                t.Errorf("badgepkg.CovertTagline(%q, %q) = %q, want %q", tt.color, tt.risk, got, tt.wantTag)
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
                        got := badgepkg.UnmarshalResults(tt.input, "Test")
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
        h := badgepkg.NewBadgeHandler(nil, nil, nil)
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
                        got := badgepkg.ScoreColor(tt.score)
                        if got != tt.want {
                                t.Errorf("badgepkg.ScoreColor(%d) = %q, want %q", tt.score, got, tt.want)
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
                        got := badgepkg.ExtractPostureScore(tt.results)
                        if got != tt.want {
                                t.Errorf("badgepkg.ExtractPostureScore() = %d, want %d", got, tt.want)
                        }
                })
        }
}

func TestExtractUnmeasurableCount(t *testing.T) {
        tests := []struct {
                name    string
                results map[string]any
                want    int
        }{
                {"nil", nil, 0},
                {"no posture", map[string]any{}, 0},
                {"posture without unmeasurable", map[string]any{"posture": map[string]any{"score": float64(90)}}, 0},
                {"unmeasurable as []string", map[string]any{"posture": map[string]any{"unmeasurable": []string{"DKIM", "DANE"}}}, 2},
                {"unmeasurable as []any (JSON round-trip)", map[string]any{"posture": map[string]any{"unmeasurable": []any{"DKIM", "DANE", "BIMI"}}}, 3},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := badgepkg.ExtractUnmeasurableCount(tt.results)
                        if got != tt.want {
                                t.Errorf("badgepkg.ExtractUnmeasurableCount() = %d, want %d", got, tt.want)
                        }
                })
        }
}
