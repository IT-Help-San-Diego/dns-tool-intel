package handlers

import (
        "encoding/json"
        "testing"
        "time"

        "dnstool/go-server/internal/dbq"

        "github.com/jackc/pgx/v5/pgtype"
)

func TestBuildHistoryItem(t *testing.T) {
        spf := "pass"
        dmarc := "fail"
        dkim := "none"
        dur := 3.14

        t.Run("all fields populated", func(t *testing.T) {
                ts := pgtype.Timestamp{Time: time.Date(2026, 3, 20, 16, 45, 0, 0, time.UTC), Valid: true}
                fullResults, _ := json.Marshal(map[string]any{"_tool_version": "v3.0.0"})

                row := dbq.DomainAnalysis{
                        ID:               10,
                        Domain:           "history.com",
                        AsciiDomain:      "history.com",
                        SpfStatus:        &spf,
                        DmarcStatus:      &dmarc,
                        DkimStatus:       &dkim,
                        AnalysisDuration: &dur,
                        CreatedAt:        ts,
                        FullResults:      fullResults,
                }

                item := buildHistoryItem(row)
                if item.ID != 10 {
                        t.Errorf("ID = %d, want 10", item.ID)
                }
                if item.Domain != "history.com" {
                        t.Errorf("Domain = %q", item.Domain)
                }
                if item.SpfStatus != "pass" {
                        t.Errorf("SpfStatus = %q", item.SpfStatus)
                }
                if item.DmarcStatus != "fail" {
                        t.Errorf("DmarcStatus = %q", item.DmarcStatus)
                }
                if item.DkimStatus != "none" {
                        t.Errorf("DkimStatus = %q", item.DkimStatus)
                }
                if item.AnalysisDuration != 3.14 {
                        t.Errorf("AnalysisDuration = %f", item.AnalysisDuration)
                }
                if item.CreatedDate != "20 Mar 2026" {
                        t.Errorf("CreatedDate = %q", item.CreatedDate)
                }
                if item.CreatedTime != "16:45 UTC" {
                        t.Errorf("CreatedTime = %q", item.CreatedTime)
                }
                if item.ToolVersion != "v3.0.0" {
                        t.Errorf("ToolVersion = %q", item.ToolVersion)
                }
        })

        t.Run("nil fields", func(t *testing.T) {
                row := dbq.DomainAnalysis{
                        ID:          5,
                        Domain:      "nil.com",
                        AsciiDomain: "nil.com",
                        CreatedAt:   pgtype.Timestamp{Valid: false},
                }

                item := buildHistoryItem(row)
                if item.SpfStatus != "" {
                        t.Errorf("SpfStatus = %q, want empty", item.SpfStatus)
                }
                if item.DmarcStatus != "" {
                        t.Errorf("DmarcStatus = %q, want empty", item.DmarcStatus)
                }
                if item.DkimStatus != "" {
                        t.Errorf("DkimStatus = %q, want empty", item.DkimStatus)
                }
                if item.AnalysisDuration != 0.0 {
                        t.Errorf("AnalysisDuration = %f, want 0", item.AnalysisDuration)
                }
                if item.CreatedDate != "" {
                        t.Errorf("CreatedDate = %q, want empty", item.CreatedDate)
                }
                if item.CreatedTime != "" {
                        t.Errorf("CreatedTime = %q, want empty", item.CreatedTime)
                }
                if item.ToolVersion != "" {
                        t.Errorf("ToolVersion = %q, want empty", item.ToolVersion)
                }
        })

        t.Run("full_results without tool version", func(t *testing.T) {
                fullResults, _ := json.Marshal(map[string]any{"other_key": "value"})
                row := dbq.DomainAnalysis{
                        ID:          6,
                        Domain:      "notool.com",
                        AsciiDomain: "notool.com",
                        FullResults: fullResults,
                }
                item := buildHistoryItem(row)
                if item.ToolVersion != "" {
                        t.Errorf("ToolVersion = %q, want empty", item.ToolVersion)
                }
        })

        t.Run("invalid json in full_results", func(t *testing.T) {
                row := dbq.DomainAnalysis{
                        ID:          7,
                        Domain:      "bad.com",
                        AsciiDomain: "bad.com",
                        FullResults: json.RawMessage(`{invalid`),
                }
                item := buildHistoryItem(row)
                if item.ToolVersion != "" {
                        t.Errorf("ToolVersion = %q, want empty for invalid JSON", item.ToolVersion)
                }
        })
}

func TestBuildHistoryItemToolVersionWrongType(t *testing.T) {
        fullResults, _ := json.Marshal(map[string]any{"_tool_version": 123})
        row := dbq.DomainAnalysis{
                ID:          8,
                Domain:      "wrongtype.com",
                AsciiDomain: "wrongtype.com",
                FullResults: fullResults,
        }
        item := buildHistoryItem(row)
        if item.ToolVersion != "" {
                t.Errorf("ToolVersion = %q, want empty for non-string _tool_version", item.ToolVersion)
        }
}

func TestBuildHistoryItemEmptyFullResults(t *testing.T) {
        row := dbq.DomainAnalysis{
                ID:          9,
                Domain:      "empty.com",
                AsciiDomain: "empty.com",
                FullResults: json.RawMessage(``),
        }
        item := buildHistoryItem(row)
        if item.ToolVersion != "" {
                t.Errorf("ToolVersion = %q, want empty", item.ToolVersion)
        }
}

func TestBuildHistoryItemPartialFields(t *testing.T) {
        spf := "pass"
        row := dbq.DomainAnalysis{
                ID:          10,
                Domain:      "partial.com",
                AsciiDomain: "partial.com",
                SpfStatus:   &spf,
                CreatedAt:   pgtype.Timestamp{Time: time.Date(2026, 12, 31, 23, 59, 0, 0, time.UTC), Valid: true},
        }
        item := buildHistoryItem(row)
        if item.SpfStatus != "pass" {
                t.Errorf("SpfStatus = %q, want pass", item.SpfStatus)
        }
        if item.DmarcStatus != "" {
                t.Errorf("DmarcStatus = %q, want empty", item.DmarcStatus)
        }
        if item.DkimStatus != "" {
                t.Errorf("DkimStatus = %q, want empty", item.DkimStatus)
        }
        if item.CreatedDate != "31 Dec 2026" {
                t.Errorf("CreatedDate = %q", item.CreatedDate)
        }
        if item.CreatedTime != "23:59 UTC" {
                t.Errorf("CreatedTime = %q", item.CreatedTime)
        }
        if item.AnalysisDuration != 0.0 {
                t.Errorf("AnalysisDuration = %f, want 0", item.AnalysisDuration)
        }
}

func TestBuildHistoryItemAsciiDomain(t *testing.T) {
        row := dbq.DomainAnalysis{
                ID:          11,
                Domain:      "münchen.de",
                AsciiDomain: "xn--mnchen-3ya.de",
        }
        item := buildHistoryItem(row)
        if item.Domain != "münchen.de" {
                t.Errorf("Domain = %q", item.Domain)
        }
        if item.AsciiDomain != "xn--mnchen-3ya.de" {
                t.Errorf("AsciiDomain = %q", item.AsciiDomain)
        }
}

func TestHistoryConstants(t *testing.T) {
        if templateHistory != "history.html" {
                t.Errorf("unexpected templateHistory: %q", templateHistory)
        }
        if mapKeyHistory != "history" {
                t.Errorf("unexpected mapKeyHistory: %q", mapKeyHistory)
        }
}

func TestNormalizeRiskColor(t *testing.T) {
        cases := map[string]string{
                "success":     "success",
                "info":        "info",
                "warning":     "warning",
                "danger":      "danger",
                "":            "secondary",
                "primary":     "secondary",
                "bg-danger":   "secondary",
                "danger fw-1": "secondary",
                "DANGER":      "secondary",
        }
        for in, want := range cases {
                if got := normalizeRiskColor(in); got != want {
                        t.Errorf("normalizeRiskColor(%q) = %q, want %q", in, got, want)
                }
        }
}

func TestBuildHistoryItemPosture(t *testing.T) {
        t.Run("valid posture state and color", func(t *testing.T) {
                fr, _ := json.Marshal(map[string]any{
                        "posture": map[string]any{"state": "High Risk", "color": "warning"},
                })
                item := buildHistoryItem(dbq.DomainAnalysis{ID: 1, Domain: "a.com", AsciiDomain: "a.com", FullResults: fr})
                if item.RiskLevel != "High Risk" {
                        t.Errorf("RiskLevel = %q, want High Risk", item.RiskLevel)
                }
                if item.RiskColor != "warning" {
                        t.Errorf("RiskColor = %q, want warning", item.RiskColor)
                }
        })

        t.Run("recommendations-only fix count is amber", func(t *testing.T) {
                fr, _ := json.Marshal(map[string]any{
                        "posture": map[string]any{
                                "state":           "High Risk",
                                "color":           "warning",
                                "critical_issues": []any{},
                                "recommendations": []any{"upgrade DMARC to reject", "add DMARC reporting"},
                        },
                })
                item := buildHistoryItem(dbq.DomainAnalysis{ID: 5, Domain: "e.com", AsciiDomain: "e.com", FullResults: fr})
                if item.FixCount != 2 {
                        t.Errorf("FixCount = %d, want 2", item.FixCount)
                }
                if item.FixColor != "warning" {
                        t.Errorf("FixColor = %q, want warning", item.FixColor)
                }
        })

        t.Run("critical issues make fix count red and include recommendations", func(t *testing.T) {
                fr, _ := json.Marshal(map[string]any{
                        "posture": map[string]any{
                                "state":           "High Risk",
                                "color":           "danger",
                                "critical_issues": []any{"DNSSEC validation is failing"},
                                "recommendations": []any{"upgrade DMARC to reject"},
                        },
                })
                item := buildHistoryItem(dbq.DomainAnalysis{ID: 6, Domain: "f.com", AsciiDomain: "f.com", FullResults: fr})
                if item.FixCount != 2 {
                        t.Errorf("FixCount = %d, want 2", item.FixCount)
                }
                if item.FixColor != "danger" {
                        t.Errorf("FixColor = %q, want danger", item.FixColor)
                }
        })

        t.Run("no findings yields zero fix count and no color", func(t *testing.T) {
                fr, _ := json.Marshal(map[string]any{
                        "posture": map[string]any{"state": "Low Risk", "color": "success"},
                })
                item := buildHistoryItem(dbq.DomainAnalysis{ID: 7, Domain: "g.com", AsciiDomain: "g.com", FullResults: fr})
                if item.FixCount != 0 {
                        t.Errorf("FixCount = %d, want 0", item.FixCount)
                }
                if item.FixColor != "" {
                        t.Errorf("FixColor = %q, want empty", item.FixColor)
                }
        })

        t.Run("wrong-typed finding fields degrade to zero without panic", func(t *testing.T) {
                fr, _ := json.Marshal(map[string]any{
                        "posture": map[string]any{
                                "state":           "High Risk",
                                "color":           "warning",
                                "critical_issues": "bad",
                                "recommendations": 5,
                        },
                })
                item := buildHistoryItem(dbq.DomainAnalysis{ID: 8, Domain: "h.com", AsciiDomain: "h.com", FullResults: fr})
                if item.FixCount != 0 {
                        t.Errorf("FixCount = %d, want 0", item.FixCount)
                }
                if item.FixColor != "" {
                        t.Errorf("FixColor = %q, want empty", item.FixColor)
                }
                if item.RiskLevel != "High Risk" {
                        t.Errorf("RiskLevel = %q, want High Risk", item.RiskLevel)
                }
        })

        t.Run("invalid color falls back to secondary", func(t *testing.T) {
                fr, _ := json.Marshal(map[string]any{
                        "posture": map[string]any{"state": "Low Risk", "color": "bg-evil x"},
                })
                item := buildHistoryItem(dbq.DomainAnalysis{ID: 2, Domain: "b.com", AsciiDomain: "b.com", FullResults: fr})
                if item.RiskLevel != "Low Risk" {
                        t.Errorf("RiskLevel = %q, want Low Risk", item.RiskLevel)
                }
                if item.RiskColor != "secondary" {
                        t.Errorf("RiskColor = %q, want secondary", item.RiskColor)
                }
        })

        t.Run("missing posture leaves fields empty", func(t *testing.T) {
                fr, _ := json.Marshal(map[string]any{"_tool_version": "v1.0.0"})
                item := buildHistoryItem(dbq.DomainAnalysis{ID: 3, Domain: "c.com", AsciiDomain: "c.com", FullResults: fr})
                if item.RiskLevel != "" {
                        t.Errorf("RiskLevel = %q, want empty", item.RiskLevel)
                }
                if item.RiskColor != "" {
                        t.Errorf("RiskColor = %q, want empty", item.RiskColor)
                }
        })

        t.Run("monitoring-suffixed state preserved verbatim", func(t *testing.T) {
                fr, _ := json.Marshal(map[string]any{
                        "posture": map[string]any{"state": "Low Risk · Monitoring", "color": "success"},
                })
                item := buildHistoryItem(dbq.DomainAnalysis{ID: 4, Domain: "d.com", AsciiDomain: "d.com", FullResults: fr})
                if item.RiskLevel != "Low Risk · Monitoring" {
                        t.Errorf("RiskLevel = %q, want monitoring-suffixed", item.RiskLevel)
                }
        })
}

func TestBuildHistoryItemICSAECount(t *testing.T) {
        t.Run("icsae evaluation drives count and overrides posture", func(t *testing.T) {
                fr, _ := json.Marshal(map[string]any{
                        "posture": map[string]any{
                                "state":           "High Risk",
                                "color":           "danger",
                                "critical_issues": []any{"a", "b", "c"},
                                "recommendations": []any{"d", "e"},
                        },
                        "icsae_evaluation": map[string]any{
                                "high_failures":   []any{"DMARC_ENFORCEMENT"},
                                "medium_failures": []any{"SPF_EFFECTIVE_POLICY", "CAA_RESTRICTION_PRESENT"},
                                "low_failures":    []any{"BIMI_CONFIGURED", "SECURITY_TXT_PRESENT"},
                        },
                })
                item := buildHistoryItem(dbq.DomainAnalysis{ID: 20, Domain: "i.com", AsciiDomain: "i.com", FullResults: fr})
                if item.FixCount != 3 {
                        t.Errorf("FixCount = %d, want 3 (high+medium, low excluded from headline)", item.FixCount)
                }
                if item.FixColor != "danger" {
                        t.Errorf("FixColor = %q, want danger (a high failure present)", item.FixColor)
                }
        })

        t.Run("medium-only failures are amber", func(t *testing.T) {
                fr, _ := json.Marshal(map[string]any{
                        "icsae_evaluation": map[string]any{
                                "high_failures":   []any{},
                                "medium_failures": []any{"DKIM_PRESENT"},
                                "low_failures":    []any{"DANE_DEPLOYED"},
                        },
                })
                item := buildHistoryItem(dbq.DomainAnalysis{ID: 21, Domain: "j.com", AsciiDomain: "j.com", FullResults: fr})
                if item.FixCount != 1 {
                        t.Errorf("FixCount = %d, want 1", item.FixCount)
                }
                if item.FixColor != "warning" {
                        t.Errorf("FixColor = %q, want warning", item.FixColor)
                }
        })

        t.Run("low-only failures yield zero headline count and no color", func(t *testing.T) {
                fr, _ := json.Marshal(map[string]any{
                        "icsae_evaluation": map[string]any{
                                "high_failures":   []any{},
                                "medium_failures": []any{},
                                "low_failures":    []any{"HTTPS_SVCB_MODERN", "BIMI_CONFIGURED"},
                        },
                })
                item := buildHistoryItem(dbq.DomainAnalysis{ID: 22, Domain: "k.com", AsciiDomain: "k.com", FullResults: fr})
                if item.FixCount != 0 {
                        t.Errorf("FixCount = %d, want 0 (low excluded from headline)", item.FixCount)
                }
                if item.FixColor != "" {
                        t.Errorf("FixColor = %q, want empty", item.FixColor)
                }
        })

        t.Run("absent icsae evaluation falls back to posture", func(t *testing.T) {
                fr, _ := json.Marshal(map[string]any{
                        "posture": map[string]any{
                                "state":           "High Risk",
                                "color":           "warning",
                                "critical_issues": []any{},
                                "recommendations": []any{"upgrade DMARC to reject", "add DMARC reporting"},
                        },
                })
                item := buildHistoryItem(dbq.DomainAnalysis{ID: 23, Domain: "l.com", AsciiDomain: "l.com", FullResults: fr})
                if item.FixCount != 2 {
                        t.Errorf("FixCount = %d, want 2 (posture fallback)", item.FixCount)
                }
                if item.FixColor != "warning" {
                        t.Errorf("FixColor = %q, want warning", item.FixColor)
                }
        })
}
