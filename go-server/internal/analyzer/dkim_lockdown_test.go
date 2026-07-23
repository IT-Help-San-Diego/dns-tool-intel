// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "context"
        "strings"
        "testing"
)

func TestAllDKIMKeysRevoked(t *testing.T) {
        revokedKey := map[string]any{"revoked": true}
        activeKey := map[string]any{"revoked": false}

        tests := []struct {
                name      string
                selectors map[string]map[string]any
                want      bool
        }{
                {
                        name:      "empty selector map is not a revocation",
                        selectors: map[string]map[string]any{},
                        want:      false,
                },
                {
                        name: "all keys revoked",
                        selectors: map[string]map[string]any{
                                "a._domainkey": {"key_info": []map[string]any{revokedKey}},
                                "b._domainkey": {"key_info": []map[string]any{revokedKey}},
                        },
                        want: true,
                },
                {
                        name: "mixed revoked and active",
                        selectors: map[string]map[string]any{
                                "a._domainkey": {"key_info": []map[string]any{revokedKey}},
                                "b._domainkey": {"key_info": []map[string]any{activeKey}},
                        },
                        want: false,
                },
                {
                        name: "selector without key_info is indeterminate, not revoked",
                        selectors: map[string]map[string]any{
                                "a._domainkey": {},
                        },
                        want: false,
                },
                {
                        name: "json-shaped key_info ([]any) all revoked",
                        selectors: map[string]map[string]any{
                                "a._domainkey": {"key_info": []any{map[string]any{"revoked": true}}},
                        },
                        want: true,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        if got := allDKIMKeysRevoked(tt.selectors); got != tt.want {
                                t.Errorf("allDKIMKeysRevoked() = %v, want %v", got, tt.want)
                        }
                })
        }
}

func TestHasNullMXRecords(t *testing.T) {
        tests := []struct {
                name string
                mx   []string
                want bool
        }{
                {"rfc7505 null mx", []string{"0 ."}, true},
                {"bare dot", []string{"."}, true},
                {"normal mx", []string{"10 mail.example.com."}, false},
                {"null among real (still declared)", []string{"10 mail.example.com.", "0 ."}, true},
                {"empty", nil, false},
                {"trailing space", []string{"0 . "}, true},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        if got := hasNullMXRecords(tt.mx); got != tt.want {
                                t.Errorf("hasNullMXRecords(%v) = %v, want %v", tt.mx, got, tt.want)
                        }
                })
        }
}

func TestIsSPFHardFailOnly(t *testing.T) {
        tests := []struct {
                name string
                spf  string
                want bool
        }{
                {"bare hard fail", "v=spf1 -all", true},
                {"case and whitespace tolerant", "  V=SPF1   -ALL ", true},
                {"softfail is not lockdown", "v=spf1 ~all", false},
                {"hard fail with mechanisms is a sending domain", "v=spf1 include:_spf.google.com -all", false},
                {"empty", "", false},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        if got := isSPFHardFailOnly(tt.spf); got != tt.want {
                                t.Errorf("isSPFHardFailOnly(%q) = %v, want %v", tt.spf, got, tt.want)
                        }
                })
        }
}

func TestApplyDKIMLockdownVerdict(t *testing.T) {
        tests := []struct {
                name        string
                allRevoked  bool
                wildcard    bool
                noMail      bool
                wantStatus  string
                wantContain string
        }{
                {
                        name:       "not all revoked passes through untouched",
                        allRevoked: false,
                        wantStatus: "warning",
                },
                {
                        name:        "no-mail wildcard lockdown is success",
                        allRevoked:  true,
                        wildcard:    true,
                        noMail:      true,
                        wantStatus:  "success",
                        wantContain: "RFC 6376",
                },
                {
                        name:        "no-mail enumerated revocation is success",
                        allRevoked:  true,
                        wildcard:    false,
                        noMail:      true,
                        wantStatus:  "success",
                        wantContain: "RFC 6376",
                },
                {
                        name:        "mail-sending domain with all keys revoked stays warning",
                        allRevoked:  true,
                        wildcard:    false,
                        noMail:      false,
                        wantStatus:  "warning",
                        wantContain: "revoked",
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        status, msg := applyDKIMLockdownVerdict("warning", "orig", tt.allRevoked, tt.wildcard, tt.noMail, 3)
                        if status != tt.wantStatus {
                                t.Errorf("status = %q, want %q (msg: %s)", status, tt.wantStatus, msg)
                        }
                        if !tt.allRevoked && msg != "orig" {
                                t.Errorf("message should pass through, got %q", msg)
                        }
                        if tt.wantContain != "" && !strings.Contains(msg, tt.wantContain) {
                                t.Errorf("message %q should contain %q", msg, tt.wantContain)
                        }
                })
        }
}

func TestAnalyzeDKIM_WildcardRevokedNoMailLockdown(t *testing.T) {
        mock := NewMockDNSClient()
        revoked := []string{"v=DKIM1; p="}
        mock.AddResponse("TXT", "amazonses._domainkey.example.com", revoked)
        mock.AddResponse("TXT", "barracuda._domainkey.example.com", revoked)
        mock.AddResponse("TXT", dkimWildcardProbe+".example.com", revoked)
        mock.AddResponse("TXT", "example.com", []string{"v=spf1 -all"})

        a := &Analyzer{DNS: mock}
        result := a.AnalyzeDKIM(context.Background(), "example.com", []string{"0 ."}, nil)

        if got := result["status"]; got != "success" {
                t.Errorf("status = %v, want success (message: %v)", got, result["message"])
        }
        if got := result["wildcard_dkim"]; got != true {
                t.Errorf("wildcard_dkim = %v, want true", got)
        }
        msg, _ := result["message"].(string)
        if !strings.Contains(msg, "RFC 6376") {
                t.Errorf("message should cite RFC 6376, got %q", msg)
        }
        providers, _ := result["found_providers"].([]string)
        if len(providers) != 0 {
                t.Errorf("found_providers should be suppressed for wildcard artifact, got %v", providers)
        }
        issues, _ := result["key_issues"].([]string)
        if len(issues) != 1 {
                t.Errorf("key_issues should be deduplicated under wildcard, got %d entries", len(issues))
        }
}

func TestAnalyzeDKIM_ProbeMissNoMailStillDedupesIssues(t *testing.T) {
        mock := NewMockDNSClient()
        revoked := []string{"v=DKIM1; p="}
        mock.AddResponse("TXT", "amazonses._domainkey.example.com", revoked)
        mock.AddResponse("TXT", "barracuda._domainkey.example.com", revoked)
        // No wildcard probe response: enumerated revocation, not wildcard.
        mock.AddResponse("TXT", "example.com", []string{"v=spf1 -all"})

        a := &Analyzer{DNS: mock}
        result := a.AnalyzeDKIM(context.Background(), "example.com", []string{"0 ."}, nil)

        if got := result["status"]; got != "success" {
                t.Errorf("status = %v, want success (message: %v)", got, result["message"])
        }
        if got := result["wildcard_dkim"]; got != false {
                t.Errorf("wildcard_dkim = %v, want false", got)
        }
        issues, _ := result["key_issues"].([]string)
        if len(issues) != 1 {
                t.Errorf("key_issues should be deduplicated whenever all keys are revoked, got %d entries", len(issues))
        }
        providers, _ := result["found_providers"].([]string)
        if len(providers) == 0 {
                t.Errorf("found_providers should be retained without wildcard proof, got %v", providers)
        }
}

func TestAnalyzeDKIM_AllRevokedOnMailSendingDomainStaysWarning(t *testing.T) {
        mock := NewMockDNSClient()
        mock.AddResponse("TXT", "amazonses._domainkey.example.com", []string{"v=DKIM1; p="})
        mock.AddResponse("TXT", "example.com", []string{"v=spf1 include:_spf.example.net -all"})

        a := &Analyzer{DNS: mock}
        result := a.AnalyzeDKIM(context.Background(), "example.com", []string{"10 mail.example.com."}, nil)

        if got := result["status"]; got != "warning" {
                t.Errorf("status = %v, want warning (message: %v)", got, result["message"])
        }
        msg, _ := result["message"].(string)
        if !strings.Contains(msg, "revoked") {
                t.Errorf("message should mention revocation, got %q", msg)
        }
}
