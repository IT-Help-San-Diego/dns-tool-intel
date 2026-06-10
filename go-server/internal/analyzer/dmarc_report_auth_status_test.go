// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "context"
        "testing"

        "dnstool/go-server/internal/dnsclient"
)

// statusMockDNS embeds MockDNSClient to satisfy the full DNSQuerier interface
// and adds the optional QueryDNSWithStatus capability, so tests can drive the
// three-state DMARC external-reporting auth check WITHOUT touching the network.
type statusMockDNS struct {
        MockDNSClient
        records map[string][]string
        status  map[string]dnsclient.LookupStatus
}

func (m *statusMockDNS) QueryDNS(_ context.Context, _, domain string) []string {
        return m.records[domain]
}

func (m *statusMockDNS) QueryDNSWithStatus(_ context.Context, _, domain string) ([]string, dnsclient.LookupStatus) {
        return m.records[domain], m.status[domain]
}

func TestValidateDMARCExternalAuth_ThreeStates(t *testing.T) {
        const (
                domain     = "example.com"
                extDomain  = "ext.com"
                authDomain = "example.com._report._dmarc.ext.com"
        )
        dmarcData := map[string]any{"rua": "mailto:reports@ext.com"}

        tests := []struct {
                name           string
                records        []string
                status         dnsclient.LookupStatus
                wantTopStatus  string
                wantState      string
                wantAuthorized bool
                wantIssues     int
                wantNotices    int
        }{
                {
                        name:           "resolved with DMARC record is authorized",
                        records:        []string{"v=DMARC1;"},
                        status:         dnsclient.LookupResolved,
                        wantTopStatus:  "success",
                        wantState:      reportAuthAuthorized,
                        wantAuthorized: true,
                        wantIssues:     0,
                        wantNotices:    0,
                },
                {
                        name:           "authoritative absence is unauthorized (a real finding)",
                        records:        nil,
                        status:         dnsclient.LookupAbsent,
                        wantTopStatus:  "warning",
                        wantState:      reportAuthUnauthorized,
                        wantAuthorized: false,
                        wantIssues:     1,
                        wantNotices:    0,
                },
                {
                        // The core fix: a transient lookup failure must NOT be reported as
                        // "unauthorized" — that was the on/off flapping false negative.
                        name:           "transient lookup failure is indeterminate, not a finding",
                        records:        nil,
                        status:         dnsclient.LookupError,
                        wantTopStatus:  reportAuthIndeterminate,
                        wantState:      reportAuthIndeterminate,
                        wantAuthorized: false,
                        wantIssues:     0,
                        wantNotices:    1,
                },
                {
                        name:           "resolved but no DMARC record is unauthorized",
                        records:        []string{"some other txt"},
                        status:         dnsclient.LookupResolved,
                        wantTopStatus:  "warning",
                        wantState:      reportAuthUnauthorized,
                        wantAuthorized: false,
                        wantIssues:     1,
                        wantNotices:    0,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        a := &Analyzer{DNS: &statusMockDNS{
                                records: map[string][]string{authDomain: tt.records},
                                status:  map[string]dnsclient.LookupStatus{authDomain: tt.status},
                        }}

                        result := a.ValidateDMARCExternalAuth(context.Background(), domain, dmarcData)

                        if got := result["status"]; got != tt.wantTopStatus {
                                t.Errorf("top status = %v, want %v", got, tt.wantTopStatus)
                        }
                        if got, _ := result["issues"].([]string); len(got) != tt.wantIssues {
                                t.Errorf("issues = %d (%v), want %d", len(got), got, tt.wantIssues)
                        }
                        if got, _ := result["notices"].([]string); len(got) != tt.wantNotices {
                                t.Errorf("notices = %d (%v), want %d", len(got), got, tt.wantNotices)
                        }

                        eds, _ := result["external_domains"].([]map[string]any)
                        if len(eds) != 1 {
                                t.Fatalf("external_domains = %d, want 1", len(eds))
                        }
                        ed := eds[0]
                        if got := ed["auth_state"]; got != tt.wantState {
                                t.Errorf("auth_state = %v, want %v", got, tt.wantState)
                        }
                        if got, _ := ed["authorized"].(bool); got != tt.wantAuthorized {
                                t.Errorf("authorized = %v, want %v", got, tt.wantAuthorized)
                        }
                })
        }
}

// TestResolveReportAuth_RetriesOnlyIndeterminate proves indeterminate lookups are
// retried (up to the cap) while a definitive answer stops immediately.
func TestResolveReportAuth_RetriesOnlyIndeterminate(t *testing.T) {
        t.Run("retries then succeeds", func(t *testing.T) {
                m := &countingStatusDNS{failuresBeforeSuccess: 2, successRecords: []string{"v=DMARC1;"}}
                a := &Analyzer{DNS: m}
                records, status := a.resolveReportAuth(context.Background(), "d._report._dmarc.ext.com")
                if status != dnsclient.LookupResolved || len(records) != 1 {
                        t.Fatalf("got status=%d records=%v, want resolved with 1 record", status, records)
                }
                if m.calls != 3 {
                        t.Errorf("calls = %d, want 3 (2 transient failures + 1 success)", m.calls)
                }
        })

        t.Run("definitive absence does not retry", func(t *testing.T) {
                m := &countingStatusDNS{absent: true}
                a := &Analyzer{DNS: m}
                _, status := a.resolveReportAuth(context.Background(), "d._report._dmarc.ext.com")
                if status != dnsclient.LookupAbsent {
                        t.Fatalf("status = %d, want absent", status)
                }
                if m.calls != 1 {
                        t.Errorf("calls = %d, want 1 (no retry on definitive answer)", m.calls)
                }
        })

        t.Run("persistent failure stops at cap", func(t *testing.T) {
                m := &countingStatusDNS{failuresBeforeSuccess: 99}
                a := &Analyzer{DNS: m}
                _, status := a.resolveReportAuth(context.Background(), "d._report._dmarc.ext.com")
                if status != dnsclient.LookupError {
                        t.Fatalf("status = %d, want error", status)
                }
                if m.calls != reportAuthMaxAttempts {
                        t.Errorf("calls = %d, want %d (capped)", m.calls, reportAuthMaxAttempts)
                }
        })
}

type countingStatusDNS struct {
        MockDNSClient
        calls                 int
        failuresBeforeSuccess int
        successRecords        []string
        absent                bool
}

func (m *countingStatusDNS) QueryDNSWithStatus(context.Context, string, string) ([]string, dnsclient.LookupStatus) {
        m.calls++
        if m.absent {
                return nil, dnsclient.LookupAbsent
        }
        if m.calls > m.failuresBeforeSuccess {
                return m.successRecords, dnsclient.LookupResolved
        }
        return nil, dnsclient.LookupError
}
