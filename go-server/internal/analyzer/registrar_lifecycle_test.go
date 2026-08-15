// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "testing"
)

// TestClassifyRDAPLifecycle pins the RFC 9083 status-to-state mapping. The
// load-bearing pitfall: RFC 9083 statuses are space-separated lowercase
// ("redemption period", "pending delete", "client hold") — NOT EPP camelCase
// ("redemptionPeriod", "clientHold"). A camelCase input must fall through to
// "active" rather than silently match nothing and fabricate a state.
func TestClassifyRDAPLifecycle(t *testing.T) {
        cases := []struct {
                name     string
                statuses []string
                want     string
        }{
                {"active", []string{"active"}, "active"},
                {"active_with_transfer_lock", []string{"active", "client transfer prohibited"}, "active"},
                {"client_hold", []string{"client hold"}, "hold"},
                {"server_hold", []string{"server hold"}, "hold"},
                {"redemption", []string{"redemption period"}, "redemption"},
                {"pending_delete", []string{"pending delete"}, "pending_delete"},
                {"auto_renew", []string{"auto renew period"}, "auto_renew"},
                {"hold_outranks_active", []string{"active", "client hold"}, "hold"},
                {"pending_delete_most_terminal", []string{"redemption period", "pending delete"}, "pending_delete"},
                {"redemption_outranks_hold", []string{"client hold", "redemption period"}, "redemption"},
                {"empty_defaults_active", nil, "active"},
                {"epp_camelcase_clientHold_does_not_match", []string{"clientHold"}, "active"},
                {"epp_camelcase_redemptionPeriod_does_not_match", []string{"redemptionPeriod"}, "active"},
        }
        for _, tc := range cases {
                t.Run(tc.name, func(t *testing.T) {
                        if got := classifyRDAPLifecycle(tc.statuses); got != tc.want {
                                t.Fatalf("classifyRDAPLifecycle(%v) = %q, want %q", tc.statuses, got, tc.want)
                        }
                })
        }
}

// TestExtractRDAPLifecycle verifies the full parse: status -> state + raw list,
// events -> the four dated fields, and secureDNS.delegationSigned.
func TestExtractRDAPLifecycle(t *testing.T) {
        data := map[string]any{
                "status": []any{"active", "client transfer prohibited"},
                "events": []any{
                        map[string]any{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                        map[string]any{"eventAction": "expiration", "eventDate": "2025-01-01T00:00:00Z"},
                        map[string]any{"eventAction": "last changed", "eventDate": "2024-06-15T12:00:00Z"},
                        map[string]any{"eventAction": "last update of rdap database", "eventDate": "2024-06-16T00:00:00Z"},
                },
                "secureDNS": map[string]any{"delegationSigned": true},
        }
        out := extractRDAPLifecycle(data)
        if out["lifecycle_state"] != "active" {
                t.Fatalf("lifecycle_state = %v, want active", out["lifecycle_state"])
        }
        if out["registration_date"] != "2020-01-01T00:00:00Z" {
                t.Fatalf("registration_date = %v", out["registration_date"])
        }
        if out["expiration_date"] != "2025-01-01T00:00:00Z" {
                t.Fatalf("expiration_date = %v", out["expiration_date"])
        }
        if out["last_changed_date"] != "2024-06-15T12:00:00Z" {
                t.Fatalf("last_changed_date = %v", out["last_changed_date"])
        }
        if out["rdap_update_date"] != "2024-06-16T00:00:00Z" {
                t.Fatalf("rdap_update_date = %v", out["rdap_update_date"])
        }
        if out["delegation_signed"] != true {
                t.Fatalf("delegation_signed = %v, want true", out["delegation_signed"])
        }
        statuses, _ := out["lifecycle_statuses"].([]string)
        if len(statuses) != 2 {
                t.Fatalf("lifecycle_statuses len = %d, want 2", len(statuses))
        }
}

// TestExtractRDAPLifecycle_Minimal verifies a response with no status/events/
// secureDNS yields an empty map — never a fabricated state, never a panic.
func TestExtractRDAPLifecycle_Minimal(t *testing.T) {
        out := extractRDAPLifecycle(map[string]any{"handle": "example"})
        if len(out) != 0 {
                t.Fatalf("minimal response should yield empty lifecycle, got %v", out)
        }
}

// TestExtractRDAPLifecycle_ExpiredTakedown verifies the expiry ladder wins over a
// registry hold, matching the classify precedence.
func TestExtractRDAPLifecycle_ExpiredTakedown(t *testing.T) {
        data := map[string]any{
                "status": []any{"client hold", "redemption period"},
                "events": []any{
                        map[string]any{"eventAction": "last changed", "eventDate": "2024-08-01T00:00:00Z"},
                },
        }
        out := extractRDAPLifecycle(data)
        if out["lifecycle_state"] != "redemption" {
                t.Fatalf("lifecycle_state = %v, want redemption", out["lifecycle_state"])
        }
        if out["last_changed_date"] != "2024-08-01T00:00:00Z" {
                t.Fatalf("last_changed_date = %v", out["last_changed_date"])
        }
}

// TestExtractRDAPLifecycle_Reregistration verifies a domain that lapsed and
// was re-registered: both the original registration and the reregistration
// dates appear as separate fields so the gap is discoverable.
func TestExtractRDAPLifecycle_Reregistration(t *testing.T) {
        data := map[string]any{
                "events": []any{
                        map[string]any{"eventAction": "registration", "eventDate": "2018-12-01T00:00:00Z"},
                        map[string]any{"eventAction": "reregistration", "eventDate": "2025-11-01T00:00:00Z"},
                },
        }
        out := extractRDAPLifecycle(data)
        if out["registration_date"] != "2018-12-01T00:00:00Z" {
                t.Fatalf("registration_date = %v, want original", out["registration_date"])
        }
        if out["reregistration_date"] != "2025-11-01T00:00:00Z" {
                t.Fatalf("reregistration_date = %v, want reregistration", out["reregistration_date"])
        }
}
