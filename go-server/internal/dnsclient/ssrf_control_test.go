// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package dnsclient

import "testing"

// TestSSRFDialControl_RejectsPrivateAtConnectTime proves the dial-time SSRF
// guard refuses connections to private/reserved IPs — the DNS-rebinding / TOCTOU
// case that the pre-flight ValidateURLTarget cannot catch because the name is
// re-resolved at connect time — while honoring SkipSSRF for intentional internal
// diagnostic probes (e.g. CT-log fetches).
func TestSSRFDialControl_RejectsPrivateAtConnectTime(t *testing.T) {
        s := NewSafeHTTPClient()

        blocked := []string{
                "127.0.0.1:443",
                "10.0.0.5:80",
                "192.168.1.1:443",
                "172.16.0.1:80",
                "169.254.169.254:80", // cloud metadata endpoint
                "100.64.0.1:80",      // CGNAT
                "[::1]:443",
        }
        for _, addr := range blocked {
                if err := s.ssrfDialControl("tcp", addr, nil); err == nil {
                        t.Errorf("dial guard should refuse private/reserved %q", addr)
                }
        }

        if err := s.ssrfDialControl("tcp", "1.1.1.1:443", nil); err != nil {
                t.Errorf("dial guard should allow public IP, got %v", err)
        }

        s.SkipSSRF = true
        if err := s.ssrfDialControl("tcp", "127.0.0.1:443", nil); err != nil {
                t.Errorf("SkipSSRF must bypass dial guard for diagnostic probes, got %v", err)
        }
}
