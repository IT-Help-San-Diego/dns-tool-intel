package middleware

import (
        "testing"
)

func TestExtractRefOrigin(t *testing.T) {
        tests := []struct {
                name string
                ref  string
                want string
        }{
                {"empty string returns direct", "", "direct"},
                {"invalid URL returns direct", "://bad", "direct"},
                {"no host returns direct", "/just/a/path", "direct"},
                {"internal dnstool domain returns empty", "https://dnstool.it-help.tech/report", ""},
                {"internal it-help.tech domain returns empty", "https://app.it-help.tech/page", ""},
                {"external google returns host", "https://www.google.com/search?q=dns", "www.google.com"},
                {"external twitter returns host", "https://twitter.com/share", "twitter.com"},
                {"external with port returns host only", "https://example.com:8080/page", "example.com"},
                {"external with path returns host", "https://reddit.com/r/sysadmin", "reddit.com"},
                {"scheme only no host returns direct", "http://", "direct"},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := extractRefOrigin(tt.ref)
                        if got != tt.want {
                                t.Errorf("extractRefOrigin(%q) = %q, want %q", tt.ref, got, tt.want)
                        }
                })
        }
}

func TestNormalizePath(t *testing.T) {
        tests := []struct {
                name string
                path string
                want string
        }{
                {"root stays root", "/", "/"},
                {"trailing slash removed", "/about/", "/about"},
                {"multiple trailing slashes removed", "/page///", "/page"},
                {"query params stripped", "/report?domain=example.com", "/report"},
                {"path with trailing slash and query", "/report/?foo=bar", "/report/"},
                {"no trailing slash unchanged", "/contact", "/contact"},
                {"nested path", "/admin/settings", "/admin/settings"},
                {"nested path with trailing slash", "/admin/settings/", "/admin/settings"},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := normalizePath(tt.path)
                        if got != tt.want {
                                t.Errorf("normalizePath(%q) = %q, want %q", tt.path, got, tt.want)
                        }
                })
        }
}
