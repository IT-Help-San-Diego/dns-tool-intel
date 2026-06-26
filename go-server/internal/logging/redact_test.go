package logging

import (
        "errors"
        "log/slog"
        "strings"
        "testing"
)

func TestRedactMessage_Email(t *testing.T) {
        msg := "User user@example.com logged in"
        result := RedactMessage(msg)
        if strings.Contains(result, "user@example.com") {
                t.Errorf("expected email to be redacted: %q", result)
        }
        if !strings.Contains(result, "[REDACTED_EMAIL]") {
                t.Errorf("expected [REDACTED_EMAIL] placeholder: %q", result)
        }
}

func TestRedactMessage_Webhook(t *testing.T) {
        msg := "Sending to https://discord.com/api/webhooks/123/abc"
        result := RedactMessage(msg)
        if strings.Contains(result, "discord.com/api/webhooks") {
                t.Errorf("expected webhook to be redacted: %q", result)
        }
        if !strings.Contains(result, "[REDACTED_WEBHOOK]") {
                t.Errorf("expected [REDACTED_WEBHOOK] placeholder: %q", result)
        }
}

func TestRedactMessage_Token(t *testing.T) {
        msg := "token=abc123xyz"
        result := RedactMessage(msg)
        if strings.Contains(result, "abc123xyz") {
                t.Errorf("expected token to be redacted: %q", result)
        }
        if !strings.Contains(result, "[REDACTED_CREDENTIAL]") {
                t.Errorf("expected [REDACTED_CREDENTIAL] placeholder: %q", result)
        }
}

func TestRedactMessage_Authorization(t *testing.T) {
        msg := "authorization=BearerToken123"
        result := RedactMessage(msg)
        if strings.Contains(result, "BearerToken123") {
                t.Errorf("expected auth value to be redacted: %q", result)
        }
}

func TestRedactMessage_SecretKey(t *testing.T) {
        msg := "secret=mysecretvalue"
        result := RedactMessage(msg)
        if strings.Contains(result, "mysecretvalue") {
                t.Errorf("expected secret to be redacted: %q", result)
        }
}

func TestRedactMessage_NoSensitive(t *testing.T) {
        msg := "Application started on port 8080"
        result := RedactMessage(msg)
        if result != msg {
                t.Errorf("result = %q, want %q", result, msg)
        }
}

func TestRedactMessage_MultiplePatterns(t *testing.T) {
        msg := "user@test.com sent token=secret123 to https://discordapp.com/api/webhooks/1/2"
        result := RedactMessage(msg)
        if strings.Contains(result, "user@test.com") {
                t.Error("email should be redacted")
        }
        if strings.Contains(result, "discordapp.com/api/webhooks") {
                t.Error("webhook should be redacted")
        }
}

func TestRedactAttr_SensitiveKey(t *testing.T) {
        tests := []string{
                "password", "secret", "token", "authorization",
                "cookie", "session_id", "api_key", "webhook_url",
                "scan_token", "csrf_token", "probe_key",
        }
        for _, key := range tests {
                t.Run(key, func(t *testing.T) {
                        a := slog.String(key, "sensitive-value")
                        result := redactAttr(a)
                        if result.Value.String() != "[REDACTED]" {
                                t.Errorf("key %q: value = %q, want [REDACTED]", key, result.Value.String())
                        }
                })
        }
}

func TestRedactAttr_NonSensitiveKey(t *testing.T) {
        a := slog.String("domain", "example.com")
        result := redactAttr(a)
        if result.Value.String() != "example.com" {
                t.Errorf("non-sensitive key should preserve value: %q", result.Value.String())
        }
}

func TestRedactAttr_StringWithEmail(t *testing.T) {
        a := slog.String("message", "login by admin@corp.com")
        result := redactAttr(a)
        if strings.Contains(result.Value.String(), "admin@corp.com") {
                t.Error("email in string attr should be redacted")
        }
}

func TestRedactAttr_ErrorType(t *testing.T) {
        err := errors.New("failed for user@example.com")
        a := slog.Any("error", err)
        result := redactAttr(a)
        if strings.Contains(result.Value.String(), "user@example.com") {
                t.Error("email in error should be redacted")
        }
}

func TestRedactAttr_GroupType(t *testing.T) {
        group := slog.Group("auth",
                slog.String("password", "secret123"),
                slog.String("username", "admin"),
        )
        result := redactAttr(group)
        attrs := result.Value.Group()
        for _, a := range attrs {
                if a.Key == "password" && a.Value.String() != "[REDACTED]" {
                        t.Error("password in group should be redacted")
                }
                if a.Key == "username" && a.Value.String() != "admin" {
                        t.Error("username should be preserved")
                }
        }
}

func TestRedactAttr_CaseInsensitiveKeys(t *testing.T) {
        a := slog.String("Password", "secret")
        result := redactAttr(a)
        if result.Value.String() != "[REDACTED]" {
                t.Error("case-insensitive key should still be redacted")
        }
}

func TestSensitiveKeys_Complete(t *testing.T) {
        expected := []string{
                "password", "secret", "token", "authorization",
                "cookie", "session_id", "api_key", "webhook_url",
                "scan_token", "csrf_token", "probe_key",
        }
        for _, key := range expected {
                if !sensitiveKeys[key] {
                        t.Errorf("missing sensitive key: %q", key)
                }
        }
}

func TestRedactMessage_DiscordAppWebhook(t *testing.T) {
        msg := "hook: https://discordapp.com/api/webhooks/999/token"
        result := RedactMessage(msg)
        if !strings.Contains(result, "[REDACTED_WEBHOOK]") {
                t.Errorf("discordapp.com webhook should be redacted: %q", result)
        }
}

func TestRedactMessage_SecretWithColon(t *testing.T) {
        msg := "secret: mysecretvalue"
        result := RedactMessage(msg)
        if !strings.Contains(result, "[REDACTED_CREDENTIAL]") {
                t.Errorf("secret: pattern should be redacted: %q", result)
        }
}

func TestRedactMessage_EmptyString(t *testing.T) {
        result := RedactMessage("")
        if result != "" {
                t.Errorf("empty string should stay empty: %q", result)
        }
}

// TestRedactString_CredentialPatterns proves the strengthened tokenRe/bearerRe
// scrub every credential shape an upstream client could fold into a free-form
// log message or wrapped error (the dataflow HoundDog flags on the
// SecurityTrails/IPInfo log sites).
func TestRedactString_CredentialPatterns(t *testing.T) {
        cases := []struct {
                name string
                in   string
                leak string
        }{
                {"apikey_equals", "dial failed: apikey=AKIAEXAMPLE12345 host=api", "AKIAEXAMPLE12345"},
                {"api_key_underscore", "request api_key=EXAMPLEnotrealkey1234", "EXAMPLEnotrealkey1234"},
                {"api_key_hyphen", "header x-api-key: sk_test_ZZZ999", "sk_test_ZZZ999"},
                {"access_token", "oauth access_token=EXAMPLEnotrealtoken", "EXAMPLEnotrealtoken"},
                {"client_secret", "config client_secret=cs_9f8e7d6c", "cs_9f8e7d6c"},
                {"bearer", "Authorization: Bearer eyJhbGciOi.payload.sig", "eyJhbGciOi.payload.sig"},
                {"json_token", `{"token":"jwtAbc123"}`, "jwtAbc123"},
        }
        for _, tc := range cases {
                t.Run(tc.name, func(t *testing.T) {
                        got := redactString(tc.in)
                        if strings.Contains(got, tc.leak) {
                                t.Errorf("credential leaked: in=%q out=%q", tc.in, got)
                        }
                        if !strings.Contains(got, "[REDACTED_CREDENTIAL]") {
                                t.Errorf("expected redaction placeholder: %q", got)
                        }
                })
        }
}

func TestRedactAttr_NewCredentialKeys(t *testing.T) {
        keys := []string{
                "apikey", "api-key", "x-api-key", "access_token",
                "refresh_token", "client_secret", "auth_token", "bearer", "private_key",
        }
        for _, key := range keys {
                t.Run(key, func(t *testing.T) {
                        a := slog.String(key, "super-secret-value")
                        if got := redactAttr(a).Value.String(); got != "[REDACTED]" {
                                t.Errorf("key %q not redacted: %q", key, got)
                        }
                })
        }
}

// TestRedactString_NoOverRedaction guards against the unanchored tokenRe
// becoming over-broad: ordinary diagnostic words that merely contain "key"
// must survive untouched.
func TestRedactString_NoOverRedaction(t *testing.T) {
        in := "monkey business at gateway 10.0.0.1 with keyboard layout"
        if got := redactString(in); strings.Contains(got, "[REDACTED_CREDENTIAL]") {
                t.Errorf("false-positive redaction: in=%q out=%q", in, got)
        }
}
