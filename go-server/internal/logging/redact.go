// dns-tool:scrutiny plumbing
package logging

import (
        "log/slog"
        "regexp"
        "strings"
)

var (
        emailRe   = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
        webhookRe = regexp.MustCompile(`https?://(?:discord\.com|discordapp\.com)/api/webhooks/\S+`)
        // tokenRe scrubs labelled credentials (authorization / api-key /
        // access-token / client-secret / token / secret / password / …)
        // wherever they appear in a string. It is DELIBERATELY unanchored: a
        // credential can sit anywhere inside a free-form log message or wrapped
        // error (e.g. `dial failed: apikey=AKIA… host=…`), so anchoring it to
        // the start of the string would defeat redaction. This is not a
        // validation regex (CWE-625 anchoring guidance does not apply) and it is
        // not ReDoS-prone: its only quantifiers, `\s*` then `\S+`, match
        // disjoint character classes (whitespace vs non-whitespace) and so
        // cannot backtrack catastrophically. The optional `["']?` lets it catch
        // JSON-shaped pairs like `"token":"…"` as well as `token=…`.
        tokenRe = regexp.MustCompile(`(?i)(?:authorization|access[_-]?token|refresh[_-]?token|client[_-]?secret|api[_-]?key|apikey|token|secret|password|passwd|credential|key)["']?\s*[=:]\s*\S+`)
        // bearerRe scrubs `Bearer <token>` Authorization values, which carry no
        // key=value label of their own and so are missed by tokenRe.
        bearerRe = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/\-]+=*`)
)

var sensitiveKeys = map[string]bool{
        "password":      true,
        "secret":        true,
        "token":         true,
        "authorization": true,
        "cookie":        true,
        "session_id":    true,
        "api_key":       true,
        "apikey":        true,
        "api-key":       true,
        "x-api-key":     true,
        "access_token":  true,
        "refresh_token": true,
        "client_secret": true,
        "auth_token":    true,
        "bearer":        true,
        "private_key":   true,
        "webhook_url":   true,
        "scan_token":    true,
        "csrf_token":    true,
        "probe_key":     true,
}

func RedactMessage(s string) string {
        return redactString(s)
}

func redactString(s string) string {
        s = emailRe.ReplaceAllString(s, "[REDACTED_EMAIL]")
        s = webhookRe.ReplaceAllString(s, "[REDACTED_WEBHOOK]")
        s = bearerRe.ReplaceAllString(s, "[REDACTED_CREDENTIAL]")
        s = tokenRe.ReplaceAllString(s, "[REDACTED_CREDENTIAL]")
        return s
}

func redactAttr(a slog.Attr) slog.Attr {
        if sensitiveKeys[strings.ToLower(a.Key)] {
                a.Value = slog.StringValue("[REDACTED]")
                return a
        }

        switch a.Value.Kind() {
        case slog.KindString:
                a.Value = slog.StringValue(redactString(a.Value.String()))
        case slog.KindAny:
                if err, ok := a.Value.Any().(error); ok {
                        a.Value = slog.StringValue(redactString(err.Error()))
                } else {
                        str := a.Value.String()
                        redacted := redactString(str)
                        if redacted != str {
                                a.Value = slog.StringValue(redacted)
                        }
                }
        }

        if a.Value.Kind() == slog.KindGroup {
                attrs := a.Value.Group()
                redacted := make([]slog.Attr, len(attrs))
                for i, ga := range attrs {
                        redacted[i] = redactAttr(ga)
                }
                a.Value = slog.GroupValue(redacted...)
        }

        return a
}
