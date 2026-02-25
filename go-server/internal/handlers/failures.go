// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
        "fmt"
        "net/http"
        "regexp"
        "strings"
        "time"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
)

type FailuresHandler struct {
        DB     *db.Database
        Config *config.Config
}

func NewFailuresHandler(database *db.Database, cfg *config.Config) *FailuresHandler {
        return &FailuresHandler{DB: database, Config: cfg}
}

type FailureEntry struct {
        Domain    string
        Category  string
        Icon      string
        Timestamp string
        TimeAgo   string
}

func timeAgo(t time.Time) string {
        d := time.Since(t)
        switch {
        case d < time.Minute:
                return "just now"
        case d < time.Hour:
                m := int(d.Minutes())
                if m == 1 {
                        return "1 minute ago"
                }
                return fmt.Sprintf("%d minutes ago", m)
        case d < 24*time.Hour:
                h := int(d.Hours())
                if h == 1 {
                        return "1 hour ago"
                }
                return fmt.Sprintf("%d hours ago", h)
        default:
                days := int(d.Hours() / 24)
                if days == 1 {
                        return "1 day ago"
                }
                return fmt.Sprintf("%d days ago", days)
        }
}

var ipPattern = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?`)
var pathPattern = regexp.MustCompile(`/[a-zA-Z0-9_/.]+`)

func sanitizeErrorMessage(raw *string) (string, string) {
        if raw == nil || *raw == "" {
                return "Unknown Error", "fas fa-question-circle"
        }
        msg := strings.ToLower(*raw)

        if strings.Contains(msg, "timeout") || strings.Contains(msg, "timed out") || strings.Contains(msg, "deadline") {
                return "DNS Resolution Timeout", "fas fa-clock"
        }
        if strings.Contains(msg, "no such host") || strings.Contains(msg, "nxdomain") || strings.Contains(msg, "not found") {
                return "Domain Not Found (NXDOMAIN)", "fas fa-unlink"
        }
        if strings.Contains(msg, "connection refused") || strings.Contains(msg, "connection reset") {
                return "Connection Refused", "fas fa-ban"
        }
        if strings.Contains(msg, "servfail") || strings.Contains(msg, "server failure") {
                return "DNS Server Failure (SERVFAIL)", "fas fa-server"
        }
        if strings.Contains(msg, "network") || strings.Contains(msg, "unreachable") {
                return "Network Unreachable", "fas fa-wifi"
        }
        if strings.Contains(msg, "tls") || strings.Contains(msg, "certificate") || strings.Contains(msg, "x509") {
                return "TLS/Certificate Error", "fas fa-lock"
        }
        if strings.Contains(msg, "refused") {
                return "Query Refused", "fas fa-hand-paper"
        }
        if strings.Contains(msg, "rate limit") || strings.Contains(msg, "throttl") {
                return "Rate Limited", "fas fa-tachometer-alt"
        }
        if strings.Contains(msg, "invalid") || strings.Contains(msg, "malformed") {
                return "Invalid Input", "fas fa-exclamation-triangle"
        }

        cleaned := ipPattern.ReplaceAllString(*raw, "[redacted]")
        cleaned = pathPattern.ReplaceAllString(cleaned, "[path]")
        if len(cleaned) > 80 {
                cleaned = cleaned[:77] + "..."
        }
        return "Analysis Error: " + cleaned, "fas fa-exclamation-circle"
}

func (h *FailuresHandler) Failures(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")
        csrfToken, _ := c.Get("csrf_token")
        ctx := c.Request.Context()

        totalFailed, _ := h.DB.Queries.CountFailedAnalyses(ctx)
        totalAll, _ := h.DB.Queries.CountAllAnalyses(ctx)

        failures, err := h.DB.Queries.ListFailedAnalyses(ctx, dbq.ListFailedAnalysesParams{
                Limit:  50,
                Offset: 0,
        })
        if err != nil {
                errData := gin.H{
                        "AppVersion":      h.Config.AppVersion,
                        "MaintenanceNote": h.Config.MaintenanceNote,
                        "BetaPages":       h.Config.BetaPages,
                        "CspNonce":        nonce,
                        "CsrfToken":       csrfToken,
                        "ActivePage":      "failures",
                        "FlashMessages":   []FlashMessage{{Category: "danger", Message: "Failed to fetch failure log"}},
                }
                mergeAuthData(c, h.Config, errData)
                c.HTML(http.StatusInternalServerError, "failures.html", errData)
                return
        }

        entries := make([]FailureEntry, 0, len(failures))
        for _, f := range failures {
                category, icon := sanitizeErrorMessage(f.ErrorMessage)
                ts := ""
                ago := ""
                if f.CreatedAt.Valid {
                        ts = f.CreatedAt.Time.Format("2006-01-02 15:04 UTC")
                        ago = timeAgo(f.CreatedAt.Time)
                }
                entries = append(entries, FailureEntry{
                        Domain:    f.Domain,
                        Category:  category,
                        Icon:      icon,
                        Timestamp: ts,
                        TimeAgo:   ago,
                })
        }

        var failureRate float64
        if totalAll > 0 {
                failureRate = float64(totalFailed) / float64(totalAll) * 100
        }

        data := gin.H{
                "AppVersion":      h.Config.AppVersion,
                "MaintenanceNote": h.Config.MaintenanceNote,
                "BetaPages":       h.Config.BetaPages,
                "CspNonce":        nonce,
                "CsrfToken":       csrfToken,
                "ActivePage":      "failures",
                "Failures":        entries,
                "TotalFailed":     totalFailed,
                "TotalAnalyses":   totalAll,
                "FailureRate":     failureRate,
        }
        mergeAuthData(c, h.Config, data)
        c.HTML(http.StatusOK, "failures.html", data)
}
