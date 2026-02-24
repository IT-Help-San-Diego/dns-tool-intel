package notifier

import (
        "bytes"
        "context"
        "encoding/json"
        "fmt"
        "io"
        "log/slog"
        "net/http"
        "strings"
        "time"

        "dnstool/go-server/internal/dbq"
)

const (
        httpTimeout       = 10 * time.Second
        maxResponseBody   = 1024
        headerContentType = "Content-Type"
        mimeJSON          = "application/json"
)

type Notifier struct {
        Queries *dbq.Queries
        Client  *http.Client
}

func New(queries *dbq.Queries) *Notifier {
        return &Notifier{
                Queries: queries,
                Client: &http.Client{
                        Timeout: httpTimeout,
                },
        }
}

type discordEmbed struct {
        Title       string         `json:"title"`
        Description string         `json:"description"`
        Color       int            `json:"color"`
        Fields      []discordField `json:"fields,omitempty"`
        Timestamp   string         `json:"timestamp,omitempty"`
}

type discordField struct {
        Name   string `json:"name"`
        Value  string `json:"value"`
        Inline bool   `json:"inline"`
}

type discordPayload struct {
        Username string         `json:"username"`
        Embeds   []discordEmbed `json:"embeds"`
}

func severityColor(severity string) int {
        switch strings.ToLower(severity) {
        case "critical":
                return 0xDC3545
        case "high":
                return 0xFD7E14
        case "medium":
                return 0xFFC107
        case "low":
                return 0x17A2B8
        default:
                return 0x6C757D
        }
}

func (n *Notifier) DeliverPending(ctx context.Context, batchSize int32) (int, error) {
        pending, err := n.Queries.ListPendingNotifications(ctx, batchSize)
        if err != nil {
                return 0, fmt.Errorf("listing pending notifications: %w", err)
        }
        if len(pending) == 0 {
                return 0, nil
        }

        delivered := 0
        for _, notif := range pending {
                var sendErr error
                var httpCode int
                switch notif.EndpointType {
                case "discord":
                        httpCode, sendErr = n.sendDiscord(ctx, notif)
                default:
                        httpCode, sendErr = n.sendGenericWebhook(ctx, notif)
                }

                status := "delivered"
                var respCode *int32
                var respBody *string
                if httpCode > 0 {
                        code := int32(httpCode)
                        respCode = &code
                }
                if sendErr != nil {
                        status = "failed"
                        errMsg := sendErr.Error()
                        respBody = &errMsg
                        slog.Error("Notification delivery failed",
                                "notification_id", notif.ID,
                                "endpoint_type", notif.EndpointType,
                                "domain", notif.Domain,
                                "http_code", httpCode,
                                "error", sendErr,
                        )
                } else {
                        delivered++
                        slog.Info("Notification delivered",
                                "notification_id", notif.ID,
                                "endpoint_type", notif.EndpointType,
                                "domain", notif.Domain,
                                "http_code", httpCode,
                        )
                }

                updateErr := n.Queries.UpdateDriftNotificationStatus(ctx, dbq.UpdateDriftNotificationStatusParams{
                        ID:           notif.ID,
                        Status:       status,
                        ResponseCode: respCode,
                        ResponseBody: respBody,
                })
                if updateErr != nil {
                        slog.Error("Failed to update notification status",
                                "notification_id", notif.ID,
                                "error", updateErr,
                        )
                }
        }
        return delivered, nil
}

func (n *Notifier) sendDiscord(ctx context.Context, notif dbq.ListPendingNotificationsRow) (int, error) {
        var fields []discordField

        var diffFields []struct {
                Field string `json:"field"`
                Old   string `json:"old"`
                New   string `json:"new"`
        }
        if len(notif.DiffSummary) > 0 {
                if json.Unmarshal(notif.DiffSummary, &diffFields) == nil {
                        for _, df := range diffFields {
                                fields = append(fields, discordField{
                                        Name:   df.Field,
                                        Value:  fmt.Sprintf("`%s` → `%s`", df.Old, df.New),
                                        Inline: true,
                                })
                        }
                }
        }

        payload := discordPayload{
                Username: "DNS Tool Drift Engine",
                Embeds: []discordEmbed{
                        {
                                Title:       fmt.Sprintf("Drift Detected: %s", notif.Domain),
                                Description: fmt.Sprintf("Security posture change detected for **%s** (severity: **%s**).", notif.Domain, notif.Severity),
                                Color:       severityColor(notif.Severity),
                                Fields:      fields,
                                Timestamp:   time.Now().UTC().Format(time.RFC3339),
                        },
                },
        }

        body, err := json.Marshal(payload)
        if err != nil {
                return 0, fmt.Errorf("marshaling Discord payload: %w", err)
        }

        req, err := http.NewRequestWithContext(ctx, http.MethodPost, notif.Url, bytes.NewReader(body))
        if err != nil {
                return 0, fmt.Errorf("creating Discord request: %w", err)
        }
        req.Header.Set(headerContentType, mimeJSON)

        resp, err := n.Client.Do(req)
        if err != nil {
                return 0, fmt.Errorf("sending Discord webhook: %w", err)
        }
        defer resp.Body.Close()

        if resp.StatusCode < 200 || resp.StatusCode >= 300 {
                respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
                return resp.StatusCode, fmt.Errorf("Discord returned %d: %s", resp.StatusCode, string(respBody))
        }
        return resp.StatusCode, nil
}

func (n *Notifier) sendGenericWebhook(ctx context.Context, notif dbq.ListPendingNotificationsRow) (int, error) {
        payload := map[string]any{
                "event":     "drift_detected",
                "domain":    notif.Domain,
                "severity":  notif.Severity,
                "timestamp": time.Now().UTC().Format(time.RFC3339),
        }

        if len(notif.DiffSummary) > 0 {
                var raw json.RawMessage = notif.DiffSummary
                payload["diff_summary"] = raw
        }

        body, err := json.Marshal(payload)
        if err != nil {
                return 0, fmt.Errorf("marshaling webhook payload: %w", err)
        }

        req, err := http.NewRequestWithContext(ctx, http.MethodPost, notif.Url, bytes.NewReader(body))
        if err != nil {
                return 0, fmt.Errorf("creating webhook request: %w", err)
        }
        req.Header.Set(headerContentType, mimeJSON)
        if notif.Secret != nil && *notif.Secret != "" {
                req.Header.Set("X-Webhook-Secret", *notif.Secret)
        }

        resp, err := n.Client.Do(req)
        if err != nil {
                return 0, fmt.Errorf("sending webhook: %w", err)
        }
        defer resp.Body.Close()

        if resp.StatusCode < 200 || resp.StatusCode >= 300 {
                respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
                return resp.StatusCode, fmt.Errorf("webhook returned %d: %s", resp.StatusCode, string(respBody))
        }
        return resp.StatusCode, nil
}

func (n *Notifier) SendTestDiscord(ctx context.Context, webhookURL string) error {
        payload := discordPayload{
                Username: "DNS Tool Drift Engine",
                Embeds: []discordEmbed{
                        {
                                Title:       "Drift Engine Connected",
                                Description: "This is a verification message from the DNS Tool Drift Engine. Discord webhook integration is active and operational.",
                                Color:       0x28A745,
                                Fields: []discordField{
                                        {Name: "Status", Value: "Operational", Inline: true},
                                        {Name: "Monitored Domains", Value: strings.Join(missionCriticalDomains, "\n"), Inline: true},
                                        {Name: "Cadence", Value: "Daily", Inline: true},
                                },
                                Timestamp: time.Now().UTC().Format(time.RFC3339),
                        },
                },
        }

        body, err := json.Marshal(payload)
        if err != nil {
                return fmt.Errorf("marshaling test payload: %w", err)
        }

        req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
        if err != nil {
                return fmt.Errorf("creating test request: %w", err)
        }
        req.Header.Set(headerContentType, mimeJSON)

        resp, err := n.Client.Do(req)
        if err != nil {
                return fmt.Errorf("sending test webhook: %w", err)
        }
        defer resp.Body.Close()

        if resp.StatusCode < 200 || resp.StatusCode >= 300 {
                respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
                return fmt.Errorf("Discord returned %d: %s", resp.StatusCode, string(respBody))
        }
        return nil
}

var missionCriticalDomains = []string{
        "it-help.tech",
        "dnstool.it-help.tech",
}
