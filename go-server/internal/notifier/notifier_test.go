package notifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"dnstool/go-server/internal/dbq"
)

func TestSeverityColor(t *testing.T) {
	tests := []struct {
		severity string
		want     int
	}{
		{"critical", 0xDC3545},
		{"Critical", 0xDC3545},
		{"CRITICAL", 0xDC3545},
		{"high", 0xFD7E14},
		{"High", 0xFD7E14},
		{"medium", 0xFFC107},
		{"Medium", 0xFFC107},
		{"low", 0x17A2B8},
		{"Low", 0x17A2B8},
		{"unknown", 0x6C757D},
		{"", 0x6C757D},
		{"info", 0x6C757D},
	}
	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := severityColor(tt.severity)
			if got != tt.want {
				t.Errorf("severityColor(%q) = 0x%X, want 0x%X", tt.severity, got, tt.want)
			}
		})
	}
}

func TestNew(t *testing.T) {
	n := New(nil)
	if n == nil {
		t.Fatal("New returned nil")
	}
	if n.Client == nil {
		t.Fatal("Client is nil")
	}
	if n.Client.Timeout != httpTimeout {
		t.Errorf("Client.Timeout = %v, want %v", n.Client.Timeout, httpTimeout)
	}
	if n.Queries != nil {
		t.Error("Queries should be nil when passed nil")
	}
}

func TestSendDiscord_Success(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", r.Header.Get("Content-Type"))
		}
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	n := &Notifier{Client: srv.Client()}

	diffJSON, _ := json.Marshal([]struct {
		Field string `json:"field"`
		Old   string `json:"old"`
		New   string `json:"new"`
	}{
		{Field: "SPF", Old: "pass", New: "fail"},
	})

	notif := dbq.ListPendingNotificationsRow{
		ID:           1,
		DriftEventID: 10,
		EndpointID:   5,
		Status:       "pending",
		Url:          srv.URL,
		EndpointType: "discord",
		Domain:       "example.com",
		DiffSummary:  diffJSON,
		Severity:     "high",
	}

	code, err := n.sendDiscord(context.Background(), notif)
	if err != nil {
		t.Fatalf("sendDiscord returned error: %v", err)
	}
	if code != http.StatusNoContent {
		t.Errorf("status code = %d, want %d", code, http.StatusNoContent)
	}

	var payload discordPayload
	if err := json.Unmarshal(receivedBody, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}
	if payload.Username != "DNS Tool Drift Engine" {
		t.Errorf("Username = %q", payload.Username)
	}
	if len(payload.Embeds) != 1 {
		t.Fatalf("expected 1 embed, got %d", len(payload.Embeds))
	}
	if payload.Embeds[0].Color != 0xFD7E14 {
		t.Errorf("embed color = 0x%X, want 0x%X", payload.Embeds[0].Color, 0xFD7E14)
	}
	if len(payload.Embeds[0].Fields) != 1 {
		t.Fatalf("expected 1 field, got %d", len(payload.Embeds[0].Fields))
	}
	if payload.Embeds[0].Fields[0].Name != "SPF" {
		t.Errorf("field name = %q", payload.Embeds[0].Fields[0].Name)
	}
}

func TestSendDiscord_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("forbidden"))
	}))
	defer srv.Close()

	n := &Notifier{Client: srv.Client()}
	notif := dbq.ListPendingNotificationsRow{
		Url:      srv.URL,
		Domain:   "example.com",
		Severity: "low",
	}

	code, err := n.sendDiscord(context.Background(), notif)
	if err == nil {
		t.Fatal("expected error for non-2xx status")
	}
	if code != http.StatusForbidden {
		t.Errorf("status code = %d, want %d", code, http.StatusForbidden)
	}
}

func TestSendDiscord_NoDiffSummary(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := &Notifier{Client: srv.Client()}
	notif := dbq.ListPendingNotificationsRow{
		Url:      srv.URL,
		Domain:   "test.com",
		Severity: "medium",
	}

	code, err := n.sendDiscord(context.Background(), notif)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != http.StatusOK {
		t.Errorf("code = %d", code)
	}

	var payload discordPayload
	json.Unmarshal(receivedBody, &payload)
	if len(payload.Embeds[0].Fields) != 0 {
		t.Errorf("expected 0 fields with empty diff, got %d", len(payload.Embeds[0].Fields))
	}
}

func TestSendGenericWebhook_Success(t *testing.T) {
	secret := "my-secret"
	var receivedBody []byte
	var receivedSecret string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSecret = r.Header.Get("X-Webhook-Secret")
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := &Notifier{Client: srv.Client()}

	diffJSON := []byte(`[{"field":"DMARC","old":"none","new":"reject"}]`)
	notif := dbq.ListPendingNotificationsRow{
		Url:         srv.URL,
		Secret:      &secret,
		Domain:      "example.org",
		DiffSummary: diffJSON,
		Severity:    "critical",
	}

	code, err := n.sendGenericWebhook(context.Background(), notif)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != http.StatusOK {
		t.Errorf("code = %d", code)
	}
	if receivedSecret != secret {
		t.Errorf("secret header = %q, want %q", receivedSecret, secret)
	}

	var payload map[string]any
	json.Unmarshal(receivedBody, &payload)
	if payload["event"] != "drift_detected" {
		t.Errorf("event = %v", payload["event"])
	}
	if payload["domain"] != "example.org" {
		t.Errorf("domain = %v", payload["domain"])
	}
	if payload["diff_summary"] == nil {
		t.Error("diff_summary missing")
	}
}

func TestSendGenericWebhook_NoSecret(t *testing.T) {
	var receivedSecret string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSecret = r.Header.Get("X-Webhook-Secret")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := &Notifier{Client: srv.Client()}
	notif := dbq.ListPendingNotificationsRow{
		Url:      srv.URL,
		Domain:   "test.com",
		Severity: "low",
	}

	_, err := n.sendGenericWebhook(context.Background(), notif)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedSecret != "" {
		t.Errorf("expected no secret header, got %q", receivedSecret)
	}
}

func TestSendGenericWebhook_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer srv.Close()

	n := &Notifier{Client: srv.Client()}
	notif := dbq.ListPendingNotificationsRow{
		Url:      srv.URL,
		Domain:   "fail.com",
		Severity: "high",
	}

	code, err := n.sendGenericWebhook(context.Background(), notif)
	if err == nil {
		t.Fatal("expected error for 500")
	}
	if code != http.StatusInternalServerError {
		t.Errorf("code = %d", code)
	}
}

func TestSendTestDiscord_Success(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	n := &Notifier{Client: srv.Client()}
	err := n.SendTestDiscord(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var payload discordPayload
	json.Unmarshal(receivedBody, &payload)
	if payload.Username != "DNS Tool Drift Engine" {
		t.Errorf("Username = %q", payload.Username)
	}
	if len(payload.Embeds) != 1 {
		t.Fatalf("expected 1 embed, got %d", len(payload.Embeds))
	}
	if payload.Embeds[0].Title != "Drift Engine Connected" {
		t.Errorf("Title = %q", payload.Embeds[0].Title)
	}
	if payload.Embeds[0].Color != 0x28A745 {
		t.Errorf("Color = 0x%X", payload.Embeds[0].Color)
	}
	if len(payload.Embeds[0].Fields) != 3 {
		t.Errorf("expected 3 fields, got %d", len(payload.Embeds[0].Fields))
	}
}

func TestSendTestDiscord_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("bad request"))
	}))
	defer srv.Close()

	n := &Notifier{Client: srv.Client()}
	err := n.SendTestDiscord(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected error for 400")
	}
}

type mockDBTX struct{}

func (m *mockDBTX) Exec(ctx context.Context, sql string, args ...interface{}) (interface{ RowsAffected() int64 }, error) {
	return nil, nil
}

func TestDeliverPending_DiscordEndpoint(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := &Notifier{
		Client:  srv.Client(),
		Queries: nil,
	}

	notif := dbq.ListPendingNotificationsRow{
		ID:           1,
		EndpointType: "discord",
		Url:          srv.URL,
		Domain:       "example.com",
		Severity:     "high",
	}
	code, err := n.sendDiscord(context.Background(), notif)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != http.StatusOK {
		t.Errorf("code = %d", code)
	}
	if callCount != 1 {
		t.Errorf("expected 1 call, got %d", callCount)
	}
}

func TestSendGenericWebhook_EmptySecret(t *testing.T) {
	var receivedSecret string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSecret = r.Header.Get("X-Webhook-Secret")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := &Notifier{Client: srv.Client()}
	emptySecret := ""
	notif := dbq.ListPendingNotificationsRow{
		Url:      srv.URL,
		Secret:   &emptySecret,
		Domain:   "test.com",
		Severity: "low",
	}

	_, err := n.sendGenericWebhook(context.Background(), notif)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedSecret != "" {
		t.Errorf("expected no secret header for empty secret, got %q", receivedSecret)
	}
}

func TestSendGenericWebhook_NoDiffSummary(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := &Notifier{Client: srv.Client()}
	notif := dbq.ListPendingNotificationsRow{
		Url:      srv.URL,
		Domain:   "nodiff.com",
		Severity: "medium",
	}

	_, err := n.sendGenericWebhook(context.Background(), notif)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var payload map[string]any
	json.Unmarshal(receivedBody, &payload)
	if _, ok := payload["diff_summary"]; ok {
		t.Error("diff_summary should not be present when empty")
	}
}

func TestMissionCriticalDomains(t *testing.T) {
	if len(missionCriticalDomains) == 0 {
		t.Fatal("missionCriticalDomains should not be empty")
	}
	found := false
	for _, d := range missionCriticalDomains {
		if d == "it-help.tech" {
			found = true
		}
	}
	if !found {
		t.Error("expected it-help.tech in missionCriticalDomains")
	}
}
