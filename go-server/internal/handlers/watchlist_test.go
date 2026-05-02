//go:build bigtests

package handlers

import (
        "context"
        "fmt"
        "html/template"
        "net/http"
        "net/http/httptest"
        "net/url"
        "os"
        "strings"
        "testing"
        "time"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
        "github.com/jackc/pgx/v5/pgtype"
)

func watchlistTestDB(t *testing.T) *db.Database {
        t.Helper()
        dbURL := os.Getenv("DATABASE_URL")
        if dbURL == "" {
                t.Skip("DATABASE_URL not set")
        }
        database, err := db.ConnectForTests(dbURL)
        if err != nil {
                t.Fatalf("connect: %v", err)
        }
        t.Cleanup(func() { database.Close() })
        return database
}

func watchlistConfig() *config.Config {
        return &config.Config{
                AppVersion:    "test",
                BetaPages:     map[string]bool{},
                SectionTuning: map[string]string{},
        }
}

func watchlistRouter() *gin.Engine {
        gin.SetMode(gin.TestMode)
        r := gin.New()
        r.Use(func(c *gin.Context) {
                c.Set("csp_nonce", "test-nonce")
                c.Set("csrf_token", "test-csrf")
                c.Next()
        })
        tmpl := template.New("root")
        template.Must(tmpl.New("watchlist.html").Parse(`OK`))
        r.SetHTMLTemplate(tmpl)
        return r
}

func watchlistRouterWithUser(userID int32) *gin.Engine {
        r := watchlistRouter()
        r.Use(func(c *gin.Context) {
                c.Set("user_id", userID)
                c.Next()
        })
        return r
}

func TestMaskURL(t *testing.T) {
        tests := []struct {
                name     string
                input    string
                expected string
        }{
                {"short url", "https://example.com", "https://example.com"},
                {"exactly 30", "https://example.com/path12345/", "https://example.com/path12345/"},
                {"long url", "https://example.com/very-long-webhook-path/callbacks/abc123def456/XXXXXXXXXXXXXXXXXXXXXXXX", "https://example.com/...XXXXXXXXXX"},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        got := maskURL(tc.input)
                        if got != tc.expected {
                                t.Errorf("maskURL(%q) = %q, want %q", tc.input, got, tc.expected)
                        }
                })
        }
}

func TestCadenceToNextRun(t *testing.T) {
        tests := []struct {
                name     string
                cadence  string
                minHours float64
                maxHours float64
        }{
                {"hourly", "hourly", 0.9, 1.1},
                {"daily", "daily", 23.9, 24.1},
                {"weekly", "weekly", 167.9, 168.1},
                {"default", "unknown", 23.9, 24.1},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        before := time.Now().UTC()
                        result := cadenceToNextRun(tc.cadence)
                        if !result.Valid {
                                t.Fatal("expected valid timestamp")
                        }
                        diff := result.Time.Sub(before).Hours()
                        if diff < tc.minHours || diff > tc.maxHours {
                                t.Errorf("cadenceToNextRun(%q) diff = %f hours, want between %f and %f", tc.cadence, diff, tc.minHours, tc.maxHours)
                        }
                })
        }
}

func TestConvertWatchlistEntries(t *testing.T) {
        now := time.Now().UTC()
        entries := []dbq.DomainWatchlist{
                {
                        ID:        1,
                        Domain:    "example.com",
                        Cadence:   "daily",
                        Enabled:   true,
                        LastRunAt: pgtype.Timestamp{Time: now.Add(-1 * time.Hour), Valid: true},
                        NextRunAt: pgtype.Timestamp{Time: now.Add(23 * time.Hour), Valid: true},
                        CreatedAt: pgtype.Timestamp{Time: now.Add(-24 * time.Hour), Valid: true},
                },
                {
                        ID:      2,
                        Domain:  "test.org",
                        Cadence: "weekly",
                        Enabled: false,
                },
        }

        items := convertWatchlistEntries(entries)
        if len(items) != 2 {
                t.Fatalf("expected 2 items, got %d", len(items))
        }

        if items[0].ID != 1 || items[0].Domain != "example.com" || items[0].Cadence != "daily" || !items[0].Enabled {
                t.Errorf("unexpected first item: %+v", items[0])
        }
        if items[0].LastRunAt == "" {
                t.Error("expected non-empty LastRunAt for valid timestamp")
        }
        if items[0].NextRunAt == "" {
                t.Error("expected non-empty NextRunAt for valid timestamp")
        }
        if items[0].CreatedAt == "" {
                t.Error("expected non-empty CreatedAt for valid timestamp")
        }

        if items[1].LastRunAt != "" {
                t.Error("expected empty LastRunAt for invalid timestamp")
        }
        if items[1].NextRunAt != "" {
                t.Error("expected empty NextRunAt for invalid timestamp")
        }
        if items[1].CreatedAt != "" {
                t.Error("expected empty CreatedAt for invalid timestamp")
        }
}

func TestConvertWatchlistEntriesEmpty(t *testing.T) {
        items := convertWatchlistEntries(nil)
        if len(items) != 0 {
                t.Errorf("expected 0 items, got %d", len(items))
        }
}

func TestTimeFormatDisplay(t *testing.T) {
        ref := time.Date(2026, 2, 25, 15, 4, 0, 0, time.UTC)
        got := ref.Format(timeFormatDisplay)
        if got != "25 Feb 2026 15:04 UTC" {
                t.Errorf("timeFormatDisplay produced %q, want '25 Feb 2026 15:04 UTC'", got)
        }
}

func TestMaskURLEdgeCases(t *testing.T) {
        tests := []struct {
                name     string
                input    string
                expected string
        }{
                {"empty string", "", ""},
                {"single char", "x", "x"},
                {"exactly 31 chars", "1234567890123456789012345678901", "12345678901234567890...2345678901"},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        got := maskURL(tc.input)
                        if got != tc.expected {
                                t.Errorf("maskURL(%q) = %q, want %q", tc.input, got, tc.expected)
                        }
                })
        }
}

func TestCadenceToNextRunValid(t *testing.T) {
        result := cadenceToNextRun("hourly")
        if !result.Valid {
                t.Fatal("expected valid timestamp")
        }
        if result.Time.Before(time.Now().UTC()) {
                t.Error("expected future timestamp")
        }
}

func TestConvertWatchlistEntriesAllFieldsPresent(t *testing.T) {
        now := time.Now().UTC()
        entries := []dbq.DomainWatchlist{
                {
                        ID:        42,
                        Domain:    "sub.example.com",
                        Cadence:   "hourly",
                        Enabled:   false,
                        LastRunAt: pgtype.Timestamp{Time: now, Valid: true},
                        NextRunAt: pgtype.Timestamp{Time: now.Add(time.Hour), Valid: true},
                        CreatedAt: pgtype.Timestamp{Time: now.Add(-48 * time.Hour), Valid: true},
                },
        }

        items := convertWatchlistEntries(entries)
        if len(items) != 1 {
                t.Fatalf("expected 1 item, got %d", len(items))
        }
        item := items[0]
        if item.ID != 42 {
                t.Errorf("ID = %d, want 42", item.ID)
        }
        if item.Domain != "sub.example.com" {
                t.Errorf("Domain = %q, want sub.example.com", item.Domain)
        }
        if item.Cadence != "hourly" {
                t.Errorf("Cadence = %q, want hourly", item.Cadence)
        }
        if item.Enabled {
                t.Error("expected Enabled=false")
        }
}

func TestConvertWatchlistEntriesNoValidTimestamps(t *testing.T) {
        entries := []dbq.DomainWatchlist{
                {
                        ID:      1,
                        Domain:  "notime.com",
                        Cadence: "weekly",
                        Enabled: true,
                },
        }
        items := convertWatchlistEntries(entries)
        if items[0].LastRunAt != "" || items[0].NextRunAt != "" || items[0].CreatedAt != "" {
                t.Error("expected empty time strings for invalid timestamps")
        }
}

func TestWatchlist_Unauthenticated_RendersPage(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := watchlistConfig()
        router := watchlistRouter()
        handler := NewWatchlistHandler(database, cfg)
        router.GET("/watchlist", handler.Watchlist)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/watchlist", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("Watchlist unauthenticated: got %d, want 200", w.Code)
        }
}

func TestAddDomain_Unauthenticated_Redirects(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := watchlistConfig()
        router := watchlistRouter()
        handler := NewWatchlistHandler(database, cfg)
        router.POST("/watchlist/add", handler.AddDomain)

        form := url.Values{}
        form.Set("domain", "example.com")
        form.Set("cadence", "daily")
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/watchlist/add", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        router.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("AddDomain unauthenticated: got %d, want 303", w.Code)
        }
}

func TestAddDomain_EmptyDomain_Redirects(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := watchlistConfig()
        router := watchlistRouterWithUser(1)
        handler := NewWatchlistHandler(database, cfg)
        router.POST("/watchlist/add", handler.AddDomain)

        form := url.Values{}
        form.Set("domain", "")
        form.Set("cadence", "daily")
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/watchlist/add", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        router.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("AddDomain empty domain: got %d, want 303", w.Code)
        }
}

func TestAddDomain_InvalidCadence_DefaultsToDaily(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := watchlistConfig()
        router := watchlistRouterWithUser(1)
        handler := NewWatchlistHandler(database, cfg)
        router.POST("/watchlist/add", handler.AddDomain)

        form := url.Values{}
        form.Set("domain", "test-cadence.example.com")
        form.Set("cadence", "every-5-minutes")
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/watchlist/add", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        router.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("AddDomain invalid cadence: got %d, want 303 redirect", w.Code)
        }
}

func TestRemoveDomain_Unauthenticated_Redirects(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := watchlistConfig()
        router := watchlistRouter()
        handler := NewWatchlistHandler(database, cfg)
        router.POST("/watchlist/remove/:id", handler.RemoveDomain)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/watchlist/remove/1", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("RemoveDomain unauthenticated: got %d, want 303", w.Code)
        }
}

func TestRemoveDomain_BadID_Redirects(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := watchlistConfig()
        router := watchlistRouterWithUser(1)
        handler := NewWatchlistHandler(database, cfg)
        router.POST("/watchlist/remove/:id", handler.RemoveDomain)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/watchlist/remove/notanumber", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("RemoveDomain bad ID: got %d, want 303", w.Code)
        }
}

func TestToggleDomain_Unauthenticated_Redirects(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := watchlistConfig()
        router := watchlistRouter()
        handler := NewWatchlistHandler(database, cfg)
        router.POST("/watchlist/toggle/:id", handler.ToggleDomain)

        form := url.Values{}
        form.Set("enabled", "true")
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/watchlist/toggle/1", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        router.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("ToggleDomain unauthenticated: got %d, want 303", w.Code)
        }
}

func TestToggleDomain_BadID_Redirects(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := watchlistConfig()
        router := watchlistRouterWithUser(1)
        handler := NewWatchlistHandler(database, cfg)
        router.POST("/watchlist/toggle/:id", handler.ToggleDomain)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/watchlist/toggle/notanumber", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("ToggleDomain bad ID: got %d, want 303", w.Code)
        }
}

func TestAddEndpoint_Unauthenticated_Redirects(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := watchlistConfig()
        router := watchlistRouter()
        handler := NewWatchlistHandler(database, cfg)
        router.POST("/watchlist/endpoint/add", handler.AddEndpoint)

        form := url.Values{}
        form.Set("url", "https://hooks.example.com/callback")
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/watchlist/endpoint/add", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        router.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("AddEndpoint unauthenticated: got %d, want 303", w.Code)
        }
}

func TestAddEndpoint_EmptyURL_Redirects(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := watchlistConfig()
        router := watchlistRouterWithUser(1)
        handler := NewWatchlistHandler(database, cfg)
        router.POST("/watchlist/endpoint/add", handler.AddEndpoint)

        form := url.Values{}
        form.Set("url", "")
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/watchlist/endpoint/add", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        router.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("AddEndpoint empty URL: got %d, want 303", w.Code)
        }
}

func TestAddEndpoint_NonHTTPScheme_Redirects(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := watchlistConfig()
        router := watchlistRouterWithUser(1)
        handler := NewWatchlistHandler(database, cfg)
        router.POST("/watchlist/endpoint/add", handler.AddEndpoint)

        form := url.Values{}
        form.Set("url", "ftp://evil.example.com/malware")
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/watchlist/endpoint/add", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        router.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("AddEndpoint non-http scheme: got %d, want 303", w.Code)
        }
}

func TestRemoveEndpoint_Unauthenticated_Redirects(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := watchlistConfig()
        router := watchlistRouter()
        handler := NewWatchlistHandler(database, cfg)
        router.POST("/watchlist/endpoint/remove/:id", handler.RemoveEndpoint)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/watchlist/endpoint/remove/1", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("RemoveEndpoint unauthenticated: got %d, want 303", w.Code)
        }
}

func TestRemoveEndpoint_BadID_Redirects(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := watchlistConfig()
        router := watchlistRouterWithUser(1)
        handler := NewWatchlistHandler(database, cfg)
        router.POST("/watchlist/endpoint/remove/:id", handler.RemoveEndpoint)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/watchlist/endpoint/remove/xyz", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("RemoveEndpoint bad ID: got %d, want 303", w.Code)
        }
}

func TestToggleEndpoint_Unauthenticated_Redirects(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := watchlistConfig()
        router := watchlistRouter()
        handler := NewWatchlistHandler(database, cfg)
        router.POST("/watchlist/endpoint/toggle/:id", handler.ToggleEndpoint)

        form := url.Values{}
        form.Set("enabled", "true")
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/watchlist/endpoint/toggle/1", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        router.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("ToggleEndpoint unauthenticated: got %d, want 303", w.Code)
        }
}

func TestToggleEndpoint_BadID_Redirects(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := watchlistConfig()
        router := watchlistRouterWithUser(1)
        handler := NewWatchlistHandler(database, cfg)
        router.POST("/watchlist/endpoint/toggle/:id", handler.ToggleEndpoint)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/watchlist/endpoint/toggle/xyz", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("ToggleEndpoint bad ID: got %d, want 303", w.Code)
        }
}

func TestTestWebhook_NoURL_Redirects(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := watchlistConfig()
        cfg.DiscordWebhookURL = ""
        router := watchlistRouter()
        handler := NewWatchlistHandler(database, cfg)
        router.POST("/watchlist/test-webhook", handler.TestWebhook)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/watchlist/test-webhook", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("TestWebhook no URL: got %d, want 303", w.Code)
        }
}

func TestRemoveDomain_OwnershipEnforced(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := watchlistConfig()

        router := watchlistRouterWithUser(99999)
        handler := NewWatchlistHandler(database, cfg)
        router.POST("/watchlist/remove/:id", handler.RemoveDomain)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/watchlist/remove/1", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("RemoveDomain cross-user: got %d, want 303 redirect", w.Code)
        }
}

func TestToggleDomain_OwnershipEnforced(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := watchlistConfig()

        router := watchlistRouterWithUser(99999)
        handler := NewWatchlistHandler(database, cfg)
        router.POST("/watchlist/toggle/:id", handler.ToggleDomain)

        form := url.Values{}
        form.Set("enabled", "true")
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/watchlist/toggle/1", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        router.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("ToggleDomain cross-user: got %d, want 303 redirect", w.Code)
        }
}

func TestRemoveEndpoint_OwnershipEnforced(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := watchlistConfig()

        router := watchlistRouterWithUser(99999)
        handler := NewWatchlistHandler(database, cfg)
        router.POST("/watchlist/endpoint/remove/:id", handler.RemoveEndpoint)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/watchlist/endpoint/remove/1", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("RemoveEndpoint cross-user: got %d, want 303", w.Code)
        }
}

func TestToggleEndpoint_OwnershipEnforced(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := watchlistConfig()

        router := watchlistRouterWithUser(99999)
        handler := NewWatchlistHandler(database, cfg)
        router.POST("/watchlist/endpoint/toggle/:id", handler.ToggleEndpoint)

        form := url.Values{}
        form.Set("enabled", "true")
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/watchlist/endpoint/toggle/1", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        router.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("ToggleEndpoint cross-user: got %d, want 303", w.Code)
        }
}

func TestRemoveEndpoint_OwnershipEnforced_StateVerified(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := watchlistConfig()

        ctx := context.Background()
        ownerID := ensureTestUser(t, database)

        row, err := database.Queries.InsertNotificationEndpoint(ctx, dbq.InsertNotificationEndpointParams{
                UserID:       ownerID,
                EndpointType: "webhook",
                Url:          "https://ownership-test-endpoint.example.com/hook",
                Secret:       nil,
        })
        if err != nil {
                t.Fatalf("failed to insert test endpoint: %v", err)
        }
        endpointID := row.ID
        t.Cleanup(func() {
                _, _ = database.Pool.Exec(ctx, `DELETE FROM notification_endpoints WHERE id = $1`, endpointID)
        })

        attackerID := int32(99999)
        router := watchlistRouterWithUser(attackerID)
        handler := NewWatchlistHandler(database, cfg)
        router.POST("/watchlist/endpoint/remove/:id", handler.RemoveEndpoint)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/watchlist/endpoint/remove/%d", endpointID), nil)
        router.ServeHTTP(w, req)

        var exists bool
        err = database.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM notification_endpoints WHERE id = $1)`, endpointID).Scan(&exists)
        if err != nil {
                t.Fatalf("failed to verify endpoint: %v", err)
        }
        if !exists {
                t.Fatal("ownership violation: attacker user_id=99999 deleted endpoint belonging to another user")
        }
}

func TestToggleEndpoint_OwnershipEnforced_StateVerified(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := watchlistConfig()

        ctx := context.Background()
        ownerID := ensureTestUser(t, database)

        row, err := database.Queries.InsertNotificationEndpoint(ctx, dbq.InsertNotificationEndpointParams{
                UserID:       ownerID,
                EndpointType: "webhook",
                Url:          "https://toggle-ownership-test.example.com/hook",
                Secret:       nil,
        })
        if err != nil {
                t.Fatalf("failed to insert test endpoint: %v", err)
        }
        endpointID := row.ID
        t.Cleanup(func() {
                _, _ = database.Pool.Exec(ctx, `DELETE FROM notification_endpoints WHERE id = $1`, endpointID)
        })

        var enabledBefore bool
        _ = database.Pool.QueryRow(ctx, `SELECT enabled FROM notification_endpoints WHERE id = $1`, endpointID).Scan(&enabledBefore)

        attackerID := int32(99999)
        router := watchlistRouterWithUser(attackerID)
        handler := NewWatchlistHandler(database, cfg)
        router.POST("/watchlist/endpoint/toggle/:id", handler.ToggleEndpoint)

        form := url.Values{}
        form.Set("enabled", fmt.Sprintf("%t", !enabledBefore))
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/watchlist/endpoint/toggle/%d", endpointID), strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        router.ServeHTTP(w, req)

        var enabledAfter bool
        _ = database.Pool.QueryRow(ctx, `SELECT enabled FROM notification_endpoints WHERE id = $1`, endpointID).Scan(&enabledAfter)
        if enabledAfter != enabledBefore {
                t.Fatalf("ownership violation: attacker user_id=99999 toggled endpoint enabled from %t to %t on another user's endpoint", enabledBefore, enabledAfter)
        }
}

func TestAddDomain_DomainWithSpaces_Trimmed(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := watchlistConfig()
        router := watchlistRouterWithUser(1)
        handler := NewWatchlistHandler(database, cfg)
        router.POST("/watchlist/add", handler.AddDomain)

        form := url.Values{}
        form.Set("domain", "  Example.COM  ")
        form.Set("cadence", "daily")
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/watchlist/add", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        router.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("AddDomain trimmed: got %d, want 303", w.Code)
        }
}

func ensureTestUser(t *testing.T, database *db.Database) int32 {
        t.Helper()
        ctx := context.Background()
        var id int32
        err := database.Pool.QueryRow(ctx, `SELECT id FROM users LIMIT 1`).Scan(&id)
        if err == nil {
                return id
        }
        testSub := fmt.Sprintf("test-sub-%d", time.Now().UnixNano())
        err = database.Pool.QueryRow(ctx,
                `INSERT INTO users (email, name, google_sub, role) VALUES ($1, 'Test User', $2, 'user') RETURNING id`,
                fmt.Sprintf("watchlist-test-%d@example.com", time.Now().UnixNano()), testSub).Scan(&id)
        if err != nil {
                t.Skipf("cannot create test user: %v", err)
        }
        t.Cleanup(func() {
                _, _ = database.Pool.Exec(context.Background(), `DELETE FROM domain_watchlist WHERE user_id = $1`, id)
                _, _ = database.Pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, id)
        })
        return id
}

func TestRemoveDomain_OwnershipEnforced_StateVerified(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := watchlistConfig()

        ctx := context.Background()
        ownerID := ensureTestUser(t, database)

        row, err := database.Queries.InsertWatchlistEntry(ctx, dbq.InsertWatchlistEntryParams{
                UserID:    ownerID,
                Domain:    "ownership-test-remove.example.com",
                Cadence:   "daily",
                NextRunAt: cadenceToNextRun("daily"),
        })
        if err != nil {
                t.Fatalf("failed to insert test entry: %v", err)
        }
        entryID := row.ID
        t.Cleanup(func() {
                _, _ = database.Pool.Exec(ctx, `DELETE FROM domain_watchlist WHERE id = $1`, entryID)
        })

        attackerID := int32(99999)
        router := watchlistRouterWithUser(attackerID)
        handler := NewWatchlistHandler(database, cfg)
        router.POST("/watchlist/remove/:id", handler.RemoveDomain)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/watchlist/remove/%d", entryID), nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("cross-user remove: got %d, want 303 redirect", w.Code)
        }

        var exists bool
        err = database.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM domain_watchlist WHERE id = $1)`, entryID).Scan(&exists)
        if err != nil {
                t.Fatalf("failed to verify entry: %v", err)
        }
        if !exists {
                t.Fatal("ownership violation: attacker user_id=99999 deleted entry belonging to another user")
        }
}

func TestToggleDomain_OwnershipEnforced_StateVerified(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := watchlistConfig()

        ctx := context.Background()
        ownerID := ensureTestUser(t, database)

        row, err := database.Queries.InsertWatchlistEntry(ctx, dbq.InsertWatchlistEntryParams{
                UserID:    ownerID,
                Domain:    "ownership-test-toggle.example.com",
                Cadence:   "daily",
                NextRunAt: cadenceToNextRun("daily"),
        })
        if err != nil {
                t.Fatalf("failed to insert test entry: %v", err)
        }
        entryID := row.ID
        t.Cleanup(func() {
                _, _ = database.Pool.Exec(ctx, `DELETE FROM domain_watchlist WHERE id = $1`, entryID)
        })

        var enabledBefore bool
        _ = database.Pool.QueryRow(ctx, `SELECT enabled FROM domain_watchlist WHERE id = $1`, entryID).Scan(&enabledBefore)

        attackerID := int32(99999)
        router := watchlistRouterWithUser(attackerID)
        handler := NewWatchlistHandler(database, cfg)
        router.POST("/watchlist/toggle/:id", handler.ToggleDomain)

        form := url.Values{}
        form.Set("enabled", fmt.Sprintf("%t", !enabledBefore))
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/watchlist/toggle/%d", entryID), strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        router.ServeHTTP(w, req)

        var enabledAfter bool
        _ = database.Pool.QueryRow(ctx, `SELECT enabled FROM domain_watchlist WHERE id = $1`, entryID).Scan(&enabledAfter)
        if enabledAfter != enabledBefore {
                t.Fatalf("ownership violation: attacker user_id=99999 toggled enabled from %t to %t on another user's entry", enabledBefore, enabledAfter)
        }
}

func TestAddDomain_RateLimitRejection_ExceedsMax(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := watchlistConfig()

        ctx := context.Background()
        ownerID := ensureTestUser(t, database)

        count, err := database.Queries.CountWatchlistByUser(ctx, ownerID)
        if err != nil {
                t.Fatalf("count watchlist: %v", err)
        }

        var insertedIDs []int32
        needed := int64(maxWatchlistEntries) - count
        for i := int64(0); i < needed; i++ {
                domain := fmt.Sprintf("ratelimit-test-%d.example.com", i)
                row, err := database.Queries.InsertWatchlistEntry(ctx, dbq.InsertWatchlistEntryParams{
                        UserID:    ownerID,
                        Domain:    domain,
                        Cadence:   "daily",
                        NextRunAt: cadenceToNextRun("daily"),
                })
                if err != nil {
                        t.Fatalf("failed to insert filler entry %d: %v", i, err)
                }
                insertedIDs = append(insertedIDs, row.ID)
        }
        t.Cleanup(func() {
                for _, id := range insertedIDs {
                        _, _ = database.Pool.Exec(ctx, `DELETE FROM domain_watchlist WHERE id = $1`, id)
                }
        })

        newCount, _ := database.Queries.CountWatchlistByUser(ctx, ownerID)
        if newCount < int64(maxWatchlistEntries) {
                t.Fatalf("setup: expected count >= %d, got %d", maxWatchlistEntries, newCount)
        }

        router := watchlistRouterWithUser(ownerID)
        handler := NewWatchlistHandler(database, cfg)
        router.POST("/watchlist/add", handler.AddDomain)

        form := url.Values{}
        form.Set("domain", "one-too-many.example.com")
        form.Set("cadence", "daily")
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/watchlist/add", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        router.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("AddDomain over-limit: got %d, want 303", w.Code)
        }

        var exists bool
        _ = database.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM domain_watchlist WHERE domain = $1 AND user_id = $2)`,
                "one-too-many.example.com", ownerID).Scan(&exists)
        if exists {
                t.Fatal("rate limit bypassed: 26th entry was inserted despite count >= maxWatchlistEntries")
                _, _ = database.Pool.Exec(ctx, `DELETE FROM domain_watchlist WHERE domain = $1 AND user_id = $2`, "one-too-many.example.com", ownerID)
        }
}

func TestTestWebhook_NoURLConfigured_RedirectsWithoutPanic(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := &config.Config{
                AppVersion:    "test",
                BetaPages:     map[string]bool{},
                SectionTuning: map[string]string{},
        }

        ownerID := ensureTestUser(t, database)
        router := watchlistRouterWithUser(ownerID)
        handler := NewWatchlistHandler(database, cfg)
        router.POST("/watchlist/test-webhook", handler.TestWebhook)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/watchlist/test-webhook", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusSeeOther {
                t.Fatalf("TestWebhook with no URL configured: want 303, got %d", w.Code)
        }
        loc := w.Header().Get("Location")
        if loc != pathWatchlist {
                t.Errorf("TestWebhook redirect location = %q, want %q", loc, pathWatchlist)
        }
}

func TestTestWebhook_WithURL_InvokesNotifierWithCorrectURL(t *testing.T) {
        database := watchlistTestDB(t)
        expectedURL := "https://discord.com/api/webhooks/test/token123"
        cfg := &config.Config{
                AppVersion:        "test",
                BetaPages:         map[string]bool{},
                SectionTuning:     map[string]string{},
                DiscordWebhookURL: expectedURL,
        }

        var capturedURL string
        var capturedCtx context.Context

        ownerID := ensureTestUser(t, database)
        router := watchlistRouterWithUser(ownerID)
        handler := NewWatchlistHandler(database, cfg)
        handler.TestWebhookFunc = func(ctx context.Context, webhookURL string) error {
                capturedURL = webhookURL
                capturedCtx = ctx
                return nil
        }
        router.POST("/watchlist/test-webhook", handler.TestWebhook)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/watchlist/test-webhook", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusSeeOther {
                t.Fatalf("TestWebhook: want 303 redirect, got %d", w.Code)
        }
        if capturedURL != expectedURL {
                t.Fatalf("TestWebhookFunc received URL = %q, want %q", capturedURL, expectedURL)
        }
        if capturedCtx == nil {
                t.Fatal("TestWebhookFunc was not called or received nil context")
        }
}

func TestTestWebhook_WithURL_NotifierError_StillRedirects(t *testing.T) {
        database := watchlistTestDB(t)
        cfg := &config.Config{
                AppVersion:        "test",
                BetaPages:         map[string]bool{},
                SectionTuning:     map[string]string{},
                DiscordWebhookURL: "https://discord.com/api/webhooks/test/fail",
        }

        ownerID := ensureTestUser(t, database)
        router := watchlistRouterWithUser(ownerID)
        handler := NewWatchlistHandler(database, cfg)
        handler.TestWebhookFunc = func(ctx context.Context, webhookURL string) error {
                return fmt.Errorf("simulated webhook delivery failure")
        }
        router.POST("/watchlist/test-webhook", handler.TestWebhook)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/watchlist/test-webhook", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusSeeOther {
                t.Fatalf("TestWebhook on notifier error: want 303 redirect (error logged, not returned), got %d", w.Code)
        }
}
