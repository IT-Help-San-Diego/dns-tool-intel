package handlers

import (
        "testing"
        "time"

        "dnstool/go-server/internal/dbq"

        "github.com/jackc/pgx/v5/pgtype"
)

func TestMaskURL(t *testing.T) {
        tests := []struct {
                name     string
                input    string
                expected string
        }{
                {"short url", "https://example.com", "https://example.com"},
                {"exactly 30", "https://example.com/path12345/", "https://example.com/path12345/"},
                {"long url", "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX", "https://hooks.slack....XXXXXXXXXX"},
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
                        ID:      1,
                        Domain:  "example.com",
                        Cadence: "daily",
                        Enabled: true,
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

func TestMaxWatchlistEntries(t *testing.T) {
        if maxWatchlistEntries != 25 {
                t.Errorf("maxWatchlistEntries = %d, want 25", maxWatchlistEntries)
        }
}

func TestTimeFormatDisplay(t *testing.T) {
        ref := time.Date(2026, 2, 25, 15, 4, 0, 0, time.UTC)
        got := ref.Format(timeFormatDisplay)
        if got != "25 Feb 2026 15:04 UTC" {
                t.Errorf("timeFormatDisplay produced %q, want '25 Feb 2026 15:04 UTC'", got)
        }
}
