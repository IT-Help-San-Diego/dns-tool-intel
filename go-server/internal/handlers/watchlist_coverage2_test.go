package handlers

import (
        "strings"
        "testing"
        "time"

        "dnstool/go-server/internal/dbq"

        "github.com/jackc/pgx/v5/pgtype"
)

func TestCadenceToNextRun_Hourly_C2(t *testing.T) {
        ts := cadenceToNextRun("hourly")
        if !ts.Valid {
                t.Fatal("expected valid timestamp")
        }
        diff := time.Until(ts.Time)
        if diff < 50*time.Minute || diff > 70*time.Minute {
                t.Errorf("expected ~1h for hourly, got %v", diff)
        }
}

func TestCadenceToNextRun_Weekly_C2(t *testing.T) {
        ts := cadenceToNextRun("weekly")
        if !ts.Valid {
                t.Fatal("expected valid timestamp")
        }
        diff := time.Until(ts.Time)
        expected := 7 * 24 * time.Hour
        if diff < expected-time.Hour || diff > expected+time.Hour {
                t.Errorf("expected ~7 days for weekly, got %v", diff)
        }
}

func TestCadenceToNextRun_Default_C2(t *testing.T) {
        ts := cadenceToNextRun("unknown_cadence")
        if !ts.Valid {
                t.Fatal("expected valid timestamp")
        }
        diff := time.Until(ts.Time)
        if diff < 23*time.Hour || diff > 25*time.Hour {
                t.Errorf("expected ~24h (default) for unknown cadence, got %v", diff)
        }
}

func TestMaskURL_Short_C2(t *testing.T) {
        url20 := "12345678901234567890"
        got := maskURL(url20)
        if got != url20 {
                t.Error("expected unchanged for short URL")
        }
}

func TestMaskURL_Exactly30_C2(t *testing.T) {
        url30 := "123456789012345678901234567890"
        got := maskURL(url30)
        if got != url30 {
                t.Errorf("expected unchanged for exactly 30 char URL, got %q", got)
        }
}

func TestMaskURL_Over30_C2(t *testing.T) {
        url35 := "12345678901234567890123456789012345"
        got := maskURL(url35)
        if len(got) >= len(url35) {
                t.Errorf("expected masked (shorter) URL, got %q", got)
        }
        if !strings.Contains(got, "...") {
                t.Errorf("expected ... in masked URL, got %q", got)
        }
}

func TestConvertWatchlistEntries_NilTimestamps_C2(t *testing.T) {
        entries := []dbq.DomainWatchlist{
                {
                        ID:      1,
                        Domain:  "test.com",
                        Cadence: "daily",
                        Enabled: true,
                },
        }
        items := convertWatchlistEntries(entries)
        if len(items) != 1 {
                t.Fatalf("expected 1 item, got %d", len(items))
        }
        if items[0].LastRunAt != "" {
                t.Error("expected empty LastRunAt for nil timestamp")
        }
        if items[0].NextRunAt != "" {
                t.Error("expected empty NextRunAt for nil timestamp")
        }
        if items[0].CreatedAt != "" {
                t.Error("expected empty CreatedAt for nil timestamp")
        }
}

func TestConvertWatchlistEntries_AllValid_C2(t *testing.T) {
        now := time.Now().UTC()
        entries := []dbq.DomainWatchlist{
                {
                        ID:        1,
                        Domain:    "example.com",
                        Cadence:   "hourly",
                        Enabled:   true,
                        LastRunAt: pgtype.Timestamp{Time: now, Valid: true},
                        NextRunAt: pgtype.Timestamp{Time: now.Add(1 * time.Hour), Valid: true},
                        CreatedAt: pgtype.Timestamp{Time: now.Add(-24 * time.Hour), Valid: true},
                },
                {
                        ID:        2,
                        Domain:    "test.org",
                        Cadence:   "weekly",
                        Enabled:   false,
                        LastRunAt: pgtype.Timestamp{Time: now.Add(-7 * 24 * time.Hour), Valid: true},
                        NextRunAt: pgtype.Timestamp{Time: now.Add(7 * 24 * time.Hour), Valid: true},
                        CreatedAt: pgtype.Timestamp{Time: now.Add(-30 * 24 * time.Hour), Valid: true},
                },
        }
        items := convertWatchlistEntries(entries)
        if len(items) != 2 {
                t.Fatalf("expected 2 items, got %d", len(items))
        }
        for i, item := range items {
                if item.Domain == "" {
                        t.Errorf("item %d: expected non-empty domain", i)
                }
                if item.LastRunAt == "" {
                        t.Errorf("item %d: expected non-empty LastRunAt", i)
                }
                if item.NextRunAt == "" {
                        t.Errorf("item %d: expected non-empty NextRunAt", i)
                }
                if item.CreatedAt == "" {
                        t.Errorf("item %d: expected non-empty CreatedAt", i)
                }
        }
        if items[0].Cadence != "hourly" {
                t.Errorf("expected cadence=hourly, got %s", items[0].Cadence)
        }
        if items[1].Enabled {
                t.Error("expected second item disabled")
        }
}

func TestConvertWatchlistEntries_Empty_C2(t *testing.T) {
        items := convertWatchlistEntries(nil)
        if items == nil {
                t.Error("expected non-nil for nil input")
        }
        if len(items) != 0 {
                t.Errorf("expected 0 items, got %d", len(items))
        }
}
