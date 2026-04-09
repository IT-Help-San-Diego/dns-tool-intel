package handlers

import (
        "testing"
        "time"

        "dnstool/go-server/internal/dbq"

        "github.com/jackc/pgx/v5/pgtype"
)

func TestCadenceToNextRun_Hourly(t *testing.T) {
        ts := cadenceToNextRun("hourly")
        if !ts.Valid {
                t.Fatal("expected valid timestamp")
        }
        diff := time.Until(ts.Time)
        if diff < 50*time.Minute || diff > 70*time.Minute {
                t.Errorf("expected ~1h from now, got %v", diff)
        }
}

func TestCadenceToNextRun_Daily(t *testing.T) {
        ts := cadenceToNextRun("daily")
        if !ts.Valid {
                t.Fatal("expected valid timestamp")
        }
        diff := time.Until(ts.Time)
        if diff < 23*time.Hour || diff > 25*time.Hour {
                t.Errorf("expected ~24h from now, got %v", diff)
        }
}

func TestCadenceToNextRun_Weekly(t *testing.T) {
        ts := cadenceToNextRun("weekly")
        if !ts.Valid {
                t.Fatal("expected valid timestamp")
        }
        diff := time.Until(ts.Time)
        expected := 7 * 24 * time.Hour
        if diff < expected-time.Hour || diff > expected+time.Hour {
                t.Errorf("expected ~7 days from now, got %v", diff)
        }
}

func TestCadenceToNextRun_Unknown(t *testing.T) {
        ts := cadenceToNextRun("unknown_cadence")
        if !ts.Valid {
                t.Fatal("expected valid timestamp")
        }
        diff := time.Until(ts.Time)
        if diff < 23*time.Hour || diff > 25*time.Hour {
                t.Errorf("expected ~24h (default) from now, got %v", diff)
        }
}

func TestMaskURL_Short(t *testing.T) {
        short := "https://hooks.slack.com"
        got := maskURL(short)
        if got != short {
                t.Errorf("expected unchanged for short URL, got %q", got)
        }
}

func TestMaskURL_Long(t *testing.T) {
        long := "https://discord.com/api/webhooks/1234567890/very-long-token-string-here"
        got := maskURL(long)
        if len(got) > 35 {
                t.Errorf("expected masked URL to be shorter, got %q (len=%d)", got, len(got))
        }
        if got[:20] != long[:20] {
                t.Error("expected first 20 chars preserved")
        }
}

func TestConvertWatchlistEntries_Empty(t *testing.T) {
        items := convertWatchlistEntries(nil)
        if len(items) != 0 {
                t.Errorf("expected 0 items, got %d", len(items))
        }
}

func TestConvertWatchlistEntries_WithData(t *testing.T) {
        now := time.Now().UTC()
        entries := []dbq.DomainWatchlist{
                {
                        ID:      1,
                        Domain:  "example.com",
                        Cadence: "daily",
                        Enabled: true,
                        LastRunAt: pgtype.Timestamp{Time: now, Valid: true},
                        NextRunAt: pgtype.Timestamp{Time: now.Add(24 * time.Hour), Valid: true},
                        CreatedAt: pgtype.Timestamp{Time: now.Add(-48 * time.Hour), Valid: true},
                },
                {
                        ID:      2,
                        Domain:  "test.com",
                        Cadence: "weekly",
                        Enabled: false,
                },
        }
        items := convertWatchlistEntries(entries)
        if len(items) != 2 {
                t.Fatalf("expected 2 items, got %d", len(items))
        }
        if items[0].Domain != "example.com" {
                t.Errorf("expected example.com, got %s", items[0].Domain)
        }
        if !items[0].Enabled {
                t.Error("expected enabled=true")
        }
        if items[0].LastRunAt == "" {
                t.Error("expected LastRunAt formatted")
        }
        if items[0].NextRunAt == "" {
                t.Error("expected NextRunAt formatted")
        }
        if items[0].CreatedAt == "" {
                t.Error("expected CreatedAt formatted")
        }
        if items[1].LastRunAt != "" {
                t.Error("expected empty LastRunAt for invalid timestamp")
        }
}


