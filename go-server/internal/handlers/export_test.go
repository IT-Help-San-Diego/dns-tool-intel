package handlers

import (
        "fmt"
        "strings"
        "testing"
        "time"

        "github.com/jackc/pgx/v5/pgtype"
)

func TestNewExportHandler(t *testing.T) {
        h := NewExportHandler(nil)
        if h == nil {
                t.Fatal("expected non-nil ExportHandler")
        }
        if h.DB != nil {
                t.Error("expected nil DB")
        }
}

func TestNewExportHandlerType(t *testing.T) {
        h := NewExportHandler(nil)
        var _ *ExportHandler = h
        if h == nil {
                t.Fatal("expected non-nil ExportHandler")
        }
}

func TestExportFilenameFormat(t *testing.T) {
        ts := time.Date(2025, 6, 15, 14, 30, 45, 0, time.UTC)
        timestamp := ts.Format("20060102_150405")
        filename := fmt.Sprintf("dns_tool_export_%s.ndjson", timestamp)
        if filename != "dns_tool_export_20250615_143045.ndjson" {
                t.Errorf("unexpected filename: %s", filename)
        }
        if !strings.HasPrefix(filename, "dns_tool_export_") {
                t.Error("filename should start with dns_tool_export_")
        }
        if !strings.HasSuffix(filename, ".ndjson") {
                t.Error("filename should end with .ndjson")
        }
}

func TestFormatTimestampValid(t *testing.T) {
        ts := pgtype.Timestamp{
                Time:  time.Date(2025, 3, 15, 10, 30, 0, 0, time.UTC),
                Valid: true,
        }
        result := formatTimestamp(ts)
        if result != "15 Mar 2025, 10:30 UTC" {
                t.Errorf("formatTimestamp = %q, want %q", result, "15 Mar 2025, 10:30 UTC")
        }
}

func TestFormatTimestampInvalid(t *testing.T) {
        ts := pgtype.Timestamp{Valid: false}
        result := formatTimestamp(ts)
        if result != "" {
                t.Errorf("expected empty string for invalid timestamp, got %q", result)
        }
}

func TestFormatTimestampISOValid(t *testing.T) {
        ts := pgtype.Timestamp{
                Time:  time.Date(2025, 3, 15, 10, 30, 0, 0, time.UTC),
                Valid: true,
        }
        result := formatTimestampISO(ts)
        if result != "2025-03-15T10:30:00Z" {
                t.Errorf("formatTimestampISO = %q, want %q", result, "2025-03-15T10:30:00Z")
        }
}

func TestFormatTimestampISOInvalid(t *testing.T) {
        ts := pgtype.Timestamp{Valid: false}
        result := formatTimestampISO(ts)
        if result != "" {
                t.Errorf("expected empty string for invalid timestamp, got %q", result)
        }
}

func TestFormatTimestampISOContainsT(t *testing.T) {
        ts := pgtype.Timestamp{
                Time:  time.Date(2024, 12, 25, 0, 0, 0, 0, time.UTC),
                Valid: true,
        }
        result := formatTimestampISO(ts)
        if !strings.Contains(result, "T") {
                t.Error("ISO timestamp should contain T separator")
        }
        if !strings.HasSuffix(result, "Z") {
                t.Error("ISO timestamp should end with Z")
        }
}

func TestFormatTimestampUTCOutput(t *testing.T) {
        ts := pgtype.Timestamp{
                Time:  time.Date(2025, 1, 1, 23, 59, 59, 0, time.UTC),
                Valid: true,
        }
        result := formatTimestamp(ts)
        if !strings.HasSuffix(result, "UTC") {
                t.Error("human timestamp should end with UTC")
        }
}

func TestExportHandlerNilDB(t *testing.T) {
        h := NewExportHandler(nil)
        if h.DB != nil {
                t.Error("expected nil DB for nil input")
        }
}
