package handlers

import (
        "testing"

        "dnstool/go-server/internal/config"
)

func TestMaxZoneFileSize(t *testing.T) {
        expected := int64(2 << 20)
        if maxZoneFileSize != expected {
                t.Errorf("maxZoneFileSize = %d, want %d", maxZoneFileSize, expected)
        }
        if maxZoneFileSize != 2*1024*1024 {
                t.Errorf("maxZoneFileSize should be 2 MB (2097152), got %d", maxZoneFileSize)
        }
}

func TestTplZone(t *testing.T) {
        if tplZone != "zone.html" {
                t.Errorf("tplZone = %q, want %q", tplZone, "zone.html")
        }
}

func TestNewZoneHandler(t *testing.T) {
        cfg := &config.Config{AppVersion: "1.0.0"}
        h := NewZoneHandler(nil, cfg)
        if h == nil {
                t.Fatal("expected non-nil ZoneHandler")
        }
        if h.DB != nil {
                t.Error("expected nil DB")
        }
        if h.Config != cfg {
                t.Error("expected Config to match")
        }
        if h.Config.AppVersion != "1.0.0" {
                t.Errorf("expected AppVersion '1.0.0', got %s", h.Config.AppVersion)
        }
}

func TestNewZoneHandlerWithConfig(t *testing.T) {
        cfg := &config.Config{
                AppVersion:      "2.0.0",
                MaintenanceNote: "test note",
        }
        h := NewZoneHandler(nil, cfg)
        if h.Config.MaintenanceNote != "test note" {
                t.Errorf("expected MaintenanceNote 'test note', got %s", h.Config.MaintenanceNote)
        }
}

func TestMaxZoneFileSizeIs2MB(t *testing.T) {
        if maxZoneFileSize < 1024*1024 {
                t.Error("maxZoneFileSize should be at least 1 MB")
        }
        if maxZoneFileSize > 10*1024*1024 {
                t.Error("maxZoneFileSize should not exceed 10 MB")
        }
}

func TestZoneHandlerStructFields(t *testing.T) {
        cfg := &config.Config{
                AppVersion:      "3.0.0",
                MaintenanceNote: "maintenance",
                BetaPages:       map[string]bool{"zone": true},
        }
        h := NewZoneHandler(nil, cfg)
        if h.Config.AppVersion != "3.0.0" {
                t.Errorf("AppVersion = %q, want %q", h.Config.AppVersion, "3.0.0")
        }
        if h.Config.MaintenanceNote != "maintenance" {
                t.Errorf("MaintenanceNote = %q, want %q", h.Config.MaintenanceNote, "maintenance")
        }
        if !h.Config.BetaPages["zone"] {
                t.Error("BetaPages[zone] should be true")
        }
}

func TestFlashMessageStruct(t *testing.T) {
        tests := []struct {
                name     string
                category string
                message  string
        }{
                {"danger flash", "danger", "Something went wrong"},
                {"warning flash", "warning", "No records found"},
                {"success flash", "success", "Upload complete"},
                {"info flash", "info", "Processing..."},
                {"empty message", "", ""},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        fm := FlashMessage{Category: tt.category, Message: tt.message}
                        if fm.Category != tt.category {
                                t.Errorf("Category = %q, want %q", fm.Category, tt.category)
                        }
                        if fm.Message != tt.message {
                                t.Errorf("Message = %q, want %q", fm.Message, tt.message)
                        }
                })
        }
}

func TestZoneHandlerNilDB(t *testing.T) {
        h := NewZoneHandler(nil, &config.Config{})
        if h.DB != nil {
                t.Error("expected DB to be nil")
        }
}

func TestZoneHandlerNilConfig(t *testing.T) {
        h := NewZoneHandler(nil, nil)
        if h == nil {
                t.Fatal("expected non-nil handler even with nil config")
        }
        if h.Config != nil {
                t.Error("expected nil Config")
        }
}
