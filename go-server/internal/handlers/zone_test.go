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
