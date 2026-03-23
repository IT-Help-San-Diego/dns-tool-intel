package handlers

import (
	"dnstool/go-server/internal/config"
	"testing"
)

func TestNewContactHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", MaintenanceNote: "Beta"}
	h := NewContactHandler(cfg)
	if h == nil {
		t.Fatal("expected non-nil")
	}
	if h.Config != cfg {
		t.Error("Config mismatch")
	}
	if h.Config.AppVersion != "1.0" {
		t.Errorf("AppVersion = %q", h.Config.AppVersion)
	}
	if h.Config.MaintenanceNote != "Beta" {
		t.Errorf("MaintenanceNote = %q", h.Config.MaintenanceNote)
	}
}

func TestNewCorpusHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "2.0"}
	h := NewCorpusHandler(cfg)
	if h == nil {
		t.Fatal("expected non-nil")
	}
	if h.Config != cfg {
		t.Error("Config mismatch")
	}
}

func TestNewPrivacyHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "3.0"}
	h := NewPrivacyHandler(cfg)
	if h == nil {
		t.Fatal("expected non-nil")
	}
	if h.Config != cfg {
		t.Error("Config mismatch")
	}
}

func TestNewReferenceLibraryHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "4.0"}
	h := NewReferenceLibraryHandler(cfg)
	if h == nil {
		t.Fatal("expected non-nil")
	}
	if h.Config != cfg {
		t.Error("Config mismatch")
	}
}

func TestNewContactHandler_NilConfig(t *testing.T) {
	h := NewContactHandler(nil)
	if h == nil {
		t.Fatal("expected non-nil")
	}
}

func TestNewCorpusHandler_NilConfig(t *testing.T) {
	h := NewCorpusHandler(nil)
	if h == nil {
		t.Fatal("expected non-nil")
	}
}

func TestNewPrivacyHandler_NilConfig(t *testing.T) {
	h := NewPrivacyHandler(nil)
	if h == nil {
		t.Fatal("expected non-nil")
	}
}

func TestNewReferenceLibraryHandler_NilConfig(t *testing.T) {
	h := NewReferenceLibraryHandler(nil)
	if h == nil {
		t.Fatal("expected non-nil")
	}
}
