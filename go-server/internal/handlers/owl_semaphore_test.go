package handlers

import (
	"dnstool/go-server/internal/config"
	"testing"
)

func TestNewOwlSemaphoreHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0"}
	h := NewOwlSemaphoreHandler(cfg)
	if h == nil {
		t.Fatal("expected non-nil")
	}
	if h.Config != cfg {
		t.Error("Config mismatch")
	}
	if h.Config.AppVersion != "1.0" {
		t.Errorf("AppVersion = %q", h.Config.AppVersion)
	}
}

func TestNewOwlSemaphoreHandler_NilConfig(t *testing.T) {
	h := NewOwlSemaphoreHandler(nil)
	if h == nil {
		t.Fatal("expected non-nil handler even with nil config")
	}
	if h.Config != nil {
		t.Error("expected nil Config")
	}
}
