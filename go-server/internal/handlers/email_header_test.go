package handlers

import (
	"testing"

	"dnstool/go-server/internal/config"
)

func TestNewEmailHeaderHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0.0"}
	h := NewEmailHeaderHandler(cfg)
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
	if h.Config != cfg {
		t.Error("expected Config to be set")
	}
}

func TestEmailHeaderConstants(t *testing.T) {
	if emailHeaderTemplate != "email_header.html" {
		t.Errorf("unexpected emailHeaderTemplate: %q", emailHeaderTemplate)
	}
	if activePageEmailHeader != "email-header" {
		t.Errorf("unexpected activePageEmailHeader: %q", activePageEmailHeader)
	}
	if maxHeaderSize != 256*1024 {
		t.Errorf("unexpected maxHeaderSize: %d", maxHeaderSize)
	}
}
