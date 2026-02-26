package handlers

import (
	"testing"
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
