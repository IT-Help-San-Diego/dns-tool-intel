//go:build coverage

package handlers

import (
	"testing"
)

func TestNewTelemetryHandler_Coverage(t *testing.T) {
	h := NewTelemetryHandler(nil, nil)
	if h == nil {
		t.Fatal("expected handler")
	}
	if h.TimingsFunc != nil {
		t.Error("expected nil TimingsFunc")
	}
}
