package wayback

import (
	"context"
	"testing"
)

func TestIsValidArchiveURL(t *testing.T) {
	tests := []struct {
		url   string
		valid bool
	}{
		{"https://web.archive.org/web/20260101/http://example.com", true},
		{"https://web.archive.org/", true},
		{"https://evil.com/web/20260101", false},
		{"http://web.archive.org/web/20260101", false},
		{"", false},
		{"https://web.archive.org", false},
	}
	for _, tt := range tests {
		if got := isValidArchiveURL(tt.url); got != tt.valid {
			t.Errorf("isValidArchiveURL(%q) = %v, want %v", tt.url, got, tt.valid)
		}
	}
}

func TestArchiveResult_Fields(t *testing.T) {
	r := ArchiveResult{URL: "https://web.archive.org/web/20260101/http://example.com", Err: nil}
	if r.URL == "" {
		t.Error("expected non-empty URL")
	}
	if r.Err != nil {
		t.Errorf("expected nil Err, got %v", r.Err)
	}
}

func TestArchive_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := Archive(ctx, "http://example.com")
	if result.Err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestConstants(t *testing.T) {
	if saveEndpoint == "" {
		t.Error("saveEndpoint is empty")
	}
	if archivePrefix == "" {
		t.Error("archivePrefix is empty")
	}
	if userAgent == "" {
		t.Error("userAgent is empty")
	}
	if httpTimeout <= 0 {
		t.Error("httpTimeout is non-positive")
	}
}
