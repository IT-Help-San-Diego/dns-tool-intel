package handlers

import (
	"dnstool/go-server/internal/handlers/badgepkg"
	"strings"
	"testing"
)

func TestOwlBadgePNG_NotEmpty(t *testing.T) {
	if badgepkg.OwlBadgePNG == "" {
		t.Fatal("badgepkg.OwlBadgePNG should not be empty")
	}
}

func TestOwlBadgePNG_HasDataURIPrefix(t *testing.T) {
	if !strings.HasPrefix(badgepkg.OwlBadgePNG, "data:image/png;base64,") {
		t.Error("badgepkg.OwlBadgePNG should start with data:image/png;base64,")
	}
}

func TestOwlBadgePNG_HasContent(t *testing.T) {
	parts := strings.SplitN(badgepkg.OwlBadgePNG, ",", 2)
	if len(parts) != 2 || len(parts[1]) < 100 {
		t.Error("badgepkg.OwlBadgePNG should contain substantial base64 data")
	}
}
