package handlers

import (
	"testing"

	"dnstool/go-server/internal/botverify"
)

func TestBuildAsyncInput_PropagatesUserAgent(t *testing.T) {
	chromeUA := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
	ip := "203.0.113.7"

	inp := buildAsyncInput(chromeUA, ip, "example.com", "example.com", nil,
		false, false, false, 0, false, false)

	if inp.userAgent != chromeUA {
		t.Fatalf("userAgent not propagated: got %q, want %q", inp.userAgent, chromeUA)
	}
	if inp.clientIP != ip {
		t.Fatalf("clientIP not propagated: got %q, want %q", inp.clientIP, ip)
	}

	cls := botverify.Classify(inp.userAgent, inp.clientIP).String()
	if cls != "human" {
		t.Fatalf("Chrome UA misclassified as %q (want %q) — async scans would land in investigate bucket", cls, "human")
	}
}

func TestBuildAsyncInput_EmptyUARegression(t *testing.T) {
	inp := buildAsyncInput("", "203.0.113.7", "example.com", "example.com", nil,
		false, false, false, 0, false, false)

	cls := botverify.Classify(inp.userAgent, inp.clientIP).String()
	if cls != "investigate" {
		t.Fatalf("empty UA should classify as %q, got %q — botverify contract changed", "investigate", cls)
	}
}
