package analyzer

import (
	"testing"
)

func TestIsHostedEmailProvider_VariousInputs(t *testing.T) {
	known := []string{
		"Google Workspace",
		"Microsoft 365",
		"ProtonMail",
	}
	for _, input := range known {
		if !isHostedEmailProvider(input) {
			t.Errorf("isHostedEmailProvider(%q) = false, want true for a known hosted provider", input)
		}
	}

	unknown := []string{
		"",
		"unknown.example.com",
		"Some Random Provider",
	}
	for _, input := range unknown {
		if isHostedEmailProvider(input) {
			t.Errorf("isHostedEmailProvider(%q) = true, want false for a non-provider name", input)
		}
	}
}

func TestIsBIMICapableProvider_VariousInputs(t *testing.T) {
	capable := []string{
		"Google Workspace",
		"Microsoft 365",
		"Fastmail",
		"", // empty provider is treated as BIMI-capable by design
	}
	for _, input := range capable {
		if !isBIMICapableProvider(input) {
			t.Errorf("isBIMICapableProvider(%q) = false, want true", input)
		}
	}

	notCapable := []string{
		"bimi.example.com",
		"Some Random Provider",
	}
	for _, input := range notCapable {
		if isBIMICapableProvider(input) {
			t.Errorf("isBIMICapableProvider(%q) = true, want false for a non-capable provider", input)
		}
	}
}

func TestIsKnownDKIMProvider_VariousInputs(t *testing.T) {
	known := []interface{}{
		"google",
		"Microsoft 365",
		"protonmail",
	}
	for _, input := range known {
		if !isKnownDKIMProvider(input) {
			t.Errorf("isKnownDKIMProvider(%v) = false, want true for a known DKIM provider", input)
		}
	}

	unknown := []interface{}{
		"selector1-example-com._domainkey.example.onmicrosoft.com",
		"google._domainkey.example.com",
		"",
		"Unknown",
		nil,
		42,
	}
	for _, input := range unknown {
		if isKnownDKIMProvider(input) {
			t.Errorf("isKnownDKIMProvider(%v) = true, want false for a non-provider value", input)
		}
	}
}
