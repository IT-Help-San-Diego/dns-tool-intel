// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package dnsclient

import (
	"context"
	"golang.org/x/net/publicsuffix"
	"regexp"
	"strings"

	"golang.org/x/net/idna"
)

var (
	labelRegex = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)
	tldRegex   = regexp.MustCompile(`^[a-zA-Z]{2,}$`)
)

func DomainToASCII(domain string) (string, error) {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimRight(domain, ".")

	p := idna.New(idna.MapForLookup(), idna.Transitional(false))
	ascii, err := p.ToASCII(domain)
	if err != nil {
		if regexp.MustCompile(`^[a-zA-Z0-9.-]+$`).MatchString(domain) {
			labels := strings.Split(domain, ".")
			for _, label := range labels {
				if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
					return "", err
				}
			}
			return domain, nil
		}
		return "", err
	}
	return ascii, nil
}

const maxLabelDepth = 10

func ValidateDomain(domain string) bool {
	if domain == "" || len(domain) > 253 {
		return false
	}

	domain = strings.TrimSpace(domain)
	domain = strings.TrimLeft(domain, ".")
	domain = strings.TrimRight(domain, ".")
	if domain == "" {
		return false
	}

	ascii, err := DomainToASCII(domain)
	if err != nil {
		return false
	}

	if strings.Contains(ascii, "..") || strings.HasPrefix(ascii, ".") || strings.HasPrefix(ascii, "-") {
		return false
	}

	labels := strings.Split(ascii, ".")

	if len(labels) == 1 {
		return validateTLD(labels[0])
	}

	if len(labels) > maxLabelDepth {
		return false
	}

	if !validateLabels(labels) {
		return false
	}

	return validateTLD(labels[len(labels)-1])
}

func IsTLDInput(domain string) bool {
	d := strings.TrimSpace(domain)
	d = strings.TrimLeft(d, ".")
	d = strings.TrimRight(d, ".")
	if d == "" {
		return false
	}
	return !strings.Contains(d, ".") && validateTLD(d)
}

// IsRegistryZone reports whether the input names a REGISTRY ZONE APEX rather
// than a registrable domain — either a single-label TLD ("com") or a
// multi-label public suffix ("co.uk", "ac.uk", "com.au").
//
// IsTLDInput only ever returned true for a single label, so "co.uk" fell
// through and received the full domain battery: SPF, DMARC, DKIM and the rest
// queried against a zone apex where they cannot meaningfully exist, and their
// absence reported as findings about a domain nobody registered.
//
// The public suffix list is the producer for this question, so it is asked
// directly rather than approximated by counting dots — "bbc.co.uk" has two
// dots and IS registrable, while "co.uk" has one and is not.
//
// NOTE this is deliberately NOT a drop-in replacement for IsTLDInput at every
// call site. It widens WHAT IS RECOGNISED as a registry zone; it does not
// claim the tool can yet produce a complete registry-zone report. Callers use
// it to suppress checks that are meaningless at an apex — with a stated
// reason — not to assert the resulting report is finished.
func IsRegistryZone(domain string) bool {
	d := strings.TrimSpace(domain)
	d = strings.TrimLeft(d, ".")
	d = strings.TrimRight(d, ".")
	if d == "" {
		return false
	}
	if IsTLDInput(d) {
		return true
	}
	d = strings.ToLower(d)
	// EffectiveTLDPlusOne fails exactly when the input IS a public suffix
	// (there is no registrable name above it), which is the signal wanted.
	if _, err := publicsuffix.EffectiveTLDPlusOne(d); err == nil {
		return false
	}
	suffix, _ := publicsuffix.PublicSuffix(d)
	return strings.EqualFold(d, suffix)
}

func validateLabels(labels []string) bool {
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		if !labelRegex.MatchString(label) {
			return false
		}
	}
	return true
}

func validateTLD(tld string) bool {
	return tldRegex.MatchString(tld) || strings.HasPrefix(tld, "xn--")
}

func GetTLD(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) == 0 {
		return ""
	}
	return strings.ToLower(parts[len(parts)-1])
}

func FindParentZone(c *Client, ctx context.Context, domain string) string {
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts)-1; i++ {
		candidate := strings.Join(parts[i:], ".")
		results := c.QueryDNS(ctx, "NS", candidate)
		if len(results) > 0 {
			return candidate
		}
	}
	return ""
}
