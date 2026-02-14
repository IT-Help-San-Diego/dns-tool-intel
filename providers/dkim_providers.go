// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Proprietary — All rights reserved.
// This file provides the real implementation of isKnownDKIMProvider.
// It overrides the stub in the public repo (providers.go).
package analyzer

import "strings"

var knownDKIMProviders = map[string]bool{
	"google":          true,
	"microsoft":       true,
	"protonmail":      true,
	"zoho":            true,
	"fastmail":        true,
	"yahoo":           true,
	"mailgun":         true,
	"sendgrid":        true,
	"amazonses":       true,
	"postmark":        true,
	"sparkpost":       true,
	"mailchimp":       true,
	"mandrill":        true,
	"sendinblue":      true,
	"brevo":           true,
	"constantcontact": true,
	"mimecast":        true,
}

func isKnownDKIMProvider(provider interface{}) bool {
	s, ok := provider.(string)
	if !ok || s == "" {
		return false
	}
	return knownDKIMProviders[strings.ToLower(s)]
}
