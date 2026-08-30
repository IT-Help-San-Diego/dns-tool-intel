// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

const (
	mapKeyFormat  = "format"
	mapKeyIssuer  = "issuer"
	mapKeyMessage = "message"
	mapKeyValid   = "valid"
	mapKeyWarning = "warning"
)

var (
	bimiLogoRe = regexp.MustCompile(`(?i)l=([^;\s]+)`)
	bimiVMCRe  = regexp.MustCompile(`(?i)a=([^;\s]+)`)
)

func buildBIMIMessage(logoURL, vmcURL *string, logoData, vmcData map[string]any) (string, string) {
	status := "success"
	var messageParts []string

	status, messageParts = buildBIMICoreMessage(logoURL, vmcURL, logoData, vmcData)
	messageParts = appendBIMILogoIssue(logoURL, logoData, &status, messageParts)

	return status, strings.Join(messageParts, " ")
}

func buildBIMICoreMessage(logoURL, vmcURL *string, logoData, vmcData map[string]any) (string, []string) {
	status := "success"
	var parts []string

	if vmcURL != nil && vmcData[mapKeyValid] == true {
		parts = append(parts, "BIMI with VMC certificate")
		if issuer, ok := vmcData[mapKeyIssuer].(string); ok && issuer != "" {
			parts = append(parts, fmt.Sprintf("(from %s)", issuer))
		}
	} else if vmcURL != nil {
		parts = append(parts, "BIMI with VMC")
		if errStr, ok := vmcData[mapKeyError].(string); ok && errStr != "" {
			status = mapKeyWarning
			parts = append(parts, fmt.Sprintf("- VMC issue: %s", errStr))
		}
	} else if logoURL != nil {
		parts = append(parts, "BIMI configured")
		if logoData[mapKeyValid] == true {
			parts = append(parts, "- logo validated")
		}
		parts = append(parts, "(VMC recommended for Gmail)")
	} else {
		status = mapKeyWarning
		parts = append(parts, "BIMI record found but missing logo URL")
	}

	return status, parts
}

func appendBIMILogoIssue(logoURL *string, logoData map[string]any, status *string, parts []string) []string {
	if logoURL != nil && logoData[mapKeyValid] != true {
		if errStr, ok := logoData[mapKeyError].(string); ok && errStr != "" {
			*status = mapKeyWarning
			parts = append(parts, fmt.Sprintf("Logo issue: %s", errStr))
		}
	}
	return parts
}

func filterBIMIRecords(records []string) []string {
	var valid []string
	for _, r := range records {
		if strings.HasPrefix(strings.ToLower(r), "v=bimi1") {
			valid = append(valid, r)
		}
	}
	return valid
}

func extractBIMIURLs(record string) (logoURL, vmcURL *string) {
	if m := bimiLogoRe.FindStringSubmatch(record); m != nil {
		logoURL = &m[1]
	}
	if m := bimiVMCRe.FindStringSubmatch(record); m != nil {
		vmcURL = &m[1]
	}
	return
}

func (a *Analyzer) fetchBIMIValidations(ctx context.Context, logoURL, vmcURL *string) (map[string]any, map[string]any) {
	var logoData, vmcData map[string]any
	if logoURL != nil {
		logoData = a.validateBIMILogo(ctx, *logoURL)
	} else {
		logoData = map[string]any{}
	}
	if vmcURL != nil {
		vmcData = a.validateBIMIVMC(ctx, *vmcURL)
	} else {
		vmcData = map[string]any{}
	}
	return logoData, vmcData
}

func (a *Analyzer) AnalyzeBIMI(ctx context.Context, domain string) map[string]any {
	bimiDomain := fmt.Sprintf("default._bimi.%s", domain)
	records, lookupStatus := a.resolveWithStatus(ctx, "TXT", bimiDomain)
	bimiSource := domain

	// BIMI spec (draft-brand-indicators-for-message-identification §7.2,
	// mirroring DMARC RFC 7489 §6.6.3): if no assertion record exists at
	// default._bimi.<domain>, receivers query default._bimi.<org-domain>.
	// Exact-name-only lookup under-reports brand indicators on subdomains —
	// the same Replit-era defect class fixed for CAA in #478, one protocol
	// over. Fall back only on CONFIRMED absence; an indeterminate org-domain
	// lookup keeps the verdict indeterminate rather than fabricating absence.
	if len(records) == 0 && !isIndeterminateLookup(lookupStatus) {
		if org, orgIndeterminate := orgDomain(domain); !orgIndeterminate && org != strings.ToLower(strings.TrimRight(domain, ".")) {
			orgRecords, orgStatus := a.resolveWithStatus(ctx, "TXT", fmt.Sprintf("default._bimi.%s", org))
			if isIndeterminateLookup(orgStatus) {
				lookupStatus = orgStatus
			} else if len(orgRecords) > 0 {
				records = orgRecords
				bimiSource = org
			}
		}
	}

	baseResult := map[string]any{
		"status":        mapKeyWarning,
		mapKeyMessage:   "No BIMI record found",
		"record":        nil,
		"logo_url":      nil,
		"vmc_url":       nil,
		"logo_valid":    nil,
		"logo_format":   nil,
		"logo_error":    nil,
		"vmc_valid":     nil,
		"vmc_issuer":    nil,
		"vmc_subject":   nil,
		"vmc_error":     nil,
		mapKeyBimiState: triStateAbsentConf,
	}

	if len(records) == 0 {
		if isIndeterminateLookup(lookupStatus) {
			baseResult["status"] = statusIndeterminate
			baseResult[mapKeyMessage] = indeterminateLookupMessage("BIMI", lookupStatus)
			baseResult[mapKeyBimiState] = triStateIndeterminate
		}
		return baseResult
	}

	validRecords := filterBIMIRecords(records)
	if len(validRecords) == 0 {
		baseResult[mapKeyMessage] = "No valid BIMI record found"
		return baseResult
	}

	record := validRecords[0]
	logoURL, vmcURL := extractBIMIURLs(record)
	logoData, vmcData := a.fetchBIMIValidations(ctx, logoURL, vmcURL)
	status, message := buildBIMIMessage(logoURL, vmcURL, logoData, vmcData)
	if bimiSource != domain {
		message = fmt.Sprintf("Covered by organizational-domain BIMI (default._bimi.%s applies to this subdomain per the BIMI assertion-record fallback, mirroring RFC 7489 §6.6.3). %s", bimiSource, message)
	}

	result := map[string]any{
		"status":        status,
		mapKeyMessage:   message,
		"record":        record,
		"logo_url":      derefStr(logoURL),
		"vmc_url":       derefStr(vmcURL),
		"logo_valid":    logoData[mapKeyValid],
		"logo_format":   logoData[mapKeyFormat],
		"logo_error":    logoData[mapKeyError],
		"vmc_valid":     vmcData[mapKeyValid],
		"vmc_issuer":    vmcData[mapKeyIssuer],
		"vmc_subject":   vmcData["subject"],
		"vmc_error":     vmcData[mapKeyError],
		mapKeyBimiState: triStatePresent,
	}
	if bimiSource != domain {
		result["bimi_source"] = bimiSource
		result["inherited"] = true
	}
	return result
}

func (a *Analyzer) validateBIMILogo(ctx context.Context, url string) map[string]any {
	result := map[string]any{mapKeyValid: false, mapKeyFormat: nil, mapKeyError: nil}

	if url == "" {
		result[mapKeyError] = "No URL"
		return result
	}

	resp, err := a.HTTP.Get(ctx, url)
	if err != nil {
		result[mapKeyError] = classifyHTTPError(err, 30)
		return result
	}

	body, err := a.HTTP.ReadBody(resp, 1<<20)
	if err != nil {
		result[mapKeyError] = "Failed to read response"
		return result
	}

	if resp.StatusCode != 200 {
		result[mapKeyError] = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return result
	}

	classifyBIMILogoFormat(resp.Header.Get("Content-Type"), body, result)
	return result
}

func classifyBIMILogoFormat(contentType string, body []byte, result map[string]any) {
	lowerCT := strings.ToLower(contentType)
	switch {
	case strings.Contains(lowerCT, "svg"):
		result[mapKeyValid] = true
		result[mapKeyFormat] = "SVG"
	case strings.Contains(lowerCT, "image"):
		parts := strings.Split(contentType, "/")
		formatName := "unknown"
		if len(parts) >= 2 {
			formatName = strings.ToUpper(parts[1])
		}
		content := strings.ToLower(string(body[:minInt(500, len(body))]))
		if strings.Contains(content, "<svg") {
			result[mapKeyValid] = true
			result[mapKeyFormat] = "SVG"
		} else {
			result[mapKeyValid] = false
			result[mapKeyFormat] = formatName
			result[mapKeyError] = fmt.Sprintf("BIMI requires SVG Tiny PS format (draft-svg-tiny-ps-abrotman), found %s", formatName)
		}
	default:
		content := strings.ToLower(string(body[:minInt(500, len(body))]))
		if strings.Contains(content, "<svg") {
			result[mapKeyValid] = true
			result[mapKeyFormat] = "SVG"
		} else {
			result[mapKeyError] = "Not SVG format (draft-svg-tiny-ps-abrotman requires SVG Tiny PS)"
		}
	}
}

func (a *Analyzer) validateBIMIVMC(ctx context.Context, url string) map[string]any {
	result := map[string]any{mapKeyValid: false, mapKeyIssuer: nil, "subject": nil, mapKeyError: nil}

	if url == "" {
		result[mapKeyError] = "No URL"
		return result
	}

	resp, err := a.HTTP.Get(ctx, url)
	if err != nil {
		result[mapKeyError] = classifyHTTPError(err, 30)
		return result
	}

	body, err := a.HTTP.ReadBody(resp, 1<<20)
	if err != nil {
		result[mapKeyError] = "Failed to read response"
		return result
	}

	if resp.StatusCode != 200 {
		result[mapKeyError] = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return result
	}

	classifyVMCCertificate(string(body), result)
	return result
}

func classifyVMCCertificate(content string, result map[string]any) {
	if !strings.Contains(content, "-----BEGIN CERTIFICATE-----") {
		result[mapKeyError] = "Invalid certificate format"
		return
	}
	result[mapKeyValid] = true
	switch {
	case strings.Contains(content, "DigiCert"):
		result[mapKeyIssuer] = "DigiCert"
	case strings.Contains(content, "Entrust"):
		result[mapKeyIssuer] = "Entrust"
	case strings.Contains(content, "GlobalSign"):
		result[mapKeyIssuer] = "GlobalSign"
	default:
		result[mapKeyIssuer] = "Verified CA"
	}
}
