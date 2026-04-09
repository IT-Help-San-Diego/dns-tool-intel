//go:build intel

// dns-tool:scrutiny science
// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Full implementation — private repo only.
package ai_surface

import "context"

func (s *Scanner) CheckLLMSTxt(ctx context.Context, domain string) map[string]any {
	// Intel-boundary: full implementation provided by dns-tool-intel at build time.
	return map[string]any{
		"found":      false,
		"full_found": false,
		"url":        nil,
		"full_url":   nil,
		"fields":     map[string]any{},
		"evidence":   []Evidence{},
	}
}

func looksLikeLLMSTxt(body string) bool {
	// Intel-boundary: llms.txt format heuristic provided by dns-tool-intel at build time.
	return false
}

func parseLLMSTxt(body string) map[string]any {
	// Intel-boundary: full parser provided by dns-tool-intel at build time.
	return map[string]any{}
}

func parseLLMSTxtFieldLine(line, section string, fields map[string]any, docs *[]string) {
	// Intel-boundary: field-line parser provided by dns-tool-intel at build time.
}
