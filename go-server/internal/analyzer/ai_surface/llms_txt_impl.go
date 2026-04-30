// dns-tool:scrutiny science
// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

package ai_surface

import "context"

func (s *Scanner) CheckLLMSTxt(ctx context.Context, domain string) map[string]any {
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
	return false
}

func parseLLMSTxt(body string) map[string]any {
	return map[string]any{}
}

func parseLLMSTxtFieldLine(line, section string, fields map[string]any, docs *[]string) {
}
