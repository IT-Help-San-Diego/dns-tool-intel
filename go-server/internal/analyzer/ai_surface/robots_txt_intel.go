//go:build intel

// dns-tool:scrutiny science
// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Full implementation — private repo only.
package ai_surface

import "context"

var knownAICrawlers = []string{
	// Intel-boundary: full AI crawler list populated by dns-tool-intel at build time.
}

func (s *Scanner) CheckRobotsTxtAI(ctx context.Context, domain string) map[string]any {
	// Intel-boundary: full implementation provided by dns-tool-intel at build time.
	return map[string]any{
		"found":              false,
		"url":                nil,
		"blocks_ai_crawlers": false,
		"allows_ai_crawlers": false,
		"blocked_crawlers":   []string{},
		"allowed_crawlers":   []string{},
		"directives":         []robotsDirective{},
		"evidence":           []Evidence{},
	}
}

func parseRobotsForAI(body string) (blocked []string, allowed []string, directives []robotsDirective) {
	// Intel-boundary: full implementation provided by dns-tool-intel at build time.
	return nil, nil, nil
}

func processRobotsLine(lower, line string, currentUA string, seenBlocked, seenAllowed map[string]bool, directives *[]robotsDirective) {
	// Intel-boundary: full implementation provided by dns-tool-intel at build time.
}

func matchAICrawler(userAgent string) string {
	// Intel-boundary: full implementation provided by dns-tool-intel at build time.
	return ""
}
