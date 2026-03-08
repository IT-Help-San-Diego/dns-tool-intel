//go:build intel

// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Full AI crawler intelligence list.

package ai_surface

func GetAICrawlers() []string {
	return []string{
		"GPTBot", "ChatGPT-User", "CCBot", "Google-Extended",
		"anthropic-ai", "ClaudeBot", "Claude-Web",
		"Bytespider", "Diffbot", "FacebookBot",
		"Omgilibot", "Applebot-Extended", "PerplexityBot",
		"YouBot", "Amazonbot",
	}
}
