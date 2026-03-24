//go:build !intel

// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Stub implementations. See github.com/IT-Help-San-Diego/dns-tool-intel for the full version.
// dns-tool:scrutiny science
package ai_surface

import "context"

func (s *Scanner) fetchTextFile(ctx context.Context, url string) (string, error) {
	return "", nil
}
