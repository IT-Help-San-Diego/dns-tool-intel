// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
//
// Package goldenfixtures exposes the golden-fixture regression corpus to the
// server. manifest.json is the single source of truth, maintained by
// scripts/refresh-golden-fixtures.sh — this package embeds it rather than
// duplicating the domain list in Go.
// dns-tool:scrutiny science
package goldenfixtures

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
)

//go:embed manifest.json
var manifestJSON []byte

type manifest struct {
	Domains []string `json:"domains"`
}

var (
	loadOnce  sync.Once
	domainSet map[string]bool
	domains   []string
)

func load() {
	domainSet = map[string]bool{}
	var m manifest
	if err := json.Unmarshal(manifestJSON, &m); err != nil {
		return
	}
	for _, d := range m.Domains {
		d = normalize(d)
		if d != "" && !domainSet[d] {
			domainSet[d] = true
			domains = append(domains, d)
		}
	}
}

func normalize(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

// Domains returns the baseline-corpus domains listed in manifest.json.
func Domains() []string {
	loadOnce.Do(load)
	out := make([]string, len(domains))
	copy(out, domains)
	return out
}

// IsBaselineDomain reports whether the domain's full-scan snapshot is part
// of the regression baseline corpus.
func IsBaselineDomain(domain string) bool {
	loadOnce.Do(load)
	return domainSet[normalize(domain)]
}
