// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package agentpkg

import (
	"dnstool/go-server/internal/analyzer"
	"dnstool/go-server/internal/config"
)

// NewAgentHandlerWithStore is a test-helper constructor that allows callers
// to inject a LookupStore directly without supplying a full analyzer/config/tdf.
func NewAgentHandlerWithStore(store LookupStore) *AgentHandler {
	return &AgentHandler{
		Config:      &config.Config{},
		Analyzer:    (*analyzer.Analyzer)(nil),
		lookupStore: store,
	}
}
