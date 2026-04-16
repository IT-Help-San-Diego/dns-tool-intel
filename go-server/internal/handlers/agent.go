// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "dnstool/go-server/internal/analyzer"
        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/handlers/agentpkg"
)

type AgentHandler = agentpkg.AgentHandler
type AgentSaveFn = agentpkg.AgentSaveFn

func NewAgentHandler(cfg *config.Config, a *analyzer.Analyzer, store ...agentpkg.LookupStore) *AgentHandler {
        return agentpkg.NewAgentHandler(cfg, a, NewTemplateData, store...)
}

func NewAgentHandlerWithStore(store agentpkg.LookupStore) *AgentHandler {
        return agentpkg.NewAgentHandlerWithStore(store)
}
