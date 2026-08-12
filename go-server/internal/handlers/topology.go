// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"encoding/json"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"dnstool/go-server/internal/botverify"
	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/fixturecorpus"

	"github.com/gin-gonic/gin"
)

type TopologyHandler struct {
	Config        *config.Config
	solverOnce    sync.Once
	solverLayouts map[string]json.RawMessage
}

func NewTopologyHandler(cfg *config.Config) *TopologyHandler {
	return &TopologyHandler{Config: cfg}
}

func (h *TopologyHandler) loadSolverLayouts() {
	h.solverLayouts = make(map[string]json.RawMessage)
	profiles := []string{"desktop", "tablet", "mobile"}
	solverDir := filepath.Join("go-server", "tools", "topology-solver", "output")

	for _, profile := range profiles {
		path := filepath.Join(solverDir, profile+"-layout.json")
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if json.Valid(data) {
			h.solverLayouts[profile] = data
		}
	}
}

// SolverJSON returns the merged solver layout profiles as a template.JS
// value, loading them once. Shared by the /topology page and the
// /replay/:id permalink so both render identical layout data.
func (h *TopologyHandler) SolverJSON() template.JS {
	h.solverOnce.Do(h.loadSolverLayouts)

	solverJSON := "{}"
	if len(h.solverLayouts) > 0 {
		merged, err := json.Marshal(h.solverLayouts)
		if err == nil {
			solverJSON = string(merged)
		}
	}
	return template.JS(solverJSON)
}

func (h *TopologyHandler) Topology(c *gin.Context) {
	data := NewTemplateData(c, h.Config, "topology")
	data["SolverLayouts"] = h.SolverJSON()
	data["FixtureCorpusJSON"] = FixtureCorpusJS()
	// Autorun is the fail-closed server-side gate on the ?domain= scan
	// auto-start. Only a COMPLETED botverify classification with zero bot
	// signal (HumanVerified) may inject the autorun flag; JS-executing
	// crawlers (Ahrefs Site Audit, Google Chrome-Lighthouse, Applebot, …)
	// arrive here with ?domain= from history links and must get a prefilled
	// idle box, not a scan. See topology.js AUTORUN_DOMAIN gate.
	data["Autorun"] = botverify.Classify(c.Request.UserAgent(), c.ClientIP()).HumanVerified()
	c.HTML(http.StatusOK, "topology.html", data)
}

// FixtureCorpusJS exposes the fixture-domain disclosure corpus to templates
// so the scan console can light up when a golden-fixture or ICAE-case
// domain is scanned.
func FixtureCorpusJS() template.JS {
	return template.JS(fixturecorpus.CorpusJSON())
}
