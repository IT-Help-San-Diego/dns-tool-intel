// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

// Scan Replay — a "MIDI-like" replay file DERIVED on demand from the
// recorded scan timeline. Every replayed event maps 1:1 to a stored
// scan_phase_telemetry row and the payload carries the stored SHA3-512
// from scan_telemetry_hash verbatim, so shares are tamper-evident
// snapshots: nothing is synthesized, no fabrication is possible.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

const replayFormatVersion = 1

const msgNoReplay = "No replay available — this analysis has no recorded scan timeline. /dev/null scans and scans that predate telemetry capture are analyzed without a stored timeline."

// replayEvent is one recorded pipeline event. T is milliseconds
// relative to scan start; Dur is the recorded task duration; Rc is the
// recorded record count.
type replayEvent struct {
	T     int32  `json:"t"`
	Group string `json:"group"`
	Task  string `json:"task"`
	Dur   int32  `json:"dur"`
	Rc    int32  `json:"rc"`
	Err   string `json:"err,omitempty"`
}

// replayProtocols lists the nine per-protocol verdict slots surfaced in
// replay payloads, keyed to the full_results section that stores each
// protocol's status.
var replayProtocols = []struct {
	Key     string
	Section string
}{
	{"spf", mapKeySpfAnalysis},
	{"dkim", mapKeyDkimAnalysis},
	{"dmarc", mapKeyDmarcAnalysis},
	{"dnssec", "dnssec_analysis"},
	{"dane", "dane_analysis"},
	{"mtasts", "mta_sts_analysis"},
	{"tlsrpt", "tlsrpt_analysis"},
	{"bimi", "bimi_analysis"},
	{"caa", "caa_analysis"},
}

// replayVerdicts extracts stored per-protocol statuses from a saved
// full_results document. A missing section or missing status is
// reported as "indeterminate" — never collapsed into pass or fail
// (tri-state honesty).
func replayVerdicts(fullResults []byte) map[string]string {
	var fr map[string]json.RawMessage
	if len(fullResults) > 0 {
		if err := json.Unmarshal(fullResults, &fr); err != nil {
			fr = nil
		}
	}
	verdicts := make(map[string]string, len(replayProtocols))
	for _, p := range replayProtocols {
		status := "indeterminate"
		if raw, ok := fr[p.Section]; ok {
			var section struct {
				Status string `json:"status"`
			}
			if json.Unmarshal(raw, &section) == nil && section.Status != "" {
				status = section.Status
			}
		}
		verdicts[p.Key] = status
	}
	return verdicts
}

// APIReplay serves the derived replay v1 JSON for a stored analysis.
// Privacy is enforced by the same loader as /api/analysis/:id: private
// analyses are owner-only (403 for other signed-in users, 404 for
// unauthenticated callers). Analyses without a recorded timeline get an
// honest 404.
func (h *AnalysisHandler) APIReplay(c *gin.Context) {
	analysis, ok := h.loadAnalysisForAPI(c)
	if !ok {
		return
	}

	ctx := c.Request.Context()
	hash, err := h.store().GetTelemetryHash(ctx, analysis.ID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{mapKeyError: msgNoReplay})
		return
	}
	rows, err := h.store().GetTelemetryByAnalysis(ctx, analysis.ID)
	if err != nil || len(rows) == 0 {
		c.JSON(http.StatusNotFound, gin.H{mapKeyError: msgNoReplay})
		return
	}

	events := make([]replayEvent, 0, len(rows))
	for _, r := range rows {
		ev := replayEvent{
			T:     r.StartedAtMs,
			Group: r.PhaseGroup,
			Task:  r.PhaseTask,
			Dur:   r.DurationMs,
		}
		if r.RecordCount != nil {
			ev.Rc = *r.RecordCount
		}
		if r.Error != nil {
			ev.Err = *r.Error
		}
		events = append(events, ev)
	}

	c.JSON(http.StatusOK, gin.H{
		"v":           replayFormatVersion,
		"analysis_id": analysis.ID,
		mapKeyDomain:  analysis.Domain,
		"total_ms":    hash.TotalDurationMs,
		"sha3_512":    hash.Sha3512,
		"events":      events,
		"verdicts":    replayVerdicts(analysis.FullResults),
	})
}

// ReplayPage renders the topology page in replay mode for a shareable
// permalink. Access control runs BEFORE any template data is built so a
// private analysis never leaks its domain through OG metadata, and the
// no-timeline case gets the same honest 404 as the API.
func (h *AnalysisHandler) ReplayPage(topo *TopologyHandler) gin.HandlerFunc {
	return func(c *gin.Context) {
		nonce, ok := c.Get("csp_nonce")
		if !ok {
			nonce = ""
		}
		csrfToken, ok := c.Get("csrf_token")
		if !ok {
			csrfToken = ""
		}

		analysisID, err := strconv.ParseInt(c.Param("id"), 10, 32)
		if err != nil {
			h.renderErrorPage(c, http.StatusBadRequest, nonce, csrfToken, mapKeyDanger, errMsgInvalidAnalysisID)
			return
		}

		ctx := c.Request.Context()
		analysis, err := h.store().GetAnalysisByID(ctx, int32(analysisID))
		if err != nil {
			h.renderErrorPage(c, http.StatusNotFound, nonce, csrfToken, mapKeyDanger, strAnalysisNotFound)
			return
		}
		if !h.checkPrivateAccess(c, analysis.ID, analysis.Private) {
			h.renderRestrictedAccess(c, nonce, csrfToken)
			return
		}

		hash, err := h.store().GetTelemetryHash(ctx, analysis.ID)
		if err != nil {
			h.renderErrorPage(c, http.StatusNotFound, nonce, csrfToken, mapKeyWarning, msgNoReplay)
			return
		}

		data := NewTemplateData(c, h.Config, "topology")
		data["SolverLayouts"] = topo.SolverJSON()
		data["ReplayID"] = analysis.ID
		data["ReplayDomain"] = analysis.Domain
		data["ReplayTotalMs"] = hash.TotalDurationMs
		data["ReplaySeconds"] = fmt.Sprintf("%.1f", float64(hash.TotalDurationMs)/1000.0)
		c.HTML(http.StatusOK, "topology.html", data)
	}
}
