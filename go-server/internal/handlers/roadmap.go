// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
	"net/http"

	"dnstool/go-server/internal/config"

	"github.com/gin-gonic/gin"
)

type RoadmapItem struct {
	Title    string
	Version  string
	Date     string
	Notes    string
	Type     string
	Priority string
}

type RoadmapHandler struct {
	Config *config.Config
}

func NewRoadmapHandler(cfg *config.Config) *RoadmapHandler {
	return &RoadmapHandler{Config: cfg}
}

func (h *RoadmapHandler) Roadmap(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")

	done := []RoadmapItem{
		{Title: "Intelligence Confidence Audit Engine (ICAE)", Version: "129 Test Cases", Date: "Feb 2026", Type: "Feature"},
		{Title: "Intelligence Currency Assurance Engine (ICuAE)", Version: "29 Test Cases", Date: "Feb 2026", Type: "Feature"},
		{Title: "Email Header Analyzer", Version: "v26.20.0+", Date: "Feb 2026", Type: "Feature"},
		{Title: "Drift Engine Phases 1–2", Version: "v26.19.40", Date: "Feb 2026", Type: "Feature"},
		{Title: "Architecture Page", Version: "v26.20.77–83", Date: "Feb 2026", Type: "Feature"},
		{Title: "DKIM Selector Expansion (39→81+)", Version: "v26.20.69–70", Date: "Feb 2026", Type: "Feature"},
		{Title: "Brand Verdict Matrix Overhaul", Version: "v26.20.71", Date: "Feb 2026", Type: "Feature"},
		{Title: "Optional Authentication (Google OAuth 2.0 PKCE)", Version: "v26.20.56–57", Date: "Feb 2026", Type: "Feature"},
		{Title: "Probe Network First Node", Version: "v26.20.0+", Date: "Feb 2026", Type: "Feature"},
		{Title: "LLM Documentation Strategy", Version: "v26.25.26", Date: "Feb 2026", Type: "Feature"},
		{Title: "XSS Security Fix (Tooltip Safe DOM)", Version: "v26.25.26", Date: "Feb 2026", Type: "Security"},
		{Title: "Color Science Page (CIE Scotopic, WCAG)", Version: "v26.20.0+", Date: "Feb 2026", Type: "Feature"},
		{Title: "Badge System (SVG, Shields.io)", Version: "v26.20.0+", Date: "Feb 2026", Type: "Feature"},
		{Title: "Domain Snapshot", Version: "v26.20.0+", Date: "Feb 2026", Type: "Feature"},
		{Title: "Certificate Transparency Resilience", Version: "v26.20.76", Date: "Feb 2026", Type: "Feature"},
		{Title: "Nmap DNS Security Probing", Version: "v26.20.0+", Date: "Feb 2026", Type: "Feature"},
		{Title: "One-Liner Verification Commands", Version: "v26.20.0+", Date: "Feb 2026", Type: "Feature"},
		{Title: "Zone File Upload for Analysis", Version: "v26.20.0+", Date: "Feb 2026", Type: "Feature"},
		{Title: "Hash Integrity Audit Engine", Version: "v26.21.45", Date: "Feb 2026", Type: "Feature"},
		{Title: "Download Verification (SHA-3-512)", Version: "v26.21.49–50", Date: "Feb 2026", Type: "Feature"},
		{Title: "Accountability Log", Version: "v26.21.46", Date: "Feb 2026", Type: "Feature"},
		{Title: "Glass Badge System (ICAE, Protocol, Section)", Version: "v26.25.38–43", Date: "Feb 2026", Type: "Feature"},
		{Title: "Covert Recon Mode", Version: "v26.20.0+", Date: "Feb 2026", Type: "Feature"},
		{Title: "Web/DNS/Email Hosting Detection", Version: "v26.25.43", Date: "Feb 2026", Type: "Feature"},
		{Title: "Question Branding System (dt-question)", Version: "v26.25.70", Date: "Feb 2026", Type: "Feature"},
	}

	inProgress := []RoadmapItem{
		{Title: "Visual Cohesion — Top-to-Bottom Consistency", Type: "Feature", Priority: "Medium", Notes: "Glass treatment, question branding, and token system across all report modes"},
		{Title: "Public Roadmap Page", Type: "Feature", Priority: "Medium", Notes: "This page — kanban view of project progress"},
		{Title: "Approach & Methodology Page", Type: "Feature", Priority: "Medium", Notes: "Documentation of scientific rigor and quality gate philosophy"},
	}

	nextUp := []RoadmapItem{
		{Title: "API Access (Programmatic Analysis)", Type: "Feature", Priority: "High", Notes: "Programmatic analysis for automation workflows with rate limiting, authentication, versioning"},
		{Title: "CLI App (Homebrew/Binary)", Type: "Feature", Priority: "High", Notes: "Terminal application for macOS/Linux — works without login for basic analysis"},
		{Title: "Probe Network Second Node (Kali)", Type: "Feature", Priority: "High", Notes: "SMTP/TLS verification, DANE/DNSSEC validation, testssl.sh analysis from Kali OSINT node"},
		{Title: "Multi-Probe Consensus Engine", Type: "Feature", Priority: "High", Notes: "Cross-probe agreement analysis — TLS config consensus, certificate fingerprint comparison"},
	}

	backlog := []RoadmapItem{
		{Title: "Personal Analysis History", Type: "Feature", Priority: "Medium", Notes: "Per-user session tracking and analysis library"},
		{Title: "Drift Engine Alerts", Type: "Feature", Priority: "Medium", Notes: "Webhook/email notifications when domain security posture changes"},
		{Title: "Saved Reports", Type: "Feature", Priority: "Medium", Notes: "Bookmark and revisit past analyses with snapshot storage"},
		{Title: "Drift Engine Phases 3–4", Type: "Feature", Priority: "Medium", Notes: "Timeline visualization and scheduled monitoring with baselines"},
		{Title: "Probe Security.txt + Landing Pages", Type: "Feature", Priority: "Medium", Notes: "Transparency artifacts for probe VPS nodes"},
		{Title: "Homebrew Distribution", Type: "Feature", Priority: "Medium", Notes: "macOS/Linux package distribution for CLI app"},
		{Title: "Globalping.io Integration", Type: "Feature", Priority: "Low", Notes: "Distributed DNS resolution from 100+ global locations"},
		{Title: "Zone File Import as Drift Baseline", Type: "Feature", Priority: "Low", Notes: "Upload zone files to establish posture baseline for drift detection"},
		{Title: "Raw Intelligence API Access", Type: "Feature", Priority: "Low", Notes: "Direct access to collected intelligence without processing layers"},
		{Title: "ISC Recommendation Path Integration", Type: "Feature", Priority: "Low", Notes: "Integration with ISC remediation/hardening recommendations"},
	}

	data := gin.H{
		"AppVersion":      h.Config.AppVersion,
		"MaintenanceNote": h.Config.MaintenanceNote,
		"BetaPages":       h.Config.BetaPages,
		"CspNonce":        nonce,
		"ActivePage":      "roadmap",
		"Done":            done,
		"DoneCount":       len(done),
		"InProgress":      inProgress,
		"InProgressCount": len(inProgress),
		"NextUp":          nextUp,
		"NextUpCount":     len(nextUp),
		"Backlog":         backlog,
		"BacklogCount":    len(backlog),
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, "roadmap.html", data)
}
