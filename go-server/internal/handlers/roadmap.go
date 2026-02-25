// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
        "net/http"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

const (
        roadmapDateFeb2026    = "Feb 2026"
        roadmapVersionV2620   = "v26.20.0+"
        roadmapTypeFeature    = "Feature"
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
                {Title: "Intelligence Confidence Audit Engine (ICAE)", Version: "129 Test Cases", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Intelligence Currency Assurance Engine (ICuAE)", Version: "29 Test Cases", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Email Header Analyzer", Version: roadmapVersionV2620, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Drift Engine Phases 1–2", Version: "v26.19.40", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Architecture Page", Version: "v26.20.77–83", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "DKIM Selector Expansion (39→81+)", Version: "v26.20.69–70", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Brand Verdict Matrix Overhaul", Version: "v26.20.71", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Optional Authentication (Google OAuth 2.0 PKCE)", Version: "v26.20.56–57", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Probe Network First Node", Version: roadmapVersionV2620, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "LLM Documentation Strategy", Version: "v26.25.26", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "XSS Security Fix (Tooltip Safe DOM)", Version: "v26.25.26", Date: roadmapDateFeb2026, Type: "Security"},
                {Title: "Color Science Page (CIE Scotopic, WCAG)", Version: roadmapVersionV2620, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Badge System (SVG, Shields.io)", Version: roadmapVersionV2620, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Domain Snapshot", Version: roadmapVersionV2620, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Certificate Transparency Resilience", Version: "v26.20.76", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Nmap DNS Security Probing", Version: roadmapVersionV2620, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "One-Liner Verification Commands", Version: roadmapVersionV2620, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Zone File Upload for Analysis", Version: roadmapVersionV2620, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Hash Integrity Audit Engine", Version: "v26.21.45", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Download Verification (SHA-3-512)", Version: "v26.21.49–50", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Accountability Log", Version: "v26.21.46", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Glass Badge System (ICAE, Protocol, Section)", Version: "v26.25.38–43", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Covert Recon Mode", Version: roadmapVersionV2620, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Web/DNS/Email Hosting Detection", Version: "v26.25.43", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Question Branding System (dt-question)", Version: "v26.25.70", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Approach & Methodology Page", Version: "v26.25.83", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "TTL Alignment & Big Picture Questions", Version: "v26.25.93", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Unified Confidence Aggregation (ICD 203)", Version: "v26.25.94", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Homepage Simplification & TTL Deep Linking", Version: "v26.25.95", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "DMARC External Auth Remediation", Version: "v26.25.95", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Symbiotic Security — Five Archetypes Section", Version: "v26.25.96", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Methodology Page Rename & Cross-Links", Version: "v26.25.96", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Delegation Consistency Analyzer", Version: "v26.25.94", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Nameserver Fleet Matrix", Version: "v26.25.94", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "DNSSEC Operations Deep Dive", Version: "v26.25.94", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Live SonarCloud Badge & Evidence Qualification", Version: "v26.25.97", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Probe Network Second Node (Kali)", Version: "v26.26.02", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Multi-Probe Consensus Engine", Version: "v26.26.02", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Public Roadmap Page", Version: "v26.26.02", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "SonarCloud Quality Gate Fix", Version: "v26.26.03", Date: roadmapDateFeb2026, Type: "Quality"},
                {Title: "Nmap Subdomain Enrichment", Version: "v26.26.02", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Admin Probe Management Panel", Version: "v26.26.02", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
        }

        inProgress := []RoadmapItem{
                {Title: "Visual Cohesion — Top-to-Bottom Consistency", Type: roadmapTypeFeature, Priority: "Medium", Notes: "Glass treatment, question branding, and token system across all report modes"},
                {Title: "LLMs.txt & JSON-LD Consistency Audit", Type: roadmapTypeFeature, Priority: "Medium", Notes: "Cross-validate documentation, schema markup, and feature claims against actual site state"},
                {Title: "Stats Page Visual Redesign", Type: roadmapTypeFeature, Priority: "Medium", Notes: "Glass/gradient aesthetic matching rest of site — polished data presentation"},
        }

        nextUp := []RoadmapItem{
                {Title: "DoH/DoT Detection", Type: roadmapTypeFeature, Priority: "High", Notes: "Test whether domains support DNS-over-HTTPS (RFC 8484) and DNS-over-TLS (RFC 7858) — encrypted transport posture analysis"},
                {Title: "Distributed Probe Mesh (Good Net Citizens)", Type: roadmapTypeFeature, Priority: "High", Notes: "Volunteer browser-based DNS probes via DoH relay — multi-vantage consensus with Byzantine-resilient thresholds, reputation scoring, and privacy-preserving blinded work queues"},
                {Title: "API Access (Programmatic Analysis)", Type: roadmapTypeFeature, Priority: "High", Notes: "Programmatic analysis for automation workflows with rate limiting, authentication, versioning"},
                {Title: "CLI App (Homebrew/Binary)", Type: roadmapTypeFeature, Priority: "High", Notes: "Terminal application for macOS/Linux — works without login for basic analysis"},
        }

        backlog := []RoadmapItem{
                {Title: "Personal Analysis History", Type: roadmapTypeFeature, Priority: "Medium", Notes: "Per-user session tracking and analysis library"},
                {Title: "Drift Engine Alerts", Type: roadmapTypeFeature, Priority: "Medium", Notes: "Webhook/email notifications when domain security posture changes"},
                {Title: "Saved Reports", Type: roadmapTypeFeature, Priority: "Medium", Notes: "Bookmark and revisit past analyses with snapshot storage"},
                {Title: "Drift Engine Phases 3–4", Type: roadmapTypeFeature, Priority: "Medium", Notes: "Timeline visualization and scheduled monitoring with baselines"},
                {Title: "Probe Security.txt + Landing Pages", Type: roadmapTypeFeature, Priority: "Medium", Notes: "Transparency artifacts for probe VPS nodes"},
                {Title: "Homebrew Distribution", Type: roadmapTypeFeature, Priority: "Medium", Notes: "macOS/Linux package distribution for CLI app"},
                {Title: "Globalping.io Integration", Type: roadmapTypeFeature, Priority: "Low", Notes: "Distributed DNS resolution from 100+ global locations"},
                {Title: "Zone File Import as Drift Baseline", Type: roadmapTypeFeature, Priority: "Low", Notes: "Upload zone files to establish posture baseline for drift detection"},
                {Title: "Raw Intelligence API Access", Type: roadmapTypeFeature, Priority: "Low", Notes: "Direct access to collected intelligence without processing layers"},
                {Title: "ISC Recommendation Path Integration", Type: roadmapTypeFeature, Priority: "Low", Notes: "Integration with ISC remediation/hardening recommendations"},
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
