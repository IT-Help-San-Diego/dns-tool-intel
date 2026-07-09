// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
//
// CHANGELOG DATE POLICY
// =====================
// Each entry's Date field must reflect the ACTUAL date the feature shipped or
// the incident occurred — NOT the version number prefix, NOT "today", and NOT
// the date the changelog entry was written. Version numbers (26.14.x, 26.13.x)
// are feature-level counters and do NOT encode dates.
//
// When adding a new entry:
//  1. Determine the real ship/event date.
//  2. Use (or create) a named date constant below.
//  3. Reference the constant — never inline a date string.
//
// HISTORICAL EDIT AUDIT
// =====================
// 2026-03-05 (commit 751fe32f): Corrected SPDX license identifier in the
//
//      dateFeb17 changelog entry from "BSL 1.1" (not a valid SPDX identifier;
//      could be confused with Boost Software License) to "BUSL-1.1" (the
//      correct SPDX identifier for Business Source License 1.1). This was an
//      intentional, targeted correction — NOT a mass version rewrite. Only 3
//      lines changed: the date-mapping comment, the entry Title, and the entry
//      Description. No version strings were altered. The same commit also
//      corrected the identifier across 14 other project files (README, CITATION,
//      architecture docs, methodology PDF, etc.) as part of a project-wide
//      SPDX compliance sweep. Investigated and confirmed clean on 2026-03-05
//      by cross-referencing git diff, version string diversity (26 distinct
//      versions intact), and release script analysis.
//
// Canonical date mapping (verified Feb 28, 2026):
//
//      dateFeb28 — Schema.org Intelligence Pipeline Mapping,
//                  Intelligence Pipeline Topology Visualization
//      dateFeb26 — Safari Covert Mode Fix, Stats Success Rate Fix,
//                  Daily Analysis Stats Tracking, Admin IP Audit Trail,
//                  CSRF Form Fix (TTL Tuner & Watchlist),
//                  TTL Tuner UX Overhaul, DNS Provider Detection Expansion (5→15),
//                  NS Provider-Locked Display, Mobile Homepage Scroll Fix,
//                  Navbar Dropdown Refinement, HTTP Observatory A+ Infrastructure,
//                  Secure Cookie Infrastructure, TTL Tuner Mobile Responsive Table,
//                  SonarCloud Quality Gate Fixes
//      dateFeb23 — Architecture Page TLP:GREEN Redesign, Currency Level Hero Card Label,
//                  PWA Icon Edge Cleanup
//      dateFeb21 — Misplaced DMARC Record Detection, Covert Mode Recon Report UI,
//                  High-DPI PWA Icon Regeneration, Origin Story Page,
//                  ASCII Art Homepage Hero
//      dateFeb19 — Architecture Diagrams, miekg/dns v2 Migration, CT Resilience,
//                  History Table Cleanup, Brand Verdict Overhaul, DKIM Selector Expansion,
//                  Privacy-Preserving Analytics, Admin Analytics Dashboard,
//                  Admin Dashboard + JSON Export, Admin Bootstrap Fix,
//                  UNLIKELY Badge Color Unification
//      dateFeb18 — Google OAuth 2.0 + PKCE, Security Redaction & Mission Statement
//      dateFeb17 — BUSL-1.1 License Migration, Boundary Integrity Test Suite
//      dateFeb15 — Dual Intelligence Products (Engineer's DNS Intelligence Report & Executive's DNS Intelligence Brief), OpenPhish Threat
//                  Intelligence Attribution, Email Header Analyzer Homepage Promotion
//      dateFeb14 — High-Speed Subdomain Discovery
//      dateFeb13 — DNS History Cache, Verify It Yourself, Confidence Indicators,
//                  SMTP Transport Verification, AI Surface Scanner, DNS History
//                  Timeline, Enhanced Remediation Engine, Email Security Mgmt
//      dateFeb12 — Intelligence Sources Inventory, PTR-Based Hosting Detection,
//                  IP-to-ASN Attribution, DANE/TLSA, Go Rewrite, IP Investigation,
//                  Email Header Analyzer, Enterprise DNS Detection
//      dateFeb11 — Incident Disclosure, Honest Data Reporting
// dns-tool:scrutiny design
package handlers

const (
        dateMar25 = "Mar 25, 2026"
        dateMar24 = "Mar 24, 2026"
        dateMar20 = "Mar 20, 2026"
        dateMar19 = "Mar 19, 2026"
        dateMar18 = "Mar 18, 2026"
        dateMar14 = "Mar 14, 2026"
        dateMar12 = "Mar 12, 2026"
        dateMar10 = "Mar 10, 2026"
        dateMar08 = "Mar 8, 2026"
        dateMar06 = "Mar 6, 2026"
        dateFeb28 = "Feb 28, 2026"
        dateFeb26 = "Feb 26, 2026"
        dateFeb23 = "Feb 23, 2026"
        dateFeb21 = "Feb 21, 2026"
        dateFeb19 = "Feb 19, 2026"
        dateFeb18 = "Feb 18, 2026"
        dateFeb17 = "Feb 17, 2026"
        dateFeb15 = "Feb 15, 2026"
        dateFeb14 = "Feb 14, 2026"
        dateFeb13 = "Feb 13, 2026"
        dateFeb12 = "Feb 12, 2026"
        dateFeb11 = "Feb 11, 2026"
        dateJan22 = "Jan 22, 2026"
        dateNov05 = "Nov 5, 2025"
        dateJun05 = "Jun 5, 2025"
        dateMay24 = "May 24, 2025"
        dateMay18 = "May 18, 2025"
        dateNov23 = "Nov 5, 2023"
        date2019  = "2019"

        ver263832 = "26.38.32"
        ver263830 = "26.38.30"
        ver263802 = "26.38.02"
        ver263732 = "26.37.32"
        ver263716 = "26.37.16"
        ver263611 = "26.36.11"
        ver263609 = "26.36.09"
        ver263535 = "26.35.35"
        ver263534 = "26.35.34"
        ver263440 = "26.34.40"
        ver263439 = "26.34.39"
        ver263438 = "26.34.38"
        ver262823 = "26.28.23"
        ver262822 = "26.28.22"
        ver262821 = "26.28.21"
        ver262820 = "26.28.20"
        ver262704 = "26.27.04"
        ver262703 = "26.27.03"
        ver262701 = "26.27.01"
        ver262525 = "26.25.25"
        ver262225 = "26.22.25"
        ver262088 = "26.20.88"
        ver262076 = "26.20.76"

        iconShieldAlt  = "shield-alt"
        iconMobileAlt  = "mobile-alt"
        iconSatDish    = "satellite-dish"

        catIntelligence = "Intelligence"
        catSecurity     = "Security"
        catTransparency = "Transparency"
        catBrand        = "Brand"
        catOrigins      = "Origins"
        catCore         = "Core"
        catUX           = "UX"
)

type ChangelogEntry struct {
        Version     string
        Date        string
        Category    string
        Title       string
        Description string
        Icon        string
        IsIncident  bool
        IsLegacy    bool
}

func GetRecentChangelog(n int) []ChangelogEntry {
        all := GetChangelog()
        if len(all) <= n {
                return all
        }
        return all[:n]
}
