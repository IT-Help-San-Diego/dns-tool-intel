// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/db"
	"dnstool/go-server/internal/dbq"

	"github.com/gin-gonic/gin"
)

const remediationTemplate = "remediation.html"

type RemediationHandler struct {
	DB          *db.Database
	Config      *config.Config
	lookupStore LookupStore
}

func (h *RemediationHandler) store() LookupStore {
	if h.lookupStore != nil {
		return h.lookupStore
	}
	if h.DB != nil {
		return h.DB.Queries
	}
	return nil
}

func NewRemediationHandler(database *db.Database, cfg *config.Config) *RemediationHandler {
	return &RemediationHandler{DB: database, Config: cfg}
}

func (h *RemediationHandler) RemediationPage(c *gin.Context) {
	analysisIDStr := c.Query("analysis_id")
	domain := c.Query("domain")

	data := NewTemplateData(c, h.Config, "remediation")
	data[strShowform] = true
	data["BaseURL"] = h.Config.BaseURL

	if analysisIDStr == "" && domain == "" {
		c.HTML(http.StatusOK, remediationTemplate, data)
		return
	}

	analysis, ok := h.resolveAnalysis(c, analysisIDStr, domain, data)
	if !ok {
		return
	}

	if analysis.Private && !h.checkPrivateAccess(c, analysis.ID) {
		data["FlashMessages"] = []FlashMessage{{Category: mapKeyDanger, Message: "This analysis is private. Please sign in to access it."}}
		c.HTML(http.StatusOK, remediationTemplate, data)
		return
	}

	h.renderRemediationResults(c, analysis, data)
}

func (h *RemediationHandler) resolveAnalysis(c *gin.Context, analysisIDStr, domain string, data gin.H) (dbq.DomainAnalysis, bool) {
	ctx := c.Request.Context()

	if analysisIDStr != "" {
		return h.resolveByID(c, ctx, analysisIDStr, data)
	}
	return h.resolveByDomain(c, ctx, domain, data)
}

func (h *RemediationHandler) resolveByID(c *gin.Context, ctx context.Context, idStr string, data gin.H) (dbq.DomainAnalysis, bool) {
	id, parseErr := strconv.ParseInt(idStr, 10, 32)
	if parseErr != nil {
		data["FlashMessages"] = []FlashMessage{{Category: mapKeyDanger, Message: "Invalid analysis ID."}}
		c.HTML(http.StatusOK, remediationTemplate, data)
		return dbq.DomainAnalysis{}, false
	}
	analysis, err := h.store().GetAnalysisByID(ctx, int32(id))
	if err != nil {
		data["FlashMessages"] = []FlashMessage{{Category: mapKeyDanger, Message: "Analysis not found. Please check the scan number and try again."}}
		c.HTML(http.StatusOK, remediationTemplate, data)
		return dbq.DomainAnalysis{}, false
	}
	return analysis, true
}

func (h *RemediationHandler) resolveByDomain(c *gin.Context, ctx context.Context, domain string, data gin.H) (dbq.DomainAnalysis, bool) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		data["FlashMessages"] = []FlashMessage{{Category: mapKeyDanger, Message: "Please enter a valid domain name."}}
		data["FormDomain"] = domain
		c.HTML(http.StatusOK, remediationTemplate, data)
		return dbq.DomainAnalysis{}, false
	}
	analysis, err := h.store().GetRecentAnalysisByDomain(ctx, domain)
	if err != nil {
		data["FlashMessages"] = []FlashMessage{{Category: mapKeyWarning, Message: fmt.Sprintf("No analysis found for %s. Run a scan first, then come back here.", domain)}}
		data["FormDomain"] = domain
		data["SuggestScan"] = true
		data["SuggestDomain"] = domain
		c.HTML(http.StatusOK, remediationTemplate, data)
		return dbq.DomainAnalysis{}, false
	}
	return analysis, true
}

func (h *RemediationHandler) renderRemediationResults(c *gin.Context, analysis dbq.DomainAnalysis, data gin.H) {
	if analysis.AnalysisSuccess == nil || !*analysis.AnalysisSuccess || len(analysis.FullResults) == 0 || string(analysis.FullResults) == "null" {
		data["FlashMessages"] = []FlashMessage{{Category: mapKeyWarning, Message: "This analysis did not complete successfully. No remediation data is available."}}
		c.HTML(http.StatusOK, remediationTemplate, data)
		return
	}

	results := NormalizeResults(analysis.FullResults)

	// ICSAE-first (2026-09-03, the two-verdicts defect): the history page's
	// "N issues to fix" badge reads icsae_classification.RealFixCount — the
	// reality-matched, counted-once headline. The legacy remediation field's
	// all_fixes is a SECOND, older producer of the same count that stopped
	// receiving new control IDs (NO_MAIL_HARDENED is classified a real fix
	// by ICSAE but never enters all_fixes), so a row could show "1 issue to
	// fix" on /history and "No Issues Found" on /remediation for the same
	// analysis. One count, one producer: when the ICSAE remediation queue
	// exists, render from IT (FixCount = RealFixCount); the legacy field is
	// a FALLBACK for pre-ICSAE rows only.
	if queue, hasQueue := results["icsae_remediation_queue"].(map[string]any); hasQueue {
		data["ShowResults"] = true
		data["AnalysisDomain"] = analysis.Domain
		data["AnalysisID"] = analysis.ID
		data["AnalysisTime"] = formatTimestamp(analysis.CreatedAt)
		data["PostureAchievable"], _ = results["remediation"].(map[string]any)["posture_achievable"].(string)
		items := buildRemediationItemsFromICSAE(queue)
		data["FixCount"] = len(items)
		data["TopFixes"] = nil
		data["DNSFixes"], data["ManualFixes"] = splitByDNS(items)
		c.HTML(http.StatusOK, remediationTemplate, data)
		return
	}

	remData, hasRem := results["remediation"].(map[string]any)
	if !hasRem {
		data["FlashMessages"] = []FlashMessage{{Category: "info", Message: "No remediation items found — this domain may already be well-configured."}}
		data["ShowResults"] = true
		data["AnalysisDomain"] = analysis.Domain
		data["AnalysisID"] = analysis.ID
		data["AnalysisTime"] = formatTimestamp(analysis.CreatedAt)
		data["FixCount"] = 0
		c.HTML(http.StatusOK, remediationTemplate, data)
		return
	}

	allFixes, _ := remData["all_fixes"].([]any)
	topFixes, _ := remData["top_fixes"].([]any)
	fixCount := len(allFixes)
	postureAchievable, _ := remData["posture_achievable"].(string)

	remediationItems := buildRemediationItems(allFixes)

	var dnsFixes, manualFixes []remediationItem
	for _, item := range remediationItems {
		if item.HasDNS {
			dnsFixes = append(dnsFixes, item)
		} else {
			manualFixes = append(manualFixes, item)
		}
	}

	data[strShowform] = false
	data["ShowResults"] = true
	data["AnalysisDomain"] = analysis.Domain
	data["AnalysisID"] = analysis.ID
	data["AnalysisTime"] = formatTimestamp(analysis.CreatedAt)
	data["FixCount"] = fixCount
	data["TopFixes"] = topFixes
	data["PostureAchievable"] = postureAchievable
	data["DNSFixes"] = dnsFixes
	data["ManualFixes"] = manualFixes
	data["AllFixes"] = remediationItems

	c.HTML(http.StatusOK, remediationTemplate, data)
}

func (h *RemediationHandler) RemediationSubmit(c *gin.Context) {
	analysisID := strings.TrimSpace(c.PostForm("analysis_id"))
	domain := strings.TrimSpace(c.PostForm("domain"))

	if analysisID != "" {
		c.Redirect(http.StatusSeeOther, "/remediation?analysis_id="+analysisID)
		return
	}
	if domain != "" {
		domain = strings.ToLower(domain)
		c.Redirect(http.StatusSeeOther, "/remediation?domain="+domain)
		return
	}
	c.Redirect(http.StatusSeeOther, "/remediation")
}

func (h *RemediationHandler) checkPrivateAccess(c *gin.Context, analysisID int32) bool {
	auth, exists := c.Get(mapKeyAuthenticated)
	if !exists || auth != true {
		return false
	}
	uid, ok := c.Get(mapKeyUserId)
	if !ok {
		return false
	}
	userID, ok := uid.(int32)
	if !ok {
		return false
	}
	isOwner, err := h.store().CheckAnalysisOwnership(c.Request.Context(), dbq.CheckAnalysisOwnershipParams{
		AnalysisID: analysisID,
		UserID:     userID,
	})
	return err == nil && isOwner
}

type remediationItem struct {
	Title          string
	Description    string
	Section        string
	SeverityLabel  string
	SeverityColor  string
	RFC            string
	RFCURL         string
	HasDNS         bool
	DNSType        string
	DNSHost        string
	DNSValue       string
	DNSPurpose     string
	DNSHostHelp    string
	DNSRecord      string
	CopyableRecord string
}

func buildRemediationItems(allFixes []any) []remediationItem {
	items := make([]remediationItem, 0, len(allFixes))
	for _, f := range allFixes {
		fixMap, ok := f.(map[string]any)
		if !ok {
			raw, marshalOK := json.Marshal(f)
			if marshalOK != nil {
				continue
			}
			if json.Unmarshal(raw, &fixMap) != nil {
				continue
			}
		}

		item := remediationItem{
			Title:         getStr(fixMap, "title"),
			Description:   getStr(fixMap, "fix"),
			Section:       getStr(fixMap, "section"),
			SeverityLabel: getStr(fixMap, "severity_label"),
			SeverityColor: getStr(fixMap, "severity_color"),
			RFC:           getStr(fixMap, "rfc"),
			RFCURL:        getStr(fixMap, "rfc_url"),
		}

		dnsHost := getStr(fixMap, "dns_host")
		dnsType := getStr(fixMap, "dns_type")
		dnsValue := getStr(fixMap, "dns_value")

		if dnsHost != "" && dnsType != "" {
			item.HasDNS = true
			item.DNSType = dnsType
			item.DNSHost = dnsHost
			item.DNSValue = dnsValue
			item.DNSPurpose = getStr(fixMap, "dns_purpose")
			item.DNSHostHelp = getStr(fixMap, "dns_host_help")
			item.CopyableRecord = buildCopyableRecord(dnsType, dnsHost, dnsValue)
		} else if rec := getStr(fixMap, "dns_record"); rec != "" {
			item.HasDNS = true
			item.DNSRecord = rec
			item.CopyableRecord = rec
		}

		items = append(items, item)
	}
	return items
}

func buildCopyableRecord(dnsType, host, value string) string {
	if value == "" {
		return ""
	}
	return fmt.Sprintf("%s  %s  %s", host, dnsType, value)
}

func getStr(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Sprintf("%v", v)
	}
	return s
}

func init() {
	slog.Debug("remediation handler registered")
}

// buildRemediationItemsFromICSAE renders the ICSAE remediation queue into the
// template's remediationItem shape — one producer for the fix list, matching
// the history page's RealFixCount badge (the two-verdicts defect, 2026-09-03).
// Section carries the exploit class; Description carries the attacker action +
// exploit basis so the "why" stays visible; severity labels/colors derive from
// the queue's own severity.
func buildRemediationItemsFromICSAE(queue map[string]any) []remediationItem {
	rawItems, _ := queue["items"].([]any)
	items := make([]remediationItem, 0, len(rawItems))
	for _, it := range rawItems {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		severity := getStr(m, "severity")
		item := remediationItem{
			Title:         getStr(m, "title"),
			Description:   buildICSAEDescription(m),
			Section:       "Real Fix — " + getStr(m, "exploit_class"),
			SeverityLabel: strings.ToUpper(severity[:1]) + severity[1:],
			RFC:           firstRFC(m),
		}
		item.SeverityColor = severityColorFor(severity)
		items = append(items, item)
	}
	return items
}

func buildICSAEDescription(m map[string]any) string {
	parts := []string{}
	if v := getStr(m, "attacker_action"); v != "" {
		parts = append(parts, v)
	}
	if v := getStr(m, "exploit_basis"); v != "" {
		parts = append(parts, "Exploitability: "+v)
	}
	if v := getStr(m, "blast_basis"); v != "" {
		parts = append(parts, "Blast radius: "+v)
	}
	if v := getStr(m, "confidence_basis"); v != "" {
		parts = append(parts, "Confidence: "+v)
	}
	return strings.Join(parts, " ")
}

func firstRFC(m map[string]any) string {
	rfcs, _ := m["rfcs"].([]any)
	if len(rfcs) == 0 {
		return ""
	}
	return getStr(map[string]any{"v": rfcs[0]}, "v")
}

func severityColorFor(severity string) string {
	switch severity {
	case "high":
		return "danger"
	case "medium":
		return "warning"
	default:
		return "info"
	}
}

// splitByDNS partitions remediation items the way the legacy path does. ICSAE
// queue items carry no paste-ready DNS record yet (the queue is triage, not a
// zone patch), so they render as manual fixes unless they grow dns_* fields.
func splitByDNS(items []remediationItem) (dns, manual []remediationItem) {
	for _, it := range items {
		if it.HasDNS {
			dns = append(dns, it)
		} else {
			manual = append(manual, it)
		}
	}
	return dns, manual
}
