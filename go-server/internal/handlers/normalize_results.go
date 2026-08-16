// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"encoding/json"
	"fmt"
	"strings"

	"dnstool/go-server/internal/analyzer"
)

const (
	mapKeyAnswer    = "answer"
	mapKeyColor     = "color"
	mapKeyError     = "error"
	mapKeyPosture   = "posture"
	mapKeyReason    = "reason"
	mapKeySecondary = "secondary"
	mapKeyState     = "state"
	mapKeySuccess   = "success"
	mapKeyUnknown   = "unknown"
	mapKeyUserId    = "user_id"
	strPossible     = "Possible"
	strProtected    = "Protected"
	strSecure       = "Secure"
	answerYes       = "Yes"
)

var normalizeDefaults = map[string]interface{}{
	"basic_records":         map[string]interface{}{},
	"authoritative_records": map[string]interface{}{},
	mapKeySpfAnalysis:       map[string]interface{}{mapKeyStatus: mapKeyUnknown, "records": []interface{}{}},
	mapKeyDmarcAnalysis:     map[string]interface{}{mapKeyStatus: mapKeyUnknown, "policy": nil, "records": []interface{}{}},
	"dkim_analysis":         map[string]interface{}{mapKeyStatus: mapKeyUnknown, "selectors": map[string]interface{}{}},
	"registrar_info":        map[string]interface{}{"registrar": nil, "source": nil},
	mapKeyPosture:           map[string]interface{}{mapKeyState: mapKeyUnknown, "label": "Unknown", "icon": "question-circle", mapKeyColor: mapKeySecondary, "message": "Posture data unavailable", "deliberate_monitoring": false, "deliberate_monitoring_note": "", "issues": []interface{}{}, "monitoring": []interface{}{}, "configured": []interface{}{}, "absent": []interface{}{}},
	"dane_analysis":         map[string]interface{}{mapKeyStatus: "info", "has_dane": false, "tlsa_records": []interface{}{}, "issues": []interface{}{}},
	"mta_sts_analysis":      map[string]interface{}{mapKeyStatus: mapKeyWarning},
	"tlsrpt_analysis":       map[string]interface{}{mapKeyStatus: mapKeyWarning},
	"bimi_analysis":         map[string]interface{}{mapKeyStatus: mapKeyWarning},
	"caa_analysis":          map[string]interface{}{mapKeyStatus: mapKeyWarning},
	"dnssec_analysis":       map[string]interface{}{mapKeyStatus: mapKeyWarning},
	"ct_subdomains":         map[string]interface{}{},
	"mail_posture":          map[string]interface{}{"classification": mapKeyUnknown},
	"_data_freshness":       map[string]interface{}{},
}

var legacyPostureStates = map[string]string{
	"Low":           "Low Risk",
	"Medium":        "Medium Risk",
	"High":          "High Risk",
	"Critical":      "Critical Risk",
	"STRONG":        strSecure,
	"Informational": strSecure,
	"MODERATE":      "Medium Risk",
	"WEAK":          "High Risk",
	"NONE":          "Critical Risk",
}

func NormalizeResults(fullResults json.RawMessage) map[string]interface{} {
	if len(fullResults) == 0 {
		return nil
	}

	var results map[string]interface{}
	if json.Unmarshal(fullResults, &results) != nil {
		return nil
	}

	for key, defaultVal := range normalizeDefaults {
		if _, exists := results[key]; !exists {
			results[key] = defaultVal
		}
	}

	if posture, ok := results[mapKeyPosture].(map[string]interface{}); ok {
		if state, ok := posture[mapKeyState].(string); ok {
			if normalized, found := legacyPostureStates[state]; found {
				posture[mapKeyState] = normalized
			}
			if posture[mapKeyState] == strSecure {
				posture[mapKeyColor] = mapKeySuccess
				posture["icon"] = "shield-alt"
			}
		}
		normalizeVerdicts(results, posture)
	}

	// Legacy remediation rows persisted "Secure" as the achievable posture.
	// The instrument measures configuration work, not safety — badge_embed's
	// own doctrine says no badge claims Secure — so rebucket to "Hardened"
	// at view time (same pattern as the DNSSEC backfill below). New rows
	// write "Hardened" at scan time (remediation.go computeAchievablePosture).
	if rem, ok := results["remediation"].(map[string]interface{}); ok {
		if rem["posture_achievable"] == "Secure" {
			rem["posture_achievable"] = "Hardened"
		}
	}

	// Backfill the DNSSEC display_label/severity for rows written before those
	// fields existed, so old reports render the same honest verdict as a fresh
	// scan (single source of truth, never re-derived per-template).
	analyzer.RebucketDNSSECDisplayLabel(results)

	return results
}

func normalizeVerdicts(results, posture map[string]interface{}) {
	verdicts, ok := posture["verdicts"].(map[string]interface{})
	if !ok {
		return
	}

	normalizeVerdictAnswers(verdicts)
	normalizeAIVerdicts(results, verdicts)
	normalizeEmailAnswer(verdicts)
}

func normalizeEmailAnswer(verdicts map[string]interface{}) {
	if _, has := verdicts["email_answer_short"]; has {
		return
	}
	emailAnswer, ok := verdicts["email_answer"].(string)
	if !ok || emailAnswer == "" {
		return
	}
	parts := strings.SplitN(emailAnswer, " — ", 2)
	if len(parts) == 2 {
		answer := parts[0]
		reason := parts[1]
		color := mapKeyWarning
		switch {
		case answer == "No" || answer == "Unlikely":
			color = mapKeySuccess
		case answer == answerYes || answer == "Likely":
			color = "danger"
		case answer == "Partially" || answer == "Uncertain":
			color = mapKeyWarning
		}
		verdicts["email_answer_short"] = answer
		verdicts["email_answer_reason"] = reason
		verdicts["email_answer_color"] = color
	}
}

func normalizeVerdictAnswers(verdicts map[string]interface{}) {
	answerMap := map[string]map[string]string{
		"dns_tampering": {
			strProtected:     "No",
			"Exposed":        answerYes,
			"Not Configured": strPossible,
		},
		"brand_impersonation": {
			strProtected:          "No",
			"Exposed":             answerYes,
			"Mostly Protected":    strPossible,
			"Partially Protected": strPossible,
			"Basic":               "Likely",
		},
		"certificate_control": {
			"Configured":     answerYes,
			"Not Configured": "No",
		},
		"transport": {
			"Fully Protected": answerYes,
			strProtected:      answerYes,
			"Monitoring":      "Partially",
			"Not Enforced":    "No",
		},
	}

	for key, labelToAnswer := range answerMap {
		normalizeVerdictEntry(verdicts, key, labelToAnswer)
	}
}

func normalizeVerdictEntry(verdicts map[string]interface{}, key string, labelToAnswer map[string]string) {
	v, ok := verdicts[key].(map[string]interface{})
	if !ok {
		return
	}
	if _, hasAnswer := v[mapKeyAnswer]; hasAnswer {
		return
	}
	label, ok := v["label"].(string)
	if !ok {
		label = ""
	}
	if ans, found := labelToAnswer[label]; found {
		v[mapKeyAnswer] = ans
	}
	reasonPrefixes := []string{"No — ", "Yes — ", "Possible — "}
	if reason, ok := v[mapKeyReason].(string); ok {
		for _, prefix := range reasonPrefixes {
			if strings.HasPrefix(reason, prefix) {
				v[mapKeyReason] = strings.TrimPrefix(reason, prefix)
				break
			}
		}
	}
}

func normalizeLLMsTxtVerdict(llmsTxt map[string]interface{}) map[string]interface{} {
	found, ok := llmsTxt["found"].(bool)
	if !ok {
		found = false
	}
	fullFound, ok := llmsTxt["full_found"].(bool)
	if !ok {
		fullFound = false
	}
	if found && fullFound {
		return map[string]interface{}{mapKeyAnswer: answerYes, mapKeyColor: mapKeySuccess, mapKeyReason: "llms.txt and llms-full.txt published — AI models receive structured context about this domain"}
	}
	if found {
		return map[string]interface{}{mapKeyAnswer: answerYes, mapKeyColor: mapKeySuccess, mapKeyReason: "llms.txt published — AI models receive structured context about this domain"}
	}
	return map[string]interface{}{mapKeyAnswer: "No", mapKeyColor: mapKeySecondary, mapKeyReason: "No llms.txt file detected — AI models have no structured instructions for this domain"}
}

func normalizeRobotsTxtVerdict(robotsTxt map[string]interface{}) map[string]interface{} {
	found, ok := robotsTxt["found"].(bool)
	if !ok {
		found = false
	}
	blocksAI, ok := robotsTxt["blocks_ai_crawlers"].(bool)
	if !ok {
		blocksAI = false
	}
	if found && blocksAI {
		return map[string]interface{}{mapKeyAnswer: answerYes, mapKeyColor: mapKeySuccess, mapKeyReason: "robots.txt actively blocks AI crawlers from scraping site content"}
	}
	if found {
		return map[string]interface{}{mapKeyAnswer: "No", mapKeyColor: mapKeyWarning, mapKeyReason: "robots.txt present but does not block AI crawlers — content may be freely scraped"}
	}
	return map[string]interface{}{mapKeyAnswer: "No", mapKeyColor: mapKeySecondary, mapKeyReason: "No robots.txt found — AI crawlers have unrestricted access"}
}

func normalizeCountVerdict(section map[string]interface{}, countKey, yesReason, noReason string) map[string]interface{} {
	count := getNumValue(section, countKey)
	if count > 0 {
		return map[string]interface{}{mapKeyAnswer: answerYes, mapKeyColor: "danger", mapKeyReason: fmt.Sprintf("%.0f %s", count, yesReason)}
	}
	return map[string]interface{}{mapKeyAnswer: "No", mapKeyColor: mapKeySuccess, mapKeyReason: noReason}
}

func normalizeAIVerdicts(results, verdicts map[string]interface{}) {
	if _, has := verdicts["ai_llms_txt"]; has {
		return
	}

	aiSurface, ok := results["ai_surface"].(map[string]interface{})
	if !ok {
		return
	}

	if llmsTxt, ok := aiSurface["llms_txt"].(map[string]interface{}); ok {
		verdicts["ai_llms_txt"] = normalizeLLMsTxtVerdict(llmsTxt)
	}

	if robotsTxt, ok := aiSurface["robots_txt"].(map[string]interface{}); ok {
		verdicts["ai_crawler_governance"] = normalizeRobotsTxtVerdict(robotsTxt)
	}

	if poisoning, ok := aiSurface["poisoning"].(map[string]interface{}); ok {
		verdicts["ai_poisoning"] = normalizeCountVerdict(poisoning, "ioc_count", "indicator(s) of AI recommendation manipulation detected on homepage", "No indicators of AI recommendation manipulation found")
	}

	if hidden, ok := aiSurface["hidden_prompts"].(map[string]interface{}); ok {
		verdicts["ai_hidden_prompts"] = normalizeCountVerdict(hidden, "artifact_count", "hidden prompt-like artifact(s) detected in page source", "No hidden prompt artifacts found in page source")
	}
}

func getNumValue(m map[string]interface{}, key string) float64 {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	}
	return 0
}
