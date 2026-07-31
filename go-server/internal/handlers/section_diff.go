// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type CompareSectionDef struct {
	Key   string
	Label string
	Icon  string
}

var CompareSections = []CompareSectionDef{
	{mapKeySpfAnalysis, "SPF", "envelope-open-text"},
	{mapKeyDmarcAnalysis, "DMARC", "shield-alt"},
	{"dkim_analysis", "DKIM", "key"},
	{"dnssec_analysis", "DNSSEC", "lock"},
	{"dane_analysis", "DANE / TLSA", "certificate"},
	{"mta_sts_analysis", "MTA-STS", "paper-plane"},
	{"tlsrpt_analysis", "TLS-RPT", "file-alt"},
	{"bimi_analysis", "BIMI", "image"},
	{"caa_analysis", "CAA", "certificate"},
	{mapKeyPosture, "Mail Posture", "mail-bulk"},
}

var compareSkipKeys = map[string]bool{
	mapKeyStatus: true, mapKeyState: true, "_schema_version": true,
	"_tool_version": true, "_captured_at": true,
	// Presentation keys, not measurements: the grade colour/icon/message and the
	// spoof_door axis are recomputed from the same facts on every scan, so a
	// tool-version change re-words or re-colours them without anything about the
	// DOMAIN changing. Diffing them would report "Mail Posture changed" for
	// every pair of scans straddling a display change. Real posture movement
	// still surfaces through issues/recommendations/configured/absent/grade.
	"color": true, "icon": true, "message": true, "spoof_door": true,
}

type DetailChange struct {
	Field string      `json:"field"`
	Old   interface{} `json:"old"`
	New   interface{} `json:"new"`
}

type SectionDiff struct {
	Key           string         `json:"key"`
	Label         string         `json:"label"`
	Icon          string         `json:"icon"`
	StatusA       string         `json:"status_a"`
	StatusB       string         `json:"status_b"`
	Changed       bool           `json:"changed"`
	DetailChanges []DetailChange `json:"detail_changes"`
}

func getStatus(section map[string]interface{}) string {
	if s, ok := section[mapKeyStatus].(string); ok {
		return s
	}
	if s, ok := section[mapKeyState].(string); ok {
		return s
	}
	return mapKeyUnknown
}

func ComputeSectionDiff(secA, secB map[string]interface{}, key, label, icon string) SectionDiff {
	statusA := getStatus(secA)
	statusB := getStatus(secB)

	allKeys := make(map[string]bool)
	for k := range secA {
		allKeys[k] = true
	}
	for k := range secB {
		allKeys[k] = true
	}

	sortedKeys := make([]string, 0, len(allKeys))
	for k := range allKeys {
		if !compareSkipKeys[k] {
			sortedKeys = append(sortedKeys, k)
		}
	}
	sort.Strings(sortedKeys)

	var detailChanges []DetailChange
	for _, k := range sortedKeys {
		valA := normalizeForCompare(secA[k])
		valB := normalizeForCompare(secB[k])
		jsonA, errA := json.Marshal(valA)
		jsonB, errB := json.Marshal(valB)
		if errA != nil || errB != nil {
			slog.Debug("json.Marshal failed in section diff", "field", k, "errA", errA, "errB", errB)
			continue
		}
		if string(jsonA) != string(jsonB) {
			fieldName := strings.ReplaceAll(k, "_", " ")
			fieldName = cases.Title(language.English).String(fieldName)
			detailChanges = append(detailChanges, DetailChange{
				Field: fieldName,
				Old:   valA,
				New:   valB,
			})
		}
	}

	return SectionDiff{
		Key:           key,
		Label:         label,
		Icon:          icon,
		StatusA:       statusA,
		StatusB:       statusB,
		Changed:       statusA != statusB || len(detailChanges) > 0,
		DetailChanges: detailChanges,
	}
}

func normalizeForCompare(v interface{}) interface{} {
	arr, ok := v.([]interface{})
	if !ok || len(arr) < 2 {
		return v
	}
	strs := make([]string, len(arr))
	for i, elem := range arr {
		switch e := elem.(type) {
		case string:
			strs[i] = e
		default:
			b, err := json.Marshal(e)
			if err != nil {
				slog.Debug("json.Marshal failed in normalizeForCompare", "error", err)
				strs[i] = fmt.Sprintf("%v", e)
				continue
			}
			strs[i] = string(b)
		}
	}
	sort.Strings(strs)
	_, firstIsString := arr[0].(string)
	sorted := make([]interface{}, len(strs))
	for i, s := range strs {
		sorted[i] = parseSortedElement(s, firstIsString)
	}
	return sorted
}

func parseSortedElement(s string, firstIsString bool) interface{} {
	var parsed interface{}
	if json.Unmarshal([]byte(s), &parsed) == nil && !firstIsString {
		return parsed
	}
	return s
}

func ComputeAllDiffs(resultsA, resultsB map[string]interface{}) []SectionDiff {
	diffs := make([]SectionDiff, 0, len(CompareSections))
	for _, sec := range CompareSections {
		secA := getSection(resultsA, sec.Key)
		secB := getSection(resultsB, sec.Key)
		diffs = append(diffs, ComputeSectionDiff(secA, secB, sec.Key, sec.Label, sec.Icon))
	}
	return diffs
}

func getSection(results map[string]interface{}, key string) map[string]interface{} {
	if s, ok := results[key].(map[string]interface{}); ok {
		return s
	}
	return map[string]interface{}{}
}
