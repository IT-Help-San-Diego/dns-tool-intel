// dns-tool:scrutiny science

// Package icsae bridges the Intelligence Compliance & Standards Assessment
// Engine (ICSAE) into the live Go scan pipeline.
//
// The canonical control catalog lives at dns-eval/Mappings/dns-to-controls.json
// and is evaluated offline by the Python engine (dns-eval/Mappings/evaluate.py).
// This package embeds a copy of that catalog and ports the normalize + evaluate
// logic to Go so every scan produces the same enumerated, ID'd, severity-graded,
// RFC-cited DNS-vulnerability assessment. The catalog remains the single source
// of truth; TestCatalogInSyncWithCanonical guards against drift between the
// embedded copy and the canonical file, and the cross-check test proves the Go
// engine and the Python engine agree on every control verdict.
package icsae

import (
        _ "embed"
        "encoding/json"
)

//go:embed dns-to-controls.json
var catalogJSON []byte

// WeaknessRefs holds the verified cross-references from a control to the
// security-vulnerability taxonomies the industry uses (MITRE CWE/CAPEC and the
// Bugcrowd Vulnerability Rating Taxonomy). These bridge the standards/compliance
// lineage (RFC/ISO/NIST) the catalog already cites to the weakness/attack-pattern
// lineage, so a control failure can be explained as an exploitable vulnerability.
// Coverage is intentionally partial and verified-only: a control with no verified
// mapping omits the field rather than asserting a fabricated ID.
type WeaknessRefs struct {
        CWE               []string `json:"cwe"`
        CAPEC             []string `json:"capec"`
        VRT               []string `json:"vrt"`
        MappingConfidence string   `json:"mapping_confidence"`
        MappingRationale  string   `json:"mapping_rationale"`
}

// WeaknessRef is one entry in the weakness_registry (a verified CWE/CAPEC/VRT
// identifier resolved to its authoritative title and source URL).
type WeaknessRef struct {
        Title     string `json:"title"`
        Publisher string `json:"publisher"`
        URL       string `json:"url"`
}

// Control is one entry in the ICSAE catalog (a single DNS security control whose
// failure constitutes an enumerated DNS vulnerability).
type Control struct {
        ID              string        `json:"id"`
        Title           string        `json:"title"`
        Severity        string        `json:"severity"`
        Requires        []string      `json:"requires"`
        RequiresAny     []string      `json:"requires_any"`
        AppliesWhen     []string      `json:"applies_when"`
        Standards       []string      `json:"standards"`
        RFCs            []string      `json:"rfcs"`
        Rationale       string        `json:"rationale"`
        FailExplanation string        `json:"fail_explanation"`
        WeaknessRefs    *WeaknessRefs `json:"weakness_refs,omitempty"`
}

// Registry is the parsed catalog file.
type Registry struct {
        SchemaVersion    int                    `json:"schema_version"`
        Engine           string                 `json:"engine"`
        EngineName       string                 `json:"engine_name"`
        WeaknessRegistry map[string]WeaknessRef `json:"weakness_registry"`
        Mappings         []Control              `json:"mappings"`
}

var registry Registry

func init() {
        if err := json.Unmarshal(catalogJSON, &registry); err != nil {
                panic("icsae: failed to parse embedded catalog: " + err.Error())
        }
}

// Catalog returns the parsed control registry (read-only).
func Catalog() Registry {
        return registry
}
