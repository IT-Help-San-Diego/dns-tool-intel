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

// Control is one entry in the ICSAE catalog (a single DNS security control whose
// failure constitutes an enumerated DNS vulnerability).
type Control struct {
        ID              string   `json:"id"`
        Title           string   `json:"title"`
        Severity        string   `json:"severity"`
        Requires        []string `json:"requires"`
        RequiresAny     []string `json:"requires_any"`
        AppliesWhen     []string `json:"applies_when"`
        Standards       []string `json:"standards"`
        RFCs            []string `json:"rfcs"`
        Rationale       string   `json:"rationale"`
        FailExplanation string   `json:"fail_explanation"`
}

// Registry is the parsed catalog file.
type Registry struct {
        SchemaVersion int       `json:"schema_version"`
        Engine        string    `json:"engine"`
        EngineName    string    `json:"engine_name"`
        Mappings      []Control `json:"mappings"`
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
