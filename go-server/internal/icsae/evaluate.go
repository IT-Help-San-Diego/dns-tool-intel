// dns-tool:scrutiny science
package icsae

import "sort"

// ControlResult is the verdict for a single control on one scan.
type ControlResult struct {
        ID              string        `json:"id"`
        Title           string        `json:"title"`
        Status          string        `json:"status"` // passed | failed | not_measured | not_applicable
        Severity        string        `json:"severity"`
        Standards       []string      `json:"standards"`
        RFCs            []string      `json:"rfcs"`
        FailExplanation string        `json:"fail_explanation,omitempty"`
        WeaknessRefs    *WeaknessRefs `json:"weakness_refs,omitempty"`
}

// Result is the full ICSAE assessment for one scan. Field names mirror the
// summary produced by dns-eval/Mappings/evaluate.py (tri-state, schema v9):
// not_measured controls are excluded from the denominator — MeasuredControls
// counts only passed+failed, and a not-measured control is never a failure.
type Result struct {
        SchemaVersion int `json:"schema_version"`
        TotalControls int `json:"total_controls"`
        PassedCount   int `json:"passed_count"`
        FailedCount   int `json:"failed_count"`
        NACount       int `json:"na_count"`
        // NotMeasuredCount is how many controls had at least one required
        // observation unmeasured (and none measured false).
        NotMeasuredCount int `json:"not_measured_count"`
        // MeasuredControls is the honest denominator: passed + failed only.
        MeasuredControls int `json:"measured_controls"`
        // NullObservations lists the observation codes that were not measured
        // on this scan, sorted, so an excluded control is auditable.
        NullObservations []string        `json:"null_observations"`
        HighFailures     []string        `json:"high_failures"`
        MediumFailures   []string        `json:"medium_failures"`
        LowFailures      []string        `json:"low_failures"`
        Passed           []string        `json:"passed"`
        NotApplicable    []string        `json:"not_applicable"`
        NotMeasured      []string        `json:"not_measured"`
        Results          []ControlResult `json:"results"`
        // MappedControls is how many catalog controls carry a verified
        // CWE/CAPEC/VRT cross-reference. Reported alongside TotalControls so the
        // taxonomy-bridge coverage gap is transparent rather than implied complete.
        MappedControls int `json:"mapped_controls"`
}

// Evaluate runs the ICSAE assessment against an analyzer results map (the same
// object the Python engine sees as full_results). It mirrors evaluate.py's
// tri-state contract exactly: a control verdict is passed only when every
// required observation was measured true (requires_any: at least one measured
// true), failed only on a measured false (requires_any: all measured false),
// and not_measured otherwise — an unmeasured observation is never a failure.
func Evaluate(fr map[string]any) Result {
        return evaluateObservations(deriveObservations(fr))
}

// cloneWeaknessRefs returns a deep copy so a ControlResult never shares slice
// backing arrays or the struct pointer with the global embedded catalog, keeping
// per-request results safe to hand off under concurrent scans.
func cloneWeaknessRefs(w *WeaknessRefs) *WeaknessRefs {
        if w == nil {
                return nil
        }
        c := *w
        c.CWE = append([]string(nil), w.CWE...)
        c.CAPEC = append([]string(nil), w.CAPEC...)
        c.VRT = append([]string(nil), w.VRT...)
        return &c
}

func evaluateObservations(obs Observations) Result {
        results := make([]ControlResult, 0, len(registry.Mappings))

        for _, m := range registry.Mappings {
                title := m.Title
                if title == "" {
                        title = m.ID
                }
                cr := ControlResult{
                        ID:           m.ID,
                        Title:        title,
                        Severity:     m.Severity,
                        Standards:    m.Standards,
                        RFCs:         m.RFCs,
                        WeaknessRefs: cloneWeaknessRefs(m.WeaknessRefs),
                }

                // applies_when gate: a measured-false gate makes the control
                // not_applicable; an unmeasured gate means we cannot even decide
                // applicability — not_measured, never graded.
                if len(m.AppliesWhen) > 0 {
                        gateFalse, gateNil := scanTri(obs, m.AppliesWhen)
                        if gateFalse {
                                cr.Status = "not_applicable"
                                results = append(results, cr)
                                continue
                        }
                        if gateNil {
                                cr.Status = "not_measured"
                                results = append(results, cr)
                                continue
                        }
                }

                var status string
                switch {
                case len(m.Requires) > 0:
                        anyFalse, anyNil := scanTri(obs, m.Requires)
                        switch {
                        case anyFalse:
                                status = "failed"
                        case anyNil:
                                status = "not_measured"
                        default:
                                status = "passed"
                        }
                case len(m.RequiresAny) > 0:
                        anyTrue, allFalse := false, true
                        for _, k := range m.RequiresAny {
                                switch v := obs[k]; {
                                case v == nil:
                                        allFalse = false
                                case *v:
                                        anyTrue = true
                                        allFalse = false
                                }
                        }
                        switch {
                        case anyTrue:
                                status = "passed"
                        case allFalse:
                                status = "failed"
                        default:
                                status = "not_measured"
                        }
                default:
                        status = "not_measured"
                }

                cr.Status = status
                if status == "failed" {
                        cr.FailExplanation = m.FailExplanation
                }
                results = append(results, cr)
        }

        res := Result{
                SchemaVersion: registry.SchemaVersion,
                TotalControls: len(results),
                Results:       results,
        }

        for _, m := range registry.Mappings {
                if m.WeaknessRefs != nil {
                        res.MappedControls++
                }
        }

        for _, r := range results {
                switch r.Status {
                case "passed":
                        res.PassedCount++
                        res.Passed = append(res.Passed, r.ID)
                case "not_applicable":
                        res.NACount++
                        res.NotApplicable = append(res.NotApplicable, r.ID)
                case "not_measured":
                        res.NotMeasuredCount++
                        res.NotMeasured = append(res.NotMeasured, r.ID)
                case "failed":
                        res.FailedCount++
                        switch r.Severity {
                        case "high":
                                res.HighFailures = append(res.HighFailures, r.ID)
                        case "medium":
                                res.MediumFailures = append(res.MediumFailures, r.ID)
                        case "low":
                                res.LowFailures = append(res.LowFailures, r.ID)
                        }
                }
        }
        res.MeasuredControls = res.PassedCount + res.FailedCount

        for k, v := range obs {
                if v == nil {
                        res.NullObservations = append(res.NullObservations, k)
                }
        }
        sort.Strings(res.NullObservations)

        return res
}
