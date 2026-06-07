package icsae

// ControlResult is the verdict for a single control on one scan.
type ControlResult struct {
        ID              string   `json:"id"`
        Title           string   `json:"title"`
        Status          string   `json:"status"` // passed | failed | not_applicable
        Severity        string   `json:"severity"`
        Standards       []string `json:"standards"`
        RFCs            []string `json:"rfcs"`
        FailExplanation string   `json:"fail_explanation,omitempty"`
}

// Result is the full ICSAE assessment for one scan. Field names mirror the
// summary produced by dns-eval/Mappings/evaluate.py.
type Result struct {
        SchemaVersion  int             `json:"schema_version"`
        TotalControls  int             `json:"total_controls"`
        PassedCount    int             `json:"passed_count"`
        FailedCount    int             `json:"failed_count"`
        NACount        int             `json:"na_count"`
        HighFailures   []string        `json:"high_failures"`
        MediumFailures []string        `json:"medium_failures"`
        LowFailures    []string        `json:"low_failures"`
        Passed         []string        `json:"passed"`
        NotApplicable  []string        `json:"not_applicable"`
        Results        []ControlResult `json:"results"`
}

// Evaluate runs the ICSAE assessment against an analyzer results map (the same
// object the Python engine sees as full_results). It mirrors evaluate.py exactly,
// including the canonical quirk that the requires_spf key is never consulted —
// only requires / requires_any decide a control's verdict.
func Evaluate(fr map[string]any) Result {
        return evaluateObservations(deriveObservations(fr))
}

func evaluateObservations(obs Observations) Result {
        results := make([]ControlResult, 0, len(registry.Mappings))

        for _, m := range registry.Mappings {
                title := m.Title
                if title == "" {
                        title = m.ID
                }
                cr := ControlResult{
                        ID:        m.ID,
                        Title:     title,
                        Severity:  m.Severity,
                        Standards: m.Standards,
                        RFCs:      m.RFCs,
                }

                if len(m.AppliesWhen) > 0 && !allTrue(obs, m.AppliesWhen) {
                        cr.Status = "not_applicable"
                        results = append(results, cr)
                        continue
                }

                var passed bool
                switch {
                case len(m.Requires) > 0:
                        passed = allTrue(obs, m.Requires)
                case len(m.RequiresAny) > 0:
                        passed = anyTrue(obs, m.RequiresAny)
                default:
                        passed = false
                }

                if passed {
                        cr.Status = "passed"
                } else {
                        cr.Status = "failed"
                        cr.FailExplanation = m.FailExplanation
                }
                results = append(results, cr)
        }

        res := Result{
                SchemaVersion: registry.SchemaVersion,
                TotalControls: len(results),
                Results:       results,
        }

        for _, r := range results {
                switch r.Status {
                case "passed":
                        res.PassedCount++
                        res.Passed = append(res.Passed, r.ID)
                case "not_applicable":
                        res.NACount++
                        res.NotApplicable = append(res.NotApplicable, r.ID)
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

        return res
}
