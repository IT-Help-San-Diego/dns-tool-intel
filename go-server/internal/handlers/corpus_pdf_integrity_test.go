package handlers

import (
        "os"
        "os/exec"
        "path/filepath"
        "strings"
        "testing"
)

// TestCorpusPDFIntegrity is the audit-grade guard the architect prescribed
// after the v26.46.20 incident, where the corpus listing page rendered
// Paper V as METACOGNITIVE while the actual PDF banner self-classified as
// NORMATIVE — a quiet drift between website chrome and scientific
// artifact. For every PDF in the published research corpus this test:
//
//  1. Runs `pdftotext -l 1` on the first page and locates the
//     classification banner block, then asserts the full
//     {classification, T, det, mapping} tuple within a small window after
//     that banner anchor — not "anywhere on page 1" — so the tuple cannot
//     accidentally satisfy the test by appearing in a footnote or legend
//     while the actual banner has drifted.
//  2. Runs `pdftotext` on the full document and asserts the expected
//     concept-DOI family appears somewhere in the body.
//  3. Asserts the expectation table covers every *.pdf in static/docs/, so
//     a newly added corpus paper cannot sneak in unguarded.
//
// In CI / release gate, set REQUIRE_PDF_AUDIT=1 to convert the
// "pdftotext missing on PATH" skip into a hard failure. Locally the test
// skips cleanly so dev environments without poppler do not break.

type corpusPDFExpectation struct {
        filename       string // basename in static/docs/
        classification string // classification token, after whitespace+hyphens are stripped+uppercased
        transform      string // "T = ..." substring (raw, e.g., "T = I", "T = σᵥ")
        determinant    string // "det = ..." substring (raw, e.g., "det = +1", "det = −1")
        mapping        string // mapping substring (raw, e.g., "(x, y) → (x, y)")
        doiFamily      string // expected concept DOI substring (e.g., "10.5281/zenodo.19468134")
}

// Expected banner tuples per PDF. If you add a new corpus PDF, you MUST
// add a row here or the completeness subtest will fail.
var corpusPDFExpectations = []corpusPDFExpectation{
        // DNS Tool methodology corpus — concept DOI 10.5281/zenodo.19468134
        {
                filename:       "dns-tool-methodology.pdf",
                classification: "NORMATIVE",
                transform:      "T = I",
                determinant:    "det = +1",
                mapping:        "(x, y) → (x, y)",
                doiFamily:      "10.5281/zenodo.19468134",
        },
        {
                filename:       "philosophical-foundations.pdf",
                classification: "NONNORMATIVE",
                transform:      "T = σv",
                determinant:    "det = −1",
                mapping:        "(x, y) → (−x, y)",
                doiFamily:      "10.5281/zenodo.19468134",
        },
        {
                filename:       "founders-manifesto.pdf",
                classification: "NONNORMATIVE",
                transform:      "T = σv",
                determinant:    "det = −1",
                mapping:        "(x, y) → (−x, y)",
                doiFamily:      "10.5281/zenodo.19468134",
        },
        {
                filename:       "communication-standards.pdf",
                classification: "NORMATIVE",
                transform:      "T = I",
                determinant:    "det = +1",
                mapping:        "(x, y) → (x, y)",
                doiFamily:      "10.5281/zenodo.19468134",
        },
        // Owl Semaphore corpus — concept DOI 10.5281/zenodo.19473698
        // Paper V (system spec) is NORMATIVE per its own §2.2 closure rule.
        {
                filename:       "owl-semaphore-system.pdf",
                classification: "NORMATIVE",
                transform:      "T = I",
                determinant:    "det = +1",
                mapping:        "(x, y) → (x, y)",
                doiFamily:      "10.5281/zenodo.19473698",
        },
        {
                filename:       "owl-1-normative.pdf",
                classification: "NORMATIVE",
                transform:      "T = I",
                determinant:    "det = +1",
                mapping:        "(x, y) → (x, y)",
                doiFamily:      "10.5281/zenodo.19473698",
        },
        {
                filename:       "owl-2-non-normative.pdf",
                classification: "NONNORMATIVE",
                transform:      "T = σᵥ",
                determinant:    "det = −1",
                mapping:        "(x, y) → (−x, y)",
                doiFamily:      "10.5281/zenodo.19473698",
        },
        {
                filename:       "owl-3-critical.pdf",
                classification: "CRITICAL",
                transform:      "T = C₂",
                determinant:    "det = +1",
                mapping:        "(x, y) → (−x, −y)",
                doiFamily:      "10.5281/zenodo.19473698",
        },
        {
                filename:       "owl-4-metacognitive.pdf",
                classification: "METACOGNITIVE",
                transform:      "T = σₕ",
                determinant:    "det = −1",
                mapping:        "(x, y) → (x, −y)",
                doiFamily:      "10.5281/zenodo.19473698",
        },
}

// nonCorpusDocsPDFs are dev/test scratch artifacts that live in
// static/docs/ but are NOT part of the published research corpus. They
// are explicitly listed here so the completeness check stays sharp on
// genuine corpus additions.
var nonCorpusDocsPDFs = map[string]bool{
        "dns-tool-methodology-NEW-BADGE.pdf":            true,
        "dns-tool-methodology-transparent-test.pdf":     true,
        "founders-manifesto-nonnorm-opaque-test.pdf":    true,
        "founders-manifesto-nonnorm-transparent-test.pdf": true,
        "nonnorm-palette.pdf":                           true,
        "nonnorm-palette-v2.pdf":                        true,
        "nonnorm-palette-v3.pdf":                        true,
        "nonnorm-palette-v4.pdf":                        true,
        "nonnorm-palette-v5.pdf":                        true,
        "nonnorm-palette-v6.pdf":                        true,
        "nonnorm-palette-v7.pdf":                        true,
        "owl-seal-comparison.pdf":                       true,
        "owl-seal-layers-test.pdf":                      true,
}

func findCorpusStaticDocsDir(t *testing.T) string {
        t.Helper()
        candidates := []string{
                "static/docs",
                "go-server/static/docs",
                "../../static/docs",
                "../../../go-server/static/docs",
        }
        for _, c := range candidates {
                if info, err := os.Stat(c); err == nil && info.IsDir() {
                        abs, _ := filepath.Abs(c)
                        return abs
                }
        }
        t.Fatalf("could not locate static/docs/; tried: %v", candidates)
        return ""
}

// stripBannerNoise removes whitespace and hyphens from a banner line so
// that "N O N - N O R M AT I V E" and "N O N - N O R M A T I V E" both
// normalize to "NONNORMATIVE". pdftotext output varies by whether the
// source PDF used kerned letter-spacing.
func stripBannerNoise(s string) string {
        out := make([]rune, 0, len(s))
        for _, r := range s {
                if r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '-' {
                        continue
                }
                out = append(out, r)
        }
        return strings.ToUpper(string(out))
}

// findBannerWindow locates the classification banner on page 1 and
// returns the substring spanning from the banner up through the next ~20
// lines. The full {T, det, mapping} tuple must appear inside that window;
// matches outside the window do not count.
//
// Returns (window, true) on success or ("", false) if the classification
// token is not found at all in the normalized page text.
func findBannerWindow(pageText, classification string) (string, bool) {
        lines := strings.Split(pageText, "\n")
        for i, line := range lines {
                if strings.Contains(stripBannerNoise(line), classification) {
                        end := i + 20
                        if end > len(lines) {
                                end = len(lines)
                        }
                        return strings.Join(lines[i:end], "\n"), true
                }
        }
        return "", false
}

func TestCorpusPDFIntegrity(t *testing.T) {
        pdftotextBin, err := exec.LookPath("pdftotext")
        if err != nil {
                if os.Getenv("REQUIRE_PDF_AUDIT") == "1" {
                        t.Fatalf("REQUIRE_PDF_AUDIT=1 set but pdftotext not on PATH: %v", err)
                }
                t.Skipf("pdftotext not on PATH; skipping corpus PDF integrity audit (%v)", err)
                return
        }
        docsDir := findCorpusStaticDocsDir(t)

        // Completeness: every *.pdf in static/docs/ MUST either have an
        // expectation row or appear in nonCorpusDocsPDFs (dev/test scratch).
        // Prevents a new corpus paper from being added without a guard.
        //
        // TODO(cleanup): the files in nonCorpusDocsPDFs are palette/badge/seal
        // dev artifacts that shouldn't ship in the production static/docs/
        // directory. Move them under static/dev/ or delete them when convenient.
        t.Run("completeness", func(t *testing.T) {
                entries, err := os.ReadDir(docsDir)
                if err != nil {
                        t.Fatalf("read static/docs/: %v", err)
                }
                expected := map[string]bool{}
                for _, e := range corpusPDFExpectations {
                        expected[e.filename] = true
                }
                for _, ent := range entries {
                        if ent.IsDir() {
                                continue
                        }
                        name := ent.Name()
                        if !strings.HasSuffix(strings.ToLower(name), ".pdf") {
                                continue
                        }
                        if expected[name] || nonCorpusDocsPDFs[name] {
                                continue
                        }
                        t.Errorf("PDF %q in static/docs/ has no expectation row in corpusPDFExpectations "+
                                "and is not listed in nonCorpusDocsPDFs; add it to one of the two to keep the audit complete", name)
                }
        })

        for _, exp := range corpusPDFExpectations {
                exp := exp
                t.Run(exp.filename, func(t *testing.T) {
                        pdfPath := filepath.Join(docsDir, exp.filename)
                        if _, err := os.Stat(pdfPath); err != nil {
                                t.Fatalf("PDF missing on disk: %s (%v)", pdfPath, err)
                        }

                        // Page 1 only — for banner tuple assertion.
                        pageOut, err := exec.Command(pdftotextBin, "-layout", "-l", "1", pdfPath, "-").Output()
                        if err != nil {
                                t.Fatalf("pdftotext (page 1) failed for %s: %v", exp.filename, err)
                        }
                        pageText := string(pageOut)

                        // Whole document — for DOI presence (covers cases where the
                        // concept DOI is printed on cover, references, or back matter).
                        fullOut, err := exec.Command(pdftotextBin, "-layout", pdfPath, "-").Output()
                        if err != nil {
                                t.Fatalf("pdftotext (full) failed for %s: %v", exp.filename, err)
                        }
                        fullText := string(fullOut)

                        // Anchor: locate the classification banner on page 1, then
                        // require the rest of the tuple to live within ~20 lines after
                        // it (the banner block).
                        window, found := findBannerWindow(pageText, exp.classification)
                        if !found {
                                t.Errorf("classification banner %q not found on page 1 of %s; first-page text:\n---\n%s\n---",
                                        exp.classification, exp.filename, truncForLog(pageText))
                                return
                        }

                        for _, pair := range []struct {
                                label string
                                want  string
                        }{
                                {"transform", exp.transform},
                                {"determinant", exp.determinant},
                                {"mapping", exp.mapping},
                        } {
                                if !strings.Contains(window, pair.want) {
                                        t.Errorf("%s mismatch in %s: want %q within ~20 lines of %q banner, got banner window:\n---\n%s\n---",
                                                pair.label, exp.filename, pair.want, exp.classification, window)
                                }
                        }

                        // DOI family: anywhere in the full document.
                        if !strings.Contains(fullText, exp.doiFamily) {
                                t.Errorf("DOI family mismatch in %s: expected concept DOI %q to appear somewhere in the document",
                                        exp.filename, exp.doiFamily)
                        }
                })
        }
}

func truncForLog(s string) string {
        const maxLen = 2048
        if len(s) <= maxLen {
                return s
        }
        return s[:maxLen] + "\n...[truncated]..."
}
