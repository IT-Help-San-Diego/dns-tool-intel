package handlers

import (
        "os"
        "os/exec"
        "path/filepath"
        "sort"
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

// nonCorpusDocsPDFs is the allowlist for *.pdf files in static/docs/
// that are part of the published corpus UI but do NOT carry the
// standard Owl Semaphore classification banner block on page 1
// (classification token + T = … + det = … + (x,y) → … + DOI family).
// The completeness subtest treats these as known-and-allowed so a PDF
// without the banner cannot silently slip past the audit, while the
// banner-tuple subtest correctly skips them (no banner to drift from).
//
// History: pre-v26.46.22 this map held dev/test scratch PDFs (palette
// swatches, NEW-BADGE drafts, owl-seal layer tests) which were then
// deleted from both static trees, leaving the map empty. v26.47.08
// re-introduced one entry (the-real-bot-manifesto.pdf — an essay-format
// public manifesto without the scientific-paper banner template).
var nonCorpusDocsPDFs = map[string]bool{
        "the-real-bot-manifesto.pdf": true,
}

// findCorpusStaticDocsDir resolves the canonical static/docs directory
// in the same priority order as the runtime's findStaticDir() in
// cmd/server/main.go: prefer the repo-root "static/" tree (which is
// where the PDF generators write and what findStaticDir() returns
// first), then fall back to "go-server/static/" for non-standard CWDs.
//
// Tests run with CWD set to the package directory (go-server/internal/
// handlers/), so the "../../../static/docs" candidate is what normally
// resolves; it points to the repo-root tree, matching production.
func findCorpusStaticDocsDir(t *testing.T) string {
        t.Helper()
        candidates := []string{
                "static/docs",                    // CWD = repo root
                "go-server/static/docs",          // CWD = repo root, repo-static missing
                "../../../static/docs",           // CWD = go-server/internal/handlers (live tree)
                "../../static/docs",              // CWD = go-server/internal (live tree)
                "../../../go-server/static/docs", // CWD = go-server/internal/handlers (fallback)
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

// findAllStaticDocsDirs returns absolute paths to every static/docs
// tree that exists in this repo (typically two: repo-root static/docs
// and go-server/static/docs). Used by the drift-guard subtest to
// enforce byte-identity across both trees so the live-served copy and
// the in-package copy can never silently diverge again.
//
// The candidate order is intentionally aligned with
// findCorpusStaticDocsDir / runtime findStaticDir so that dirs[0] is
// reliably the canonical repo-root tree regardless of test CWD. This
// matters for the drift-guard error messages which call out one tree
// as canonical when reporting asymmetric presence.
func findAllStaticDocsDirs(t *testing.T) []string {
        t.Helper()
        candidates := []string{
                // Canonical (repo-root static/docs) first, matching runtime priority.
                "static/docs",            // CWD = repo root
                "../../../static/docs",   // CWD = go-server/internal/handlers
                "../../static/docs",      // CWD = go-server/internal
                // Fallback (go-server/static/docs duplicate tree).
                "go-server/static/docs",          // CWD = repo root
                "../../../go-server/static/docs", // CWD = go-server/internal/handlers
        }
        seen := map[string]bool{}
        var out []string
        for _, c := range candidates {
                if info, err := os.Stat(c); err == nil && info.IsDir() {
                        abs, _ := filepath.Abs(c)
                        if !seen[abs] {
                                seen[abs] = true
                                out = append(out, abs)
                        }
                }
        }
        return out
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

        // Drift guard: when both static trees exist (repo-root static/docs
        // AND go-server/static/docs), every *.pdf present in BOTH must be
        // byte-identical. This is the test-side companion to the v26.46.22
        // remediation that resync'd two corpus PDFs after a silent ~100-byte
        // metadata drift between trees. The runtime's findStaticDir() picks
        // "static" first then "go-server/static", so any future drift would
        // once again cause the integrity audit to verify a different copy
        // than what users are served. This subtest closes that loop by
        // failing if the two trees ever disagree.
        t.Run("no_drift_between_static_trees", func(t *testing.T) {
                dirs := findAllStaticDocsDirs(t)
                if len(dirs) < 2 {
                        t.Skipf("only one static/docs tree present (%v); drift guard not applicable", dirs)
                        return
                }
                // Use the first two distinct trees discovered (typically the
                // canonical repo-root static/docs and the go-server/static/docs
                // duplicate). Sweep is symmetric: build the UNION of PDF
                // basenames across both trees so a file added only to the
                // fallback tree is still caught (per architect review of the
                // v26.46.22 cleanup — asymmetric presence is itself drift).
                a, b := dirs[0], dirs[1]
                listPDFs := func(dir string) (map[string]bool, error) {
                        out := map[string]bool{}
                        entries, err := os.ReadDir(dir)
                        if err != nil {
                                return nil, err
                        }
                        for _, ent := range entries {
                                if ent.IsDir() {
                                        continue
                                }
                                name := ent.Name()
                                if strings.HasSuffix(strings.ToLower(name), ".pdf") {
                                        out[name] = true
                                }
                        }
                        return out, nil
                }
                setA, err := listPDFs(a)
                if err != nil {
                        t.Fatalf("read %s: %v", a, err)
                }
                setB, err := listPDFs(b)
                if err != nil {
                        t.Fatalf("read %s: %v", b, err)
                }
                union := map[string]bool{}
                for n := range setA {
                        union[n] = true
                }
                for n := range setB {
                        union[n] = true
                }
                // Sort the union for deterministic test output ordering.
                names := make([]string, 0, len(union))
                for n := range union {
                        names = append(names, n)
                }
                sort.Strings(names)
                for _, name := range names {
                        inA, inB := setA[name], setB[name]
                        switch {
                        case inA && !inB:
                                t.Errorf("PDF %q present in %s but MISSING from %s — asymmetric drift; sync the canonical repo-root static/docs/ to go-server/static/docs/ (or remove from both)",
                                        name, a, b)
                        case !inA && inB:
                                t.Errorf("PDF %q present in %s but MISSING from canonical %s — asymmetric drift; either copy back into the canonical tree or delete the stale duplicate from %s",
                                        name, b, a, b)
                        case inA && inB:
                                pa := filepath.Join(a, name)
                                pb := filepath.Join(b, name)
                                ba, errA := os.ReadFile(pa)
                                bb, errB := os.ReadFile(pb)
                                if errA != nil || errB != nil {
                                        t.Errorf("read failed for %s: errA=%v errB=%v", name, errA, errB)
                                        continue
                                }
                                if len(ba) != len(bb) {
                                        t.Errorf("PDF %q has BYTE DRIFT between static trees: %s=%d bytes vs %s=%d bytes — re-sync from canonical (PDF generators write to repo-root static/docs/)",
                                                name, a, len(ba), b, len(bb))
                                        continue
                                }
                                // Byte compare without computing a hash; cheap
                                // enough for the ~9 corpus PDFs.
                                for i := range ba {
                                        if ba[i] != bb[i] {
                                                t.Errorf("PDF %q is same length but DIFFERS at byte %d between static trees (%s vs %s) — re-sync from canonical",
                                                        name, i, a, b)
                                                break
                                        }
                                }
                        }
                }
        })

        // Completeness: every *.pdf in static/docs/ MUST have an
        // expectation row in corpusPDFExpectations (or, historically, an
        // entry in nonCorpusDocsPDFs — now empty post-v26.46.22 cleanup).
        // Prevents a new corpus paper from being added without a guard.
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
