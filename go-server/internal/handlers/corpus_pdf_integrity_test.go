package handlers

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCorpusPDFIntegrity is the audit-grade guard the architect prescribed:
// for every PDF in the published research corpus, parse the first-page
// banner via pdftotext and assert the expected
//   {classification, transform operator, determinant, mapping, DOI family}
// tuple. Any drift between a PDF's self-classification and the canonical
// expectation in this table fails the build.
//
// This test prevents recurrence of the v26.46.20 incident where the corpus
// listing page had Paper V as METACOGNITIVE while the PDF's own banner
// said NORMATIVE — a quiet drift between the website chrome and the
// scientific artifact. The corpus listing template is now generated from
// the same source of truth, but if a PDF is ever republished with a
// different banner, this test catches it before deploy.
//
// Skips cleanly if pdftotext (poppler) is not on PATH so that environments
// without the binary do not break the build; CI is expected to install it.

type corpusPDFExpectation struct {
	filename       string // basename in static/docs/
	classification string // expected classification token, after whitespace and hyphens are stripped
	transform      string // expected "T = ..." substring (raw, not normalized)
	determinant    string // expected "det = ..." substring (raw)
	mapping        string // expected mapping substring (raw, with arrow)
	doiFamily      string // expected concept DOI substring
}

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
	// Paper V (system specification) is NORMATIVE per its own §2.2 closure
	// rule (only four discrete states are valid Owl assignments; V₄ is the
	// state space, not a state) and per its own first-page banner.
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

// findCorpusStaticDocsDir locates static/docs/ relative to wherever the
// test happens to be running from. Mirrors findStaticDir's tolerance for
// being run from go-server/, repo root, or the package dir.
func findCorpusStaticDocsDir(t *testing.T) string {
	t.Helper()
	candidates := []string{
		"static/docs",                    // run from go-server/
		"go-server/static/docs",          // run from repo root
		"../../static/docs",              // run from internal/handlers/
		"../../../go-server/static/docs", // run from internal/handlers/handlers-subpkg/
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

func TestCorpusPDFIntegrity(t *testing.T) {
	pdftotextBin, err := exec.LookPath("pdftotext")
	if err != nil {
		t.Skipf("pdftotext not on PATH; skipping corpus PDF integrity audit (%v)", err)
		return
	}
	docsDir := findCorpusStaticDocsDir(t)

	for _, exp := range corpusPDFExpectations {
		exp := exp // capture for subtest closure
		t.Run(exp.filename, func(t *testing.T) {
			pdfPath := filepath.Join(docsDir, exp.filename)
			if _, err := os.Stat(pdfPath); err != nil {
				t.Fatalf("PDF missing on disk: %s (%v)", pdfPath, err)
			}

			cmd := exec.Command(pdftotextBin, "-layout", "-l", "1", pdfPath, "-")
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("pdftotext failed for %s: %v", exp.filename, err)
			}
			body := string(out)

			// Take the first ~2KB as the banner-and-cover region. The
			// classification banner is always on the first page within the
			// first few lines.
			head := body
			if len(head) > 2048 {
				head = head[:2048]
			}

			// Classification: normalize whitespace+hyphens, then substring.
			gotNormalized := stripBannerNoise(head)
			if !strings.Contains(gotNormalized, exp.classification) {
				t.Errorf("classification mismatch in %s: want banner containing %q (whitespace/hyphen-stripped), got first-page text:\n---\n%s\n---",
					exp.filename, exp.classification, head)
			}

			// Transform / determinant / mapping: raw substring match in head.
			// These use specific math glyphs (σᵥ, σₕ, C₂, +1, −1, →, ×) that
			// are stable across pdftotext renderings.
			for _, pair := range []struct {
				label string
				want  string
			}{
				{"transform", exp.transform},
				{"determinant", exp.determinant},
				{"mapping", exp.mapping},
			} {
				if !strings.Contains(head, pair.want) {
					t.Errorf("%s mismatch in %s: want %q in first-page banner, got:\n---\n%s\n---",
						pair.label, exp.filename, pair.want, head)
				}
			}

			// DOI family: search the WHOLE document, not just the head, since
			// some papers print the DOI on the cover and again in references.
			if !strings.Contains(body, exp.doiFamily) {
				t.Errorf("DOI family mismatch in %s: expected concept DOI %q to appear somewhere in the document",
					exp.filename, exp.doiFamily)
			}
		})
	}
}
