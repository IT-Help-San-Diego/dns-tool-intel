package handlers

import (
        "bufio"
        "fmt"
        "os"
        "path/filepath"
        "strings"
        "testing"
)

type forbiddenEntry struct {
        phrase    string
        allowFunc func(rel string, trimmed string) bool
}

func isConstantDef(rel, trimmed string) bool {
        if rel != "internal/handlers/agent_wrappers.go" &&
                rel != "internal/handlers/agentpkg/agent_wrappers.go" {
                return false
        }
        return strings.HasPrefix(trimmed, "confidenceMethodology") &&
                strings.Contains(trimmed, "= ")
}

var icd203TemplateFiles = map[string]bool{
        "templates/admin.html":             true,
        "templates/agent_plugin.html":      true,
        "templates/analysis_crossref.html": true,
        "templates/approach.html":          true,
        "templates/architecture.html":      true,
        "templates/confidence.html":        true,
        "templates/ede.html":               true,
        "templates/index.html":             true,
        "templates/publications.html":      true,
        "templates/reference_library.html": true,
        "templates/results.html":           true,
        "templates/stats.html":             true,
        "static/manifest.json":              true,
        "static/data/integrity_stats.json":   true,
}

var confidenceScoringTemplateFiles = map[string]bool{
        "templates/agent_plugin.html":      true,
        "templates/approach.html":          true,
        "templates/confidence.html":        true,
        "templates/manifesto.html":         true,
        "templates/reference_library.html": true,
        "templates/stats.html":             true,
        "static/manifest.json":              true,
}

var forbiddenPhrases = []forbiddenEntry{
        {
                phrase: "geometric-mean",
                allowFunc: func(rel, trimmed string) bool {
                        return isConstantDef(rel, trimmed)
                },
        },
        {
                phrase: "multi-factor",
                allowFunc: func(rel, trimmed string) bool {
                        return isConstantDef(rel, trimmed)
                },
        },
        {
                phrase: "ICD 203",
                allowFunc: func(rel, trimmed string) bool {
                        if isConstantDef(rel, trimmed) {
                                return true
                        }
                        if icd203TemplateFiles[rel] {
                                return true
                        }
                        if rel == "internal/handlers/analysis.go" &&
                                (strings.Contains(trimmed, "mapKeyStandard:") ||
                                        strings.Contains(trimmed, `"standards":`)) {
                                return true
                        }
                        if rel == "internal/handlers/analysis.go" &&
                                strings.Contains(trimmed, `sb.WriteString("#   Standards:`) {
                                return true
                        }
                        if rel == "internal/handlers/changelog.go" &&
                                strings.HasPrefix(trimmed, "Description:") {
                                return true
                        }
                        if rel == "internal/handlers/roadmap.go" &&
                                strings.HasPrefix(trimmed, "{Title:") {
                                return true
                        }
                        if rel == "internal/icae/calibration.go" &&
                                strings.HasPrefix(trimmed, "//") &&
                                strings.Contains(trimmed, "Calibration") {
                                return true
                        }
                        if rel == "internal/icuae/icuae.go" &&
                                strings.HasPrefix(trimmed, "//") &&
                                strings.Contains(trimmed, "Timeliness") {
                                return true
                        }
                        // integrity_stats.json is an audit-finding ledger; "ICD 203"
                        // appears in narrative confidence_impact / bayesian_note text,
                        // not as a methodology declaration.
                        if rel == "static/data/integrity_stats.json" ||
                                rel == "data/integrity_stats.json" {
                                return true
                        }
                        return false
                },
        },
        {
                phrase: "confidence scoring",
                allowFunc: func(rel, trimmed string) bool {
                        if isConstantDef(rel, trimmed) {
                                return true
                        }
                        if confidenceScoringTemplateFiles[rel] {
                                return true
                        }
                        if rel == "internal/icae/calibration.go" &&
                                strings.HasPrefix(trimmed, "//") &&
                                strings.Contains(trimmed, "Calibration Validation") {
                                return true
                        }
                        return false
                },
        },
}

func TestNoHardcodedMethodologyStrings(t *testing.T) {
        const thisTestFile = "internal/handlers/methodology_const_test.go"

        goServerRoot := filepath.Join("..", "..")

        absRoot, err := filepath.Abs(goServerRoot)
        if err != nil {
                t.Fatalf("failed to resolve go-server root: %v", err)
        }

        // Also walk the top-level repo static/ tree if present. findStaticDir() in
        // cmd/server/main.go prefers top-level "static" over "go-server/static",
        // so guarding only the go-server tree leaves served assets unchecked.
        absRepoStatic, err := filepath.Abs(filepath.Join("..", "..", "..", "static"))
        if err != nil {
                t.Fatalf("failed to resolve repo static dir: %v", err)
        }

        scanRoots := []string{absRoot}
        if info, statErr := os.Stat(absRepoStatic); statErr == nil && info.IsDir() {
                scanRoots = append(scanRoots, absRepoStatic)
        }

        var violations []string

        walkFn := func(scanRoot string) filepath.WalkFunc {
                return func(path string, info os.FileInfo, err error) error {
                        if err != nil {
                                return err
                        }
                        if info.IsDir() {
                                return nil
                        }
                        if !strings.HasSuffix(path, ".go") &&
                                !strings.HasSuffix(path, ".html") &&
                                !strings.HasSuffix(path, ".tmpl") &&
                                !strings.HasSuffix(path, ".js") &&
                                !strings.HasSuffix(path, ".json") {
                                return nil
                        }

                        rel, err := filepath.Rel(scanRoot, path)
                        if err != nil {
                                return err
                        }
                        rel = filepath.ToSlash(rel)

                        // Skip self when scanning the go-server tree.
                        if scanRoot == absRoot && rel == thisTestFile {
                                return nil
                        }

                        // Tag external (repo-static) paths so allowFunc/messages stay readable.
                        displayRel := rel
                        if scanRoot != absRoot {
                                displayRel = "../static/" + rel
                        }

                        f, err := os.Open(path)
                        if err != nil {
                                return fmt.Errorf("failed to open %s: %w", displayRel, err)
                        }

                        scanner := bufio.NewScanner(f)
                        scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
                        lineNum := 0
                        for scanner.Scan() {
                                lineNum++
                                line := scanner.Text()
                                trimmed := strings.TrimSpace(line)

                                for _, entry := range forbiddenPhrases {
                                        if !strings.Contains(line, entry.phrase) {
                                                continue
                                        }
                                        if entry.allowFunc(rel, trimmed) {
                                                continue
                                        }
                                        violations = append(violations,
                                                fmt.Sprintf("  %s:%d [%s]: %s", displayRel, lineNum, entry.phrase, trimmed))
                                }
                        }
                        scanErr := scanner.Err()
                        f.Close()
                        if scanErr != nil {
                                return fmt.Errorf("error scanning %s: %w", displayRel, scanErr)
                        }
                        return nil
                }
        }

        for _, scanRoot := range scanRoots {
                if err := filepath.Walk(scanRoot, walkFn(scanRoot)); err != nil {
                        t.Fatalf("failed to walk %s: %v", scanRoot, err)
                }
        }

        if len(violations) > 0 {
                t.Errorf("found hardcoded methodology phrases outside constant definitions — use confidenceMethodology or confidenceMethodologyICD instead:\n%s",
                        strings.Join(violations, "\n"))
        }
}
