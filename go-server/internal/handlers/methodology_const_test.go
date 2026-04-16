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
			return false
		},
	},
	{
		phrase: "confidence scoring",
		allowFunc: func(rel, trimmed string) bool {
			if isConstantDef(rel, trimmed) {
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

	var violations []string

	err = filepath.Walk(absRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}

		rel, err := filepath.Rel(absRoot, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)

		if rel == thisTestFile {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open %s: %w", rel, err)
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
					fmt.Sprintf("  %s:%d [%s]: %s", rel, lineNum, entry.phrase, trimmed))
			}
		}
		scanErr := scanner.Err()
		f.Close()
		if scanErr != nil {
			return fmt.Errorf("error scanning %s: %w", rel, scanErr)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk go-server tree: %v", err)
	}

	if len(violations) > 0 {
		t.Errorf("found hardcoded methodology phrases outside constant definitions — use confidenceMethodology or confidenceMethodologyICD instead:\n%s",
			strings.Join(violations, "\n"))
	}
}
