package handlers

import (
        "bufio"
        "fmt"
        "os"
        "path/filepath"
        "strings"
        "testing"
)

func TestNoHardcodedMethodologyStrings(t *testing.T) {
        const forbiddenPhrase = "geometric-mean"
        const constantFile = "agent_wrappers.go"
        const thisFile = "methodology_const_test.go"

        dir := "."
        entries, err := os.ReadDir(dir)
        if err != nil {
                t.Fatalf("failed to read handlers directory: %v", err)
        }

        var violations []string

        for _, entry := range entries {
                name := entry.Name()
                if entry.IsDir() || !strings.HasSuffix(name, ".go") {
                        continue
                }
                if name == thisFile {
                        continue
                }

                path := filepath.Join(dir, name)
                f, err := os.Open(path)
                if err != nil {
                        t.Fatalf("failed to open %s: %v", name, err)
                }

                scanner := bufio.NewScanner(f)
                scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
                lineNum := 0
                for scanner.Scan() {
                        lineNum++
                        line := scanner.Text()
                        if !strings.Contains(line, forbiddenPhrase) {
                                continue
                        }

                        trimmed := strings.TrimSpace(line)
                        if name == constantFile && strings.HasPrefix(trimmed, "confidenceMethodology") &&
                                strings.Contains(trimmed, `= "`) {
                                continue
                        }

                        violations = append(violations, fmt.Sprintf("  %s:%d: %s", name, lineNum, strings.TrimSpace(line)))
                }
                f.Close()

                if err := scanner.Err(); err != nil {
                        t.Fatalf("error scanning %s: %v", name, err)
                }
        }

        if len(violations) > 0 {
                t.Errorf("found hardcoded methodology phrase %q outside constant definition — use confidenceMethodology or confidenceMethodologyICD instead:\n%s",
                        forbiddenPhrase, strings.Join(violations, "\n"))
        }
}
