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
        const constantDefFile = "internal/handlers/agent_wrappers.go"
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
                        if !strings.Contains(line, forbiddenPhrase) {
                                continue
                        }

                        trimmed := strings.TrimSpace(line)
                        if rel == constantDefFile &&
                                strings.HasPrefix(trimmed, "confidenceMethodology") &&
                                strings.Contains(trimmed, `= "`) {
                                continue
                        }

                        violations = append(violations,
                                fmt.Sprintf("  %s:%d: %s", rel, lineNum, trimmed))
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
                t.Errorf("found hardcoded methodology phrase %q outside constant definition — use confidenceMethodology or confidenceMethodologyICD instead:\n%s",
                        forbiddenPhrase, strings.Join(violations, "\n"))
        }
}
