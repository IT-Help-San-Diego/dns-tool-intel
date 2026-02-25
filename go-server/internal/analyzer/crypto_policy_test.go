// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
        "errors"
        "fmt"
        "testing"
)

func TestClassifyDNSSECAlgorithm(t *testing.T) {
        tests := []struct {
                name         string
                algorithmNum int
                wantStrength string
                wantLabel    string
        }{
                {"RSAMD5 deprecated", 1, "deprecated", "Deprecated"},
                {"DSA deprecated", 3, "deprecated", "Deprecated"},
                {"RSA/SHA-1 legacy", 5, "legacy", "Legacy"},
                {"DSA-NSEC3-SHA1 deprecated", 6, "deprecated", "Deprecated"},
                {"RSASHA1-NSEC3-SHA1 legacy", 7, "legacy", "Legacy"},
                {"RSA/SHA-256 adequate", 8, "adequate", "Adequate"},
                {"RSA/SHA-512 legacy", 10, "legacy", "Legacy"},
                {"ECC-GOST deprecated", 12, "deprecated", "Deprecated"},
                {"ECDSA P-256 modern", 13, "modern", "Modern"},
                {"ECDSA P-384 modern", 14, "modern", "Modern"},
                {"Ed25519 modern", 15, "modern", "Modern"},
                {"Ed448 modern", 16, "modern", "Modern"},
                {"unknown algorithm 0", 0, "adequate", "Adequate"},
                {"unknown algorithm 99", 99, "adequate", "Adequate"},
                {"unknown algorithm -1", -1, "adequate", "Adequate"},
                {"unknown algorithm 255", 255, "adequate", "Adequate"},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := ClassifyDNSSECAlgorithm(tt.algorithmNum)
                        if got.Strength != tt.wantStrength {
                                t.Errorf("Strength = %q, want %q", got.Strength, tt.wantStrength)
                        }
                        if got.Label != tt.wantLabel {
                                t.Errorf("Label = %q, want %q", got.Label, tt.wantLabel)
                        }
                        if got.RFC == "" {
                                t.Error("RFC should not be empty")
                        }
                        if got.QuantumNote == "" {
                                t.Error("QuantumNote should not be empty")
                        }
                        if got.Observation == "" {
                                t.Error("Observation should not be empty")
                        }
                })
        }
}

func TestClassifyDNSSECAlgorithm_UnknownContainsAlgNum(t *testing.T) {
        got := ClassifyDNSSECAlgorithm(42)
        expected := fmt.Sprintf("Algorithm %d — not classified in RFC 8624", 42)
        if got.Observation != expected {
                t.Errorf("Observation = %q, want %q", got.Observation, expected)
        }
}

func TestClassifyDKIMKey(t *testing.T) {
        tests := []struct {
                name         string
                keyType      string
                keyBits      int
                wantStrength string
                wantLabel    string
        }{
                {"RSA under 1024", "rsa", 512, "deprecated", "Deprecated"},
                {"RSA 1024", "rsa", 1024, "weak", "Weak"},
                {"RSA 1025-2047 weak", "rsa", 1500, "weak", "Weak"},
                {"RSA 2048", "rsa", 2048, "adequate", "Adequate"},
                {"RSA 3072 adequate", "rsa", 3072, "adequate", "Adequate"},
                {"RSA 4096 strong", "rsa", 4096, "strong", "Strong"},
                {"RSA 0 bits deprecated", "rsa", 0, "deprecated", "Deprecated"},
                {"RSA negative bits deprecated", "rsa", -1, "deprecated", "Deprecated"},
                {"ed25519 strong", "ed25519", 256, "strong", "Strong"},
                {"ed25519 any bits strong", "ed25519", 0, "strong", "Strong"},
                {"unknown key type", "dsa", 2048, "adequate", "Adequate"},
                {"empty key type", "", 2048, "adequate", "Adequate"},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := ClassifyDKIMKey(tt.keyType, tt.keyBits)
                        if got.Strength != tt.wantStrength {
                                t.Errorf("Strength = %q, want %q", got.Strength, tt.wantStrength)
                        }
                        if got.Label != tt.wantLabel {
                                t.Errorf("Label = %q, want %q", got.Label, tt.wantLabel)
                        }
                        if got.RFC == "" {
                                t.Error("RFC should not be empty")
                        }
                        if got.Observation == "" {
                                t.Error("Observation should not be empty")
                        }
                })
        }
}

func TestClassifyDSDigest(t *testing.T) {
        tests := []struct {
                name         string
                digestType   int
                wantStrength string
                wantLabel    string
        }{
                {"SHA-1 deprecated", 1, "deprecated", "Deprecated"},
                {"SHA-256 adequate", 2, "adequate", "Adequate"},
                {"GOST deprecated", 3, "deprecated", "Deprecated"},
                {"SHA-384 strong", 4, "strong", "Strong"},
                {"unknown digest 0", 0, "adequate", "Adequate"},
                {"unknown digest 5", 5, "adequate", "Adequate"},
                {"unknown digest -1", -1, "adequate", "Adequate"},
                {"unknown digest 999", 999, "adequate", "Adequate"},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := ClassifyDSDigest(tt.digestType)
                        if got.Strength != tt.wantStrength {
                                t.Errorf("Strength = %q, want %q", got.Strength, tt.wantStrength)
                        }
                        if got.Label != tt.wantLabel {
                                t.Errorf("Label = %q, want %q", got.Label, tt.wantLabel)
                        }
                        if got.Observation == "" {
                                t.Error("Observation should not be empty")
                        }
                })
        }
}

func TestClassifyDSDigest_UnknownContainsType(t *testing.T) {
        got := ClassifyDSDigest(77)
        expected := fmt.Sprintf("DS digest type %d — not classified in RFC 8624", 77)
        if got.Observation != expected {
                t.Errorf("Observation = %q, want %q", got.Observation, expected)
        }
}

func TestClassifyHTTPError(t *testing.T) {
        tests := []struct {
                name        string
                err         error
                truncateLen int
                want        string
        }{
                {"tls error", errors.New("tls handshake failed"), 0, "SSL error"},
                {"certificate error", errors.New("x509 certificate invalid"), 0, "SSL error"},
                {"connection error", errors.New("connection refused"), 0, "Connection failed"},
                {"dial error", errors.New("dial tcp 1.2.3.4:443"), 0, "Connection failed"},
                {"timeout error", errors.New("request timeout exceeded"), 0, "Timeout"},
                {"generic error no truncate", errors.New("something else went wrong"), 0, "something else went wrong"},
                {"generic error with truncate", errors.New("a]very long error message here"), 10, "a]very lon"},
                {"generic error truncate longer than msg", errors.New("short"), 100, "short"},
                {"generic error truncate exact length", errors.New("12345"), 5, "12345"},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := classifyHTTPError(tt.err, tt.truncateLen)
                        if got != tt.want {
                                t.Errorf("classifyHTTPError() = %q, want %q", got, tt.want)
                        }
                })
        }
}

func TestStrContainsAny(t *testing.T) {
        tests := []struct {
                name    string
                s       string
                substrs []string
                want    bool
        }{
                {"match first", "Hello World", []string{"hello"}, true},
                {"match second", "Hello World", []string{"xyz", "world"}, true},
                {"no match", "Hello World", []string{"xyz", "abc"}, false},
                {"empty string", "", []string{"a"}, false},
                {"empty substrs", "hello", []string{}, false},
                {"case insensitive", "FOOBAR", []string{"foobar"}, true},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := strContainsAny(tt.s, tt.substrs...)
                        if got != tt.want {
                                t.Errorf("strContainsAny() = %v, want %v", got, tt.want)
                        }
                })
        }
}

func TestStrHasSuffix(t *testing.T) {
        tests := []struct {
                name     string
                s        string
                suffixes []string
                want     bool
        }{
                {"match", "test.txt", []string{".txt"}, true},
                {"no match", "test.txt", []string{".pdf"}, false},
                {"case insensitive", "FILE.TXT", []string{".txt"}, true},
                {"empty string", "", []string{".txt"}, false},
                {"empty suffixes", "test.txt", []string{}, false},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := strHasSuffix(tt.s, tt.suffixes...)
                        if got != tt.want {
                                t.Errorf("strHasSuffix() = %v, want %v", got, tt.want)
                        }
                })
        }
}

func TestUniqueStrings(t *testing.T) {
        tests := []struct {
                name  string
                input []string
                want  int
        }{
                {"no duplicates", []string{"a", "b", "c"}, 3},
                {"with duplicates", []string{"a", "b", "a", "c", "b"}, 3},
                {"all same", []string{"x", "x", "x"}, 1},
                {"empty", []string{}, 0},
                {"nil", nil, 0},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := uniqueStrings(tt.input)
                        if len(got) != tt.want {
                                t.Errorf("uniqueStrings() length = %d, want %d", len(got), tt.want)
                        }
                })
        }
}

func TestGetStr(t *testing.T) {
        m := map[string]any{"key": "value", "num": 42}
        if got := getStr(m, "key"); got != "value" {
                t.Errorf("getStr() = %q, want %q", got, "value")
        }
        if got := getStr(m, "num"); got != "" {
                t.Errorf("getStr() non-string = %q, want empty", got)
        }
        if got := getStr(m, "missing"); got != "" {
                t.Errorf("getStr() missing = %q, want empty", got)
        }
}

func TestGetSlice(t *testing.T) {
        m := map[string]any{
                "strings": []string{"a", "b"},
                "anys":    []any{"c", "d", 42},
                "num":     42,
        }
        if got := getSlice(m, "strings"); len(got) != 2 {
                t.Errorf("getSlice(strings) len = %d, want 2", len(got))
        }
        if got := getSlice(m, "anys"); len(got) != 2 {
                t.Errorf("getSlice(anys) len = %d, want 2 (non-strings skipped)", len(got))
        }
        if got := getSlice(m, "num"); got != nil {
                t.Errorf("getSlice(num) = %v, want nil", got)
        }
        if got := getSlice(m, "missing"); got != nil {
                t.Errorf("getSlice(missing) = %v, want nil", got)
        }
}

func TestGetBool(t *testing.T) {
        m := map[string]any{"flag": true, "str": "yes"}
        if !getBool(m, "flag") {
                t.Error("getBool(flag) = false, want true")
        }
        if getBool(m, "str") {
                t.Error("getBool(str) = true, want false")
        }
        if getBool(m, "missing") {
                t.Error("getBool(missing) = true, want false")
        }
}

func TestGetMap(t *testing.T) {
        sub := map[string]any{"inner": "val"}
        m := map[string]any{"sub": sub, "str": "hello"}
        if got := getMap(m, "sub"); got == nil || got["inner"] != "val" {
                t.Errorf("getMap(sub) unexpected result")
        }
        if got := getMap(m, "str"); got != nil {
                t.Errorf("getMap(str) = %v, want nil", got)
        }
        if got := getMap(m, "missing"); got != nil {
                t.Errorf("getMap(missing) = %v, want nil", got)
        }
}

func TestMapKeys(t *testing.T) {
        m := map[string]any{"a": 1, "b": 2}
        got := mapKeys(m)
        if len(got) != 2 {
                t.Errorf("mapKeys() len = %d, want 2", len(got))
        }
        empty := mapKeys(map[string]any{})
        if len(empty) != 0 {
                t.Errorf("mapKeys(empty) len = %d, want 0", len(empty))
        }
}

func TestDerefStr(t *testing.T) {
        s := "hello"
        if got := derefStr(&s); got != "hello" {
                t.Errorf("derefStr(&s) = %v, want hello", got)
        }
        if got := derefStr(nil); got != nil {
                t.Errorf("derefStr(nil) = %v, want nil", got)
        }
}

func TestDerefInt(t *testing.T) {
        n := 42
        if got := derefInt(&n); got != 42 {
                t.Errorf("derefInt(&n) = %v, want 42", got)
        }
        if got := derefInt(nil); got != nil {
                t.Errorf("derefInt(nil) = %v, want nil", got)
        }
}

func TestMinInt(t *testing.T) {
        if got := minInt(1, 2); got != 1 {
                t.Errorf("minInt(1,2) = %d", got)
        }
        if got := minInt(5, 3); got != 3 {
                t.Errorf("minInt(5,3) = %d", got)
        }
        if got := minInt(4, 4); got != 4 {
                t.Errorf("minInt(4,4) = %d", got)
        }
}

func TestMaxInt(t *testing.T) {
        if got := maxInt(1, 2); got != 2 {
                t.Errorf("maxInt(1,2) = %d", got)
        }
        if got := maxInt(5, 3); got != 5 {
                t.Errorf("maxInt(5,3) = %d", got)
        }
        if got := maxInt(4, 4); got != 4 {
                t.Errorf("maxInt(4,4) = %d", got)
        }
}
