// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package icae

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestFixtureCaseDomainRegistryDrift keeps FixtureCaseDomains honest in both
// directions: every real-world domain a hardcoded case classifies must be
// registered (so scans of it disclose the circular check), and every
// registered domain must still be referenced by a case (no stale entries).
//
// Detection is AST-based, not string-grep: it collects the first argument of
// every analyzer.ExportClassifyEnterpriseDNS call (literal or const) plus all
// testDomain* string constants across the package's non-test sources.
func TestFixtureCaseDomainRegistryDrift(t *testing.T) {
	fset := token.NewFileSet()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	consts := map[string]string{}
	var files []*ast.File
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, p, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", p, perr)
		}
		files = append(files, f)
		collectStringConsts(f, consts)
	}

	domainRe := regexp.MustCompile(`^[a-z0-9-]+(\.[a-z0-9-]+)+$`)
	reserved := func(d string) bool {
		// RFC 2606/6761 reserved names and synthetic never-resolves domains
		// are not real-world subjects.
		return strings.HasPrefix(d, "example.") ||
			strings.Contains(d, ".example") ||
			strings.HasSuffix(d, ".test") ||
			strings.HasSuffix(d, ".invalid") ||
			strings.HasSuffix(d, ".localhost") ||
			strings.HasPrefix(d, "thisdoesnotexist")
	}

	found := map[string]bool{}
	record := func(val string) {
		val = strings.ToLower(strings.TrimSuffix(val, "."))
		if domainRe.MatchString(val) && !reserved(val) {
			found[val] = true
		}
	}

	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "ExportClassifyEnterpriseDNS" {
				return true
			}
			if v, ok2 := resolveStringArg(call.Args[0], consts); ok2 {
				record(v)
			}
			return true
		})
	}
	for name, v := range consts {
		if strings.HasPrefix(name, "testDomain") {
			record(v)
		}
	}

	for d := range found {
		if _, ok := FixtureCaseDomains[d]; !ok {
			t.Errorf("hardcoded ICAE case classifies %q but it is not in FixtureCaseDomains — register it with the check that is circular for it", d)
		}
	}
	for d := range FixtureCaseDomains {
		if !found[d] {
			t.Errorf("FixtureCaseDomains registers %q but no case references it — remove the stale entry", d)
		}
	}
}

func collectStringConsts(f *ast.File, out map[string]string) {
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != len(vs.Values) {
				continue
			}
			for i, name := range vs.Names {
				if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if v, err := strconv.Unquote(lit.Value); err == nil {
						out[name.Name] = v
					}
				}
			}
		}
	}
}

func resolveStringArg(expr ast.Expr, consts map[string]string) (string, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			if v, err := strconv.Unquote(e.Value); err == nil {
				return v, true
			}
		}
	case *ast.Ident:
		if v, ok := consts[e.Name]; ok {
			return v, true
		}
	}
	return "", false
}
