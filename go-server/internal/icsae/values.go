// dns-tool:scrutiny science
package icsae

import "reflect"

// Helpers for reading loosely-typed values out of the analyzer results map
// (map[string]any). Numbers may arrive as int (live in-memory scan) or float64
// (JSON round-trip); these helpers normalize both. The semantics intentionally
// mirror Python's dict.get(key, default) so the Go engine matches the canonical
// engine exactly.

func getMap(m map[string]any, key string) map[string]any {
        if m == nil {
                return map[string]any{}
        }
        if v, ok := m[key].(map[string]any); ok {
                return v
        }
        return map[string]any{}
}

func getString(m map[string]any, key string) string {
        if m == nil {
                return ""
        }
        if v, ok := m[key].(string); ok {
                return v
        }
        return ""
}

func getBoolDefault(m map[string]any, key string, def bool) bool {
        if m == nil {
                return def
        }
        v, present := m[key]
        if !present {
                return def
        }
        if b, ok := v.(bool); ok {
                return b
        }
        return def
}

// hasAnyKey mirrors Python `any(k in m for k in keys)` — key presence only,
// value (including an explicit JSON null) irrelevant.
func hasAnyKey(m map[string]any, keys ...string) bool {
        for _, k := range keys {
                if _, present := m[k]; present {
                        return true
                }
        }
        return false
}

// triStr mirrors normalize_input.py tri_str: a measured non-empty string is
// itself; anything else collapses to "" (never a valid state name in the
// producer vocabulary, so it is a safe not-measured sentinel).
func triStr(v any) string {
        if s, ok := v.(string); ok {
                return s
        }
        return ""
}

// pyTruthy mirrors Python bool(v) over analyzer values: nil/false/""/0 and
// empty collections are falsy, everything else truthy. Typed slices from live
// in-memory scans (e.g. []string) and JSON []any must be treated identically.
func pyTruthy(v any) bool {
        switch t := v.(type) {
        case nil:
                return false
        case bool:
                return t
        case string:
                return t != ""
        case float64:
                return t != 0
        case int:
                return t != 0
        case int64:
                return t != 0
        }
        rv := reflect.ValueOf(v)
        switch rv.Kind() {
        case reflect.Slice, reflect.Array, reflect.Map:
                return rv.Len() > 0
        }
        return true
}

// pyInt mirrors Python isinstance(v, int) over analyzer values. Live scans
// carry native Go ints; JSON round-trips decode every number as float64, so a
// whole float64 counts as the int it prints as (encoding/json cannot preserve
// Python's 0-vs-0.0 distinction). Python bools are int subclasses, so bool
// counts too (True==1, False==0).
func pyInt(v any) (int, bool) {
        switch n := v.(type) {
        case bool:
                if n {
                        return 1, true
                }
                return 0, true
        case int:
                return n, true
        case int64:
                return int(n), true
        case int32:
                return int(n), true
        case float64:
                if n == float64(int64(n)) {
                        return int(n), true
                }
        }
        return 0, false
}

// hasNonEmptyList mirrors Python bool(m.get(key)) for list-valued keys: true only
// when the key holds a non-empty slice. It accepts any slice or array type via
// reflection because live in-memory analyzer output uses concrete typed slices
// (e.g. caa_analysis.records is []string), whereas JSON round-tripped fixtures
// arrive as []any. Both must be treated identically for parity.
func hasNonEmptyList(m map[string]any, key string) bool {
        if m == nil {
                return false
        }
        v, present := m[key]
        if !present || v == nil {
                return false
        }
        rv := reflect.ValueOf(v)
        switch rv.Kind() {
        case reflect.Slice, reflect.Array:
                return rv.Len() > 0
        default:
                return false
        }
}

// scanTri sweeps tri-state observations for the given keys. anyFalse means at
// least one key was measured false; anyNil means at least one key was not
// measured (missing from the map included). Callers derive the tri-state
// verdict from the pair, mirroring evaluate.py's `v is False` / `v is None`
// checks: measured-false always dominates, and only an all-measured-true set
// can pass.
func scanTri(obs Observations, keys []string) (anyFalse, anyNil bool) {
        for _, k := range keys {
                switch v := obs[k]; {
                case v == nil:
                        anyNil = true
                case !*v:
                        anyFalse = true
                }
        }
        return anyFalse, anyNil
}
