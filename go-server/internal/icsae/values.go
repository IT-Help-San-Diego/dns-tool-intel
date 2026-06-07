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

func getFloatDefault(m map[string]any, key string, def float64) float64 {
        if m == nil {
                return def
        }
        v, present := m[key]
        if !present {
                return def
        }
        switch n := v.(type) {
        case float64:
                return n
        case float32:
                return float64(n)
        case int:
                return float64(n)
        case int64:
                return float64(n)
        case int32:
                return float64(n)
        default:
                return def
        }
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

func allTrue(obs Observations, keys []string) bool {
        for _, k := range keys {
                if !obs[k] {
                        return false
                }
        }
        return true
}

func anyTrue(obs Observations, keys []string) bool {
        for _, k := range keys {
                if obs[k] {
                        return true
                }
        }
        return false
}
