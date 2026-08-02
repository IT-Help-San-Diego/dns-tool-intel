//go:build coverage

package adminpkg

import (
        "testing"
)

func TestNewAdminHandler_Coverage(t *testing.T) {
        bpFunc := func() int64 { return 42 }
        h := NewAdminHandler(nil, nil, nil, bpFunc)
        if h == nil {
                t.Fatal("expected handler")
        }
        if h.BackpressureCountFunc == nil {
                t.Error("expected backpressure func")
        }
        if h.BackpressureCountFunc() != 42 {
                t.Errorf("expected 42, got %d", h.BackpressureCountFunc())
        }
}
