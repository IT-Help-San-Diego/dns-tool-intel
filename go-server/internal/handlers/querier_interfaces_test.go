package handlers

import (
	"testing"
)

func TestAnalysisStoreInterfaceCompiles(t *testing.T) {
	var _ AnalysisStore = nil
	t.Log("AnalysisStore interface compiles")
}

func TestAuthStoreInterfaceCompiles(t *testing.T) {
	var _ AuthStore = nil
	t.Log("AuthStore interface compiles")
}

func TestPipelineStoreInterfaceCompiles(t *testing.T) {
	var _ PipelineStore = nil
	t.Log("PipelineStore interface compiles")
}

func TestLookupStoreInterfaceCompiles(t *testing.T) {
	var _ LookupStore = nil
	t.Log("LookupStore interface compiles")
}

func TestAuditStoreInterfaceCompiles(t *testing.T) {
	var _ AuditStore = nil
	t.Log("AuditStore interface compiles")
}

func TestStatsExecInterfaceCompiles(t *testing.T) {
	var _ StatsExec = nil
	t.Log("StatsExec interface compiles")
}

func TestAnalysisStoreInterfaceSatisfiedByMock(t *testing.T) {
	var store AnalysisStore = &mockAnalysisStore{}
	if store == nil {
		t.Fatal("expected non-nil mock store")
	}
}

func TestStatsExecInterfaceSatisfiedByMock(t *testing.T) {
	var exec StatsExec = &mockStatsExec{}
	if exec == nil {
		t.Fatal("expected non-nil mock exec")
	}
}

func TestLookupStoreInterfaceSatisfiedByMock(t *testing.T) {
	var store LookupStore = &mockLookupStore{}
	if store == nil {
		t.Fatal("expected non-nil mock store")
	}
}

func TestAuditStoreInterfaceSatisfiedByMock(t *testing.T) {
	var store AuditStore = &mockAuditStore{}
	if store == nil {
		t.Fatal("expected non-nil mock store")
	}
}
