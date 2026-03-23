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
