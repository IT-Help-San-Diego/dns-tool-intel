//go:build coverage

package adminpkg

import (
	"testing"
)

func TestAdminStats_FieldAccess_C2(t *testing.T) {
	s := AdminStats{
		TotalUsers:         10,
		TotalAnalyses:      100,
		UniqueDomainsCount: 50,
		PrivateAnalyses:    5,
		TotalSessions:      20,
		ActiveSessions:     3,
		ScannerAlerts:      2,
	}
	if s.TotalUsers != 10 {
		t.Errorf("expected 10 users, got %d", s.TotalUsers)
	}
	if s.ScannerAlerts != 2 {
		t.Errorf("expected 2 alerts, got %d", s.ScannerAlerts)
	}
}

func TestAdminScannerAlert_FieldAccess_C2(t *testing.T) {
	a := AdminScannerAlert{
		ID:        1,
		Domain:    "test.com",
		Source:    "scanner",
		IP:        "1.2.3.4",
		Success:   false,
		CreatedAt: "2024-01-01 00:00",
	}
	if a.Domain != "test.com" {
		t.Error("expected domain=test.com")
	}
}

func TestAdminICAERun_FieldAccess_C2(t *testing.T) {
	r := AdminICAERun{
		ID:          1,
		AppVersion:  "v1.0",
		TotalCases:  100,
		TotalPassed: 95,
		TotalFailed: 5,
		DurationMs:  1500,
		CreatedAt:   "2024-01-01 00:00",
	}
	if r.TotalFailed != 5 {
		t.Errorf("expected 5 failed, got %d", r.TotalFailed)
	}
}

func TestAdminUser_FieldAccess_C2(t *testing.T) {
	u := AdminUser{
		ID:             1,
		Email:          "test@test.com",
		Name:           "Test",
		Role:           "user",
		CreatedAt:      "2024-01-01 00:00",
		LastLoginAt:    "2024-06-01 12:00",
		SessionCount:   5,
		ActiveSessions: 2,
	}
	if u.Email != "test@test.com" {
		t.Error("expected email=test@test.com")
	}
	if u.ActiveSessions != 2 {
		t.Errorf("expected 2 active sessions, got %d", u.ActiveSessions)
	}
}

func TestAdminAnalysis_FieldAccess_C2(t *testing.T) {
	a := AdminAnalysis{
		ID:               1,
		Domain:           "example.com",
		Success:          true,
		Duration:         "1.5s",
		CreatedAt:        "2024-01-01",
		CountryCode:      "US",
		ScanIP:           "1.2.3.4",
		Private:          false,
		HasUserSelectors: true,
		ScanFlag:         false,
		ScanSource:       "web",
	}
	if a.Duration != "1.5s" {
		t.Errorf("expected 1.5s, got %s", a.Duration)
	}
}
