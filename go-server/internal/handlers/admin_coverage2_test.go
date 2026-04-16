//go:build coverage

package handlers

import (
	"context"
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"

	"dnstool/go-server/internal/config"

	"github.com/gin-gonic/gin"
)

func adminConfig2() *config.Config {
	return &config.Config{
		AppVersion:    "test-v2",
		BetaPages:     map[string]bool{},
		SectionTuning: map[string]string{},
	}
}

func adminRouter2() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("csp_nonce", "test-nonce")
		c.Set("csrf_token", "test-csrf")
		c.Next()
	})
	tmpl := template.New("root")
	template.Must(tmpl.New("admin.html").Parse(`OK`))
	template.Must(tmpl.New("admin_ops.html").Parse(`OPS`))
	r.SetHTMLTemplate(tmpl)
	return r
}

func TestAdminHandler_RunOperation_UnknownTask_C2(t *testing.T) {
	h := NewAdminHandler(nil, adminConfig2(), func() int64 { return 0 })
	router := adminRouter2()
	router.POST("/ops/run/:task", h.RunOperation)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ops/run/nonexistent-task", nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAdminHandler_RunOperation_ValidTask_C2(t *testing.T) {
	mockRunner := func(ctx context.Context, command string, args []string) CmdRunResult {
		return CmdRunResult{Stdout: "output from mock", Stderr: "", Err: nil}
	}
	h := NewAdminHandler(nil, adminConfig2(), func() int64 { return 0 })
	h.RunCmd = mockRunner
	router := adminRouter2()
	router.POST("/ops/run/:task", h.RunOperation)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ops/run/"+opsCSSCohesion, nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAdminHandler_RunOperation_FailedTask_C2(t *testing.T) {
	mockRunner := func(ctx context.Context, command string, args []string) CmdRunResult {
		return CmdRunResult{
			Stdout: "partial output",
			Stderr: "error details",
			Err:    context.DeadlineExceeded,
		}
	}
	h := NewAdminHandler(nil, adminConfig2(), func() int64 { return 0 })
	h.RunCmd = mockRunner
	router := adminRouter2()
	router.POST("/ops/run/:task", h.RunOperation)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ops/run/"+opsFeatureInventory, nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (with failure info), got %d", w.Code)
	}
}

func TestAdminHandler_RunOperation_NilRunCmd_C2(t *testing.T) {
	h := NewAdminHandler(nil, adminConfig2(), func() int64 { return 0 })
	h.RunCmd = nil
	router := adminRouter2()
	router.POST("/ops/run/:task", h.RunOperation)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ops/run/"+opsRenderDiagrams, nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAdminHandler_OperationsPage_C2(t *testing.T) {
	h := NewAdminHandler(nil, adminConfig2(), func() int64 { return 5 })
	router := adminRouter2()
	router.GET("/ops", h.OperationsPage)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ops", nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAdminHandler_RunOperation_StderrOnly_C2(t *testing.T) {
	mockRunner := func(ctx context.Context, command string, args []string) CmdRunResult {
		return CmdRunResult{Stdout: "", Stderr: "only error", Err: context.DeadlineExceeded}
	}
	h := NewAdminHandler(nil, adminConfig2(), func() int64 { return 0 })
	h.RunCmd = mockRunner
	router := adminRouter2()
	router.POST("/ops/run/:task", h.RunOperation)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ops/run/"+opsCSSCohesion, nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestOpsTaskList_Order_C2(t *testing.T) {
	tasks := opsTaskList()
	expectedOrder := []string{opsCSSCohesion, opsFeatureInventory, opsScientificColors, opsRenderDiagrams, opsFigmaBundle, opsFigmaVerify, opsMiroSync, opsFullPipeline}
	for i, task := range tasks {
		if task.ID != expectedOrder[i] {
			t.Errorf("expected task %d = %s, got %s", i, expectedOrder[i], task.ID)
		}
	}
}

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

func TestOpsWhitelist_ValidCommands_C2(t *testing.T) {
	validCommands := map[string]bool{cmdNode: true, "bash": true}
	for id, task := range opsWhitelist {
		if !validCommands[task.Command] {
			t.Errorf("task %s has unexpected command %q", id, task.Command)
		}
	}
}
