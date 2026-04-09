package handlers

import (
        "context"
        "fmt"
        "html/template"
        "net/http"
        "net/http/httptest"
        "os"
        "strings"
        "testing"
        "time"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"

        "github.com/gin-gonic/gin"
)

func adminTestDB(t *testing.T) *db.Database {
        t.Helper()
        dbURL := os.Getenv("DATABASE_URL")
        if dbURL == "" {
                t.Skip("DATABASE_URL not set")
        }
        database, err := db.ConnectForTests(dbURL)
        if err != nil {
                t.Fatalf("connect: %v", err)
        }
        t.Cleanup(func() { database.Close() })
        return database
}

func adminConfig() *config.Config {
        return &config.Config{
                AppVersion:    "test",
                BetaPages:     map[string]bool{},
                SectionTuning: map[string]string{},
        }
}

func adminRouter() *gin.Engine {
        gin.SetMode(gin.TestMode)
        r := gin.New()
        r.Use(func(c *gin.Context) {
                c.Set("csp_nonce", "test-nonce")
                c.Set("csrf_token", "test-csrf")
                c.Next()
        })
        tmpl := template.New("root")
        for _, name := range []string{"admin.html", "admin_ops.html"} {
                template.Must(tmpl.New(name).Parse(`OK`))
        }
        r.SetHTMLTemplate(tmpl)
        return r
}

func TestOpsTaskList(t *testing.T) {
        tasks := opsTaskList()

        expectedOrder := []string{
                "css-cohesion",
                "feature-inventory",
                "scientific-colors",
                "render-diagrams",
                "figma-bundle",
                "figma-verify",
                "miro-sync",
                "full-pipeline",
        }

        if len(tasks) != len(expectedOrder) {
                t.Fatalf("expected %d tasks, got %d", len(expectedOrder), len(tasks))
        }

        for i, expected := range expectedOrder {
                if tasks[i].ID != expected {
                        t.Errorf("task[%d].ID = %q, want %q", i, tasks[i].ID, expected)
                }
        }
}

func TestOpsTaskList_Labels(t *testing.T) {
        tasks := opsTaskList()
        for _, task := range tasks {
                if task.Label == "" {
                        t.Errorf("task %q has empty label", task.ID)
                }
                if task.Icon == "" {
                        t.Errorf("task %q has empty icon", task.ID)
                }
                if task.Command == "" {
                        t.Errorf("task %q has empty command", task.ID)
                }
                if len(task.Args) == 0 {
                        t.Errorf("task %q has empty args", task.ID)
                }
        }
}

func TestOpsWhitelist_AllEntriesPresent(t *testing.T) {
        expectedIDs := []string{
                "css-cohesion",
                "feature-inventory",
                "scientific-colors",
                "render-diagrams",
                "figma-bundle",
                "figma-verify",
                "miro-sync",
                "full-pipeline",
        }
        for _, id := range expectedIDs {
                if _, ok := opsWhitelist[id]; !ok {
                        t.Errorf("expected opsWhitelist to contain %q", id)
                }
        }
}

func TestOpsWhitelist_Commands(t *testing.T) {
        nodeCommands := []string{"css-cohesion", "feature-inventory", "scientific-colors", "figma-bundle", "figma-verify", "miro-sync", "full-pipeline"}
        for _, id := range nodeCommands {
                task := opsWhitelist[id]
                if task.Command != "node" {
                        t.Errorf("task %q command = %q, want 'node'", id, task.Command)
                }
        }

        renderTask := opsWhitelist["render-diagrams"]
        if renderTask.Command != "bash" {
                t.Errorf("render-diagrams command = %q, want 'bash'", renderTask.Command)
        }
}

func TestOpsTaskList_IDsMatchWhitelist(t *testing.T) {
        tasks := opsTaskList()
        for _, task := range tasks {
                if wl, ok := opsWhitelist[task.ID]; !ok {
                        t.Errorf("task %q not found in opsWhitelist", task.ID)
                } else if wl.Label != task.Label {
                        t.Errorf("task %q label mismatch: list=%q whitelist=%q", task.ID, task.Label, wl.Label)
                }
        }
}

func TestOpsWhitelist_ScriptPaths(t *testing.T) {
        for id, task := range opsWhitelist {
                if len(task.Args) == 0 {
                        t.Errorf("task %q has no args", id)
                        continue
                }
                arg := task.Args[0]
                if !strings.HasPrefix(arg, "scripts/") {
                        t.Errorf("task %q arg %q does not start with scripts/", id, arg)
                }
        }
}

func TestDeleteUser_AdminRoleBlocked(t *testing.T) {
        database := adminTestDB(t)
        cfg := adminConfig()
        router := adminRouter()
        handler := NewAdminHandler(database, cfg, func() int64 { return 0 })
        router.DELETE("/admin/user/:id", handler.DeleteUser)

        ctx := context.Background()
        var adminID int32
        err := database.Pool.QueryRow(ctx,
                `SELECT id FROM users WHERE role = 'admin' LIMIT 1`).Scan(&adminID)
        if err != nil {
                t.Skip("no admin user in DB to test deletion block")
        }

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/admin/user/%d", adminID), nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusForbidden {
                t.Fatalf("DeleteUser admin: got %d, want 403 (admin deletion should be blocked)", w.Code)
        }
        body := w.Body.String()
        if !strings.Contains(body, "Cannot delete admin") {
                t.Errorf("expected 'Cannot delete admin' in body, got %q", body)
        }

        var exists bool
        _ = database.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`, adminID).Scan(&exists)
        if !exists {
                t.Fatal("admin user was deleted despite 403 response — protection is broken")
        }
}

func TestRunOperation_UnknownTask(t *testing.T) {
        database := adminTestDB(t)
        cfg := adminConfig()
        router := adminRouter()
        handler := NewAdminHandler(database, cfg, func() int64 { return 0 })
        router.POST("/admin/ops/:task", handler.RunOperation)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/admin/ops/nonexistent-task", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusBadRequest {
                t.Fatalf("RunOperation unknown task: got %d, want 400", w.Code)
        }
        body := w.Body.String()
        if !strings.Contains(body, "Unknown operation") {
                t.Errorf("expected 'Unknown operation', got %q", body)
        }
}

func TestRunOperation_CmdRunner_Success(t *testing.T) {
        database := adminTestDB(t)
        cfg := adminConfig()

        tmpl := template.New("root")
        template.Must(tmpl.New("admin.html").Parse(`OK`))
        template.Must(tmpl.New("admin_ops.html").Parse(`{{with .OpResult}}Success={{.Success}} Output={{.Output}}{{end}}`))

        gin.SetMode(gin.TestMode)
        router := gin.New()
        router.Use(func(c *gin.Context) {
                c.Set("csp_nonce", "test-nonce")
                c.Set("csrf_token", "test-csrf")
                c.Next()
        })
        router.SetHTMLTemplate(tmpl)

        var capturedCmd string
        var capturedArgs []string
        handler := NewAdminHandler(database, cfg, func() int64 { return 0 })
        handler.RunCmd = func(ctx context.Context, command string, args []string) CmdRunResult {
                capturedCmd = command
                capturedArgs = args
                return CmdRunResult{Stdout: "operation completed OK", Stderr: "", Err: nil}
        }
        router.POST("/admin/ops/:task", handler.RunOperation)

        for taskID, task := range opsWhitelist {
                w := httptest.NewRecorder()
                req := httptest.NewRequest(http.MethodPost, "/admin/ops/"+taskID, nil)
                router.ServeHTTP(w, req)
                if w.Code != http.StatusOK {
                        t.Fatalf("RunOperation %s: got %d, want 200", taskID, w.Code)
                }
                body := w.Body.String()
                if !strings.Contains(body, "Success=true") {
                        t.Errorf("RunOperation %s: expected Success=true, got %q", taskID, body)
                }
                if !strings.Contains(body, "operation completed OK") {
                        t.Errorf("RunOperation %s: expected output in body, got %q", taskID, body)
                }
                if capturedCmd != task.Command {
                        t.Errorf("RunOperation %s: command = %q, want %q", taskID, capturedCmd, task.Command)
                }
                if len(capturedArgs) != len(task.Args) {
                        t.Errorf("RunOperation %s: args length = %d, want %d", taskID, len(capturedArgs), len(task.Args))
                }
                break
        }
}

func TestRunOperation_CmdRunner_Failure_CapturesOutput(t *testing.T) {
        database := adminTestDB(t)
        cfg := adminConfig()

        tmpl := template.New("root")
        template.Must(tmpl.New("admin.html").Parse(`OK`))
        template.Must(tmpl.New("admin_ops.html").Parse(`{{with .OpResult}}Success={{.Success}} Output={{.Output}}{{end}}`))

        gin.SetMode(gin.TestMode)
        router := gin.New()
        router.Use(func(c *gin.Context) {
                c.Set("csp_nonce", "test-nonce")
                c.Set("csrf_token", "test-csrf")
                c.Next()
        })
        router.SetHTMLTemplate(tmpl)

        handler := NewAdminHandler(database, cfg, func() int64 { return 0 })
        handler.RunCmd = func(ctx context.Context, command string, args []string) CmdRunResult {
                return CmdRunResult{
                        Stdout: "partial output before crash",
                        Stderr: "FATAL: segfault in module X",
                        Err:    fmt.Errorf("exit status 139"),
                }
        }
        router.POST("/admin/ops/:task", handler.RunOperation)

        for taskID := range opsWhitelist {
                w := httptest.NewRecorder()
                req := httptest.NewRequest(http.MethodPost, "/admin/ops/"+taskID, nil)
                router.ServeHTTP(w, req)
                body := w.Body.String()
                if !strings.Contains(body, "Success=false") {
                        t.Errorf("expected Success=false for failed command, got %q", body)
                }
                if !strings.Contains(body, "partial output before crash") {
                        t.Errorf("expected stdout in combined output, got %q", body)
                }
                if !strings.Contains(body, "FATAL: segfault in module X") {
                        t.Errorf("expected stderr in combined output, got %q", body)
                }
                break
        }
}

func TestRunOperation_CmdRunner_StderrOnlyFailure(t *testing.T) {
        database := adminTestDB(t)
        cfg := adminConfig()

        tmpl := template.New("root")
        template.Must(tmpl.New("admin.html").Parse(`OK`))
        template.Must(tmpl.New("admin_ops.html").Parse(`{{with .OpResult}}Success={{.Success}} Output={{.Output}}{{end}}`))

        gin.SetMode(gin.TestMode)
        router := gin.New()
        router.Use(func(c *gin.Context) {
                c.Set("csp_nonce", "test-nonce")
                c.Set("csrf_token", "test-csrf")
                c.Next()
        })
        router.SetHTMLTemplate(tmpl)

        handler := NewAdminHandler(database, cfg, func() int64 { return 0 })
        handler.RunCmd = func(ctx context.Context, command string, args []string) CmdRunResult {
                return CmdRunResult{Stdout: "", Stderr: "permission denied", Err: fmt.Errorf("exit status 1")}
        }
        router.POST("/admin/ops/:task", handler.RunOperation)

        for taskID := range opsWhitelist {
                w := httptest.NewRecorder()
                req := httptest.NewRequest(http.MethodPost, "/admin/ops/"+taskID, nil)
                router.ServeHTTP(w, req)
                body := w.Body.String()
                if !strings.Contains(body, "Success=false") {
                        t.Errorf("expected Success=false, got %q", body)
                }
                if !strings.Contains(body, "permission denied") {
                        t.Errorf("expected stderr-only output, got %q", body)
                }
                break
        }
}

func TestRunOperation_CmdRunner_ContextTimeout(t *testing.T) {
        database := adminTestDB(t)
        cfg := adminConfig()

        tmpl := template.New("root")
        template.Must(tmpl.New("admin.html").Parse(`OK`))
        template.Must(tmpl.New("admin_ops.html").Parse(`{{with .OpResult}}Success={{.Success}} Output={{.Output}}{{end}}`))

        gin.SetMode(gin.TestMode)
        router := gin.New()
        router.Use(func(c *gin.Context) {
                c.Set("csp_nonce", "test-nonce")
                c.Set("csrf_token", "test-csrf")
                c.Next()
        })
        router.SetHTMLTemplate(tmpl)

        handler := NewAdminHandler(database, cfg, func() int64 { return 0 })
        handler.RunCmd = func(ctx context.Context, command string, args []string) CmdRunResult {
                return CmdRunResult{
                        Stdout: "",
                        Stderr: "signal: killed",
                        Err:    context.DeadlineExceeded,
                }
        }
        router.POST("/admin/ops/:task", handler.RunOperation)

        for taskID := range opsWhitelist {
                w := httptest.NewRecorder()
                req := httptest.NewRequest(http.MethodPost, "/admin/ops/"+taskID, nil)
                router.ServeHTTP(w, req)
                body := w.Body.String()
                if !strings.Contains(body, "Success=false") {
                        t.Errorf("expected Success=false for timed-out command, got %q", body)
                }
                break
        }
}

func TestDeleteUser_BadID(t *testing.T) {
        database := adminTestDB(t)
        cfg := adminConfig()
        router := adminRouter()
        handler := NewAdminHandler(database, cfg, func() int64 { return 0 })
        router.DELETE("/admin/user/:id", handler.DeleteUser)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodDelete, "/admin/user/abc", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusBadRequest {
                t.Fatalf("DeleteUser bad ID: got %d, want 400", w.Code)
        }
}

func TestDeleteUser_NotFound(t *testing.T) {
        database := adminTestDB(t)
        cfg := adminConfig()
        router := adminRouter()
        handler := NewAdminHandler(database, cfg, func() int64 { return 0 })
        router.DELETE("/admin/user/:id", handler.DeleteUser)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodDelete, "/admin/user/999999999", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusNotFound {
                t.Fatalf("DeleteUser not found: got %d, want 404", w.Code)
        }
}

func TestResetUserSessions_BadID(t *testing.T) {
        database := adminTestDB(t)
        cfg := adminConfig()
        router := adminRouter()
        handler := NewAdminHandler(database, cfg, func() int64 { return 0 })
        router.POST("/admin/reset-sessions/:id", handler.ResetUserSessions)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/admin/reset-sessions/abc", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusBadRequest {
                t.Fatalf("ResetUserSessions bad ID: got %d, want 400", w.Code)
        }
}

func TestResetUserSessions_NotFound(t *testing.T) {
        database := adminTestDB(t)
        cfg := adminConfig()
        router := adminRouter()
        handler := NewAdminHandler(database, cfg, func() int64 { return 0 })
        router.POST("/admin/reset-sessions/:id", handler.ResetUserSessions)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/admin/reset-sessions/999999999", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusNotFound {
                t.Fatalf("ResetUserSessions not found: got %d, want 404", w.Code)
        }
}

func TestPurgeExpiredSessions_Runs(t *testing.T) {
        database := adminTestDB(t)
        cfg := adminConfig()
        router := adminRouter()
        handler := NewAdminHandler(database, cfg, func() int64 { return 0 })
        router.POST("/admin/purge-sessions", handler.PurgeExpiredSessions)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/admin/purge-sessions", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("PurgeExpiredSessions: got %d, want 303", w.Code)
        }
}

func TestAdminDashboard_Renders(t *testing.T) {
        database := adminTestDB(t)
        cfg := adminConfig()
        router := adminRouter()
        handler := NewAdminHandler(database, cfg, func() int64 { return 42 })
        router.GET("/admin", handler.Dashboard)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/admin", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("Admin Dashboard: got %d, want 200", w.Code)
        }
}

func TestOperationsPage_Renders(t *testing.T) {
        database := adminTestDB(t)
        cfg := adminConfig()
        router := adminRouter()
        handler := NewAdminHandler(database, cfg, func() int64 { return 0 })
        router.GET("/admin/ops", handler.OperationsPage)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/admin/ops", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("OperationsPage: got %d, want 200", w.Code)
        }
}

func ensureNonAdminUser(t *testing.T, database *db.Database) int32 {
        t.Helper()
        ctx := context.Background()
        var id int32
        err := database.Pool.QueryRow(ctx, `SELECT id FROM users WHERE role != 'admin' LIMIT 1`).Scan(&id)
        if err == nil {
                return id
        }
        testSub := fmt.Sprintf("admin-test-sub-%d", time.Now().UnixNano())
        err = database.Pool.QueryRow(ctx,
                `INSERT INTO users (email, name, google_sub, role) VALUES ($1, 'Admin Test User', $2, 'user') RETURNING id`,
                fmt.Sprintf("admin-test-%d@example.com", time.Now().UnixNano()), testSub).Scan(&id)
        if err != nil {
                t.Skipf("cannot create test user: %v", err)
        }
        t.Cleanup(func() {
                _, _ = database.Pool.Exec(context.Background(), `DELETE FROM sessions WHERE user_id = $1`, id)
                _, _ = database.Pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, id)
        })
        return id
}

func TestDeleteUser_CanceledContext_UserSurvives(t *testing.T) {
        database := adminTestDB(t)
        cfg := adminConfig()

        nonAdminID := ensureNonAdminUser(t, database)

        gin.SetMode(gin.TestMode)
        router := gin.New()
        tmpl := template.New("root")
        template.Must(tmpl.New("admin.html").Parse(`OK`))
        router.SetHTMLTemplate(tmpl)
        router.Use(func(c *gin.Context) {
                canceledCtx, cancel := context.WithCancel(c.Request.Context())
                cancel()
                c.Request = c.Request.WithContext(canceledCtx)
                c.Next()
        })

        handler := NewAdminHandler(database, cfg, func() int64 { return 0 })
        router.DELETE("/admin/user/:id", handler.DeleteUser)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/admin/user/%d", nonAdminID), nil)
        router.ServeHTTP(w, req)

        if w.Code == http.StatusSeeOther {
                t.Fatal("canceled context should not result in successful deletion redirect")
        }

        var exists bool
        _ = database.Pool.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`, nonAdminID).Scan(&exists)
        if !exists {
                t.Fatal("user was deleted despite canceled context — transaction rollback failed")
        }
}

func TestDeleteUser_MidTransaction_ShortDeadline_RollbackVerified(t *testing.T) {
        database := adminTestDB(t)
        cfg := adminConfig()

        nonAdminID := ensureNonAdminUser(t, database)

        ctx := context.Background()
        _, err := database.Pool.Exec(ctx, `INSERT INTO sessions (id, user_id, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour') ON CONFLICT DO NOTHING`,
                fmt.Sprintf("test-session-mid-tx-%d", nonAdminID), nonAdminID)
        if err != nil {
                t.Skipf("cannot insert test session: %v", err)
        }
        t.Cleanup(func() {
                _, _ = database.Pool.Exec(context.Background(), `DELETE FROM sessions WHERE id = $1`, fmt.Sprintf("test-session-mid-tx-%d", nonAdminID))
        })

        gin.SetMode(gin.TestMode)
        router := gin.New()
        tmpl := template.New("root")
        template.Must(tmpl.New("admin.html").Parse(`OK`))
        router.SetHTMLTemplate(tmpl)
        router.Use(func(c *gin.Context) {
                shortCtx, cancel := context.WithTimeout(c.Request.Context(), 1*time.Nanosecond)
                time.Sleep(1 * time.Millisecond)
                _ = cancel
                c.Request = c.Request.WithContext(shortCtx)
                c.Next()
        })

        handler := NewAdminHandler(database, cfg, func() int64 { return 0 })
        router.DELETE("/admin/user/:id", handler.DeleteUser)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/admin/user/%d", nonAdminID), nil)
        router.ServeHTTP(w, req)

        if w.Code == http.StatusSeeOther {
                t.Fatal("expired-deadline context should not result in successful deletion redirect")
        }

        var userExists bool
        _ = database.Pool.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`, nonAdminID).Scan(&userExists)
        if !userExists {
                t.Fatal("user was deleted despite expired context — transaction rollback failed")
        }

        var sessionExists bool
        _ = database.Pool.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM sessions WHERE id = $1)`, fmt.Sprintf("test-session-mid-tx-%d", nonAdminID)).Scan(&sessionExists)
        if !sessionExists {
                t.Fatal("session was deleted despite expired context — partial cascade without rollback")
        }
}

func TestAdminDashboard_FetchersReturnNilOnDBFailure_StillRenders(t *testing.T) {
        database := adminTestDB(t)
        cfg := adminConfig()

        gin.SetMode(gin.TestMode)
        router := gin.New()
        tmpl := template.New("root")
        template.Must(tmpl.New("admin.html").Parse(
                `Users={{len .Users}} Analyses={{len .RecentAnalyses}} TotalUsers={{.Stats.TotalUsers}} TotalAnalyses={{.Stats.TotalAnalyses}}`))
        router.SetHTMLTemplate(tmpl)
        router.Use(func(c *gin.Context) {
                canceledCtx, cancel := context.WithCancel(c.Request.Context())
                cancel()
                c.Request = c.Request.WithContext(canceledCtx)
                c.Set("csp_nonce", "test-nonce")
                c.Set("csrf_token", "test-csrf")
                c.Next()
        })

        handler := NewAdminHandler(database, cfg, func() int64 { return 0 })
        router.GET("/admin", handler.Dashboard)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/admin", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("Dashboard with canceled DB context: want 200 (graceful nil), got %d", w.Code)
        }
        body := w.Body.String()
        if !strings.Contains(body, "Users=0") {
                t.Errorf("fetchUsers should return nil (len=0) on DB error, got: %s", body)
        }
        if !strings.Contains(body, "Analyses=0") {
                t.Errorf("fetchRecentAnalyses should return nil (len=0) on DB error, got: %s", body)
        }
        if !strings.Contains(body, "TotalUsers=0") {
                t.Errorf("fetchStats.TotalUsers should be 0 on DB error, got: %s", body)
        }
        if !strings.Contains(body, "TotalAnalyses=0") {
                t.Errorf("fetchStats.TotalAnalyses should be 0 on DB error, got: %s", body)
        }
}

func TestBackpressureCountFunc_Nil(t *testing.T) {
        database := adminTestDB(t)
        cfg := adminConfig()
        router := adminRouter()
        handler := NewAdminHandler(database, cfg, nil)
        router.GET("/admin", handler.Dashboard)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/admin", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("Dashboard with nil BackpressureCountFunc: got %d, want 200", w.Code)
        }
}

func TestAdminDashboard_CanceledContext_FetchersReturnNil(t *testing.T) {
        database := adminTestDB(t)
        cfg := adminConfig()

        gin.SetMode(gin.TestMode)
        router := gin.New()
        router.Use(func(c *gin.Context) {
                c.Set("csp_nonce", "test-nonce")
                c.Set("csrf_token", "test-csrf")
                canceledCtx, cancel := context.WithCancel(c.Request.Context())
                cancel()
                c.Request = c.Request.WithContext(canceledCtx)
                c.Next()
        })
        tmpl := template.New("root")
        template.Must(tmpl.New("admin.html").Parse(
                `Users={{len .Users}} Analyses={{len .RecentAnalyses}}`))
        router.SetHTMLTemplate(tmpl)

        handler := NewAdminHandler(database, cfg, func() int64 { return 0 })
        router.GET("/admin", handler.Dashboard)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/admin", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("Dashboard with canceled context: got %d, want 200 (fetchers should return nil gracefully)", w.Code)
        }
        body := w.Body.String()
        if !strings.Contains(body, "Users=0") {
                t.Errorf("expected Users=0 (fetcher returned nil), got %q", body)
        }
        if !strings.Contains(body, "Analyses=0") {
                t.Errorf("expected Analyses=0 (fetcher returned nil), got %q", body)
        }
}

func TestRunOperation_CmdRunner_ReceivesContext(t *testing.T) {
        database := adminTestDB(t)
        cfg := adminConfig()

        tmpl := template.New("root")
        template.Must(tmpl.New("admin.html").Parse(`OK`))
        template.Must(tmpl.New("admin_ops.html").Parse(`OK`))

        gin.SetMode(gin.TestMode)
        router := gin.New()
        router.Use(func(c *gin.Context) {
                c.Set("csp_nonce", "test-nonce")
                c.Set("csrf_token", "test-csrf")
                c.Next()
        })
        router.SetHTMLTemplate(tmpl)

        var receivedCtx context.Context
        handler := NewAdminHandler(database, cfg, func() int64 { return 0 })
        handler.RunCmd = func(ctx context.Context, command string, args []string) CmdRunResult {
                receivedCtx = ctx
                return CmdRunResult{Stdout: "ok", Err: nil}
        }
        router.POST("/admin/ops/:task", handler.RunOperation)

        for taskID := range opsWhitelist {
                w := httptest.NewRecorder()
                req := httptest.NewRequest(http.MethodPost, "/admin/ops/"+taskID, nil)
                router.ServeHTTP(w, req)

                if receivedCtx == nil {
                        t.Fatal("CmdRunner was not called")
                }
                _, hasDeadline := receivedCtx.Deadline()
                if !hasDeadline {
                        t.Error("context passed to CmdRunner should have a deadline (30s timeout)")
                }
                break
        }
}
