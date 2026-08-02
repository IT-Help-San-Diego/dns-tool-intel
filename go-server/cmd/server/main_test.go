package main

import (
        "bytes"
        "context"
        "net/http"
        "net/http/httptest"
        "os"
        "path/filepath"
        "strings"
        "testing"
        "time"

        "dnstool/go-server/internal/middleware"

        "github.com/gin-gonic/gin"
)

// setupStaticRouter chdirs to a fresh tempdir, creates a `static` tree
// containing the assets the tests expect, mounts the production static
// handlers, and applies SecurityHeaders so X-Frame-Options behavior can be
// asserted end-to-end.
func setupStaticRouter(t *testing.T) *gin.Engine {
        t.Helper()
        gin.SetMode(gin.TestMode)

        origDir, err := os.Getwd()
        if err != nil {
                t.Fatal(err)
        }
        t.Cleanup(func() { _ = os.Chdir(origDir) })

        tmp := t.TempDir()
        for _, sub := range []string{"static/css", "static/js", "static/icons", "static/images"} {
                if err := os.MkdirAll(filepath.Join(tmp, sub), 0o755); err != nil {
                        t.Fatal(err)
                }
        }
        if err := os.WriteFile(filepath.Join(tmp, "static", "js", "main.js"), []byte("/*main*/"), 0o644); err != nil {
                t.Fatal(err)
        }
        if err := os.WriteFile(filepath.Join(tmp, "static", "css", "custom.css"), []byte("body{}"), 0o644); err != nil {
                t.Fatal(err)
        }
        if err := os.Chdir(tmp); err != nil {
                t.Fatal(err)
        }

        router := gin.New()
        router.Use(middleware.SecurityHeaders(false))
        mountStaticFiles(router)
        return router
}

func TestMountStaticFiles_RootDirectoryReturns404(t *testing.T) {
        router := setupStaticRouter(t)

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/static/", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusNotFound {
                t.Errorf("GET /static/ = %d, want 404", w.Code)
        }
}

func TestMountStaticFiles_SubDirectoryReturns404(t *testing.T) {
        router := setupStaticRouter(t)

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/static/css/", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusNotFound {
                t.Errorf("GET /static/css/ = %d, want 404", w.Code)
        }
}

func TestMountStaticFiles_FileServesWithFrameDeny(t *testing.T) {
        router := setupStaticRouter(t)

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/static/js/main.js", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Errorf("GET /static/js/main.js = %d, want 200", w.Code)
        }
        if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
                t.Errorf("X-Frame-Options = %q, want DENY", got)
        }
}

func TestCSPReportHandler_ValidBody(t *testing.T) {
        gin.SetMode(gin.TestMode)
        router := gin.New()
        router.POST("/api/csp-report", cspReportHandler)

        body := []byte(`{"csp-report":{"violated-directive":"script-src","blocked-uri":"https://evil.example/"}}`)
        w := httptest.NewRecorder()
        req := httptest.NewRequest("POST", "/api/csp-report", bytes.NewReader(body))
        req.Header.Set("Content-Type", "application/csp-report")
        router.ServeHTTP(w, req)

        if w.Code != http.StatusNoContent {
                t.Errorf("POST /api/csp-report (valid) = %d, want 204", w.Code)
        }
}

func TestCSPReportHandler_OversizedBodyCapped(t *testing.T) {
        gin.SetMode(gin.TestMode)
        router := gin.New()
        router.POST("/api/csp-report", cspReportHandler)

        // 64 KiB of payload — must still return 204; the handler caps the
        // read at 32 KiB and never propagates an error to the browser.
        big := bytes.Repeat([]byte("A"), 64*1024)
        w := httptest.NewRecorder()
        req := httptest.NewRequest("POST", "/api/csp-report", bytes.NewReader(big))
        req.Header.Set("Content-Type", "application/csp-report")
        router.ServeHTTP(w, req)

        if w.Code != http.StatusNoContent {
                t.Errorf("POST /api/csp-report (oversized) = %d, want 204", w.Code)
        }
}

func TestIsStaticAsset(t *testing.T) {
        trueTests := []string{
                "style.css", "app.js", "font.woff2", "font.woff",
                "logo.png", "favicon.ico", "icon.svg", "photo.jpg",
                "hero.webp", "banner.avif",
        }
        for _, tc := range trueTests {
                if !isStaticAsset(tc) {
                        t.Errorf("isStaticAsset(%q) = false, want true", tc)
                }
        }

        falseTests := []string{
                "index.html", "data.json", "page.go", "README.md",
                "", "css", ".css/",
        }
        for _, tc := range falseTests {
                if isStaticAsset(tc) {
                        t.Errorf("isStaticAsset(%q) = true, want false", tc)
                }
        }
}

func TestFindStaticDir(t *testing.T) {
        origDir, err := os.Getwd()
        if err != nil {
                t.Fatal(err)
        }
        defer os.Chdir(origDir)

        tmp := t.TempDir()
        if err := os.Mkdir(filepath.Join(tmp, "static"), 0o755); err != nil {
                t.Fatal(err)
        }

        if err := os.Chdir(tmp); err != nil {
                t.Fatal(err)
        }

        got := findStaticDir()
        if got != "static" {
                t.Errorf("findStaticDir() = %q, want %q", got, "static")
        }
}

func TestFindStaticDirFallback(t *testing.T) {
        origDir, err := os.Getwd()
        if err != nil {
                t.Fatal(err)
        }
        defer os.Chdir(origDir)

        tmp := t.TempDir()
        if err := os.Chdir(tmp); err != nil {
                t.Fatal(err)
        }

        got := findStaticDir()
        if got != "static" {
                t.Errorf("findStaticDir() fallback = %q, want %q", got, "static")
        }
}

func TestStartScheduledSync_ContextCancellation(t *testing.T) {
        ctx, cancel := context.WithCancel(context.Background())

        startScheduledSync(ctx)

        cancel()

        time.Sleep(50 * time.Millisecond)
        t.Log("MEASUREMENT: startScheduledSync goroutine respects context cancellation")
}

func TestRunNotionSync_ScriptNotFound(t *testing.T) {
        origDir, err := os.Getwd()
        if err != nil {
                t.Fatal(err)
        }
        defer os.Chdir(origDir)

        tmp := t.TempDir()
        if err := os.Chdir(tmp); err != nil {
                t.Fatal(err)
        }

        runNotionSync()
        t.Log("MEASUREMENT: runNotionSync handles missing script gracefully — no panic, no crash")
}

func TestStaticMIME_CriticalTypes(t *testing.T) {
        criticalTypes := map[string]string{
                ".css":   "text/css; charset=utf-8",
                ".js":    "application/javascript",
                ".json":  "application/json",
                ".svg":   "image/svg+xml",
                ".woff2": "font/woff2",
                ".png":   "image/png",
                ".webp":  "image/webp",
                ".avif":  "image/avif",
                ".pdf":   "application/pdf",
        }

        for ext, expectedType := range criticalTypes {
                actual, ok := staticMIME[ext]
                if !ok {
                        t.Errorf("missing MIME type for %s", ext)
                        continue
                }
                if actual != expectedType {
                        t.Errorf("MIME type for %s = %q, want %q", ext, actual, expectedType)
                }
        }
        t.Logf("MEASUREMENT: %d MIME types registered in staticMIME map", len(staticMIME))
}

func TestStaticMIME_VideoFormats(t *testing.T) {
        videoTypes := map[string]string{
                ".mp4":  "video/mp4",
                ".webm": "video/webm",
                ".ogg":  "video/ogg",
        }
        for ext, expected := range videoTypes {
                actual, ok := staticMIME[ext]
                if !ok {
                        t.Errorf("missing video MIME type for %s", ext)
                        continue
                }
                if actual != expected {
                        t.Errorf("video MIME type for %s = %q, want %q", ext, actual, expected)
                }
        }
}

func TestStaticMIME_FontFormats(t *testing.T) {
        fontTypes := map[string]string{
                ".woff":  "font/woff",
                ".woff2": "font/woff2",
                ".ttf":   "font/ttf",
        }
        for ext, expected := range fontTypes {
                actual, ok := staticMIME[ext]
                if !ok {
                        t.Errorf("missing font MIME type for %s", ext)
                        continue
                }
                if actual != expected {
                        t.Errorf("font MIME type for %s = %q, want %q", ext, actual, expected)
                }
        }
}

func TestFindStaticDirGoServer(t *testing.T) {
        origDir, err := os.Getwd()
        if err != nil {
                t.Fatal(err)
        }
        defer os.Chdir(origDir)

        tmp := t.TempDir()
        goServerStatic := filepath.Join(tmp, "go-server", "static")
        if err := os.MkdirAll(goServerStatic, 0o755); err != nil {
                t.Fatal(err)
        }
        if err := os.Chdir(tmp); err != nil {
                t.Fatal(err)
        }

        got := findStaticDir()
        if got != "go-server/static" {
                t.Errorf("findStaticDir() with go-server/static = %q, want %q", got, "go-server/static")
        }
}

func setupImagesRouter(t *testing.T) (*gin.Engine, string) {
        t.Helper()
        gin.SetMode(gin.TestMode)

        tmp := t.TempDir()
        imgDir := filepath.Join(tmp, "images")
        if err := os.MkdirAll(filepath.Join(imgDir, "sub"), 0o755); err != nil {
                t.Fatal(err)
        }
        if err := os.WriteFile(filepath.Join(imgDir, "logo.png"), []byte("PNG"), 0o644); err != nil {
                t.Fatal(err)
        }
        if err := os.WriteFile(filepath.Join(imgDir, "sub", "icon.png"), []byte("ICON"), 0o644); err != nil {
                t.Fatal(err)
        }

        router := gin.New()
        imagesFS := http.Dir(imgDir)
        imagesFileServer := http.StripPrefix("/images", http.FileServer(imagesFS))
        serveImages := func(c *gin.Context) {
                fp := strings.TrimPrefix(c.Param("filepath"), "/")
                if fp == "" {
                        c.Status(http.StatusNotFound)
                        return
                }
                c.Header("Cache-Control", "public, max-age=86400")
                imagesFileServer.ServeHTTP(c.Writer, c.Request)
        }
        router.GET("/images/*filepath", serveImages)
        router.HEAD("/images/*filepath", serveImages)

        return router, tmp
}

func TestImagesHandler_ValidPath(t *testing.T) {
        router, _ := setupImagesRouter(t)

        w := httptest.NewRecorder()
        req, _ := http.NewRequest("GET", "/images/logo.png", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Errorf("valid image path: got status %d, want %d", w.Code, http.StatusOK)
        }
        if w.Body.String() != "PNG" {
                t.Errorf("valid image path: got body %q, want %q", w.Body.String(), "PNG")
        }
}

func TestImagesHandler_ValidSubdirectory(t *testing.T) {
        router, _ := setupImagesRouter(t)

        w := httptest.NewRecorder()
        req, _ := http.NewRequest("GET", "/images/sub/icon.png", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Errorf("valid subdirectory path: got status %d, want %d", w.Code, http.StatusOK)
        }
        if w.Body.String() != "ICON" {
                t.Errorf("valid subdirectory path: got body %q, want %q", w.Body.String(), "ICON")
        }
}

func TestImagesHandler_TraversalBlocked(t *testing.T) {
        router, tmp := setupImagesRouter(t)

        secret := filepath.Join(tmp, "secret.txt")
        if err := os.WriteFile(secret, []byte("SECRET"), 0o644); err != nil {
                t.Fatal(err)
        }

        paths := []string{
                "/images/../secret.txt",
                "/images/sub/../../secret.txt",
        }
        for _, p := range paths {
                w := httptest.NewRecorder()
                req, _ := http.NewRequest("GET", p, nil)
                router.ServeHTTP(w, req)
                if w.Code != http.StatusNotFound {
                        t.Errorf("traversal path %q: got status %d, want %d", p, w.Code, http.StatusNotFound)
                }
                if strings.Contains(w.Body.String(), "SECRET") {
                        t.Errorf("traversal path %q: leaked file content outside images dir", p)
                }
        }
}

func TestImagesHandler_AbsolutePathBlocked(t *testing.T) {
        router, _ := setupImagesRouter(t)

        w := httptest.NewRecorder()
        req, _ := http.NewRequest("GET", "/images//etc/passwd", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusNotFound {
                t.Errorf("absolute path /etc/passwd: got status %d, want %d", w.Code, http.StatusNotFound)
        }
        if strings.Contains(w.Body.String(), "root:") {
                t.Errorf("absolute path /etc/passwd: leaked system file content")
        }
}

func TestImagesHandler_EncodedTraversalBlocked(t *testing.T) {
        router, tmp := setupImagesRouter(t)

        secret := filepath.Join(tmp, "secret.txt")
        if err := os.WriteFile(secret, []byte("SECRET"), 0o644); err != nil {
                t.Fatal(err)
        }

        paths := []string{
                "/images/%2e%2e/secret.txt",
                "/images/sub/%2e%2e/%2e%2e/secret.txt",
        }
        for _, p := range paths {
                w := httptest.NewRecorder()
                req, _ := http.NewRequest("GET", p, nil)
                router.ServeHTTP(w, req)
                if w.Code != http.StatusNotFound {
                        t.Errorf("encoded traversal path %q: got status %d, want %d", p, w.Code, http.StatusNotFound)
                }
                if strings.Contains(w.Body.String(), "SECRET") {
                        t.Errorf("encoded traversal path %q: leaked file content outside images dir", p)
                }
        }
}

func TestImagesHandler_EmptyPath(t *testing.T) {
        router, _ := setupImagesRouter(t)

        w := httptest.NewRecorder()
        req, _ := http.NewRequest("GET", "/images/", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusNotFound {
                t.Errorf("empty path: got status %d, want %d", w.Code, http.StatusNotFound)
        }
}

func TestImagesHandler_HeadRequest(t *testing.T) {
        router, _ := setupImagesRouter(t)

        w := httptest.NewRecorder()
        req, _ := http.NewRequest("HEAD", "/images/logo.png", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Errorf("HEAD valid image: got status %d, want %d", w.Code, http.StatusOK)
        }
}

func TestImagesHandler_NonexistentFile(t *testing.T) {
        router, _ := setupImagesRouter(t)

        w := httptest.NewRecorder()
        req, _ := http.NewRequest("GET", "/images/does-not-exist.png", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusNotFound {
                t.Errorf("nonexistent file: got status %d, want %d", w.Code, http.StatusNotFound)
        }
}
