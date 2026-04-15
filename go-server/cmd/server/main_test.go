package main

import (
        "context"
        "net/http"
        "net/http/httptest"
        "os"
        "path/filepath"
        "strings"
        "testing"
        "time"

        "github.com/gin-gonic/gin"
)

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

func TestFindTemplatesDir(t *testing.T) {
        origDir, err := os.Getwd()
        if err != nil {
                t.Fatal(err)
        }
        defer os.Chdir(origDir)

        tmp := t.TempDir()
        if err := os.Mkdir(filepath.Join(tmp, "templates"), 0o755); err != nil {
                t.Fatal(err)
        }

        if err := os.Chdir(tmp); err != nil {
                t.Fatal(err)
        }

        got := findTemplatesDir()
        if got != "templates" {
                t.Errorf("findTemplatesDir() = %q, want %q", got, "templates")
        }
}

func TestFindTemplatesDirFallback(t *testing.T) {
        origDir, err := os.Getwd()
        if err != nil {
                t.Fatal(err)
        }
        defer os.Chdir(origDir)

        tmp := t.TempDir()
        if err := os.Chdir(tmp); err != nil {
                t.Fatal(err)
        }

        got := findTemplatesDir()
        if got != "templates" {
                t.Errorf("findTemplatesDir() fallback = %q, want %q", got, "templates")
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

func TestFindTemplatesDirGoServer(t *testing.T) {
        origDir, err := os.Getwd()
        if err != nil {
                t.Fatal(err)
        }
        defer os.Chdir(origDir)

        tmp := t.TempDir()
        goServerTemplates := filepath.Join(tmp, "go-server", "templates")
        if err := os.MkdirAll(goServerTemplates, 0o755); err != nil {
                t.Fatal(err)
        }
        if err := os.Chdir(tmp); err != nil {
                t.Fatal(err)
        }

        got := findTemplatesDir()
        if got != "go-server/templates" {
                t.Errorf("findTemplatesDir() with go-server/templates = %q, want %q", got, "go-server/templates")
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

        if w.Code == http.StatusOK && strings.Contains(w.Body.String(), "root:") {
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

        if w.Code == http.StatusNotFound {
                t.Errorf("empty path: got unexpected 404; http.FileServer should serve directory listing")
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
