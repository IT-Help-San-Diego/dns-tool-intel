// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"dnstool/go-server/internal/analyzer"
	"dnstool/go-server/internal/citation"
	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/db"
	"dnstool/go-server/internal/dbq"
	"dnstool/go-server/internal/dnsclient"
	"dnstool/go-server/internal/entitlements"
	"dnstool/go-server/internal/handlers"
	"dnstool/go-server/internal/handlers/adminpkg"
	"dnstool/go-server/internal/handlers/agentpkg"
	"dnstool/go-server/internal/handlers/authpkg"
	"dnstool/go-server/internal/handlers/badgepkg"
	"dnstool/go-server/internal/handlers/contentpkg"
	"dnstool/go-server/internal/logging"
	"dnstool/go-server/internal/middleware"
	"dnstool/go-server/internal/notifier"
	"dnstool/go-server/internal/scanner"
	tmplFuncs "dnstool/go-server/internal/templates"

	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
)

const (
	mapKeyError = "error"
)

const headerCacheControl = "Cache-Control"
const headerContentType = "Content-Type"
const contentTypeJSON = "application/json"
const contentTypeHTML = "text/html; charset=utf-8"

var staticMIME = map[string]string{
	".mp4":   "video/mp4",
	".webm":  "video/webm",
	".ogg":   "video/ogg",
	".m4a":   "audio/mp4",
	".css":   "text/css; charset=utf-8",
	".js":    "application/javascript",
	".json":  contentTypeJSON,
	".html":  "text/html; charset=utf-8",
	".xml":   "application/xml",
	".svg":   "image/svg+xml",
	".png":   "image/png",
	".jpg":   "image/jpeg",
	".jpeg":  "image/jpeg",
	".gif":   "image/gif",
	".webp":  "image/webp",
	".avif":  "image/avif",
	".ico":   "image/x-icon",
	".woff":  "font/woff",
	".woff2": "font/woff2",
	".ttf":   "font/ttf",
	".pdf":   "application/pdf",
	".txt":   "text/plain; charset=utf-8",
	".map":   contentTypeJSON,
	".zip":   "application/zip",
}

func init() {
	for ext, ct := range staticMIME {
		_ = mime.AddExtensionType(ext, ct)
	}
}

// printVersionAndExit handles --version/-version/version before any listener is
// opened or any config is loaded. BUILD.md documents `./server --version` as the
// way to verify a build, so it must work on a machine with no DATABASE_URL, no
// free port, and no environment at all.
//
// Values come from config.Version/GitCommit/BuildTime, injected via -ldflags by
// build.sh (see scripts/version.sh). An unflagged `go build` — the command
// BUILD.md gives researchers — leaves them at their fallbacks, so the output
// says so rather than printing a bare "dev" that looks like a real version.
func printVersionAndExit() {
	fmt.Printf("DNS Tool %s\n", config.Version)
	fmt.Printf("  commit:     %s\n", config.GitCommit)
	fmt.Printf("  built:      %s\n", config.BuildTime)
	fmt.Printf("  go:         %s\n", runtime.Version())
	fmt.Printf("  platform:   %s/%s\n", runtime.GOOS, runtime.GOARCH)
	if config.Version == "dev" {
		fmt.Println()
		fmt.Println("Built without version injection (plain `go build`).")
		fmt.Println("For a version-stamped binary: bash build.sh")
	}
	os.Exit(0)
}

func main() {
	// Argument handling comes first: --version must not require a bindable port
	// or a database.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "-version", "version", "-v":
			printVersionAndExit()
		case "--help", "-help", "help", "-h":
			fmt.Println("DNS Tool — Domain Security Intelligence Platform")
			fmt.Println()
			fmt.Println("Usage: server [--version] [--help]")
			fmt.Println()
			fmt.Println("With no arguments, starts the web server.")
			fmt.Println()
			fmt.Println("Environment:")
			fmt.Println("  PORT           listen port (default 5000)")
			fmt.Println("  DATABASE_URL   PostgreSQL connection string.")
			fmt.Println("                 If unset or unreachable, the server starts in")
			fmt.Println("                 DEGRADED MODE: pages that need no persistence")
			fmt.Println("                 still render, analysis history is unavailable.")
			fmt.Println()
			fmt.Println("Docs: BUILD.md · https://dnstool.it-help.tech")
			os.Exit(0)
		}
	}

	initLogger()

	earlyAddr := resolveListenAddr()

	var handler atomic.Value
	handler.Store(startingHandler())

	srv := &http.Server{
		Addr: earlyAddr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handler.Load().(http.Handler).ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	waitForListener(srv)
	slog.Info("Early listener started — accepting healthchecks", "address", earlyAddr)

	cfg, err := config.Load()
	if err != nil {
		slog.Error("Failed to load config", mapKeyError, err)
		os.Exit(1)
	}

	dnsclient.SetUserAgentVersion(cfg.AppVersion)

	database, err := db.Connect(cfg.DatabaseURL)
	if err != nil {
		slog.Error("Failed to connect to database", mapKeyError, err)
		runDegradedMode(&handler, cfg, srv)
		return
	}
	defer database.Close()

	database.RunSeedMigrations("go-server/db/migrations")

	logger, err := logging.Setup(database.Pool, cfg.DiscordWebhookURL)
	if err != nil {
		slog.Warn("Structured logger setup failed, continuing with default", mapKeyError, err)
	} else {
		defer logger.Close()
		slog.Info("Structured logging initialized",
			logging.AttrEvent, logging.EventStartup,
			logging.AttrCategory, logging.CategorySystem,
			"sinks", "stdout+jsonl+db+discord",
		)
	}

	scannerWatch := middleware.NewScannerWatch(scanner.MatchCISA)
	slog.Info("Scanner watch enabled — site-wide CISA range + forged-Referer attribution")

	router, analyticsCollector := buildRouter(cfg, database, scannerWatch)

	dnsAnalyzer, ctStore := initAnalyzer(cfg, database)

	dnsHistoryCache := analyzer.NewDNSHistoryCache(24 * time.Hour)
	slog.Info("DNS history cache initialized", "ttl", "24h")

	rateLimiter := middleware.NewInMemoryRateLimiter()
	slog.Info("Rate limiter initialized", "backend", "in-memory", "max_requests", middleware.RateLimitMaxRequests, "window_seconds", middleware.RateLimitWindow)

	registerRoutes(routeDeps{
		Router:       router,
		Cfg:          cfg,
		DB:           database,
		Analyzer:     dnsAnalyzer,
		HistoryCache: dnsHistoryCache,
		RateLimiter:  rateLimiter,
		ScannerWatch: scannerWatch,
	})

	handler.Store(http.HandlerFunc(router.Handler().ServeHTTP))
	slog.Info("Full router ready — handler swapped",
		"address", earlyAddr,
		"version", cfg.AppVersion,
		"commit", config.GitCommit,
		"built", config.BuildTime,
	)

	syncCtx, syncCancel := context.WithCancel(context.Background())
	defer syncCancel()
	startScheduledSync(syncCtx)

	ctEnrichment := analyzer.NewCTEnrichmentJob(database.Queries, ctStore)
	ctEnrichment.Start(syncCtx)

	driftNotifier := notifier.New(dbq.New(database.Pool))
	startNotificationDelivery(syncCtx, driftNotifier)

	awaitShutdown(srv, syncCancel, analyticsCollector)
}

func initLogger() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Value.Kind() == slog.KindString {
				v := a.Value.String()
				if strings.Contains(v, "@") || strings.Contains(v, "webhook") || strings.Contains(v, "token=") {
					return slog.Attr{Key: a.Key, Value: slog.StringValue("[REDACTED_EARLY]")}
				}
			}
			return a
		},
	})))
}

func resolveListenAddr() string {
	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
	}
	return fmt.Sprintf("0.0.0.0:%s", port)
}

func startingHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Starting handler serving request", "path", r.URL.Path, "method", r.Method)
		if r.URL.Path == "/healthz" {
			w.Header().Set(headerContentType, contentTypeJSON)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"starting"}`))
			return
		}
		w.Header().Set(headerContentType, contentTypeHTML)
		w.Header().Set(headerCacheControl, "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html lang="en" data-bs-theme="dark"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>DNS Tool — Starting</title><meta http-equiv="refresh" content="2"><style>*{margin:0;padding:0;box-sizing:border-box}body{background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}div{text-align:center}.spinner{width:40px;height:40px;border:3px solid #30363d;border-top-color:#58a6ff;border-radius:50%;animation:spin .8s linear infinite;margin:0 auto 1rem}@keyframes spin{to{transform:rotate(360deg)}}h1{font-size:1.2rem;font-weight:500;margin-bottom:.5rem}p{color:#8b949e;font-size:.85rem}</style></head><body><div><div class="spinner"></div><h1>DNS Tool</h1><p>Initializing analysis engine…</p></div></body></html>`))
	})
}

func waitForListener(srv *http.Server) {
	listenErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			listenErr <- err
		}
	}()
	select {
	case err := <-listenErr:
		slog.Error("Server failed to bind", mapKeyError, err)
		os.Exit(1)
	case <-time.After(100 * time.Millisecond):
	}
}

func runDegradedMode(handler *atomic.Value, cfg *config.Config, srv *http.Server) {
	handler.Store(degradedHandler())
	slog.Warn("Running in DEGRADED mode — serving maintenance page, waiting for database")
	go retryDatabaseLoop(cfg.DatabaseURL)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	slog.Info("Shutdown signal received in degraded mode")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
}

func degradedHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.Header().Set(headerContentType, contentTypeJSON)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"degraded","reason":"database_unavailable"}`))
			return
		}
		w.Header().Set(headerContentType, contentTypeHTML)
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>DNS Tool — Maintenance</title><meta http-equiv="refresh" content="30"><style>body{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#0d1117;color:#c9d1d9}div{text-align:center;max-width:480px;padding:2rem}.icon{font-size:3rem;margin-bottom:1rem}h1{color:#58a6ff;margin:0 0 .5rem}p{color:#8b949e;line-height:1.6}</style></head><body><div><div class="icon">🦉</div><h1>DNS Tool</h1><p>The service is temporarily unavailable while the database connection is being restored. This page will automatically refresh.</p></div></body></html>`))
	})
}

func retryDatabaseLoop(dbURL string) {
	for {
		time.Sleep(15 * time.Second)
		slog.Info("Retrying database connection in degraded mode...")
		if retryDB, retryErr := db.Connect(dbURL); retryErr == nil {
			slog.Info("Database reconnected in degraded mode — full restart required")
			retryDB.Close()
		}
	}
}

func buildRouter(cfg *config.Config, database *db.Database, scannerWatch *middleware.ScannerWatch) (*gin.Engine, *middleware.AnalyticsCollector) {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.SetTrustedProxies([]string{"127.0.0.1/8", "::1/128"})
	router.ForwardedByClientIP = true
	router.RemoteIPHeaders = []string{"X-Forwarded-For", "X-Real-Ip"}
	slog.Info("Trusted proxies configured — reading client IP from X-Forwarded-For via local proxy")

	logSecurityHeadersMode(cfg.IsDevEnvironment)

	router.Use(middleware.Recovery(cfg.AppVersion, map[string]any{
		"MaintenanceNote":   cfg.MaintenanceNote,
		"BetaPages":         cfg.BetaPages,
		"OriginTrialToken":  cfg.OriginTrialToken,
		"IsCloudDeployment": cfg.IsCloudDeployment,
	}))
	if !cfg.IsDevEnvironment {
		router.Use(middleware.CanonicalHostRedirect(cfg.BaseURL))
	}
	router.Use(gzip.Gzip(gzip.BestSpeed))
	router.Use(middleware.RequestContext())
	router.Use(middleware.SecurityHeaders(cfg.IsDevEnvironment))

	csrf := middleware.NewCSRFMiddleware(cfg.SessionSecret)
	router.Use(csrf.Handler())

	router.Use(middleware.SessionLoader(database.Pool))

	analyticsCollector := middleware.NewAnalyticsCollector(database.Pool, cfg.BaseURL)
	router.Use(analyticsCollector.Middleware())

	// ScannerWatch must be registered BEFORE any route is mounted: gin
	// snapshots the handler chain at route-registration time, so adding
	// it later would leave static-asset routes unwatched — and a Qualys
	// WAS sweep spends much of its crawl on static assets.
	if scannerWatch != nil {
		router.Use(scannerWatch.Middleware())
	}

	loadTemplates(router)
	mountStaticFiles(router)

	return router, analyticsCollector
}

func logSecurityHeadersMode(isDev bool) {
	if isDev {
		slog.Info("Security headers: dev mode — iframe embedding allowed for Replit preview")
	} else {
		slog.Info("Security headers: production mode — strict frame-ancestors, X-Frame-Options DENY")
	}
}

func loadTemplates(router *gin.Engine) {
	templatesDir := findTemplatesDir()
	slog.Info("Templates directory resolved", "path", templatesDir)
	globPattern := filepath.Join(templatesDir, "*.html")
	tmpl, err := template.New("").Funcs(tmplFuncs.FuncMap()).ParseGlob(globPattern)
	if err != nil {
		cwd, _ := os.Getwd()
		slog.Error("Failed to parse templates", "error", err, "glob", globPattern, "cwd", cwd)
		os.Exit(1)
	}
	router.SetHTMLTemplate(tmpl)
}

func mountStaticFiles(router *gin.Engine) {
	staticDir := findStaticDir()
	staticRoot := filepath.Clean(staticDir)
	slog.Info("Static directory resolved", "path", staticDir)
	tmplFuncs.InitSRI(staticDir)
	staticFS := http.Dir(staticDir)
	fileServer := http.StripPrefix("/static", http.FileServer(staticFS))
	serveStatic := func(c *gin.Context) {
		fp := c.Param("filepath")
		// Block directory listing. http.FileServer would otherwise render
		// an HTML index for trailing-slash paths and any directory whose
		// name has no extension, leaking the file tree structure (Qualys
		// QID 150124, CWE-451/829/1021 — "Clickjacking — Framable Page"
		// fired on /static/, /static/css/, /static/js/, etc.). Files
		// themselves still serve normally.
		if fp == "" || fp == "/" || strings.HasSuffix(fp, "/") {
			c.Status(http.StatusNotFound)
			return
		}
		if isStaticAsset(fp) {
			if strings.Contains(c.Request.URL.RawQuery, "v=") {
				c.Header(headerCacheControl, "public, max-age=31536000, immutable")
			} else {
				c.Header(headerCacheControl, "public, max-age=86400")
			}
		} else if filepath.Ext(fp) == "" {
			// Path has no file extension — treat as directory and refuse.
			// Real extensionless files we want to serve (robots.txt,
			// llms.txt, sw.js, manifest.json) all have extensions, so this
			// is safe. The /.well-known/ tree is exposed via dedicated
			// routes, not via the static catch-all.
			//
			// Path safety: TrimPrefix the leading slash so filepath.Join
			// semantics are unambiguous across OSes and any future router
			// change to .Param shape. filepath.IsLocal rejects empty,
			// absolute, and root-escaping ("..") paths BEFORE any join —
			// the CodeQL-recognized path-injection (CWE-22) sanitizer for
			// this flow. (The empty path was previously rejected by the
			// IsDir check below; IsLocal 404s it one step earlier.)
			rel := strings.TrimPrefix(fp, "/")
			if !filepath.IsLocal(rel) {
				c.Status(http.StatusNotFound)
				return
			}
			absPath := filepath.Join(staticDir, filepath.Clean(rel))
			// Containment guard (defense-in-depth behind IsLocal):
			// explicitly confirm the joined path stays under staticDir
			// before touching the filesystem. (Actual file bytes are
			// served by http.FileServer, which is independently rooted
			// at staticDir and rejects traversal.)
			if absPath != staticRoot && !strings.HasPrefix(absPath, staticRoot+string(os.PathSeparator)) {
				c.Status(http.StatusNotFound)
				return
			}
			if info, err := os.Stat(absPath); err == nil && info.IsDir() {
				c.Status(http.StatusNotFound)
				return
			}
		}
		fileServer.ServeHTTP(c.Writer, c.Request)
	}
	router.GET("/static/*filepath", serveStatic)
	router.HEAD("/static/*filepath", serveStatic)

	faviconHandler := func(c *gin.Context) {
		c.Header(headerCacheControl, "public, max-age=86400")
		c.File(filepath.Join(staticDir, "icons", "favicon-48x48.png"))
	}
	router.GET("/favicon.ico", faviconHandler)
	router.HEAD("/favicon.ico", faviconHandler)

	appleTouchHandler := func(c *gin.Context) {
		c.Header(headerCacheControl, "public, max-age=86400")
		c.File(filepath.Join(staticDir, "icons", "apple-touch-icon-180x180.png"))
	}
	router.GET("/apple-touch-icon.png", appleTouchHandler)
	router.HEAD("/apple-touch-icon.png", appleTouchHandler)
	router.GET("/apple-touch-icon-precomposed.png", appleTouchHandler)
	router.HEAD("/apple-touch-icon-precomposed.png", appleTouchHandler)

	imagesFS := http.Dir(filepath.Join(staticDir, "images"))
	imagesFileServer := http.StripPrefix("/images", http.FileServer(imagesFS))
	serveImages := func(c *gin.Context) {
		fp := strings.TrimPrefix(c.Param("filepath"), "/")
		if fp == "" {
			c.Status(http.StatusNotFound)
			return
		}
		c.Header(headerCacheControl, "public, max-age=86400")
		imagesFileServer.ServeHTTP(c.Writer, c.Request)
	}
	router.GET("/images/*filepath", serveImages)
	router.HEAD("/images/*filepath", serveImages)
}

func initAnalyzer(cfg *config.Config, database *db.Database) (*analyzer.Analyzer, analyzer.CTStore) {
	ctStore := analyzer.NewPgCTStore(database.Queries)
	dnsAnalyzer := analyzer.New(analyzer.WithCTStore(ctStore))
	dnsAnalyzer.SMTPProbeMode = cfg.SMTPProbeMode
	dnsAnalyzer.IPFSProbeMode = cfg.IPFSProbeMode
	dnsAnalyzer.ProbeAPIURL = cfg.ProbeAPIURL
	dnsAnalyzer.ProbeAPIKey = cfg.ProbeAPIKey
	for _, p := range cfg.Probes {
		dnsAnalyzer.Probes = append(dnsAnalyzer.Probes, analyzer.ProbeEndpoint{
			ID:    p.ID,
			Label: p.Label,
			URL:   p.URL,
			Key:   p.Key,
		})
	}
	slog.Info("DNS analyzer initialized with telemetry", "smtp_probe_mode", cfg.SMTPProbeMode, "ipfs_probe_mode", cfg.IPFSProbeMode, "probe_count", len(cfg.Probes))

	analyzer.InitIETFMetadata()
	analyzer.ScheduleRFCRefresh()
	scanner.StartCISARefresh()

	return dnsAnalyzer, ctStore
}

type routeDeps struct {
	Router       *gin.Engine
	Cfg          *config.Config
	DB           *db.Database
	Analyzer     *analyzer.Analyzer
	HistoryCache *analyzer.DNSHistoryCache
	RateLimiter  *middleware.InMemoryRateLimiter
	ScannerWatch *middleware.ScannerWatch
	HeavyShed    gin.HandlerFunc
}

func registerRoutes(d routeDeps) {
	staticDir := findStaticDir()

	// Shared concurrency cap for DB-heavy report routes; sheds excess
	// load with 503 + Retry-After instead of queuing behind a saturated
	// connection pool (2026-07-24 outage). Never applied to "/",
	// "/healthz", or static assets.
	d.HeavyShed = middleware.LoadShedder(middleware.HeavyRouteMaxConcurrent, middleware.HeavyRouteMaxWait)

	homeHandler := handlers.NewHomeHandler(d.Cfg, d.DB)
	healthHandler := handlers.NewHealthHandler(d.DB, d.Analyzer)
	historyHandler := handlers.NewHistoryHandler(d.DB, d.Cfg)
	analysisHandler := handlers.NewAnalysisHandler(d.DB, d.Cfg, d.Analyzer, d.HistoryCache)
	statsHandler := handlers.NewStatsHandler(d.DB, d.Cfg)
	compareHandler := handlers.NewCompareHandler(d.DB, d.Cfg)
	exportHandler := handlers.NewExportHandler(d.DB)
	snapshotHandler := handlers.NewSnapshotHandler(d.DB, d.Cfg)
	staticHandler := handlers.NewStaticHandler(staticDir, d.Cfg.AppVersion, d.Cfg.BaseURL)
	proxyHandler := handlers.NewProxyHandler()

	registerCoreRoutes(d.Router, homeHandler, healthHandler, staticHandler)
	registerAnalysisRoutes(d, analysisHandler, historyHandler, statsHandler, compareHandler, exportHandler, snapshotHandler)
	registerFeatureRoutes(d, analysisHandler, proxyHandler, staticHandler)
	registerAdminRoutes(d)
	registerAuthRoutes(d)
	registerNotFoundRoute(d.Router, d.Cfg)
}

func registerCoreRoutes(router *gin.Engine, home *handlers.HomeHandler, health *handlers.HealthHandler, static *handlers.StaticHandler) {
	router.GET("/", home.Index)
	router.HEAD("/", home.Index)
	router.GET("/fragment/topology", home.ScanTopologyFragment)
	router.GET("/fragment/icons.js", home.IconsJS)
	router.GET("/healthz", health.Healthz)
	router.HEAD("/healthz", health.Healthz)
	router.GET("/api/capacity", health.Capacity)
	router.GET("/go/health", middleware.RequireAdmin(), health.HealthCheck)
	router.POST("/api/csp-report", cspReportHandler)

	router.GET("/.well-known/security.txt", static.SecurityTxt)
	router.GET("/security.txt", static.SecurityTxt)
	router.GET("/robots.txt", static.RobotsTxt)
	router.GET("/sitemap.xml", static.SitemapXML)
	router.GET("/bimi-logo.svg", static.BIMILogoSVG)
	router.GET("/llms.txt", static.LLMsTxt)
	router.GET("/llms-full.txt", static.LLMsFullTxt)
	router.GET("/.well-known/llms.txt", static.LLMsTxt)
	router.GET("/.well-known/llms-full.txt", static.LLMsFullTxt)
	router.GET("/manifest.json", static.ManifestJSON)
	router.GET("/sw.js", static.ServiceWorker)
}

func registerAnalysisRoutes(d routeDeps, analysis *handlers.AnalysisHandler, history *handlers.HistoryHandler, stats *handlers.StatsHandler, compare *handlers.CompareHandler, export *handlers.ExportHandler, snapshot *handlers.SnapshotHandler) {
	d.Router.GET("/analyze", analysis.Analyze)
	// HEAD must mirror GET semantics (RFC 9110 §9.3.2): same status, same headers,
	// no body. CDNs and link-validators use HEAD to revalidate cached responses;
	// returning 404 on HEAD makes them treat the URL as dead.
	d.Router.HEAD("/analyze", analysis.Analyze)
	d.Router.POST("/analyze", middleware.AnalyzeRateLimit(d.RateLimiter), analysis.Analyze)
	d.Router.GET("/api/scan/progress/:token", handlers.ScanProgressHandler(analysis.ProgressStore))
	d.Router.GET("/history", d.HeavyShed, history.History)
	d.Router.GET("/analysis/:id", d.HeavyShed, analysis.ViewAnalysis)
	d.Router.GET("/analysis/:id/view", d.HeavyShed, analysis.ViewAnalysisStatic)
	d.Router.GET("/analysis/:id/view/:mode", d.HeavyShed, analysis.ViewAnalysisStatic)
	d.Router.GET("/analysis/:id/executive", d.HeavyShed, analysis.ViewAnalysisExecutive)
	d.Router.GET("/stats", stats.Stats)
	d.Router.GET("/statistics", stats.StatisticsRedirect)
	d.Router.GET("/compare", compare.Compare)
	d.Router.GET("/snapshot/:domain", snapshot.Snapshot)
	d.Router.GET("/export/json", middleware.RequireAdmin(), export.ExportJSON)
	d.Router.GET("/export/subdomains", analysis.ExportSubdomainsCSV)
	d.Router.GET("/analysis/:id/crossref", d.HeavyShed, analysis.ViewCrossReference)
	d.Router.GET("/api/analysis/:id", analysis.APIAnalysis)
	d.Router.GET("/api/replay/:id", analysis.APIReplay)
	d.Router.GET("/api/analysis/:id/checksum", analysis.APIAnalysisChecksum)
	d.Router.GET("/api/analysis/:id/crossref", d.HeavyShed, analysis.APICrossReference)
	d.Router.GET("/api/subdomains/*domain", analysis.APISubdomains)
	d.Router.GET("/api/dns-history", analysis.APIDNSHistory)
}

func registerFeatureRoutes(d routeDeps, analysis *handlers.AnalysisHandler, proxy *handlers.ProxyHandler, static *handlers.StaticHandler) {
	dossierHandler := handlers.NewDossierHandler(d.DB, d.Cfg)
	d.Router.GET("/dossier", middleware.RequireFeature(entitlements.FeatureDossier), dossierHandler.Dossier)

	driftHandler := handlers.NewDriftHandler(d.DB, d.Cfg)
	d.Router.GET("/drift", driftHandler.Timeline)

	watchlistHandler := handlers.NewWatchlistHandler(d.DB, d.Cfg)
	d.Router.GET("/watchlist", middleware.RequireFeature(entitlements.FeatureWatchlist), watchlistHandler.Watchlist)
	d.Router.POST("/watchlist/add", middleware.RequireFeature(entitlements.FeatureWatchlist), watchlistHandler.AddDomain)
	d.Router.POST("/watchlist/:id/delete", middleware.RequireFeature(entitlements.FeatureWatchlist), watchlistHandler.RemoveDomain)
	d.Router.POST("/watchlist/:id/toggle", middleware.RequireFeature(entitlements.FeatureWatchlist), watchlistHandler.ToggleDomain)
	d.Router.POST("/watchlist/endpoint/add", middleware.RequireFeature(entitlements.FeatureWatchlist), watchlistHandler.AddEndpoint)
	d.Router.POST("/watchlist/endpoint/:id/delete", middleware.RequireFeature(entitlements.FeatureWatchlist), watchlistHandler.RemoveEndpoint)
	d.Router.POST("/watchlist/endpoint/:id/toggle", middleware.RequireFeature(entitlements.FeatureWatchlist), watchlistHandler.ToggleEndpoint)
	d.Router.POST("/watchlist/webhook/test", middleware.RequireAdmin(), watchlistHandler.TestWebhook)

	failuresHandler := handlers.NewFailuresHandler(d.DB, d.Cfg)
	d.Router.GET("/failures", failuresHandler.Failures)

	remediationHandler := handlers.NewRemediationHandler(d.DB, d.Cfg)
	d.Router.GET("/remediation", d.HeavyShed, remediationHandler.RemediationPage)
	d.Router.POST("/remediation", remediationHandler.RemediationSubmit)

	investigateHandler := handlers.NewInvestigateHandler(d.Cfg, d.Analyzer)
	d.Router.GET("/investigate", investigateHandler.InvestigatePage)
	d.Router.POST("/investigate", middleware.AnalyzeRateLimit(d.RateLimiter), investigateHandler.Investigate)

	emailHeaderHandler := handlers.NewEmailHeaderHandler(d.Cfg)
	d.Router.GET("/email-header", emailHeaderHandler.EmailHeaderPage)
	d.Router.POST("/email-header", middleware.AnalyzeRateLimit(d.RateLimiter), emailHeaderHandler.AnalyzeEmailHeader)

	toolkitHandler := handlers.NewToolkitHandler(d.Cfg)
	d.Router.GET("/toolkit", toolkitHandler.ToolkitPage)
	d.Router.POST("/toolkit/myip", toolkitHandler.MyIP)
	d.Router.POST("/toolkit/portcheck", middleware.AnalyzeRateLimit(d.RateLimiter), toolkitHandler.PortCheck)

	ttlTunerHandler := handlers.NewTTLTunerHandler(d.Cfg, d.Analyzer)
	d.Router.GET("/ttl-tuner", ttlTunerHandler.TTLTunerPage)
	d.Router.GET("/ttl-tuner/analyze", func(c *gin.Context) { c.Redirect(http.StatusMovedPermanently, "/ttl-tuner") })
	d.Router.POST("/ttl-tuner/analyze", middleware.AnalyzeRateLimit(d.RateLimiter), ttlTunerHandler.AnalyzeTTL)

	d.Router.GET("/proxy/bimi-logo", proxy.BIMILogo)

	agentHandler := agentpkg.NewAgentHandler(d.Cfg, d.Analyzer, handlers.NewTemplateData, d.DB.Queries)
	agentHandler.SaveFn = analysis.SaveForAgent
	d.Router.GET("/agent/search", middleware.AgentRateLimit(d.RateLimiter), agentHandler.AgentSearch)
	d.Router.GET("/agent/api", middleware.AgentRateLimit(d.RateLimiter), agentHandler.AgentAPI)
	d.Router.GET("/agent/badge-view", agentHandler.BadgeView)
	d.Router.GET("/agent/snapshot-view", agentHandler.SnapshotView)
	d.Router.GET("/agent/json-view", agentHandler.JSONView)
	d.Router.GET("/agent/csv-view", agentHandler.CSVView)
	d.Router.GET("/agent/checksum-view", agentHandler.ChecksumView)
	d.Router.GET("/agent/wayback-view", agentHandler.WaybackHTMLView)
	d.Router.GET("/agent/wayback", agentHandler.WaybackView)
	d.Router.GET("/agent/topology-view", agentHandler.TopologyView)
	d.Router.GET("/agent/sources-view", agentHandler.SourcesView)
	d.Router.GET("/agent/confidence-view", agentHandler.ConfidenceView)
	d.Router.GET("/agent/guide-view", agentHandler.GuideView)
	d.Router.GET("/agent/report", agentHandler.ReportView)
	d.Router.GET("/agent/opensearch.xml", agentHandler.OpenSearchXML)
	d.Router.GET("/agent/plugin", agentHandler.PluginPage)

	zoneHandler := handlers.NewZoneHandler(d.DB, d.Cfg)
	d.Router.GET("/zone", middleware.RequireFeature(entitlements.FeatureZoneUpload), zoneHandler.UploadForm)
	d.Router.POST("/zone/upload", middleware.RequireFeature(entitlements.FeatureZoneUpload), zoneHandler.ProcessUpload)

	registerContentRoutes(d.Router, d.Cfg, d.DB, static, analysis)
}

func registerContentRoutes(router *gin.Engine, cfg *config.Config, database *db.Database, static *handlers.StaticHandler, analysis *handlers.AnalysisHandler) {
	sourcesHandler := handlers.NewSourcesHandler(cfg)
	router.GET("/sources", sourcesHandler.Sources)

	citationReg := citation.Global()
	citationHandler := handlers.NewCitationHandler(cfg, citationReg, database)
	router.GET("/api/authorities", citationHandler.Authorities)
	router.GET("/api/research", citationHandler.ResearchAPI)
	router.GET("/cite", citationHandler.CitePage)
	router.GET("/cite/software", citationHandler.SoftwareCitation)

	tdf := handlers.NewTemplateData
	architectureHandler := contentpkg.NewArchitectureHandler(cfg, tdf)
	router.GET("/architecture", architectureHandler.Architecture)

	signatureHandler := handlers.NewSignatureHandler(cfg)
	router.GET("/signature", signatureHandler.SignaturePage)

	topologyHandler := handlers.NewTopologyHandler(cfg)
	router.GET("/topology", topologyHandler.Topology)
	router.GET("/replay/:id", analysis.ReplayPage(topologyHandler))

	changelogHandler := handlers.NewChangelogHandler(cfg)
	router.GET("/changelog", changelogHandler.Changelog)

	faqHandler := contentpkg.NewFAQHandler(cfg, tdf)
	router.GET("/faq/subdomains", faqHandler.SubdomainDiscovery)

	confidenceHandler := handlers.NewConfidenceHandler(cfg, database)
	router.GET("/confidence", confidenceHandler.Confidence)
	router.GET("/confidence/audit-log", confidenceHandler.AuditLog)

	securityPolicyHandler := contentpkg.NewSecurityPolicyHandler(cfg, tdf)
	router.GET("/security-policy", securityPolicyHandler.SecurityPolicy)

	privacyHandler := contentpkg.NewPrivacyHandler(cfg, tdf)
	router.GET("/privacy", privacyHandler.Privacy)

	aboutHandler := contentpkg.NewAboutHandler(cfg, tdf)
	router.GET("/about", aboutHandler.About)

	contactHandler := contentpkg.NewContactHandler(cfg, tdf)
	router.GET("/contact", contactHandler.Contact)

	refLibHandler := contentpkg.NewReferenceLibraryHandler(cfg, tdf)
	router.GET("/reference-library", refLibHandler.ReferenceLibrary)

	roadmapHandler := handlers.NewRoadmapHandler(cfg)
	router.GET("/roadmap", roadmapHandler.Roadmap)

	approachHandler := contentpkg.NewApproachHandler(cfg, tdf)
	router.GET("/approach", approachHandler.Approach)

	edeHandler := handlers.NewEDEHandler(database, cfg)
	router.GET("/ede", edeHandler.EDE)

	manifestoHandler := contentpkg.NewManifestoHandler(cfg, tdf)
	router.GET("/manifesto", manifestoHandler.Manifesto)

	ecosystemHandler := contentpkg.NewEcosystemHandler(cfg, tdf)
	router.GET("/ecosystem", ecosystemHandler.Ecosystem)

	owlSemaphoreHandler := handlers.NewOwlSemaphoreHandler(cfg)
	router.GET("/owl-semaphore", owlSemaphoreHandler.OwlSemaphore)
	router.GET("/owl-layers", owlSemaphoreHandler.OwlLayers)

	commStdsHandler := contentpkg.NewCommunicationStandardsHandler(cfg, tdf)
	router.GET("/communication-standards", commStdsHandler.CommunicationStandards)

	// Legacy named PDF routes — canonical citation URLs (Zenodo DOI
	// 10.5281/zenodo.19468134, JSON-LD on /corpus). Each registers GET + HEAD
	// so that link checkers, social-card preview bots, and curl -I (which
	// issues HEAD by default) get a 200 instead of falling through to NoRoute
	// and rendering a 404. The handlers themselves are method-agnostic —
	// http.ServeFile honors HEAD by writing only headers.
	router.GET("/methodology", static.MethodologyPDF)
	router.HEAD("/methodology", static.MethodologyPDF)
	router.GET("/docs/dns-tool-methodology.pdf", static.MethodologyPDF)
	router.HEAD("/docs/dns-tool-methodology.pdf", static.MethodologyPDF)
	router.GET("/foundations", static.FoundationsPDF)
	router.HEAD("/foundations", static.FoundationsPDF)
	router.GET("/docs/philosophical-foundations.pdf", static.FoundationsPDF)
	router.HEAD("/docs/philosophical-foundations.pdf", static.FoundationsPDF)
	router.GET("/manifesto-pdf", static.ManifestoPDF)
	router.HEAD("/manifesto-pdf", static.ManifestoPDF)
	router.GET("/docs/founders-manifesto.pdf", static.ManifestoPDF)
	router.HEAD("/docs/founders-manifesto.pdf", static.ManifestoPDF)
	router.GET("/communication-standards-pdf", static.CommStandardsPDF)
	router.HEAD("/communication-standards-pdf", static.CommStandardsPDF)
	router.GET("/docs/communication-standards.pdf", static.CommStandardsPDF)
	router.HEAD("/docs/communication-standards.pdf", static.CommStandardsPDF)

	router.GET("/docs/owl-semaphore-system.pdf", static.OwlSemaphoreSystemPDF)
	router.HEAD("/docs/owl-semaphore-system.pdf", static.OwlSemaphoreSystemPDF)
	router.GET("/docs/owl-1-normative.pdf", static.Owl1NormativePDF)
	router.HEAD("/docs/owl-1-normative.pdf", static.Owl1NormativePDF)
	router.GET("/docs/owl-2-non-normative.pdf", static.Owl2NonNormativePDF)
	router.HEAD("/docs/owl-2-non-normative.pdf", static.Owl2NonNormativePDF)
	router.GET("/docs/owl-3-critical.pdf", static.Owl3CriticalPDF)
	router.HEAD("/docs/owl-3-critical.pdf", static.Owl3CriticalPDF)
	router.GET("/docs/owl-4-metacognitive.pdf", static.Owl4MetacognitivePDF)
	router.HEAD("/docs/owl-4-metacognitive.pdf", static.Owl4MetacognitivePDF)
	router.GET("/docs/the-real-bot-manifesto.pdf", static.RealBotManifestoPDF)
	router.HEAD("/docs/the-real-bot-manifesto.pdf", static.RealBotManifestoPDF)

	// Versioned PDF route: /docs/v<AppVersion>/<filename>.pdf
	// Used to bypass any prior edge-cache poisoning of
	// legacy /docs/<file>.pdf paths. Filename allowlist is enforced inside
	// the handler. Legacy routes above remain canonical for external
	// citations (Zenodo DOI 10.5281/zenodo.19468134) and JSON-LD.
	router.GET("/docs/:appver/:filename", static.VersionedPDF)
	router.HEAD("/docs/:appver/:filename", static.VersionedPDF)

	videoHandler := handlers.NewVideoHandler(cfg)
	router.GET("/publications", videoHandler.Publications)
	router.GET("/video/forgotten-domain", videoHandler.ForgottenDomain)
	router.GET("/case-study/", videoHandler.CaseStudyIndex)
	router.GET("/case-study/intelligence-dmarc", videoHandler.IntelligenceDMARC)

	roeHandler := contentpkg.NewROEHandler(cfg, tdf)
	router.GET("/roe", roeHandler.ROE)

	blackSiteHandler := handlers.NewBlackSiteHandler(database, cfg)
	router.GET("/black-site", blackSiteHandler.BlackSite)

	brandColorsHandler := handlers.NewBrandColorsHandler(cfg)
	router.GET("/brand-colors", brandColorsHandler.BrandColors)

	colorScienceHandler := contentpkg.NewColorScienceHandler(cfg, tdf)
	router.GET("/color-science", colorScienceHandler.ColorScience)

	badgeHandler := badgepkg.NewBadgeHandler(database, cfg, handlers.NewTemplateData)
	router.GET("/badge", badgeHandler.Badge)
	router.GET("/badge/shields", badgeHandler.BadgeShieldsIO)
	router.GET("/badge/embed", badgeHandler.BadgeEmbed)
	router.GET("/badge/animated", func(c *gin.Context) { handlers.BadgeAnimated(badgeHandler, c) })

	router.GET("/analysis/:id/cite", citationHandler.AnalysisCitation)
}

func registerAdminRoutes(d routeDeps) {
	healthHandler := handlers.NewHealthHandler(d.DB, d.Analyzer)
	d.Router.GET("/api/health", middleware.RequireAdmin(), healthHandler.HealthCheck)

	adminHandler := adminpkg.NewAdminHandler(d.DB, d.Cfg, handlers.NewTemplateData, d.Analyzer.BackpressureRejections)
	d.Router.GET("/ops", middleware.RequireAdmin(), adminHandler.Dashboard)
	d.Router.POST("/ops/user/:id/delete", middleware.RequireAdmin(), adminHandler.DeleteUser)
	d.Router.POST("/ops/user/:id/reset-sessions", middleware.RequireAdmin(), adminHandler.ResetUserSessions)
	d.Router.POST("/ops/sessions/purge-expired", middleware.RequireAdmin(), adminHandler.PurgeExpiredSessions)
	d.Router.GET("/ops/operations", middleware.RequireAdmin(), adminHandler.OperationsPage)
	d.Router.POST("/ops/run/:task", middleware.RequireAdmin(), adminHandler.RunOperation)

	confidenceBackfillHandler := handlers.NewConfidenceBackfillHandler(d.DB)
	d.Router.POST("/ops/confidence-backfill", middleware.RequireAdmin(), confidenceBackfillHandler.Start)
	d.Router.GET("/ops/confidence-backfill/status", middleware.RequireAdmin(), confidenceBackfillHandler.Status)

	probeAdminHandler := adminpkg.NewProbeAdminHandler(d.DB, d.Cfg, handlers.NewTemplateData)
	d.Router.GET("/ops/probes", middleware.RequireAdmin(), probeAdminHandler.ProbeDashboard)
	d.Router.POST("/ops/probes/:id/:action", middleware.RequireAdmin(), probeAdminHandler.RunProbeAction)

	analyticsHandler := handlers.NewAnalyticsHandler(d.DB, d.Cfg)
	d.Router.GET("/ops/analytics", middleware.RequireAdmin(), analyticsHandler.Dashboard)

	telemetryHandler := handlers.NewTelemetryHandler(d.DB, d.Cfg)
	d.Router.GET("/ops/telemetry", middleware.RequireAdmin(), telemetryHandler.Dashboard)
	d.Router.GET("/admin/telemetry", middleware.RequireAdmin(), telemetryHandler.Dashboard)
	d.Router.GET("/api/telemetry/verify/:id", middleware.RequireAdmin(), telemetryHandler.VerifyHash)

	logsHandler := handlers.NewLogsHandler(d.DB, d.Cfg)
	d.Router.GET("/ops/logs", middleware.RequireAdmin(), logsHandler.Dashboard)
	d.Router.GET("/admin/logs", middleware.RequireAdmin(), logsHandler.Dashboard)
	d.Router.GET("/admin/logs/export", middleware.RequireAdmin(), logsHandler.ExportJSONL)

	pipelineHandler := handlers.NewPipelineHandler(d.DB, d.Cfg)
	d.Router.GET("/ops/pipeline", middleware.RequireAdmin(), pipelineHandler.Observatory)

	if d.ScannerWatch != nil {
		d.Router.GET("/ops/scanners", middleware.RequireAdmin(), d.ScannerWatch.Handler)
	}
}

func registerAuthRoutes(d routeDeps) {
	authHandler := authpkg.NewAuthHandler(d.Cfg, d.DB.Pool)
	if d.Cfg.GoogleClientID != "" {
		authRL := middleware.AuthRateLimit(d.RateLimiter)
		d.Router.GET("/auth/login", authRL, authHandler.Login)
		d.Router.GET("/auth/callback", authRL, authHandler.Callback)
		d.Router.POST("/auth/logout", authHandler.Logout)
	}
}

func registerNotFoundRoute(router *gin.Engine, cfg *config.Config) {
	router.NoRoute(func(c *gin.Context) {
		nonce, _ := c.Get("csp_nonce")
		csrfToken, _ := c.Get("csrf_token")
		data := gin.H{
			"AppVersion":        cfg.AppVersion,
			"MaintenanceNote":   cfg.MaintenanceNote,
			"BetaPages":         cfg.BetaPages,
			"IsCloudDeployment": cfg.IsCloudDeployment,
			"CspNonce":          nonce,
			"CsrfToken":         csrfToken,
			"ActivePage":        "home",
		}
		for k, v := range middleware.GetAuthTemplateData(c) {
			data[k] = v
		}
		if cfg.GoogleClientID != "" {
			data["GoogleAuthEnabled"] = true
		}
		c.HTML(http.StatusNotFound, "index.html", data)
	})
}

func awaitShutdown(srv *http.Server, syncCancel context.CancelFunc, ac *middleware.AnalyticsCollector) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	<-quit
	slog.Info("Shutdown signal received, draining connections…")

	syncCancel()
	ac.Flush()
	slog.Info("Analytics flushed on shutdown")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("Server forced to shutdown", mapKeyError, err)
		os.Exit(1)
	}

	slog.Info("Server exited cleanly")
}

func findTemplatesDir() string {
	candidates := []string{
		"go-server/templates",
		"templates",
		"../templates",
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}
	slog.Warn("Templates directory not found, using default")
	return "templates"
}

var cacheableExts = map[string]bool{
	".css": true, ".js": true, ".woff": true, ".woff2": true, ".ttf": true,
	".png": true, ".ico": true, ".svg": true, ".jpg": true, ".jpeg": true,
	".gif": true, ".webp": true, ".avif": true,
	".mp4": true, ".webm": true, ".ogg": true, ".m4a": true,
	".pdf": true, ".zip": true, ".map": true,
}

func isStaticAsset(fp string) bool {
	return cacheableExts[filepath.Ext(fp)]
}

func findStaticDir() string {
	candidates := []string{
		"static",
		"go-server/static",
		"../static",
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}
	slog.Warn("Static directory not found, using default")
	return "static"
}

// cspReportHandler receives CSP / NEL violation reports from browsers.
// Wired to the Reporting-Endpoints + Report-To headers and the CSP
// `report-to` / `report-uri` directives set in the security middleware.
// CSP report bodies are bounded (the browser will not send anything huge),
// but cap the read at 32 KiB to be defensive. Already CSRF-exempt via the
// /api/ prefix in middleware/csrf.go. Returns 204 unconditionally — failure
// to log a CSP report must never break the violating page.
//
// Body shapes accepted (browser dependent):
//   - report-uri legacy:  { "csp-report": { "violated-directive": ..., ... } }
//   - Reporting API v1:   [ { "type": "csp-violation", "body": { ... } }, ... ]
//
// We try to extract the most useful structured fields for slog and fall back
// to the raw payload if neither shape parses.
func cspReportHandler(c *gin.Context) {
	const maxReportBytes = 32 * 1024
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxReportBytes))
	if err != nil {
		slog.Warn("csp-report read error", "error", err, "remote", c.ClientIP())
		c.Status(http.StatusNoContent)
		return
	}
	if len(body) == 0 {
		c.Status(http.StatusNoContent)
		return
	}
	logCSPReport(body, c.Request.UserAgent(), c.ClientIP(), c.GetHeader("Content-Type"))
	c.Status(http.StatusNoContent)
}

func logCSPReport(body []byte, ua, remote, ct string) {
	base := []any{
		"event", "csp_report",
		"category", "security",
		"size", len(body),
		"ua", ua,
		"remote", remote,
		"content_type", ct,
	}
	// Try Reporting API v1 first: top-level JSON array.
	var arr []map[string]any
	if err := json.Unmarshal(body, &arr); err == nil {
		for _, rep := range arr {
			repBody, _ := rep["body"].(map[string]any)
			slog.Info("csp-report",
				append(base,
					"report_type", rep["type"],
					"url", rep["url"],
					"violated_directive", csprStr(repBody, "effectiveDirective", "violatedDirective"),
					"blocked_uri", csprStr(repBody, "blockedURL", "blockedURI"),
					"document_uri", csprStr(repBody, "documentURL", "documentURI"),
					"source_file", csprStr(repBody, "sourceFile"),
					"line", repBody["lineNumber"],
					"disposition", csprStr(repBody, "disposition"),
				)...,
			)
		}
		return
	}
	// Fall back to legacy report-uri envelope: { "csp-report": {...} }.
	var legacy map[string]any
	if err := json.Unmarshal(body, &legacy); err == nil {
		rep, _ := legacy["csp-report"].(map[string]any)
		if rep != nil {
			slog.Info("csp-report",
				append(base,
					"report_type", "csp-violation",
					"violated_directive", csprStr(rep, "effective-directive", "violated-directive"),
					"blocked_uri", csprStr(rep, "blocked-uri"),
					"document_uri", csprStr(rep, "document-uri"),
					"source_file", csprStr(rep, "source-file"),
					"line", rep["line-number"],
					"disposition", csprStr(rep, "disposition"),
				)...,
			)
			return
		}
	}
	// Unknown shape — log raw body bounded by the read cap above.
	slog.Info("csp-report", append(base, "report_type", "unknown", "body", string(body))...)
}

// csprStr returns the first non-empty string value for any of the candidate
// keys. CSP report payloads use slightly different field names across browser
// versions and report formats.
func csprStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func startScheduledSync(ctx context.Context) {
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		slog.Warn("Could not load ET timezone, using UTC-5 offset")
		loc = time.FixedZone("ET", -5*60*60)
	}

	go func() {
		for {
			now := time.Now().In(loc)
			next := time.Date(now.Year(), now.Month(), now.Day(), 4, 0, 0, 0, loc)
			if now.After(next) {
				next = next.Add(24 * time.Hour)
			}
			wait := time.Until(next)
			slog.Info("Notion sync scheduled", "next_run", next.Format("2006-01-02 15:04 MST"), "wait", wait.Round(time.Minute))

			select {
			case <-time.After(wait):
				runNotionSync()
			case <-ctx.Done():
				slog.Info("Scheduled sync shutting down")
				return
			}
		}
	}()
}

func startNotificationDelivery(ctx context.Context, n *notifier.Notifier) {
	go func() {
		const interval = 30 * time.Second
		const batchSize int32 = 50
		slog.Info("Notification delivery loop started", "interval", interval, "batch_size", batchSize)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				delivered, err := n.DeliverPending(ctx, batchSize)
				if err != nil {
					slog.Error("Notification delivery error", mapKeyError, err)
				} else if delivered > 0 {
					slog.Info("Notifications delivered", "count", delivered)
				}
			case <-ctx.Done():
				slog.Info("Notification delivery loop shutting down")
				return
			}
		}
	}()
}

func runNotionSync() {
	slog.Info("Starting scheduled Notion roadmap sync")

	scriptPath := "scripts/notion-roadmap-sync.mjs"
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		slog.Warn("Notion sync script not found", "path", scriptPath)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "node", scriptPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		slog.Error("Notion sync failed", mapKeyError, err, "output", string(output))
		return
	}
	slog.Info("Notion sync completed", "output", string(output))
}
