// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package middleware

import (
        "context"
        "crypto/rand"
        "encoding/binary"
        "encoding/hex"
        "encoding/json"
        "errors"
        "log/slog"
        "math"
        "net/url"
        "os"
        "strings"
        "sync"
        "time"

        "github.com/axiomhq/hyperloglog"
        "github.com/gin-gonic/gin"
        "github.com/jackc/pgx/v5"
        "github.com/jackc/pgx/v5/pgxpool"
        "golang.org/x/crypto/sha3"
)

const (
        mapKeyDirect = "direct"
        mapKeyError  = "error"

        // hllSaltKey is the row key under which the stable HLL salt is persisted
        // in the analytics_meta table. The salt is 32 random bytes generated once
        // at first server start and NEVER rotated; rotation would break the
        // mergeability of HLL sketches across the rotation boundary, which is the
        // entire point of using HLL for cross-day distinct counting.
        hllSaltKey = "hll_salt_v1"

        // hllPrecision controls the HLL register count m = 2^precision.
        // p=14 → m=16384 → relative standard error ≈ 1.04/√m ≈ 0.81%.
        // Dense serialized size ≈ 12 KB per day.
        // Reference: Flajolet, Fusy, Gandouet, Meunier (2007) "HyperLogLog: the
        // analysis of a near-optimal cardinality estimation algorithm", DMTCS;
        // Heule, Nunkesser, Hall (2013) "HyperLogLog in Practice", EDBT '13.
        hllPrecision uint8 = 14
)

// AnalyticsCollector aggregates per-day visit telemetry in memory and
// flushes it to PostgreSQL once per minute.
//
// Two distinct hash pipelines coexist for two distinct purposes:
//
//  1. pseudoID(ip, ua) uses a daily-rotating salt to track per-day uniques
//     in the in-memory `visitors` set. The daily rotation guarantees forward
//     secrecy: yesterday's salt is gone, so yesterday's pseudoIDs cannot be
//     re-derived even by the operator. Per-day count is exact.
//
//  2. dailyHLL is a HyperLogLog++ sketch ingested with hashes derived from a
//     STABLE salt (hllSalt). Stability across days is required so that the
//     per-day sketches can be unioned to compute the true distinct count of
//     visitors across arbitrary date windows. HLL stores only register max
//     values, never the underlying identifiers, so it is irreversible.
//
// The "Total Unique Visitors" stat formerly used SUM(unique_visitors), which
// double-counts every returning visitor and is mathematically incorrect.
// The HLL pipeline replaces it with a true distinct count.
type AnalyticsCollector struct {
        pool       *pgxpool.Pool
        baseHost   string
        excludeIPs map[string]bool

        mu              sync.Mutex
        dailySalt       string
        saltDate        string
        visitors        map[string]bool
        pageviews       int
        pageCounts      map[string]int
        refCounts       map[string]int
        analysisDomains map[string]bool
        analysesRun     int

        // Stable HLL pipeline. See type-doc for rationale.
        hllSalt    []byte
        hllEnabled bool
        dailyHLL   *hyperloglog.Sketch
}

func NewAnalyticsCollector(pool *pgxpool.Pool, baseURL string) *AnalyticsCollector {
        host := ""
        if u, err := url.Parse(baseURL); err == nil {
                host = u.Hostname()
        }
        excluded := parseExcludeIPs()
        ac := &AnalyticsCollector{
                pool:            pool,
                baseHost:        host,
                excludeIPs:      excluded,
                visitors:        make(map[string]bool),
                pageCounts:      make(map[string]int),
                refCounts:       make(map[string]int),
                analysisDomains: make(map[string]bool),
                dailyHLL:        hyperloglog.New14(),
        }
        if len(excluded) > 0 {
                slog.Info("Analytics: excluding owner IPs from visitor counts", "count", len(excluded))
        }
        ac.rotateSalt()
        ac.initHLL()
        go ac.flushLoop()
        return ac
}

// initHLL idempotently provisions the analytics_meta table + hll_visitors
// column and loads (or generates and persists) the stable HLL salt.
// Failure is non-fatal: if the salt cannot be loaded, HLL stays disabled
// and the legacy daily-uniques pipeline still functions.
func (ac *AnalyticsCollector) initHLL() {
        if ac.pool == nil {
                slog.Debug("Analytics: HLL disabled (no DB pool)")
                return
        }
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()

        if err := ac.ensureHLLSchema(ctx); err != nil {
                slog.Warn("Analytics: HLL schema provisioning failed; true unique counting disabled", mapKeyError, err)
                return
        }
        salt, err := ac.loadOrCreateHLLSalt(ctx)
        if err != nil {
                slog.Warn("Analytics: HLL salt unavailable; true unique counting disabled", mapKeyError, err)
                return
        }
        ac.mu.Lock()
        ac.hllSalt = salt
        ac.hllEnabled = true
        ac.mu.Unlock()
        slog.Info("Analytics: HLL true-unique-visitor counting enabled",
                "precision", hllPrecision,
                "registers", 1<<hllPrecision,
                "std_error_pct", 0.81)
}

// ensureHLLSchema applies idempotent DDL so the HLL pipeline works even on
// databases that have not had migration 014 applied out-of-band. All
// operations are CREATE/ALTER ... IF NOT EXISTS.
func (ac *AnalyticsCollector) ensureHLLSchema(ctx context.Context) error {
        stmts := []string{
                `CREATE TABLE IF NOT EXISTS analytics_meta (
                        key TEXT PRIMARY KEY,
                        value BYTEA NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )`,
                `ALTER TABLE site_analytics ADD COLUMN IF NOT EXISTS hll_visitors BYTEA`,
        }
        for _, s := range stmts {
                if _, err := ac.pool.Exec(ctx, s); err != nil {
                        return err
                }
        }
        return nil
}

// loadOrCreateHLLSalt returns the persistent 32-byte HLL salt, generating
// and storing one on first call. The INSERT uses ON CONFLICT DO NOTHING so
// concurrent first-starts converge to a single salt value (re-read after
// insert to obtain the winner).
func (ac *AnalyticsCollector) loadOrCreateHLLSalt(ctx context.Context) ([]byte, error) {
        var salt []byte
        err := ac.pool.QueryRow(ctx,
                `SELECT value FROM analytics_meta WHERE key = $1`, hllSaltKey).Scan(&salt)
        if err == nil && len(salt) >= 32 {
                return salt, nil
        }
        if err != nil && !errors.Is(err, pgx.ErrNoRows) {
                return nil, err
        }

        fresh := make([]byte, 32)
        if _, err := rand.Read(fresh); err != nil {
                return nil, err
        }
        if _, err := ac.pool.Exec(ctx,
                `INSERT INTO analytics_meta (key, value) VALUES ($1, $2)
                 ON CONFLICT (key) DO NOTHING`, hllSaltKey, fresh); err != nil {
                return nil, err
        }
        if err := ac.pool.QueryRow(ctx,
                `SELECT value FROM analytics_meta WHERE key = $1`, hllSaltKey).Scan(&salt); err != nil {
                return nil, err
        }
        if len(salt) < 32 {
                return nil, errors.New("loaded HLL salt is too short")
        }
        return salt, nil
}

func parseExcludeIPs() map[string]bool {
        raw := os.Getenv("ANALYTICS_EXCLUDE_IPS")
        if raw == "" {
                return nil
        }
        m := make(map[string]bool)
        for _, ip := range strings.Split(raw, ",") {
                ip = strings.TrimSpace(ip)
                if ip != "" {
                        m[ip] = true
                }
        }
        return m
}

func (ac *AnalyticsCollector) rotateSalt() {
        today := time.Now().UTC().Format("2006-01-02")
        if ac.saltDate == today {
                return
        }
        b := make([]byte, 32)
        if _, err := rand.Read(b); err != nil {
                slog.Error("rand.Read failed", "error", err)
        }
        ac.dailySalt = hex.EncodeToString(b)
        ac.saltDate = today
        ac.visitors = make(map[string]bool)
        ac.pageCounts = make(map[string]int)
        ac.refCounts = make(map[string]int)
        ac.analysisDomains = make(map[string]bool)
        ac.analysesRun = 0
        ac.pageviews = 0
        // Reset the HLL accumulator on day rotation. The previous day's sketch
        // has already been merged into its DB row by the most recent Flush.
        ac.dailyHLL = hyperloglog.New14()
}

func (ac *AnalyticsCollector) pseudoID(ip, ua string) string {
        h := sha3.Sum512([]byte(ac.dailySalt + "|" + ip + "|" + ua))
        return hex.EncodeToString(h[:8])
}

// hllHash mixes (ip, ua) under the stable hllSalt and returns the first 64
// bits of SHA3-512 as the value to insert into the HLL sketch. SHA-3 is
// uniformly distributed in its output, which is the only requirement HLL
// places on its input hash.
func (ac *AnalyticsCollector) hllHash(ip, ua string) uint64 {
        h := sha3.New512()
        _, _ = h.Write(ac.hllSalt)
        _, _ = h.Write([]byte{'|'})
        _, _ = h.Write([]byte(ip))
        _, _ = h.Write([]byte{'|'})
        _, _ = h.Write([]byte(ua))
        sum := h.Sum(nil)
        return binary.BigEndian.Uint64(sum[:8])
}

func (ac *AnalyticsCollector) Middleware() gin.HandlerFunc {
        return func(c *gin.Context) {
                path := c.Request.URL.Path

                if strings.HasPrefix(path, "/static/") ||
                        strings.HasPrefix(path, "/favicon") ||
                        path == "/robots.txt" ||
                        path == "/sitemap.xml" ||
                        path == "/health" ||
                        path == "/sw.js" ||
                        path == "/manifest.json" ||
                        strings.HasPrefix(path, "/.well-known/") ||
                        path == "/llms.txt" ||
                        path == "/llms-full.txt" {
                        c.Next()
                        return
                }

                c.Set("analytics_collector", ac)
                c.Next()

                if c.Writer.Status() >= 400 {
                        return
                }

                ip := c.ClientIP()

                if ac.excludeIPs[ip] {
                        return
                }
                if role, exists := c.Get(mapKeyUserRole); exists && role == "admin" {
                        return
                }

                ua := c.Request.UserAgent()
                referer := extractRefOrigin(c.Request.Referer(), ac.baseHost)
                pagePath := normalizePath(path)

                ac.mu.Lock()
                ac.rotateSalt()
                ac.pageviews++
                pid := ac.pseudoID(ip, ua)
                ac.visitors[pid] = true
                ac.pageCounts[pagePath]++
                if referer != "" && referer != mapKeyDirect {
                        ac.refCounts[referer]++
                }
                if ac.hllEnabled && ac.dailyHLL != nil {
                        ac.dailyHLL.InsertHash(ac.hllHash(ip, ua))
                }
                ac.mu.Unlock()
        }
}

func (ac *AnalyticsCollector) RecordAnalysis(domain string) {
        ac.mu.Lock()
        defer ac.mu.Unlock()
        ac.analysesRun++
        ac.analysisDomains[strings.ToLower(domain)] = true
}

func extractRefOrigin(ref, baseHost string) string {
        if ref == "" {
                return mapKeyDirect
        }
        u, err := url.Parse(ref)
        if err != nil {
                return mapKeyDirect
        }
        host := u.Hostname()
        if host == "" {
                return mapKeyDirect
        }
        if baseHost != "" && (host == baseHost || strings.HasSuffix(host, "."+baseHost)) {
                return ""
        }
        return host
}

func normalizePath(p string) string {
        if p == "/" {
                return "/"
        }
        p = strings.TrimRight(p, "/")
        parts := strings.SplitN(p, "?", 2)
        return parts[0]
}

func (ac *AnalyticsCollector) flushLoop() {
        ticker := time.NewTicker(60 * time.Second)
        defer ticker.Stop()
        for range ticker.C {
                ac.Flush()
        }
}

func (ac *AnalyticsCollector) Flush() {
        ac.mu.Lock()
        if ac.pageviews == 0 {
                ac.mu.Unlock()
                return
        }

        today := time.Now().UTC().Format("2006-01-02")
        pv := ac.pageviews
        uv := len(ac.visitors)
        ar := ac.analysesRun
        ud := len(ac.analysisDomains)

        topPages := make(map[string]int)
        for k, v := range ac.pageCounts {
                topPages[k] = v
        }
        refs := make(map[string]int)
        for k, v := range ac.refCounts {
                refs[k] = v
        }

        // Snapshot HLL delta and reset, so each flush only writes inserts that
        // happened during this interval. HLL union is idempotent so re-merging
        // the same elements would still be correct, just wasteful IO.
        var deltaHLL *hyperloglog.Sketch
        if ac.hllEnabled && ac.dailyHLL != nil {
                deltaHLL = ac.dailyHLL
                ac.dailyHLL = hyperloglog.New14()
        }

        ac.pageviews = 0
        ac.analysesRun = 0
        ac.pageCounts = make(map[string]int)
        ac.refCounts = make(map[string]int)
        ac.mu.Unlock()

        pagesJSON, err := json.Marshal(topPages)
        if err != nil {
                slog.Warn("Analytics flush: marshal top_pages", mapKeyError, err)
        }
        refsJSON, err := json.Marshal(refs)
        if err != nil {
                slog.Warn("Analytics flush: marshal refs", mapKeyError, err)
        }

        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()

        _, err = ac.pool.Exec(ctx, `
                INSERT INTO site_analytics (date, pageviews, unique_visitors, analyses_run, unique_domains_analyzed, referrer_sources, top_pages)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (date) DO UPDATE SET
                        pageviews = site_analytics.pageviews + EXCLUDED.pageviews,
                        unique_visitors = GREATEST(site_analytics.unique_visitors, EXCLUDED.unique_visitors),
                        analyses_run = site_analytics.analyses_run + EXCLUDED.analyses_run,
                        unique_domains_analyzed = GREATEST(site_analytics.unique_domains_analyzed, EXCLUDED.unique_domains_analyzed),
                        referrer_sources = (
                                SELECT COALESCE(jsonb_object_agg(key, val), '{}'::jsonb)
                                FROM (
                                        SELECT key, SUM(value::bigint) AS val
                                        FROM (
                                                SELECT key, value::bigint FROM jsonb_each_text(site_analytics.referrer_sources)
                                                UNION ALL
                                                SELECT key, value::bigint FROM jsonb_each_text(EXCLUDED.referrer_sources)
                                        ) t
                                        GROUP BY key
                                ) merged
                        ),
                        top_pages = (
                                SELECT COALESCE(jsonb_object_agg(key, val), '{}'::jsonb)
                                FROM (
                                        SELECT key, SUM(value::bigint) AS val
                                        FROM (
                                                SELECT key, value::bigint FROM jsonb_each_text(site_analytics.top_pages)
                                                UNION ALL
                                                SELECT key, value::bigint FROM jsonb_each_text(EXCLUDED.top_pages)
                                        ) t
                                        GROUP BY key
                                ) merged
                        ),
                        updated_at = NOW()
        `, today, pv, uv, ar, ud, refsJSON, pagesJSON)
        if err != nil {
                slog.Error("Analytics flush failed", mapKeyError, err)
                return
        }

        if deltaHLL != nil {
                if hllErr := ac.flushHLLDelta(ctx, today, deltaHLL); hllErr != nil {
                        slog.Warn("Analytics HLL flush failed", mapKeyError, hllErr, "date", today)
                }
        }

        slog.Debug("Analytics flushed", "date", today, "pageviews", pv, "unique_visitors", uv)
}

// flushHLLDelta merges the in-memory delta sketch into today's persisted
// sketch atomically. The read+merge+write happens inside a single
// transaction with a row-level lock to keep multi-writer correctness even
// if a future deployment runs more than one collector instance.
func (ac *AnalyticsCollector) flushHLLDelta(ctx context.Context, today string, delta *hyperloglog.Sketch) error {
        tx, err := ac.pool.Begin(ctx)
        if err != nil {
                return err
        }
        defer func() { _ = tx.Rollback(ctx) }()

        var existing []byte
        err = tx.QueryRow(ctx,
                `SELECT hll_visitors FROM site_analytics WHERE date = $1 FOR UPDATE`,
                today).Scan(&existing)
        if err != nil && !errors.Is(err, pgx.ErrNoRows) {
                return err
        }

        merged := delta
        if len(existing) > 0 {
                prior := hyperloglog.New14()
                if uErr := prior.UnmarshalBinary(existing); uErr == nil {
                        if mErr := prior.Merge(delta); mErr == nil {
                                merged = prior
                        } else {
                                slog.Warn("Analytics HLL: merge failed; overwriting with delta", mapKeyError, mErr)
                        }
                } else {
                        slog.Warn("Analytics HLL: existing sketch unreadable; overwriting", mapKeyError, uErr)
                }
        }

        blob, err := merged.MarshalBinary()
        if err != nil {
                return err
        }
        if _, err := tx.Exec(ctx,
                `UPDATE site_analytics SET hll_visitors = $1 WHERE date = $2`,
                blob, today); err != nil {
                return err
        }
        return tx.Commit(ctx)
}

// TrueUniqueVisitorsResult carries the output of a HLL-union distinct-count
// query plus enough metadata for callers to render an honest UI: the date
// range actually covered by HLL data and the formal precision of the
// estimator.
type TrueUniqueVisitorsResult struct {
        Estimate    uint64    // distinct visitors over [Since, Until], cardinality of the HLL union
        DaysCovered int       // number of daily HLL sketches that participated in the union
        Since       time.Time // earliest date in the union (UTC, day-aligned), zero if none
        Until       time.Time // latest date in the union (UTC, day-aligned), zero if none
        StdErrorPct float64   // theoretical relative standard error of the estimator (~0.81% at p=14)
        OK          bool      // false → no HLL sketches available yet; Estimate is meaningless
}

// ComputeTrueUniqueVisitors unions every persisted daily HLL sketch in the
// requested window and returns the cardinality of the union — i.e. the
// mathematically correct count of distinct visitors over that window.
//
// Window semantics:
//   - if since is zero, no lower bound is applied
//   - if until is zero, no upper bound is applied
//
// OK=false means no HLL data is available in the window. Callers should
// surface that state explicitly rather than fall back to the known-incorrect
// SUM(unique_visitors) value.
func ComputeTrueUniqueVisitors(ctx context.Context, pool *pgxpool.Pool, since, until time.Time) TrueUniqueVisitorsResult {
        res := TrueUniqueVisitorsResult{StdErrorPct: hllStdErrorPct(hllPrecision)}
        if pool == nil {
                return res
        }

        query := `SELECT date, hll_visitors FROM site_analytics WHERE hll_visitors IS NOT NULL`
        args := []interface{}{}
        if !since.IsZero() {
                query += ` AND date >= $1`
                args = append(args, since)
        }
        if !until.IsZero() {
                if len(args) == 0 {
                        query += ` AND date <= $1`
                } else {
                        query += ` AND date <= $2`
                }
                args = append(args, until)
        }
        query += ` ORDER BY date ASC`

        rows, err := pool.Query(ctx, query, args...)
        if err != nil {
                slog.Warn("Analytics: query HLL sketches failed", mapKeyError, err)
                return res
        }
        defer rows.Close()

        union := hyperloglog.New14()
        for rows.Next() {
                var d time.Time
                var blob []byte
                if scanErr := rows.Scan(&d, &blob); scanErr != nil {
                        slog.Warn("Analytics: scan HLL sketch failed", mapKeyError, scanErr)
                        continue
                }
                if len(blob) == 0 {
                        continue
                }
                sk := hyperloglog.New14()
                if uErr := sk.UnmarshalBinary(blob); uErr != nil {
                        slog.Warn("Analytics: unmarshal HLL sketch failed", mapKeyError, uErr)
                        continue
                }
                if mErr := union.Merge(sk); mErr != nil {
                        slog.Warn("Analytics: merge HLL sketch failed", mapKeyError, mErr)
                        continue
                }
                if res.DaysCovered == 0 || d.Before(res.Since) {
                        res.Since = d
                }
                if d.After(res.Until) {
                        res.Until = d
                }
                res.DaysCovered++
        }
        if rerr := rows.Err(); rerr != nil {
                slog.Warn("Analytics: HLL sketch row iteration failed", mapKeyError, rerr)
        }
        if res.DaysCovered == 0 {
                return res
        }
        res.Estimate = union.Estimate()
        res.OK = true
        return res
}

// hllStdErrorPct returns the theoretical relative standard error percentage
// of the HLL estimator at the given precision: 100 * 1.04 / sqrt(2^p).
// At p=14 (m=16384) this is exactly 100 * 1.04 / 128 = 0.8125%.
// Reference: Flajolet et al. 2007, §4.
//
// We use math.Sqrt (stdlib, no external dependency) for exact convergence.
// An earlier hand-rolled Newton's method with 8 iterations starting from
// z = x produced 0.7833% — a 4% relative error in a number we are
// publishing to users as a precision guarantee. That defeated the entire
// purpose of having a precision guarantee, so we use the IEEE-754 correct
// stdlib implementation.
func hllStdErrorPct(p uint8) float64 {
        m := float64(uint64(1) << p)
        return 100.0 * 1.04 / math.Sqrt(m)
}

// TrueUniqueVisitors is a convenience wrapper that returns the all-time
// distinct-visitor estimate against this collector's pool.
func (ac *AnalyticsCollector) TrueUniqueVisitors(ctx context.Context) TrueUniqueVisitorsResult {
        if ac == nil {
                return TrueUniqueVisitorsResult{StdErrorPct: hllStdErrorPct(hllPrecision)}
        }
        return ComputeTrueUniqueVisitors(ctx, ac.pool, time.Time{}, time.Time{})
}
