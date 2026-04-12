// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package db_test

import (
        "context"
        "fmt"
        "os"
        "strings"
        "sync/atomic"
        "testing"
        "time"

        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"
)

func getTestDB(t *testing.T) *db.Database {
        t.Helper()
        dbURL := os.Getenv("DATABASE_URL")
        if dbURL == "" {
                t.Skip("DATABASE_URL not set, skipping integration test")
        }
        database, err := db.ConnectForTests(dbURL)
        if err != nil {
                t.Fatalf("Failed to connect to database: %v", err)
        }
        t.Cleanup(func() { database.Close() })
        return database
}

func TestHealthCheck(t *testing.T) {
        database := getTestDB(t)
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()

        if err := database.HealthCheck(ctx); err != nil {
                t.Fatalf("Health check failed: %v", err)
        }
}

func TestListSuccessfulAnalyses(t *testing.T) {
        database := getTestDB(t)
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()

        analyses, err := database.Queries.ListSuccessfulAnalyses(ctx, dbq.ListSuccessfulAnalysesParams{
                Limit:  5,
                Offset: 0,
        })
        if err != nil {
                t.Fatalf("ListSuccessfulAnalyses failed: %v", err)
        }

        t.Logf("Found %d successful analyses", len(analyses))
        for _, a := range analyses {
                t.Logf("  - %s (ID: %d)", a.Domain, a.ID)
        }
}

func TestCountAllAnalyses(t *testing.T) {
        database := getTestDB(t)
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()

        count, err := database.Queries.CountAllAnalyses(ctx)
        if err != nil {
                t.Fatalf("CountAllAnalyses failed: %v", err)
        }
        t.Logf("Total analyses in database: %d", count)
}

func TestListRecentStats(t *testing.T) {
        database := getTestDB(t)
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()

        stats, err := database.Queries.ListRecentStats(ctx, 5)
        if err != nil {
                t.Fatalf("ListRecentStats failed: %v", err)
        }
        t.Logf("Found %d recent stat entries", len(stats))
}

func TestListPopularDomains(t *testing.T) {
        database := getTestDB(t)
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()

        domains, err := database.Queries.ListPopularDomains(ctx, 5)
        if err != nil {
                t.Fatalf("ListPopularDomains failed: %v", err)
        }
        t.Logf("Top %d popular domains:", len(domains))
        for _, d := range domains {
                t.Logf("  - %s (%d analyses)", d.Domain, d.Count)
        }
}

func TestCountryDistribution(t *testing.T) {
        database := getTestDB(t)
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()

        countries, err := database.Queries.ListCountryDistribution(ctx, 5)
        if err != nil {
                t.Fatalf("ListCountryDistribution failed: %v", err)
        }
        t.Logf("Top %d countries:", len(countries))
        for _, c := range countries {
                name := ""
                if c.CountryName != nil {
                        name = *c.CountryName
                }
                code := ""
                if c.CountryCode != nil {
                        code = *c.CountryCode
                }
                t.Logf("  - %s (%s): %d", name, code, c.Count)
        }
}

func TestConnect_ProductionSafeguard_BlocksHeliumHost(t *testing.T) {
        t.Setenv("REPLIT_DEPLOYMENT", "1")
        _, err := db.Connect("postgres://user:pass@helium:5432/testdb")
        if err == nil {
                t.Fatal("expected error when connecting to helium host in production, got nil")
        }
        if got := err.Error(); !strings.Contains(got, "misconfiguration") || !strings.Contains(got, "helium") {
                t.Errorf("expected misconfiguration error mentioning helium, got: %s", got)
        }
}

func TestClose_NilPool_NoPanic(t *testing.T) {
        d := &db.Database{Pool: nil}
        d.Close()
}

func TestClose_DoubleClosed_NoPanic(t *testing.T) {
        database := getTestDB(t)
        database.Close()
        database.Close()
}

func TestHealthCheck_CanceledContext_ReturnsError(t *testing.T) {
        database := getTestDB(t)
        ctx, cancel := context.WithCancel(context.Background())
        cancel()
        err := database.HealthCheck(ctx)
        if err == nil {
                t.Fatal("expected error from HealthCheck with canceled context")
        }
}

func TestConnectWithRetry_FailsThenSucceeds(t *testing.T) {
        var attempts atomic.Int32
        fakeDB := &db.Database{}

        connector := db.ConnectorFunc(func(url string) (*db.Database, error) {
                n := attempts.Add(1)
                if n < 3 {
                        return nil, fmt.Errorf("connection refused (attempt %d)", n)
                }
                return fakeDB, nil
        })

        result, err := db.ConnectWithRetry("postgres://fake", connector, 5, 1*time.Millisecond)
        if err != nil {
                t.Fatalf("expected success after retries, got error: %v", err)
        }
        if result != fakeDB {
                t.Error("expected returned DB to be the fake DB")
        }
        if attempts.Load() != 3 {
                t.Errorf("expected 3 attempts, got %d", attempts.Load())
        }
}

func TestConnectWithRetry_ExhaustsAllRetries(t *testing.T) {
        var attempts atomic.Int32
        connector := db.ConnectorFunc(func(url string) (*db.Database, error) {
                attempts.Add(1)
                return nil, fmt.Errorf("persistent failure")
        })

        _, err := db.ConnectWithRetry("postgres://fake", connector, 3, 1*time.Millisecond)
        if err == nil {
                t.Fatal("expected error after exhausting retries")
        }
        if !strings.Contains(err.Error(), "persistent failure") {
                t.Errorf("expected last error to propagate, got: %v", err)
        }
        if attempts.Load() != 3 {
                t.Errorf("expected exactly 3 attempts, got %d", attempts.Load())
        }
}

func TestConnectWithRetry_RetryDelayIsRespected(t *testing.T) {
        var attempts atomic.Int32
        retryDelay := 50 * time.Millisecond
        maxRetries := 4

        connector := db.ConnectorFunc(func(url string) (*db.Database, error) {
                n := attempts.Add(1)
                if n < int32(maxRetries) {
                        return nil, fmt.Errorf("fail attempt %d", n)
                }
                return &db.Database{}, nil
        })

        start := time.Now()
        _, err := db.ConnectWithRetry("postgres://fake", connector, maxRetries, retryDelay)
        elapsed := time.Since(start)

        if err != nil {
                t.Fatalf("unexpected error: %v", err)
        }

        expectedMinDelay := time.Duration(maxRetries-2) * retryDelay
        if elapsed < expectedMinDelay {
                t.Errorf("retry loop completed in %v, expected at least %v (retries should sleep)", elapsed, expectedMinDelay)
        }
}

func TestConnectWithRetry_SucceedsOnFirstTry(t *testing.T) {
        var attempts atomic.Int32
        fakeDB := &db.Database{}
        connector := db.ConnectorFunc(func(url string) (*db.Database, error) {
                attempts.Add(1)
                return fakeDB, nil
        })

        result, err := db.ConnectWithRetry("postgres://fake", connector, 5, 1*time.Millisecond)
        if err != nil {
                t.Fatalf("unexpected error: %v", err)
        }
        if result != fakeDB {
                t.Error("expected returned DB to be the fake DB")
        }
        if attempts.Load() != 1 {
                t.Errorf("should not retry on success, got %d attempts", attempts.Load())
        }
}

func TestConnectWithRetry_SafeguardBlocksBeforeRetry(t *testing.T) {
        t.Setenv("REPLIT_DEPLOYMENT", "1")
        var attempts atomic.Int32
        connector := db.ConnectorFunc(func(url string) (*db.Database, error) {
                attempts.Add(1)
                return nil, fmt.Errorf("should not reach here")
        })

        _, err := db.ConnectWithRetry("postgres://user:pass@helium:5432/testdb", connector, 5, 1*time.Millisecond)
        if err == nil {
                t.Fatal("expected safeguard error")
        }
        if !strings.Contains(err.Error(), "misconfiguration") {
                t.Errorf("expected misconfiguration error, got: %v", err)
        }
        if attempts.Load() != 0 {
                t.Errorf("connector should not be called when safeguard triggers, got %d attempts", attempts.Load())
        }
}

func TestConnectWithRetry_URLPassedToConnector(t *testing.T) {
        var receivedURL string
        connector := db.ConnectorFunc(func(url string) (*db.Database, error) {
                receivedURL = url
                return &db.Database{}, nil
        })

        _, _ = db.ConnectWithRetry("postgres://myhost:5432/mydb", connector, 1, 1*time.Millisecond)
        if receivedURL != "postgres://myhost:5432/mydb" {
                t.Errorf("connector received URL %q, want postgres://myhost:5432/mydb", receivedURL)
        }
}

