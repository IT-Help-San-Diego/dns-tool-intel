// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func newLoadShedRouter(capacity int, maxWait time.Duration, handler gin.HandlerFunc) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/heavy", LoadShedder(capacity, maxWait), handler)
	return r
}

func TestLoadShedderPassesUnderCapacity(t *testing.T) {
	r := newLoadShedRouter(2, 50*time.Millisecond, func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/heavy", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if w.Header().Get("Retry-After") != "" {
		t.Fatalf("unexpected Retry-After header on passed request")
	}
}

func TestLoadShedderShedsWhenSaturated(t *testing.T) {
	occupied := make(chan struct{})
	release := make(chan struct{})
	r := newLoadShedRouter(1, 30*time.Millisecond, func(c *gin.Context) {
		close(occupied)
		<-release
		c.String(http.StatusOK, "ok")
	})

	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/heavy", nil))
		firstDone <- w
	}()

	select {
	case <-occupied:
	case <-time.After(2 * time.Second):
		t.Fatal("first request never reached handler")
	}

	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/heavy", nil))

	if w2.Code != http.StatusServiceUnavailable {
		t.Fatalf("saturated status = %d, want %d", w2.Code, http.StatusServiceUnavailable)
	}
	if got := w2.Header().Get("Retry-After"); got != heavyRouteRetryAfter {
		t.Fatalf("Retry-After = %q, want %q", got, heavyRouteRetryAfter)
	}
	if got := w2.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want %q", got, "no-store")
	}

	close(release)
	select {
	case w1 := <-firstDone:
		if w1.Code != http.StatusOK {
			t.Fatalf("first request status = %d, want %d", w1.Code, http.StatusOK)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first request never completed")
	}
}

func TestLoadShedderReleasesSlotAfterCompletion(t *testing.T) {
	r := newLoadShedRouter(1, 30*time.Millisecond, func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/heavy", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("sequential request %d status = %d, want %d", i, w.Code, http.StatusOK)
		}
	}
}

func TestLoadShedderReleasesSlotAfterPanic(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(gin.Recovery())
	shed := LoadShedder(1, 30*time.Millisecond)
	first := true
	r.GET("/heavy", shed, func(c *gin.Context) {
		if first {
			first = false
			panic("boom")
		}
		c.String(http.StatusOK, "ok")
	})

	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, httptest.NewRequest(http.MethodGet, "/heavy", nil))
	if w1.Code != http.StatusInternalServerError {
		t.Fatalf("panicking request status = %d, want %d", w1.Code, http.StatusInternalServerError)
	}

	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/heavy", nil))
	if w2.Code != http.StatusOK {
		t.Fatalf("post-panic request status = %d, want %d — semaphore slot leaked", w2.Code, http.StatusOK)
	}
}

func TestLoadShedderAbortsOnClientCancel(t *testing.T) {
	occupied := make(chan struct{})
	release := make(chan struct{})
	var handlerRuns atomic.Int32
	r := newLoadShedRouter(1, 5*time.Second, func(c *gin.Context) {
		handlerRuns.Add(1)
		close(occupied)
		<-release
		c.String(http.StatusOK, "ok")
	})

	go func() {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/heavy", nil))
	}()

	select {
	case <-occupied:
	case <-time.After(2 * time.Second):
		t.Fatal("first request never reached handler")
	}

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/heavy", nil).WithContext(ctx)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		done <- w
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	// The waiter must give up promptly on cancel — long before the 5s
	// slot wait — without being shed (no Retry-After) and without ever
	// running the handler (the only slot is still held).
	select {
	case w := <-done:
		if got := handlerRuns.Load(); got != 1 {
			t.Fatalf("handler ran %d times, want 1 (cancelled waiter must not execute)", got)
		}
		if w.Header().Get("Retry-After") != "" {
			t.Fatalf("cancelled waiter was shed; want plain abort")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled waiter did not return promptly")
	}
	close(release)
}
