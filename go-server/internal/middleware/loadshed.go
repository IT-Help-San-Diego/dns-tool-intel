// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package middleware

import (
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	// HeavyRouteMaxConcurrent bounds how many database-heavy report
	// requests render at once. Sized below the pgx pool (20) so
	// background writers (analytics flush, log sink) and the homepage
	// metrics refresh always retain connections. Added after the
	// 2026-07-24 crawler-wave outage saturated the pool and queued
	// requests for minutes.
	HeavyRouteMaxConcurrent = 14

	// HeavyRouteMaxWait is how long a request may wait for a slot
	// before being shed with 503. Short on purpose: bounded queues
	// degrade to fast refusals instead of minutes-long backlogs.
	HeavyRouteMaxWait = 5 * time.Second

	// heavyRouteRetryAfter tells crawlers when to come back (seconds).
	heavyRouteRetryAfter = "30"

	// shedLogSampleEvery limits shed logging to one line per N sheds so
	// a crawler storm cannot flood the log pipeline (which itself
	// writes to the database).
	shedLogSampleEvery = 50
)

// LoadShedder returns middleware that caps concurrent execution of the
// wrapped routes with a buffered-channel semaphore. Requests wait up to
// maxWait for a slot, then receive a static 503 with Retry-After. Never
// wrap "/", "/healthz", or static assets — the deployment health check and
// uptime probes must stay unthrottled.
func LoadShedder(capacity int, maxWait time.Duration) gin.HandlerFunc {
	// Fail safe on misconfiguration: a capacity below 1 would make the
	// semaphore unbuffered (or panic outright for negative values),
	// shedding every request after maxWait. Clamp to a floor of 1 so a
	// bad constant degrades to serialized requests, not a total outage.
	if capacity < 1 {
		capacity = 1
	}
	sem := make(chan struct{}, capacity)
	var shedTotal atomic.Uint64
	return func(c *gin.Context) {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
			c.Next()
			return
		default:
		}

		timer := time.NewTimer(maxWait)
		defer timer.Stop()
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
			c.Next()
		case <-timer.C:
			shedOverCapacity(c, shedTotal.Add(1))
		case <-c.Request.Context().Done():
			c.Abort()
		}
	}
}

func shedOverCapacity(c *gin.Context, shedCount uint64) {
	if shedCount == 1 || shedCount%shedLogSampleEvery == 0 {
		slog.Warn("Load shed: heavy-route capacity exceeded",
			"route", c.FullPath(),
			"shed_total", shedCount)
	}
	c.Header("Retry-After", heavyRouteRetryAfter)
	c.Header("Cache-Control", "no-store")
	const shedMsg = "Server is briefly at capacity. Please retry in a few seconds."
	if strings.HasPrefix(c.Request.URL.Path, "/api/") {
		// JSON API clients must not receive a text/plain 503 body.
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": shedMsg})
	} else {
		c.String(http.StatusServiceUnavailable, shedMsg)
	}
	c.Abort()
}
