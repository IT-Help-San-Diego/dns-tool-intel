// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
	"context"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/db"
	"dnstool/go-server/internal/dbq"
	tmplFuncs "dnstool/go-server/internal/templates"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// These tests render the REAL history template through the REAL handler in
// both deployment modes. The lesson is agent_test.go's: fifteen hardcoded
// public-host literals and no assertion about the local build's output shape
// meant local behavior was untested for months. Here both modes are asserted
// on the same fixture: the local build shows the Local ↔ Cloud flipper with
// an outbound link to the canonical host; the cloud build renders none of it.
//
// The handler is driven down its error path (a store whose every query
// fails), which still renders the full page header — so no database or
// network is needed and the assertions run against genuine template output.

type failingRow struct{}

func (failingRow) Scan(...any) error { return context.DeadlineExceeded }

type failingTx struct{}

func (failingTx) Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, context.DeadlineExceeded
}
func (failingTx) Query(context.Context, string, ...interface{}) (pgx.Rows, error) {
	return nil, context.DeadlineExceeded
}
func (failingTx) QueryRow(context.Context, string, ...interface{}) pgx.Row {
	return failingRow{}
}

func historyFlipperRouter(t *testing.T, isCloud bool) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	tmpl, err := template.New("").Funcs(tmplFuncs.FuncMap()).ParseGlob("../../templates/*.html")
	if err != nil {
		t.Fatalf("parse real templates: %v", err)
	}

	h := &HistoryHandler{
		DB: &db.Database{Queries: dbq.New(failingTx{})},
		Config: &config.Config{
			AppVersion:        "test",
			IsCloudDeployment: isCloud,
			CanonicalBaseURL:  "https://dnstool.it-help.tech",
		},
	}

	r := gin.New()
	r.SetHTMLTemplate(tmpl)
	r.GET("/history", h.History)
	return r
}

func renderHistory(t *testing.T, isCloud bool) string {
	t.Helper()
	r := historyFlipperRouter(t, isCloud)
	req := httptest.NewRequest("GET", "/history", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (failing store drives the error path, which still renders the header)", w.Code)
	}
	body := w.Body.String()
	// Apparatus check: a blank error page would pass any absence assertion.
	// The header must have actually rendered for absence to mean anything.
	if !strings.Contains(body, "Analysis History") {
		t.Fatal("page header did not render — the template pipeline is broken, so flipper assertions below would be vacuous")
	}
	return body
}

func TestHistoryFlipper_LocalBuildLinksToCloud(t *testing.T) {
	body := renderHistory(t, false)

	if !strings.Contains(body, `aria-label="History source"`) {
		t.Error("local build is missing the Local ↔ Cloud flipper")
	}
	if !strings.Contains(body, `href="https://dnstool.it-help.tech/history"`) {
		t.Error("the Cloud pill does not link to the canonical public /history — a local BASE_URL must never leak into this link")
	}
	if !strings.Contains(body, `rel="noopener"`) {
		t.Error("the outbound Cloud link is missing rel=noopener")
	}
}

func TestHistoryFlipper_CloudBuildRendersNoFlipper(t *testing.T) {
	body := renderHistory(t, true)

	if strings.Contains(body, `aria-label="History source"`) {
		t.Error("cloud build renders the flipper — the cloud has no local counterpart to link to, so this control must be local-only")
	}
}
