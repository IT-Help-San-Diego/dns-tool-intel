// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
        "html/template"
        "net/http"
        "net/http/httptest"
        "net/url"
        "strings"

        "github.com/gin-gonic/gin"
)

func mustParseMinimalTemplate(name string) *template.Template {
        return template.Must(template.New(name).Parse("{{define \"" + name + "\"}}ok{{end}}"))
}

func init() {
        gin.SetMode(gin.TestMode)
}

func mockGinContext() *gin.Context {
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
        return c
}

func mockGinContextWithForm(sel1, sel2 string) *gin.Context {
        form := url.Values{}
        form.Set("dkim_selector1", sel1)
        form.Set("dkim_selector2", sel2)

        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
        c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        return c
}

func mockGinContextWithCovert(covert string) *gin.Context {
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        queryURL := "/"
        if covert != "" {
                queryURL = "/?covert=" + covert
        }
        c.Request = httptest.NewRequest(http.MethodGet, queryURL, nil)
        return c
}
