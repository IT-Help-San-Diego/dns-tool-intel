// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// dns-tool:scrutiny design
package handlers

import (
        "context"
        "encoding/json"
        "net/http"
        "strconv"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
        "github.com/jackc/pgx/v5/pgtype"
)

const (
        mapKeyDossier  = "dossier"
        templateDossier = "dossier.html"
        pathDossier     = "/dossier"
)

type DossierHandler struct {
        DB     *db.Database
        Config *config.Config
}

func NewDossierHandler(database *db.Database, cfg *config.Config) *DossierHandler {
        return &DossierHandler{DB: database, Config: cfg}
}

type dossierItem struct {
        ID               int32
        Domain           string
        AsciiDomain      string
        SpfStatus        string
        DmarcStatus      string
        DkimStatus       string
        AnalysisSuccess  bool
        AnalysisDuration float64
        CreatedDate      string
        CreatedTime      string
        ToolVersion      string
        PostureHash      string
}

type analysisRow interface {
        GetID() int32
        GetDomain() string
        GetAsciiDomain() string
        GetSpfStatus() *string
        GetDmarcStatus() *string
        GetDkimStatus() *string
        GetAnalysisDuration() *float64
        GetPostureHash() *string
        GetCreatedAt() pgtype.Timestamp
        GetFullResults() json.RawMessage
}

type listRow struct{ dbq.ListUserAnalysesRow }

func (r listRow) GetID() int32                       { return r.ID }
func (r listRow) GetDomain() string                  { return r.Domain }
func (r listRow) GetAsciiDomain() string             { return r.AsciiDomain }
func (r listRow) GetSpfStatus() *string              { return r.SpfStatus }
func (r listRow) GetDmarcStatus() *string            { return r.DmarcStatus }
func (r listRow) GetDkimStatus() *string             { return r.DkimStatus }
func (r listRow) GetAnalysisDuration() *float64      { return r.AnalysisDuration }
func (r listRow) GetPostureHash() *string            { return r.PostureHash }
func (r listRow) GetCreatedAt() pgtype.Timestamp     { return r.CreatedAt }
func (r listRow) GetFullResults() json.RawMessage    { return r.FullResults }

type searchRow struct{ dbq.SearchUserAnalysesRow }

func (r searchRow) GetID() int32                     { return r.ID }
func (r searchRow) GetDomain() string                { return r.Domain }
func (r searchRow) GetAsciiDomain() string           { return r.AsciiDomain }
func (r searchRow) GetSpfStatus() *string            { return r.SpfStatus }
func (r searchRow) GetDmarcStatus() *string          { return r.DmarcStatus }
func (r searchRow) GetDkimStatus() *string           { return r.DkimStatus }
func (r searchRow) GetAnalysisDuration() *float64    { return r.AnalysisDuration }
func (r searchRow) GetPostureHash() *string          { return r.PostureHash }
func (r searchRow) GetCreatedAt() pgtype.Timestamp   { return r.CreatedAt }
func (r searchRow) GetFullResults() json.RawMessage  { return r.FullResults }

func derefStr(p *string) string {
        if p != nil {
                return *p
        }
        return ""
}

func buildDossierItemFrom(a analysisRow) dossierItem {
        dur := 0.0
        if d := a.GetAnalysisDuration(); d != nil {
                dur = *d
        }
        createdDate, createdTime := "", ""
        if ts := a.GetCreatedAt(); ts.Valid {
                createdDate = FormatDate(ts.Time)
                createdTime = FormatTime(ts.Time)
        }
        return dossierItem{
                ID:               a.GetID(),
                Domain:           a.GetDomain(),
                AsciiDomain:      a.GetAsciiDomain(),
                SpfStatus:        derefStr(a.GetSpfStatus()),
                DmarcStatus:      derefStr(a.GetDmarcStatus()),
                DkimStatus:       derefStr(a.GetDkimStatus()),
                AnalysisSuccess:  true,
                AnalysisDuration: dur,
                CreatedDate:      createdDate,
                CreatedTime:      createdTime,
                ToolVersion:      ExtractToolVersion(a.GetFullResults()),
                PostureHash:      derefStr(a.GetPostureHash()),
        }
}

func (h *DossierHandler) Dossier(c *gin.Context) {
        // Signed-out access never reaches here: the /dossier route is gated by
        // middleware.RequireFeature, which redirects browsers to /auth/login
        // and answers API clients with 401 JSON.
        uid, _ := c.Get("user_id")
        userID, _ := uid.(int32)

        page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
        if page < 1 {
                page = 1
        }
        searchDomain := c.Query("domain")
        perPage := 20

        ctx := c.Request.Context()

        total, err := h.countUserAnalyses(ctx, userID, searchDomain)
        if err != nil {
                errData := NewTemplateData(c, h.Config, mapKeyDossier)
                errData["FlashMessages"] = []FlashMessage{{Category: "danger", Message: "Failed to load intelligence reports"}}
                c.HTML(http.StatusInternalServerError, templateDossier, errData)
                return
        }

        pagination := NewPagination(page, perPage, total)

        items, err := h.fetchUserAnalyses(ctx, userID, searchDomain, &pagination)
        if err != nil {
                errData := NewTemplateData(c, h.Config, mapKeyDossier)
                errData["FlashMessages"] = []FlashMessage{{Category: "danger", Message: "Failed to load tasked collections"}}
                c.HTML(http.StatusInternalServerError, templateDossier, errData)
                return
        }

        pd := BuildPagination(page, pagination.TotalPages, total)

        data := NewTemplateData(c, h.Config, mapKeyDossier)
        data["Analyses"] = items
        data["Pagination"] = pd
        data["SearchDomain"] = searchDomain
        data["TotalReports"] = total
        data["SearchAction"] = pathDossier
        data["SearchPlaceholder"] = "Search your assessed domains..."
        data["SearchAriaLabel"] = "Search dossier by domain name"
        data["PaginationLabel"] = "Intelligence reports pagination"
        data["PaginationBase"] = pathDossier
        c.HTML(http.StatusOK, templateDossier, data)
}

func (h *DossierHandler) countUserAnalyses(ctx context.Context, userID int32, searchDomain string) (int64, error) {
        if searchDomain != "" {
                searchPattern := "%" + searchDomain + "%"
                return h.DB.Queries.CountSearchUserAnalyses(ctx, dbq.CountSearchUserAnalysesParams{
                        UserID: userID,
                        Domain: searchPattern,
                })
        }
        return h.DB.Queries.CountUserAnalyses(ctx, userID)
}

func (h *DossierHandler) fetchUserAnalyses(ctx context.Context, userID int32, searchDomain string, pagination *PaginationInfo) ([]dossierItem, error) {
        if searchDomain != "" {
                searchPattern := "%" + searchDomain + "%"
                analyses, err := h.DB.Queries.SearchUserAnalyses(ctx, dbq.SearchUserAnalysesParams{
                        UserID: userID,
                        Domain: searchPattern,
                        Limit:  pagination.Limit(),
                        Offset: pagination.Offset(),
                })
                if err != nil {
                        return nil, err
                }
                items := make([]dossierItem, 0, len(analyses))
                for _, a := range analyses {
                        items = append(items, buildDossierItemFrom(searchRow{a}))
                }
                return items, nil
        }

        analyses, err := h.DB.Queries.ListUserAnalyses(ctx, dbq.ListUserAnalysesParams{
                UserID: userID,
                Limit:  pagination.Limit(),
                Offset: pagination.Offset(),
        })
        if err != nil {
                return nil, err
        }
        items := make([]dossierItem, 0, len(analyses))
        for _, a := range analyses {
                items = append(items, buildDossierItemFrom(listRow{a}))
        }
        return items, nil
}
