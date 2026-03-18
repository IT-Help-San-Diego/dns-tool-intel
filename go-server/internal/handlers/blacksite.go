// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"log"
	"net/http"

	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/db"

	"github.com/gin-gonic/gin"
)

type BlackSiteHandler struct {
	DB     *db.Database
	Config *config.Config
}

func NewBlackSiteHandler(database *db.Database, cfg *config.Config) *BlackSiteHandler {
	return &BlackSiteHandler{DB: database, Config: cfg}
}

type detaineeView struct {
	BsiID              string
	ShaHash            string
	Title              string
	ThreatLevel        string
	Status             string
	CapturedBy         string
	FileReferences     string
	InterrogationNotes string
	WitnessStatement   string
	DamageAssessment   string
	RecommendedRemedy  string
}

type renditionView struct {
	BsiID       string
	ShaHash     string
	Title       string
	ThreatLevel string
	CommitHash  string
	RenderedBy  string
	Method      string
	Notes       string
	RenderedAt  string
}

type threatCount struct {
	Level string
	Count int64
}

func (h *BlackSiteHandler) BlackSite(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	ctx := c.Request.Context()

	detainees, err := h.DB.Queries.ListDetainees(ctx)
	if err != nil {
		log.Printf("black-site: failed to list detainees: %v", err)
	}

	counts, err := h.DB.Queries.CountDetaineesByThreatLevel(ctx)
	if err != nil {
		log.Printf("black-site: failed to count by threat: %v", err)
	}

	totalRow, err := h.DB.Queries.CountDetaineesTotal(ctx)
	if err != nil {
		log.Printf("black-site: failed to count total: %v", err)
	}

	renditionsRaw, err := h.DB.Queries.ListRenditions(ctx)
	if err != nil {
		log.Printf("black-site: failed to list renditions: %v", err)
	}

	aptList := []detaineeView{}
	zerodayList := []detaineeView{}
	exploitList := []detaineeView{}
	cveList := []detaineeView{}
	iocList := []detaineeView{}

	for _, d := range detainees {
		dv := detaineeView{
			BsiID:              d.BsiID,
			ShaHash:            d.ShaHash,
			Title:              d.Title,
			ThreatLevel:        d.ThreatLevel,
			Status:             d.Status,
			CapturedBy:         d.CapturedBy,
			FileReferences:     d.FileReferences,
			InterrogationNotes: d.InterrogationNotes,
			WitnessStatement:   d.WitnessStatement,
			DamageAssessment:   d.DamageAssessment,
			RecommendedRemedy:  d.RecommendedRemedy,
		}
		switch d.ThreatLevel {
		case "APT":
			aptList = append(aptList, dv)
		case "ZERO-DAY":
			zerodayList = append(zerodayList, dv)
		case "EXPLOIT":
			exploitList = append(exploitList, dv)
		case "CVE":
			cveList = append(cveList, dv)
		case "IOC":
			iocList = append(iocList, dv)
		}
	}

	countMap := map[string]int64{}
	for _, tc := range counts {
		countMap[tc.ThreatLevel] = tc.Count
	}

	renditions := []renditionView{}
	for _, r := range renditionsRaw {
		rv := renditionView{
			BsiID:       r.BsiID,
			ShaHash:     r.ShaHash,
			Title:       r.Title,
			ThreatLevel: r.ThreatLevel,
			CommitHash:  r.CommitHash,
			RenderedBy:  r.RenderedBy,
			Method:      r.Method,
			Notes:       r.Notes,
		}
		if r.RenderedAt.Valid {
			rv.RenderedAt = r.RenderedAt.Time.Format("2006-01-02")
		}
		renditions = append(renditions, rv)
	}

	data := gin.H{
		"AppVersion":      h.Config.AppVersion,
		"MaintenanceNote": h.Config.MaintenanceNote,
		"BetaPages":       h.Config.BetaPages,
		"CspNonce":        nonce,
		"ActivePage":      "black-site",
		"APTDetainees":    aptList,
		"ZeroDayDetainees": zerodayList,
		"ExploitDetainees": exploitList,
		"CVEDetainees":     cveList,
		"IOCDetainees":     iocList,
		"APTCount":         countMap["APT"],
		"ZeroDayCount":     countMap["ZERO-DAY"],
		"ExploitCount":     countMap["EXPLOIT"],
		"CVECount":         countMap["CVE"],
		"IOCCount":         countMap["IOC"],
		"TotalCount":       totalRow,
		"Renditions":       renditions,
		"HasRenditions":    len(renditions) > 0,
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, "black_site.html", data)
}
