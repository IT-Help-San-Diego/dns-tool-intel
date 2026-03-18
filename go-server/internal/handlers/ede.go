// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "encoding/json"
        "log/slog"
        "net/http"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
)

type EDEHandler struct {
        DB     *db.Database
        Config *config.Config
}

func NewEDEHandler(database *db.Database, cfg *config.Config) *EDEHandler {
        return &EDEHandler{DB: database, Config: cfg}
}

func (h *EDEHandler) EDE(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")
        ctx := c.Request.Context()

        var integrityData IntegrityData

        var dbAvailable bool
        var dbEvents []dbq.EdeEvent
        if h.DB != nil && h.DB.Queries != nil {
                var err error
                dbEvents, err = h.DB.Queries.ListEDEEvents(ctx)
                if err != nil {
                        slog.Warn("EDE: DB query failed, falling back to JSON", "error", err)
                } else if len(dbEvents) > 0 {
                        dbAvailable = true
                }
        }

        if !dbAvailable {
                integrityData = loadIntegrityData()
        } else {
                counts, cErr := h.DB.Queries.CountEDEEvents(ctx)
                if cErr != nil {
                        slog.Warn("EDE: CountEDEEvents failed", "error", cErr)
                }
                amendments, aErr := h.DB.Queries.ListEDEAmendments(ctx)
                if aErr != nil {
                        slog.Warn("EDE: ListEDEAmendments failed", "error", aErr)
                }

                amendmentMap := map[string][]EDEAmendment{}
                for _, a := range amendments {
                        am := EDEAmendment{
                                Ground:        a.Ground,
                                FieldChanged:  a.FieldChanged,
                                OriginalValue: a.OriginalValue,
                                CorrectedTo:   a.CorrectedTo,
                                Justification: a.Justification,
                        }
                        if a.Evidence != nil {
                                am.Evidence = *a.Evidence
                        }
                        if a.Rationale != nil && *a.Rationale != "" {
                                am.Evidence = *a.Rationale
                        }
                        if a.AmendmentDate.Valid {
                                am.Date = a.AmendmentDate.Time.Format("2006-01-02")
                        }
                        amendmentMap[a.EdeID] = append(amendmentMap[a.EdeID], am)
                }

                events := make([]IntegrityEvent, 0, len(dbEvents))
                protocolSet := map[string]bool{}
                for _, e := range dbEvents {
                        ev := IntegrityEvent{
                                ID:          e.EdeID,
                                Category:    e.Category,
                                Severity:    e.Severity,
                                Title:       e.Title,
                                Status:      e.Status,
                                Attribution: e.Attribution,
                                Commit:      e.CommitRef,
                        }
                        if e.EventDate.Valid {
                                ev.Date = e.EventDate.Time.Format("2006-01-02")
                        }
                        if e.ConfidenceImpact != nil {
                                ev.ConfidenceImpact = *e.ConfidenceImpact
                        }
                        if e.Resolution != nil {
                                ev.Resolution = *e.Resolution
                        }
                        if e.BayesianNote != nil {
                                ev.BayesianNote = *e.BayesianNote
                        }
                        if e.CorrectionAction != nil {
                                ev.CorrectionAction = *e.CorrectionAction
                        }
                        if e.PreventionRule != nil {
                                ev.PreventionRule = *e.PreventionRule
                        }
                        if e.AuthoritativeSource != nil {
                                ev.AuthoritativeSource = *e.AuthoritativeSource
                        }

                        var protocols []string
                        if len(e.ProtocolsAffected) > 0 {
                                if pErr := json.Unmarshal(e.ProtocolsAffected, &protocols); pErr != nil {
                                        slog.Warn("EDE: failed to unmarshal protocols_affected", "ede_id", e.EdeID, "error", pErr)
                                }
                        }
                        ev.ProtocolsAffected = protocols
                        for _, p := range protocols {
                                protocolSet[p] = true
                        }

                        if ams, ok := amendmentMap[e.EdeID]; ok {
                                ev.Amendments = ams
                        }
                        redactDignityAmendments(&ev)
                        hashEvent(&ev)
                        events = append(events, ev)
                }

                allProtocols := make([]string, 0, len(protocolSet))
                for p := range protocolSet {
                        allProtocols = append(allProtocols, p)
                }

                lastDate := ""
                if len(events) > 0 {
                        lastDate = events[0].Date
                }

                integrityData = IntegrityData{
                        Summary: IntegritySummary{
                                TotalEvents:              int(counts.Total),
                                Open:                     int(counts.Open),
                                Closed:                   int(counts.Closed),
                                ConfidenceRecalibrations: int(counts.Recalibrations),
                                LastEventDate:            lastDate,
                                ProtocolsAffected:        allProtocols,
                        },
                        Events: events,
                        Taxonomy: map[string]string{
                                "scoring_calibration":      "Scoring Calibration",
                                "evidence_reinterpretation": "Evidence Reinterpretation",
                                "drift_detection":          "Drift Detection",
                                "resolver_trust":           "Resolver Trust",
                                "false_positive":           "False Positive",
                                "confidence_decay":         "Confidence Decay",
                                "governance_correction":    "Governance Correction",
                                "citation_error":           "Citation Error",
                                "overclaim":               "Overclaim",
                                "standards_misattribution": "Standards Misattribution",
                        },
                        TamperResistancePolicy: TamperResistancePolicy{
                                Enabled:       true,
                                Effective:     "2026-03-07",
                                Standard:      "SHA-3-512 per-event hashing",
                                AmendmentRule: "FACTUAL_ERROR or DIGNITY_OF_EXPRESSION only",
                        },
                }

                fileData := loadIntegrityData()
                integrityData.SHA3Hash = fileData.SHA3Hash
        }

        data := gin.H{
                "AppVersion":      h.Config.AppVersion,
                "MaintenanceNote": h.Config.MaintenanceNote,
                "BetaPages":       h.Config.BetaPages,
                "CspNonce":        nonce,
                "ActivePage":      "ede",
                "IntegrityData":   integrityData,
        }
        mergeAuthData(c, h.Config, data)
        c.HTML(http.StatusOK, "ede.html", data)
}
