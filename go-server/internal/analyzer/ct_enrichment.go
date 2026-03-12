// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "context"
        "encoding/json"
        "log/slog"
        "time"

        "dnstool/go-server/internal/dbq"
)

const (
        stEnrichmentDelay    = 60 * time.Second
        stEnrichmentInterval = 24 * time.Hour
        stTopDomainLimit     = 50
)

type STBudgetDB interface {
        GetSTBudget(ctx context.Context, monthKey string) (dbq.GetSTBudgetRow, error)
        UpsertSTBudget(ctx context.Context, arg dbq.UpsertSTBudgetParams) error
        GetTopAnalyzedDomains(ctx context.Context, limit int32) ([]dbq.GetTopAnalyzedDomainsRow, error)
        ListPriorityDomains(ctx context.Context) ([]dbq.ListPriorityDomainsRow, error)
}

type CTEnrichmentJob struct {
        budgetDB STBudgetDB
        ctStore  CTStore
}

func NewCTEnrichmentJob(budgetDB STBudgetDB, ctStore CTStore) *CTEnrichmentJob {
        return &CTEnrichmentJob{
                budgetDB: budgetDB,
                ctStore:  ctStore,
        }
}

func (j *CTEnrichmentJob) Start(ctx context.Context) {
        initSecurityTrails()
        if !securityTrailsEnabled {
                slog.Info("CT enrichment: SecurityTrails not configured, skipping background enrichment")
                return
        }

        go func() {
                select {
                case <-time.After(stEnrichmentDelay):
                case <-ctx.Done():
                        return
                }

                j.run(ctx)

                ticker := time.NewTicker(stEnrichmentInterval)
                defer ticker.Stop()
                for {
                        select {
                        case <-ticker.C:
                                j.run(ctx)
                        case <-ctx.Done():
                                return
                        }
                }
        }()

        slog.Info("CT enrichment: scheduled", "initial_delay", stEnrichmentDelay, "interval", stEnrichmentInterval)
}

func (j *CTEnrichmentJob) run(ctx context.Context) {
        monthKey := time.Now().Format("2006-01")

        budget, err := j.budgetDB.GetSTBudget(ctx, monthKey)
        if err != nil {
                budget = dbq.GetSTBudgetRow{
                        MonthKey:  monthKey,
                        CallsUsed: 0,
                }
        }

        remaining := int(stMonthlyBudget) - int(budget.CallsUsed) - stBudgetReserve
        if remaining <= 0 {
                slog.Info("CT enrichment: monthly SecurityTrails budget exhausted",
                        "month", monthKey,
                        "used", budget.CallsUsed,
                        "limit", stMonthlyBudget,
                )
                return
        }

        enrichmentTargets := j.buildEnrichmentList(ctx)

        var enrichedDomains []string
        if len(budget.DomainsEnriched) > 0 {
                _ = json.Unmarshal(budget.DomainsEnriched, &enrichedDomains)
        }
        enrichedSet := make(map[string]bool, len(enrichedDomains))
        for _, d := range enrichedDomains {
                enrichedSet[d] = true
        }

        enriched := 0
        for _, td := range enrichmentTargets {
                if remaining <= 0 {
                        break
                }
                if enrichedSet[td.Domain] {
                        continue
                }

                budget.CallsUsed++
                remaining--

                domainsJSON, _ := json.Marshal(append(enrichedDomains, td.Domain))
                if err := j.budgetDB.UpsertSTBudget(ctx, dbq.UpsertSTBudgetParams{
                        MonthKey:        monthKey,
                        CallsUsed:       budget.CallsUsed,
                        DomainsEnriched: domainsJSON,
                }); err != nil {
                        slog.Warn("CT enrichment: failed to persist budget before API call, aborting", mapKeyError, err)
                        break
                }

                subs, status, fetchErr := FetchSubdomains(ctx, td.Domain)
                if fetchErr != nil || (status != nil && (status.RateLimited || status.Errored)) {
                        slog.Warn("CT enrichment: SecurityTrails fetch failed",
                                mapKeyDomain, td.Domain,
                                "rate_limited", status != nil && status.RateLimited,
                        )
                        enrichedDomains = append(enrichedDomains, td.Domain)
                        enrichedSet[td.Domain] = true
                        if status != nil && status.RateLimited {
                                break
                        }
                        continue
                }

                if len(subs) > 0 {
                        j.mergeST(ctx, td.Domain, subs)
                }

                enrichedDomains = append(enrichedDomains, td.Domain)
                enrichedSet[td.Domain] = true
                enriched++
        }

        slog.Info("CT enrichment: cycle complete",
                "month", monthKey,
                "enriched_this_run", enriched,
                "total_used", budget.CallsUsed,
                "remaining", remaining,
        )
}

type enrichmentTarget struct {
        Domain   string
        Priority bool
}

func (j *CTEnrichmentJob) buildEnrichmentList(ctx context.Context) []enrichmentTarget {
        var targets []enrichmentTarget
        seen := make(map[string]bool)

        priorityDomains, err := j.budgetDB.ListPriorityDomains(ctx)
        if err != nil {
                slog.Warn("CT enrichment: failed to load priority domains", mapKeyError, err)
        } else {
                for _, pd := range priorityDomains {
                        targets = append(targets, enrichmentTarget{Domain: pd.Domain, Priority: true})
                        seen[pd.Domain] = true
                }
                slog.Info("CT enrichment: priority domains loaded", mapKeyCount, len(priorityDomains))
        }

        remaining := stTopDomainLimit - len(targets)
        if remaining > 0 {
                topDomains, err := j.budgetDB.GetTopAnalyzedDomains(ctx, int32(stTopDomainLimit))
                if err != nil {
                        slog.Warn("CT enrichment: failed to get top analyzed domains", mapKeyError, err)
                } else {
                        for _, td := range topDomains {
                                if seen[td.Domain] {
                                        continue
                                }
                                targets = append(targets, enrichmentTarget{Domain: td.Domain, Priority: false})
                                seen[td.Domain] = true
                                remaining--
                                if remaining <= 0 {
                                        break
                                }
                        }
                }
        }

        return targets
}

func (j *CTEnrichmentJob) mergeST(ctx context.Context, domain string, stSubdomains []string) {
        existing, ok := j.ctStore.Get(ctx, domain)
        if !ok {
                existing = []map[string]any{}
        }

        existingNames := make(map[string]bool, len(existing))
        for _, sd := range existing {
                if name, ok := sd[mapKeyName].(string); ok {
                        existingNames[name] = true
                }
        }

        added := 0
        for _, fqdn := range stSubdomains {
                if existingNames[fqdn] {
                        continue
                }
                existing = append(existing, map[string]any{
                        mapKeyName:      fqdn,
                        mapKeyIsCurrent: false,
                        mapKeySource:    "securitytrails",
                        mapKeyFirstSeen: time.Now().Format("2006-01-02"),
                })
                added++
        }

        if added > 0 {
                j.ctStore.Set(ctx, domain, existing, "crt.sh+securitytrails")
                slog.Info("CT enrichment: SecurityTrails subdomains merged",
                        mapKeyDomain, domain,
                        "new_subdomains", added,
                        "total", len(existing),
                )
        }
}
