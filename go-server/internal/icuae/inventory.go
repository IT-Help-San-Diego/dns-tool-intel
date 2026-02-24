// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package icuae

type TestCategory struct {
        Name     string
        Standard string
        Cases    int
        Icon     string
}

type TestInventory struct {
        TotalCases      int
        TotalDimensions int
        Categories      []TestCategory
}

func GetTestInventory() *TestInventory {
        categories := []TestCategory{
                {Name: "Score-to-Grade Boundaries", Standard: "All Standards", Cases: 1, Icon: "fas fa-ruler-combined"},
                {Name: "Currentness", Standard: "ISO/IEC 25012", Cases: 6, Icon: "fas fa-clock"},
                {Name: "TTL Compliance", Standard: "RFC 8767", Cases: 5, Icon: "fas fa-check-circle"},
                {Name: "Completeness", Standard: StandardNIST80053SI18, Cases: 4, Icon: "fas fa-th"},
                {Name: "Source Credibility", Standard: "ISO/IEC 25012 + SPJ", Cases: 3, Icon: "fas fa-users"},
                {Name: "TTL Relevance", Standard: StandardNIST80053SI18, Cases: 6, Icon: "fas fa-balance-scale"},
                {Name: "Integration & Constants", Standard: "All Standards", Cases: 4, Icon: "fas fa-cogs"},
        }

        total := 0
        for _, c := range categories {
                total += c.Cases
        }

        return &TestInventory{
                TotalCases:      total,
                TotalDimensions: 5,
                Categories:      categories,
        }
}
