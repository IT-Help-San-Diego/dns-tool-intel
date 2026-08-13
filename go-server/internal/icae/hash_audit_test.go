package icae

import (
        "encoding/json"
        "testing"

        "dnstool/go-server/internal/analyzer"
        "dnstool/go-server/internal/dbq"

        "github.com/jackc/pgx/v5/pgtype"
)

func TestAuditHashIntegrity_NilQueries(t *testing.T) {
        result := AuditHashIntegrity(nil, nil, 100)
        if result != nil {
                t.Error("expected nil for nil queries")
        }
}

func TestHashAuditResult_Struct(t *testing.T) {
        result := &HashAuditResult{
                TotalAudited:    10,
                TotalVerified:   8,
                TotalFailed:     1,
                TotalMissing:    1,
                TotalHashedInDB: 10,
                IntegrityPct:    80,
        }
        if result.IntegrityPct != 80 {
                t.Errorf("IntegrityPct = %d", result.IntegrityPct)
        }
}

func TestAuditSingleRow_NilHash(t *testing.T) {
        row := dbq.GetRecentHashedAnalysesRow{
                PostureHash: nil,
        }
        result := &HashAuditResult{}
        auditSingleRow(row, result)
        if result.TotalMissing != 1 {
                t.Errorf("TotalMissing = %d, want 1", result.TotalMissing)
        }
}

func TestAuditSingleRow_EmptyHash(t *testing.T) {
        empty := ""
        row := dbq.GetRecentHashedAnalysesRow{
                PostureHash: &empty,
        }
        result := &HashAuditResult{}
        auditSingleRow(row, result)
        if result.TotalMissing != 1 {
                t.Errorf("TotalMissing = %d, want 1", result.TotalMissing)
        }
}

func TestAuditSingleRow_InvalidJSON(t *testing.T) {
        hash := "abc123"
        row := dbq.GetRecentHashedAnalysesRow{
                PostureHash: &hash,
                FullResults: []byte("{invalid json}"),
                Domain:      "test.com",
                ID:          1,
        }
        result := &HashAuditResult{}
        auditSingleRow(row, result)
        if result.TotalFailed != 1 {
                t.Errorf("TotalFailed = %d, want 1", result.TotalFailed)
        }
        if len(result.FailedDomains) != 1 || result.FailedDomains[0] != "test.com" {
                t.Errorf("FailedDomains = %v", result.FailedDomains)
        }
}

func TestAuditSingleRow_ValidResults_Mismatch(t *testing.T) {
        hash := "wronghash"
        fullResults := map[string]any{"spf_analysis": map[string]any{"status": "pass"}}
        jsonBytes, _ := json.Marshal(fullResults)
        row := dbq.GetRecentHashedAnalysesRow{
                PostureHash: &hash,
                FullResults: jsonBytes,
                Domain:      "mismatch.com",
                ID:          2,
        }
        result := &HashAuditResult{}
        auditSingleRow(row, result)
        if result.TotalFailed != 1 {
                t.Errorf("TotalFailed = %d, want 1", result.TotalFailed)
        }
}

func TestAuditSingleRow_ValidResults_Match(t *testing.T) {
        fullResults := map[string]any{"spf_analysis": map[string]any{"status": "pass"}}
        jsonBytes, _ := json.Marshal(fullResults)

        var parsed map[string]any
        json.Unmarshal(jsonBytes, &parsed)
        recomputed := analyzer.CanonicalPostureHash(parsed)

        row := dbq.GetRecentHashedAnalysesRow{
                PostureHash: &recomputed,
                FullResults: jsonBytes,
                Domain:      "match.com",
                ID:          3,
                CreatedAt:   pgtype.Timestamp{Valid: true},
        }
        result := &HashAuditResult{}
        auditSingleRow(row, result)
        if result.TotalVerified != 1 {
                t.Errorf("TotalVerified = %d, want 1", result.TotalVerified)
        }
}

func TestHashMatches_SHA256EraRow(t *testing.T) {
        results := map[string]any{"spf_analysis": map[string]any{"status": "pass"}}
        stored := analyzer.CanonicalPostureHashLegacySHA256(results)
        if len(stored) != 64 {
                t.Fatalf("sha256 hash length = %d, want 64", len(stored))
        }
        if !hashMatches(stored, results) {
                t.Error("sha256-era row must verify via the legacy formula")
        }
}

func TestHashMatches_CurrentFormula(t *testing.T) {
        results := map[string]any{"spf_analysis": map[string]any{"status": "pass"}}
        if !hashMatches(analyzer.CanonicalPostureHash(results), results) {
                t.Error("current-formula row must verify")
        }
        if hashMatches("not-a-real-hash-of-any-era-or-length-just-wrong-bytes", results) {
                t.Error("junk hash must not verify")
        }
}

func TestHashMatches_LegacySelectorPinnedRow(t *testing.T) {
        // A row hashed before extractSortedSelectors learned the map shape:
        // sha3 formula with dkim_selectors pinned to "". Its bytes never
        // changed — the audit must keep verifying it via the frozen form, or
        // the public integrity panel fails the whole pre-fix window on
        // deploy.
        fullResults := map[string]any{
                "dkim_analysis": map[string]any{
                        "status": "success",
                        "selectors": map[string]any{
                                "google._domainkey": map[string]any{
                                        "records": []any{"v=DKIM1; k=rsa; p=AAA"},
                                },
                        },
                },
        }
        jsonBytes, _ := json.Marshal(fullResults)
        var parsed map[string]any
        json.Unmarshal(jsonBytes, &parsed)

        stored := analyzer.CanonicalPostureHashLegacySelectors(parsed)
        if analyzer.CanonicalPostureHash(parsed) == stored {
                t.Fatal("test vector fails to distinguish live from legacy formula")
        }

        row := dbq.GetRecentHashedAnalysesRow{
                PostureHash: &stored,
                FullResults: jsonBytes,
                Domain:      "legacy-selectors.com",
                ID:          4,
                CreatedAt:   pgtype.Timestamp{Valid: true},
        }
        result := &HashAuditResult{}
        auditSingleRow(row, result)
        if result.TotalVerified != 1 || result.TotalFailed != 0 {
                t.Fatalf("pinned-selectors row must verify: verified=%d failed=%d",
                        result.TotalVerified, result.TotalFailed)
        }
}
