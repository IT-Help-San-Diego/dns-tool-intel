//go:build dbtest

package agentpkg

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"dnstool/go-server/internal/dbq"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestAgentCacheLookup_HitPublic(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/agent/search?q=example.com", nil)

        success := true
        mock := &mockLookupStore{
                GetRecentAnalysisByDomainFn: func(_ context.Context, domain string) (dbq.DomainAnalysis, error) {
                        return dbq.DomainAnalysis{
                                ID:              42,
                                Domain:          domain,
                                FullResults:     json.RawMessage(`{"domain":"example.com","analysis_success":true}`),
                                AnalysisSuccess: &success,
                                CreatedAt:       pgtype.Timestamp{Time: time.Now().Add(-10 * time.Minute), Valid: true},
                        }, nil
                },
        }
        h := NewAgentHandlerWithStore(mock)
        results, id := h.agentCacheLookup(c, "example.com")
        if results == nil {
                t.Fatal("expected cache hit")
        }
        if id != 42 {
                t.Errorf("expected id=42, got %d", id)
        }
}

func TestAgentCacheLookup_SkipPrivate(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/agent/search?q=secret.com", nil)

        success := true
        mock := &mockLookupStore{
                GetRecentAnalysisByDomainFn: func(_ context.Context, domain string) (dbq.DomainAnalysis, error) {
                        return dbq.DomainAnalysis{
                                ID:              99,
                                Domain:          domain,
                                Private:         true,
                                FullResults:     json.RawMessage(`{"domain":"secret.com"}`),
                                AnalysisSuccess: &success,
                                CreatedAt:       pgtype.Timestamp{Time: time.Now().Add(-5 * time.Minute), Valid: true},
                        }, nil
                },
        }
        h := NewAgentHandlerWithStore(mock)
        results, _ := h.agentCacheLookup(c, "secret.com")
        if results != nil {
                t.Error("expected nil for private analysis")
        }
}

func TestAgentCacheLookup_SkipScanFlag(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/agent/search?q=flagged.com", nil)

        success := true
        mock := &mockLookupStore{
                GetRecentAnalysisByDomainFn: func(_ context.Context, domain string) (dbq.DomainAnalysis, error) {
                        return dbq.DomainAnalysis{
                                ID:              100,
                                Domain:          domain,
                                ScanFlag:        true,
                                FullResults:     json.RawMessage(`{"domain":"flagged.com"}`),
                                AnalysisSuccess: &success,
                                CreatedAt:       pgtype.Timestamp{Time: time.Now().Add(-5 * time.Minute), Valid: true},
                        }, nil
                },
        }
        h := NewAgentHandlerWithStore(mock)
        results, _ := h.agentCacheLookup(c, "flagged.com")
        if results != nil {
                t.Error("expected nil for scan-flagged analysis")
        }
}

func TestAgentCacheLookup_SkipExpired(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/agent/search?q=old.com", nil)

        success := true
        mock := &mockLookupStore{
                GetRecentAnalysisByDomainFn: func(_ context.Context, domain string) (dbq.DomainAnalysis, error) {
                        return dbq.DomainAnalysis{
                                ID:              101,
                                Domain:          domain,
                                FullResults:     json.RawMessage(`{"domain":"old.com"}`),
                                AnalysisSuccess: &success,
                                CreatedAt:       pgtype.Timestamp{Time: time.Now().Add(-2 * time.Hour), Valid: true},
                        }, nil
                },
        }
        h := NewAgentHandlerWithStore(mock)
        results, _ := h.agentCacheLookup(c, "old.com")
        if results != nil {
                t.Error("expected nil for expired analysis")
        }
}

func TestAgentCacheLookup_SkipNilSuccess(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/agent/search?q=incomplete.com", nil)

        mock := &mockLookupStore{
                GetRecentAnalysisByDomainFn: func(_ context.Context, domain string) (dbq.DomainAnalysis, error) {
                        return dbq.DomainAnalysis{
                                ID:              102,
                                Domain:          domain,
                                FullResults:     json.RawMessage(`{"domain":"incomplete.com"}`),
                                AnalysisSuccess: nil,
                                CreatedAt:       pgtype.Timestamp{Time: time.Now().Add(-5 * time.Minute), Valid: true},
                        }, nil
                },
        }
        h := NewAgentHandlerWithStore(mock)
        results, _ := h.agentCacheLookup(c, "incomplete.com")
        if results != nil {
                t.Error("expected nil for nil AnalysisSuccess (legacy/incomplete row)")
        }
}
