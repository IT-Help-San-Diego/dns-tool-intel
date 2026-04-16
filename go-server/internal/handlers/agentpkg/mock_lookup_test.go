//go:build dbtest

package agentpkg

import (
	"context"

	"dnstool/go-server/internal/dbq"
)

type mockLookupStore struct {
	GetRecentAnalysisByDomainFn func(ctx context.Context, domain string) (dbq.DomainAnalysis, error)
}

func (m *mockLookupStore) GetRecentAnalysisByDomain(ctx context.Context, domain string) (dbq.DomainAnalysis, error) {
	if m.GetRecentAnalysisByDomainFn != nil {
		return m.GetRecentAnalysisByDomainFn(ctx, domain)
	}
	return dbq.DomainAnalysis{}, nil
}
