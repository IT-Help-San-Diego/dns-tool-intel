package handlers

import (
        "context"
        "errors"

        "dnstool/go-server/internal/dbq"

        "github.com/jackc/pgx/v5/pgconn"
)

type mockAnalysisStore struct {
        InsertAnalysisFn                   func(ctx context.Context, arg dbq.InsertAnalysisParams) (dbq.InsertAnalysisRow, error)
        UpsertDomainIndexFn                func(ctx context.Context, arg dbq.UpsertDomainIndexParams) error
        GetPreviousAnalysisForDriftFn      func(ctx context.Context, domain string) (dbq.GetPreviousAnalysisForDriftRow, error)
        GetPreviousAnalysisForDriftBeforeFn func(ctx context.Context, arg dbq.GetPreviousAnalysisForDriftBeforeParams) (dbq.GetPreviousAnalysisForDriftBeforeRow, error)
        InsertDriftEventFn                 func(ctx context.Context, arg dbq.InsertDriftEventParams) (dbq.InsertDriftEventRow, error)
        ListEndpointsForWatchedDomainFn    func(ctx context.Context, domain string) ([]dbq.ListEndpointsForWatchedDomainRow, error)
        InsertDriftNotificationFn          func(ctx context.Context, arg dbq.InsertDriftNotificationParams) (int32, error)
        InsertPhaseTelemetryFn             func(ctx context.Context, arg dbq.InsertPhaseTelemetryParams) error
        InsertTelemetryHashFn              func(ctx context.Context, arg dbq.InsertTelemetryHashParams) error
        InsertUserAnalysisFn               func(ctx context.Context, arg dbq.InsertUserAnalysisParams) error
        UpdateWaybackURLFn                 func(ctx context.Context, arg dbq.UpdateWaybackURLParams) error
        CountHashedAnalysesFn              func(ctx context.Context) (int64, error)
        ListHashedAnalysesFn               func(ctx context.Context, arg dbq.ListHashedAnalysesParams) ([]dbq.ListHashedAnalysesRow, error)
        GetAnalysisByIDFn                  func(ctx context.Context, id int32) (dbq.DomainAnalysis, error)
        CheckAnalysisOwnershipFn           func(ctx context.Context, arg dbq.CheckAnalysisOwnershipParams) (bool, error)
        GetRecentAnalysisByDomainFn        func(ctx context.Context, domain string) (dbq.DomainAnalysis, error)
}

func (m *mockAnalysisStore) InsertAnalysis(ctx context.Context, arg dbq.InsertAnalysisParams) (dbq.InsertAnalysisRow, error) {
        if m.InsertAnalysisFn != nil {
                return m.InsertAnalysisFn(ctx, arg)
        }
        return dbq.InsertAnalysisRow{}, nil
}

func (m *mockAnalysisStore) UpsertDomainIndex(ctx context.Context, arg dbq.UpsertDomainIndexParams) error {
        if m.UpsertDomainIndexFn != nil {
                return m.UpsertDomainIndexFn(ctx, arg)
        }
        return nil
}

func (m *mockAnalysisStore) GetPreviousAnalysisForDrift(ctx context.Context, domain string) (dbq.GetPreviousAnalysisForDriftRow, error) {
        if m.GetPreviousAnalysisForDriftFn != nil {
                return m.GetPreviousAnalysisForDriftFn(ctx, domain)
        }
        return dbq.GetPreviousAnalysisForDriftRow{}, nil
}

func (m *mockAnalysisStore) GetPreviousAnalysisForDriftBefore(ctx context.Context, arg dbq.GetPreviousAnalysisForDriftBeforeParams) (dbq.GetPreviousAnalysisForDriftBeforeRow, error) {
        if m.GetPreviousAnalysisForDriftBeforeFn != nil {
                return m.GetPreviousAnalysisForDriftBeforeFn(ctx, arg)
        }
        return dbq.GetPreviousAnalysisForDriftBeforeRow{}, nil
}

func (m *mockAnalysisStore) InsertDriftEvent(ctx context.Context, arg dbq.InsertDriftEventParams) (dbq.InsertDriftEventRow, error) {
        if m.InsertDriftEventFn != nil {
                return m.InsertDriftEventFn(ctx, arg)
        }
        return dbq.InsertDriftEventRow{}, nil
}

func (m *mockAnalysisStore) ListEndpointsForWatchedDomain(ctx context.Context, domain string) ([]dbq.ListEndpointsForWatchedDomainRow, error) {
        if m.ListEndpointsForWatchedDomainFn != nil {
                return m.ListEndpointsForWatchedDomainFn(ctx, domain)
        }
        return nil, nil
}

func (m *mockAnalysisStore) InsertDriftNotification(ctx context.Context, arg dbq.InsertDriftNotificationParams) (int32, error) {
        if m.InsertDriftNotificationFn != nil {
                return m.InsertDriftNotificationFn(ctx, arg)
        }
        return 0, nil
}

func (m *mockAnalysisStore) InsertPhaseTelemetry(ctx context.Context, arg dbq.InsertPhaseTelemetryParams) error {
        if m.InsertPhaseTelemetryFn != nil {
                return m.InsertPhaseTelemetryFn(ctx, arg)
        }
        return nil
}

func (m *mockAnalysisStore) InsertTelemetryHash(ctx context.Context, arg dbq.InsertTelemetryHashParams) error {
        if m.InsertTelemetryHashFn != nil {
                return m.InsertTelemetryHashFn(ctx, arg)
        }
        return nil
}

func (m *mockAnalysisStore) InsertUserAnalysis(ctx context.Context, arg dbq.InsertUserAnalysisParams) error {
        if m.InsertUserAnalysisFn != nil {
                return m.InsertUserAnalysisFn(ctx, arg)
        }
        return nil
}

func (m *mockAnalysisStore) UpdateWaybackURL(ctx context.Context, arg dbq.UpdateWaybackURLParams) error {
        if m.UpdateWaybackURLFn != nil {
                return m.UpdateWaybackURLFn(ctx, arg)
        }
        return nil
}

func (m *mockAnalysisStore) CountHashedAnalyses(ctx context.Context) (int64, error) {
        if m.CountHashedAnalysesFn != nil {
                return m.CountHashedAnalysesFn(ctx)
        }
        return 0, nil
}

func (m *mockAnalysisStore) ListHashedAnalyses(ctx context.Context, arg dbq.ListHashedAnalysesParams) ([]dbq.ListHashedAnalysesRow, error) {
        if m.ListHashedAnalysesFn != nil {
                return m.ListHashedAnalysesFn(ctx, arg)
        }
        return nil, nil
}

func (m *mockAnalysisStore) GetAnalysisByID(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
        if m.GetAnalysisByIDFn != nil {
                return m.GetAnalysisByIDFn(ctx, id)
        }
        return dbq.DomainAnalysis{}, nil
}

func (m *mockAnalysisStore) CheckAnalysisOwnership(ctx context.Context, arg dbq.CheckAnalysisOwnershipParams) (bool, error) {
        if m.CheckAnalysisOwnershipFn != nil {
                return m.CheckAnalysisOwnershipFn(ctx, arg)
        }
        return false, nil
}

func (m *mockAnalysisStore) GetRecentAnalysisByDomain(ctx context.Context, domain string) (dbq.DomainAnalysis, error) {
        if m.GetRecentAnalysisByDomainFn != nil {
                return m.GetRecentAnalysisByDomainFn(ctx, domain)
        }
        return dbq.DomainAnalysis{}, nil
}

type mockStatsExecer struct {
        ExecFn func(ctx context.Context, sql string, arguments ...interface{}) (pgconn.CommandTag, error)
}

func (m *mockStatsExecer) Exec(ctx context.Context, sql string, arguments ...interface{}) (pgconn.CommandTag, error) {
        if m.ExecFn != nil {
                return m.ExecFn(ctx, sql, arguments...)
        }
        return pgconn.NewCommandTag(""), nil
}

type mockAuditStore struct {
        countHashedAnalysesFn func(ctx context.Context) (int64, error)
        listHashedAnalysesFn  func(ctx context.Context, arg dbq.ListHashedAnalysesParams) ([]dbq.ListHashedAnalysesRow, error)
}

func (m *mockAuditStore) CountHashedAnalyses(ctx context.Context) (int64, error) {
        if m.countHashedAnalysesFn != nil {
                return m.countHashedAnalysesFn(ctx)
        }
        return 0, nil
}

func (m *mockAuditStore) ListHashedAnalyses(ctx context.Context, arg dbq.ListHashedAnalysesParams) ([]dbq.ListHashedAnalysesRow, error) {
        if m.listHashedAnalysesFn != nil {
                return m.listHashedAnalysesFn(ctx, arg)
        }
        return nil, nil
}

type mockLookupStore struct {
        GetAnalysisByIDFn          func(ctx context.Context, id int32) (dbq.DomainAnalysis, error)
        CheckAnalysisOwnershipFn   func(ctx context.Context, arg dbq.CheckAnalysisOwnershipParams) (bool, error)
        GetRecentAnalysisByDomainFn func(ctx context.Context, domain string) (dbq.DomainAnalysis, error)
}

func (m *mockLookupStore) GetAnalysisByID(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
        if m.GetAnalysisByIDFn != nil {
                return m.GetAnalysisByIDFn(ctx, id)
        }
        return dbq.DomainAnalysis{}, errors.New("not found")
}

func (m *mockLookupStore) CheckAnalysisOwnership(ctx context.Context, arg dbq.CheckAnalysisOwnershipParams) (bool, error) {
        if m.CheckAnalysisOwnershipFn != nil {
                return m.CheckAnalysisOwnershipFn(ctx, arg)
        }
        return false, nil
}

func (m *mockLookupStore) GetRecentAnalysisByDomain(ctx context.Context, domain string) (dbq.DomainAnalysis, error) {
        if m.GetRecentAnalysisByDomainFn != nil {
                return m.GetRecentAnalysisByDomainFn(ctx, domain)
        }
        return dbq.DomainAnalysis{}, errors.New("not found")
}
