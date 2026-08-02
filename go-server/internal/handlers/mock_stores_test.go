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
        GetTelemetryByAnalysisFn           func(ctx context.Context, analysisID int32) ([]dbq.ScanPhaseTelemetry, error)
        GetTelemetryHashFn                 func(ctx context.Context, analysisID int32) (dbq.ScanTelemetryHash, error)
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

func (m *mockAnalysisStore) GetTelemetryByAnalysis(ctx context.Context, analysisID int32) ([]dbq.ScanPhaseTelemetry, error) {
        if m.GetTelemetryByAnalysisFn != nil {
                return m.GetTelemetryByAnalysisFn(ctx, analysisID)
        }
        return nil, nil
}

func (m *mockAnalysisStore) GetTelemetryHash(ctx context.Context, analysisID int32) (dbq.ScanTelemetryHash, error) {
        if m.GetTelemetryHashFn != nil {
                return m.GetTelemetryHashFn(ctx, analysisID)
        }
        return dbq.ScanTelemetryHash{}, errors.New("no telemetry hash recorded")
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

// Badge-only public lookups (badgepkg.LookupStore). The public-row exclusion
// lives in the real SQL (private=FALSE AND scan_flag=FALSE AND
// analysis_success=TRUE AND full_results IS NOT NULL); the mock reproduces that
// same predicate so badge tests exercise the actual contract — a private,
// flagged, failed, or empty row resolves as "not found", never as a badge.
func (m *mockLookupStore) GetPublicAnalysisByID(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
        a, err := m.GetAnalysisByID(ctx, id)
        if err != nil {
                return dbq.DomainAnalysis{}, err
        }
        if a.Private || a.ScanFlag || a.AnalysisSuccess == nil || !*a.AnalysisSuccess || len(a.FullResults) == 0 {
                return dbq.DomainAnalysis{}, errors.New("not found")
        }
        return a, nil
}

func (m *mockLookupStore) GetRecentPublicAnalysisByDomain(ctx context.Context, domain string) (dbq.DomainAnalysis, error) {
        a, err := m.GetRecentAnalysisByDomain(ctx, domain)
        if err != nil {
                return dbq.DomainAnalysis{}, err
        }
        if a.Private || a.ScanFlag || a.AnalysisSuccess == nil || !*a.AnalysisSuccess || len(a.FullResults) == 0 {
                return dbq.DomainAnalysis{}, errors.New("not found")
        }
        return a, nil
}

type mockAuthStore struct {
        upsertUserFn                      func(ctx context.Context, arg dbq.UpsertUserParams) (dbq.User, error)
        promoteUserToAdminFn              func(ctx context.Context, id int32) error
        countAdminUsersFn                 func(ctx context.Context) (int64, error)
        createSessionFn                   func(ctx context.Context, arg dbq.CreateSessionParams) error
        deleteSessionFn                   func(ctx context.Context, id string) error
        listWatchlistByUserFn             func(ctx context.Context, userID int32) ([]dbq.DomainWatchlist, error)
        insertWatchlistEntryFn            func(ctx context.Context, arg dbq.InsertWatchlistEntryParams) (dbq.InsertWatchlistEntryRow, error)
        listNotificationEndpointsByUserFn func(ctx context.Context, userID int32) ([]dbq.NotificationEndpoint, error)
        insertNotificationEndpointFn      func(ctx context.Context, arg dbq.InsertNotificationEndpointParams) (dbq.InsertNotificationEndpointRow, error)
}

func (m *mockAuthStore) UpsertUser(ctx context.Context, arg dbq.UpsertUserParams) (dbq.User, error) {
        if m.upsertUserFn != nil {
                return m.upsertUserFn(ctx, arg)
        }
        return dbq.User{}, nil
}

func (m *mockAuthStore) PromoteUserToAdmin(ctx context.Context, id int32) error {
        if m.promoteUserToAdminFn != nil {
                return m.promoteUserToAdminFn(ctx, id)
        }
        return nil
}

func (m *mockAuthStore) CountAdminUsers(ctx context.Context) (int64, error) {
        if m.countAdminUsersFn != nil {
                return m.countAdminUsersFn(ctx)
        }
        return 0, nil
}

func (m *mockAuthStore) CreateSession(ctx context.Context, arg dbq.CreateSessionParams) error {
        if m.createSessionFn != nil {
                return m.createSessionFn(ctx, arg)
        }
        return nil
}

func (m *mockAuthStore) DeleteSession(ctx context.Context, id string) error {
        if m.deleteSessionFn != nil {
                return m.deleteSessionFn(ctx, id)
        }
        return nil
}

func (m *mockAuthStore) ListWatchlistByUser(ctx context.Context, userID int32) ([]dbq.DomainWatchlist, error) {
        if m.listWatchlistByUserFn != nil {
                return m.listWatchlistByUserFn(ctx, userID)
        }
        return nil, nil
}

func (m *mockAuthStore) InsertWatchlistEntry(ctx context.Context, arg dbq.InsertWatchlistEntryParams) (dbq.InsertWatchlistEntryRow, error) {
        if m.insertWatchlistEntryFn != nil {
                return m.insertWatchlistEntryFn(ctx, arg)
        }
        return dbq.InsertWatchlistEntryRow{}, nil
}

func (m *mockAuthStore) ListNotificationEndpointsByUser(ctx context.Context, userID int32) ([]dbq.NotificationEndpoint, error) {
        if m.listNotificationEndpointsByUserFn != nil {
                return m.listNotificationEndpointsByUserFn(ctx, userID)
        }
        return nil, nil
}

func (m *mockAuthStore) InsertNotificationEndpoint(ctx context.Context, arg dbq.InsertNotificationEndpointParams) (dbq.InsertNotificationEndpointRow, error) {
        if m.insertNotificationEndpointFn != nil {
                return m.insertNotificationEndpointFn(ctx, arg)
        }
        return dbq.InsertNotificationEndpointRow{}, nil
}
