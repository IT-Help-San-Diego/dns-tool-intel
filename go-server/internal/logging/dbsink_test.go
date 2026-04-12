package logging

import (
        "context"
        "strings"
        "sync"
        "sync/atomic"
        "testing"
        "time"

        "github.com/jackc/pgx/v5/pgconn"
)

type mockPool struct {
        mu       sync.Mutex
        inserts  []DBLogEntry
        execErr  error
        execFunc func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

func (m *mockPool) Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
        if m.execFunc != nil {
                return m.execFunc(ctx, sql, arguments...)
        }
        m.mu.Lock()
        defer m.mu.Unlock()
        if m.execErr != nil {
                return pgconn.CommandTag{}, m.execErr
        }
        if len(arguments) >= 4 {
                entry := DBLogEntry{
                        Level:   argStr(arguments, 1),
                        Message: argStr(arguments, 2),
                        Event:   argStr(arguments, 3),
                }
                m.inserts = append(m.inserts, entry)
        }
        return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func argStr(args []any, idx int) string {
        if idx < len(args) {
                if s, ok := args[idx].(string); ok {
                        return s
                }
        }
        return ""
}

func (m *mockPool) insertCount() int {
        m.mu.Lock()
        defer m.mu.Unlock()
        return len(m.inserts)
}

func TestDBSink_RealWorker_BatchFlush(t *testing.T) {
        pool := &mockPool{}
        sink := NewDBSinkFromPool(pool)
        defer sink.Close()

        for i := 0; i < dbBatchSize; i++ {
                sink.Write(DBLogEntry{
                        Timestamp: time.Now(),
                        Level:     "INFO",
                        Message:   "batch test",
                        Attrs:     map[string]string{},
                })
        }

        deadline := time.After(3 * time.Second)
        for {
                select {
                case <-deadline:
                        t.Fatalf("batch flush did not happen within timeout; got %d inserts, want %d", pool.insertCount(), dbBatchSize)
                default:
                        if pool.insertCount() >= dbBatchSize {
                                return
                        }
                        time.Sleep(10 * time.Millisecond)
                }
        }
}

func TestDBSink_RealWorker_TimerFlush(t *testing.T) {
        pool := &mockPool{}
        sink := NewDBSinkFromPool(pool)
        defer sink.Close()

        sink.Write(DBLogEntry{
                Timestamp: time.Now(),
                Level:     "WARN",
                Message:   "timer flush test",
                Attrs:     map[string]string{},
        })

        deadline := time.After(dbFlushInterval + 2*time.Second)
        for {
                select {
                case <-deadline:
                        t.Fatalf("timer flush did not happen; got %d inserts", pool.insertCount())
                default:
                        if pool.insertCount() >= 1 {
                                return
                        }
                        time.Sleep(100 * time.Millisecond)
                }
        }
}

func TestDBSink_RealWorker_GracefulShutdown(t *testing.T) {
        pool := &mockPool{}
        sink := NewDBSinkFromPool(pool)

        for i := 0; i < 5; i++ {
                sink.Write(DBLogEntry{
                        Timestamp: time.Now(),
                        Level:     "INFO",
                        Message:   "shutdown test",
                        Attrs:     map[string]string{},
                })
        }

        time.Sleep(50 * time.Millisecond)
        sink.Close()

        count := pool.insertCount()
        if count != 5 {
                t.Fatalf("graceful shutdown: got %d flushed entries, want 5", count)
        }
}

func TestDBSink_RealWorker_GracefulShutdown_LargerBatch(t *testing.T) {
        pool := &mockPool{}
        sink := NewDBSinkFromPool(pool)

        for i := 0; i < 30; i++ {
                sink.Write(DBLogEntry{
                        Timestamp: time.Now(),
                        Level:     "ERROR",
                        Message:   "shutdown drain test",
                        Attrs:     map[string]string{},
                })
        }

        time.Sleep(50 * time.Millisecond)
        sink.Close()

        count := pool.insertCount()
        if count != 30 {
                t.Fatalf("graceful shutdown large batch: got %d flushed entries, want 30", count)
        }
}

func TestDBSink_Write_DropsWhenClosed(t *testing.T) {
        sink := &DBSink{
                ch:   make(chan DBLogEntry, dbChanSize),
                done: make(chan struct{}),
        }
        sink.closed.Store(true)

        sink.Write(DBLogEntry{Level: "ERROR", Message: "should be dropped"})

        select {
        case <-sink.ch:
                t.Error("entry should not be written to closed sink")
        default:
        }
}

func TestDBSink_Write_DropsWhenChannelFull(t *testing.T) {
        sink := &DBSink{
                pool: &mockPool{},
                ch:   make(chan DBLogEntry, 1),
                done: make(chan struct{}),
        }

        sink.Write(DBLogEntry{Level: "INFO", Message: "first"})
        sink.Write(DBLogEntry{Level: "INFO", Message: "second - should be dropped"})
        sink.Write(DBLogEntry{Level: "INFO", Message: "third - should also be dropped"})

        if len(sink.ch) != 1 {
                t.Errorf("channel length = %d, want 1 (subsequent entries should be dropped)", len(sink.ch))
        }

        if sink.Dropped.Load() != 2 {
                t.Errorf("Dropped counter = %d, want 2 (two entries were dropped)", sink.Dropped.Load())
        }

        got := <-sink.ch
        if got.Message != "first" {
                t.Errorf("expected first entry to remain in channel, got %q", got.Message)
        }

        if len(sink.ch) != 0 {
                t.Errorf("channel should be empty after draining first entry, got %d remaining", len(sink.ch))
        }
}

func TestDBSink_Write_ChannelFull_LogsDropOnStderr(t *testing.T) {
        var logMessages []string
        var logMu sync.Mutex
        origLog := stderrLog
        stderrLog = func(msg string) {
                logMu.Lock()
                logMessages = append(logMessages, msg)
                logMu.Unlock()
        }
        defer func() { stderrLog = origLog }()

        sink := &DBSink{
                pool: &mockPool{},
                ch:   make(chan DBLogEntry, 1),
                done: make(chan struct{}),
        }

        sink.Write(DBLogEntry{Level: "INFO", Message: "fills-channel"})
        sink.Write(DBLogEntry{Level: "INFO", Message: "overflow-triggers-log"})

        logMu.Lock()
        defer logMu.Unlock()
        if len(logMessages) != 1 {
                t.Fatalf("expected 1 stderr log on first overflow, got %d", len(logMessages))
        }
        if !strings.Contains(logMessages[0], "log entry dropped") {
                t.Errorf("stderr log should mention 'log entry dropped', got %q", logMessages[0])
        }
        if !strings.Contains(logMessages[0], "total dropped: 1") {
                t.Errorf("stderr log should report total dropped count, got %q", logMessages[0])
        }
}

func TestDBSink_Write_ChannelFull_SilentDrop_NoDeadlock(t *testing.T) {
        sink := &DBSink{
                pool: &mockPool{},
                ch:   make(chan DBLogEntry, 2),
                done: make(chan struct{}),
        }

        sink.Write(DBLogEntry{Level: "INFO", Message: "msg1"})
        sink.Write(DBLogEntry{Level: "INFO", Message: "msg2"})

        done := make(chan struct{})
        go func() {
                sink.Write(DBLogEntry{Level: "INFO", Message: "msg3-overflow"})
                close(done)
        }()

        select {
        case <-done:
        case <-time.After(1 * time.Second):
                t.Fatal("Write blocked on full channel — should have silently dropped")
        }

        if len(sink.ch) != 2 {
                t.Errorf("channel should still have 2 entries, got %d", len(sink.ch))
        }
        if sink.Dropped.Load() != 1 {
                t.Errorf("Dropped counter = %d, want 1 (overflow entry should be counted)", sink.Dropped.Load())
        }
}

func TestDBSink_Close_Idempotent(t *testing.T) {
        pool := &mockPool{}
        sink := NewDBSinkFromPool(pool)
        sink.Close()
        sink.Close()
}

func TestDBSink_FlushBatch_DBError_LogsToStderr(t *testing.T) {
        var logMessages []string
        var logMu sync.Mutex
        origLog := stderrLog
        stderrLog = func(msg string) {
                logMu.Lock()
                logMessages = append(logMessages, msg)
                logMu.Unlock()
        }
        defer func() { stderrLog = origLog }()

        pool := &mockPool{execErr: context.DeadlineExceeded}
        sink := &DBSink{
                pool: pool,
                ch:   make(chan DBLogEntry, dbChanSize),
                done: make(chan struct{}),
        }

        batch := []DBLogEntry{
                {Timestamp: time.Now(), Level: "ERROR", Message: "fail", Attrs: map[string]string{}},
        }
        sink.flushBatch(batch)

        logMu.Lock()
        defer logMu.Unlock()
        if len(logMessages) == 0 {
                t.Error("expected stderrLog to be called on DB insert failure")
        }
        foundRelevant := false
        for _, msg := range logMessages {
                if strings.Contains(msg, "deadline") || strings.Contains(msg, "insert") || strings.Contains(msg, "DB") {
                        foundRelevant = true
                }
        }
        if !foundRelevant {
                t.Errorf("stderrLog messages should reference the DB error, got: %v", logMessages)
        }
}

func TestDBSink_FlushBatch_TraceIDTruncation(t *testing.T) {
        var capturedTraceID string
        pool := &mockPool{
                execFunc: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
                        if len(arguments) >= 7 {
                                if tid, ok := arguments[6].(string); ok {
                                        capturedTraceID = tid
                                }
                        }
                        return pgconn.NewCommandTag("INSERT 0 1"), nil
                },
        }
        sink := &DBSink{
                pool: pool,
                ch:   make(chan DBLogEntry, dbChanSize),
                done: make(chan struct{}),
        }

        longTraceID := strings.Repeat("a", 100)
        batch := []DBLogEntry{
                {Timestamp: time.Now(), Level: "INFO", Message: "trace test", TraceID: longTraceID, Attrs: map[string]string{}},
        }
        sink.flushBatch(batch)

        if len(capturedTraceID) != 64 {
                t.Errorf("trace ID should be truncated to 64, got length %d", len(capturedTraceID))
        }
}

func TestDBSink_FlushBatch_PreservesAllFields(t *testing.T) {
        var capturedArgs []any
        pool := &mockPool{
                execFunc: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
                        capturedArgs = arguments
                        return pgconn.NewCommandTag("INSERT 0 1"), nil
                },
        }
        sink := &DBSink{
                pool: pool,
                ch:   make(chan DBLogEntry, dbChanSize),
                done: make(chan struct{}),
        }

        batch := []DBLogEntry{
                {
                        Timestamp: time.Now(),
                        Level:     "WARN",
                        Message:   "test message",
                        Event:     "dns.scan",
                        Category:  "security",
                        Domain:    "example.com",
                        TraceID:   "trace-abc",
                        Attrs:     map[string]string{"key": "value"},
                },
        }
        sink.flushBatch(batch)

        if capturedArgs == nil {
                t.Fatal("flushBatch did not call Exec")
        }
        if len(capturedArgs) < 7 {
                t.Fatalf("expected at least 7 args, got %d", len(capturedArgs))
        }
        if capturedArgs[1] != "WARN" {
                t.Errorf("level arg = %v, want WARN", capturedArgs[1])
        }
        if capturedArgs[2] != "test message" {
                t.Errorf("message arg = %v, want 'test message'", capturedArgs[2])
        }
        if capturedArgs[3] != "dns.scan" {
                t.Errorf("event arg = %v, want 'dns.scan'", capturedArgs[3])
        }
        if capturedArgs[4] != "security" {
                t.Errorf("category arg = %v, want 'security'", capturedArgs[4])
        }
        if capturedArgs[5] != "example.com" {
                t.Errorf("domain arg = %v, want 'example.com'", capturedArgs[5])
        }
        if capturedArgs[6] != "trace-abc" {
                t.Errorf("traceID arg = %v, want 'trace-abc'", capturedArgs[6])
        }
}

func TestDBSink_Prune_DeletesOldestBeyondThreshold(t *testing.T) {
        var capturedLimit int
        var capturedSQL string
        pool := &mockPool{
                execFunc: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
                        capturedSQL = sql
                        if len(arguments) > 0 {
                                if v, ok := arguments[0].(int); ok {
                                        capturedLimit = v
                                }
                        }
                        return pgconn.NewCommandTag("DELETE 500"), nil
                },
        }

        sink := &DBSink{
                pool: pool,
                ch:   make(chan DBLogEntry, dbChanSize),
                done: make(chan struct{}),
        }
        sink.prune()

        if capturedLimit != dbMaxCap {
                t.Errorf("prune LIMIT = %d, want %d (dbMaxCap)", capturedLimit, dbMaxCap)
        }
        if capturedLimit != 10000 {
                t.Errorf("prune threshold hardcoded value = %d, want 10000", capturedLimit)
        }
        if !strings.Contains(capturedSQL, "DELETE FROM system_log_entries") {
                t.Errorf("prune SQL missing DELETE statement: %q", capturedSQL)
        }
        if !strings.Contains(capturedSQL, "LIMIT $1") {
                t.Errorf("prune SQL missing parameterized LIMIT: %q", capturedSQL)
        }
        if !strings.Contains(capturedSQL, "ORDER BY timestamp DESC") {
                t.Errorf("prune SQL missing ORDER BY timestamp DESC (retains newest): %q", capturedSQL)
        }
        if !strings.Contains(capturedSQL, "NOT IN") {
                t.Errorf("prune SQL missing NOT IN (should keep top N, delete rest): %q", capturedSQL)
        }
}

func TestDBSink_Prune_ContextTimeout(t *testing.T) {
        var ctxDeadlineOK bool
        pool := &mockPool{
                execFunc: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
                        _, ok := ctx.Deadline()
                        ctxDeadlineOK = ok
                        return pgconn.NewCommandTag("DELETE 0"), nil
                },
        }

        sink := &DBSink{
                pool: pool,
                ch:   make(chan DBLogEntry, dbChanSize),
                done: make(chan struct{}),
        }
        sink.prune()

        if !ctxDeadlineOK {
                t.Error("prune should use a context with timeout/deadline")
        }
}

func TestDBSink_Prune_DBError_LogsWithoutPanic(t *testing.T) {
        var logCalled atomic.Int32
        origLog := stderrLog
        stderrLog = func(msg string) {
                logCalled.Add(1)
        }
        defer func() { stderrLog = origLog }()

        pool := &mockPool{execErr: context.DeadlineExceeded}
        sink := &DBSink{
                pool: pool,
                ch:   make(chan DBLogEntry, dbChanSize),
                done: make(chan struct{}),
        }
        sink.prune()

        if logCalled.Load() == 0 {
                t.Error("expected stderrLog to be called on prune failure")
        }
}

func TestDBSink_PruneLoop_TriggersOnTick(t *testing.T) {
        var pruneCalls atomic.Int32
        pool := &mockPool{
                execFunc: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
                        if strings.Contains(sql, "DELETE FROM system_log_entries") {
                                pruneCalls.Add(1)
                        }
                        return pgconn.NewCommandTag("DELETE 0"), nil
                },
        }

        sink := &DBSink{
                pool: pool,
                ch:   make(chan DBLogEntry, dbChanSize),
                done: make(chan struct{}),
        }

        sink.wg.Add(1)
        go func() {
                defer sink.wg.Done()
                sink.prune()
                sink.prune()
                sink.prune()
        }()
        sink.wg.Wait()

        got := pruneCalls.Load()
        if got != 3 {
                t.Fatalf("prune should have been called 3 times, got %d", got)
        }
}

func TestDBSink_RealWorker_BatchFlush_ExactThreshold(t *testing.T) {
        pool := &mockPool{}
        sink := NewDBSinkFromPool(pool)
        defer sink.Close()

        for i := 0; i < dbBatchSize-1; i++ {
                sink.Write(DBLogEntry{
                        Timestamp: time.Now(),
                        Level:     "INFO",
                        Message:   "sub-threshold",
                        Attrs:     map[string]string{},
                })
        }

        time.Sleep(200 * time.Millisecond)
        if pool.insertCount() > 0 {
                t.Errorf("sub-threshold: expected 0 flushes before batch size, got %d", pool.insertCount())
        }

        sink.Write(DBLogEntry{
                Timestamp: time.Now(),
                Level:     "INFO",
                Message:   "threshold trigger",
                Attrs:     map[string]string{},
        })

        deadline := time.After(3 * time.Second)
        for {
                select {
                case <-deadline:
                        t.Fatalf("batch flush at exact threshold did not happen; got %d inserts", pool.insertCount())
                default:
                        if pool.insertCount() >= dbBatchSize {
                                return
                        }
                        time.Sleep(10 * time.Millisecond)
                }
        }
}
