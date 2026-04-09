package handlers

import (
        "context"
        "testing"
)

func TestOpsTaskList_Coverage(t *testing.T) {
        tasks := opsTaskList()
        if len(tasks) != 8 {
                t.Errorf("expected 8 ops tasks, got %d", len(tasks))
        }
        ids := make(map[string]bool)
        for _, task := range tasks {
                ids[task.ID] = true
        }
        expectedIDs := []string{opsCSSCohesion, opsFeatureInventory, opsScientificColors, opsRenderDiagrams, opsFigmaBundle, opsFigmaVerify, opsMiroSync, opsFullPipeline}
        for _, id := range expectedIDs {
                if !ids[id] {
                        t.Errorf("missing expected task ID: %s", id)
                }
        }
}

func TestOpsWhitelist_AllTasksHaveLabels(t *testing.T) {
        for id, task := range opsWhitelist {
                if task.Label == "" {
                        t.Errorf("task %s has no label", id)
                }
                if task.Command == "" {
                        t.Errorf("task %s has no command", id)
                }
                if len(task.Args) == 0 {
                        t.Errorf("task %s has no args", id)
                }
                if task.Icon == "" {
                        t.Errorf("task %s has no icon", id)
                }
        }
}

func TestDefaultCmdRunner_InvalidCommand(t *testing.T) {
        ctx := context.Background()
        result := defaultCmdRunner(ctx, "nonexistent-command-12345", []string{})
        if result.Err == nil {
                t.Error("expected error for nonexistent command")
        }
}

func TestDefaultCmdRunner_Echo(t *testing.T) {
        ctx := context.Background()
        result := defaultCmdRunner(ctx, "echo", []string{"hello"})
        if result.Err != nil {
                t.Errorf("unexpected error: %v", result.Err)
        }
        if result.Stdout == "" {
                t.Error("expected stdout output")
        }
}

func TestNewAdminHandler_Coverage(t *testing.T) {
        bpFunc := func() int64 { return 42 }
        h := NewAdminHandler(nil, nil, bpFunc)
        if h == nil {
                t.Fatal("expected handler")
        }
        if h.BackpressureCountFunc == nil {
                t.Error("expected backpressure func")
        }
        if h.RunCmd == nil {
                t.Error("expected RunCmd set")
        }
        if h.BackpressureCountFunc() != 42 {
                t.Errorf("expected 42, got %d", h.BackpressureCountFunc())
        }
}

func TestCmdRunResult_FieldAccess(t *testing.T) {
        r := CmdRunResult{Stdout: "out", Stderr: "err", Err: nil}
        if r.Stdout != "out" {
                t.Error("expected stdout=out")
        }
        if r.Stderr != "err" {
                t.Error("expected stderr=err")
        }
        if r.Err != nil {
                t.Error("expected nil error")
        }
}

