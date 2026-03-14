package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"dnstool/go-server/internal/analyzer"

	"github.com/gin-gonic/gin"
)

type phaseStatus struct {
	Status        string `json:"status"`
	DurationMs    int    `json:"duration_ms,omitempty"`
	CompletedAtMs int    `json:"completed_at_ms,omitempty"`
	StartedAtMs   int    `json:"started_at_ms,omitempty"`
}

type scanProgress struct {
	mu          sync.Mutex
	startTime   time.Time
	phases      map[string]*phaseStatus
	complete    bool
	redirectURL string
	analysisID  int32
}

type ProgressStore struct {
	store sync.Map
}

func NewProgressStore() *ProgressStore {
	ps := &ProgressStore{}
	go ps.cleanupLoop()
	return ps
}

func (ps *ProgressStore) NewToken() (string, *scanProgress) {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)

	progress := &scanProgress{
		startTime: time.Now(),
		phases:    make(map[string]*phaseStatus),
	}

	for _, group := range analyzer.PhaseGroupOrder {
		progress.phases[group] = &phaseStatus{Status: "pending"}
	}

	ps.store.Store(token, progress)
	return token, progress
}

func (ps *ProgressStore) Get(token string) *scanProgress {
	val, ok := ps.store.Load(token)
	if !ok {
		return nil
	}
	return val.(*scanProgress)
}

func (ps *ProgressStore) Delete(token string) {
	ps.store.Delete(token)
}

func (ps *ProgressStore) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		ps.store.Range(func(key, val any) bool {
			sp := val.(*scanProgress)
			if time.Since(sp.startTime) > 5*time.Minute {
				ps.store.Delete(key)
			}
			return true
		})
	}
}

func (sp *scanProgress) UpdatePhase(group, status string, durationMs int) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	elapsedMs := int(time.Since(sp.startTime).Milliseconds())
	ps, exists := sp.phases[group]
	if !exists {
		sp.phases[group] = &phaseStatus{Status: status, DurationMs: durationMs, CompletedAtMs: elapsedMs}
		return
	}
	if ps.Status == "done" {
		return
	}
	ps.Status = status
	ps.DurationMs = durationMs
	ps.CompletedAtMs = elapsedMs
}

func (sp *scanProgress) MarkComplete(analysisID int32, redirectURL string) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	sp.complete = true
	sp.analysisID = analysisID
	sp.redirectURL = redirectURL
	for _, ps := range sp.phases {
		if ps.Status != "done" {
			ps.Status = "done"
		}
	}
}

func (sp *scanProgress) MarkFailed(errMsg string) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	sp.complete = true
	sp.redirectURL = ""
}

func (sp *scanProgress) MakeProgressCallback() analyzer.ProgressCallback {
	return func(group, status string, durationMs int) {
		sp.UpdatePhase(group, status, durationMs)
	}
}

func (sp *scanProgress) toJSON() map[string]any {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	elapsedMs := int(time.Since(sp.startTime).Milliseconds())

	status := "running"
	if sp.complete {
		status = "complete"
	}

	phases := make(map[string]any, len(sp.phases))
	for group, ps := range sp.phases {
		phases[group] = map[string]any{
			"status":          ps.Status,
			"duration_ms":     ps.DurationMs,
			"completed_at_ms": ps.CompletedAtMs,
			"started_at_ms":   ps.StartedAtMs,
		}
	}

	result := map[string]any{
		"status":     status,
		"elapsed_ms": elapsedMs,
		"phases":     phases,
	}

	if sp.complete && sp.redirectURL != "" {
		result["redirect_url"] = sp.redirectURL
		result["analysis_id"] = sp.analysisID
	}

	return result
}

func ScanProgressHandler(store *ProgressStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.Param("token")
		sp := store.Get(token)
		if sp == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "progress token not found or expired"})
			return
		}
		c.JSON(http.StatusOK, sp.toJSON())
	}
}
