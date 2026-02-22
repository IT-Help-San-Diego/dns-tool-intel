package handlers

import (
        "log/slog"
        "net/http"
        "strconv"
        "strings"
        "time"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"

        "github.com/jackc/pgx/v5/pgtype"
        "github.com/gin-gonic/gin"
)

const templateWatchlist = "watchlist.html"

const maxWatchlistEntries = 25

type WatchlistHandler struct {
        DB     *db.Database
        Config *config.Config
}

func NewWatchlistHandler(database *db.Database, cfg *config.Config) *WatchlistHandler {
        return &WatchlistHandler{DB: database, Config: cfg}
}

type watchlistItem struct {
        ID        int32
        Domain    string
        Cadence   string
        Enabled   bool
        LastRunAt string
        NextRunAt string
        CreatedAt string
}

type endpointItem struct {
        ID           int32
        EndpointType string
        URL          string
        MaskedURL    string
        Enabled      bool
        CreatedAt    string
}

func maskURL(u string) string {
        if len(u) <= 30 {
                return u
        }
        return u[:20] + "..." + u[len(u)-10:]
}

func cadenceToNextRun(cadence string) pgtype.Timestamp {
        var d time.Duration
        switch cadence {
        case "hourly":
                d = time.Hour
        case "daily":
                d = 24 * time.Hour
        case "weekly":
                d = 7 * 24 * time.Hour
        default:
                d = 24 * time.Hour
        }
        return pgtype.Timestamp{Time: time.Now().UTC().Add(d), Valid: true}
}

func (h *WatchlistHandler) baseTmplData(c *gin.Context) gin.H {
        nonce := c.MustGet("csp_nonce")
        csrfToken := c.MustGet("csrf_token")
        data := gin.H{
                "AppVersion":      h.Config.AppVersion,
                "MaintenanceNote": h.Config.MaintenanceNote,
                "CspNonce":        nonce,
                "CsrfToken":       csrfToken,
                "ActivePage":      "watchlist",
        }
        mergeAuthData(c, h.Config, data)
        return data
}

func (h *WatchlistHandler) Watchlist(c *gin.Context) {
        uid, _ := c.Get("user_id")
        userID, ok := uid.(int32)
        if !ok || userID == 0 {
                data := h.baseTmplData(c)
                data["FlashMessages"] = []FlashMessage{{Category: "warning", Message: "Sign in to manage your watchlist."}}
                data["WatchlistItems"] = []watchlistItem{}
                data["Endpoints"] = []endpointItem{}
                data["WatchlistCount"] = 0
                data["MaxWatchlist"] = maxWatchlistEntries
                c.HTML(http.StatusOK, templateWatchlist, data)
                if !c.Writer.Written() {
                        slog.Error("Watchlist template produced no output — possible execution error")
                } else {
                        slog.Debug("Watchlist rendered", "size", c.Writer.Size())
                }
                return
        }

        ctx := c.Request.Context()

        entries, err := h.DB.Queries.ListWatchlistByUser(ctx, userID)
        if err != nil {
                slog.Error("Failed to load watchlist", "user_id", userID, "error", err)
                data := h.baseTmplData(c)
                data["FlashMessages"] = []FlashMessage{{Category: "danger", Message: "Failed to load watchlist."}}
                c.HTML(http.StatusInternalServerError, templateWatchlist, data)
                return
        }

        items := make([]watchlistItem, 0, len(entries))
        for _, e := range entries {
                wi := watchlistItem{
                        ID:      e.ID,
                        Domain:  e.Domain,
                        Cadence: e.Cadence,
                        Enabled: e.Enabled,
                }
                if e.LastRunAt.Valid {
                        wi.LastRunAt = e.LastRunAt.Time.Format("2 Jan 2006 15:04 UTC")
                }
                if e.NextRunAt.Valid {
                        wi.NextRunAt = e.NextRunAt.Time.Format("2 Jan 2006 15:04 UTC")
                }
                if e.CreatedAt.Valid {
                        wi.CreatedAt = e.CreatedAt.Time.Format("2 Jan 2006 15:04 UTC")
                }
                items = append(items, wi)
        }

        endpoints, err := h.DB.Queries.ListNotificationEndpointsByUser(ctx, userID)
        if err != nil {
                slog.Error("Failed to load endpoints", "user_id", userID, "error", err)
        }
        eps := make([]endpointItem, 0, len(endpoints))
        for _, ep := range endpoints {
                ei := endpointItem{
                        ID:           ep.ID,
                        EndpointType: ep.EndpointType,
                        URL:          ep.Url,
                        MaskedURL:    maskURL(ep.Url),
                        Enabled:      ep.Enabled,
                }
                if ep.CreatedAt.Valid {
                        ei.CreatedAt = ep.CreatedAt.Time.Format("2 Jan 2006 15:04 UTC")
                }
                eps = append(eps, ei)
        }

        data := h.baseTmplData(c)
        data["WatchlistItems"] = items
        data["Endpoints"] = eps
        data["WatchlistCount"] = len(items)
        data["MaxWatchlist"] = maxWatchlistEntries
        c.HTML(http.StatusOK, templateWatchlist, data)
}

func (h *WatchlistHandler) AddDomain(c *gin.Context) {
        uid, _ := c.Get("user_id")
        userID, ok := uid.(int32)
        if !ok || userID == 0 {
                c.Redirect(http.StatusSeeOther, "/watchlist")
                return
        }

        domain := strings.TrimSpace(strings.ToLower(c.PostForm("domain")))
        cadence := c.PostForm("cadence")
        if domain == "" {
                c.Redirect(http.StatusSeeOther, "/watchlist")
                return
        }
        if cadence != "hourly" && cadence != "daily" && cadence != "weekly" {
                cadence = "daily"
        }

        ctx := c.Request.Context()

        count, err := h.DB.Queries.CountWatchlistByUser(ctx, userID)
        if err != nil {
                slog.Error("Failed to count watchlist", "error", err)
                c.Redirect(http.StatusSeeOther, "/watchlist")
                return
        }
        if count >= int64(maxWatchlistEntries) {
                c.Redirect(http.StatusSeeOther, "/watchlist")
                return
        }

        _, err = h.DB.Queries.InsertWatchlistEntry(ctx, dbq.InsertWatchlistEntryParams{
                UserID:    userID,
                Domain:    domain,
                Cadence:   cadence,
                NextRunAt: cadenceToNextRun(cadence),
        })
        if err != nil {
                slog.Error("Failed to add watchlist entry", "user_id", userID, "domain", domain, "error", err)
        }

        c.Redirect(http.StatusSeeOther, "/watchlist")
}

func (h *WatchlistHandler) RemoveDomain(c *gin.Context) {
        uid, _ := c.Get("user_id")
        userID, ok := uid.(int32)
        if !ok || userID == 0 {
                c.Redirect(http.StatusSeeOther, "/watchlist")
                return
        }

        idStr := c.Param("id")
        entryID, err := strconv.Atoi(idStr)
        if err != nil {
                c.Redirect(http.StatusSeeOther, "/watchlist")
                return
        }

        ctx := c.Request.Context()
        if err := h.DB.Queries.DeleteWatchlistEntry(ctx, dbq.DeleteWatchlistEntryParams{
                ID:     int32(entryID),
                UserID: userID,
        }); err != nil {
                slog.Error("Failed to delete watchlist entry", "id", entryID, "error", err)
        }

        c.Redirect(http.StatusSeeOther, "/watchlist")
}

func (h *WatchlistHandler) ToggleDomain(c *gin.Context) {
        uid, _ := c.Get("user_id")
        userID, ok := uid.(int32)
        if !ok || userID == 0 {
                c.Redirect(http.StatusSeeOther, "/watchlist")
                return
        }

        idStr := c.Param("id")
        entryID, err := strconv.Atoi(idStr)
        if err != nil {
                c.Redirect(http.StatusSeeOther, "/watchlist")
                return
        }

        enabled := c.PostForm("enabled") == "true"

        ctx := c.Request.Context()
        if err := h.DB.Queries.ToggleWatchlistEntry(ctx, dbq.ToggleWatchlistEntryParams{
                ID:      int32(entryID),
                UserID:  userID,
                Enabled: enabled,
        }); err != nil {
                slog.Error("Failed to toggle watchlist entry", "id", entryID, "error", err)
        }

        c.Redirect(http.StatusSeeOther, "/watchlist")
}

func (h *WatchlistHandler) AddEndpoint(c *gin.Context) {
        uid, _ := c.Get("user_id")
        userID, ok := uid.(int32)
        if !ok || userID == 0 {
                c.Redirect(http.StatusSeeOther, "/watchlist")
                return
        }

        url := strings.TrimSpace(c.PostForm("url"))
        secret := strings.TrimSpace(c.PostForm("secret"))
        if url == "" || (!strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://")) {
                c.Redirect(http.StatusSeeOther, "/watchlist")
                return
        }

        var secretPtr *string
        if secret != "" {
                secretPtr = &secret
        }

        ctx := c.Request.Context()
        _, err := h.DB.Queries.InsertNotificationEndpoint(ctx, dbq.InsertNotificationEndpointParams{
                UserID:       userID,
                EndpointType: "webhook",
                Url:          url,
                Secret:       secretPtr,
        })
        if err != nil {
                slog.Error("Failed to add notification endpoint", "user_id", userID, "url", url, "error", err)
        }

        c.Redirect(http.StatusSeeOther, "/watchlist")
}

func (h *WatchlistHandler) RemoveEndpoint(c *gin.Context) {
        uid, _ := c.Get("user_id")
        userID, ok := uid.(int32)
        if !ok || userID == 0 {
                c.Redirect(http.StatusSeeOther, "/watchlist")
                return
        }

        idStr := c.Param("id")
        endpointID, err := strconv.Atoi(idStr)
        if err != nil {
                c.Redirect(http.StatusSeeOther, "/watchlist")
                return
        }

        ctx := c.Request.Context()
        if err := h.DB.Queries.DeleteNotificationEndpoint(ctx, dbq.DeleteNotificationEndpointParams{
                ID:     int32(endpointID),
                UserID: userID,
        }); err != nil {
                slog.Error("Failed to delete notification endpoint", "id", endpointID, "error", err)
        }

        c.Redirect(http.StatusSeeOther, "/watchlist")
}

func (h *WatchlistHandler) ToggleEndpoint(c *gin.Context) {
        uid, _ := c.Get("user_id")
        userID, ok := uid.(int32)
        if !ok || userID == 0 {
                c.Redirect(http.StatusSeeOther, "/watchlist")
                return
        }

        idStr := c.Param("id")
        endpointID, err := strconv.Atoi(idStr)
        if err != nil {
                c.Redirect(http.StatusSeeOther, "/watchlist")
                return
        }

        enabled := c.PostForm("enabled") == "true"

        ctx := c.Request.Context()
        if err := h.DB.Queries.ToggleNotificationEndpoint(ctx, dbq.ToggleNotificationEndpointParams{
                ID:      int32(endpointID),
                UserID:  userID,
                Enabled: enabled,
        }); err != nil {
                slog.Error("Failed to toggle notification endpoint", "id", endpointID, "error", err)
        }

        c.Redirect(http.StatusSeeOther, "/watchlist")
}
