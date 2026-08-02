package handlers

import (
        "net/http"
        "net/http/httptest"
        "net/url"
        "testing"
        "time"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/dbq"
        "dnstool/go-server/internal/handlers/authpkg"

        "github.com/gin-gonic/gin"
        "github.com/jackc/pgx/v5/pgtype"
)

func TestSanitizeNextPath(t *testing.T) {
        tests := []struct {
                in   string
                want string
        }{
                {"/ops", "/ops"},
                {"/dossier?domain=example.com", "/dossier?domain=example.com"},
                {"/", "/"},
                {"", ""},
                {"ops", ""},                       // relative, not absolute-path
                {"//evil.com/x", ""},              // protocol-relative
                {"https://evil.com/x", ""},        // absolute URL
                {"/\\evil.com", ""},               // backslash normalization trick
                {"/ok\\evil", ""},                 // backslash anywhere
                {"/x" + string(make([]byte, 600)), ""}, // over length cap
        }
        for _, tt := range tests {
                if got := authpkg.SanitizeNextPath(tt.in); got != tt.want {
                        t.Errorf("sanitizeNextPath(%q) = %q, want %q", tt.in, got, tt.want)
                }
        }
}

func loginWithNext(t *testing.T, next string) []*http.Cookie {
        t.Helper()
        gin.SetMode(gin.TestMode)
        cfg := &config.Config{
                GoogleClientID:    "test-client-id",
                GoogleRedirectURL: "https://test.example.com/auth/callback",
        }
        h := authpkg.NewAuthHandlerWithStore(cfg, nil, &mockAuthStore{})

        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        target := "/auth/login"
        if next != "" {
                target += "?next=" + url.QueryEscape(next)
        }
        c.Request = httptest.NewRequest(http.MethodGet, target, nil)
        h.Login(c)
        if w.Code != http.StatusFound {
                t.Fatalf("Login: expected 302, got %d", w.Code)
        }
        return w.Result().Cookies()
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
        for _, ck := range cookies {
                if ck.Name == name {
                        return ck
                }
        }
        return nil
}

func TestLogin_SafeNextStoredInCookie(t *testing.T) {
        ck := findCookie(loginWithNext(t, "/ops"), authpkg.OauthNextCookie)
        if ck == nil {
                t.Fatal("expected next cookie to be set")
        }
        val, err := url.QueryUnescape(ck.Value)
        if err != nil || val != "/ops" {
                t.Errorf("next cookie value = %q (unescaped %q), want /ops", ck.Value, val)
        }
        if ck.MaxAge <= 0 {
                t.Errorf("next cookie MaxAge = %d, want positive", ck.MaxAge)
        }
}

func TestLogin_UnsafeNextClearsCookie(t *testing.T) {
        for _, next := range []string{"https://evil.com/x", "//evil.com", ""} {
                ck := findCookie(loginWithNext(t, next), authpkg.OauthNextCookie)
                if ck == nil {
                        t.Fatalf("next=%q: expected a clearing Set-Cookie for the next cookie", next)
                }
                if ck.Value != "" || ck.MaxAge > 0 {
                        t.Errorf("next=%q: cookie should be cleared, got value=%q maxage=%d", next, ck.Value, ck.MaxAge)
                }
        }
}

func finalizeWithNextCookie(t *testing.T, cookieValue string, firstLogin bool) *httptest.ResponseRecorder {
        t.Helper()
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
        if cookieValue != "" {
                c.Request.AddCookie(&http.Cookie{Name: authpkg.OauthNextCookie, Value: cookieValue})
        }

        h := authpkg.NewAuthHandlerWithStore(&config.Config{}, nil, &mockAuthStore{})

        created := time.Now().Add(-24 * time.Hour)
        lastLogin := time.Now()
        if firstLogin {
                created = time.Now()
                lastLogin = created.Add(2 * time.Second)
        }
        user := dbq.User{
                ID:          7,
                Role:        "user",
                CreatedAt:   pgtype.Timestamp{Time: created, Valid: true},
                LastLoginAt: pgtype.Timestamp{Time: lastLogin, Valid: true},
        }
        h.FinalizeLogin(c, "test-session-id", user, "User", "user@example.com")
        if w.Code != http.StatusFound {
                t.Fatalf("FinalizeLogin: expected 302, got %d", w.Code)
        }
        return w
}

func TestFinalizeLogin_HonorsSafeNext(t *testing.T) {
        w := finalizeWithNextCookie(t, "/ops", false)
        if loc := w.Header().Get("Location"); loc != "/ops" {
                t.Errorf("Location = %q, want /ops", loc)
        }
        ck := findCookie(w.Result().Cookies(), authpkg.OauthNextCookie)
        if ck == nil || ck.Value != "" || ck.MaxAge > 0 {
                t.Error("next cookie should be cleared after finalize")
        }
}

func TestFinalizeLogin_NextWinsOverWelcome(t *testing.T) {
        w := finalizeWithNextCookie(t, "/dossier", true)
        if loc := w.Header().Get("Location"); loc != "/dossier" {
                t.Errorf("Location = %q, want /dossier (next beats welcome)", loc)
        }
}

func TestFinalizeLogin_RejectsUnsafeNext(t *testing.T) {
        for _, unsafe := range []string{"//evil.com", "https://evil.com/x", "evil"} {
                w := finalizeWithNextCookie(t, unsafe, false)
                if loc := w.Header().Get("Location"); loc != "/" {
                        t.Errorf("next cookie %q: Location = %q, want /", unsafe, loc)
                }
        }
}

func TestFinalizeLogin_NoNextFallsBackToRoot(t *testing.T) {
        w := finalizeWithNextCookie(t, "", false)
        if loc := w.Header().Get("Location"); loc != "/" {
                t.Errorf("Location = %q, want /", loc)
        }
}
