// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package config

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// Version, GitCommit, and BuildTime are injected at build time via -ldflags
// (see build.sh + scripts/version.sh). Version is derived from git
// (`git describe --tags`), so these literals are fallbacks only — they apply
// when the binary is built without ldflags (e.g. a bare `go run`). Do NOT
// hand-edit Version to bump a release; create a git tag instead.
var (
	Version   = "dev"
	GitCommit = "dev"
	BuildTime = "unknown"
)

type ProbeEndpoint struct {
	ID    string
	Label string
	URL   string
	Key   string
}

type Config struct {
	DatabaseURL        string
	SessionSecret      string
	Port               string
	AppVersion         string
	// CanonicalBaseURL is the public instrument's address, always the
	// canonical host — never BASE_URL, which on a local build points at the
	// local instance and would make the history flipper's "Cloud" link a
	// circle. Local surfaces use it to LINK to the cloud counterpart
	// (the flippers brief's direct-link fork: no fetch, no phone-home on
	// page load; the disclosure is the user's own click).
	CanonicalBaseURL   string
	SMTPProbeMode      string
	IPFSProbeMode      string
	ProbeAPIURL        string
	ProbeAPIKey        string
	Probes             []ProbeEndpoint
	MaintenanceNote    string
	SectionTuning      map[string]string
	BetaPages          map[string]bool
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string
	InitialAdminEmail  string
	BaseURL            string
	IsDevEnvironment   bool
	IsCloudDeployment  bool
	DiscordWebhookURL  string
	YouTubeVideoIDs    map[string]string
	OriginTrialToken   string
	// TrustedProxies is the list of peer CIDRs gin may accept
	// X-Forwarded-For from. Defaults to loopback only (an on-box proxy);
	// TRUSTED_PROXIES overrides it entirely — the deployment declares the
	// full list, because an implicit merge would hide which peers are
	// actually trusted when reading the unit file.
	TrustedProxies []string
}

// IsCloudDeploymentEnv reports whether this process is the deployed cloud
// instance — the cloud→local lever. Two keys are recognized:
// CLOUD_DEPLOYMENT (platform-neutral; the AWS unit file sets it) and
// REPLIT_DEPLOYMENT (set by the Replit platform on published deployments).
// Recognizing both means a rollback deploy onto Replit behaves as cloud
// with no env change. Shared with db.go's production-database guard so the
// two can never disagree about what "deployed" means.
func IsCloudDeploymentEnv() bool {
	return os.Getenv("CLOUD_DEPLOYMENT") != "" || os.Getenv("REPLIT_DEPLOYMENT") != ""
}

var betaPagesMap = map[string]bool{
	"toolkit":      true,
	"investigate":  true,
	"email-header": true,
	"ttl-tuner":    true,
	"topology":     true,
}

var sectionTuningMap = map[string]string{
	"ai":   "Beta",
	"smtp": "Beta",
}

func Load() (*Config, error) {
	dbURL := os.Getenv("DATABASE_URL_OVERRIDE")
	if dbURL == "" {
		dbURL = os.Getenv("DATABASE_URL")
	}
	if dbURL == "" {
		return nil, fmt.Errorf("DATABASE_URL environment variable is required")
	}

	sessionSecret := os.Getenv("SESSION_SECRET")
	if sessionSecret == "" {
		return nil, fmt.Errorf("SESSION_SECRET environment variable is required")
	}

	port := envOrDefault("PORT", "5000")
	smtpProbeMode, probeAPIURL := resolveProbeMode()
	probes := loadProbeEndpoints(probeAPIURL)
	tuning := loadSectionTuning()
	if err := assertDeploymentEnvironment(); err != nil {
		return nil, err
	}
	baseURL, isDevEnv := resolveBaseURL()
	googleRedirectURL := envOrDefault("GOOGLE_REDIRECT_URL", baseURL+"/auth/callback")
	betaPages := copyBetaPages()
	trustedProxies, err := resolveTrustedProxies()
	if err != nil {
		return nil, err
	}

	ipfsProbeMode := envOrDefault("IPFS_PROBE_MODE", "off")
	if ipfsProbeMode == "remote" && len(probes) == 0 {
		ipfsProbeMode = "off"
	}

	return &Config{
		DatabaseURL:        dbURL,
		SessionSecret:      sessionSecret,
		Port:               port,
		AppVersion:         Version,
		CanonicalBaseURL:   canonicalBaseURL,
		SMTPProbeMode:      smtpProbeMode,
		IPFSProbeMode:      ipfsProbeMode,
		ProbeAPIURL:        probeAPIURL,
		ProbeAPIKey:        os.Getenv("PROBE_API_KEY"),
		Probes:             probes,
		MaintenanceNote:    os.Getenv("MAINTENANCE_NOTE"),
		SectionTuning:      tuning,
		BetaPages:          betaPages,
		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		GoogleRedirectURL:  googleRedirectURL,
		InitialAdminEmail:  strings.TrimSpace(os.Getenv("INITIAL_ADMIN_EMAIL")),
		BaseURL:            baseURL,
		IsDevEnvironment:   isDevEnv,
		// The cloud→local lever: true only on the deployed cloud
		// instance. Local and Replit-dev runs skip cloud-only UI
		// (e.g. the privacy/cookie banner) — and cloud-only side
		// effects: Wayback archival is gated on this same field.
		IsCloudDeployment: IsCloudDeploymentEnv(),
		DiscordWebhookURL: os.Getenv("DISCORD_WEBHOOK_URL"),
		YouTubeVideoIDs:   parseYouTubeIDs(os.Getenv("YOUTUBE_VIDEO_IDS")),
		OriginTrialToken:  strings.TrimSpace(os.Getenv("ORIGIN_TRIAL_TOKEN")),
		TrustedProxies:    trustedProxies,
	}, nil
}

func parseYouTubeIDs(raw string) map[string]string {
	m := make(map[string]string)
	if raw == "" {
		return m
	}
	for _, pair := range strings.Split(raw, ",") {
		parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(parts) == 2 {
			m[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return m
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func resolveProbeMode() (string, string) {
	smtpProbeMode := os.Getenv("SMTP_PROBE_MODE")
	if smtpProbeMode == "" {
		smtpProbeMode = "skip"
	}
	probeAPIURL := os.Getenv("PROBE_API_URL")
	if probeAPIURL != "" && smtpProbeMode == "skip" {
		smtpProbeMode = "remote"
	}
	return smtpProbeMode, probeAPIURL
}

func loadProbeEndpoints(probeAPIURL string) []ProbeEndpoint {
	var probes []ProbeEndpoint
	if probeAPIURL != "" {
		probes = append(probes, ProbeEndpoint{
			ID:    "probe-01",
			Label: envOrDefault("PROBE_LABEL", "US-East (Boston)"),
			URL:   probeAPIURL,
			Key:   os.Getenv("PROBE_API_KEY"),
		})
	}
	if probeAPIURL2 := os.Getenv("PROBE_API_URL_2"); probeAPIURL2 != "" {
		probes = append(probes, ProbeEndpoint{
			ID:    "probe-02",
			Label: envOrDefault("PROBE_LABEL_2", "US-East (Kali/02)"),
			URL:   probeAPIURL2,
			Key:   os.Getenv("PROBE_API_KEY_2"),
		})
	}
	return probes
}

func loadSectionTuning() map[string]string {
	tuning := make(map[string]string)
	for k, v := range sectionTuningMap {
		tuning[k] = v
	}
	envTuning := os.Getenv("SECTION_TUNING")
	if envTuning == "" {
		return tuning
	}
	for _, pair := range strings.Split(envTuning, ",") {
		parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(parts) == 2 {
			tuning[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return tuning
}

const canonicalBaseURL = "https://dnstool.it-help.tech"

// replitEphemeralHostSuffixes are the rotating, deploy-specific hostnames Replit
// assigns to dev workspaces and deployment containers. They are correct for the
// dev preview (set via BASE_URL in the development environment) but must NEVER
// appear in production absolute URLs: external consumers — e.g. the DEVONagent
// Pro search plugin, whose LinksMatching filter is "*dnstool.it-help.tech*", and
// OpenGraph/OAuth-redirect/canonical-link tags — key off the public domain. A
// stale dev BASE_URL leaking into a production container therefore makes the
// agent plugin match zero result links (scan still runs + saves, but the client
// sees "no results"). See replit.md § DNS provider / agent plugin notes.
var replitEphemeralHostSuffixes = []string{
	".replit.dev",
	".replit.app",
	".repl.co",
	".kirk.replit.dev",
	".picard.replit.dev",
}

func isReplitEphemeralBaseURL(raw string) bool {
	s := strings.ToLower(strings.TrimSpace(raw))
	for _, suffix := range replitEphemeralHostSuffixes {
		if strings.Contains(s, suffix) {
			return true
		}
	}
	return false
}

func resolveBaseURL() (string, bool) {
	baseURLRaw := os.Getenv("BASE_URL")
	baseURL := baseURLRaw
	if baseURL == "" {
		baseURL = canonicalBaseURL
	}
	if IsCloudDeploymentEnv() {
		// In production, never emit a Replit-ephemeral host in absolute URLs.
		// A dev BASE_URL inherited by the deployment container would otherwise
		// break external consumers that key off the canonical public domain.
		if isReplitEphemeralBaseURL(baseURL) {
			baseURL = canonicalBaseURL
		}
		return baseURL, false
	}
	replitDevDomain := os.Getenv("REPLIT_DEV_DOMAIN")
	isDevEnv := replitDevDomain != ""
	return baseURL, isDevEnv
}

// AssertDeploymentEnvironment fails loudly — before the router builds, though
// NOT before the early healthcheck listener binds (see the ordering note below)
// — when a dev-environment variable has leaked into a published deployment. These are the same class as the helium database-host guard in
// db.go: a mis-set secret that is silently corrected (or silently widens the
// CSP) produces a running system that is wrong in ways nobody sees.
//
// Each message names the offending variable, what it currently holds, and the
// action to take — matching the helium guard's "say what to fix, not just
// what's wrong" shape, because an operator reading a deploy log at 3am should
// not have to find the source to know which secret to change.
//
// Called from config.Load(), which runs AFTER the early listener binds
// (main.go: waitForListener + "Early listener started", then config.Load()).
// Until config.Load() succeeds, the early listener is serving startingHandler():
// /healthz answers {"status":"starting"} with HTTP 503 and every other route a
// 503 spinner page (503 since the AWS pre-cutover change — these answered 200
// before, so a platform healthcheck could read green in the instant before
// config.Load() failed and os.Exit(1) fired: a crash-loop that looked
// healthy). The assertion still cannot stop the early listener from accepting
// connections first; it only guarantees the bad configuration never serves
// real analysis traffic. Readiness is the router's /healthz — the only 200,
// body {"status":"ok"}.
func assertDeploymentEnvironment() error {
	if !IsCloudDeploymentEnv() {
		return nil
	}

	if os.Getenv("REPLIT_DEV_BANNER") == "1" {
		return fmt.Errorf("misconfiguration: REPLIT_DEV_BANNER=1 is set in a published deployment, which widens script-src/connect-src/frame-src with the Replit dev-banner wildcard in production; remove REPLIT_DEV_BANNER from the deployment's secrets (it belongs only in the dev workspace)")
	}

	if raw := os.Getenv("BASE_URL"); raw != "" && isReplitEphemeralBaseURL(raw) {
		return fmt.Errorf("misconfiguration: BASE_URL=%q in a published deployment carries a Replit-ephemeral hostname; set BASE_URL to %q in the deployment's secrets or delete it and let the canonical default apply (resolveBaseURL currently corrects this silently, which is why the leak went unreported)", raw, canonicalBaseURL)
	}

	return nil
}

// defaultTrustedProxies is loopback only: correct when nothing fronts the
// binary (direct serving) and when an on-box proxy (nginx/caddy terminating
// TLS) forwards over localhost. Any off-box hop — ALB, CloudFront-to-origin —
// must be declared via TRUSTED_PROXIES or its X-Forwarded-For is ignored and
// every client resolves to the hop's address (rate limiting, analytics, geo,
// and the My-IP tool all collapse onto the proxy).
var defaultTrustedProxies = []string{"127.0.0.1/8", "::1/128"}

func resolveTrustedProxies() ([]string, error) {
	raw := strings.TrimSpace(os.Getenv("TRUSTED_PROXIES"))
	if raw == "" {
		return defaultTrustedProxies, nil
	}
	var proxies []string
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// Validate here, at boot, so a typo'd CIDR fails the deploy
		// loudly instead of silently trusting nobody: gin would return
		// the same error from SetTrustedProxies, but a config error
		// should name the env var that carries it.
		if _, ipnet, err := net.ParseCIDR(entry); err != nil {
			if net.ParseIP(entry) == nil {
				return nil, fmt.Errorf("misconfiguration: TRUSTED_PROXIES entry %q is neither a CIDR nor an IP; fix the deployment env (comma-separated CIDRs/IPs, e.g. \"127.0.0.1/8,::1/128\")", entry)
			}
		} else if ones, _ := ipnet.Mask.Size(); ones == 0 {
			// /0 trusts every peer on the internet, which makes
			// X-Forwarded-For client-forgeable: rate limits become
			// evadable by rotating fake XFF values and every stored
			// client IP (analytics, geo, abuse logs, the My-IP tool)
			// records an attacker-chosen address. There is no valid
			// deployment of this instrument where that is intended.
			return nil, fmt.Errorf("misconfiguration: TRUSTED_PROXIES entry %q trusts every peer, making client IPs forgeable via X-Forwarded-For; list the actual proxy CIDRs instead", entry)
		}
		proxies = append(proxies, entry)
	}
	if len(proxies) == 0 {
		return nil, fmt.Errorf("misconfiguration: TRUSTED_PROXIES is set but contains no entries; unset it to use the loopback default or list the proxy CIDRs")
	}
	return proxies, nil
}

func copyBetaPages() map[string]bool {
	betaPages := make(map[string]bool)
	for k, v := range betaPagesMap {
		betaPages[k] = v
	}
	return betaPages
}
