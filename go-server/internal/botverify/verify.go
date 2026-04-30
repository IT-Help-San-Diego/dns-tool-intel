// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
//
// Package botverify performs cryptographically-defensible bot identification
// using two-factor verification: claimed User-Agent string AND reverse-DNS +
// forward-DNS roundtrip on the client IP.
//
// This mirrors the "verified bot" methodology used by Cloudflare, Akamai, and
// Google Search Central. A bot is only classified as VerifiedBot when both:
//
//  1. Its User-Agent string matches a known operator pattern (e.g. "Googlebot",
//     "GPTBot/1.0", "ClaudeBot"), AND
//  2. PTR(client_ip) returns a hostname whose suffix is on the operator's
//     allowlist (e.g. *.googlebot.com), AND that hostname's forward A/AAAA
//     records resolve back to the same IP.
//
// Anything that fails either check is classified as Investigate — meaning we
// have an unverified claim, possibly a UA spoofer, possibly legitimate-but-
// unknown traffic that warrants human review before it shapes our published
// statistics.
//
// Devon Agent Pro is identified by UA only because it runs as a desktop app on
// the user's ISP — there is no operator-controlled IP range to verify against.
//
// Verification results are cached per-IP for 1 hour to avoid PTR/A queries on
// every request.
package botverify

import (
        "net"
        "sort"
        "strings"
        "sync"
        "time"
)

// Class is the trichotomy used to label a request's provenance.
type Class int

const (
        // ClassHuman means we did not detect any bot signal in the User-Agent.
        // The request looks like a browser-driven human session.
        ClassHuman Class = iota
        // ClassVerifiedBot means the User-Agent claimed a known bot identity AND
        // the source IP passed reverse+forward DNS verification against that
        // operator's allowlist (or, for Devon Agent, UA-only because it is a
        // desktop application).
        ClassVerifiedBot
        // ClassInvestigate means the User-Agent claimed a bot identity but the
        // IP did not verify, OR the User-Agent is one of several patterns we do
        // not yet have an operator allowlist for. These rows should not shape
        // "human" statistics until reviewed.
        ClassInvestigate
)

// Result is the outcome of classifying a single request.
type Result struct {
        Class    Class
        BotName  string // operator name when ClassVerifiedBot ("Googlebot", "GPTBot", etc.)
        UA       string
        IP       string
        Verified bool // true iff ClassVerifiedBot
}

// String renders Result as a stable scan_source value for persistence.
//
// Values are: "human", "verified_bot:<name>", "investigate".
// Returns empty string for an unrecognised Class so callers can fall through
// without overwriting other scan_source values (e.g. the existing scanner
// Classification path used for Qualys/CISA security-tool detection).
func (r Result) String() string {
        switch r.Class {
        case ClassHuman:
                return "human"
        case ClassVerifiedBot:
                if r.BotName != "" {
                        return "verified_bot:" + r.BotName
                }
                return "verified_bot"
        case ClassInvestigate:
                return "investigate"
        }
        return ""
}

// botRule binds a User-Agent substring (case-insensitive) to a verification
// strategy. If RDNSSuffixes is non-empty, the source IP must reverse-resolve
// to a hostname ending in one of those suffixes AND that hostname must
// forward-resolve back to the same IP. If UAOnly is true, no IP verification
// is required (use only for desktop/CLI tools where the IP is the end-user's,
// not the operator's).
type botRule struct {
        UAMatch      string
        BotName      string
        RDNSSuffixes []string
        UAOnly       bool
}

// botRules is the operator allowlist. Adding a new verified bot is a matter
// of appending one entry. Suffixes are lowercased and matched as DNS name
// suffixes (a leading "." is appended for safety so "evil-googlebot.com"
// does not match "googlebot.com").
//
// References:
//   - Google: https://developers.google.com/search/docs/crawling-indexing/verifying-googlebot
//   - Bing/Microsoft: https://www.bing.com/webmasters/help/how-to-verify-bingbot-3905dc26
//   - OpenAI GPTBot: https://platform.openai.com/docs/bots
//   - Anthropic ClaudeBot: https://support.anthropic.com/en/articles/8896518
//   - Perplexity: https://docs.perplexity.ai/guides/bots
//   - Apple: https://support.apple.com/en-us/119829
//   - Yandex: https://yandex.com/support/webmaster/robot-workings/check-yandex-robots.html
//   - DuckDuckGo: https://duckduckgo.com/duckduckbot
//   - Ahrefs: https://ahrefs.com/robot
//   - Semrush: https://www.semrush.com/bot/
//   - Majestic: https://mj12bot.com/
var botRules = []botRule{
        // ---- Search engines ----
        {UAMatch: "googlebot", BotName: "Googlebot", RDNSSuffixes: []string{".googlebot.com", ".google.com"}},
        {UAMatch: "google-inspectiontool", BotName: "Google-InspectionTool", RDNSSuffixes: []string{".googlebot.com", ".google.com"}},
        {UAMatch: "google-extended", BotName: "Google-Extended", RDNSSuffixes: []string{".googlebot.com", ".google.com"}},
        {UAMatch: "adsbot-google", BotName: "AdsBot-Google", RDNSSuffixes: []string{".googlebot.com", ".google.com"}},
        {UAMatch: "bingbot", BotName: "Bingbot", RDNSSuffixes: []string{".search.msn.com"}},
        {UAMatch: "msnbot", BotName: "MSNBot", RDNSSuffixes: []string{".search.msn.com"}},
        {UAMatch: "yandexbot", BotName: "YandexBot", RDNSSuffixes: []string{".yandex.com", ".yandex.ru", ".yandex.net"}},
        {UAMatch: "duckduckbot", BotName: "DuckDuckBot", RDNSSuffixes: []string{".duckduckgo.com", ".duckduckbot.com"}},
        {UAMatch: "applebot", BotName: "Applebot", RDNSSuffixes: []string{".applebot.apple.com", ".apple.com"}},

        // ---- AI/LLM crawlers ----
        {UAMatch: "gptbot", BotName: "GPTBot", RDNSSuffixes: []string{".openai.com", ".chatgpt.com"}},
        {UAMatch: "chatgpt-user", BotName: "ChatGPT-User", RDNSSuffixes: []string{".openai.com", ".chatgpt.com"}},
        {UAMatch: "oai-searchbot", BotName: "OAI-SearchBot", RDNSSuffixes: []string{".openai.com", ".chatgpt.com"}},
        {UAMatch: "claudebot", BotName: "ClaudeBot", RDNSSuffixes: []string{".anthropic.com", ".claude.com"}},
        {UAMatch: "claude-user", BotName: "Claude-User", RDNSSuffixes: []string{".anthropic.com", ".claude.com"}},
        {UAMatch: "anthropic-ai", BotName: "Anthropic-AI", RDNSSuffixes: []string{".anthropic.com", ".claude.com"}},
        {UAMatch: "perplexitybot", BotName: "PerplexityBot", RDNSSuffixes: []string{".perplexity.ai"}},
        {UAMatch: "perplexity-user", BotName: "Perplexity-User", RDNSSuffixes: []string{".perplexity.ai"}},
        {UAMatch: "google-cloudvertexbot", BotName: "Google-CloudVertexBot", RDNSSuffixes: []string{".googlebot.com", ".google.com"}},

        // ---- SEO / link-graph crawlers ----
        {UAMatch: "ahrefsbot", BotName: "AhrefsBot", RDNSSuffixes: []string{".ahrefs.com", ".ahrefs.net"}},
        {UAMatch: "semrushbot", BotName: "SemrushBot", RDNSSuffixes: []string{".semrush.com"}},
        {UAMatch: "mj12bot", BotName: "MJ12bot (Majestic)", RDNSSuffixes: []string{".mj12bot.com", ".majestic.com"}},

        // ---- Desktop / CLI agents (UA-only; user's own ISP IP) ----
        {UAMatch: "devonagent", BotName: "Devon Agent Pro", UAOnly: true},

        // ---- Social-link previews (UA-only or partial verification) ----
        {UAMatch: "facebookexternalhit", BotName: "Facebook External Hit", RDNSSuffixes: []string{".facebook.com", ".tfbnw.net"}},
        {UAMatch: "linkedinbot", BotName: "LinkedInBot", RDNSSuffixes: []string{".linkedin.com"}},
        {UAMatch: "slackbot", BotName: "Slackbot", RDNSSuffixes: []string{".slack.com"}},
        {UAMatch: "twitterbot", BotName: "Twitterbot", RDNSSuffixes: []string{".twttr.com", ".twitter.com", ".x.com"}},
        {UAMatch: "discordbot", BotName: "Discordbot", RDNSSuffixes: []string{".discord.com", ".discordapp.com"}},
        {UAMatch: "telegrambot", BotName: "TelegramBot", RDNSSuffixes: []string{".telegram.org"}},

        // ---- Generic bot signals we cannot verify (always Investigate, never VerifiedBot) ----
        // These match the "investigate" bucket: claims to be a bot but we have no
        // operator allowlist to verify against. Distinct from human and verified.
}

// investigateUASignals are case-insensitive substrings indicating something
// non-human is making the request, but for which we do not have an operator
// allowlist. These force ClassInvestigate even when no botRule matches.
var investigateUASignals = []string{
        "bot/", "bot ", "spider", "crawler", "crawling", "scraper", "scraping",
        "http-client", "httpclient", "okhttp", "python-requests", "go-http-client",
        "curl/", "wget/", "libwww-perl", "java/", "ruby", "axios/", "node-fetch",
        "headlesschrome", "phantomjs", "puppeteer", "playwright",
        "facebot", "ia_archiver", "dataprovider", "mauibot", "petalbot", "bytespider",
        "clarabot", "webcrawler", "feedfetcher", "feedburner", "seoscanners",
        "dotbot", "rogerbot", "screaming frog", "sitebulb", "websiteauditor",
        "censysinspect", "shodan", "internetmeasurement",
}

// verifyCache memoises Verify results per (UA, IP) tuple for 1 hour.
type cacheEntry struct {
        result    Result
        cachedAt  time.Time
}

var (
        cacheMu  sync.RWMutex
        cache    = make(map[string]cacheEntry)
        cacheTTL = 1 * time.Hour
)

// cacheMaxEntries bounds the cache so an attacker rotating UA/IP pairs can't
// drive unbounded memory growth. 50 000 entries × ~256 B per entry ≈ ~13 MiB
// worst case — generous for legitimate diversity, capped against abuse.
const cacheMaxEntries = 50000

// maxUALen caps the user-agent string length we cache to defend against
// pathological multi-kilobyte UA strings being used as an amplification vector.
const maxUALen = 512

// sweepCacheLocked enforces a strict bound: caller is guaranteed that on
// return len(cache) < cacheMaxEntries, leaving at least one slot for the
// pending insert. First, evict all entries past TTL. If still at or over
// capacity, sort by age and drop oldest entries until strictly below the cap.
// Caller must hold cacheMu (write lock).
func sweepCacheLocked(now time.Time) {
        for k, e := range cache {
                if now.Sub(e.cachedAt) >= cacheTTL {
                        delete(cache, k)
                }
        }
        if len(cache) < cacheMaxEntries {
                return
        }
        // Strict-bound path: collect (key, age) for every entry, sort by age,
        // and delete the oldest until we have at least one free slot. This is
        // O(n log n) but only fires when we are at the bound, which is the
        // attack scenario where the small extra cost is worthwhile.
        type kv struct {
                k string
                t time.Time
        }
        all := make([]kv, 0, len(cache))
        for k, e := range cache {
                all = append(all, kv{k, e.cachedAt})
        }
        sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
        // Target len after sweep: 75 % of cap, so we don't sweep on every insert
        // once we are at the bound. Ceiling-divide rounds defensively down.
        target := (cacheMaxEntries * 3) / 4
        toDelete := len(cache) - target
        for i := 0; i < toDelete && i < len(all); i++ {
                delete(cache, all[i].k)
        }
}

// rdnsLookup is a swappable hook for tests. Production wires net.LookupAddr.
var rdnsLookup = net.LookupAddr

// fwdLookup is a swappable hook for tests. Production wires net.LookupHost.
var fwdLookup = net.LookupHost

// Classify performs verified-bot classification on the (userAgent, clientIP)
// tuple. Results are memoised per-IP for 1 hour to avoid repeated DNS work.
//
// Empty inputs return ClassHuman with Verified=false — the safe default.
func Classify(userAgent, clientIP string) Result {
        // Cap user-agent length before any further work — pathological multi-KiB
        // UAs are an amplification vector both for the cache key and the
        // classification regex paths.
        if len(userAgent) > maxUALen {
                userAgent = userAgent[:maxUALen]
        }
        uaLower := strings.ToLower(strings.TrimSpace(userAgent))
        ip := strings.TrimSpace(clientIP)

        cacheKey := uaLower + "|" + ip
        cacheMu.RLock()
        if entry, ok := cache[cacheKey]; ok && time.Since(entry.cachedAt) < cacheTTL {
                cacheMu.RUnlock()
                return entry.result
        }
        cacheMu.RUnlock()

        res := classifyUncached(uaLower, ip, userAgent)

        cacheMu.Lock()
        // Sweep before insert if we've grown past the bound; cheap when small.
        if len(cache) >= cacheMaxEntries {
                sweepCacheLocked(time.Now())
        }
        cache[cacheKey] = cacheEntry{result: res, cachedAt: time.Now()}
        cacheMu.Unlock()
        return res
}

func classifyUncached(uaLower, ip, originalUA string) Result {
        res := Result{UA: originalUA, IP: ip, Class: ClassHuman}

        if uaLower == "" {
                // Empty UA on a real HTTP request is itself a strong "investigate" signal
                // — browsers always send a UA. But we don't have enough to call it bot.
                res.Class = ClassInvestigate
                return res
        }

        // Step 1: try to match a known bot rule.
        for _, rule := range botRules {
                if !strings.Contains(uaLower, rule.UAMatch) {
                        continue
                }
                res.BotName = rule.BotName
                if rule.UAOnly {
                        res.Class = ClassVerifiedBot
                        res.Verified = true
                        return res
                }
                // IP verification required.
                if ip == "" || verifyRDNS(ip, rule.RDNSSuffixes) {
                        if ip == "" {
                                // No IP to verify — degrade to Investigate, not VerifiedBot.
                                res.Class = ClassInvestigate
                                return res
                        }
                        res.Class = ClassVerifiedBot
                        res.Verified = true
                        return res
                }
                // UA claims a known operator but PTR did not verify — likely spoofed.
                res.Class = ClassInvestigate
                return res
        }

        // Step 2: no known operator rule matched — check generic bot signals.
        for _, sig := range investigateUASignals {
                if strings.Contains(uaLower, sig) {
                        res.Class = ClassInvestigate
                        return res
                }
        }

        // Step 3: nothing bot-like in the UA — treat as human.
        return res
}

// verifyRDNS performs the reverse-DNS + forward-DNS roundtrip check.
//
// Returns true iff:
//  1. PTR(ip) returns a hostname whose lowercased FQDN ends with one of the
//     allowed suffixes (suffixes are matched against ".host" form so the rule
//     ".googlebot.com" does NOT match "evil-googlebot.com"), AND
//  2. forward-DNS lookup of that hostname returns the same IP back.
//
// Either lookup failing, or no matching suffix, returns false.
func verifyRDNS(ip string, allowedSuffixes []string) bool {
        if len(allowedSuffixes) == 0 {
                return false
        }
        names, err := rdnsLookup(ip)
        if err != nil || len(names) == 0 {
                return false
        }
        for _, name := range names {
                nameLower := strings.ToLower(strings.TrimSuffix(name, "."))
                // Prepend "." so suffix match is anchored at a label boundary.
                nameAnchored := "." + nameLower
                matchesSuffix := false
                for _, suffix := range allowedSuffixes {
                        if strings.HasSuffix(nameAnchored, strings.ToLower(suffix)) {
                                matchesSuffix = true
                                break
                        }
                }
                if !matchesSuffix {
                        continue
                }
                // Forward-resolve back and confirm IP matches.
                addrs, err := fwdLookup(nameLower)
                if err != nil {
                        continue
                }
                for _, addr := range addrs {
                        if addr == ip {
                                return true
                        }
                }
        }
        return false
}

// PurgeCache clears the verification cache. Intended for tests; production
// rotates entries by TTL.
func PurgeCache() {
        cacheMu.Lock()
        cache = make(map[string]cacheEntry)
        cacheMu.Unlock()
}
