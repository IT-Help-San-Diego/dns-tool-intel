// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package dnsclient

import (
        "context"
        "encoding/json"
        "fmt"
        "io"
        "log/slog"
        "net"
        "net/http"
        "net/url"
        "sort"
        "strings"
        "sync"
        "time"

        "codeberg.org/miekg/dns"
        "codeberg.org/miekg/dns/dnsutil"
)

type ResolverConfig struct {
        Name string
        IP   string
        DoH  string
}

// S1313 suppressed: these are well-known public DNS resolver IPs — intentional
// hardcoded constants for the multi-resolver consensus architecture (RFC-documented services).
// SECINTENT-003: Hardcoded DNS resolver IPs
var DefaultResolvers = []ResolverConfig{
        {Name: "Cloudflare", IP: resolverCloudflare, DoH: "https://cloudflare-dns.com/dns-query"},
        {Name: "Google", IP: resolverGoogle, DoH: "https://dns.google/resolve"},
        {Name: "Quad9", IP: "9.9.9.10"},
        {Name: "OpenDNS", IP: "208.67.222.222"},
        {Name: "DNS4EU", IP: "86.54.11.100", DoH: "https://unfiltered.joindns4.eu/dns-query"},
}

var UserAgent = "DNSTool-DomainSecurityAudit/1.0 (+https://dnstool.it-help.tech)"

func SetUserAgentVersion(version string) {
        UserAgent = fmt.Sprintf("DNSTool-DomainSecurityAudit/%s (+https://dnstool.it-help.tech)", version)
}

const (
        dohGoogleURL    = "https://dns.google/resolve"
        defaultTimeout  = 2 * time.Second
        defaultLifetime = 4 * time.Second
        consensusWait   = 5 * time.Second

        resolverCloudflare = "1.1.1.1"
        resolverGoogle     = "8.8.8.8"

        dnsPort      = "53"
        protoUDP     = "udp"
        protoTCP     = "tcp"
        dohTypeRRSIG = 46

        // errTruncatedTCP marks a TC=1 UDP answer whose TCP retry also failed.
        // It is a non-empty, non-NXDOMAIN error string so classifyResolverResult
        // folds it into outcomeTransient — never an authoritative absence built
        // from the partial UDP answer.
        errTruncatedTCP = "TRUNCATED: TC=1 and TCP fallback failed"

        mapKeyDiscrepancies = "discrepancies"
        mapKeyError         = "error"
        mapKeyDomain        = "domain"
        mapKeyResolver      = "resolver"
        dnsTypeTXT          = "TXT"
)

type ConsensusResult struct {
        Records         []string            `json:"records"`
        Consensus       bool                `json:"consensus"`
        ResolverCount   int                 `json:"resolver_count"`
        Discrepancies   []string            `json:"discrepancies"`
        ResolverResults map[string][]string `json:"resolver_results"`
}

type RecordWithTTL struct {
        Records       []string
        TTL           *uint32
        Authenticated bool
}

type ADFlagResult struct {
        ADFlag       bool              `json:"ad_flag"`
        Validated    bool              `json:"validated"`
        ResolverUsed *string           `json:"resolver_used"`
        Error        *string           `json:"error"`
        State        string            `json:"state"`
        ResolverAD   map[string]string `json:"resolver_ad"`
}

type Client struct {
        resolvers  []ResolverConfig
        httpClient *http.Client
        timeout    time.Duration
        lifetime   time.Duration

        cacheMu  sync.RWMutex
        cache    map[string]cacheEntry
        cacheTTL time.Duration
        cacheMax int
}

type cacheEntry struct {
        data      []string
        timestamp time.Time
}

type Option func(*Client)

func WithResolvers(r []ResolverConfig) Option {
        return func(c *Client) { c.resolvers = r }
}

func WithHTTPClient(h *http.Client) Option {
        return func(c *Client) { c.httpClient = h }
}

func WithTimeout(t time.Duration) Option {
        return func(c *Client) { c.timeout = t }
}

func WithCacheTTL(t time.Duration) Option {
        return func(c *Client) { c.cacheTTL = t }
}

func New(opts ...Option) *Client {
        c := &Client{
                resolvers: DefaultResolvers,
                httpClient: &http.Client{
                        Timeout: 10 * time.Second,
                        Transport: &http.Transport{
                                MaxIdleConns:        20,
                                IdleConnTimeout:     120 * time.Second,
                                DisableKeepAlives:   false,
                                MaxIdleConnsPerHost: 5,
                        },
                },
                timeout:  defaultTimeout,
                lifetime: defaultLifetime,
                cache:    make(map[string]cacheEntry),
                cacheTTL: 0,
                cacheMax: 0,
        }
        for _, o := range opts {
                o(c)
        }
        return c
}

func (c *Client) Warmup() {
        ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
        defer cancel()
        req, err := http.NewRequestWithContext(ctx, "GET", dohGoogleURL, nil)
        if err != nil {
                return
        }
        q := url.Values{}
        q.Set("name", "example.com")
        q.Set("type", "A")
        req.URL.RawQuery = q.Encode()
        req.Header.Set("Accept", "application/dns-json")
        req.Header.Set("User-Agent", UserAgent)
        resp, err := c.httpClient.Do(req)
        if err != nil {
                slog.Debug("DoH warmup failed", mapKeyError, err)
                return
        }
        safeClose(resp.Body, "doh-warmup")
        slog.Info("DoH connection pool warmed up")
}

func (c *Client) cacheGet(key string) ([]string, bool) {
        c.cacheMu.RLock()
        defer c.cacheMu.RUnlock()
        entry, ok := c.cache[key]
        if !ok {
                return nil, false
        }
        if time.Since(entry.timestamp) > c.cacheTTL {
                return nil, false
        }
        return entry.data, true
}

func (c *Client) cacheSet(key string, data []string) {
        c.cacheMu.Lock()
        defer c.cacheMu.Unlock()
        c.cache[key] = cacheEntry{data: data, timestamp: time.Now()}
        if len(c.cache) > c.cacheMax {
                cutoff := time.Now().Add(-c.cacheTTL)
                for k, v := range c.cache {
                        if v.timestamp.Before(cutoff) {
                                delete(c.cache, k)
                        }
                }
        }
}

func dnsTypeFromString(recordType string) (uint16, error) {
        switch strings.ToUpper(recordType) {
        case "A":
                return dns.TypeA, nil
        case "AAAA":
                return dns.TypeAAAA, nil
        case "MX":
                return dns.TypeMX, nil
        case dnsTypeTXT:
                return dns.TypeTXT, nil
        case "NS":
                return dns.TypeNS, nil
        case "CNAME":
                return dns.TypeCNAME, nil
        case "CAA":
                return dns.TypeCAA, nil
        case "SOA":
                return dns.TypeSOA, nil
        case "SRV":
                return dns.TypeSRV, nil
        case "TLSA":
                return dns.TypeTLSA, nil
        case "DNSKEY":
                return dns.TypeDNSKEY, nil
        case "DS":
                return dns.TypeDS, nil
        case "RRSIG":
                return dns.TypeRRSIG, nil
        case "NSEC":
                return dns.TypeNSEC, nil
        case "NSEC3":
                return dns.TypeNSEC3, nil
        case "PTR":
                return dns.TypePTR, nil
        default:
                return 0, fmt.Errorf("unsupported record type: %s", recordType)
        }
}

func rrToString(rr dns.RR) string {
        switch v := rr.(type) {
        case *dns.A:
                return v.A.Addr.String()
        case *dns.AAAA:
                return v.AAAA.Addr.String()
        case *dns.MX:
                return fmt.Sprintf("%d %s", v.MX.Preference, v.MX.Mx)
        case *dns.TXT:
                return strings.Join(v.TXT.Txt, "")
        case *dns.NS:
                return v.NS.Ns
        case *dns.CNAME:
                return v.CNAME.Target
        case *dns.CAA:
                return fmt.Sprintf("%d %s \"%s\"", v.CAA.Flag, v.CAA.Tag, v.CAA.Value)
        case *dns.SOA:
                return fmt.Sprintf("%s %s %d %d %d %d %d", v.SOA.Ns, v.SOA.Mbox, v.SOA.Serial, v.SOA.Refresh, v.SOA.Retry, v.SOA.Expire, v.SOA.Minttl)
        case *dns.SRV:
                return fmt.Sprintf("%d %d %d %s", v.SRV.Priority, v.SRV.Weight, v.SRV.Port, v.SRV.Target)
        case *dns.TLSA:
                return fmt.Sprintf("%d %d %d %s", v.TLSA.Usage, v.TLSA.Selector, v.TLSA.MatchingType, v.TLSA.Certificate)
        case *dns.DNSKEY:
                return v.String()
        case *dns.DS:
                return v.String()
        case *dns.RRSIG:
                return v.String()
        default:
                hdr := rr.Header()
                full := rr.String()
                prefix := hdr.String()
                return strings.TrimPrefix(full, prefix)
        }
}

func (c *Client) QueryDNS(ctx context.Context, recordType, domain string) []string {
        if domain == "" || recordType == "" {
                return nil
        }

        cacheKey := fmt.Sprintf("%s:%s", strings.ToUpper(recordType), strings.ToLower(domain))
        if cached, ok := c.cacheGet(cacheKey); ok {
                return cached
        }

        results := c.dohQuery(ctx, domain, recordType)
        if len(results) > 0 {
                c.cacheSet(cacheKey, results)
                return results
        }

        results = c.parallelUDPQuery(ctx, domain, recordType)
        if len(results) > 0 {
                c.cacheSet(cacheKey, results)
        }
        return results
}

func (c *Client) parallelUDPQuery(ctx context.Context, domain, recordType string) []string {
        type udpResult struct {
                records []string
        }
        ch := make(chan udpResult, len(c.resolvers))
        qctx, cancel := context.WithTimeout(ctx, defaultLifetime)
        defer cancel()

        for _, resolver := range c.resolvers {
                go func(ip string) {
                        ch <- udpResult{records: c.udpQuery(qctx, domain, recordType, ip)}
                }(resolver.IP)
        }

        for range c.resolvers {
                r := <-ch
                if len(r.records) > 0 {
                        return r.records
                }
        }
        return nil
}

// LookupStatus classifies the outcome of a DNS resolution attempt so callers can
// tell "the record is genuinely absent" apart from "the lookup failed". This
// distinction is required by RFC 7489 §7.1 external-reporting authorization,
// where asserting "not authorized" from a probe that never completed is a false
// negative — see QueryDNSWithStatus.
type LookupStatus int

const (
        // LookupError means the lookup was indeterminate (timeout / SERVFAIL /
        // network error). Callers MUST NOT infer a record's absence from this.
        LookupError LookupStatus = iota
        // LookupResolved means at least one resolver returned answer records.
        LookupResolved
        // LookupAbsent means a resolver authoritatively reported no such record
        // (NXDOMAIN, or NOERROR with no matching answer / NODATA) — the record is
        // genuinely not published.
        LookupAbsent
        // LookupConflict means resolvers returned DIFFERENT present record sets with
        // no strict plurality winner — the record is mid-propagation / "in flux".
        // Like LookupError it is INDETERMINATE: callers MUST NOT infer absence from it
        // (a stale recursive cache disagreeing with the live record is not an
        // authoritative answer). It is kept distinct from LookupError so the report can
        // say "resolvers disagree / DNS in flux" rather than "lookup failed".
        LookupConflict
)

// resolverOutcome is the per-resolver classification used to fold many resolver
// answers into a single LookupStatus.
type resolverOutcome int

const (
        // outcomeTransient — the resolver could not give an authoritative answer
        // (timeout, SERVFAIL, REFUSED, FORMERR, network error). It says nothing about
        // whether the record exists and MUST NOT be read as absence.
        outcomeTransient resolverOutcome = iota
        // outcomeAbsent — an authoritative "no record" (NXDOMAIN, or NOERROR/NODATA).
        outcomeAbsent
        // outcomeResolved — the resolver returned answer records.
        outcomeResolved
)

// classifyResolverResult maps a single resolver's (errStr, records) into one of
// three outcomes. errStr is "" on success (NOERROR), "NXDOMAIN" for NXDOMAIN, and
// the RCODE name (e.g. "SERVFAIL", "REFUSED") or an error string for any other
// failure — so only "" and "NXDOMAIN" count as authoritative absence.
func classifyResolverResult(errStr string, records []string) resolverOutcome {
        switch {
        case errStr == "" && len(records) > 0:
                return outcomeResolved
        case errStr == "" || errStr == "NXDOMAIN":
                return outcomeAbsent
        default:
                return outcomeTransient
        }
}

// canonicalRecordKey builds an order-independent key for a resolved record set so
// two resolvers that return the same records in a different order still count as
// agreeing. The sort is on a copy, so the caller's record order is untouched.
func canonicalRecordKey(records []string) string {
        cp := append([]string(nil), records...)
        sort.Strings(cp)
        return strings.Join(cp, "\x00")
}

// consensusOutcome is the result of folding many resolvers' answers into one verdict.
type consensusOutcome int

const (
        // consensusTransient — no resolver cast a usable vote (all timed out / SERVFAIL).
        consensusTransient consensusOutcome = iota
        // consensusResolved — a single present record set is the strict plurality winner.
        consensusResolved
        // consensusAbsent — no resolver returned a present record set, but at least one
        // authoritatively reported the record absent (NXDOMAIN / NODATA).
        consensusAbsent
        // consensusConflict — resolvers returned DIFFERENT present record sets with no
        // strict plurality winner: the record is mid-propagation / in flux. Presenting
        // any single resolver's value as truth would be a precision violation, so it is
        // treated as indeterminate (a stale cache is not an authoritative answer).
        consensusConflict
)

// foldResolverConsensus folds per-resolver outcomes into a single consensus, replacing
// the old "first resolver to answer wins" race in which one stale recursive cache
// could decide a security verdict even when the majority of independent resolvers
// agreed on the live record. keys[i] is the canonical key of resolver i's present
// record set (meaningful only when outcomes[i] == outcomeResolved).
//
// Precision-over-recall rules:
//   - Among resolvers that returned a PRESENT record set, the value with the most
//     votes wins, but ONLY when it is a strict plurality (more votes than any other
//     present value). A tie for the top present value is consensusConflict.
//   - A present answer always outranks an absence: absences are weighed only when no
//     resolver returned a present record set, so an absence is never fabricated from
//     a present-vs-absent disagreement.
//   - Transient failures abstain: a failing resolver can neither win nor break a tie.
//
// It returns the index (into keys/outcomes) of a representative winning resolver, or
// -1 when there is no single winner, plus the folded outcome.
func foldResolverConsensus(keys []string, outcomes []resolverOutcome) (int, consensusOutcome) {
        counts := make(map[string]int)
        firstIdx := make(map[string]int)
        anyPresent := false
        anyAbsent := false
        for i, oc := range outcomes {
                switch oc {
                case outcomeResolved:
                        anyPresent = true
                        counts[keys[i]]++
                        if _, seen := firstIdx[keys[i]]; !seen {
                                firstIdx[keys[i]] = i
                        }
                case outcomeAbsent:
                        anyAbsent = true
                }
        }

        if anyPresent {
                topKey := ""
                topCount := 0
                tied := false
                for k, n := range counts {
                        switch {
                        case n > topCount:
                                topKey, topCount, tied = k, n, false
                        case n == topCount:
                                tied = true
                        }
                }
                if tied {
                        return -1, consensusConflict
                }
                return firstIdx[topKey], consensusResolved
        }

        if anyAbsent {
                return -1, consensusAbsent
        }
        return -1, consensusTransient
}

// QueryDNSWithStatus resolves recordType/domain and classifies the outcome.
// Unlike QueryDNS — which returns an empty slice for BOTH a genuinely-absent
// record and a failed lookup — this reports a transient failure as LookupError,
// so callers never fabricate an "absent" verdict from a probe that timed out.
func (c *Client) QueryDNSWithStatus(ctx context.Context, recordType, domain string) ([]string, LookupStatus) {
        if domain == "" || recordType == "" {
                return nil, LookupError
        }

        cacheKey := fmt.Sprintf("%s:%s", strings.ToUpper(recordType), strings.ToLower(domain))
        if cached, ok := c.cacheGet(cacheKey); ok {
                return cached, LookupResolved
        }

        type res struct {
                records []string
                errStr  string
        }
        ch := make(chan res, len(c.resolvers))
        qctx, cancel := context.WithTimeout(ctx, defaultLifetime)
        defer cancel()

        for _, resolver := range c.resolvers {
                go func(ip string) {
                        _, records, errStr := c.querySingleResolver(qctx, domain, recordType, ip)
                        ch <- res{records: records, errStr: errStr}
                }(resolver.IP)
        }

        results := make([]res, 0, len(c.resolvers))
        for range c.resolvers {
                results = append(results, <-ch)
        }

        keys := make([]string, len(results))
        outcomes := make([]resolverOutcome, len(results))
        for i, r := range results {
                outcomes[i] = classifyResolverResult(r.errStr, r.records)
                if outcomes[i] == outcomeResolved {
                        keys[i] = canonicalRecordKey(r.records)
                }
        }

        // Consensus, not first-to-answer: the value the most resolvers agree on wins, so
        // a single stale recursive cache can no longer decide the verdict while the
        // majority of independent resolvers hold the live record. A no-majority split is
        // LookupConflict (indeterminate / in flux), never one resolver's value as truth.
        switch idx, outcome := foldResolverConsensus(keys, outcomes); outcome {
        case consensusResolved:
                c.cacheSet(cacheKey, results[idx].records)
                return results[idx].records, LookupResolved
        case consensusAbsent:
                return nil, LookupAbsent
        case consensusConflict:
                return nil, LookupConflict
        }

        // Every UDP resolver failed transiently. Use DoH ONLY as positive
        // confirmation: records => resolved. Absence is never asserted from here,
        // because the DoH path also collapses errors into an empty answer.
        if dohResults := c.dohQuery(ctx, domain, recordType); len(dohResults) > 0 {
                c.cacheSet(cacheKey, dohResults)
                return dohResults, LookupResolved
        }
        return nil, LookupError
}

func (c *Client) QueryDNSWithTTL(ctx context.Context, recordType, domain string) RecordWithTTL {
        if domain == "" || recordType == "" {
                return RecordWithTTL{}
        }

        result := c.dohQueryWithTTL(ctx, domain, recordType)
        if len(result.Records) > 0 {
                return result
        }

        return c.parallelUDPQueryWithTTL(ctx, domain, recordType)
}

func (c *Client) parallelUDPQueryWithTTL(ctx context.Context, domain, recordType string) RecordWithTTL {
        ch := make(chan RecordWithTTL, len(c.resolvers))
        qctx, cancel := context.WithTimeout(ctx, defaultLifetime)
        defer cancel()

        for _, resolver := range c.resolvers {
                go func(ip string) {
                        ch <- c.udpQueryWithTTL(qctx, domain, recordType, ip)
                }(resolver.IP)
        }

        for range c.resolvers {
                r := <-ch
                if len(r.Records) > 0 {
                        return r
                }
        }
        return RecordWithTTL{}
}

// QueryDNSWithTTLStatus is the tri-state, TTL/AD-preserving query path. It folds
// every resolver's outcome through classifyResolverResult exactly like
// QueryDNSWithStatus — a single resolved answer short-circuits, absence is only
// asserted from an authoritative NXDOMAIN/NODATA, and an all-transient sweep
// reports LookupError — but unlike QueryDNSWithStatus it returns the full
// RecordWithTTL (TTL + Authenticated) so DANE/DNSSEC can both render the TTL and
// tell "record absent" apart from "lookup failed". DoH is used as positive
// confirmation only, never to assert absence.
func (c *Client) QueryDNSWithTTLStatus(ctx context.Context, recordType, domain string) (RecordWithTTL, LookupStatus) {
        if domain == "" || recordType == "" {
                return RecordWithTTL{}, LookupError
        }

        type res struct {
                rec    RecordWithTTL
                errStr string
        }
        ch := make(chan res, len(c.resolvers))
        qctx, cancel := context.WithTimeout(ctx, defaultLifetime)
        defer cancel()

        for _, resolver := range c.resolvers {
                go func(ip string) {
                        rec, errStr := c.udpQueryWithTTLStatus(qctx, domain, recordType, ip)
                        ch <- res{rec: rec, errStr: errStr}
                }(resolver.IP)
        }

        results := make([]res, 0, len(c.resolvers))
        for range c.resolvers {
                results = append(results, <-ch)
        }

        keys := make([]string, len(results))
        outcomes := make([]resolverOutcome, len(results))
        for i, r := range results {
                outcomes[i] = classifyResolverResult(r.errStr, r.rec.Records)
                if outcomes[i] == outcomeResolved {
                        keys[i] = canonicalRecordKey(r.rec.Records)
                }
        }

        // Consensus, not first-to-answer (see QueryDNSWithStatus): the majority record
        // set wins; a no-majority split is LookupConflict (indeterminate / in flux).
        switch idx, outcome := foldResolverConsensus(keys, outcomes); outcome {
        case consensusResolved:
                return results[idx].rec, LookupResolved
        case consensusAbsent:
                return RecordWithTTL{}, LookupAbsent
        case consensusConflict:
                return RecordWithTTL{}, LookupConflict
        }

        // Every UDP resolver failed transiently. Use DoH ONLY as positive
        // confirmation: records => resolved. Absence is never asserted here.
        if doh := c.dohQueryWithTTL(ctx, domain, recordType); len(doh.Records) > 0 {
                return doh, LookupResolved
        }
        return RecordWithTTL{}, LookupError
}

func (c *Client) querySingleResolver(ctx context.Context, domain, recordType, resolverIP string) (string, []string, string) {
        qtype, err := dnsTypeFromString(recordType)
        if err != nil {
                return resolverIP, nil, err.Error()
        }

        fqdn := dnsutil.Fqdn(domain)
        msg := dns.NewMsg(fqdn, qtype)
        msg.RecursionDesired = true
        msg.UDPSize, msg.Security = 4096, true

        client := newDNSClient(c.timeout)

        r, _, err := client.Exchange(ctx, msg, protoUDP, net.JoinHostPort(resolverIP, dnsPort))
        if err != nil {
                return resolverIP, nil, err.Error()
        }

        // RFC 7766 §5 / RFC 1035 §4.2.1: a truncated UDP answer (TC=1) carries an
        // incomplete record set and MUST be retried over TCP — the partial UDP
        // answers are discarded. Domains that deliberately overflow the UDP/EDNS
        // buffer with oversized TXT sets (e.g. apple.com publishes multi-KB junk
        // TXT records "to truncate UDP responses") otherwise drop records such as
        // SPF, yielding a false "no SPF record" verdict. If the TCP retry itself
        // fails the partial UDP answer is NOT trusted — we surface a transient
        // error so no caller fabricates an "absent" verdict from an incomplete set.
        if r.Truncated {
                rt, _, errt := client.Exchange(ctx, msg, protoTCP, net.JoinHostPort(resolverIP, dnsPort))
                if errt != nil || rt == nil {
                        return resolverIP, nil, errTruncatedTCP
                }
                r = rt
        }

        if r.Rcode == dns.RcodeNameError {
                return resolverIP, nil, "NXDOMAIN"
        }

        // Any non-success RCODE other than NXDOMAIN (SERVFAIL, REFUSED, FORMERR, …)
        // is a server-side failure, NOT an authoritative answer. Surface it as a
        // transient error so callers never mistake it for "record is absent".
        if r.Rcode != dns.RcodeSuccess {
                rcodeName, ok := dns.RcodeToString[r.Rcode]
                if !ok {
                        rcodeName = fmt.Sprintf("RCODE%d", r.Rcode)
                }
                return resolverIP, nil, rcodeName
        }

        var results []string
        for _, rr := range r.Answer {
                // RFC 4035: a DO=1 query (msg.Security = true above) can return RRSIG records
                // alongside the answer. They are signatures, not content — drop them unless
                // RRSIG itself was requested, so a signature never leaks into a record set
                // (e.g. an RRSIG string contaminating the DMARC/SPF records[]). Mirrors the
                // filter already applied in udpQueryWithTTLStatus.
                if _, isRRSIG := rr.(*dns.RRSIG); isRRSIG && qtype != dns.TypeRRSIG {
                        continue
                }
                s := rrToString(rr)
                if s != "" {
                        results = append(results, s)
                }
        }
        sort.Strings(results)
        return resolverIP, results, ""
}

func (c *Client) QueryWithConsensus(ctx context.Context, recordType, domain string) ConsensusResult {
        if domain == "" || recordType == "" {
                return ConsensusResult{Consensus: true}
        }

        type resolverResult struct {
                name    string
                results []string
                err     string
        }

        ch := make(chan resolverResult, len(c.resolvers))
        ctx2, cancel := context.WithTimeout(ctx, consensusWait)
        defer cancel()

        for _, r := range c.resolvers {
                go func(resolver ResolverConfig) {
                        _, results, errStr := c.querySingleResolver(ctx2, domain, recordType, resolver.IP)
                        ch <- resolverResult{name: resolver.Name, results: results, err: errStr}
                }(r)
        }

        resolverResults := make(map[string][]string)
        for i := 0; i < len(c.resolvers); i++ {
                select {
                case rr := <-ch:
                        if rr.err == "" {
                                resolverResults[rr.name] = rr.results
                        } else {
                                slog.Debug("resolver error", mapKeyResolver, rr.name, "record_type", recordType, mapKeyDomain, domain, mapKeyError, rr.err)
                        }
                case <-ctx2.Done():
                        break
                }
        }

        if len(resolverResults) == 0 {
                dohResults := c.dohQuery(ctx, domain, recordType)
                return ConsensusResult{
                        Records:         dohResults,
                        Consensus:       true,
                        ResolverCount:   boolToInt(len(dohResults) > 0),
                        ResolverResults: map[string][]string{"DoH": dohResults},
                }
        }

        consensusRecords, allSame, discrepancies := findConsensus(resolverResults)
        if !allSame {
                slog.Warn("DNS discrepancy", mapKeyDomain, domain, "record_type", recordType, mapKeyDiscrepancies, discrepancies)
        }

        return ConsensusResult{
                Records:         consensusRecords,
                Consensus:       allSame,
                ResolverCount:   len(resolverResults),
                Discrepancies:   discrepancies,
                ResolverResults: resolverResults,
        }
}

func findConsensus(resolverResults map[string][]string) (records []string, allSame bool, discrepancies []string) {
        resultSets := make(map[string]int)
        for _, results := range resolverResults {
                key := strings.Join(results, "|")
                resultSets[key]++
        }

        var mostCommonKey string
        var mostCommonCount int
        for key, count := range resultSets {
                if count > mostCommonCount {
                        mostCommonKey = key
                        mostCommonCount = count
                }
        }

        if mostCommonKey != "" {
                records = strings.Split(mostCommonKey, "|")
                if len(records) == 1 && records[0] == "" {
                        records = nil
                }
        }

        allSame = len(resultSets) <= 1
        if !allSame {
                for name, results := range resolverResults {
                        key := strings.Join(results, "|")
                        if key != mostCommonKey {
                                discrepancies = append(discrepancies, fmt.Sprintf("%s returned different results: %v", name, results))
                        }
                }
        }
        return
}

func (c *Client) ValidateResolverConsensus(ctx context.Context, domain string) map[string]any {
        criticalTypes := []string{"A", "MX", "NS", dnsTypeTXT}
        result := map[string]any{
                "consensus_reached":    true,
                "resolvers_queried":    len(c.resolvers),
                "checks_performed":     0,
                mapKeyDiscrepancies:    []string{},
                "per_record_consensus": map[string]any{},
        }

        type checkResult struct {
                recordType string
                consensus  ConsensusResult
                err        error
        }

        ch := make(chan checkResult, len(criticalTypes))
        ctx2, cancel := context.WithTimeout(ctx, 8*time.Second)
        defer cancel()

        for _, rt := range criticalTypes {
                go func(recordType string) {
                        cr := c.QueryWithConsensus(ctx2, recordType, domain)
                        ch <- checkResult{recordType: recordType, consensus: cr}
                }(rt)
        }

        perRecord := make(map[string]any)
        var allDisc []string
        checksPerformed := 0
        consensusReached := true

        for i := 0; i < len(criticalTypes); i++ {
                select {
                case cr := <-ch:
                        checksPerformed++
                        perRecord[cr.recordType] = map[string]any{
                                "consensus":         cr.consensus.Consensus,
                                "resolver_count":    cr.consensus.ResolverCount,
                                mapKeyDiscrepancies: cr.consensus.Discrepancies,
                        }
                        if !cr.consensus.Consensus {
                                consensusReached = false
                                for _, d := range cr.consensus.Discrepancies {
                                        allDisc = append(allDisc, fmt.Sprintf("%s: %s", cr.recordType, d))
                                }
                        }
                case <-ctx2.Done():
                        break
                }
        }

        result["consensus_reached"] = consensusReached
        result["checks_performed"] = checksPerformed
        result[mapKeyDiscrepancies] = allDisc
        result["per_record_consensus"] = perRecord
        return result
}

func (c *Client) CheckDNSSECADFlag(ctx context.Context, domain string) ADFlagResult {
        result := ADFlagResult{ResolverAD: make(map[string]string)}

        var secure, adAbsent, bogus int

        for _, r := range c.resolvers {
                fqdn := dnsutil.Fqdn(domain)
                msg := dns.NewMsg(fqdn, dns.TypeA)
                msg.RecursionDesired = true
                msg.UDPSize, msg.Security = 4096, true

                dnsClient := newDNSClient(3 * time.Second)

                resp, _, err := dnsClient.Exchange(ctx, msg, protoUDP, net.JoinHostPort(r.IP, dnsPort))
                if err != nil {
                        if isNXDomain(resp) {
                                result.ResolverAD[r.Name] = "nxdomain"
                                continue
                        }
                        slog.Debug("AD flag check failed", mapKeyResolver, r.IP, mapKeyError, err)
                        result.ResolverAD[r.Name] = "unmeasured"
                        continue
                }

                if resp.Rcode == dns.RcodeNameError {
                        result.ResolverAD[r.Name] = "nxdomain"
                        continue
                }

                // SERVFAIL from a validating resolver means DNSSEC validation
                // FAILED (expired RRSIG, broken chain, unsupported algorithm) — a
                // distinct "bogus" signal, not "ad_absent" and not a failed check.
                // The old code had no SERVFAIL branch, so bogus fell through to
                // ADFlag=false and read identically to an AD-absent response (RFC 4033 §5:
                // bogus is signaled via RCODE=2 / Server Failure).
                if resp.Rcode == dns.RcodeServerFailure {
                        result.ResolverAD[r.Name] = "bogus"
                        bogus++
                        continue
                }

                if resp.Rcode != dns.RcodeSuccess {
                        slog.Debug("AD flag check non-success RCODE", mapKeyResolver, r.IP, "rcode", resp.Rcode)
                        result.ResolverAD[r.Name] = "unmeasured"
                        continue
                }

                if len(resp.Answer) == 0 {
                        msg2 := dns.NewMsg(fqdn, dns.TypeSOA)
                        msg2.RecursionDesired = true
                        msg2.UDPSize, msg2.Security = 4096, true
                        r2, _, err2 := dnsClient.Exchange(ctx, msg2, protoUDP, net.JoinHostPort(r.IP, dnsPort))
                        if err2 == nil {
                                resp = r2
                        }
                }

                if resp.AuthenticatedData {
                        result.ResolverAD[r.Name] = "secure"
                        secure++
                } else {
                        result.ResolverAD[r.Name] = "ad_absent"
                        adAbsent++
                }
        }

        // Aggregate classification. RFC 4033 §5 defines four validation states
        // (Secure / Insecure / Bogus / Indeterminate); we surface the wire signal
        // honestly and never overclaim where the RFC says the signal is ambiguous:
        //   "secure"     — AD bit set (RFC: Secure).
        //   "ad_absent"  — AD bit clear; RFC 4033 §5 notes the signaling mechanism
        //                  cannot distinguish Insecure from Indeterminate, so we
        //                  record the observation (AD absent) rather than naming a
        //                  state we cannot prove.
        //   "bogus"      — SERVFAIL (RFC 4033 §5: bogus is signaled via RCODE=2).
        //   "split"      — OUR term: validating resolvers disagree.
        //   "unmeasured" — OUR term: no resolver cast a usable vote.
        switch {
        case bogus > 0:
                result.State = "bogus"
                result.ADFlag = false
                result.Validated = false
        case secure+adAbsent == 0:
                result.State = "unmeasured"
                result.ADFlag = false
                result.Validated = false
                errStr := "Could not verify AD flag"
                result.Error = &errStr
        case adAbsent == 0 && secure > 0:
                result.State = "secure"
                result.ADFlag = true
                result.Validated = true
        case secure == 0 && adAbsent > 0:
                result.State = "ad_absent"
                result.ADFlag = false
                result.Validated = false
        default:
                result.State = "split"
                result.ADFlag = false
                result.Validated = false
        }

        return result
}

func (c *Client) ExchangeContext(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
        resolverAddr := net.JoinHostPort(c.resolvers[0].IP, dnsPort)
        return c.exchangeWithFallback(ctx, msg, resolverAddr)
}

func (c *Client) exchangeWithFallback(ctx context.Context, msg *dns.Msg, resolverAddr string) (*dns.Msg, error) {
        client := newDNSClient(c.timeout)
        r, _, err := client.Exchange(ctx, msg, protoUDP, resolverAddr)
        if err == nil {
                return r, nil
        }

        slog.Debug("UDP query failed, falling back to TCP", mapKeyResolver, resolverAddr, mapKeyError, err)
        r, _, err = client.Exchange(ctx, msg, "tcp", resolverAddr)
        return r, err
}

// QueryNSID sends an RFC 5001 NSID probe to a single nameserver and returns the
// server's self-identification string (hex-encoded) plus the round-trip time in
// milliseconds. NSID is how an anycast node identifies itself, so this is the
// cheapest way to audit "which node answered me" from a single vantage point. A
// server that does not implement NSID returns an empty string with no error —
// the absence of an NSID is a capability gap, not a failure (RFC 5001 makes the
// option optional). miekg/dns v2 models EDNS0 options as pseudo-RRs in msg.Pseudo.
// nameserverAddr is a host:port string.
func (c *Client) QueryNSID(ctx context.Context, nameserverAddr string) (nsid string, rttMs int64, err error) {
        msg := dns.NewMsg(".", dns.TypeNS)
        msg.RecursionDesired = false
        msg.Pseudo = append(msg.Pseudo, &dns.NSID{})

        client := newDNSClient(c.timeout)
        start := time.Now()
        r, _, err := client.Exchange(ctx, msg, protoUDP, nameserverAddr)
        rttMs = time.Since(start).Milliseconds()
        if err != nil {
                return "", rttMs, err
        }
        for _, rr := range r.Pseudo {
                if o, ok := rr.(*dns.NSID); ok && o.Nsid != "" {
                        return o.Nsid, rttMs, nil
                }
        }
        return "", rttMs, nil
}

func (c *Client) QuerySpecificResolver(ctx context.Context, recordType, domain, resolverIP string) ([]string, error) {
        qtype, err := dnsTypeFromString(recordType)
        if err != nil {
                return nil, err
        }

        fqdn := dnsutil.Fqdn(domain)
        msg := dns.NewMsg(fqdn, qtype)
        msg.RecursionDesired = false

        resolverAddr := net.JoinHostPort(resolverIP, dnsPort)
        r, err := c.exchangeWithFallback(ctx, msg, resolverAddr)
        if err != nil {
                return nil, err
        }

        if r.Rcode == dns.RcodeNameError {
                return nil, nil
        }

        var results []string
        for _, rr := range r.Answer {
                s := rrToString(rr)
                if s != "" {
                        results = append(results, s)
                }
        }
        return results, nil
}

// QuerySpecificResolverAuth queries a single resolver with recursion disabled and
// returns the answer records, whether the response was authoritative (the AA
// bit), and a status string: "" on a NOERROR answer, "NXDOMAIN" for NXDOMAIN, or
// the RCODE name (SERVFAIL/REFUSED/FORMERR/…) or transport-error string otherwise.
// Unlike QuerySpecificResolver it never folds a SERVFAIL/REFUSED/timeout — which
// carry no answer section — into an empty, and therefore falsely "absent", record
// set. Absence may only be asserted from an authoritative NOERROR/NODATA answer
// (RFC 4035 §3.2.3); the AA bit lets callers refuse to assert absence from a
// non-authoritative responder.
func (c *Client) QuerySpecificResolverAuth(ctx context.Context, recordType, domain, resolverIP string) ([]string, bool, string) {
        qtype, err := dnsTypeFromString(recordType)
        if err != nil {
                return nil, false, err.Error()
        }

        fqdn := dnsutil.Fqdn(domain)
        msg := dns.NewMsg(fqdn, qtype)
        msg.RecursionDesired = false

        resolverAddr := net.JoinHostPort(resolverIP, dnsPort)
        r, err := c.exchangeWithFallback(ctx, msg, resolverAddr)
        if err != nil {
                return nil, false, err.Error()
        }
        if r.Rcode == dns.RcodeNameError {
                return nil, r.Authoritative, "NXDOMAIN"
        }
        if r.Rcode != dns.RcodeSuccess {
                rcodeName, ok := dns.RcodeToString[r.Rcode]
                if !ok {
                        rcodeName = fmt.Sprintf("RCODE%d", r.Rcode)
                }
                return nil, r.Authoritative, rcodeName
        }

        var results []string
        for _, rr := range r.Answer {
                s := rrToString(rr)
                if s != "" {
                        results = append(results, s)
                }
        }
        return results, r.Authoritative, ""
}

func (c *Client) QueryWithTTLFromResolver(ctx context.Context, recordType, domain, resolverIP string) RecordWithTTL {
        qtype, err := dnsTypeFromString(recordType)
        if err != nil {
                return RecordWithTTL{}
        }

        fqdn := dnsutil.Fqdn(domain)
        msg := dns.NewMsg(fqdn, qtype)
        msg.RecursionDesired = false

        resolverAddr := net.JoinHostPort(resolverIP, dnsPort)
        r, err := c.exchangeWithFallback(ctx, msg, resolverAddr)
        if err != nil {
                return RecordWithTTL{}
        }

        if r.Rcode == dns.RcodeNameError {
                return RecordWithTTL{}
        }

        var results []string
        var ttl *uint32
        for _, rr := range r.Answer {
                s := rrToString(rr)
                if s != "" {
                        results = append(results, s)
                        if ttl == nil {
                                t := rr.Header().TTL
                                ttl = &t
                        }
                }
        }
        return RecordWithTTL{Records: results, TTL: ttl}
}

func (c *Client) dohQuery(ctx context.Context, domain, recordType string) []string {
        result := c.dohQueryWithTTL(ctx, domain, recordType)
        return result.Records
}

type dohResponse struct {
        Status int  `json:"Status"`
        AD     bool `json:"AD"`
        Answer []struct {
                Data string `json:"data"`
                TTL  uint32 `json:"TTL"`
                Type int    `json:"type"`
        } `json:"Answer"`
}

func (c *Client) dohQueryWithTTL(ctx context.Context, domain, recordType string) RecordWithTTL {
        req, err := http.NewRequestWithContext(ctx, "GET", dohGoogleURL, nil)
        if err != nil {
                return RecordWithTTL{}
        }

        q := url.Values{}
        q.Set("name", domain)
        q.Set("type", strings.ToUpper(recordType))
        q.Set("do", "1")
        req.URL.RawQuery = q.Encode()
        req.Header.Set("Accept", "application/dns-json")
        req.Header.Set("User-Agent", UserAgent)

        resp, err := c.httpClient.Do(req)
        if err != nil {
                slog.Debug("DoH query failed", mapKeyDomain, domain, "type", recordType, mapKeyError, err)
                return RecordWithTTL{}
        }
        defer safeClose(resp.Body, "doh-response")

        if resp.StatusCode != http.StatusOK {
                return RecordWithTTL{}
        }

        body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
        if err != nil {
                return RecordWithTTL{}
        }

        return parseDohResponse(body, recordType)
}

func parseDohResponse(body []byte, recordType string) RecordWithTTL {
        var data dohResponse
        if json.Unmarshal(body, &data) != nil {
                return RecordWithTTL{}
        }

        if data.Status != 0 {
                return RecordWithTTL{}
        }

        if len(data.Answer) == 0 {
                return RecordWithTTL{}
        }

        requestedRRSIG := strings.ToUpper(recordType) == "RRSIG"
        var results []string
        var ttl *uint32
        seen := make(map[string]bool)
        for _, answer := range data.Answer {
                if answer.Type == dohTypeRRSIG && !requestedRRSIG {
                        continue
                }
                rd := strings.TrimSpace(answer.Data)
                if rd == "" {
                        continue
                }
                if strings.ToUpper(recordType) == dnsTypeTXT {
                        rd = strings.Trim(rd, "\"")
                }
                if !seen[rd] {
                        results = append(results, rd)
                        seen[rd] = true
                }
                if ttl == nil {
                        t := answer.TTL
                        ttl = &t
                }
        }

        return RecordWithTTL{Records: results, TTL: ttl, Authenticated: data.AD}
}

func (c *Client) ProbeExists(ctx context.Context, domain string) (exists bool, cname string) {
        fqdn := dnsutil.Fqdn(domain)
        msg := dns.NewMsg(fqdn, dns.TypeA)
        msg.RecursionDesired = true

        dnsClient := newDNSClient(3 * time.Second)

        resolverIP := resolverGoogle
        r, _, err := dnsClient.Exchange(ctx, msg, protoUDP, net.JoinHostPort(resolverIP, dnsPort))
        if err != nil {
                resolverIP = resolverCloudflare
                r, _, err = dnsClient.Exchange(ctx, msg, protoUDP, net.JoinHostPort(resolverIP, dnsPort))
                if err != nil {
                        return false, ""
                }
        }

        if r.Rcode == dns.RcodeNameError {
                return false, ""
        }

        hasA := false
        cnameTarget := ""
        for _, rr := range r.Answer {
                switch v := rr.(type) {
                case *dns.A:
                        hasA = true
                case *dns.CNAME:
                        if cnameTarget == "" {
                                cnameTarget = strings.TrimSuffix(v.CNAME.Target, ".")
                        }
                }
        }

        if hasA || cnameTarget != "" {
                return true, cnameTarget
        }
        return false, ""
}

func (c *Client) udpQuery(ctx context.Context, domain, recordType, resolverIP string) []string {
        result := c.udpQueryWithTTL(ctx, domain, recordType, resolverIP)
        return result.Records
}

func (c *Client) udpQueryWithTTL(ctx context.Context, domain, recordType, resolverIP string) RecordWithTTL {
        r, _ := c.udpQueryWithTTLStatus(ctx, domain, recordType, resolverIP)
        return r
}

// udpQueryWithTTLStatus is the TTL/AD-preserving sibling of querySingleResolver:
// it returns the record (with TTL + Authenticated flag) AND the per-resolver
// errStr ("" on NOERROR, "NXDOMAIN" for NXDOMAIN, the RCODE name or error string
// otherwise) so callers can fold the result through classifyResolverResult and
// distinguish an authoritative absence from a transient failure.
func (c *Client) udpQueryWithTTLStatus(ctx context.Context, domain, recordType, resolverIP string) (RecordWithTTL, string) {
        qtype, err := dnsTypeFromString(recordType)
        if err != nil {
                return RecordWithTTL{}, err.Error()
        }

        fqdn := dnsutil.Fqdn(domain)
        msg := dns.NewMsg(fqdn, qtype)
        msg.RecursionDesired = true
        msg.UDPSize, msg.Security = 4096, true

        dnsClient := newDNSClient(c.timeout)

        r, _, err := dnsClient.Exchange(ctx, msg, protoUDP, net.JoinHostPort(resolverIP, dnsPort))
        if err != nil {
                return RecordWithTTL{}, err.Error()
        }

        // RFC 7766 §5: retry truncated (TC=1) answers over TCP so large signed
        // RRsets (DNSKEY/TLSA) and oversized TXT sets are not silently truncated
        // into a partial — and therefore wrong — record set. A failed TCP retry
        // is reported as transient rather than trusting the partial UDP answer.
        if r.Truncated {
                rt, _, errt := dnsClient.Exchange(ctx, msg, protoTCP, net.JoinHostPort(resolverIP, dnsPort))
                if errt != nil || rt == nil {
                        return RecordWithTTL{}, errTruncatedTCP
                }
                r = rt
        }

        if r.Rcode == dns.RcodeNameError {
                return RecordWithTTL{}, "NXDOMAIN"
        }

        // Any non-success RCODE other than NXDOMAIN (SERVFAIL, REFUSED, FORMERR, …)
        // is a server-side failure, NOT an authoritative answer — surface it as a
        // transient error so callers never mistake it for "record is absent".
        if r.Rcode != dns.RcodeSuccess {
                rcodeName, ok := dns.RcodeToString[r.Rcode]
                if !ok {
                        rcodeName = fmt.Sprintf("RCODE%d", r.Rcode)
                }
                return RecordWithTTL{}, rcodeName
        }

        var results []string
        var ttl *uint32
        for _, rr := range r.Answer {
                if _, isRRSIG := rr.(*dns.RRSIG); isRRSIG && qtype != dns.TypeRRSIG {
                        continue
                }
                s := rrToString(rr)
                if s != "" {
                        results = append(results, s)
                        if ttl == nil {
                                t := rr.Header().TTL
                                ttl = &t
                        }
                }
        }

        return RecordWithTTL{Records: results, TTL: ttl, Authenticated: r.AuthenticatedData}, ""
}

func newDNSClient(timeout time.Duration) *dns.Client {
        return &dns.Client{
                Transport: &dns.Transport{
                        Dialer: &net.Dialer{
                                Timeout: timeout,
                        },
                        ReadTimeout:  timeout,
                        WriteTimeout: timeout,
                },
        }
}

func isNXDomain(r *dns.Msg) bool {
        return r != nil && r.Rcode == dns.RcodeNameError
}

func boolToInt(b bool) int {
        if b {
                return 1
        }
        return 0
}
