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
	// Port overrides the default DNS port (53) for this resolver. Empty means
	// the default. Test seam: mock servers bind ephemeral ports.
	Port string
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
	TopVotes        int                 `json:"top_votes"`
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
	// DNSKEY/DS/RRSIG render RDATA ONLY — the embedded rdata's String(),
	// never the RR's full presentation format. The full form embeds the
	// header name/TTL/class, and TTL is resolver-cache state, not zone
	// data: five healthy resolvers answering a warm-cache zone report five
	// different remaining TTLs, so TTL-bearing strings made
	// canonicalRecordKey read agreement as conflict (measured live
	// 2026-08-17: example.com DNSKEY TTLs 1527/553/2787/3076 across four
	// resolvers -> consensusConflict -> signed domains graded
	// indeterminate). Bare rdata is the shape the DoH path returns and the
	// shape field-position consumers (parseAlgorithm reads Fields[1] as
	// the algorithm) and analyzer test mocks have always assumed. NOTE:
	// the default branch's TrimPrefix idiom is NOT equivalent here —
	// Header.String() omits the TYPE token that RR.String() includes, so
	// it would leave a "	TYPE	" residue (adversarial review caught
	// exactly that in the first version of this fix).
	case *dns.DNSKEY:
		return v.DNSKEY.String()
	case *dns.DS:
		return v.DS.String()
	case *dns.RRSIG:
		return v.RRSIG.String()
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
	// A validating resolver SERVFAILs a broken-DNSSEC zone and hides its
	// published records, so the CD=0 DoH pass above comes back empty for a
	// domain that genuinely has records. Retry with checking disabled
	// (CD=1) as positive confirmation only: if the zone publishes records,
	// resolve; if still empty, keep the error. Absence is never asserted
	// from a CD query (RFC 4035 §3.2.2 / RFC 6840 §5.9).
	if cdResults := c.dohQueryWithTTL(ctx, domain, recordType, true); len(cdResults.Records) > 0 {
		c.cacheSet(cacheKey, cdResults.Records)
		return cdResults.Records, LookupResolved
	}
	return nil, LookupError
}

func (c *Client) QueryDNSWithTTL(ctx context.Context, recordType, domain string) RecordWithTTL {
	if domain == "" || recordType == "" {
		return RecordWithTTL{}
	}

	result := c.dohQueryWithTTL(ctx, domain, recordType, false)
	if len(result.Records) > 0 {
		return result
	}

	result = c.parallelUDPQueryWithTTL(ctx, domain, recordType)
	if len(result.Records) > 0 {
		return result
	}

	// Broken-DNSSEC fallback (CD): a validating resolver SERVFAILs a bogus zone, so
	// the normal query returns zero records and would read as "record absent" for a
	// zone that merely has a broken chain. Re-query with checking-disabled to see the
	// PUBLISHED records; the bogus signal itself stays in the DNSSEC AD consensus
	// (which remains validation-enabled). Policy in the client, not a per-call-site fix.
	if cd := c.dohQueryWithTTL(ctx, domain, recordType, true); len(cd.Records) > 0 {
		return cd
	}
	return RecordWithTTL{}
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
func (c *Client) QueryDNSWithTTLStatus(ctx context.Context, recordType, domain string, checkingDisabled bool) (RecordWithTTL, LookupStatus) {
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
			rec, errStr := c.udpQueryWithTTLStatus(qctx, domain, recordType, ip, checkingDisabled)
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
		// Carry the denial's own authentication out of the fold: with CD=0,
		// a validating resolver that sets AD on an empty answer has PROVEN
		// the record absent (RFC 4035 §3.2.3) — one AD-bearing absent vote
		// is positive evidence (the hasSecureNoBogus doctrine's shape).
		// CD=1 queries can never carry it: CD disables validation, so AD is
		// protocol-zeroed. Records stays empty — absence semantics unchanged.
		auth := make([]bool, len(results))
		for i := range results {
			auth[i] = results[i].rec.Authenticated
		}
		return RecordWithTTL{Authenticated: absentDenialAD(outcomes, auth)}, LookupAbsent
	case consensusConflict:
		return RecordWithTTL{}, LookupConflict
	}

	// Every UDP resolver failed transiently. Use DoH ONLY as positive
	// confirmation: records => resolved. Absence is never asserted here.
	if doh := c.dohQueryWithTTL(ctx, domain, recordType, checkingDisabled); len(doh.Records) > 0 {
		return doh, LookupResolved
	}
	return RecordWithTTL{}, LookupError
}

// absentDenialAD reports whether EVERY absent-voting resolver's answer carried
// the AD bit — unanimity, not any-vote. Measured 2026-08-17: OpenDNS sets AD
// on NSEC3 opt-out DS denials (resolutionscope.com, google.com) where absence
// is genuinely unprovable (RFC 5155 — an opt-out span proves nothing), while
// strict validators (Cloudflare/Quad9/DNS4EU) correctly omit it. One loose
// AD-setter must never fake a cryptographic proof; unanimity passes exactly
// the provable denials (measured: all resolvers set AD on the signed-parent
// .dev denial) and errs only in the safe direction — a never-AD resolver can
// demote a provable denial to "unauthenticated", never assert proof that
// does not exist. Meaningful only for CD=0 queries (CD=1 protocol-zeroes AD).
func absentDenialAD(outcomes []resolverOutcome, authenticated []bool) bool {
	sawAbsent := false
	for i, oc := range outcomes {
		if oc != outcomeAbsent {
			continue
		}
		sawAbsent = true
		if i >= len(authenticated) || !authenticated[i] {
			return false
		}
	}
	return sawAbsent
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
			Records: dohResults,
			// Zero resolver answers is not consensus. #386 fixed the
			// main path but this early return still claimed it, and an
			// all-SERVFAIL bogus zone takes exactly this branch — the
			// fixture's row 18400 persisted consensus_reached=true with
			// resolver_count=0 on every record type. Agreement requires
			// at least one measurement.
			Consensus:       len(dohResults) > 0,
			ResolverCount:   boolToInt(len(dohResults) > 0),
			TopVotes:        boolToInt(len(dohResults) > 0),
			ResolverResults: map[string][]string{"DoH": dohResults},
		}
	}

	consensusRecords, allSame, discrepancies, topVotes := findConsensus(resolverResults)
	if !allSame {
		slog.Warn("DNS discrepancy", mapKeyDomain, domain, "record_type", recordType, mapKeyDiscrepancies, discrepancies)
	}

	return ConsensusResult{
		Records:         consensusRecords,
		Consensus:       allSame && len(consensusRecords) > 0,
		ResolverCount:   len(resolverResults),
		TopVotes:        topVotes,
		Discrepancies:   discrepancies,
		ResolverResults: resolverResults,
	}
}

func findConsensus(resolverResults map[string][]string) (records []string, allSame bool, discrepancies []string, topVotes int) {
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
	topVotes = mostCommonCount

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
				"top_votes":         cr.consensus.TopVotes,
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

// witnessResolver returns the first resolver whose vote equals the aggregate
// state — a named witness for the verdict (#385), extracted so the gocyclo
// ratchet stays at baseline. For disagreement states (split/unmeasured) no
// single resolver represents the aggregate, so no witness is named.
func witnessResolver(state string, resolverAD map[string]string, resolvers []ResolverConfig) *string {
	if state == "split" || state == "unmeasured" {
		return nil
	}
	for _, r := range resolvers {
		if resolverAD[r.Name] == state {
			name := r.Name
			return &name
		}
	}
	return nil
}

// adVote is one resolver's cast vote in the AD sweep, or "unmeasured" when it
// could not cast one (error, budget expiry) — never absent, so the fold can
// never silently shrink the denominator.
type adVote struct {
	name string
	vote string
}

// adVoteFor runs a single resolver's AD probe and posts its vote. Extracted
// from CheckDNSSECADFlag to keep each function under the complexity ratchet:
// the vote logic is one decision chain, the sweep is one fan-out.
func (c *Client) adVoteFor(ctx context.Context, res ResolverConfig, domain string, votes chan<- adVote) {
	fqdn := dnsutil.Fqdn(domain)
	msg := dns.NewMsg(fqdn, dns.TypeA)
	msg.RecursionDesired = true
	msg.UDPSize, msg.Security = 4096, true

	dnsClient := newDNSClient(3 * time.Second)
	port := res.Port
	if port == "" {
		port = dnsPort
	}
	addr := net.JoinHostPort(res.IP, port)

	resp, _, err := dnsClient.Exchange(ctx, msg, protoUDP, addr)
	if err != nil {
		if isNXDomain(resp) {
			votes <- adVote{res.Name, "nxdomain"}
			return
		}
		slog.Debug("AD flag check failed", mapKeyResolver, res.IP, mapKeyError, err)
		votes <- adVote{res.Name, "unmeasured"}
		return
	}

	if resp.Rcode == dns.RcodeNameError {
		votes <- adVote{res.Name, "nxdomain"}
		return
	}

	// SERVFAIL is ambiguous: RFC 4033 §5 signals "bogus" via RCODE=2,
	// but SERVFAIL is ALSO plain transport failure, resolver overload,
	// or upstream trouble — it is not, by itself, a measurement of
	// validation failure. Cross-check with CD=1: if the resolver
	// answers with checking disabled, the SERVFAIL was genuine
	// validation rejection (a bogus vote). If CD=1 also fails, the
	// failure is transport and this resolver casts no vote at all.
	if resp.Rcode == dns.RcodeServerFailure {
		if c.cdConfirmedBogus(ctx, addr, fqdn) {
			votes <- adVote{res.Name, "bogus"}
		} else {
			votes <- adVote{res.Name, "unmeasured"}
		}
		return
	}

	if resp.Rcode != dns.RcodeSuccess {
		slog.Debug("AD flag check non-success RCODE", mapKeyResolver, res.IP, "rcode", resp.Rcode)
		votes <- adVote{res.Name, "unmeasured"}
		return
	}

	if len(resp.Answer) == 0 {
		msg2 := dns.NewMsg(fqdn, dns.TypeSOA)
		msg2.RecursionDesired = true
		msg2.UDPSize, msg2.Security = 4096, true
		r2, _, err2 := dnsClient.Exchange(ctx, msg2, protoUDP, addr)
		if err2 == nil {
			resp = r2
		}
	}

	if resp.AuthenticatedData {
		votes <- adVote{res.Name, "secure"}
	} else {
		votes <- adVote{res.Name, "ad_absent"}
	}
}

func (c *Client) CheckDNSSECADFlag(ctx context.Context, domain string) ADFlagResult {
	result := ADFlagResult{ResolverAD: make(map[string]string)}

	var secure, adAbsent, bogus int

	// Parallel sweep — the same fan-out used everywhere else in this client.
	// The serial loop this replaced was the positional-failure class: a slow
	// resolver at position 1 consumed the envelope (5 × 3s = 15s worst case
	// inside a 15s nested budget), resolvers 4 and 5 never ran, and their
	// absence folded as consensus instead of as unmeasured. Each resolver now
	// runs concurrently with its own 3s deadline, so every resolver always
	// gets to vote, and a vote it could not cast (error, budget expiry) is
	// recorded as "unmeasured" rather than silently shrinking the denominator.
	votes := make(chan adVote, len(c.resolvers))
	for _, r := range c.resolvers {
		go c.adVoteFor(ctx, r, domain, votes)
	}

	for range c.resolvers {
		vote := <-votes
		result.ResolverAD[vote.name] = vote.vote
		switch vote.vote {
		case "secure":
			secure++
		case "ad_absent":
			adAbsent++
		case "bogus":
			bogus++
		}
	}

	state, adFlag, validated := foldADVotes(secure, adAbsent, bogus)
	result.State = state
	result.ADFlag = adFlag
	result.Validated = validated
	result.ResolverUsed = witnessResolver(state, result.ResolverAD, c.resolvers)
	if state == "unmeasured" {
		errStr := "Could not verify AD flag"
		result.Error = &errStr
	}

	return result
}

// foldADVotes classifies the resolver votes into an aggregate validation state.
// It is a pure function so the fold can be unit-tested without a network.
//
// RFC 4033 §5 defines four validation states (Secure / Insecure / Bogus /
// Indeterminate); we surface the wire signal honestly and never overclaim where
// the RFC says the signal is ambiguous:
//
//	"secure"     — AD bit set (RFC: Secure).
//	"ad_absent"  — AD bit clear; RFC 4033 §5 notes the signaling mechanism
//	               cannot distinguish Insecure from Indeterminate, so we record
//	               the observation (AD absent) rather than naming a state we
//	               cannot prove.
//	"bogus"      — a CD=1-confirmed SERVFAIL (genuine validation rejection).
//	"split"      — OUR term: validating resolvers disagree.
//	"unmeasured" — OUR term: no resolver cast a usable vote.
//
// A single bogus vote never outvotes secure votes: a transient SERVFAIL
// (transport) already casts no vote, and a CD-confirmed bogus alongside a
// secure vote is genuine disagreement (split), not rejection.
func foldADVotes(secure, adAbsent, bogus int) (state string, adFlag, validated bool) {
	switch {
	case bogus > 0 && secure == 0 && adAbsent == 0:
		// Every usable vote is a CD-confirmed validation rejection.
		return "bogus", false, false
	case bogus > 0 && (secure > 0 || adAbsent > 0):
		// A CD-confirmed bogus vote disagrees with a secure or ad-absent
		// vote — genuine resolver disagreement, not a unanimous rejection.
		return "split", false, false
	case secure+adAbsent == 0:
		return "unmeasured", false, false
	case adAbsent == 0 && secure > 0:
		return "secure", true, true
	case secure == 0 && adAbsent > 0:
		return "ad_absent", false, false
	default:
		return "split", false, false
	}
}

// cdConfirmedBogus re-queries the resolver with the CD (checking disabled) bit
// set. If the resolver then answers NOERROR, the original SERVFAIL was DNSSEC
// validation rejection — the resolver holds the zone's data but refused to vouch
// for it under validation, a genuine bogus vote. If CD=1 also fails, the SERVFAIL
// was transport/upstream trouble and the resolver casts no vote. (RFC 4035 §3.2.2:
// with CD=1 the resolver returns records WITHOUT validating, so a broken chain's
// data is visible instead of SERVFAILing away.)
func (c *Client) cdConfirmedBogus(ctx context.Context, resolverAddr, fqdn string) bool {
	msg := dns.NewMsg(fqdn, dns.TypeA)
	msg.RecursionDesired = true
	msg.UDPSize, msg.Security = 4096, true
	msg.CheckingDisabled = true

	dnsClient := newDNSClient(3 * time.Second)
	resp, _, err := dnsClient.Exchange(ctx, msg, protoUDP, resolverAddr)
	if err != nil || resp == nil {
		return false
	}
	return resp.Rcode == dns.RcodeSuccess
}

func (c *Client) ExchangeContext(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	resolverAddr := net.JoinHostPort(c.resolvers[0].IP, dnsPort)
	return c.exchangeWithFallback(ctx, msg, resolverAddr)
}

// ExchangeContextToResolver runs the same UDP-with-TCP-fallback exchange as
// ExchangeContext, but against an explicitly named resolver IP. Delegation
// consistency needs this to interrogate a specific PARENT zone server, whose
// answers are referrals (delegation data in the authority section) rather
// than recursive answers.
func (c *Client) ExchangeContextToResolver(ctx context.Context, msg *dns.Msg, resolverIP string) (*dns.Msg, error) {
	resolverAddr := net.JoinHostPort(resolverIP, dnsPort)
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
	// A parent server answers a delegated child's name with a REFERRAL:
	// the requested glue (the in-bailiwick nameserver's A/AAAA) rides in
	// the ADDITIONAL section (r.Extra), not the answer. Answer-first
	// stays canonical for authoritative answers; Extra adds what a
	// referral carries — the exact-section class caught three times in
	// the delegation checker (Answer-only reads of referral-shaped data).
	//
	// NAME filter (CC review, 4th section-family member — "right section,
	// unchecked name"): a referral's ADDITIONAL carries glue for EVERY
	// in-bailiwick nameserver at once, so a type-only filter would
	// attribute ns2's address to ns1. Match the record's owner name
	// against the queried FQDN (the fork's Header carries Name even
	// though it carries no RrType).
	fqdnLower := strings.ToLower(fqdn)
	for _, rr := range r.Extra {
		if dnsRrTypeMatches(rr, qtype) &&
			strings.EqualFold(rr.Header().Name, fqdnLower) {
			s := rrToString(rr)
			if s != "" {
				results = append(results, s)
			}
		}
	}
	return results, nil
}

// dnsRrTypeMatches reports whether rr's concrete type equals the query
// type — the fork's Header carries no type field, so the type switch is the
// discriminator.
func dnsRrTypeMatches(rr dns.RR, qtype uint16) bool {
	switch rr.(type) {
	case *dns.A:
		return qtype == dns.TypeA
	case *dns.AAAA:
		return qtype == dns.TypeAAAA
	case *dns.NS:
		return qtype == dns.TypeNS
	case *dns.TXT:
		return qtype == dns.TypeTXT
	case *dns.MX:
		return qtype == dns.TypeMX
	case *dns.DS:
		return qtype == dns.TypeDS
	case *dns.DNSKEY:
		return qtype == dns.TypeDNSKEY
	default:
		return false
	}
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
	result := c.dohQueryWithTTL(ctx, domain, recordType, false)
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

func (c *Client) dohQueryWithTTL(ctx context.Context, domain, recordType string, checkingDisabled bool) RecordWithTTL {
	req, err := http.NewRequestWithContext(ctx, "GET", dohGoogleURL, nil)
	if err != nil {
		return RecordWithTTL{}
	}

	q := url.Values{}
	q.Set("name", domain)
	q.Set("type", strings.ToUpper(recordType))
	q.Set("do", "1")
	if checkingDisabled {
		// RFC 4035 §3.2.2 / RFC 6840 §5.9: set the CD (checking disabled) bit so
		// the resolver returns the zone's PUBLISHED records without validating them.
		// The DNSSEC key lookups want what the zone publishes (to report "broken"),
		// not a validator's refusal to hand over data it won't vouch for.
		q.Set("cd", "1")
	}
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
	// checkingDisabled (CD) so a broken-DNSSEC zone's A record is still visible:
	// a validating resolver returns SERVFAIL/0-answers for such a zone, which the
	// old code read as "domain does not exist" and dropped the whole scan. CD=1
	// asks "what does the zone publish" so existence is judged on the record, not
	// the validator's refusal to vouch for it (RFC 4035 §3.2.2).
	msg.CheckingDisabled = true

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
	r, _ := c.udpQueryWithTTLStatus(ctx, domain, recordType, resolverIP, false)
	return r
}

// udpQueryWithTTLStatus is the TTL/AD-preserving sibling of querySingleResolver:
// it returns the record (with TTL + Authenticated flag) AND the per-resolver
// errStr ("" on NOERROR, "NXDOMAIN" for NXDOMAIN, the RCODE name or error string
// otherwise) so callers can fold the result through classifyResolverResult and
// distinguish an authoritative absence from a transient failure.
func (c *Client) udpQueryWithTTLStatus(ctx context.Context, domain, recordType, resolverIP string, checkingDisabled bool) (RecordWithTTL, string) {
	qtype, err := dnsTypeFromString(recordType)
	if err != nil {
		return RecordWithTTL{}, err.Error()
	}

	fqdn := dnsutil.Fqdn(domain)
	msg := dns.NewMsg(fqdn, qtype)
	msg.RecursionDesired = true
	msg.UDPSize, msg.Security = 4096, true
	// checkingDisabled maps to the CD (checking disabled) bit — when set, the
	// resolver returns the zone's published records WITHOUT validating them, so a
	// broken chain's DNSKEY/DS are visible instead of SERVFAILing away (RFC 4035 §3.2.2).
	msg.CheckingDisabled = checkingDisabled

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
