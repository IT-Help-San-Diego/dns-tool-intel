// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package botverify

import (
	"errors"
	"testing"
)

// stubLookups installs deterministic PTR/forward-DNS resolvers for the test
// scope. Pass a map of ip→hostnames for PTR and hostname→ips for forward.
// Returns a teardown that restores the previous hooks AND purges the cache
// (so tests do not leak verified results into one another).
func stubLookups(t *testing.T, ptr map[string][]string, forward map[string][]string) func() {
	t.Helper()
	prevR := rdnsLookup
	prevF := fwdLookup
	rdnsLookup = func(ip string) ([]string, error) {
		if names, ok := ptr[ip]; ok {
			return names, nil
		}
		return nil, errors.New("no PTR")
	}
	fwdLookup = func(host string) ([]string, error) {
		if ips, ok := forward[host]; ok {
			return ips, nil
		}
		return nil, errors.New("no A")
	}
	PurgeCache()
	return func() {
		rdnsLookup = prevR
		fwdLookup = prevF
		PurgeCache()
	}
}

func TestClassify_HumanBrowser(t *testing.T) {
	defer stubLookups(t, nil, nil)()
	r := Classify("Mozilla/5.0 (Macintosh; Intel Mac OS X) Safari/605", "203.0.113.7")
	if r.Class != ClassHuman {
		t.Fatalf("expected ClassHuman, got %v (%s)", r.Class, r.String())
	}
	if r.Verified {
		t.Fatal("human result must not have Verified=true")
	}
	if got, want := r.String(), "human"; got != want {
		t.Errorf("String()=%q want %q", got, want)
	}
}

func TestClassify_GooglebotVerified(t *testing.T) {
	ptr := map[string][]string{
		"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."},
	}
	forward := map[string][]string{
		"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"},
	}
	defer stubLookups(t, ptr, forward)()

	r := Classify("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "66.249.66.1")
	if r.Class != ClassVerifiedBot {
		t.Fatalf("expected ClassVerifiedBot, got %v (%s)", r.Class, r.String())
	}
	if !r.Verified {
		t.Fatal("verified bot must have Verified=true")
	}
	if r.BotName != "Googlebot" {
		t.Errorf("BotName=%q want Googlebot", r.BotName)
	}
	if got, want := r.String(), "verified_bot:Googlebot"; got != want {
		t.Errorf("String()=%q want %q", got, want)
	}
}

func TestClassify_GooglebotSpoofedFailsRDNS(t *testing.T) {
	// Claims to be Googlebot but PTR returns an unrelated host — must NOT verify.
	ptr := map[string][]string{
		"198.51.100.5": {"some-random-vps.example.net."},
	}
	forward := map[string][]string{
		"some-random-vps.example.net": {"198.51.100.5"},
	}
	defer stubLookups(t, ptr, forward)()

	r := Classify("Googlebot/2.1", "198.51.100.5")
	if r.Class != ClassInvestigate {
		t.Fatalf("spoofed Googlebot must be ClassInvestigate, got %v", r.Class)
	}
	if r.Verified {
		t.Fatal("unverified must not have Verified=true")
	}
	if got, want := r.String(), "investigate"; got != want {
		t.Errorf("String()=%q want %q", got, want)
	}
}

func TestClassify_GooglebotForwardMismatchFailsVerification(t *testing.T) {
	// PTR returns a googlebot.com host but its forward-DNS resolves to a different IP.
	ptr := map[string][]string{
		"203.0.113.99": {"crawl-203-0-113-99.googlebot.com."},
	}
	forward := map[string][]string{
		"crawl-203-0-113-99.googlebot.com": {"66.249.66.1"}, // different IP
	}
	defer stubLookups(t, ptr, forward)()

	r := Classify("Googlebot/2.1", "203.0.113.99")
	if r.Class != ClassInvestigate {
		t.Fatalf("forward-mismatch must be ClassInvestigate, got %v", r.Class)
	}
}

func TestClassify_GooglebotSuffixBoundary(t *testing.T) {
	// Attacker controls evil-googlebot.com — must NOT match the .googlebot.com
	// suffix because we anchor at the label boundary.
	ptr := map[string][]string{
		"192.0.2.55": {"crawler.evil-googlebot.com."},
	}
	forward := map[string][]string{
		"crawler.evil-googlebot.com": {"192.0.2.55"},
	}
	defer stubLookups(t, ptr, forward)()

	r := Classify("Googlebot/2.1", "192.0.2.55")
	if r.Class != ClassInvestigate {
		t.Fatalf("evil-googlebot.com PTR must NOT verify, got %v", r.Class)
	}
}

func TestClassify_GPTBotVerified(t *testing.T) {
	ptr := map[string][]string{
		"172.0.0.1": {"egress-172-0-0-1.openai.com."},
	}
	forward := map[string][]string{
		"egress-172-0-0-1.openai.com": {"172.0.0.1"},
	}
	defer stubLookups(t, ptr, forward)()

	r := Classify("Mozilla/5.0 AppleWebKit/537.36 (compatible; GPTBot/1.0; +https://openai.com/gptbot)", "172.0.0.1")
	if r.Class != ClassVerifiedBot {
		t.Fatalf("GPTBot must verify on .openai.com PTR, got %v", r.Class)
	}
	if r.BotName != "GPTBot" {
		t.Errorf("BotName=%q want GPTBot", r.BotName)
	}
}

func TestClassify_DevonAgentUAOnly(t *testing.T) {
	defer stubLookups(t, nil, nil)()
	// Devon Agent runs on user's ISP IP — no PTR allowlist applies.
	r := Classify("DEVONagent/3.5 (Macintosh; Intel)", "73.45.12.99")
	if r.Class != ClassVerifiedBot {
		t.Fatalf("DEVONagent must verify by UA alone, got %v (%s)", r.Class, r.String())
	}
	if r.BotName != "Devon Agent Pro" {
		t.Errorf("BotName=%q want Devon Agent Pro", r.BotName)
	}
}

func TestClassify_GenericBotInvestigate(t *testing.T) {
	defer stubLookups(t, nil, nil)()
	cases := []string{
		"python-requests/2.31",
		"curl/8.4.0",
		"Mozilla/5.0 (compatible; UnknownBot/1.0; +http://example.com/bot)",
		"okhttp/4.9.3",
		"Go-http-client/1.1",
	}
	for _, ua := range cases {
		r := Classify(ua, "203.0.113.10")
		if r.Class != ClassInvestigate {
			t.Errorf("UA=%q expected ClassInvestigate, got %v (%s)", ua, r.Class, r.String())
		}
	}
}

func TestClassify_EmptyUAInvestigate(t *testing.T) {
	defer stubLookups(t, nil, nil)()
	r := Classify("", "203.0.113.11")
	if r.Class != ClassInvestigate {
		t.Errorf("empty UA expected ClassInvestigate, got %v", r.Class)
	}
}

func TestClassify_ResultCached(t *testing.T) {
	calls := 0
	prevR := rdnsLookup
	prevF := fwdLookup
	rdnsLookup = func(ip string) ([]string, error) {
		calls++
		return []string{"crawl-1-1-1-1.googlebot.com."}, nil
	}
	fwdLookup = func(host string) ([]string, error) {
		return []string{"1.1.1.1"}, nil
	}
	PurgeCache()
	defer func() {
		rdnsLookup = prevR
		fwdLookup = prevF
		PurgeCache()
	}()

	for i := 0; i < 5; i++ {
		_ = Classify("Googlebot/2.1", "1.1.1.1")
	}
	if calls != 1 {
		t.Errorf("expected exactly 1 PTR call (cached), got %d", calls)
	}
}

func TestResult_StringFallthrough(t *testing.T) {
	if got := (Result{Class: ClassVerifiedBot}).String(); got != "verified_bot" {
		t.Errorf("VerifiedBot with empty BotName: got %q want verified_bot", got)
	}
}

func TestClassify_AhrefsSiteAuditVerified(t *testing.T) {
	// Live-verified 2026-08-12: PTR sardine530.ahrefs.net <-> 202.8.42.18.
	ptr := map[string][]string{"202.8.42.18": {"sardine530.ahrefs.net."}}
	forward := map[string][]string{"sardine530.ahrefs.net": {"202.8.42.18"}}
	defer stubLookups(t, ptr, forward)()

	r := Classify("Mozilla/5.0 (compatible; AhrefsSiteAudit/6.1; +http://ahrefs.com/robot/site-audit)", "202.8.42.18")
	if r.Class != ClassVerifiedBot {
		t.Fatalf("AhrefsSiteAudit must verify on .ahrefs.net PTR, got %v (%s)", r.Class, r.String())
	}
	if r.BotName != "AhrefsSiteAudit" {
		t.Errorf("BotName=%q want AhrefsSiteAudit", r.BotName)
	}
	if got, want := r.String(), "verified_bot:AhrefsSiteAudit"; got != want {
		t.Errorf("String()=%q want %q", got, want)
	}
}

func TestClassify_ChromeLighthouseVerified(t *testing.T) {
	// Live-verified 2026-08-12: PTR google-proxy-*.google.com <-> source IP.
	ptr := map[string][]string{"74.125.215.199": {"google-proxy-74-125-215-199.google.com."}}
	forward := map[string][]string{"google-proxy-74-125-215-199.google.com": {"74.125.215.199"}}
	defer stubLookups(t, ptr, forward)()

	r := Classify("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Chrome-Lighthouse", "74.125.215.199")
	if r.Class != ClassVerifiedBot {
		t.Fatalf("Chrome-Lighthouse must verify on .google.com PTR, got %v (%s)", r.Class, r.String())
	}
	if got, want := r.String(), "verified_bot:Chrome-Lighthouse"; got != want {
		t.Errorf("String()=%q want %q", got, want)
	}
}

func TestClassify_ChromeLighthouseSpoofedIsInvestigate(t *testing.T) {
	// UA claims Chrome-Lighthouse but PTR does not verify — must NOT be human.
	ptr := map[string][]string{"198.51.100.9": {"some-unrelated-vps.example.net."}}
	forward := map[string][]string{"some-unrelated-vps.example.net": {"198.51.100.9"}}
	defer stubLookups(t, ptr, forward)()

	r := Classify("Chrome/136.0.0.0 Safari/537.36 Chrome-Lighthouse", "198.51.100.9")
	if r.Class != ClassInvestigate {
		t.Fatalf("spoofed Chrome-Lighthouse must be ClassInvestigate, got %v", r.Class)
	}
}

func TestHumanVerified_FailClosedContract(t *testing.T) {
	// A zero-value Result (any future error/short-circuit path) must NEVER
	// report a verified human: ClassHuman is the zero value of Class, so the
	// gate relies on the explicit Classified flag.
	var zero Result
	if zero.HumanVerified() {
		t.Fatal("zero Result must fail closed (not HumanVerified)")
	}

	defer stubLookups(t, nil, nil)()
	// Completed, no-bot-signal classification IS the one true positive.
	r := Classify("Mozilla/5.0 (Macintosh; Intel Mac OS X) Safari/605", "203.0.113.7")
	if !r.HumanVerified() {
		t.Fatal("completed human classification must be HumanVerified")
	}
	// Investigate — empty UA — must not be HumanVerified.
	r2 := Classify("", "203.0.113.8")
	if r2.HumanVerified() {
		t.Fatal("investigate classification must not be HumanVerified")
	}
	// Verified bot must not be HumanVerified.
	r3 := Classify("DEVONagent/3.5 (Macintosh; Intel)", "73.45.12.99")
	if r3.HumanVerified() {
		t.Fatal("verified bot must not be HumanVerified")
	}
}
