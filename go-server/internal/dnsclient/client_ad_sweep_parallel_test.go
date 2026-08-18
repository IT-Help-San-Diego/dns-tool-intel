package dnsclient

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
	"codeberg.org/miekg/dns/dnsutil"
)

// TestCheckDNSSECADFlag_ParallelNotPositional pins the positional-failure fix:
// the AD sweep must run all resolvers concurrently (wall time = max resolver
// latency, not the sum), and a resolver that never casts a vote must appear
// in the result as "unmeasured" — never silently absent from the fold.
//
// Layout: a SLOW resolver (1.2s, answers AD) placed FIRST, a fast resolver
// (answers AD immediately), and two silent servers (accept the query, never
// answer — a 3s client timeout each). Serial execution would need
// ~1.2s + 0s + 3s + 3s = 7.2s; parallel needs ~3s. The old serial loop with
// a nested 15s caller budget was exactly the class where the slow resolver
// ate the envelope and later resolvers never voted.
func TestCheckDNSSECADFlag_ParallelNotPositional(t *testing.T) {
	// slowPort is read by the global mock-DNS handler goroutines and written
	// by this test goroutine after the servers bind — an atomic keeps the two
	// sides race-free without coupling server startup order.
	var slowPort atomic.Pointer[string]

	// One handler for both mock DNS servers; per-server behaviour keyed on the
	// local address (the port the request was served from).
	dns.HandleFunc(".", func(_ context.Context, w dns.ResponseWriter, req *dns.Msg) {
		sp := slowPort.Load()
		if sp != nil && w.LocalAddr().String() == "127.0.0.1:"+*sp {
			time.Sleep(1200 * time.Millisecond)
		}
		m := new(dns.Msg)
		dnsutil.SetReply(m, req)
		m.AuthenticatedData = true
		_, _ = io.Copy(w, m)
	})
	defer dns.HandleRemove(".")

	cancel1, addr1, err := dnstest.UDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("start mock DNS server 1: %v", err)
	}
	defer cancel1()
	cancel2, addr2, err := dnstest.UDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("start mock DNS server 2: %v", err)
	}
	defer cancel2()

	_, slowPortStr, err := net.SplitHostPort(addr1)
	if err != nil {
		t.Fatalf("split hostport: %v", err)
	}
	slowPort.Store(&slowPortStr)
	_, fastPort, err := net.SplitHostPort(addr2)
	if err != nil {
		t.Fatalf("split hostport: %v", err)
	}
	silentA := startSilentServer(t)
	silentB := startSilentServer(t)

	c := New(WithResolvers([]ResolverConfig{
		{Name: "slow", IP: "127.0.0.1", Port: slowPortStr},
		{Name: "fast", IP: "127.0.0.1", Port: fastPort},
		{Name: "silent-a", IP: "127.0.0.1", Port: silentA},
		{Name: "silent-b", IP: "127.0.0.1", Port: silentB},
	}))

	start := time.Now()
	result := c.CheckDNSSECADFlag(context.Background(), "example.com")
	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		t.Errorf("sweep took %v — not parallel; serial worst case is ~7.2s, parallel ~3s", elapsed)
	}

	// Every resolver must appear in the map — the fix's core: no silent shrink.
	for _, want := range []string{"slow", "fast", "silent-a", "silent-b"} {
		if _, ok := result.ResolverAD[want]; !ok {
			t.Errorf("resolver %q missing from ResolverAD — never-voted resolvers must be recorded", want)
		}
	}

	if got := result.ResolverAD["slow"]; got != "secure" {
		t.Errorf("slow resolver vote = %q, want secure (it answered AD)", got)
	}
	if got := result.ResolverAD["fast"]; got != "secure" {
		t.Errorf("fast resolver vote = %q, want secure", got)
	}
	for _, name := range []string{"silent-a", "silent-b"} {
		if got := result.ResolverAD[name]; got != "unmeasured" {
			t.Errorf("silent resolver %s vote = %q, want unmeasured (it never answered)", name, got)
		}
	}

	// Two secure votes, two unmeasured — the fold must not read the silent
	// pair as ad_absent consensus.
	if result.State != "secure" || !result.ADFlag {
		t.Errorf("state = %q, ADFlag = %v — want secure/true (2 secure votes, 2 unmeasured)", result.State, result.ADFlag)
	}
}

// startSilentServer binds an ephemeral UDP socket that accepts queries and
// never answers — the resolver times out at its own 3s deadline.
func startSilentServer(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			_, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			// Deliberately never respond.
		}
	}()
	_, port, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("split hostport: %v", err)
	}
	return port
}
