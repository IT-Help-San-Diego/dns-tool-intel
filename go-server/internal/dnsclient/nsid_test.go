package dnsclient

import (
        "context"
        "io"
        "testing"
        "time"

        "codeberg.org/miekg/dns"
        "codeberg.org/miekg/dns/dnsutil"
        "codeberg.org/miekg/dns/dnstest"
)

// mockNSIDHandler responds to any query, echoing its question and (when identity
// is non-empty) attaching an NSID pseudo-RR so the client can read which "node"
// answered. Exercises the v2 pseudo-RR path: NSID travels in msg.Pseudo.
func mockNSIDHandler(identity string) func(context.Context, dns.ResponseWriter, *dns.Msg) {
        return func(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
                m := new(dns.Msg)
                dnsutil.SetReply(m, req)
                if identity != "" {
                        m.Pseudo = append(m.Pseudo, &dns.NSID{Nsid: identity})
                }
                _, _ = io.Copy(w, m)
        }
}

func TestQueryNSID(t *testing.T) {
        const want = "6d6f636b6e6f6465" // hex "mocknode"
        dns.HandleFunc(".", mockNSIDHandler(want))
        defer dns.HandleRemove(".")

        cancel, addr, err := dnstest.UDPServer("127.0.0.1:0")
        if err != nil {
                t.Fatalf("start mock DNS server: %v", err)
        }
        defer cancel()

        c := New()
        ctx, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel2()

        nsid, rttMs, err := c.QueryNSID(ctx, addr)
        if err != nil {
                t.Fatalf("QueryNSID(%q): %v", addr, err)
        }
        if nsid != want {
                t.Errorf("nsid = %q, want %q", nsid, want)
        }
        if rttMs < 0 {
                t.Errorf("rttMs = %d, want >= 0", rttMs)
        }
}

func TestQueryNSIDAbsent(t *testing.T) {
        // A server that does not implement NSID returns no pseudo-RR. Per RFC 5001
        // this is a capability gap, not a failure — the method must return an empty
        // string with no error, never fabricate a node identity.
        dns.HandleFunc(".", mockNSIDHandler(""))
        defer dns.HandleRemove(".")

        cancel, addr, err := dnstest.UDPServer("127.0.0.1:0")
        if err != nil {
                t.Fatalf("start mock DNS server: %v", err)
        }
        defer cancel()

        c := New()
        ctx, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel2()

        nsid, _, err := c.QueryNSID(ctx, addr)
        if err != nil {
                t.Fatalf("QueryNSID(%q): %v", addr, err)
        }
        if nsid != "" {
                t.Errorf("nsid = %q, want empty (server returned no NSID)", nsid)
        }
}
