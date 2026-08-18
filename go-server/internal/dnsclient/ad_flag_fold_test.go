package dnsclient

import (
	"context"
	"io"
	"sync/atomic"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
	"codeberg.org/miekg/dns/dnsutil"
)

// TestFoldADVotes pins the aggregate classification. The load-bearing case is
// the negative test from Ruling 1 (2026-08-15): a single bogus vote must NEVER
// outvote secure votes. Before the fix, `case bogus > 0` won unconditionally,
// so one transient SERVFAIL flipped a healthy signed domain to "bogus" (broken).
func TestFoldADVotes(t *testing.T) {
	cases := []struct {
		name                    string
		secure, adAbsent, bogus int
		wantState               string
		wantADFlag              bool
		wantValidated           bool
	}{
		{
			// THE negative test: 4 secure + 1 (CD-confirmed) bogus is genuine
			// disagreement, not rejection. Pre-fix this returned "bogus".
			name: "single bogus beside secure is split", secure: 4, bogus: 1,
			wantState: "split", wantADFlag: false, wantValidated: false,
		},
		{
			name: "all secure", secure: 4,
			wantState: "secure", wantADFlag: true, wantValidated: true,
		},
		{
			name: "all bogus", bogus: 5,
			wantState: "bogus", wantADFlag: false, wantValidated: false,
		},
		{
			name:      "no usable votes",
			wantState: "unmeasured", wantADFlag: false, wantValidated: false,
		},
		{
			name: "all ad absent", adAbsent: 5,
			wantState: "ad_absent", wantADFlag: false, wantValidated: false,
		},
		{
			name: "secure and ad absent", secure: 3, adAbsent: 2,
			wantState: "split", wantADFlag: false, wantValidated: false,
		},
		{
			name: "bogus beside ad absent", adAbsent: 3, bogus: 2,
			wantState: "split", wantADFlag: false, wantValidated: false,
		},
		{
			name: "bogus beside secure", secure: 1, bogus: 3,
			wantState: "split", wantADFlag: false, wantValidated: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state, adFlag, validated := foldADVotes(tc.secure, tc.adAbsent, tc.bogus)
			if state != tc.wantState {
				t.Errorf("state = %q, want %q", state, tc.wantState)
			}
			if adFlag != tc.wantADFlag {
				t.Errorf("adFlag = %v, want %v", adFlag, tc.wantADFlag)
			}
			if validated != tc.wantValidated {
				t.Errorf("validated = %v, want %v", validated, tc.wantValidated)
			}
		})
	}
}

// TestCDConfirmedBogus verifies the CD=1 cross-check discriminator: a resolver
// that answers NOERROR with checking disabled was rejecting on validation
// grounds (genuine bogus); one that still SERVFAILs was transport-failing and
// casts no vote. This is the mechanism that stops a transient SERVFAIL from
// counting as a bogus vote in the fold.
func TestCDConfirmedBogus(t *testing.T) {
	// failCD is read by the mock-DNS handler goroutines and written by this
	// test goroutine between phases — an atomic keeps the two sides race-free
	// under `go test -race`.
	var failCD atomic.Bool // when true, the mock SERVFAILs even on CD=1
	dns.HandleFunc(".", func(_ context.Context, w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		dnsutil.SetReply(m, req)
		if failCD.Load() {
			m.Rcode = dns.RcodeServerFailure
		} else {
			m.Rcode = dns.RcodeSuccess
		}
		_, _ = io.Copy(w, m)
	})
	defer dns.HandleRemove(".")

	cancel, addr, err := dnstest.UDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("start mock DNS server: %v", err)
	}
	defer cancel()

	c := New()
	ctx := context.Background()

	// CD=1 answers NOERROR -> the original SERVFAIL was validation (genuine bogus).
	failCD.Store(false)
	if !c.cdConfirmedBogus(ctx, addr, "example.com.") {
		t.Error("CD=1 NOERROR should confirm a genuine bogus vote")
	}

	// CD=1 also SERVFAILs -> transport failure, the resolver casts no vote.
	failCD.Store(true)
	if c.cdConfirmedBogus(ctx, addr, "example.com.") {
		t.Error("CD=1 SERVFAIL must NOT confirm bogus (transport, not validation)")
	}
}
