package dnsclient

import (
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

// TestRRToStringIgnoresHeaderTTL pins the consensus-critical invariant behind
// the warm-cache DNSSEC flatten: two resolvers answering the SAME DNSKEY/DS
// rdata with DIFFERENT cached TTLs must produce IDENTICAL record strings.
// canonicalRecordKey compares these strings verbatim across the five-resolver
// fan-out, so a TTL leaking into them makes healthy resolvers "disagree" on
// any warm-cache zone. Measured live 2026-08-17: example.com DNSKEY TTLs were
// 1527/553/2787/3076 across four resolvers at one instant -> every string
// differed -> consensusConflict -> zero key material -> consistency_guard ->
// a signed domain graded indeterminate. Cold-cache zones passed by lottery
// (>=2 resolvers happening to align).
//
// The contract is EXACT bare rdata — space-separated fields, no header name/
// TTL/class and no TYPE token — because three consumers assume it: the DoH
// path has always returned bare rdata, parseAlgorithm reads Fields[1] as the
// algorithm (a "\tDS\t"-prefixed string shifts that to the KEY TAG — the
// defect adversarial review caught in this fix's first version, which
// asserted only TTL-invariance and passed with the wrong shape), and the
// analyzer test mocks feed bare rdata. Hence the EXACT string assertions.
func TestRRToStringIgnoresHeaderTTL(t *testing.T) {
	const pubKey = "mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="
	const digest = "BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A86764247C"

	cases := []struct {
		name string
		want string
		mk   func(ttl uint32) dns.RR
	}{
		{
			name: "DNSKEY",
			want: "257 3 13 " + pubKey,
			mk: func(ttl uint32) dns.RR {
				return &dns.DNSKEY{
					Hdr:    dns.Header{Name: "example.com.", TTL: ttl, Class: dns.ClassINET},
					DNSKEY: rdata.DNSKEY{Flags: 257, Protocol: 3, Algorithm: 13, PublicKey: pubKey},
				}
			},
		},
		{
			name: "DS",
			want: "370 13 2 " + digest,
			mk: func(ttl uint32) dns.RR {
				return &dns.DS{
					Hdr: dns.Header{Name: "example.com.", TTL: ttl, Class: dns.ClassINET},
					DS:  rdata.DS{KeyTag: 370, Algorithm: 13, DigestType: 2, Digest: digest},
				}
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			warm := rrToString(c.mk(1527))
			cold := rrToString(c.mk(553))
			if warm != cold {
				t.Fatalf("%s string varies with header TTL — consensus will conflict on warm-cache zones:\n  ttl=1527: %q\n  ttl=553:  %q", c.name, warm, cold)
			}
			if warm != c.want {
				t.Fatalf("%s is not EXACT bare rdata (parseAlgorithm reads Fields[1] as the algorithm):\n  got:  %q\n  want: %q", c.name, warm, c.want)
			}
		})
	}

	// RRSIG has no exact pin (no field-position consumer exists for it) but
	// must obey the same TTL-invariance: its rdata carries OrigTTL, which is
	// zone data and stable — only the HEADER TTL varies per resolver cache.
	mkSig := func(ttl uint32) dns.RR {
		return &dns.RRSIG{
			Hdr:   dns.Header{Name: "example.com.", TTL: ttl, Class: dns.ClassINET},
			RRSIG: rdata.RRSIG{TypeCovered: dns.TypeDNSKEY, Algorithm: 13, Labels: 2, OrigTTL: 3600, KeyTag: 370, SignerName: "example.com.", Signature: "c2ln"},
		}
	}
	if a, b := rrToString(mkSig(1527)), rrToString(mkSig(553)); a != b {
		t.Fatalf("RRSIG string varies with header TTL:\n  %q\n  %q", a, b)
	} else if strings.Contains(a, "1527") {
		t.Fatalf("RRSIG string carries the header TTL: %q", a)
	}
}
