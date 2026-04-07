package dns_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
	"codeberg.org/miekg/dns/internal/bin"
	"codeberg.org/miekg/dns/internal/dnsfuzz"
)

func ExampleMsg() {
	m := dns.NewMsg("miek.nl.", dns.TypeMX)
	c := new(dns.Client)
	r, _, err := c.Exchange(context.TODO(), m, "udp", "127.0.0.1:53")
	if err != nil {
		log.Fatal(err)
	}
	if m, ok := r.Answer[0].(*dns.MX); ok {
		fmt.Println(m.Mx)
	}
	if n, ok := r.Pseudo[0].(*dns.NSID); ok {
		fmt.Println(n.Nsid)
	}
	for rr := range r.RRs() {
		fmt.Println(rr)
	}
}

func ExampleMsg_dNSSEC() {
	m := dns.NewMsg("miek.nl.", dns.TypeMX)
	m.UDPSize = dns.DefaultMsgSize
	m.Security = true
	dns.Exchange(context.TODO(), m, "udp", "127.0.0.1:53")
	// handle returned message.
}

func TestMsgBinary(t *testing.T) {
	tcs := []struct {
		name string
		buf  []byte
		fn   func(*dns.Msg) error
	}{
		{
			// m := dns.NewMsg("example.org.", dns.TypeMX)
			// m.Answer = []dns.RR{dnstest.New("example.org. IN SOA linode.atoom.net. miek\\.miek.nl. 1 3600 3600 3600 3600")}
			"soa-mbox",
			[]byte{148, 44, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 7, 101, 120, 97, 109, 112, 108, 101, 3, 111, 114, 103, 0, 0, 15, 0, 1, 192, 12, 0, 6, 0, 1, 0, 0, 14, 16, 0, 52, 6, 108, 105, 110, 111, 100, 101, 5, 97, 116, 111, 111, 109, 3, 110, 101, 116, 0, 9, 109, 105, 101, 107, 46, 109, 105, 101, 107, 2, 110, 108, 0, 0, 0, 0, 1, 0, 0, 14, 16, 0, 0, 14, 16, 0, 0, 14, 16, 0, 0, 14, 16},
			func(m *dns.Msg) error {
				if len(m.Answer) != 1 {
					return errors.New("expected answer section")
				}
				s, ok := m.Answer[0].(*dns.SOA)
				if !ok {
					return errors.New("expected SOA")
				}
				if s.Mbox != `miek\.miek.nl.` {
					return errors.New("SOA Mbox is not correct")
				}
				return nil
			},
		},

		{
			"edns0-subnet",
			[]byte{149, 112, 0, 16, 0, 1, 0, 0, 0, 0, 0, 1, 1, 97, 4, 109, 105, 69, 75, 2, 78, 76, 0, 0, 1, 0, 1, 0, 0, 41, 5, 120, 0, 0, 128, 0, 0, 11, 0, 8, 0, 7, 0, 1, 24, 0, 14, 128, 63},
			func(m *dns.Msg) error {
				if len(m.Pseudo) == 0 {
					return errors.New("expected pseudo section")
				}
				s, ok := m.Pseudo[0].(*dns.SUBNET)
				if !ok {
					return errors.New("expected EDNS0 SUBNET")
				}
				const addr = "14.128.63.0"
				if s.Address != netip.MustParseAddr(addr) {
					return errors.New("expected address: " + addr)
				}
				return nil
			},
		},
		{
			"edns0-subnet",
			[]byte{255, 234, 0, 16, 0, 1, 0, 0, 0, 0, 0, 1, 7, 99, 111, 114, 101, 68, 110, 83, 2, 105, 111, 0, 0, 28, 0, 1, 0, 0, 41, 5, 120, 0, 0, 128, 0, 0, 11, 0, 8, 0, 7, 0, 1, 24, 0, 62, 212, 234},
			func(m *dns.Msg) error {
				if len(m.Pseudo) == 0 {
					return errors.New("expected pseudo section")
				}
				s, ok := m.Pseudo[0].(*dns.SUBNET)
				if !ok {
					return errors.New("expected EDNS0 SUBNET")
				}
				const addr = "62.212.234.0"
				if s.Address != netip.MustParseAddr(addr) {
					return errors.New("expected address: " + addr)
				}
				return nil
			},
		},
		{
			"opt-and-tsig",
			[]byte{148, 7, 1, 32, 0, 1, 0, 0, 0, 0, 0, 2, 4, 109, 105, 101, 107, 2, 110, 108, 0, 0, 6, 0, 1, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 12, 0, 10, 0, 8, 73, 65, 52, 201, 253, 43, 171, 193, 4, 109, 105, 101, 107, 2, 110, 108, 0, 0, 250, 0, 255, 0, 0, 0, 0, 0, 93, 11, 104, 109, 97, 99, 45, 115, 104, 97, 53, 49, 50, 0, 0, 0, 105, 104, 143, 225, 1, 44, 0, 64, 195, 169, 191, 31, 144, 147, 160, 197, 245, 76, 217, 137, 234, 208, 246, 112, 113, 12, 208, 172, 99, 181, 29, 108, 140, 62, 197, 130, 116, 207, 127, 178, 163, 16, 242, 203, 41, 135, 60, 218, 187, 237, 181, 106, 91, 34, 125, 38, 190, 56, 117, 43, 76, 212, 161, 165, 61, 214, 193, 180, 117, 1, 27, 129, 148, 7, 0, 0, 0, 0},
			func(m *dns.Msg) error {
				if len(m.Pseudo) == 0 {
					return errors.New("expected pseudo section")
				}
				_, ok := m.Pseudo[len(m.Pseudo)-1].(*dns.TSIG)
				if !ok {
					return errors.New("expected TSIG")
				}
				return nil
			},
		},
		{
			"opt-and-tsig-extra-should-empty",
			[]byte{148, 7, 1, 32, 0, 1, 0, 0, 0, 0, 0, 2, 4, 109, 105, 101, 107, 2, 110, 108, 0, 0, 6, 0, 1, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 12, 0, 10, 0, 8, 73, 65, 52, 201, 253, 43, 171, 193, 4, 109, 105, 101, 107, 2, 110, 108, 0, 0, 250, 0, 255, 0, 0, 0, 0, 0, 93, 11, 104, 109, 97, 99, 45, 115, 104, 97, 53, 49, 50, 0, 0, 0, 105, 104, 143, 225, 1, 44, 0, 64, 195, 169, 191, 31, 144, 147, 160, 197, 245, 76, 217, 137, 234, 208, 246, 112, 113, 12, 208, 172, 99, 181, 29, 108, 140, 62, 197, 130, 116, 207, 127, 178, 163, 16, 242, 203, 41, 135, 60, 218, 187, 237, 181, 106, 91, 34, 125, 38, 190, 56, 117, 43, 76, 212, 161, 165, 61, 214, 193, 180, 117, 1, 27, 129, 148, 7, 0, 0, 0, 0},
			func(m *dns.Msg) error {
				if len(m.Extra) != 0 {
					return errors.New("expected additional section to be empty")
				}
				return nil
			},
		},
		{
			"unknown-edns0-code20",
			//  edns255 := &dns.ERFC3597{EDNS0Code: 255, Code: hex.EncodeToString([]byte("hallo"))}
			//  m.Pseudo = append(m.Pseudo, edns255)
			[]byte{0, 3, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 3, 119, 119, 119, 7, 101, 120, 97, 109, 112, 108, 101, 3, 111, 114, 103, 0, 0, 1, 0, 1, 0, 0, 41, 0, 0, 0, 0, 0, 0, 0, 9, 0, 255, 0, 5, 104, 97, 108, 108, 111},
			func(m *dns.Msg) error {
				if len(m.Pseudo) != 1 {
					return errors.New("expected pseudo section to carry an option")
				}
				x := m.Pseudo[0].(*dns.ERFC3597)
				if x.EDNS0Code != 255 {
					return fmt.Errorf("expected code 255, got %d", x.EDNS0Code)
				}
				return nil
			},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			m := &dns.Msg{Data: tc.buf}
			if err := m.Unpack(); err != nil {
				t.Logf("%v\n", bin.Dump(m.Data))
				t.Fatal(err)
			}
			if err := tc.fn(m); err != nil {
				t.Logf("%s\n", bin.Dump(m.Data))
				t.Fatal(err)
			}
		})
	}
}

func TestMsg(t *testing.T) {
	const msgArcount = 10 // offset in the message where the Arcount is, 2 octets long.
	testcases := []struct {
		name   string
		makeFn func() *dns.Msg
		testFn func(m *dns.Msg) error
	}{
		{
			"extendedrcode",
			func() *dns.Msg {
				m := dns.NewMsg("example.org.", dns.TypeMX)
				m.ID = 3
				m.Rcode = dns.RcodeBadTime
				return m
			},
			func(r *dns.Msg) error {
				if r.Rcode != dns.RcodeBadTime {
					return fmt.Errorf("expected %s, got %s", dns.RcodeToString[dns.RcodeBadTime], dns.RcodeToString[r.Rcode])
				}
				return nil
			},
		},
		{
			"security",
			func() *dns.Msg { m := dns.NewMsg("example.org.", dns.TypeMX); m.ID = 3; m.Security = true; return m },
			func(r *dns.Msg) error {
				if !r.Security {
					return fmt.Errorf("expected %t, got %t", r.Security, !r.Security)
				}
				arcount := binary.BigEndian.Uint16(r.Data[msgArcount:])
				if arcount != 1 {
					return fmt.Errorf("expected arcount to be 1, got %d", arcount)
				}
				return nil
			},
		},
		{
			"security+nsd",
			func() *dns.Msg {
				m := dns.NewMsg("example.org.", dns.TypeMX)
				m.ID = 3
				m.Security = true
				m.Pseudo = []dns.RR{&dns.NSID{}}
				return m
			},
			func(r *dns.Msg) error {
				if !r.Security {
					return fmt.Errorf("expected %t, got %t", r.Security, !r.Security)
				}
				arcount := binary.BigEndian.Uint16(r.Data[msgArcount:])
				if arcount != 1 { // nsid and DO bit are stored in a single record
					return fmt.Errorf("expected arcount to be 1, got %d", arcount)
				}
				if x := len(r.Pseudo); x != 1 {
					return fmt.Errorf("expected len(pseudo) to be 1, got %d", x)
				}
				return nil
			},
		},
		{
			"security+tsig-nosign+nsid",
			func() *dns.Msg {
				m := dns.NewMsg("example.org.", dns.TypeMX)
				m.ID = 3
				m.Security = true
				m.Pseudo = []dns.RR{&dns.NSID{}}
				m.Pseudo = append(m.Pseudo, dns.NewTSIG("example.", dns.HmacSHA256, 0))
				return m
			},
			func(r *dns.Msg) error {
				if !r.Security {
					return fmt.Errorf("expected %t, got %t", !r.Security, r.Security)
				}
				arcount := binary.BigEndian.Uint16(r.Data[10:])
				if arcount != 2 { // nsid and DO bit are stored in a single record + tsig
					return fmt.Errorf("expected arcount to be 2, got %d", arcount)
				}
				if x := len(r.Pseudo); x != 2 {
					return fmt.Errorf("expected len(pseudo) to be 2, got %d", x)
				}
				return nil
			},
		},
		{
			"tsig",
			func() *dns.Msg {
				m := dns.NewMsg("example.org.", dns.TypeMX)
				m.ID = 3
				m.Pseudo = []dns.RR{dns.NewTSIG("example.", dns.HmacSHA256, 0)}
				return m
			},
			func(r *dns.Msg) error {
				if r.Security {
					return fmt.Errorf("expected %t, got %t", !r.Security, r.Security)
				}
				arcount := binary.BigEndian.Uint16(r.Data[10:])
				if arcount != 1 {
					return fmt.Errorf("expected arcount to be q, got %d", arcount)
				}
				if x := len(r.Pseudo); x != 1 {
					return fmt.Errorf("expected len(pseudo) to be 1, got %d", x)
				}
				if x := len(r.Extra); x != 0 {
					return fmt.Errorf("expected len(extra) to be 0, got %d", x)
				}
				return nil
			},
		},
		{
			"nsec3",
			func() *dns.Msg {
				m := dns.NewMsg("miek.nl.", dns.TypeMX)
				m.ID = 3
				nsec3 := dnstest.New("k36vo59bkum4osckkrd8tvibdgr0njbc.nl. 599 IN NSEC3 1 0 0 - K36VONMLM2T8IF3G8P5AV864OHLTB7K7 NS SOA TXT RRSIG DNSKEY NSEC3PARAM")
				m.Answer = []dns.RR{nsec3}
				return m
			},
			func(r *dns.Msg) error {
				expect := []byte{0, 3, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 4, 109, 105, 101, 107, 2, 110, 108, 0, 0, 15, 0, 1, 32, 107, 51, 54, 118, 111, 53, 57, 98, 107, 117, 109, 52, 111, 115, 99, 107, 107, 114, 100, 56, 116, 118, 105, 98, 100, 103, 114, 48, 110, 106, 98, 99, 192, 17, 0, 50, 0, 1, 0, 0, 2, 87, 0, 35, 1, 0, 0, 0, 0, 20, 160, 205, 252, 94, 213, 176, 186, 137, 60, 112, 70, 74, 175, 160, 196, 196, 107, 213, 158, 135, 0, 7, 34, 0, 128, 0, 0, 2, 144}
				if bytes.Compare(r.Data, expect) != 0 {
					return fmt.Errorf("Msg octets do not match")
				}
				return nil

			},
		},
		{
			"pseudo-nsid",
			func() *dns.Msg {
				m := dns.NewMsg("miek.nl.", dns.TypeMX)
				m.ID = 3
				m.Pseudo = []dns.RR{&dns.NSID{}}
				return m
			},
			func(r *dns.Msg) error {
				// 41 is OPT after the zeros, 04 -> rdlength, 03 -> code of NSID, 00 -> "rdlength" of NSID
				expect := []byte{0, 3, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 4, 109, 105, 101, 107, 2, 110, 108, 0, 0, 15, 0, 1, 0, 0, 41, 0, 0, 0, 0, 0, 0, 0, 4, 0, 3, 0, 0}
				if bytes.Compare(r.Data, expect) != 0 {
					return fmt.Errorf("Msg octets do not match")
				}
				return nil
			},
		},
		{
			"question-mx",
			func() *dns.Msg {
				m := dns.NewMsg("miek.nl.", dns.TypeMX)
				m.ID = 3
				return m
			},
			func(r *dns.Msg) error {
				expect := []byte{0, 3, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 109, 105, 101, 107, 2, 110, 108, 0, 0, 15, 0, 1}
				if bytes.Compare(r.Data, expect) != 0 {
					return fmt.Errorf("Msg octets do not match")
				}
				return nil
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.makeFn()
			m.Pack()

			r := new(dns.Msg)
			r.Data = m.Data
			r.Unpack()
			if err := tc.testFn(r); err != nil {
				t.Fatalf("failed testFn: %s", err)
			}
		})
	}

}

func FuzzMsgPack(f *testing.F) {
	binaries := []string{"dig-mx-miek.nl", "dig+do+nsid-a-miek.nl"}
	for _, binary := range binaries {
		buf, _ := os.ReadFile("testdata/" + binary)
		f.Add(buf)
	}
	start := time.Now()
	f.Fuzz(func(t *testing.T, b []byte) {
		m := &dns.Msg{Data: b}
		m.Unpack()
		dnsfuzz.Stop(t, start)
	})
}

func TestMsgReadAll(t *testing.T) {
	m := dns.NewMsg("example.org.", dns.TypeA)
	m.Pack()

	done := make(chan struct{})
	go func() {
		io.ReadAll(m) // should not hang
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected io.ReadAll to complete, but hung")
	}
}
