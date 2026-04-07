package dns_test

// This files has (testable) snippets to document  how to do common tasks.
// Feel free to add ones you encountered when using this library.

import (
	"context"
	"fmt"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// ExampleHeader_replace shows how to overwrite a header.
func ExampleHeader_replace() {
	rr := &dns.MX{}
	*(rr.Header()) = dns.Header{Name: dnsutil.Fqdn("example.org"), Class: dns.ClassINET}
	// Or
	hdr := rr.Header()
	*hdr = dns.Header{Name: dnsutil.Fqdn("example.org"), Class: dns.ClassINET}
	// Or
	rr.Header().Name = "example.org."
	rr.Header().Class = dns.ClassINET
}

// ExampleRDATA shows how to access the various elements in a [dns.RR].
func ExampleRDATA() {
	rr := &dns.MX{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET, TTL: 3600}, MX: rdata.MX{Preference: 10, Mx: "mx.miek.nl."}}
	rh := rr.Header()
	rd := rr.Data()
	fmt.Println("Split RR")
	fmt.Printf("Record = %v\n", rr)
	fmt.Printf("Header = %v\n", rh)
	fmt.Printf("Data   = %v\n", rd)

	// Updating rr.Preference does not affect rd, rd is a copy.
	rr.Preference = 20
	fmt.Printf("Data   = %v\n", rd) // Still 10 mx.miek.nl.

	// Updating rd.Preference does not affect rr.
	rdmx := rd.(rdata.MX) // Need this otherwise:  cannot assign to rd.(rdata.MX).Preference (neither addressable nor a map index expression)
	rdmx.Preference = 20

	// Update the RR with the new rdata.
	fn := dns.TypeToRDATA[dns.TypeMX]
	fn(rr, rdmx)
	fmt.Printf("Record = %v\n", rr) // .... 20 mx.miek.nl.
}

// ExampleMsg_packUnpack shows how to serialize and deserialize DNS messages.
//
// In v1, Pack returned ([]byte, error) and Unpack took a []byte argument.
// In v2, Pack stores the wire format in msg.Data and Unpack reads from msg.Data.
// Always copy msg.Data if you need to hold on to the bytes after the message
// is reused or the pool reclaims it.
func ExampleMsg_packUnpack() {
	m := dns.NewMsg("example.com.", dns.TypeA)

	// Pack encodes the message into wire format stored in m.Data.
	// It does not return the bytes; retrieve them from m.Data after the call.
	if err := m.Pack(); err != nil {
		panic(err)
	}

	// Copy before handing off — m.Data may be reused by the pool.
	wire := make([]byte, len(m.Data))
	copy(wire, m.Data)

	// Unpack: place the raw bytes into m.Data, then call Unpack with no args.
	m2 := new(dns.Msg)
	m2.Data = wire
	if err := m2.Unpack(); err != nil {
		panic(err)
	}

	fmt.Println(m2.Question[0].Header().Name)
	// Output:
	// example.com.
}

// ExampleMsg_edns shows how to set and inspect EDNS0 fields.
//
// In v1 you built an OPT record by hand and appended it to msg.Extra, then
// retrieved it with msg.IsEdns0(). In v2 the DO bit and UDP payload size are
// first-class fields on Msg. Pack creates the OPT record automatically;
// Unpack populates the fields back from the wire.
func ExampleMsg_edns() {
	m := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeDNSKEY)

	// Set EDNS0 directly — no explicit OPT record needed.
	m.Security = true // DO (DNSSEC OK) bit
	m.UDPSize = 4096  // advertised UDP payload size

	if err := m.Pack(); err != nil {
		panic(err)
	}

	// Simulate receiving the message and inspecting EDNS0 on the far end.
	r := new(dns.Msg)
	r.Data = make([]byte, len(m.Data))
	copy(r.Data, m.Data)
	if err := r.Unpack(); err != nil {
		panic(err)
	}

	fmt.Println("DO bit:", r.Security)
	fmt.Println("UDP size:", r.UDPSize)
	// Output:
	// DO bit: true
	// UDP size: 4096
}

// ExampleClient_transferIn shows how to perform an AXFR zone transfer.
//
// In v1 you created a dns.Transfer struct, called .In(), and received records
// in env.RR. In v2 use Client.TransferIn; records arrive in env.Answer.
// Use a context to cancel early (e.g. once you have seen enough records).
func ExampleClient_transferIn() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	msg := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeAXFR)
	msg.RecursionDesired = false

	client := dns.NewClient()

	ch, err := client.TransferIn(ctx, msg, "tcp", "192.0.2.1:53")
	if err != nil {
		// Connection or send error before the transfer started.
		return
	}

	for env := range ch {
		if env.Error != nil {
			fmt.Println("transfer error:", env.Error)
			return
		}
		for _, rr := range env.Answer {
			fmt.Println(rr)
		}
	}
}
