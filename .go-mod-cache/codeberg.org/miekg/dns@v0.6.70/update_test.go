package dns

// ExampleMsg_dynamicUpdateNameUsed shows how to set the RRs in the prereq section to
// "Name is in use" RRs. RFC 2136 section 2.4.4. Also see [ANY].
func ExampleMsg_dynamicUpdateNameUsed() {
	u := NewMsg("example.org.", TypeSOA)
	u.Opcode = OpcodeUpdate
	any := &ANY{Hdr: Header{Name: "example.org.", Class: ClassANY}}
	u.Answer = append(u.Answer, any)
	// u can now be send
}

func ExampleMsg_dynamicUpdateRemoveName() {
	u := NewMsg("example.org.", TypeSOA)
	u.Opcode = OpcodeUpdate

	any := &ANY{Hdr: Header{Name: "example.org.", Class: ClassANY}}
	u.Ns = append(u.Ns, any)
	// u can now be send
}

// ExampleMsg_dynamicRemove creates a dynamic update packet that deletes RR from a
// RRSset, see RFC 2136 section 2.5.4. Also see [ANY].
func ExampleMsg_dynamicUpdateRemove() {
	u := NewMsg("example.org.", TypeSOA)
	u.Opcode = OpcodeUpdate

	a, _ := New("example.org. IN A 127.0.0.1")
	a.Header().Class = ClassNONE
	a.Header().TTL = 0
	u.Ns = append(u.Ns, a)
	// u can now be send
}
