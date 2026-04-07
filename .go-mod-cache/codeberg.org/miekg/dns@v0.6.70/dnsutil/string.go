package dnsutil

import (
	"strconv"

	"codeberg.org/miekg/dns"
)

// TypeToString converts the type to the text presentation, or to "TYPE"+value if the type is unknown.
// Also see [ClassToString], [RcodeToString], [OpcodeToString], [CodeToString] for similar functions.
func TypeToString(t uint16) string {
	if t1, ok := dns.TypeToString[t]; ok {
		return t1
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// RcodeToString converts the code to the text presentation, or to "RCODE"+value if the rcode is unknown.
// Also see [ClassToString], [TypeToString], [OpcodeToString], [CodeToString] for similar functions.
func RcodeToString(r uint16) string {
	if r1, ok := dns.RcodeToString[r]; ok {
		return r1
	}
	return "RCODE" + strconv.Itoa(int(r))
}

// ClassToString converts the class to the text presentation, or to "CLASS"+value if the class is unknown.
// Also see [RcodeToString], [TypeToString], [OpcodeToString], [CodeToString] for similar functions.
func ClassToString(c uint16) string {
	if c1, ok := dns.ClassToString[c]; ok {
		return c1
	}
	return "CLASS" + strconv.Itoa(int(c))
}

// OpcodeToString converts the opcode to the text presentation, or to "OPCODE"+value if the opcode is unknown.
// Also see [RcodeToString], [TypeToString], [ClassToString], [CodeToString] for similar functions.
func OpcodeToString(o uint8) string {
	if o1, ok := dns.OpcodeToString[o]; ok {
		return o1
	}
	return "OPCODE" + strconv.Itoa(int(o))
}

// CodeToString converts the ENDS0 code to the text presentation, or to "CODE"+value if the code is unknown.
// Also see [RcodeToString], [TypeToString], [ClassToString], [OpcodeToString] for similar functions.
func CodeToString(c uint16) string {
	if c1, ok := dns.CodeToString[c]; ok {
		return c1
	}
	return "CODE" + strconv.Itoa(int(c))
}
