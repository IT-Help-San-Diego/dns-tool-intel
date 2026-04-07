package empty

import (
	"codeberg.org/miekg/dns"
)

type Empty int

func (e *Empty) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc { return nil }
