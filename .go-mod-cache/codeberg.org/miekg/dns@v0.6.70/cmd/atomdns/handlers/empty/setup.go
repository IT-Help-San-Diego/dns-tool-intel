package empty

import (
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func (e *Empty) Setup(co *dnsserver.Controller) error {
	for co.Next() {
	}
	return nil
}
