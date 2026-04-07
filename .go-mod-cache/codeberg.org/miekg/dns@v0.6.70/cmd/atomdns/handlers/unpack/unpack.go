package unpack

import (
	"context"
	"fmt"

	"codeberg.org/miekg/dns"
)

type Unpack struct {
	// ClassFunc checks the class. The default (when nil) is to only allow the "IN" class.
	ClassFunc func(*dns.Msg) error
}

func (u *Unpack) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		if err := r.Unpack(); err != nil {
			log().Debug("Unpack failure", Err(err), "zone", dns.Zone(ctx))
			return
		}
		if err := u.ClassFunc(r); err != nil {
			log().Debug("Forbidden class", Err(err), "zone", dns.Zone(ctx))
			return
		}

		next.ServeDNS(ctx, w, r)
	})
}

func DefaultClassFunc(r *dns.Msg) error {
	if len(r.Question) == 0 {
		return nil
	}
	if r.Question[0].Header().Class == dns.ClassINET {
		return nil
	}
	return fmt.Errorf("class is not IN")
}
