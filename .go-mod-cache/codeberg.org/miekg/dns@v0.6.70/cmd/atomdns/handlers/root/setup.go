package root

import (
	"os"
	"path/filepath"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/conffile"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func (r *Root) Setup(co *dnsserver.Controller) error {
	r.global = co.Global.Root

	for co.Next() {
		args := co.RemainingArgs()
		if len(args) != 1 {
			return co.ArgErr()
		}
		cur := conffile.Tilde(args[0])
		if !filepath.IsAbs(cur) {
			pwd, _ := os.Getwd()
			cur = filepath.Join(pwd, cur)
		}
		if _, err := os.Stat(cur); err != nil {
			return err
		}
		co.Global.Root = cur
	}
	return nil
}

func (r *Root) Teardown(co *dnsserver.Controller) error { co.Global.Root = r.global; return nil }
