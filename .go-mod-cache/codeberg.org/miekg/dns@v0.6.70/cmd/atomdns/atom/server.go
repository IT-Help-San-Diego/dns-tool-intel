package atom

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strings"
	"sync/atomic"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/atom/atomhttp"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/empty"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/global"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/metrics"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/refuse"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/unpack"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/conffile"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnslog"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/zlog"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/caddyserver/certmagic"
	"golang.org/x/net/netutil"
)

type Server struct {
	global  *global.Global
	config  []byte
	version string // atomdns version

	mux     *dns.ServeMux
	servers []*dns.Server
	started chan error

	tlsservers []*dns.Server
	tlsstarted chan error

	httpservers []*atomhttp.Server
	httpstarted chan error

	unixservers []*dns.Server
	unixstarted chan error
}

// Start starts a server.
func (s *Server) Start() error {
	if err := s.global.Startup(); err != nil {
		return fmt.Errorf("global: %w", err)
	}
	for i := range s.servers {
		go Serve(s.started, s.servers[i])
	}
	// drain the channel, we either get a nil for success or otherwise an error _for each server_ started
	for range s.servers {
		err := <-s.started
		if err != nil {
			return fmt.Errorf("dns: %w", err)
		}
	}

	for i := range s.tlsservers {
		opt := func(srv *dns.Server) error {
			if x := s.global.TlsLimits.MaxInflight; x > 0 {
				srv.ListenFunc = func(s *dns.Server) {
					s.Listener = netutil.LimitListener(s.Listener, x)
				}
			}
			return nil
		}
		go Serve(s.tlsstarted, s.tlsservers[i], opt)
	}
	for range s.tlsservers {
		err := <-s.tlsstarted
		if err != nil {
			return fmt.Errorf("dot: %w", err)
		}
	}

	for i := range s.httpservers {
		go atomhttp.Serve(s.httpstarted, s.httpservers[i], s.global)
	}
	for range s.httpservers {
		if err := <-s.httpstarted; err != nil {
			return fmt.Errorf("doh: %w", err)
		}
	}

	for i := range s.unixservers {
		opt := func(srv *dns.Server) (err error) {
			srv.Net = "unix"
			srv.Listener, err = net.Listen("unix", s.global.UnixAddr)
			return err
		}
		go Serve(s.unixstarted, s.unixservers[i], opt)
	}
	for range s.unixservers {
		err := <-s.unixstarted
		if err != nil {
			return fmt.Errorf("dou: %w", err)
		}
	}
	roles := []slog.Attr{}
	const r = "role"
	if addr := s.Addr(); len(addr) > 0 {
		roles = append(roles, slog.String(r, "DNS:"+addr[0]))
	}

	if s.global.TlsConfig != nil || s.global.TlsCertConfig != nil {
		if s.global.HttpLimits.Servers > 0 {
			roles = append(roles, slog.String(r, "DOH:"+s.HttpAddr()[0]))
		}
		if s.global.TlsLimits.Servers > 0 {
			roles = append(roles, slog.String(r, "DOT:"+s.TlsAddr()[0]))
		}
	}
	if s.global.UnixLimits.Servers > 0 {
		roles = append(roles, slog.String(r, "DOU:"+s.UnixAddr()[0]))
	}

	// bit of a cop out, but if roles is empty, we have nothing to run
	if len(roles) == 0 {
		return fmt.Errorf("no servers defined, nothing to do")
	}

	if bi := builtinfo(); len(bi) == 4 {
		slog.Info("Build", bi[0], bi[1], bi[2], bi[3])
	}
	slog.Info("Listening", "total", len(roles), "roles", slog.GroupValue(roles...))
	slog.Info("Launched", "config", s.global.Config, "PID", os.Getpid(), "version", "v"+s.version, "dns", dns.Version, "zones", len(s.global.Registered))
	return nil
}

func Serve(ch chan error, srv *dns.Server, opts ...func(s *dns.Server) error) {
	for _, opt := range opts {
		if err := opt(srv); err != nil {
			ch <- err
			return
		}
	}
	if err := srv.ListenAndServe(); err != nil {
		ch <- err
		return
	}
}

// Shutdown shuts down a server.
func (s *Server) Shutdown(ctx context.Context) error {
	if err := s.global.Shutdown(); err != nil {
		slog.Warn("Failed to run shutdown", dnslog.Error(err))
	}
	for _, srv := range s.servers {
		srv.Shutdown(ctx)
	}
	for _, srv := range s.tlsservers {
		srv.Shutdown(ctx)
	}
	for _, srv := range s.httpservers {
		srv.Shutdown(ctx)
	}
	for _, srv := range s.unixservers {
		srv.Shutdown(ctx)
	}
	return nil
}

// New returns a new server that has parsed the config in and r. If conf start with < and ends with > it's
// considered "not a file" and the contents of r is also stored in s.config.
func New(conf string, r io.Reader) (*Server, error) {
	s := &Server{mux: dns.NewServeMux()}
	w := &bytes.Buffer{}

	if builtin(conf) {
		r = io.TeeReader(r, w)
	}

	global, err := s.parse(conf, r)
	if err != nil {
		return nil, err
	}
	if builtin(conf) {
		s.config = w.Bytes()
	}
	s.global = global

	// dns servers
	s.servers = make([]*dns.Server, global.Limits.Servers*2) // *2=udp/tcp
	s.started = make(chan error, len(s.servers))
	for j := range s.servers {
		net := "tcp"
		if j < len(s.servers)/2 {
			net = "udp"
		}
		s.servers[j] = &dns.Server{
			ReuseAddr: true, ReusePort: true,
			Handler: s.mux, Net: net, Addr: global.Addr, MaxTCPQueries: global.Limits.MaxTCPQueries,
		}
		msgInvalidFunc(s.servers[j], global.MetricsN)
		s.servers[j].NotifyStartedFunc = func(_ context.Context) { s.started <- nil }
	}

	// dot server
	s.tlsservers = make([]*dns.Server, global.TlsLimits.Servers)
	s.tlsstarted = make(chan error, len(s.tlsservers))
	for j := range s.tlsservers {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		if global.TlsConfig != nil {
			tlsConfig = global.TlsConfig.Clone()
		}
		if global.TlsCertConfig != nil {
			tlsConfig = global.TlsCertConfig.TLSConfig().Clone()
		}
		tlsConfig.NextProtos = dns.NextProtos
		s.tlsservers[j] = &dns.Server{
			ReuseAddr:     true,
			ReusePort:     true,
			TLSConfig:     tlsConfig,
			Handler:       s.mux,
			Net:           "tcp",
			Addr:          global.TlsAddr,
			MaxTCPQueries: global.TlsLimits.MaxTCPQueries,
		}
		msgInvalidFunc(s.tlsservers[j], global.MetricsN)
		s.tlsservers[j].NotifyStartedFunc = func(_ context.Context) { s.tlsstarted <- nil }
	}

	// doh servers
	s.httpservers = make([]*atomhttp.Server, global.HttpLimits.Servers)
	s.httpstarted = make(chan error, len(s.httpservers))
	for j := range s.httpservers {
		var i atomic.Uint64
		N := global.MetricsN
		s.httpservers[j] = atomhttp.New(global.HttpAddr, s.mux, func(_ *dns.Msg, _ error) {
			if N == 0 {
				return
			}
			if (i.Add(1)-1)%N == 0 {
				metrics.Dropped.Inc()
			}
		})
	}

	// dou servers
	s.unixservers = make([]*dns.Server, global.UnixLimits.Servers)
	s.unixstarted = make(chan error, len(s.unixservers))
	for j := range s.unixservers {
		s.unixservers[j] = &dns.Server{
			Handler:       s.mux,
			Net:           "unix",
			Addr:          global.UnixAddr,
			MaxTCPQueries: global.UnixLimits.MaxTCPQueries,
		}
		msgInvalidFunc(s.unixservers[j], global.MetricsN)
		s.unixservers[j].NotifyStartedFunc = func(_ context.Context) { s.unixstarted <- nil }
	}

	// Check if we need something else running on 443 to do the challenge for TLS certs.
	if global.TlsCertConfig != nil {
		slog.Debug("Startup running extra server for ACME challenge", "port", "443")
		h, p, _ := net.SplitHostPort(global.HttpAddr)
		if p != "0" && p != "443" {
			addr := net.JoinHostPort(h, "443")
			s.httpservers = append(
				s.httpservers,
				atomhttp.New(addr, s.mux, func(_ *dns.Msg, _ error) {}),
			)
			s.httpstarted = make(chan error, len(s.httpservers))
		}
	}

	return s, nil
}

func (s *Server) parse(conf string, r io.Reader) (*global.Global, error) {
	blocks, err := conffile.Parse(conf, r)
	if err != nil {
		return nil, err
	}

	certmagic.Default.Logger = zlog.New(false)
	global := &global.Global{
		Registered: make(map[string]struct{}),
		Config:     conf,
		Root:       func() string { wd, _ := os.Getwd(); return wd }(),
		Addr:       "[::]:53",
		Limits:     global.Limits{MaxTCPQueries: dns.MaxTCPQueries, Servers: runtime.NumCPU() * 3},
		TlsAddr:    "[::]:853",
	}

	return global, s.Setup(conf, global, blocks)
}

func (s *Server) Setup(conf string, global *global.Global, blocks []conffile.HandlerBlock) error {
	for _, b := range blocks {
		if b.Keys != nil {
			continue
		}
		for _, dir := range b.Directives {
			d := conffile.NewDispenser(conf, nil, b.Tokens[dir], nil)
			err := global.Setup(d)
			if err != nil {
				return fmt.Errorf("could not parse global config: %w", err)
			}
		}
		global.OnStartup(func() error {
			slog.With("handler", "global").Info("Startup", "signal", "HUP")
			return nil
		})
		break
	}
	// reset for reload, s.mux is lock guarded, global.Registered is used in a non-concurrent way
	for k := range global.Registered {
		s.mux.HandleRemove(k)
	}
	global.Registered = map[string]struct{}{}

	type teardown struct {
		name string
		fn   func(*dnsserver.Controller) error
	}

	const Unpack = 0
	for _, b := range blocks {
		if b.Keys == nil {
			continue
		}
		hs := []handlers.Handler{new(unpack.Unpack)}
		hs[Unpack].(*unpack.Unpack).ClassFunc = unpack.DefaultClassFunc

		teardowns := []teardown{}
		names := []string{}

		// prepend unpack to start the chain
		for _, name := range b.Directives {
			names = append(names, name)
			newFn, ok := handlers.StringToHandler[name]
			if !ok {
				slog.With("handler", name).Warn("Unknown handler, skipping config")
				newFn = func() handlers.Handler { return new(empty.Empty) }
			}
			handler := newFn()
			if s, ok := handler.(handlers.Setupper); ok {
				co := &dnsserver.Controller{
					Dispenser: conffile.NewDispenser(conf, b.Keys, b.Tokens[name], names),
					Global:    global,
				}
				err := s.Setup(co)
				if err != nil {
					return handler.Err(fmt.Errorf("%w for '%s'", err, strings.Join(b.Keys, ",")))
				}
			}
			if t, ok := handler.(handlers.Teardowner); ok {
				teardowns = append(teardowns, teardown{name, t.Teardown})
			}

			if fn := handler.HandlerFunc(nil); fn != nil {
				// Do not add noop handler funcs.
				hs = append(hs, handler)
			} else {
				// Noop handler, check again if its a setupper, otherwise it isn't doing anything.
				if _, ok := handler.(handlers.Setupper); !ok {
					return fmt.Errorf("handler: %s, is a noop handler, but has no setup", name)
				}
			}
			if c, ok := handler.(handlers.Classer); ok {
				hs[Unpack].(*unpack.Unpack).ClassFunc = c.Class
			}
		}

		for _, teardown := range teardowns {
			co := &dnsserver.Controller{
				Dispenser: conffile.NewDispenser(conf, b.Keys, nil, nil),
				Global:    global,
			}
			err := teardown.fn(co)
			if err != nil {
				newFn, _ := handlers.StringToHandler[teardown.name]
				handler := newFn()
				return handler.Err(fmt.Errorf("%w for '%s'", err, strings.Join(b.Keys, ",")))
			}
		}

		hs = append(hs, new(refuse.Refuse)) // add refuse guard

		for _, k := range b.Keys {
			k = dnsutil.Canonical(k)

			if _, ok := global.Registered[k]; ok {
				return fmt.Errorf("origin already registered: %s", k)
			}

			if !global.Quiet {
				attrs := make([]slog.Attr, len(names))
				for i := range names {
					attrs[i] = slog.String("handler", names[i])
				}

				slog.Info(k, "handlers", slog.GroupValue(attrs...))
			}
			s.mux.HandleFunc(k, handlers.Compile(hs))
			global.Registered[k] = struct{}{}
		}
	}
	return nil
}

// When a server is started on the wildcard port, this method can be used to get the actual address and
// listening port. Note that with a wildcard port the servers will all run on a different port. For all
// returned address the first half are the UDP listening port, the other half is TCP.
// See [Server.HttpAddr] for getting the addresss of the DOH server.
func (s *Server) Addr() []string {
	addr := make([]string, len(s.servers))
	for i, srv := range s.servers {
		if x := srv.Listener; x != nil {
			addr[i] = x.Addr().String()
		}
		if x := srv.PacketConn; x != nil {
			addr[i] = x.LocalAddr().String()
		}
	}
	return addr
}

// HttpAddr return the addresses of the DOH servers. See [Server.Addr].
func (s *Server) HttpAddr() []string {
	addr := make([]string, len(s.httpservers))
	for i, srv := range s.httpservers {
		addr[i] = srv.Listener.Addr().String()
	}
	return addr
}

// TlsAddr returns the addreses of the DOT servers. See [Server.Addr].
func (s *Server) TlsAddr() []string {
	addr := make([]string, len(s.tlsservers))
	for i, srv := range s.tlsservers {
		addr[i] = srv.Listener.Addr().String()
	}
	return addr
}

func (s *Server) UnixAddr() []string {
	addr := make([]string, len(s.unixservers))
	for i, srv := range s.unixservers {
		addr[i] = srv.Listener.Addr().String()
	}
	return addr
}

func builtin(conf string) bool { return strings.HasPrefix(conf, "<") && strings.HasSuffix(conf, ">") }

// msgInvalidFunc sets up the MsgInvalidFunc for a server.
func msgInvalidFunc(s *dns.Server, N uint64) {
	var i atomic.Uint64
	s.MsgInvalidFunc = func(_ *dns.Msg, _ error) {
		if N == 0 {
			return
		}
		if (i.Add(1)-1)%N == 0 {
			metrics.Dropped.Inc()
		}
	}
}
