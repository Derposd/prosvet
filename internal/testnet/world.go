package testnet

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ordinarysim/prosvet/internal/catalog"
	"github.com/ordinarysim/prosvet/internal/fingerprint"
	"github.com/ordinarysim/prosvet/internal/probe"
)

// Host describes one simulated service and how the censor treats it.
type Host struct {
	Name string
	IP   string

	System *Record // system resolver answer (default: A=IP)
	NSDI   *Record // national DNS answer (default: same as System)
	Ref    *Record // reference DoH answer (default: A=IP)

	TLS     Action            // middlebox default action for this IP
	Rules   map[string]Action // per-SNI actions; the key "$self" means Name
	Rogue   bool              // origin presents a certificate from an untrusted "state" CA
	Block   string            // "blackhole" or "refuse" at TCP level
	HTTP80  string            // if set, port 80 answers with a redirect to this location
	NoQUIC  bool
	Missing bool // no server listens (connection refused on every port)
}

// World is a running simulated network.
type World struct {
	CA      *CA
	Rogue   *CA
	Dialer  *Dialer
	SysDNS  *DNSServer
	NSDI    *DNSServer
	RefDNS  *DNSServer
	closers []func()
}

// Simulated infrastructure addresses (TEST-NET-2, never routed).
const (
	NSDIAddr   = "198.51.100.53"
	DoHHost    = "doh.test"
	PublicDNS1 = "198.51.100.1"
	PublicDNS8 = "198.51.100.8"
)

// NewWorld starts all servers for the given hosts.
func NewWorld(hosts []Host) (*World, error) {
	w := &World{Dialer: NewDialer()}
	var err error
	if w.CA, err = NewCA("Prosvet Testnet Root"); err != nil {
		return nil, err
	}
	if w.Rogue, err = NewCA("Russian Trusted Sub CA"); err != nil {
		return nil, err
	}

	sys, nsdi, ref := map[string]Record{}, map[string]Record{}, map[string]Record{}
	names := []string{DoHHost}
	for _, h := range hosts {
		names = append(names, h.Name)
		def := Record{A: []string{h.IP}}
		s := def
		if h.System != nil {
			s = *h.System
		}
		sys[h.Name] = s
		n := s
		if h.NSDI != nil {
			n = *h.NSDI
		}
		nsdi[h.Name] = n
		r := def
		if h.Ref != nil {
			r = *h.Ref
		}
		ref[h.Name] = r
	}
	// Interception probes answered by the simulated public resolvers.
	ref["whoami.cloudflare"] = Record{TXT: []string{"192.0.2.1"}}
	ref["id.server"] = Record{TXT: []string{"FRA"}}
	ref["o-o.myaddr.l.google.com"] = Record{TXT: []string{"192.0.2.1"}}

	if w.SysDNS, err = NewDNSServer(sys); err != nil {
		return nil, err
	}
	w.closers = append(w.closers, func() { _ = w.SysDNS.Close() })
	if w.NSDI, err = NewDNSServer(nsdi); err != nil {
		return nil, err
	}
	w.closers = append(w.closers, func() { _ = w.NSDI.Close() })
	if w.RefDNS, err = NewDNSServer(ref); err != nil {
		return nil, err
	}
	w.closers = append(w.closers, func() { _ = w.RefDNS.Close() })
	w.Dialer.Route(net.JoinHostPort(NSDIAddr, "53"), w.NSDI.Addr)
	// The simulated "public" resolvers answer with the reference data by default.
	w.Dialer.Route(net.JoinHostPort(PublicDNS1, "53"), w.RefDNS.Addr)
	w.Dialer.Route(net.JoinHostPort(PublicDNS8, "53"), w.RefDNS.Addr)

	origin, err := w.startOrigin(w.CA, names)
	if err != nil {
		return nil, err
	}
	w.Dialer.Route(net.JoinHostPort(DoHHost, "443"), origin)
	rogue, err := w.startOrigin(w.Rogue, names)
	if err != nil {
		return nil, err
	}
	plain, err := w.startPlain("")
	if err != nil {
		return nil, err
	}

	for _, h := range hosts {
		addr443 := net.JoinHostPort(h.IP, "443")
		addr80 := net.JoinHostPort(h.IP, "80")
		switch {
		case h.Block == "blackhole":
			w.Dialer.Blackhole(h.IP)
			continue
		case h.Block == "refuse" || h.Missing:
			w.Dialer.Refuse(h.IP)
			continue
		}
		up := origin
		if h.Rogue {
			up = rogue
		}
		rules := map[string]Action{}
		for k, v := range h.Rules {
			if k == "$self" {
				k = h.Name
			}
			rules[k] = v
		}
		mb, err := NewMiddlebox(up, h.TLS, rules)
		if err != nil {
			return nil, err
		}
		w.closers = append(w.closers, func() { _ = mb.Close() })
		w.Dialer.Route(addr443, mb.Addr())
		if h.HTTP80 != "" {
			bp, err := w.startPlain(h.HTTP80)
			if err != nil {
				return nil, err
			}
			w.Dialer.Route(addr80, bp)
		} else {
			w.Dialer.Route(addr80, plain)
		}
	}
	return w, nil
}

// Close stops every server.
func (w *World) Close() {
	for i := len(w.closers) - 1; i >= 0; i-- {
		w.closers[i]()
	}
}

func (w *World) startOrigin(ca *CA, names []string) (string, error) {
	cert, err := ca.Leaf(names...)
	if err != nil {
		return "", err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	mux := http.NewServeMux()
	mux.Handle("/dns-query", w.RefDNS.DoHHandler())
	mux.HandleFunc("/big", func(rw http.ResponseWriter, _ *http.Request) {
		body := strings.Repeat("prosvet testnet payload ", (256<<10)/24+1)[:256<<10]
		rw.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = rw.Write([]byte(body))
	})
	mux.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		body := "<!doctype html><title>" + r.Host + "</title><p>" + strings.Repeat("ok ", 1200) + "</p>"
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		rw.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = rw.Write([]byte(body))
	})
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	w.closers = append(w.closers, func() { _ = srv.Close() })
	return ln.Addr().String(), nil
}

func (w *World) startPlain(location string) (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if location != "" {
			http.Redirect(rw, r, location, http.StatusFound)
			return
		}
		_, _ = rw.Write([]byte("<html><body>plain ok</body></html>"))
	})}
	go func() { _ = srv.Serve(ln) }()
	w.closers = append(w.closers, func() { _ = srv.Close() })
	return ln.Addr().String(), nil
}

// Env returns a probe environment wired to this world.
func (w *World) Env(t probe.Timeouts) *probe.Env {
	env := probe.NewEnv("test")
	env.Dialer = w.Dialer
	env.Timeouts = t
	env.RootCAs = w.CA.Pool()
	env.UDPAddrMap = w.Dialer.UDPRoutes()
	sysAddr := w.SysDNS.Addr
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", sysAddr)
	}}
	env.LookupHost = func(ctx context.Context, host string) ([]string, error) {
		addrs, err := r.LookupHost(ctx, host)
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			return nil, err
		}
		return addrs, err
	}
	env.IsBogon = func(ip string) bool {
		if strings.HasPrefix(ip, "198.51.100.") || strings.HasPrefix(ip, "203.0.113.") {
			return false // simulated public addresses
		}
		return fingerprint.IsBogon(ip)
	}
	return env
}

// FastTimeouts keeps tests quick.
func FastTimeouts() probe.Timeouts {
	return probe.Timeouts{
		DNS:       time.Second,
		Connect:   700 * time.Millisecond,
		Handshake: 900 * time.Millisecond,
		FirstByte: time.Second,
		Stall:     500 * time.Millisecond,
		QUIC:      700 * time.Millisecond,
	}
}

// DNSConfig returns resolver definitions pointing into the world.
func DNSConfig() *catalog.DNSConfig {
	return &catalog.DNSConfig{
		Version: 1, Kind: "resolvers", ID: "dns", Default: true,
		Title: catalog.Text{"en": "DNS"},
		Resolvers: []catalog.Resolver{
			{ID: "system", Type: "system", Name: catalog.Text{"en": "System"}},
			{ID: "nsdi", Name: catalog.Text{"en": "NSDI"}, Role: "official_reference", UDP: []string{NSDIAddr}},
			{ID: "reference", Name: catalog.Text{"en": "Reference DoH"}, DoH: "https://" + DoHHost + "/dns-query"},
		},
		ReferenceDoH: []string{"reference"},
		ProbeDomains: []catalog.ProbeDomain{},
	}
}
