// Package probe implements the individual network measurements: DNS lookups
// over several transports, TCP connect, TLS handshakes with SNI variants,
// HTTP fetches with stall detection, QUIC and ECH handshakes.
//
// Probes never use proxies from the environment: the goal is to measure the
// user's own network path.
package probe

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"net/http"
	"time"

	"github.com/ordinarysim/prosvet/internal/brand"
	"github.com/ordinarysim/prosvet/internal/fingerprint"
)

// Dialer opens network connections. It is an interface so tests can simulate
// blackholed or redirected addresses.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Timeouts for individual probe steps.
type Timeouts struct {
	DNS       time.Duration
	Connect   time.Duration
	Handshake time.Duration
	FirstByte time.Duration
	Stall     time.Duration
	QUIC      time.Duration
}

// DefaultTimeouts are tuned for slow mobile networks.
func DefaultTimeouts() Timeouts {
	return Timeouts{
		DNS:       3 * time.Second,
		Connect:   5 * time.Second,
		Handshake: 6 * time.Second,
		FirstByte: 8 * time.Second,
		Stall:     6 * time.Second,
		QUIC:      5 * time.Second,
	}
}

// Scale multiplies every timeout by f.
func (t Timeouts) Scale(f float64) Timeouts {
	if f <= 0 || f == 1 {
		return t
	}
	m := func(d time.Duration) time.Duration { return time.Duration(float64(d) * f) }
	return Timeouts{m(t.DNS), m(t.Connect), m(t.Handshake), m(t.FirstByte), m(t.Stall), m(t.QUIC)}
}

// SystemLookup resolves a host with the operating system resolver.
type SystemLookup func(ctx context.Context, host string) ([]string, error)

// Env carries everything probes need. The zero value is not usable; call NewEnv.
type Env struct {
	Dialer    Dialer
	Timeouts  Timeouts
	UserAgent string

	// LookupHost resolves with the system resolver (replaceable in tests).
	LookupHost SystemLookup
	// RootCAs is used to judge certificate trust; nil means the system pool.
	RootCAs *x509.CertPool
	// IsBogon decides whether a DNS answer is a non-public address.
	IsBogon func(string) bool
	// Fingerprints for stub/block page detection.
	Fingerprints *fingerprint.DB
	// UDPAddrMap rewrites UDP destinations (tests only): "ip:port" -> "ip:port".
	UDPAddrMap map[string]string
}

// NewEnv returns an Env with real network access and default settings.
func NewEnv(version string) *Env {
	d := &net.Dialer{KeepAlive: -1}
	r := &net.Resolver{}
	return &Env{
		Dialer:    d,
		Timeouts:  DefaultTimeouts(),
		UserAgent: "prosvet/" + version + " (+" + brand.RepoURL + ")",
		LookupHost: func(ctx context.Context, host string) ([]string, error) {
			return r.LookupHost(ctx, host)
		},
		IsBogon:      fingerprint.IsBogon,
		Fingerprints: fingerprint.Default(),
	}
}

// HTTPClient returns an HTTP client that ignores proxy settings and dials through Env.Dialer.
func (e *Env) HTTPClient(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		Proxy:               nil,
		DialContext:         e.Dialer.DialContext,
		TLSHandshakeTimeout: e.Timeouts.Handshake,
		TLSClientConfig:     &tls.Config{RootCAs: e.RootCAs, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        4,
		IdleConnTimeout:     10 * time.Second,
		DisableCompression:  true,
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

// RandomSNI returns a syntactically valid server name that no real service uses.
func RandomSNI() string {
	var b [5]byte
	_, _ = rand.Read(b[:])
	return "prosvet-" + hex.EncodeToString(b[:]) + ".example.com"
}

func ms(d time.Duration) int64 { return d.Milliseconds() }
