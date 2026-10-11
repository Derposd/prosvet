package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Derposd/prosvet/internal/errclass"
	"github.com/Derposd/prosvet/internal/model"
)

// TLSOptions configures a TLS probe.
type TLSOptions struct {
	Variant string // model.VariantReal | VariantNone | VariantRandom | VariantECH
	Host    string // real host name (used for SNI in the real/ech variants and for cert validation)
	ALPN    []string
	ECH     []byte // ECHConfigList for the ech variant
	Keep    bool   // return the connection on success
}

// countingConn counts bytes received on the wire (TCP payload, including the
// TLS handshake). Censors count these bytes too, e.g. for the 16–20 KB freeze.
type countingConn struct {
	net.Conn
	in atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.in.Add(int64(n))
	return n, err
}

// TLSConn is an established TLS connection that knows how many bytes arrived on the wire.
type TLSConn struct {
	*tls.Conn
	wire *countingConn
}

// WireIn returns the number of TCP payload bytes received so far.
func (c *TLSConn) WireIn() int64 { return c.wire.in.Load() }

// Connect performs only the TCP connect step.
func (e *Env) Connect(ctx context.Context, ip string, port int) *model.TLSResult {
	res := &model.TLSResult{Variant: "tcp", Stage: "connect"}
	conn, d, err := e.dial(ctx, ip, port)
	res.ConnectMs = ms(d)
	res.Outcome = errclass.Classify(err)
	if err != nil {
		res.Error = errclass.Short(err)
		return res
	}
	_ = conn.Close()
	return res
}

func (e *Env) dial(ctx context.Context, ip string, port int) (net.Conn, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, e.Timeouts.Connect)
	defer cancel()
	start := time.Now()
	conn, err := e.Dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	return conn, time.Since(start), err
}

// TLS connects to ip:port and performs a TLS handshake. Certificate errors do
// not fail the handshake; they are recorded in the result instead.
func (e *Env) TLS(ctx context.Context, ip string, port int, opt TLSOptions) (*model.TLSResult, *TLSConn) {
	res := &model.TLSResult{Variant: opt.Variant, Stage: "connect"}
	raw, d, err := e.dial(ctx, ip, port)
	res.ConnectMs = ms(d)
	if err != nil {
		res.Outcome = errclass.Classify(err)
		res.Error = errclass.Short(err)
		return res, nil
	}
	res.Stage = "handshake"

	cfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // verification is done manually and recorded, never enforced
		MinVersion:         tls.VersionTLS12,
		NextProtos:         opt.ALPN,
	}
	switch opt.Variant {
	case model.VariantReal:
		cfg.ServerName = opt.Host
	case model.VariantRandom:
		cfg.ServerName = RandomSNI()
	case model.VariantECH:
		cfg.ServerName = opt.Host
		cfg.MinVersion = tls.VersionTLS13
		cfg.EncryptedClientHelloConfigList = opt.ECH
	case model.VariantNone:
		// empty ServerName: no SNI extension is sent
	}

	hctx, cancel := context.WithTimeout(ctx, e.Timeouts.Handshake)
	defer cancel()
	if dl, ok := hctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	cc := &countingConn{Conn: raw}
	tc := tls.Client(cc, cfg)
	start := time.Now()
	err = tc.HandshakeContext(hctx)
	res.HandshakeMs = ms(time.Since(start))
	if err != nil {
		var rej *tls.ECHRejectionError
		if errors.As(err, &rej) {
			res.Outcome = model.Responded
		} else {
			res.Outcome = errclass.Classify(err)
		}
		res.Error = errclass.Short(err)
		_ = raw.Close()
		return res, nil
	}
	_ = raw.SetDeadline(time.Time{})
	st := tc.ConnectionState()
	res.Outcome = model.OK
	res.Version = tls.VersionName(st.Version)
	res.ECHAccepted = st.ECHAccepted
	if len(st.PeerCertificates) > 0 {
		res.Cert = e.analyzeCert(st.PeerCertificates, opt.Host)
	}
	if opt.Keep {
		return res, &TLSConn{Conn: tc, wire: cc}
	}
	_ = tc.Close()
	return res, nil
}

// analyzeCert checks the presented chain against the system (or configured) roots.
func (e *Env) analyzeCert(chain []*x509.Certificate, host string) *model.CertInfo {
	leaf := chain[0]
	info := &model.CertInfo{
		Subject:  certName(leaf),
		Issuer:   issuerName(leaf),
		NotAfter: leaf.NotAfter,
	}
	if host != "" {
		info.ValidForHost = leaf.VerifyHostname(host) == nil
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	opts := x509.VerifyOptions{DNSName: host, Intermediates: inter, Roots: e.RootCAs}
	if _, err := leaf.Verify(opts); err == nil {
		info.TrustedSystem = true
	}
	for _, c := range chain {
		if IsRussianTrustedCA(c) {
			info.RussianTrustedCA = true
		}
	}
	return info
}

// IsRussianTrustedCA reports whether cert belongs to, or was issued by, the
// Russian state CA ("Russian Trusted Root CA" / "Russian Trusted Sub CA").
func IsRussianTrustedCA(c *x509.Certificate) bool {
	for _, n := range []string{c.Issuer.CommonName, c.Subject.CommonName} {
		if strings.Contains(strings.ToLower(n), "russian trusted") {
			return true
		}
	}
	for _, o := range append(append([]string{}, c.Issuer.Organization...), c.Subject.Organization...) {
		lo := strings.ToLower(o)
		if strings.Contains(lo, "ministry of digital development") || strings.Contains(lo, "минцифры") {
			return true
		}
	}
	return false
}

func certName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	if len(c.DNSNames) > 0 {
		return c.DNSNames[0]
	}
	return ""
}

func issuerName(c *x509.Certificate) string {
	parts := []string{}
	if c.Issuer.CommonName != "" {
		parts = append(parts, c.Issuer.CommonName)
	}
	if len(c.Issuer.Organization) > 0 {
		parts = append(parts, c.Issuer.Organization[0])
	}
	return strings.Join(parts, ", ")
}
