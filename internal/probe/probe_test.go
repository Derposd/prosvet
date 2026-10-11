package probe_test

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/Derposd/prosvet/internal/catalog"
	"github.com/Derposd/prosvet/internal/model"
	"github.com/Derposd/prosvet/internal/probe"
	"github.com/Derposd/prosvet/internal/testnet"
)

func newWorld(t *testing.T) (*testnet.World, *probe.Env) {
	t.Helper()
	w, err := testnet.NewWorld([]testnet.Host{
		{Name: "ok.test", IP: "198.51.100.10"},
		{Name: "gone.test", IP: "198.51.100.11", System: &testnet.Record{NX: true}},
		{Name: "sni.test", IP: "198.51.100.15", Rules: map[string]testnet.Action{"$self": {Kind: testnet.Reset}}},
		{Name: "freeze.test", IP: "198.51.100.18", Rules: map[string]testnet.Action{"$self": {Kind: testnet.Freeze, FreezeAfter: 16 << 10}}},
		{Name: "mitm.test", IP: "198.51.100.20", Rogue: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	return w, w.Env(testnet.FastTimeouts())
}

func TestTLSVariants(t *testing.T) {
	_, env := newWorld(t)
	ctx := context.Background()

	r, _ := env.TLS(ctx, "198.51.100.10", 443, probe.TLSOptions{Variant: model.VariantReal, Host: "ok.test"})
	if !r.Succeeded() || r.Cert == nil || !r.Cert.ValidForHost || !r.Cert.TrustedSystem {
		t.Fatalf("ok.test real: %+v %+v", r, r.Cert)
	}
	r, _ = env.TLS(ctx, "198.51.100.15", 443, probe.TLSOptions{Variant: model.VariantReal, Host: "sni.test"})
	if r.Stage != "handshake" || (r.Outcome != model.Reset && r.Outcome != model.EOF) {
		t.Fatalf("sni.test real should be reset at handshake: %+v", r)
	}
	for _, v := range []string{model.VariantNone, model.VariantRandom} {
		r, _ = env.TLS(ctx, "198.51.100.15", 443, probe.TLSOptions{Variant: v, Host: "sni.test"})
		if !r.Outcome.ServerAnswered() {
			t.Fatalf("sni.test %s should pass the middlebox: %+v", v, r)
		}
	}
	r, _ = env.TLS(ctx, "198.51.100.20", 443, probe.TLSOptions{Variant: model.VariantReal, Host: "mitm.test"})
	if !r.Succeeded() || r.Cert.TrustedSystem || !r.Cert.RussianTrustedCA {
		t.Fatalf("mitm.test cert should be untrusted and flagged: %+v", r.Cert)
	}
}

func TestHTTPFreezeCountsWireBytes(t *testing.T) {
	_, env := newWorld(t)
	ctx := context.Background()
	r, conn := env.TLS(ctx, "198.51.100.18", 443, probe.TLSOptions{Variant: model.VariantReal, Host: "freeze.test", ALPN: []string{"http/1.1"}, Keep: true})
	if conn == nil {
		t.Fatalf("handshake failed: %+v", r)
	}
	defer conn.Close()
	h, _ := env.HTTPGet(ctx, conn, probe.HTTPOptions{Host: "freeze.test", Path: "/big", Limit: 128 << 10})
	if !h.Stalled || h.Outcome != model.Stall {
		t.Fatalf("expected stall: %+v", h)
	}
	if h.BytesBeforeStall < 15<<10 || h.BytesBeforeStall > 17<<10 {
		t.Fatalf("wire bytes before stall = %d, want ~16 KiB", h.BytesBeforeStall)
	}
	if h.RawBytes >= h.WireBytes {
		t.Fatalf("application bytes (%d) must be below wire bytes (%d)", h.RawBytes, h.WireBytes)
	}
}

func TestHTTPComplete(t *testing.T) {
	_, env := newWorld(t)
	ctx := context.Background()
	_, conn := env.TLS(ctx, "198.51.100.10", 443, probe.TLSOptions{Variant: model.VariantReal, Host: "ok.test", ALPN: []string{"http/1.1"}, Keep: true})
	if conn == nil {
		t.Fatal("handshake failed")
	}
	defer conn.Close()
	h, body := env.HTTPGet(ctx, conn, probe.HTTPOptions{Host: "ok.test", Path: "/big", Limit: 64 << 10, Keep: 128})
	if h.Outcome != model.OK || h.Status != 200 || !h.Truncated || h.Bytes != 64<<10 || len(body) != 128 {
		t.Fatalf("unexpected: %+v (body %d)", h, len(body))
	}
	if h.ThroughputKbps <= 0 {
		t.Fatal("throughput not computed")
	}
}

func TestDNSTransports(t *testing.T) {
	_, env := newWorld(t)
	ctx := context.Background()
	sys := env.Resolve(ctx, probe.ResolverSpec{Transport: probe.TransportSystem}, "gone.test")
	if sys.Outcome != model.NXDomain {
		t.Fatalf("system: %+v", sys)
	}
	doh := env.Resolve(ctx, probe.ResolverSpec{ID: "ref", Transport: probe.TransportDoH, URL: "https://" + testnet.DoHHost + "/dns-query"}, "gone.test")
	if doh.Outcome != model.OK || len(doh.Addrs) != 1 || doh.Addrs[0] != "198.51.100.11" || doh.Resolver != "doh:ref" {
		t.Fatalf("doh: %+v", doh)
	}
	udp := env.Resolve(ctx, probe.ResolverSpec{ID: "nsdi", Transport: probe.TransportUDP, Addr: testnet.NSDIAddr + ":53"}, "gone.test")
	if udp.Outcome != model.NXDomain {
		t.Fatalf("udp: %+v", udp)
	}
	stub := env.Resolve(ctx, probe.ResolverSpec{ID: "x", Transport: probe.TransportUDP, Addr: "192.0.2.99:53"}, "ok.test")
	if stub.Outcome == model.OK {
		t.Fatal("unrouted resolver must fail")
	}
}

func TestIntercept(t *testing.T) {
	w, env := newWorld(t)
	ctx := context.Background()
	ok := env.Intercept(ctx, catalog.Interception{ID: "a", Resolver: testnet.PublicDNS1, QName: "id.server", QClass: "CH", QType: "TXT", Expect: "colo_code"})
	if !ok.Passed || ok.Detail != "colo=FRA" {
		t.Fatalf("clean: %+v", ok)
	}
	w.Dialer.Route(testnet.PublicDNS1+":53", w.NSDI.Addr)
	bad := env.Intercept(ctx, catalog.Interception{ID: "b", Resolver: testnet.PublicDNS1, QName: "whoami.cloudflare", QClass: "CH", QType: "TXT", Expect: "nonempty"})
	if bad.Passed || bad.Outcome != model.NXDomain {
		t.Fatalf("intercepted: %+v", bad)
	}
}

func startQUIC(t *testing.T, w *testnet.World, versions ...quic.Version) string {
	t.Helper()
	cert, err := w.CA.Leaf("quic.test")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13},
		&quic.Config{Versions: versions})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				time.Sleep(100 * time.Millisecond)
				_ = c.CloseWithError(0, "")
			}()
		}
	}()
	return ln.Addr().String()
}

func TestQUIC(t *testing.T) {
	w, env := newWorld(t)
	ctx := context.Background()
	addr := startQUIC(t, w, quic.Version1)
	sink, err := net.ListenPacket("udp", "127.0.0.1:0") // swallows every datagram
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	env.UDPAddrMap = map[string]string{
		"198.51.100.70:443": addr,
		"198.51.100.71:443": sink.LocalAddr().String(),
	}
	if r := env.QUIC(ctx, "198.51.100.70", 443, "quic.test", model.VariantReal, 1); r.Outcome != model.OK {
		t.Fatalf("v1 handshake: %+v", r)
	}
	if r := env.QUIC(ctx, "198.51.100.70", 443, "quic.test", model.VariantReal, 2); r.Outcome != model.Unsupported && r.Outcome != model.Responded {
		t.Fatalf("v2 against v1-only server: %+v", r)
	}
	start := time.Now()
	r := env.QUIC(ctx, "198.51.100.71", 443, "quic.test", model.VariantReal, 1)
	if r.Outcome != model.Timeout {
		t.Fatalf("blackholed QUIC should time out: %+v", r)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("QUIC timeout not respected")
	}
}

func TestConnect(t *testing.T) {
	_, env := newWorld(t)
	if r := env.Connect(context.Background(), "198.51.100.10", 443); r.Outcome != model.OK {
		t.Fatalf("%+v", r)
	}
	if r := env.Connect(context.Background(), "198.51.100.250", 443); r.Outcome == model.OK {
		t.Fatal("unrouted address must fail")
	}
}

func TestPlainHTTP(t *testing.T) {
	_, env := newWorld(t)
	h := env.PlainHTTP(context.Background(), "198.51.100.10", 80, "ok.test", "/")
	if h.Outcome != model.OK || h.Status != 200 || h.Blockpage != "" {
		t.Fatalf("%+v", h)
	}
}

func TestSpecsFor(t *testing.T) {
	r := catalog.Resolver{ID: "cf", UDP: []string{"1.1.1.1"}, DoH: "https://cloudflare-dns.com/dns-query"}
	r.DoT = &struct {
		Host string `yaml:"host"`
		Addr string `yaml:"addr"`
	}{Host: "one.one.one.one", Addr: "1.1.1.1:853"}
	specs := probe.SpecsFor(r)
	if len(specs) != 3 || specs[0].Addr != net.JoinHostPort("1.1.1.1", strconv.Itoa(53)) || specs[1].Host != "one.one.one.one" || specs[2].Label() != "doh:cf" {
		t.Fatalf("%+v", specs)
	}
}
