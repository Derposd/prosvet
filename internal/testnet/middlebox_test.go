package testnet

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
)

func captureHello(t *testing.T, sni string) []byte {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	go func() {
		c := tls.Client(b, &tls.Config{ServerName: sni, InsecureSkipVerify: true}) //nolint:gosec // test
		_ = c.Handshake()
		_ = b.Close()
	}()
	rec, err := readRecord(a)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestParseSNI(t *testing.T) {
	for _, sni := range []string{"example.com", "a-very-long-subdomain.with.many.labels.example.org"} {
		got, err := ParseSNI(captureHello(t, sni))
		if err != nil || got != sni {
			t.Fatalf("got %q, %v; want %q", got, err, sni)
		}
	}
	got, err := ParseSNI(captureHello(t, ""))
	if err != nil || got != "" {
		t.Fatalf("no-SNI hello: got %q, %v", got, err)
	}
	if _, err := ParseSNI([]byte{0x17, 3, 3, 0, 1, 0}); err == nil {
		t.Fatal("non-handshake record must fail")
	}
}

func TestRateCopy(t *testing.T) {
	src := io.LimitReader(zeroReader{}, 1000)
	var dst countWriter
	copyRate(&dst, src, 100000)
	if dst.n != 1000 {
		t.Fatalf("copied %d", dst.n)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { return len(p), nil }

type countWriter struct{ n int }

func (c *countWriter) Write(p []byte) (int, error) { c.n += len(p); return len(p), nil }
