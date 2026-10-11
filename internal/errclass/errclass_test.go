package errclass

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Derposd/prosvet/internal/model"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want model.Outcome
	}{
		{"nil", nil, model.OK},
		{"deadline", context.DeadlineExceeded, model.Timeout},
		{"eof", io.EOF, model.EOF},
		{"wrapped eof", fmt.Errorf("read: %w", io.ErrUnexpectedEOF), model.EOF},
		{"nxdomain", &net.DNSError{IsNotFound: true}, model.NXDomain},
		{"dns timeout", &net.DNSError{IsTimeout: true}, model.Timeout},
		{"dns other", &net.DNSError{Err: "server misbehaving"}, model.ServFail},
		{"tls alert", tls.AlertError(40), model.TLSAlert},
		{"reset msg", errors.New("read tcp: connection reset by peer"), model.Reset},
		{"reset msg win", errors.New("wsarecv: An existing connection was forcibly closed by the remote host."), model.Reset},
		{"refused msg", errors.New("connectex: No connection could be made because the target machine actively refused it."), model.Refused},
		{"unknown", errors.New("weird"), model.Error},
	}
	for _, c := range cases {
		if got := Classify(c.err); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

func TestClassifyRealSockets(t *testing.T) {
	// Refused: a port that was just closed.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	_, err = net.DialTimeout("tcp", addr, time.Second)
	if got := Classify(err); got != model.Refused {
		t.Errorf("closed port: got %s (%v)", got, err)
	}

	// Reset: server closes with SO_LINGER=0.
	l, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 16)
		_, _ = c.Read(buf)
		_ = c.(*net.TCPConn).SetLinger(0)
		_ = c.Close()
	}()
	c, err := net.DialTimeout("tcp", l.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("hello"))
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = c.Read(make([]byte, 16))
	if got := Classify(err); got != model.Reset && got != model.EOF {
		t.Errorf("linger 0: got %s (%v)", got, err)
	}
}

func TestShortScrubsAddresses(t *testing.T) {
	err := &net.OpError{Op: "dial", Net: "tcp", Source: &net.TCPAddr{IP: net.IPv4(10, 1, 2, 3), Port: 5555},
		Err: errors.New("connect 10.1.2.3:5555 -> 203.0.113.1:443 refused")}
	s := Short(err)
	if strings.Contains(s, "10.1.2.3") || strings.Contains(s, "203.0.113.1") {
		t.Fatalf("address leaked: %q", s)
	}
}
