package testnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
)

// Dialer routes connections inside the simulated network. Every address must
// be mapped explicitly, so tests never touch the real network.
type Dialer struct {
	mu        sync.RWMutex
	routes    map[string]string // "host:port" -> "127.0.0.1:port" (tcp and udp)
	blackhole map[string]bool   // ip -> silently dropped
	refuse    map[string]bool   // ip -> connection refused
	inner     net.Dialer
}

// NewDialer returns an empty dialer.
func NewDialer() *Dialer {
	return &Dialer{routes: map[string]string{}, blackhole: map[string]bool{}, refuse: map[string]bool{}}
}

// Route maps addr (host:port) to a local listener address.
func (d *Dialer) Route(addr, to string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.routes[addr] = to
}

// Blackhole makes connections to ip hang until the context expires.
func (d *Dialer) Blackhole(ip string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.blackhole[ip] = true
}

// Refuse makes connections to ip fail with "connection refused".
func (d *Dialer) Refuse(ip string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.refuse[ip] = true
}

// UDPRoutes returns the UDP routes for QUIC (probe.Env.UDPAddrMap).
func (d *Dialer) UDPRoutes() map[string]string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make(map[string]string, len(d.routes))
	for k, v := range d.routes {
		out[k] = v
	}
	return out
}

// DialContext implements probe.Dialer.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	d.mu.RLock()
	to, routed := d.routes[address]
	bh := d.blackhole[host]
	rf := d.refuse[host]
	d.mu.RUnlock()
	switch {
	case bh:
		<-ctx.Done()
		return nil, &net.OpError{Op: "dial", Net: network, Err: timeoutErr{}}
	case rf:
		return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
	case !routed:
		return nil, fmt.Errorf("testnet: no route to %s", address)
	}
	return d.inner.DialContext(ctx, network, to)
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout (testnet blackhole)" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

var _ net.Error = timeoutErr{}

// ErrNoRoute is returned for unmapped addresses.
var ErrNoRoute = errors.New("testnet: no route")
