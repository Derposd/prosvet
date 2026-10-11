package testnet

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// ActionKind is what a middlebox does with a matching flow.
type ActionKind int

// Middlebox actions.
const (
	Pass   ActionKind = iota // forward unchanged
	Reset                    // send a TCP RST after the ClientHello
	Drop                     // swallow everything, never answer
	Freeze                   // forward, but stop delivering server data after N bytes
	Rate                     // forward server data at a limited rate
)

// Action is a middlebox decision.
type Action struct {
	Kind        ActionKind
	FreezeAfter int // bytes, for Freeze
	RateBps     int // bytes per second, for Rate
}

// Middlebox is an in-path TLS-aware censor in front of an upstream server.
// Rules are keyed by SNI ("" means "no SNI"); Default applies otherwise.
type Middlebox struct {
	ln       net.Listener
	upstream string
	Rules    map[string]Action
	Default  Action
	wg       sync.WaitGroup
	done     chan struct{}
}

// NewMiddlebox listens on 127.0.0.1 and forwards to upstream.
func NewMiddlebox(upstream string, def Action, rules map[string]Action) (*Middlebox, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	m := &Middlebox{ln: ln, upstream: upstream, Rules: rules, Default: def, done: make(chan struct{})}
	if m.Rules == nil {
		m.Rules = map[string]Action{}
	}
	m.wg.Add(1)
	go m.loop()
	return m, nil
}

// Addr is the listening address.
func (m *Middlebox) Addr() string { return m.ln.Addr().String() }

// Close stops the middlebox.
func (m *Middlebox) Close() error {
	close(m.done)
	err := m.ln.Close()
	m.wg.Wait()
	return err
}

func (m *Middlebox) loop() {
	defer m.wg.Done()
	for {
		c, err := m.ln.Accept()
		if err != nil {
			return
		}
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.handle(c)
		}()
	}
}

func (m *Middlebox) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	hello, err := readRecord(c)
	if err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	sni, _ := ParseSNI(hello)
	act, ok := m.Rules[sni]
	if !ok {
		act = m.Default
	}
	switch act.Kind {
	case Reset:
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		return
	case Drop:
		m.hold(c)
		return
	}
	up, err := net.DialTimeout("tcp", m.upstream, 2*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	if _, err := up.Write(hello); err != nil {
		return
	}
	go func() {
		_, _ = io.Copy(up, c)
		_ = up.Close()
	}()
	switch act.Kind {
	case Freeze:
		_, _ = io.CopyN(c, up, int64(act.FreezeAfter))
		m.hold(c) // keep the connection open but deliver nothing more
	case Rate:
		copyRate(c, up, act.RateBps)
	default:
		_, _ = io.Copy(c, up)
	}
}

// hold keeps a connection open, discarding input, until the peer gives up.
func (m *Middlebox) hold(c net.Conn) {
	go func() {
		<-m.done
		_ = c.Close()
	}()
	_, _ = io.Copy(io.Discard, c)
}

func copyRate(dst io.Writer, src io.Reader, bps int) {
	if bps <= 0 {
		_, _ = io.Copy(dst, src)
		return
	}
	chunk := max(bps/20, 256)
	buf := make([]byte, chunk)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for range tick.C {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// readRecord reads one complete TLS record.
func readRecord(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != 0x16 {
		return nil, errors.New("not a TLS handshake record")
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

// ParseSNI extracts the server name from a TLS record containing a ClientHello.
// It returns "" (and no error) when the ClientHello has no SNI extension.
func ParseSNI(rec []byte) (string, error) {
	errShort := errors.New("short ClientHello")
	if len(rec) < 5+4 || rec[0] != 0x16 || rec[5] != 0x01 {
		return "", errors.New("not a ClientHello")
	}
	p := rec[5+4:] // skip record header and handshake header
	if len(p) < 2+32+1 {
		return "", errShort
	}
	p = p[2+32:] // version + random
	sid := int(p[0])
	if len(p) < 1+sid+2 {
		return "", errShort
	}
	p = p[1+sid:]
	cs := int(binary.BigEndian.Uint16(p))
	if len(p) < 2+cs+1 {
		return "", errShort
	}
	p = p[2+cs:]
	comp := int(p[0])
	if len(p) < 1+comp+2 {
		return "", errShort
	}
	p = p[1+comp:]
	extLen := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if len(p) < extLen {
		return "", errShort
	}
	p = p[:extLen]
	for len(p) >= 4 {
		typ := binary.BigEndian.Uint16(p)
		l := int(binary.BigEndian.Uint16(p[2:]))
		if len(p) < 4+l {
			return "", errShort
		}
		data := p[4 : 4+l]
		p = p[4+l:]
		if typ != 0 { // server_name
			continue
		}
		if len(data) < 2+1+2 {
			return "", errShort
		}
		data = data[2:]
		if data[0] != 0 {
			continue
		}
		nl := int(binary.BigEndian.Uint16(data[1:]))
		if len(data) < 3+nl {
			return "", errShort
		}
		return string(data[3 : 3+nl]), nil
	}
	return "", nil
}
