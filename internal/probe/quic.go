package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/ordinarysim/prosvet/internal/errclass"
	"github.com/ordinarysim/prosvet/internal/model"
)

func init() {
	// quic-go splits and reorders the ClientHello by default to defeat naive
	// SNI filters. Prosvet measures what an ordinary client experiences, so the
	// scrambling is disabled. The receive-buffer warning is noise for short probes.
	_ = os.Setenv("QUIC_GO_DISABLE_CLIENTHELLO_SCRAMBLING", "true")
	_ = os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
}

// QUIC attempts a QUIC handshake (ALPN h3) to ip:port with the given SNI.
// Each call uses a fresh UDP socket, so a blackholed flow does not affect the
// next attempt.
func (e *Env) QUIC(ctx context.Context, ip string, port int, sni, variant string, version int) *model.QUICResult {
	res := &model.QUICResult{Version: version, Variant: variant}
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		res.Outcome = model.Error
		res.Error = errclass.Short(err)
		return res
	}
	defer udp.Close()

	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	if m, ok := e.UDPAddrMap[addr]; ok {
		addr = m
	}
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		res.Outcome = model.Error
		res.Error = errclass.Short(err)
		return res
	}
	v := quic.Version1
	if version == 2 {
		v = quic.Version2
	}
	tlsConf := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, //nolint:gosec // only reachability is measured
		NextProtos:         []string{"h3"},
		MinVersion:         tls.VersionTLS13,
	}
	conf := &quic.Config{
		Versions:             []quic.Version{v},
		HandshakeIdleTimeout: e.Timeouts.QUIC,
		MaxIdleTimeout:       e.Timeouts.QUIC,
	}
	ctx, cancel := context.WithTimeout(ctx, e.Timeouts.QUIC+time.Second)
	defer cancel()
	start := time.Now()
	conn, err := quic.Dial(ctx, udp, raddr, tlsConf, conf)
	res.RTTMs = ms(time.Since(start))
	if err == nil {
		res.Outcome = model.OK
		_ = conn.CloseWithError(0, "")
		return res
	}
	res.Outcome = classifyQUIC(err)
	res.Error = errclass.Short(err)
	return res
}

func classifyQUIC(err error) model.Outcome {
	var (
		hto *quic.HandshakeTimeoutError
		ito *quic.IdleTimeoutError
		vne *quic.VersionNegotiationError
		te  *quic.TransportError
		ae  *quic.ApplicationError
		sr  *quic.StatelessResetError
	)
	switch {
	case errors.As(err, &hto), errors.As(err, &ito), errors.Is(err, context.DeadlineExceeded):
		return model.Timeout
	case errors.As(err, &vne):
		return model.Unsupported
	case errors.As(err, &te), errors.As(err, &ae), errors.As(err, &sr):
		return model.Responded
	}
	return errclass.Classify(err)
}
