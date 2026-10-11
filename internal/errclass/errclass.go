// Package errclass maps network errors to probe outcomes in a portable way.
//
// The same failure looks different on every OS (ECONNRESET vs WSAECONNRESET,
// "connection reset by peer" vs "forcibly closed by the remote host"), so the
// classification relies on errno values first and on messages only as a fallback.
package errclass

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/Derposd/prosvet/internal/model"
)

// Classify returns the outcome for err (model.OK for nil).
func Classify(err error) model.Outcome {
	if err == nil {
		return model.OK
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return model.Timeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return model.Timeout
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsNotFound:
			return model.NXDomain
		case dnsErr.IsTimeout:
			return model.Timeout
		default:
			return model.ServFail
		}
	}
	var alert tls.AlertError
	if errors.As(err, &alert) {
		return model.TLSAlert
	}
	var recErr tls.RecordHeaderError
	if errors.As(err, &recErr) {
		return model.Error
	}
	if o, ok := classifyErrno(err); ok {
		return o
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return model.EOF
	}
	return classifyMessage(err.Error())
}

func classifyErrno(err error) (model.Outcome, bool) {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return "", false
	}
	switch {
	case isReset(errno):
		return model.Reset, true
	case isRefused(errno):
		return model.Refused, true
	case isTimeout(errno):
		return model.Timeout, true
	case isUnreachable(errno):
		return model.Unreachable, true
	}
	return "", false
}

func classifyMessage(msg string) model.Outcome {
	m := strings.ToLower(msg)
	switch {
	case strings.Contains(m, "reset by peer"), strings.Contains(m, "forcibly closed"),
		strings.Contains(m, "connection reset"), strings.Contains(m, "connection was aborted"):
		return model.Reset
	case strings.Contains(m, "connection refused"), strings.Contains(m, "actively refused"):
		return model.Refused
	case strings.Contains(m, "timeout"), strings.Contains(m, "timed out"), strings.Contains(m, "i/o timeout"):
		return model.Timeout
	case strings.Contains(m, "no route to host"), strings.Contains(m, "network is unreachable"),
		strings.Contains(m, "unreachable"):
		return model.Unreachable
	case strings.Contains(m, "eof"):
		return model.EOF
	case strings.Contains(m, "remote error: tls"):
		return model.TLSAlert
	}
	return model.Error
}

// Short returns a compact, privacy-safe description of err for reports.
// Local addresses (which may contain the user's IP) are removed.
func Short(err error) string {
	if err == nil {
		return ""
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		err = op.Err
	}
	s := err.Error()
	if len(s) > 160 {
		s = s[:160]
	}
	return scrubLocal(s)
}

// scrubLocal removes "local ip:port" fragments that some errors contain.
func scrubLocal(s string) string {
	fields := strings.Fields(s)
	out := fields[:0]
	for _, f := range fields {
		if host, _, err := net.SplitHostPort(strings.Trim(f, ":,")); err == nil && net.ParseIP(host) != nil {
			out = append(out, "<addr>")
			continue
		}
		if net.ParseIP(strings.Trim(f, ":,")) != nil {
			out = append(out, "<addr>")
			continue
		}
		out = append(out, f)
	}
	return strings.Join(out, " ")
}
