package probe

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/ordinarysim/prosvet/internal/errclass"
	"github.com/ordinarysim/prosvet/internal/model"
)

// HTTPOptions configures an HTTP fetch over an existing connection.
type HTTPOptions struct {
	Host  string
	Path  string
	Limit int64 // maximum body bytes to read
	Keep  int   // body bytes kept for fingerprinting
}

// DefaultBodyLimit bounds every download (the 16–20 KB freeze window is far below it).
const DefaultBodyLimit = 256 << 10

// stallReader extends the read deadline after every successful read and
// records when the first byte arrived.
type stallReader struct {
	conn      net.Conn
	firstByte time.Duration
	stall     time.Duration
	start     time.Time
	first     time.Time
	n         int64
	wire      func() int64 // wire-level byte counter, if available
}

// wireBytes returns bytes received on the wire, falling back to application bytes.
func (r *stallReader) wireBytes() int64 {
	if r.wire != nil {
		return r.wire()
	}
	return r.n
}

func (r *stallReader) Read(p []byte) (int, error) {
	if r.n == 0 {
		_ = r.conn.SetReadDeadline(r.start.Add(r.firstByte))
	} else {
		_ = r.conn.SetReadDeadline(time.Now().Add(r.stall))
	}
	n, err := r.conn.Read(p)
	if n > 0 {
		if r.n == 0 {
			r.first = time.Now()
		}
		r.n += int64(n)
	}
	return n, err
}

// HTTPGet sends a GET request over conn and reads the response with stall
// detection. It returns the result and up to opt.Keep bytes of the body.
func (e *Env) HTTPGet(ctx context.Context, conn net.Conn, opt HTTPOptions) (*model.HTTPResult, []byte) {
	res := &model.HTTPResult{ContentLength: -1}
	if opt.Limit <= 0 {
		opt.Limit = DefaultBodyLimit
	}
	if opt.Path == "" {
		opt.Path = "/"
	}
	start := time.Now()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	reqText := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
		opt.Path, opt.Host, e.UserAgent)
	_ = conn.SetWriteDeadline(start.Add(e.Timeouts.FirstByte))
	if _, err := io.WriteString(conn, reqText); err != nil {
		res.Outcome = errclass.Classify(err)
		res.Error = errclass.Short(err)
		return res, nil
	}

	sr := &stallReader{conn: conn, firstByte: e.Timeouts.FirstByte, stall: e.Timeouts.Stall, start: start}
	if w, ok := conn.(interface{ WireIn() int64 }); ok {
		sr.wire = w.WireIn
	}
	br := bufio.NewReaderSize(sr, 16<<10)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+opt.Host+opt.Path, nil)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		e.finishHTTP(res, sr, start, err)
		return res, nil
	}
	defer resp.Body.Close()
	res.Status = resp.StatusCode
	res.ContentLength = resp.ContentLength
	res.Location = resp.Header.Get("Location")
	if !sr.first.IsZero() {
		res.TTFBMs = ms(sr.first.Sub(start))
	}

	keep := make([]byte, 0, min(opt.Keep, 64<<10))
	buf := make([]byte, 16<<10)
	var readErr error
	for res.Bytes < opt.Limit {
		n, err := resp.Body.Read(buf[:min(int64(len(buf)), opt.Limit-res.Bytes)])
		if n > 0 {
			if len(keep) < opt.Keep {
				keep = append(keep, buf[:min(n, opt.Keep-len(keep))]...)
			}
			res.Bytes += int64(n)
		}
		if err != nil {
			readErr = err
			break
		}
	}
	if res.Bytes >= opt.Limit {
		res.Truncated = true
		readErr = nil
	}
	if errors.Is(readErr, io.EOF) {
		readErr = nil
	}
	e.finishHTTP(res, sr, start, readErr)
	if e.Fingerprints != nil {
		res.Blockpage = e.Fingerprints.MatchHTTP(res.Location, keep)
	}
	return res, keep
}

func (e *Env) finishHTTP(res *model.HTTPResult, sr *stallReader, start time.Time, err error) {
	res.RawBytes = sr.n
	res.WireBytes = sr.wireBytes()
	res.DurationMs = ms(time.Since(start))
	if !sr.first.IsZero() {
		if res.TTFBMs == 0 {
			res.TTFBMs = ms(sr.first.Sub(start))
		}
		// Clamp: on some platforms the monotonic clock ticks coarsely.
		el := max(time.Since(sr.first).Seconds(), 0.001)
		if res.Bytes >= 16<<10 {
			res.ThroughputKbps = float64(res.Bytes) * 8 / 1000 / el
		}
	}
	if err == nil {
		res.Outcome = model.OK
		res.Complete = res.Truncated || res.ContentLength < 0 || res.Bytes >= res.ContentLength
		return
	}
	o := errclass.Classify(err)
	if o == model.Timeout && sr.n > 0 {
		o = model.Stall
		res.Stalled = true
		res.BytesBeforeStall = res.WireBytes
	}
	if o == model.EOF && res.ContentLength >= 0 && res.Bytes < res.ContentLength && sr.n > 0 {
		// connection closed before the announced length arrived
		res.BytesBeforeStall = res.WireBytes
	}
	res.Outcome = o
	res.Error = errclass.Short(err)
}

// PlainHTTP fetches http://host/path from ip:80 and checks block page fingerprints.
func (e *Env) PlainHTTP(ctx context.Context, ip string, port int, host, path string) *model.HTTPResult {
	conn, _, err := e.dial(ctx, ip, port)
	if err != nil {
		o := errclass.Classify(err)
		return &model.HTTPResult{Outcome: o, ContentLength: -1, Error: errclass.Short(err)}
	}
	defer conn.Close()
	res, _ := e.HTTPGet(ctx, conn, HTTPOptions{Host: host, Path: path, Limit: 64 << 10, Keep: 64 << 10})
	return res
}

// HostPort formats a host and port.
func HostPort(host string, port int) string { return net.JoinHostPort(host, strconv.Itoa(port)) }
