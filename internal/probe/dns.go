package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/Derposd/prosvet/internal/catalog"
	"github.com/Derposd/prosvet/internal/errclass"
	"github.com/Derposd/prosvet/internal/model"
)

// DNS transports.
const (
	TransportSystem = "system"
	TransportUDP    = "udp"
	TransportDoT    = "dot"
	TransportDoH    = "doh"
)

// ResolverSpec addresses one resolver over one transport.
type ResolverSpec struct {
	ID        string
	Name      string
	Transport string
	Addr      string // udp/dot: ip:port
	Host      string // dot: TLS server name
	URL       string // doh
}

// Label returns a compact identifier like "doh:cloudflare".
func (s ResolverSpec) Label() string {
	if s.Transport == TransportSystem {
		return "system"
	}
	return s.Transport + ":" + s.ID
}

// Endpoint returns a human-readable endpoint string.
func (s ResolverSpec) Endpoint() string {
	switch s.Transport {
	case TransportDoH:
		return s.URL
	case TransportSystem:
		return "os"
	default:
		return s.Addr
	}
}

// SpecsFor expands a catalog resolver into one spec per transport.
func SpecsFor(r catalog.Resolver) []ResolverSpec {
	name := r.Name.Get("en")
	if r.Type == TransportSystem {
		return []ResolverSpec{{ID: r.ID, Name: name, Transport: TransportSystem}}
	}
	var out []ResolverSpec
	if len(r.UDP) > 0 {
		out = append(out, ResolverSpec{ID: r.ID, Name: name, Transport: TransportUDP, Addr: net.JoinHostPort(r.UDP[0], "53")})
	}
	if r.DoT != nil {
		out = append(out, ResolverSpec{ID: r.ID, Name: name, Transport: TransportDoT, Addr: r.DoT.Addr, Host: r.DoT.Host})
	}
	if r.DoH != "" {
		out = append(out, ResolverSpec{ID: r.ID, Name: name, Transport: TransportDoH, URL: r.DoH})
	}
	return out
}

// DoHSpec returns the DoH spec of a catalog resolver, if any.
func DoHSpec(r catalog.Resolver) (ResolverSpec, bool) {
	if r.DoH == "" {
		return ResolverSpec{}, false
	}
	return ResolverSpec{ID: r.ID, Name: r.Name.Get("en"), Transport: TransportDoH, URL: r.DoH}, true
}

// Exchange sends m through the resolver and returns the response.
func (e *Env) Exchange(ctx context.Context, spec ResolverSpec, m *dns.Msg) (*dns.Msg, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, e.Timeouts.DNS)
	defer cancel()
	start := time.Now()
	var (
		resp *dns.Msg
		err  error
	)
	switch spec.Transport {
	case TransportUDP:
		resp, err = e.exchangeStream(ctx, "udp", spec.Addr, "", m)
	case TransportDoT:
		resp, err = e.exchangeStream(ctx, "tcp", spec.Addr, spec.Host, m)
	case TransportDoH:
		resp, err = e.exchangeDoH(ctx, spec.URL, m)
	default:
		err = fmt.Errorf("transport %q does not support raw queries", spec.Transport)
	}
	return resp, time.Since(start), err
}

func (e *Env) exchangeStream(ctx context.Context, network, addr, tlsHost string, m *dns.Msg) (*dns.Msg, error) {
	raw, err := e.Dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	conn := raw
	if tlsHost != "" {
		tc := tls.Client(raw, &tls.Config{ServerName: tlsHost, RootCAs: e.RootCAs, MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		conn = tc
	}
	co := &dns.Conn{Conn: conn}
	if err := co.WriteMsg(m); err != nil {
		return nil, err
	}
	for {
		resp, err := co.ReadMsg()
		if err != nil {
			return nil, err
		}
		if resp.Id == m.Id {
			return resp, nil
		}
	}
}

func (e *Env) exchangeDoH(ctx context.Context, url string, m *dns.Msg) (*dns.Msg, error) {
	q := m.Copy()
	q.Id = 0 // RFC 8484 recommends id 0 for cache friendliness
	wire, err := q.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", e.UserAgent)
	resp, err := e.HTTPClient(e.Timeouts.DNS + e.Timeouts.Handshake).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: http status %d", resp.StatusCode)
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, fmt.Errorf("doh: %w", err)
	}
	out.Id = m.Id
	return out, nil
}

// Resolve looks up IPv4 addresses of name through spec.
func (e *Env) Resolve(ctx context.Context, spec ResolverSpec, name string) model.DNSAnswer {
	ans := model.DNSAnswer{Resolver: spec.Label()}
	if spec.Transport == TransportSystem {
		return e.resolveSystem(ctx, name)
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.RecursionDesired = true
	resp, rtt, err := e.Exchange(ctx, spec, m)
	ans.RTTMs = ms(rtt)
	if err != nil {
		ans.Outcome = errclass.Classify(err)
		if ans.Outcome == model.NXDomain {
			ans.Outcome = model.ServFail
		}
		ans.Error = errclass.Short(err)
		return ans
	}
	return e.fillAnswer(ans, resp)
}

func (e *Env) fillAnswer(ans model.DNSAnswer, resp *dns.Msg) model.DNSAnswer {
	switch resp.Rcode {
	case dns.RcodeSuccess:
	case dns.RcodeNameError:
		ans.Outcome = model.NXDomain
		return ans
	default:
		ans.Outcome = model.ServFail
		ans.Error = dns.RcodeToString[resp.Rcode]
		return ans
	}
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			ans.Addrs = append(ans.Addrs, a.A.String())
		}
	}
	if len(ans.Addrs) == 0 {
		ans.Outcome = model.NoAnswer
		return ans
	}
	ans.Outcome = model.OK
	e.annotate(&ans)
	return ans
}

func (e *Env) resolveSystem(ctx context.Context, name string) model.DNSAnswer {
	ans := model.DNSAnswer{Resolver: "system"}
	ctx, cancel := context.WithTimeout(ctx, e.Timeouts.DNS)
	defer cancel()
	start := time.Now()
	addrs, err := e.LookupHost(ctx, name)
	ans.RTTMs = ms(time.Since(start))
	if err != nil {
		ans.Outcome = errclass.Classify(err)
		if ans.Outcome != model.NXDomain && ans.Outcome != model.Timeout {
			ans.Outcome = model.ServFail
		}
		ans.Error = errclass.Short(err)
		return ans
	}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			ans.Addrs = append(ans.Addrs, ip.String())
		}
	}
	if len(ans.Addrs) == 0 {
		ans.Outcome = model.NoAnswer
		return ans
	}
	ans.Outcome = model.OK
	e.annotate(&ans)
	return ans
}

func (e *Env) annotate(ans *model.DNSAnswer) {
	sort.Strings(ans.Addrs)
	if e.Fingerprints != nil {
		ans.Stub = e.Fingerprints.MatchDNS(ans.Addrs)
	}
	for _, a := range ans.Addrs {
		if e.IsBogon != nil && e.IsBogon(a) {
			ans.Bogon = true
		}
	}
}

// ResolveFirst tries specs in order and returns the first successful answer.
// It returns the last answer when none succeeded.
func (e *Env) ResolveFirst(ctx context.Context, specs []ResolverSpec, name string) model.DNSAnswer {
	var last model.DNSAnswer
	for _, s := range specs {
		ans := e.Resolve(ctx, s, name)
		if ans.Outcome == model.OK || ans.Outcome == model.NXDomain {
			return ans
		}
		last = ans
	}
	if last.Resolver == "" {
		last = model.DNSAnswer{Resolver: "reference", Outcome: model.Skipped}
	}
	return last
}

// FetchECHConfig returns the ECHConfigList from the HTTPS record of host.
func (e *Env) FetchECHConfig(ctx context.Context, specs []ResolverSpec, host string) ([]byte, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeHTTPS)
	m.RecursionDesired = true
	lastErr := errors.New("no resolver available")
	for _, s := range specs {
		resp, _, err := e.Exchange(ctx, s, m)
		if err != nil {
			lastErr = err
			continue
		}
		for _, rr := range resp.Answer {
			h, ok := rr.(*dns.HTTPS)
			if !ok {
				continue
			}
			for _, kv := range h.Value {
				if ech, ok := kv.(*dns.SVCBECHConfig); ok && len(ech.ECH) > 0 {
					return ech.ECH, nil
				}
			}
		}
		lastErr = fmt.Errorf("no ECH config in HTTPS record of %s", host)
	}
	return nil, lastErr
}

var coloRe = regexp.MustCompile(`^[A-Z]{3}$`)

// Intercept runs one interception probe. The returned detail never contains
// IP addresses (some probes echo the client address).
func (e *Env) Intercept(ctx context.Context, p catalog.Interception) model.InterceptionCheck {
	res := model.InterceptionCheck{ID: p.ID, Resolver: p.Resolver, QName: p.QName, Expect: p.Expect}
	qtype, ok := dns.StringToType[strings.ToUpper(p.QType)]
	if !ok {
		qtype = dns.TypeA
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(p.QName), qtype)
	m.RecursionDesired = true
	if strings.EqualFold(p.QClass, "CH") {
		m.Question[0].Qclass = dns.ClassCHAOS
	}
	spec := ResolverSpec{ID: p.Resolver, Transport: TransportUDP, Addr: net.JoinHostPort(p.Resolver, "53")}
	resp, _, err := e.Exchange(ctx, spec, m)
	if err != nil {
		res.Outcome = errclass.Classify(err)
		res.Detail = string(res.Outcome)
		return res
	}
	res.Outcome = model.OK
	rcode := dns.RcodeToString[resp.Rcode]
	var txt []string
	var nA int
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.TXT:
			txt = append(txt, strings.Join(v.Txt, ""))
		case *dns.A:
			nA++
		}
	}
	switch p.Expect {
	case "nonempty":
		res.Passed = resp.Rcode == dns.RcodeSuccess && len(txt) > 0
		res.Detail = fmt.Sprintf("rcode=%s txt=%d", rcode, len(txt))
	case "colo_code":
		res.Passed = len(txt) > 0 && coloRe.MatchString(txt[0])
		if res.Passed {
			res.Detail = "colo=" + txt[0]
		} else {
			res.Detail = fmt.Sprintf("rcode=%s txt=%d", rcode, len(txt))
		}
	case "noerror":
		res.Passed = resp.Rcode == dns.RcodeSuccess && nA > 0
		res.Detail = fmt.Sprintf("rcode=%s a=%d", rcode, nA)
	default:
		res.Detail = "unknown expectation"
	}
	if resp.Rcode == dns.RcodeNameError {
		res.Outcome = model.NXDomain
	}
	return res
}
