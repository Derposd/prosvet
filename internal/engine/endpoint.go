package engine

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/ordinarysim/prosvet/internal/catalog"
	"github.com/ordinarysim/prosvet/internal/classify"
	"github.com/ordinarysim/prosvet/internal/model"
	"github.com/ordinarysim/prosvet/internal/probe"
)

// measureTarget probes every endpoint of t (concurrently), the throttle URL,
// and classifies the result.
func (e *Engine) measureTarget(ctx context.Context, t catalog.Target, cctx classify.Context) model.TargetResult {
	start := time.Now()
	tr := model.TargetResult{
		ID: t.ID, Name: t.Name, Category: t.Category, Role: t.Role,
		Expect: t.Expect, Since: t.Since, ThrottleURL: t.ThrottleURL,
		Endpoints: make([]model.EndpointResult, len(t.Endpoints)),
	}
	if tr.Name == "" {
		tr.Name = t.ID
	}
	var wg sync.WaitGroup
	for i, ep := range t.Endpoints {
		if t.IsBaseline() {
			// Baselines only need the throughput measurement.
			tr.Endpoints[i] = model.EndpointResult{Name: ep.Name(), Port: ep.EffectivePort(),
				Verdict: model.Verdict{Kind: model.KindOK, Confidence: model.High}}
			continue
		}
		wg.Add(1)
		go func(i int, ep catalog.Endpoint) {
			defer wg.Done()
			if !e.acquire(ctx) {
				tr.Endpoints[i] = model.EndpointResult{Name: ep.Name(), Port: ep.EffectivePort(),
					Verdict: model.Verdict{Kind: model.KindUnknown, Confidence: model.Low}}
				return
			}
			defer e.release()
			r := e.measureEndpoint(ctx, ep)
			classify.Endpoint(&r, cctx)
			tr.Endpoints[i] = r
		}(i, ep)
	}
	if t.ThrottleURL != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !e.acquire(ctx) {
				return
			}
			defer e.release()
			tr.Throttle = e.measureThrottle(ctx, t.ThrottleURL)
		}()
	}
	wg.Wait()
	if t.IsBaseline() {
		tr.Status = model.StatusOK
		tr.Verdict = model.Verdict{Kind: model.KindOK, Confidence: model.High}
		if tr.Throttle == nil || tr.Throttle.Outcome != model.OK {
			tr.Status = model.StatusUnknown
			tr.Verdict = model.Verdict{Kind: model.KindUnknown, Confidence: model.Low}
		}
	} else {
		classify.Target(&tr, cctx)
	}
	tr.DurationMs = time.Since(start).Milliseconds()
	return tr
}

// measureEndpoint runs all configured tests for one endpoint.
func (e *Engine) measureEndpoint(ctx context.Context, ep catalog.Endpoint) model.EndpointResult {
	res := model.EndpointResult{Name: ep.Name(), Port: ep.EffectivePort(), Note: ep.Note}
	R := e.Opt.Repeats
	host := ep.Host

	var ip string
	var refAns model.DNSAnswer
	if host != "" {
		sys := e.repeatDNS(ctx, host)
		refAns = e.reference(ctx, host)
		var nsdi *model.DNSAnswer
		if e.nsdi != nil && (sys.Outcome != model.OK || sys.Stub != "" || sys.Bogon) {
			a := e.Env.Resolve(ctx, *e.nsdi, host)
			nsdi = &a
		}
		if ep.Has(catalog.TestDNS) {
			res.DNS = &model.DNSResult{System: sys, NSDI: nsdi, Reference: &refAns}
		}
		switch {
		case sys.Outcome == model.OK && sys.Stub == "" && !sys.Bogon:
			ip, res.IPSource = sys.Addrs[0], "system"
		case refAns.Outcome == model.OK && len(refAns.Addrs) > 0:
			ip, res.IPSource = refAns.Addrs[0], "reference"
		case sys.Outcome == model.OK:
			ip, res.IPSource = sys.Addrs[0], "system"
		}
		if ip == "" {
			if res.DNS == nil {
				res.DNS = &model.DNSResult{System: sys, NSDI: nsdi, Reference: &refAns}
			}
			return res
		}
	} else {
		h, _, err := net.SplitHostPort(ep.Addr)
		if err != nil {
			return res
		}
		ip = h
	}
	res.IP = ip
	port := ep.EffectivePort()

	switch {
	case ep.Has(catalog.TestTLS) || ep.Has(catalog.TestHTTP):
		e.tlsAndHTTP(ctx, ep, &res, ip, port, refAns)
	case ep.Has(catalog.TestTCP):
		var rs []*model.TLSResult
		for i := 0; i < R; i++ {
			if i > 0 {
				e.pause(ctx)
			}
			rs = append(rs, e.Env.Connect(ctx, ip, port))
		}
		res.TCP = voteTLS(rs)
	}
	if ep.Has(catalog.TestTLSNoSNI) && res.TLSVariant(model.VariantNone) == nil {
		res.TLS = append(res.TLS, e.repeatTLS(ctx, ip, port, model.VariantNone, host))
	}
	if ep.HTTP80 && host != "" {
		res.HTTP80 = e.Env.PlainHTTP(ctx, ip, 80, host, "/")
	}
	if e.Opt.QUIC && host != "" && ep.Has(catalog.TestQUIC) {
		for _, v := range ep.EffectiveQUICVersions() {
			// Random SNI first: a filtered real-SNI flow may be blackholed for minutes.
			res.QUIC = append(res.QUIC, e.repeatQUIC(ctx, ip, port, probe.RandomSNI(), model.VariantRandom, v))
			res.QUIC = append(res.QUIC, e.repeatQUIC(ctx, ip, port, host, model.VariantReal, v))
		}
	}
	if host != "" && ep.Has(catalog.TestECH) {
		res.ECH = e.measureECH(ctx, ip, port, host)
	}
	return res
}

func (e *Engine) tlsAndHTTP(ctx context.Context, ep catalog.Endpoint, res *model.EndpointResult, ip string, port int, refAns model.DNSAnswer) {
	host := ep.Host
	withHTTP := ep.Has(catalog.TestHTTP) && host != ""
	var reals []*model.TLSResult
	var https []*model.HTTPResult
	for i := 0; i < e.Opt.Repeats; i++ {
		if i > 0 {
			e.pause(ctx)
		}
		r, conn := e.Env.TLS(ctx, ip, port, probe.TLSOptions{Variant: model.VariantReal, Host: host, ALPN: []string{"http/1.1"}, Keep: withHTTP})
		reals = append(reals, r)
		if conn != nil {
			h, _ := e.Env.HTTPGet(ctx, conn, probe.HTTPOptions{Host: host, Path: ep.EffectivePath(), Limit: e.Opt.EndpointBody, Keep: 64 << 10})
			_ = conn.Close()
			https = append(https, h)
		}
	}
	real := voteTLS(reals)
	res.TLS = append(res.TLS, real)
	if len(https) > 0 && real.Succeeded() {
		res.HTTP = voteHTTP(https)
	}
	if real.Stage == "handshake" && !real.Succeeded() {
		// Differential test: is the failure tied to the server name?
		res.TLS = append(res.TLS, e.repeatTLS(ctx, ip, port, model.VariantNone, host))
		res.TLS = append(res.TLS, e.repeatTLS(ctx, ip, port, model.VariantRandom, host))
	}
	// Validate a differing system answer against the reference address.
	if res.IPSource == "system" && refAns.Outcome == model.OK && len(refAns.Addrs) > 0 && !contains(refAns.Addrs, ip) {
		badCert := real.Succeeded() && real.Cert != nil && !real.Cert.ValidForHost
		if !real.Succeeded() || badCert {
			r, _ := e.Env.TLS(ctx, refAns.Addrs[0], port, probe.TLSOptions{Variant: model.VariantReal, Host: host})
			res.RefTLS = r
		}
	}
}

func (e *Engine) repeatTLS(ctx context.Context, ip string, port int, variant, host string) *model.TLSResult {
	var rs []*model.TLSResult
	for i := 0; i < e.Opt.Repeats; i++ {
		if i > 0 {
			e.pause(ctx)
		}
		r, _ := e.Env.TLS(ctx, ip, port, probe.TLSOptions{Variant: variant, Host: host})
		rs = append(rs, r)
	}
	return voteTLS(rs)
}

func (e *Engine) repeatQUIC(ctx context.Context, ip string, port int, sni, variant string, version int) *model.QUICResult {
	var rs []*model.QUICResult
	for i := 0; i < e.Opt.Repeats; i++ {
		if i > 0 {
			e.pause(ctx)
		}
		rs = append(rs, e.Env.QUIC(ctx, ip, port, sni, variant, version))
	}
	return voteQUIC(rs)
}

func (e *Engine) repeatDNS(ctx context.Context, host string) model.DNSAnswer {
	var rs []model.DNSAnswer
	for i := 0; i < e.Opt.Repeats; i++ {
		rs = append(rs, e.Env.Resolve(ctx, probe.ResolverSpec{Transport: probe.TransportSystem}, host))
	}
	return voteDNS(rs)
}

func (e *Engine) measureECH(ctx context.Context, ip string, port int, host string) *model.TLSResult {
	cfg, err := e.Env.FetchECHConfig(ctx, e.refSpecs, host)
	if err != nil {
		return &model.TLSResult{Variant: model.VariantECH, Stage: "config", Outcome: model.Skipped, Error: err.Error()}
	}
	var rs []*model.TLSResult
	for i := 0; i < e.Opt.Repeats; i++ {
		if i > 0 {
			e.pause(ctx)
		}
		r, _ := e.Env.TLS(ctx, ip, port, probe.TLSOptions{Variant: model.VariantECH, Host: host, ECH: cfg})
		rs = append(rs, r)
	}
	return voteTLS(rs)
}

// measureThrottle downloads throttle URL (bounded) Repeats times.
func (e *Engine) measureThrottle(ctx context.Context, raw string) *model.HTTPResult {
	u, err := url.Parse(raw)
	if err != nil {
		return &model.HTTPResult{Outcome: model.Error, ContentLength: -1, Error: err.Error()}
	}
	host := u.Hostname()
	port := 443
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}
	path := u.RequestURI()
	ans := e.Env.Resolve(ctx, probe.ResolverSpec{Transport: probe.TransportSystem}, host)
	ip := ""
	if ans.Outcome == model.OK && ans.Stub == "" && !ans.Bogon {
		ip = ans.Addrs[0]
	} else if ref := e.reference(ctx, host); ref.Outcome == model.OK {
		ip = ref.Addrs[0]
	}
	if ip == "" {
		return &model.HTTPResult{Outcome: ans.Outcome, ContentLength: -1, Error: "dns: " + string(ans.Outcome)}
	}
	var rs []*model.HTTPResult
	for i := 0; i < e.Opt.Repeats; i++ {
		if i > 0 {
			e.pause(ctx)
		}
		tlsRes, conn := e.Env.TLS(ctx, ip, port, probe.TLSOptions{Variant: model.VariantReal, Host: host, ALPN: []string{"http/1.1"}, Keep: true})
		if conn == nil {
			rs = append(rs, &model.HTTPResult{Outcome: tlsRes.Outcome, ContentLength: -1, Error: "tls " + tlsRes.Stage + ": " + string(tlsRes.Outcome)})
			continue
		}
		h, _ := e.Env.HTTPGet(ctx, conn, probe.HTTPOptions{Host: host, Path: path, Limit: e.Opt.ThrottleLimit})
		_ = conn.Close()
		rs = append(rs, h)
	}
	return voteHTTP(rs)
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
