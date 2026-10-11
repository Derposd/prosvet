package classify

import (
	"testing"

	"github.com/ordinarysim/prosvet/internal/model"
)

var ctx = Context{BaselineKbps: 50000, Connectivity: true}

func tlsOK(variant string) *model.TLSResult {
	return &model.TLSResult{Variant: variant, Stage: "handshake", Outcome: model.OK, Agree: 3, Runs: 3,
		Cert: &model.CertInfo{Subject: "example.com", Issuer: "R3, Let's Encrypt", ValidForHost: true, TrustedSystem: true}}
}

func tlsFail(variant, stage string, o model.Outcome) *model.TLSResult {
	return &model.TLSResult{Variant: variant, Stage: stage, Outcome: o, Agree: 3, Runs: 3}
}

func dnsOK(addrs ...string) *model.DNSResult {
	return &model.DNSResult{
		System:    model.DNSAnswer{Resolver: "system", Outcome: model.OK, Addrs: addrs, Agree: 3, Runs: 3},
		Reference: &model.DNSAnswer{Resolver: "doh:cloudflare", Outcome: model.OK, Addrs: addrs},
	}
}

func httpOK() *model.HTTPResult {
	return &model.HTTPResult{Outcome: model.OK, Status: 200, Bytes: 120000, RawBytes: 121000, ContentLength: 120000,
		Complete: true, ThroughputKbps: 40000, Agree: 3, Runs: 3}
}

func TestEndpointRules(t *testing.T) {
	cases := []struct {
		name    string
		ep      model.EndpointResult
		ctx     *Context
		kind    model.Kind
		subtype string
		conf    model.Confidence
	}{
		{
			name: "ok",
			ep:   model.EndpointResult{Name: "example.com", IP: "93.184.216.34", Port: 443, IPSource: "system", DNS: dnsOK("93.184.216.34"), TLS: []*model.TLSResult{tlsOK("real")}, HTTP: httpOK()},
			kind: model.KindOK, conf: model.High,
		},
		{
			name: "nsdi removal",
			ep: model.EndpointResult{Name: "youtube.com", IP: "142.250.1.1", Port: 443, IPSource: "reference",
				DNS: &model.DNSResult{
					System:    model.DNSAnswer{Resolver: "system", Outcome: model.NXDomain, Agree: 3, Runs: 3},
					NSDI:      &model.DNSAnswer{Resolver: "udp:nsdi", Outcome: model.NXDomain},
					Reference: &model.DNSAnswer{Resolver: "doh:cloudflare", Outcome: model.OK, Addrs: []string{"142.250.1.1"}},
				},
				TLS: []*model.TLSResult{tlsOK("real")}, HTTP: httpOK()},
			kind: model.KindDNS, subtype: "nsdi_removed", conf: model.High,
		},
		{
			name: "dns stub",
			ep: model.EndpointResult{Name: "blocked.example", IP: "95.167.13.50", Port: 443, IPSource: "system",
				DNS: &model.DNSResult{
					System:    model.DNSAnswer{Resolver: "system", Outcome: model.OK, Addrs: []string{"95.167.13.50"}, Stub: "ru.rostelecom.1"},
					Reference: &model.DNSAnswer{Resolver: "doh:cloudflare", Outcome: model.OK, Addrs: []string{"1.2.3.4"}},
				},
				TLS: []*model.TLSResult{tlsFail("real", "connect", model.Timeout)}},
			kind: model.KindDNS, subtype: "stub", conf: model.High,
		},
		{
			name: "ip block drop",
			ep:   model.EndpointResult{Name: "x.example", IP: "1.2.3.4", Port: 443, IPSource: "system", DNS: dnsOK("1.2.3.4"), TLS: []*model.TLSResult{tlsFail("real", "connect", model.Timeout)}},
			kind: model.KindIPBlock, subtype: "drop", conf: model.High,
		},
		{
			name: "ip block 2 of 3",
			ep: model.EndpointResult{Name: "x.example", IP: "1.2.3.4", Port: 443, IPSource: "system", DNS: dnsOK("1.2.3.4"),
				TLS: []*model.TLSResult{{Variant: "real", Stage: "connect", Outcome: model.Timeout, Agree: 2, Runs: 3}}},
			kind: model.KindIPBlock, subtype: "drop", conf: model.Medium,
		},
		{
			name: "sni dpi reset",
			ep: model.EndpointResult{Name: "x.example", IP: "1.2.3.4", Port: 443, IPSource: "system", DNS: dnsOK("1.2.3.4"),
				TLS: []*model.TLSResult{tlsFail("real", "handshake", model.Reset), tlsFail("none", "handshake", model.TLSAlert), tlsOK("random")}},
			kind: model.KindSNIDPI, subtype: "reset", conf: model.High,
		},
		{
			name: "sni dpi drop",
			ep: model.EndpointResult{Name: "x.example", IP: "1.2.3.4", Port: 443, IPSource: "system", DNS: dnsOK("1.2.3.4"),
				TLS: []*model.TLSResult{tlsFail("real", "handshake", model.Timeout), tlsOK("none")}},
			kind: model.KindSNIDPI, subtype: "drop", conf: model.High,
		},
		{
			name: "tls reset regardless of sni",
			ep: model.EndpointResult{Name: "x.example", IP: "1.2.3.4", Port: 443, IPSource: "system", DNS: dnsOK("1.2.3.4"),
				TLS: []*model.TLSResult{tlsFail("real", "handshake", model.Reset), tlsFail("none", "handshake", model.Reset), tlsFail("random", "handshake", model.Reset)}},
			kind: model.KindTLSReset, subtype: "reset", conf: model.Medium,
		},
		{
			name: "handshake timeout everywhere",
			ep: model.EndpointResult{Name: "x.example", IP: "1.2.3.4", Port: 443, IPSource: "system", DNS: dnsOK("1.2.3.4"),
				TLS: []*model.TLSResult{tlsFail("real", "handshake", model.Timeout), tlsFail("none", "handshake", model.Timeout)}},
			kind: model.KindTimeout, subtype: "handshake", conf: model.Low,
		},
		{
			name: "freeze 16kb",
			ep: model.EndpointResult{Name: "x.example", IP: "1.2.3.4", Port: 443, IPSource: "system", DNS: dnsOK("1.2.3.4"),
				TLS:  []*model.TLSResult{tlsOK("real")},
				HTTP: &model.HTTPResult{Outcome: model.Stall, Stalled: true, BytesBeforeStall: 16 << 10, RawBytes: 16 << 10, StallRuns: 3, Runs: 3, Agree: 3}},
			kind: model.KindThrottleFreeze, subtype: "16-20kb", conf: model.High,
		},
		{
			name: "rate throttle",
			ep: model.EndpointResult{Name: "x.example", IP: "1.2.3.4", Port: 443, IPSource: "system", DNS: dnsOK("1.2.3.4"),
				TLS:  []*model.TLSResult{tlsOK("real")},
				HTTP: &model.HTTPResult{Outcome: model.OK, Bytes: 200000, Complete: true, ThroughputKbps: 140, Runs: 3, Agree: 3}},
			kind: model.KindThrottleRate, conf: model.Medium,
		},
		{
			name: "state ca on foreign site",
			ep: model.EndpointResult{Name: "www.google.com", IP: "1.2.3.4", Port: 443, IPSource: "system", DNS: dnsOK("1.2.3.4"),
				TLS: []*model.TLSResult{{Variant: "real", Stage: "handshake", Outcome: model.OK, Agree: 3, Runs: 3,
					Cert: &model.CertInfo{Issuer: "Russian Trusted Sub CA", ValidForHost: true, TrustedSystem: true, RussianTrustedCA: true}}}},
			kind: model.KindTLSMITM, subtype: "state_ca", conf: model.High,
		},
		{
			name: "state ca on domestic site is fine",
			ep: model.EndpointResult{Name: "online.sberbank.ru", IP: "1.2.3.4", Port: 443, IPSource: "system", DNS: dnsOK("1.2.3.4"),
				TLS: []*model.TLSResult{{Variant: "real", Stage: "handshake", Outcome: model.OK, Agree: 3, Runs: 3,
					Cert: &model.CertInfo{Issuer: "Russian Trusted Sub CA", ValidForHost: true, RussianTrustedCA: true}}},
				HTTP: httpOK()},
			kind: model.KindOK, conf: model.High,
		},
		{
			name: "blockpage on port 80",
			ep: model.EndpointResult{Name: "x.example", IP: "1.2.3.4", Port: 443, IPSource: "system", DNS: dnsOK("1.2.3.4"),
				TLS:    []*model.TLSResult{tlsFail("real", "handshake", model.Reset)},
				HTTP80: &model.HTTPResult{Outcome: model.OK, Status: 302, Location: "http://warning.rt.ru/", Blockpage: "ru.rostelecom.warning"}},
			kind: model.KindBlockpage, subtype: "ru.rostelecom.warning", conf: model.High,
		},
		{
			name: "no connectivity",
			ep:   model.EndpointResult{Name: "x.example", IP: "1.2.3.4", Port: 443, DNS: dnsOK("1.2.3.4"), TLS: []*model.TLSResult{tlsFail("real", "connect", model.Timeout)}},
			ctx:  &Context{Connectivity: false},
			kind: model.KindNoConnectivity, conf: model.High,
		},
		{
			name: "telegram dc tcp only",
			ep:   model.EndpointResult{Name: "149.154.167.51", IP: "149.154.167.51", Port: 443, TCP: tlsFail("tcp", "connect", model.Timeout)},
			kind: model.KindIPBlock, subtype: "drop", conf: model.High,
		},
		{
			name: "quic sni only endpoint",
			ep: model.EndpointResult{Name: "www.google.com", IP: "1.2.3.4", Port: 443, QUIC: []*model.QUICResult{
				{Version: 1, Variant: "random", Outcome: model.Responded, Agree: 3, Runs: 3},
				{Version: 1, Variant: "real", Outcome: model.Timeout, Agree: 3, Runs: 3},
			}},
			kind: model.KindQUICSNI, subtype: "v1", conf: model.High,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cx := ctx
			if c.ctx != nil {
				cx = *c.ctx
			}
			ep := c.ep
			Endpoint(&ep, cx)
			if ep.Verdict.Kind != c.kind || ep.Verdict.Subtype != c.subtype || ep.Verdict.Confidence != c.conf {
				t.Fatalf("got %s/%s/%s want %s/%s/%s (evidence %+v)",
					ep.Verdict.Kind, ep.Verdict.Subtype, ep.Verdict.Confidence, c.kind, c.subtype, c.conf, ep.Verdict.Evidence)
			}
			if c.kind != model.KindOK && len(ep.Verdict.Evidence) == 0 {
				t.Fatal("non-ok verdicts must carry evidence")
			}
		})
	}
}

func TestDNSBlockWithIPBlockSecondary(t *testing.T) {
	ep := model.EndpointResult{Name: "whatsapp.com", IP: "157.240.1.1", Port: 443, IPSource: "reference",
		DNS: &model.DNSResult{
			System:    model.DNSAnswer{Resolver: "system", Outcome: model.NXDomain, Agree: 3, Runs: 3},
			Reference: &model.DNSAnswer{Resolver: "doh:quad9", Outcome: model.OK, Addrs: []string{"157.240.1.1"}},
		},
		TLS: []*model.TLSResult{tlsFail("real", "handshake", model.Reset), tlsOK("none")},
	}
	Endpoint(&ep, ctx)
	if ep.Verdict.Kind != model.KindDNS {
		t.Fatalf("primary must be dns, got %s", ep.Verdict.Kind)
	}
	if len(ep.Secondary) != 1 || ep.Secondary[0] != model.KindSNIDPI {
		t.Fatalf("secondary must be sni_dpi, got %v", ep.Secondary)
	}
}

func TestCDNAddressDifferenceIsNotTampering(t *testing.T) {
	ep := model.EndpointResult{Name: "www.google.com", IP: "142.250.1.1", Port: 443, IPSource: "system",
		DNS: &model.DNSResult{
			System:    model.DNSAnswer{Resolver: "system", Outcome: model.OK, Addrs: []string{"142.250.1.1"}},
			Reference: &model.DNSAnswer{Resolver: "doh:cloudflare", Outcome: model.OK, Addrs: []string{"172.217.2.2"}},
		},
		TLS: []*model.TLSResult{tlsOK("real")}, HTTP: httpOK(),
	}
	Endpoint(&ep, ctx)
	if ep.Verdict.Kind != model.KindOK {
		t.Fatalf("got %s", ep.Verdict.Kind)
	}
}

func TestPrivateCAIsNotMITM(t *testing.T) {
	ep := model.EndpointResult{Name: "chat.signal.org", IP: "13.248.212.111", Port: 443, IPSource: "system", DNS: dnsOK("13.248.212.111"),
		TLS: []*model.TLSResult{{Variant: "real", Stage: "handshake", Outcome: model.OK, Agree: 3, Runs: 3,
			Cert: &model.CertInfo{Issuer: "Signal Messenger, Signal Messenger, LLC", ValidForHost: true, TrustedSystem: false}}},
		HTTP: httpOK()}
	Endpoint(&ep, ctx)
	if ep.Verdict.Kind != model.KindOK {
		t.Fatalf("private PKI must not be reported as MITM, got %s", ep.Verdict.Kind)
	}
	if len(ep.Verdict.Evidence) != 1 || ep.Verdict.Evidence[0].Key != "ev.cert.untrusted" {
		t.Fatalf("expected an untrusted-certificate note: %+v", ep.Verdict.Evidence)
	}
}

func TestUnreachableSystemAddressIsIPBlockNotDNS(t *testing.T) {
	ep := model.EndpointResult{Name: "gql.example", IP: "45.1.1.1", Port: 443, IPSource: "system",
		DNS: &model.DNSResult{
			System:    model.DNSAnswer{Resolver: "system", Outcome: model.OK, Addrs: []string{"45.1.1.1"}},
			Reference: &model.DNSAnswer{Resolver: "doh:cloudflare", Outcome: model.OK, Addrs: []string{"151.1.1.1"}},
		},
		TLS:    []*model.TLSResult{tlsFail("real", "connect", model.Timeout)},
		RefTLS: tlsOK("real"),
	}
	Endpoint(&ep, ctx)
	if ep.Verdict.Kind != model.KindIPBlock {
		t.Fatalf("got %s/%s", ep.Verdict.Kind, ep.Verdict.Subtype)
	}
	last := ep.Verdict.Evidence[len(ep.Verdict.Evidence)-1]
	if last.Key != "ev.connect.ref_ok" {
		t.Fatalf("missing ref_ok evidence: %+v", ep.Verdict.Evidence)
	}
}

func TestSubstitutedDNS(t *testing.T) {
	ep := model.EndpointResult{Name: "site.example", IP: "10.10.10.10", Port: 443, IPSource: "system",
		DNS: &model.DNSResult{
			System:    model.DNSAnswer{Resolver: "system", Outcome: model.OK, Addrs: []string{"91.1.1.1"}},
			Reference: &model.DNSAnswer{Resolver: "doh:cloudflare", Outcome: model.OK, Addrs: []string{"104.1.1.1"}},
		},
		TLS:    []*model.TLSResult{{Variant: "real", Stage: "handshake", Outcome: model.OK, Agree: 3, Runs: 3, Cert: &model.CertInfo{ValidForHost: false, TrustedSystem: true}}},
		RefTLS: tlsOK("real"),
	}
	Endpoint(&ep, ctx)
	if ep.Verdict.Kind != model.KindDNS || ep.Verdict.Subtype != "substituted" {
		t.Fatalf("got %s/%s", ep.Verdict.Kind, ep.Verdict.Subtype)
	}
}

func TestQUICSecondaryOnWorkingSite(t *testing.T) {
	ep := model.EndpointResult{Name: "www.youtube.com", IP: "1.2.3.4", Port: 443, IPSource: "system", DNS: dnsOK("1.2.3.4"),
		TLS: []*model.TLSResult{tlsOK("real")}, HTTP: httpOK(),
		QUIC: []*model.QUICResult{
			{Version: 1, Variant: "random", Outcome: model.Responded, Agree: 3, Runs: 3},
			{Version: 1, Variant: "real", Outcome: model.Timeout, Agree: 3, Runs: 3},
			{Version: 2, Variant: "real", Outcome: model.OK, Agree: 3, Runs: 3},
		}}
	Endpoint(&ep, ctx)
	if ep.Verdict.Kind != model.KindOK {
		t.Fatalf("primary should stay ok, got %s", ep.Verdict.Kind)
	}
	if len(ep.Secondary) != 1 || ep.Secondary[0] != model.KindQUICSNI {
		t.Fatalf("secondary: %v", ep.Secondary)
	}
}

func TestTargetAggregation(t *testing.T) {
	mk := func(k model.Kind, c model.Confidence) model.EndpointResult {
		return model.EndpointResult{Verdict: model.Verdict{Kind: k, Confidence: c, Evidence: []model.Evidence{{Key: "x"}}}}
	}
	cases := []struct {
		name   string
		eps    []model.EndpointResult
		thr    *model.HTTPResult
		status model.Status
		kind   model.Kind
	}{
		{"all ok", []model.EndpointResult{mk(model.KindOK, model.High), mk(model.KindOK, model.High)}, nil, model.StatusOK, model.KindOK},
		{"all blocked", []model.EndpointResult{mk(model.KindSNIDPI, model.High), mk(model.KindSNIDPI, model.High), mk(model.KindIPBlock, model.High)}, nil, model.StatusBlocked, model.KindSNIDPI},
		{"partial", []model.EndpointResult{mk(model.KindOK, model.High), mk(model.KindDNS, model.High)}, nil, model.StatusPartial, model.KindDNS},
		{"throttled by url", []model.EndpointResult{mk(model.KindOK, model.High)},
			&model.HTTPResult{Outcome: model.Stall, Stalled: true, BytesBeforeStall: 17000, StallRuns: 3, Runs: 3}, model.StatusThrottled, model.KindThrottleFreeze},
		{"unreachable", []model.EndpointResult{mk(model.KindNoConnectivity, model.High)}, nil, model.StatusUnreachable, model.KindNoConnectivity},
		{"protocol only", []model.EndpointResult{mk(model.KindQUICSNI, model.High)}, nil, model.StatusBlocked, model.KindQUICSNI},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := model.TargetResult{Endpoints: c.eps, Throttle: c.thr}
			Target(&tr, ctx)
			if tr.Status != c.status || tr.Verdict.Kind != c.kind {
				t.Fatalf("got %s/%s want %s/%s", tr.Status, tr.Verdict.Kind, c.status, c.kind)
			}
		})
	}
}

func TestPrimaryConfidenceBoost(t *testing.T) {
	eps := []model.EndpointResult{
		{Verdict: model.Verdict{Kind: model.KindSNIDPI, Confidence: model.Medium}},
		{Verdict: model.Verdict{Kind: model.KindSNIDPI, Confidence: model.Medium}},
	}
	tr := model.TargetResult{Endpoints: eps}
	Target(&tr, ctx)
	if tr.Verdict.Confidence != model.High {
		t.Fatalf("two agreeing endpoints should raise confidence, got %s", tr.Verdict.Confidence)
	}
}

func TestWhitelist(t *testing.T) {
	ok := func(n int) []model.WhitelistCheck {
		out := make([]model.WhitelistCheck, n)
		for i := range out {
			out[i] = model.WhitelistCheck{Stage: "ok", Outcome: model.OK}
		}
		return out
	}
	fail := func(n int, stage string) []model.WhitelistCheck {
		out := make([]model.WhitelistCheck, n)
		for i := range out {
			out[i] = model.WhitelistCheck{Stage: stage, Outcome: model.Timeout}
		}
		return out
	}
	cases := []struct {
		name     string
		dom, frn []model.WhitelistCheck
		verdict  string
		level    string
	}{
		{"active", ok(18), fail(12, "handshake"), model.WhitelistActive, "handshake"},
		{"active by ip", append(ok(16), fail(2, "connect")...), fail(12, "connect"), model.WhitelistActive, "connect"},
		{"normal", ok(18), ok(12), model.WhitelistNormal, ""},
		{"dead", fail(18, "connect"), fail(12, "connect"), model.WhitelistNoConnectivity, ""},
		{"degraded", ok(18), append(ok(5), fail(7, "dns")...), model.WhitelistDegraded, "dns"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &model.WhitelistResult{Domestic: c.dom, Foreign: c.frn}
			Whitelist(r, WhitelistThresholds{})
			if r.Verdict != c.verdict || r.FailureLevel != c.level {
				t.Fatalf("got %s/%s want %s/%s", r.Verdict, r.FailureLevel, c.verdict, c.level)
			}
		})
	}
}

func TestDNSFindings(t *testing.T) {
	r := &model.DNSReport{
		Resolvers: []model.ResolverStatus{
			{ID: "google", Transport: "doh", Outcome: model.Reset},
			{ID: "cloudflare", Transport: "dot", Outcome: model.Reset},
			{ID: "quad9", Transport: "doh", Outcome: model.OK},
		},
		Interception: []model.InterceptionCheck{
			{ID: "a", Resolver: "1.1.1.1", Outcome: model.OK, Passed: false},
			{ID: "b", Resolver: "8.8.8.8", Outcome: model.NXDomain, Passed: false},
			{ID: "c", Resolver: "8.8.8.8", Outcome: model.Timeout, Passed: false},
		},
		Domains: []model.DomainCheck{{Name: "youtube.com", Answers: []model.DNSAnswer{
			{Resolver: "system", Outcome: model.NXDomain},
			{Resolver: "doh:quad9", Outcome: model.OK, Addrs: []string{"142.250.1.1"}},
		}}},
	}
	DNSFindings(r)
	kinds := map[string]model.DNSFinding{}
	for _, f := range r.Findings {
		kinds[f.Kind] = f
	}
	if f, ok := kinds["dns_interception"]; !ok || f.Confidence != model.High || len(f.Resolvers) != 2 {
		t.Fatalf("interception finding wrong: %+v", r.Findings)
	}
	if _, ok := kinds["doh_blocked"]; !ok {
		t.Fatal("doh_blocked missing")
	}
	if _, ok := kinds["dot_blocked"]; !ok {
		t.Fatal("dot_blocked missing")
	}
	if f, ok := kinds["system_resolver_tampering"]; !ok || f.Domains[0] != "youtube.com" {
		t.Fatal("system_resolver_tampering missing")
	}
}
