// Package classify turns raw measurements into verdicts: which kind of
// interference (if any) affects an endpoint or a target, how confident we are
// and which evidence supports the conclusion.
//
// The rules follow docs/research.md §7.2. The `expect` field of a target is
// deliberately never consulted, so prior beliefs cannot bias the result.
package classify

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Derposd/prosvet/internal/model"
)

// Context carries scan-wide facts needed by the rules.
type Context struct {
	// BaselineKbps is the domestic reference throughput (0 = unknown).
	BaselineKbps float64
	// Connectivity is false when even control hosts were unreachable.
	Connectivity bool
}

// Freeze window for the "TCP 16–20" signature, in bytes received on the wire
// (TCP payload including the TLS handshake), which is what the censor counts.
const (
	FreezeMin = 12 << 10
	FreezeMax = 36 << 10
)

// Rate throttling thresholds.
const (
	RateRatio   = 0.25   // below 25% of the domestic baseline
	RateMaxKbps = 1000.0 // and below 1 Mbit/s
	RateMinBody = 48 << 10
)

func ev(key string, kv ...string) model.Evidence {
	e := model.Evidence{Key: key}
	if len(kv) > 1 {
		e.Args = map[string]string{}
		for i := 0; i+1 < len(kv); i += 2 {
			e.Args[kv[i]] = kv[i+1]
		}
	}
	return e
}

func runs(agree, total int) model.Evidence {
	return ev("ev.runs", "agree", strconv.Itoa(agree), "runs", strconv.Itoa(total))
}

// confFromRuns returns High for unanimous results and lowers it otherwise.
func confFromRuns(base model.Confidence, agree, total int) model.Confidence {
	if total > 1 && agree < total {
		return base.Lower()
	}
	return base
}

// Endpoint classifies one endpoint and fills ep.Verdict / ep.Secondary.
func Endpoint(ep *model.EndpointResult, c Context) {
	v, secondary := endpoint(ep, c)
	ep.Verdict = v
	ep.Secondary = dedupKinds(secondary, v.Kind)
}

func endpoint(ep *model.EndpointResult, c Context) (model.Verdict, []model.Kind) {
	var secondary []model.Kind
	protocol := protocolVerdicts(ep)
	for _, p := range protocol {
		secondary = append(secondary, p.Kind)
	}

	real := ep.TLSVariant(model.VariantReal)
	main := real
	if main == nil {
		main = ep.TCP
	}
	if main != nil && main.Stage == "connect" && main.Outcome != model.OK {
		// QUIC failures add nothing when the address is unreachable anyway.
		secondary = nil
	}

	if !c.Connectivity && (main == nil || !main.Succeeded()) && !quicAllOK(ep) {
		return model.Verdict{Kind: model.KindNoConnectivity, Confidence: model.High,
			Evidence: []model.Evidence{ev("ev.no_connectivity")}}, nil
	}

	// Protocol-only endpoints (QUIC/ECH tests without a TCP handshake).
	if main == nil {
		if v, ok := dnsVerdict(ep); ok {
			return v, secondary
		}
		if len(protocol) > 0 {
			var rest []model.Kind
			for _, p := range protocol[1:] {
				rest = append(rest, p.Kind)
			}
			return protocol[0], rest
		}
		if quicAllOK(ep) {
			return model.Verdict{Kind: model.KindOK, Confidence: model.High}, nil
		}
		return model.Verdict{Kind: model.KindUnknown, Confidence: model.Low,
			Evidence: []model.Evidence{ev("ev.dns.unresolvable")}}, nil
	}

	// TLS interception.
	if real.Succeeded() && real.Cert != nil {
		if v, ok := mitmVerdict(ep, real); ok {
			return v, secondary
		}
	}

	// Block pages.
	for _, h := range []*model.HTTPResult{ep.HTTP80, ep.HTTP} {
		if h != nil && h.Blockpage != "" {
			return model.Verdict{Kind: model.KindBlockpage, Subtype: h.Blockpage, Confidence: model.High,
				Evidence: []model.Evidence{ev("ev.http.blockpage", "fp", h.Blockpage)}}, secondary
		}
	}

	// DNS tampering takes precedence: it is the first layer that fails.
	if v, ok := dnsVerdict(ep); ok {
		if !main.Succeeded() {
			if k, _ := transportKind(ep, main); k != model.KindOK && k != model.KindUnknown {
				secondary = append(secondary, k)
				v.Evidence = append(v.Evidence, ev("ev.dns.also_blocked_ip", "kind", string(k)))
			}
		} else if ep.IPSource == "reference" {
			v.Evidence = append(v.Evidence, ev("ev.dns.reference_reachable"))
		}
		return v, secondary
	}

	if !main.Succeeded() {
		_, v := transportKind(ep, main)
		if main.Stage == "connect" && ep.RefTLS.Succeeded() {
			v.Evidence = append(v.Evidence, ev("ev.connect.ref_ok"))
		}
		return v, secondary
	}

	// The handshake works; look at the HTTP exchange.
	notes := certNotes(ep, real)
	if v, ok := httpVerdict(ep.HTTP, c); ok {
		v.Evidence = append(v.Evidence, notes...)
		return v, secondary
	}
	return model.Verdict{Kind: model.KindOK, Confidence: confFromRuns(model.High, main.Agree, main.Runs), Evidence: notes}, secondary
}

// transportKind classifies a failed connect or handshake.
func transportKind(ep *model.EndpointResult, main *model.TLSResult) (model.Kind, model.Verdict) {
	addr := ep.IP + ":" + strconv.Itoa(ep.Port)
	if main.Stage == "connect" {
		var sub string
		base := model.High
		switch main.Outcome {
		case model.Timeout:
			sub = "drop"
		case model.Refused, model.Reset:
			sub = "reject"
			base = model.Medium
		case model.Unreachable:
			sub = "unreachable"
			base = model.Medium
		default:
			sub = string(main.Outcome)
			base = model.Low
		}
		return model.KindIPBlock, model.Verdict{Kind: model.KindIPBlock, Subtype: sub,
			Confidence: confFromRuns(base, main.Agree, main.Runs),
			Evidence: []model.Evidence{
				ev("ev.connect.failed", "addr", addr, "outcome", string(main.Outcome)),
				runs(main.Agree, main.Runs),
			}}
	}

	// Handshake failed.
	if main.Outcome == model.TLSAlert {
		return model.KindUnknown, model.Verdict{Kind: model.KindUnknown, Confidence: model.Low,
			Evidence: []model.Evidence{ev("ev.tls.alert")}}
	}
	none := ep.TLSVariant(model.VariantNone)
	random := ep.TLSVariant(model.VariantRandom)
	var passed []string
	for _, v := range []*model.TLSResult{none, random} {
		if v != nil && v.Outcome.ServerAnswered() {
			passed = append(passed, v.Variant)
		}
	}
	evidence := []model.Evidence{
		ev("ev.tls.real_failed", "outcome", string(main.Outcome)),
		runs(main.Agree, main.Runs),
	}
	if len(passed) > 0 {
		for _, p := range passed {
			evidence = append(evidence, ev("ev.tls.variant_ok", "variant", p))
		}
		sub := "reset"
		switch main.Outcome {
		case model.Timeout:
			sub = "drop"
		case model.EOF:
			sub = "eof"
		}
		return model.KindSNIDPI, model.Verdict{Kind: model.KindSNIDPI, Subtype: sub,
			Confidence: confFromRuns(model.High, main.Agree, main.Runs), Evidence: evidence}
	}
	tested := none != nil || random != nil
	allReset := main.Outcome == model.Reset && (!tested || variantsAre(model.Reset, none, random))
	if allReset {
		if tested {
			evidence = append(evidence, ev("ev.tls.all_variants_failed", "outcome", "reset"))
		}
		return model.KindTLSReset, model.Verdict{Kind: model.KindTLSReset, Subtype: "reset",
			Confidence: confFromRuns(model.Medium, main.Agree, main.Runs), Evidence: evidence}
	}
	if main.Outcome == model.EOF {
		return model.KindTLSReset, model.Verdict{Kind: model.KindTLSReset, Subtype: "eof",
			Confidence: model.Low, Evidence: evidence}
	}
	if tested {
		evidence = append(evidence, ev("ev.tls.all_variants_failed", "outcome", string(main.Outcome)))
	}
	return model.KindTimeout, model.Verdict{Kind: model.KindTimeout, Subtype: "handshake",
		Confidence: model.Low, Evidence: evidence}
}

func variantsAre(o model.Outcome, vs ...*model.TLSResult) bool {
	for _, v := range vs {
		if v != nil && v.Outcome != o {
			return false
		}
	}
	return true
}

// mitmVerdict reports TLS interception. Only a certificate from the Russian
// state CA on a foreign site counts: services with their own private PKI
// (e.g. Signal) legitimately present certificates browsers do not trust, so an
// untrusted issuer alone is recorded as evidence, never as a verdict.
func mitmVerdict(ep *model.EndpointResult, real *model.TLSResult) (model.Verdict, bool) {
	cert := real.Cert
	if cert.RussianTrustedCA && !isDomesticTLD(ep.Name) {
		return model.Verdict{Kind: model.KindTLSMITM, Subtype: "state_ca", Confidence: model.High,
			Evidence: []model.Evidence{ev("ev.cert.russian_ca", "issuer", cert.Issuer)}}, true
	}
	return model.Verdict{}, false
}

// certNotes explains unusual but non-conclusive certificates.
func certNotes(ep *model.EndpointResult, real *model.TLSResult) []model.Evidence {
	if real == nil || real.Cert == nil || real.Cert.TrustedSystem {
		return nil
	}
	cert := real.Cert
	if cert.RussianTrustedCA && isDomesticTLD(ep.Name) {
		return []model.Evidence{ev("ev.cert.domestic_ca", "issuer", cert.Issuer)}
	}
	if cert.ValidForHost {
		return []model.Evidence{ev("ev.cert.untrusted", "issuer", cert.Issuer)}
	}
	return []model.Evidence{ev("ev.cert.wrong_host", "subject", cert.Subject, "issuer", cert.Issuer)}
}

func isDomesticTLD(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	return strings.HasSuffix(h, ".ru") || strings.HasSuffix(h, ".su") || strings.HasSuffix(h, ".xn--p1ai") || strings.HasSuffix(h, ".рф")
}

// dnsVerdict detects DNS tampering by comparing the system answer with the
// reference (DoH) answer.
func dnsVerdict(ep *model.EndpointResult) (model.Verdict, bool) {
	d := ep.DNS
	if d == nil {
		return model.Verdict{}, false
	}
	sys := d.System
	ref := d.Reference
	refOK := ref != nil && ref.Outcome == model.OK && !ref.Bogon && ref.Stub == ""
	base := []model.Evidence{}
	add := func(e ...model.Evidence) { base = append(base, e...) }
	refEv := func() {
		if refOK {
			add(ev("ev.dns.reference_ok", "resolver", ref.Resolver, "addrs", strings.Join(first(ref.Addrs, 3), ", ")))
		}
	}
	nsdiNX := d.NSDI != nil && d.NSDI.Outcome == model.NXDomain
	switch {
	case sys.Stub != "":
		add(ev("ev.dns.stub", "fp", sys.Stub, "addrs", strings.Join(first(sys.Addrs, 3), ", ")))
		refEv()
		return model.Verdict{Kind: model.KindDNS, Subtype: "stub", Confidence: model.High, Evidence: base}, true
	case sys.Outcome == model.NXDomain && refOK:
		add(ev("ev.dns.nxdomain"))
		refEv()
		sub := "nxdomain"
		if nsdiNX {
			sub = "nsdi_removed"
			add(ev("ev.dns.nsdi_nx"))
		}
		return model.Verdict{Kind: model.KindDNS, Subtype: sub, Confidence: confFromRuns(model.High, sys.Agree, sys.Runs), Evidence: base}, true
	case sys.Outcome == model.OK && sys.Bogon && refOK:
		add(ev("ev.dns.bogon", "addrs", strings.Join(first(sys.Addrs, 3), ", ")))
		refEv()
		return model.Verdict{Kind: model.KindDNS, Subtype: "bogon", Confidence: model.High, Evidence: base}, true
	case (sys.Outcome == model.ServFail || sys.Outcome == model.NoAnswer || sys.Outcome == model.Timeout) && refOK:
		add(ev("ev.dns.failure", "outcome", string(sys.Outcome)))
		refEv()
		return model.Verdict{Kind: model.KindDNS, Subtype: "failure", Confidence: confFromRuns(model.Medium, sys.Agree, sys.Runs), Evidence: base}, true
	case sys.Outcome == model.OK && refOK && !overlap(sys.Addrs, ref.Addrs):
		// Different addresses are normal for CDNs. Only call it tampering when
		// the system address fails TLS validation and the reference one passes.
		// A failing connection to the system address is not proof of
		// substitution (it may be an IP block of one CDN node), so a server
		// that answers with someone else's certificate is required.
		real := ep.TLSVariant(model.VariantReal)
		wrongServer := real.Succeeded() && real.Cert != nil && !real.Cert.ValidForHost
		refGood := ep.RefTLS.Succeeded() && ep.RefTLS.Cert != nil && ep.RefTLS.Cert.ValidForHost
		if wrongServer && refGood {
			add(ev("ev.dns.substituted", "addrs", strings.Join(first(sys.Addrs, 3), ", ")))
			refEv()
			return model.Verdict{Kind: model.KindDNS, Subtype: "substituted", Confidence: model.High, Evidence: base}, true
		}
	}
	return model.Verdict{}, false
}

// httpVerdict inspects the HTTP exchange after a successful handshake.
func httpVerdict(h *model.HTTPResult, c Context) (model.Verdict, bool) {
	if h == nil {
		return model.Verdict{}, false
	}
	if v, ok := throttleVerdict(h, c); ok {
		return v, true
	}
	if h.Outcome == model.Reset || (h.Outcome == model.EOF && h.RawBytes > 0 && !h.Complete) {
		return model.Verdict{Kind: model.KindTLSReset, Subtype: "midstream", Confidence: confFromRuns(model.Medium, h.Agree, h.Runs),
			Evidence: []model.Evidence{ev("ev.http.midstream", "bytes", strconv.FormatInt(h.RawBytes, 10)), runs(h.Agree, h.Runs)}}, true
	}
	if h.Outcome == model.Timeout && h.RawBytes == 0 {
		return model.Verdict{Kind: model.KindTimeout, Subtype: "http", Confidence: model.Low,
			Evidence: []model.Evidence{ev("ev.http.no_response"), runs(h.Agree, h.Runs)}}, true
	}
	return model.Verdict{}, false
}

// throttleVerdict detects the 16–20 KB freeze and rate limiting.
func throttleVerdict(h *model.HTTPResult, c Context) (model.Verdict, bool) {
	if h == nil {
		return model.Verdict{}, false
	}
	stallMajority := h.StallRuns*2 > h.Runs || (h.Runs <= 1 && h.Stalled)
	if stallMajority {
		bytes := h.BytesBeforeStall
		e := []model.Evidence{
			ev("ev.http.freeze", "bytes", kb(bytes)),
			ev("ev.runs", "agree", strconv.Itoa(h.StallRuns), "runs", strconv.Itoa(max(h.Runs, 1))),
		}
		if bytes >= FreezeMin && bytes <= FreezeMax {
			return model.Verdict{Kind: model.KindThrottleFreeze, Subtype: "16-20kb",
				Confidence: confFromRuns(model.High, h.StallRuns, max(h.Runs, 1)), Evidence: e}, true
		}
		return model.Verdict{Kind: model.KindThrottleFreeze, Subtype: "stall",
			Confidence: model.Medium, Evidence: e}, true
	}
	if c.BaselineKbps > 0 && h.Outcome == model.OK && h.Bytes >= RateMinBody && h.ThroughputKbps > 0 &&
		h.ThroughputKbps < RateRatio*c.BaselineKbps && h.ThroughputKbps < RateMaxKbps {
		return model.Verdict{Kind: model.KindThrottleRate, Confidence: model.Medium,
			Evidence: []model.Evidence{ev("ev.http.rate",
				"kbps", fmt.Sprintf("%.0f", h.ThroughputKbps),
				"baseline", fmt.Sprintf("%.0f", c.BaselineKbps))}}, true
	}
	return model.Verdict{}, false
}

// protocolVerdicts returns verdicts for QUIC and ECH problems of an endpoint.
func protocolVerdicts(ep *model.EndpointResult) []model.Verdict {
	var out []model.Verdict
	tcpOK := false
	if r := ep.TLSVariant(model.VariantReal); r.Succeeded() {
		tcpOK = true
	}
	byVersion := map[int]map[string]*model.QUICResult{}
	for _, q := range ep.QUIC {
		if byVersion[q.Version] == nil {
			byVersion[q.Version] = map[string]*model.QUICResult{}
		}
		byVersion[q.Version][q.Variant] = q
	}
	versions := make([]int, 0, len(byVersion))
	for v := range byVersion {
		versions = append(versions, v)
	}
	sort.Ints(versions)
	var v1Blocked bool
	for _, ver := range versions {
		m := byVersion[ver]
		real, random := m[model.VariantReal], m[model.VariantRandom]
		if real == nil || real.Outcome.ServerAnswered() {
			continue
		}
		vs := strconv.Itoa(ver)
		if real.Outcome == model.Timeout && random != nil && random.Outcome.ServerAnswered() {
			out = append(out, model.Verdict{Kind: model.KindQUICSNI, Subtype: "v" + vs,
				Confidence: confFromRuns(model.High, real.Agree, real.Runs),
				Evidence:   []model.Evidence{ev("ev.quic.real_timeout", "version", vs), ev("ev.quic.random_ok", "version", vs)}})
			v1Blocked = v1Blocked || ver == 1
			continue
		}
		if real.Outcome == model.Timeout && (random == nil || random.Outcome == model.Timeout) {
			conf := model.Low
			if tcpOK {
				conf = model.Medium
			}
			out = append(out, model.Verdict{Kind: model.KindQUICBlocked, Subtype: "v" + vs, Confidence: conf,
				Evidence: []model.Evidence{ev("ev.quic.all_timeout", "version", vs)}})
			v1Blocked = v1Blocked || ver == 1
		}
	}
	if v1Blocked {
		if m := byVersion[2]; m != nil && m[model.VariantReal] != nil && m[model.VariantReal].Outcome.ServerAnswered() {
			out[0].Evidence = append(out[0].Evidence, ev("ev.quic.v2_ok"))
		}
	}
	if ep.ECH != nil && ep.ECH.Outcome.Interfered() && tcpOK {
		out = append(out, model.Verdict{Kind: model.KindECHBlocked, Confidence: confFromRuns(model.High, ep.ECH.Agree, ep.ECH.Runs),
			Evidence: []model.Evidence{ev("ev.ech.failed", "outcome", string(ep.ECH.Outcome))}})
	}
	return out
}

func quicAllOK(ep *model.EndpointResult) bool {
	if len(ep.QUIC) == 0 && ep.ECH == nil {
		return false
	}
	for _, q := range ep.QUIC {
		if q.Variant == model.VariantReal && !q.Outcome.ServerAnswered() {
			return false
		}
	}
	return ep.ECH == nil || ep.ECH.Outcome == model.OK
}

func overlap(a, b []string) bool {
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	for _, y := range b {
		if set[y] {
			return true
		}
	}
	return false
}

func first(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func kb(b int64) string {
	return strconv.FormatFloat(float64(b)/1024, 'f', 1, 64)
}

func dedupKinds(ks []model.Kind, exclude model.Kind) []model.Kind {
	seen := map[model.Kind]bool{exclude: true, model.KindOK: true, model.KindUnknown: true}
	var out []model.Kind
	for _, k := range ks {
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}
