package classify

import (
	"strconv"

	"github.com/Derposd/prosvet/internal/model"
)

// Target aggregates endpoint verdicts into a target status and verdict.
// Endpoints must already be classified with Endpoint.
func Target(t *model.TargetResult, c Context) {
	var (
		blocking, throttling, okCount, unreach, protoOnly int
		kinds                                             = map[model.Kind][]*model.EndpointResult{}
		secondary                                         []model.Kind
	)
	n := len(t.Endpoints)
	for i := range t.Endpoints {
		ep := &t.Endpoints[i]
		k := ep.Verdict.Kind
		kinds[k] = append(kinds[k], ep)
		secondary = append(secondary, ep.Secondary...)
		switch {
		case k == model.KindNoConnectivity:
			unreach++
		case k.IsBlocking():
			blocking++
		case k.IsThrottling():
			throttling++
		case k.IsProtocol():
			protoOnly++
		case k == model.KindOK:
			okCount++
		}
	}

	// Dedicated throttling measurement of the target.
	var throttleV *model.Verdict
	if t.Throttle != nil {
		if v, ok := throttleVerdict(t.Throttle, c); ok {
			throttleV = &v
		}
	}

	switch {
	case n > 0 && unreach == n:
		t.Status = model.StatusUnreachable
		t.Verdict = model.Verdict{Kind: model.KindNoConnectivity, Confidence: model.High,
			Evidence: []model.Evidence{ev("ev.no_connectivity")}}
	case blocking > 0:
		t.Verdict = primary(kinds, func(k model.Kind) bool { return k.IsBlocking() })
		if blocking+unreach == n {
			t.Status = model.StatusBlocked
		} else {
			t.Status = model.StatusPartial
		}
		if n > 1 {
			t.Verdict.Evidence = append(t.Verdict.Evidence, ev("ev.endpoints",
				"affected", strconv.Itoa(blocking), "total", strconv.Itoa(n)))
		}
		if throttleV != nil {
			secondary = append(secondary, throttleV.Kind)
		}
	case throttling > 0 || throttleV != nil:
		t.Status = model.StatusThrottled
		if throttleV != nil {
			t.Verdict = *throttleV
		} else {
			t.Verdict = primary(kinds, func(k model.Kind) bool { return k.IsThrottling() })
		}
	case protoOnly > 0 && okCount == 0:
		// Only protocol probes were run (e.g. the QUIC category) and they failed.
		t.Status = model.StatusBlocked
		t.Verdict = primary(kinds, func(k model.Kind) bool { return k.IsProtocol() })
	case okCount+protoOnly > 0:
		t.Status = model.StatusOK
		t.Verdict = model.Verdict{Kind: model.KindOK, Confidence: model.High}
		if protoOnly > 0 {
			for k := range kinds {
				if k.IsProtocol() {
					secondary = append(secondary, k)
				}
			}
		}
	default:
		t.Status = model.StatusUnknown
		t.Verdict = model.Verdict{Kind: model.KindUnknown, Confidence: model.Low}
	}
	t.Secondary = dedupKinds(secondary, t.Verdict.Kind)
}

// primary picks the most frequent kind among those accepted by keep
// (ties broken by display priority) and merges evidence/confidence.
func primary(kinds map[model.Kind][]*model.EndpointResult, keep func(model.Kind) bool) model.Verdict {
	var best model.Kind
	bestN := 0
	for _, k := range model.AllKinds {
		if !keep(k) {
			continue
		}
		if n := len(kinds[k]); n > bestN {
			best, bestN = k, n
		}
	}
	eps := kinds[best]
	if len(eps) == 0 {
		return model.Verdict{Kind: model.KindUnknown, Confidence: model.Low}
	}
	v := eps[0].Verdict
	conf := v.Confidence
	for _, e := range eps[1:] {
		if e.Verdict.Confidence.Rank() > conf.Rank() {
			conf = e.Verdict.Confidence
		}
	}
	if len(eps) >= 2 && conf == model.Medium {
		conf = model.High
	}
	out := model.Verdict{Kind: best, Subtype: v.Subtype, Confidence: conf}
	out.Evidence = append(out.Evidence, v.Evidence...)
	return out
}
