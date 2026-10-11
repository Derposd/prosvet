package engine

import (
	"sort"

	"github.com/ordinarysim/prosvet/internal/model"
)

// pick returns the winning key: OK when it is the majority, otherwise the most
// frequent non-OK key (first occurrence wins ties). Interference must be seen
// in most attempts before it is reported.
func pick(keys []string, okKey string) (string, int) {
	counts := map[string]int{}
	order := []string{}
	for _, k := range keys {
		if counts[k] == 0 {
			order = append(order, k)
		}
		counts[k]++
	}
	if counts[okKey]*2 > len(keys) {
		return okKey, counts[okKey]
	}
	best, bestN := "", 0
	for _, k := range order {
		if k == okKey {
			continue
		}
		if counts[k] > bestN {
			best, bestN = k, counts[k]
		}
	}
	if bestN == 0 || counts[okKey] > bestN {
		return okKey, counts[okKey]
	}
	return best, bestN
}

func voteTLS(rs []*model.TLSResult) *model.TLSResult {
	if len(rs) == 0 {
		return nil
	}
	keys := make([]string, len(rs))
	for i, r := range rs {
		keys[i] = r.Key()
	}
	win, n := pick(keys, "handshake:ok")
	if rs[0].Stage == "connect" && rs[0].Variant == "tcp" {
		win, n = pick(keys, "connect:ok")
	}
	for _, r := range rs {
		if r.Key() == win {
			out := *r
			out.Agree, out.Runs = n, len(rs)
			return &out
		}
	}
	return rs[0]
}

func voteHTTP(rs []*model.HTTPResult) *model.HTTPResult {
	if len(rs) == 0 {
		return nil
	}
	keys := make([]string, len(rs))
	stalls := 0
	var stallBytes []int64
	var rates []float64
	for i, r := range rs {
		keys[i] = string(r.Outcome)
		if r.Stalled {
			stalls++
			stallBytes = append(stallBytes, r.BytesBeforeStall)
		}
		if r.Outcome == model.OK && r.ThroughputKbps > 0 {
			rates = append(rates, r.ThroughputKbps)
		}
	}
	win, n := pick(keys, string(model.OK))
	var out model.HTTPResult
	for _, r := range rs {
		if string(r.Outcome) == win {
			out = *r
			break
		}
	}
	out.Agree, out.Runs, out.StallRuns = n, len(rs), stalls
	if len(stallBytes) > 0 {
		out.BytesBeforeStall = medianInt(stallBytes)
	}
	if len(rates) > 0 {
		out.ThroughputKbps = medianFloat(rates)
	}
	return &out
}

func voteQUIC(rs []*model.QUICResult) *model.QUICResult {
	if len(rs) == 0 {
		return nil
	}
	keys := make([]string, len(rs))
	for i, r := range rs {
		// Any server answer counts as "reachable" for voting purposes.
		if r.Outcome.ServerAnswered() {
			keys[i] = "answered"
		} else {
			keys[i] = string(r.Outcome)
		}
	}
	win, n := pick(keys, "answered")
	for i, r := range rs {
		if keys[i] == win {
			out := *r
			out.Agree, out.Runs = n, len(rs)
			return &out
		}
	}
	return rs[0]
}

func voteDNS(rs []model.DNSAnswer) model.DNSAnswer {
	if len(rs) == 0 {
		return model.DNSAnswer{Outcome: model.Skipped}
	}
	keys := make([]string, len(rs))
	for i, r := range rs {
		keys[i] = string(r.Outcome)
	}
	win, n := pick(keys, string(model.OK))
	for _, r := range rs {
		if string(r.Outcome) == win {
			r.Agree, r.Runs = n, len(rs)
			return r
		}
	}
	return rs[0]
}

func medianInt(v []int64) int64 {
	s := append([]int64(nil), v...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
}

func medianFloat(v []float64) float64 {
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	return s[len(s)/2]
}
