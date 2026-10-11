package classify

import (
	"github.com/ordinarysim/prosvet/internal/model"
)

// WhitelistThresholds mirror whitelist.yaml.
type WhitelistThresholds struct {
	DomesticOK float64
	ForeignMax float64
	Dead       float64
	Normal     float64
}

// DefaultWhitelistThresholds are used when the YAML omits them.
func DefaultWhitelistThresholds() WhitelistThresholds {
	return WhitelistThresholds{DomesticOK: 0.7, ForeignMax: 0.15, Dead: 0.3, Normal: 0.7}
}

// Whitelist fills the verdict of a whitelist-mode check from its host results.
func Whitelist(r *model.WhitelistResult, th WhitelistThresholds) {
	def := DefaultWhitelistThresholds()
	if th.DomesticOK == 0 {
		th.DomesticOK = def.DomesticOK
	}
	if th.ForeignMax == 0 {
		th.ForeignMax = def.ForeignMax
	}
	if th.Dead == 0 {
		th.Dead = def.Dead
	}
	if th.Normal == 0 {
		th.Normal = def.Normal
	}
	r.DomesticOK, r.DomesticTotal = countOK(r.Domestic)
	r.ForeignOK, r.ForeignTotal = countOK(r.Foreign)
	rd := ratio(r.DomesticOK, r.DomesticTotal)
	rf := ratio(r.ForeignOK, r.ForeignTotal)

	switch {
	case rd < th.Dead && rf < th.Dead:
		r.Verdict = model.WhitelistNoConnectivity
		r.Confidence = model.High
		if rd > 0 || rf > 0 {
			r.Confidence = model.Medium
		}
	case rd >= th.DomesticOK && rf <= th.ForeignMax:
		r.Verdict = model.WhitelistActive
		r.Confidence = model.Medium
		if r.ForeignOK == 0 && r.ForeignTotal >= 6 {
			r.Confidence = model.High
		}
		r.FailureLevel = failureLevel(r.Foreign)
	case rd >= th.Normal && rf >= th.Normal:
		r.Verdict = model.WhitelistNormal
		r.Confidence = model.High
	default:
		r.Verdict = model.WhitelistDegraded
		r.Confidence = model.Medium
		r.FailureLevel = failureLevel(append(append([]model.WhitelistCheck{}, r.Foreign...), r.Domestic...))
	}
}

func countOK(cs []model.WhitelistCheck) (ok, total int) {
	for _, c := range cs {
		total++
		if c.Stage == "ok" {
			ok++
		}
	}
	return ok, total
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

// failureLevel reports at which stage failing hosts break (dns, connect, handshake or mixed).
func failureLevel(cs []model.WhitelistCheck) string {
	counts := map[string]int{}
	failed := 0
	for _, c := range cs {
		if c.Stage == "ok" {
			continue
		}
		failed++
		counts[c.Stage]++
	}
	if failed == 0 {
		return ""
	}
	for stage, n := range counts {
		if float64(n) >= 0.75*float64(failed) {
			return stage
		}
	}
	return "mixed"
}
