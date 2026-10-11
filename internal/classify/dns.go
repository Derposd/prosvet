package classify

import (
	"sort"
	"strings"

	"github.com/Derposd/prosvet/internal/model"
)

// DNSFindings derives conclusions from the resolver matrix and interception probes.
func DNSFindings(r *model.DNSReport) {
	var out []model.DNSFinding

	// Interception: a probe that should reach Cloudflare/Google directly got a
	// wrong answer while the transport itself worked.
	var intercepted []string
	for _, ic := range r.Interception {
		if !ic.Passed && (ic.Outcome == model.OK || ic.Outcome == model.NXDomain) {
			intercepted = appendUnique(intercepted, ic.Resolver)
		}
	}
	if len(intercepted) > 0 {
		conf := model.Medium
		if countFailed(r.Interception) >= 2 {
			conf = model.High
		}
		out = append(out, model.DNSFinding{Kind: "dns_interception", Resolvers: intercepted, Confidence: conf})
	}

	// Blocked transports.
	blocked := map[string][]string{}
	for _, s := range r.Resolvers {
		if s.Transport == "system" || s.Outcome == model.OK {
			continue
		}
		if s.Outcome.Interfered() || s.Outcome == model.Refused || s.Outcome == model.TLSAlert {
			blocked[s.Transport] = appendUnique(blocked[s.Transport], s.ID)
		}
	}
	for _, tr := range []string{"doh", "dot", "udp"} {
		if ids := blocked[tr]; len(ids) > 0 {
			conf := model.Medium
			if len(ids) >= 2 {
				conf = model.High
			}
			out = append(out, model.DNSFinding{Kind: tr + "_blocked", Resolvers: ids, Confidence: conf})
		}
	}

	// Divergence between the system resolver and the reference answers.
	var divergent []string
	for _, d := range r.Domains {
		if d.Role == "control" {
			continue
		}
		// Address sets of CDNs legitimately differ, so only NXDOMAIN, stubs and
		// bogons count as tampering here.
		var sys *model.DNSAnswer
		refOK := false
		for i := range d.Answers {
			a := &d.Answers[i]
			switch {
			case a.Resolver == "system":
				sys = a
			case strings.HasPrefix(a.Resolver, "doh:") && a.Outcome == model.OK && !a.Bogon && a.Stub == "":
				refOK = true
			}
		}
		if sys != nil && refOK && (sys.Outcome == model.NXDomain || sys.Stub != "" || sys.Bogon) {
			divergent = append(divergent, d.Name)
		}
	}
	if len(divergent) > 0 {
		sort.Strings(divergent)
		out = append(out, model.DNSFinding{Kind: "system_resolver_tampering", Domains: divergent, Confidence: model.High})
	}
	r.Findings = out
}

func countFailed(ics []model.InterceptionCheck) int {
	n := 0
	for _, ic := range ics {
		if !ic.Passed && (ic.Outcome == model.OK || ic.Outcome == model.NXDomain) {
			n++
		}
	}
	return n
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
