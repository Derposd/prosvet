package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ordinarysim/prosvet/internal/i18n"
	"github.com/ordinarysim/prosvet/internal/model"
)

// View is a renderer-independent, localised projection of a report. All
// output formats (terminal, Markdown, HTML, TUI, dashboard) are built from it,
// so they always say the same thing.
type View struct {
	Lang        string
	Title       string
	Tagline     string
	Demo        bool
	DemoBanner  string
	Started     string
	Duration    string
	Network     NetworkView
	Summary     model.Summary
	SummaryText string
	Baseline    string
	Groups      []GroupView
	Problems    []TargetView
	DNS         *DNSView
	Whitelist   *WhitelistView
	Notices     []string
	Version     string
	Labels      Labels
}

// Labels are localised headings used by the renderers.
type Labels struct {
	Problems  string
	DNS       string
	DNSNone   string
	Network   string
	Endpoints string
	Evidence  string
	Secondary string
	Generated string
	Domestic  string
	Foreign   string
	Whitelist string
	Summary   string
}

// NetworkView describes the network in words.
type NetworkView struct {
	Line   string
	ISP    string
	ASN    string
	Region string
	Conn   string
}

// GroupView is one category.
type GroupView struct {
	ID      string
	Title   string
	Targets []TargetView
}

// TargetView is one target, ready to print.
type TargetView struct {
	ID         string
	Name       string
	Category   string
	Status     model.Status
	StatusText string
	Kind       model.Kind
	KindTitle  string
	Subtype    string
	Confidence string
	Explain    string
	Evidence   []string
	Secondary  []string
	Expect     string
	Endpoints  []EndpointView
}

// EndpointView is one endpoint line.
type EndpointView struct {
	Name      string
	Kind      model.Kind
	KindTitle string
	Subtype   string
	Detail    string
}

// DNSView summarises DNS findings.
type DNSView struct {
	Findings  []string
	Resolvers []ResolverView
}

// ResolverView is one resolver transport.
type ResolverView struct {
	Name      string
	Transport string
	Outcome   string
	OK        bool
}

// WhitelistView summarises the whitelist check.
type WhitelistView struct {
	Verdict  string
	Title    string
	Explain  string
	Counts   string
	Level    string
	Domestic []WLHostView
	Foreign  []WLHostView
}

// WLHostView is one whitelist host.
type WLHostView struct {
	Host  string
	Org   string
	OK    bool
	Stage string
}

// CategoryTitles maps category ids to localised titles.
type CategoryTitles map[string]string

// Build creates the view of rep in the bundle's language.
func Build(rep *model.Report, b *i18n.Bundle, titles CategoryTitles) *View {
	v := &View{
		Lang:       b.Lang,
		Title:      "Prosvet",
		Tagline:    b.T("app.tagline"),
		Demo:       rep.Options.Demo,
		DemoBanner: b.T("app.demo_banner"),
		Summary:    rep.Summary,
		Version:    rep.Tool.Version,
		Labels: Labels{
			Problems: b.T("report.problems"), DNS: b.T("dns.title"), DNSNone: b.T("dns.none"),
			Network: b.T("network.title"), Endpoints: b.T("report.endpoints"), Evidence: b.T("report.evidence"),
			Secondary: b.T("report.secondary"), Generated: b.T("report.generated"),
			Domestic: b.T("whitelist.domestic"), Foreign: b.T("whitelist.foreign"),
			Whitelist: b.T("whitelist.title"), Summary: b.T("report.summary"),
		},
	}
	if !rep.StartedAt.IsZero() {
		v.Started = rep.StartedAt.Local().Format("2006-01-02 15:04")
		if !rep.FinishedAt.IsZero() {
			v.Duration = rep.FinishedAt.Sub(rep.StartedAt).Round(1e9).String()
		}
	}
	v.SummaryText = b.T("cli.summary",
		"ok", fmt.Sprint(rep.Summary.OK), "throttled", fmt.Sprint(rep.Summary.Throttled),
		"partial", fmt.Sprint(rep.Summary.Partial), "blocked", fmt.Sprint(rep.Summary.Blocked))
	if rep.Baseline != nil {
		v.Baseline = b.T("cli.baseline", "kbps", fmt.Sprintf("%.0f", rep.Baseline.Kbps))
	}
	v.Network = buildNetwork(rep.Network, b)
	if rep.Network.VPNSuspected {
		v.Notices = append(v.Notices, b.T("network.vpn_warning", "reason", rep.Network.VPNReason))
	}
	if rep.Network.ProxyIgnored {
		v.Notices = append(v.Notices, b.T("network.proxy_ignored"))
	}
	if rep.Connectivity != nil {
		v.Notices = append(v.Notices, b.KindTitle(model.KindNoConnectivity)+": "+b.KindExplain(model.KindNoConnectivity))
	}

	index := map[string]int{}
	for _, t := range rep.Targets {
		if t.Role == "baseline" {
			continue
		}
		tv := buildTarget(t, b)
		gi, ok := index[t.Category]
		if !ok {
			title := titles[t.Category]
			if title == "" {
				title = t.Category
			}
			v.Groups = append(v.Groups, GroupView{ID: t.Category, Title: title})
			gi = len(v.Groups) - 1
			index[t.Category] = gi
		}
		v.Groups[gi].Targets = append(v.Groups[gi].Targets, tv)
		if t.Status != model.StatusOK {
			v.Problems = append(v.Problems, tv)
		}
	}
	sort.SliceStable(v.Problems, func(i, j int) bool {
		return statusRank(v.Problems[i].Status) > statusRank(v.Problems[j].Status)
	})
	if rep.DNS != nil {
		v.DNS = buildDNS(rep.DNS, b)
	}
	if rep.Whitelist != nil {
		v.Whitelist = BuildWhitelist(rep.Whitelist, b)
	}
	return v
}

func statusRank(s model.Status) int {
	switch s {
	case model.StatusBlocked:
		return 5
	case model.StatusPartial:
		return 4
	case model.StatusThrottled:
		return 3
	case model.StatusUnreachable:
		return 2
	case model.StatusUnknown:
		return 1
	}
	return 0
}

func buildNetwork(n model.NetworkInfo, b *i18n.Bundle) NetworkView {
	unknown := b.T("network.unknown")
	nv := NetworkView{ISP: n.ISP, Region: n.RegionName, Conn: b.T("conn." + n.Conn)}
	if nv.ISP == "" {
		nv.ISP = unknown
	}
	if n.ASN != 0 {
		nv.ASN = fmt.Sprintf("AS%d", n.ASN)
	}
	if nv.Region == "" {
		nv.Region = n.Region
	}
	if nv.Region == "" {
		nv.Region = unknown
	}
	parts := []string{nv.ISP}
	if nv.ASN != "" {
		parts[0] += " (" + nv.ASN + ")"
	}
	parts = append(parts, nv.Region, nv.Conn)
	nv.Line = strings.Join(parts, " · ")
	return nv
}

func buildTarget(t model.TargetResult, b *i18n.Bundle) TargetView {
	tv := TargetView{
		ID: t.ID, Name: t.Name, Category: t.Category,
		Status: t.Status, StatusText: b.Status(t.Status),
		Kind: t.Verdict.Kind, KindTitle: b.KindTitle(t.Verdict.Kind),
		Subtype:    b.Subtype(t.Verdict.Subtype),
		Confidence: b.Confidence(t.Verdict.Confidence),
		Explain:    b.KindExplain(t.Verdict.Kind),
	}
	for _, e := range t.Verdict.Evidence {
		tv.Evidence = append(tv.Evidence, b.Evidence(e))
	}
	for _, k := range t.Secondary {
		tv.Secondary = append(tv.Secondary, b.KindTitle(k))
	}
	if t.Expect != "" && t.Expect != "unknown" {
		tv.Expect = b.T("cli.expect", "expect", b.Status(model.Status(t.Expect)))
	}
	for _, ep := range t.Endpoints {
		ev := EndpointView{Name: ep.Name, Kind: ep.Verdict.Kind, KindTitle: b.KindTitle(ep.Verdict.Kind), Subtype: b.Subtype(ep.Verdict.Subtype)}
		if ep.Port != 0 && ep.Port != 443 {
			ev.Name = fmt.Sprintf("%s:%d", ep.Name, ep.Port)
		}
		if len(ep.Verdict.Evidence) > 0 {
			ev.Detail = b.Evidence(ep.Verdict.Evidence[0])
		}
		tv.Endpoints = append(tv.Endpoints, ev)
	}
	return tv
}

func buildDNS(d *model.DNSReport, b *i18n.Bundle) *DNSView {
	v := &DNSView{}
	for _, f := range d.Findings {
		v.Findings = append(v.Findings, b.T("dns.finding."+f.Kind,
			"resolvers", strings.Join(f.Resolvers, ", "), "domains", strings.Join(f.Domains, ", ")))
	}
	for _, r := range d.Resolvers {
		v.Resolvers = append(v.Resolvers, ResolverView{Name: r.Name, Transport: strings.ToUpper(r.Transport), Outcome: string(r.Outcome), OK: r.Outcome == model.OK})
	}
	return v
}

// BuildWhitelist renders a whitelist result.
func BuildWhitelist(w *model.WhitelistResult, b *i18n.Bundle) *WhitelistView {
	v := &WhitelistView{
		Verdict: w.Verdict,
		Title:   b.T("whitelist." + w.Verdict + ".title"),
		Explain: b.T("whitelist." + w.Verdict + ".explain"),
		Counts: b.T("whitelist.counts", "dok", fmt.Sprint(w.DomesticOK), "dtotal", fmt.Sprint(w.DomesticTotal),
			"fok", fmt.Sprint(w.ForeignOK), "ftotal", fmt.Sprint(w.ForeignTotal)),
	}
	if w.FailureLevel != "" {
		v.Level = b.T("whitelist.level." + w.FailureLevel)
	}
	conv := func(cs []model.WhitelistCheck) []WLHostView {
		var out []WLHostView
		for _, c := range cs {
			out = append(out, WLHostView{Host: c.Host, Org: c.Org, OK: c.Stage == "ok", Stage: c.Stage})
		}
		return out
	}
	v.Domestic, v.Foreign = conv(w.Domestic), conv(w.Foreign)
	return v
}
