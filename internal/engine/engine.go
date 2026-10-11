// Package engine orchestrates a scan: it selects targets, runs the probes for
// every endpoint (repeated, with majority voting), measures throttling,
// classifies the results and streams progress events.
package engine

import (
	"context"
	"math/rand/v2"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/ordinarysim/prosvet/internal/catalog"
	"github.com/ordinarysim/prosvet/internal/classify"
	"github.com/ordinarysim/prosvet/internal/model"
	"github.com/ordinarysim/prosvet/internal/probe"
)

// Options tune a scan.
type Options struct {
	Repeats       int
	Concurrency   int
	QUIC          bool
	DNSChecks     bool
	Precheck      bool
	Jitter        time.Duration
	EndpointBody  int64 // bytes read from each endpoint's page
	ThrottleLimit int64 // bytes read from throttle_url
	Version       string
	Commit        string
	Demo          bool
}

// DefaultOptions returns production defaults.
func DefaultOptions() Options {
	return Options{
		Repeats:       3,
		Concurrency:   12,
		QUIC:          true,
		DNSChecks:     true,
		Precheck:      true,
		Jitter:        250 * time.Millisecond,
		EndpointBody:  64 << 10,
		ThrottleLimit: probe.DefaultBodyLimit,
	}
}

// EventKind identifies progress events.
type EventKind int

// Event kinds.
const (
	EventStarted EventKind = iota
	EventPhase
	EventTarget
	EventFinished
)

// Phases reported through EventPhase.
const (
	PhasePrecheck = "precheck"
	PhaseBaseline = "baseline"
	PhaseTargets  = "targets"
	PhaseDNS      = "dns"
	PhaseWL       = "whitelist"
)

// Event is a progress notification.
type Event struct {
	Kind   EventKind
	Phase  string
	Done   int
	Total  int
	Target *model.TargetResult
	Report *model.Report
}

// Engine runs scans.
type Engine struct {
	Env     *probe.Env
	Catalog *catalog.Catalog
	Opt     Options

	refSpecs []probe.ResolverSpec
	nsdi     *probe.ResolverSpec
	sem      chan struct{}

	mu       sync.Mutex
	refCache map[string]model.DNSAnswer
}

// New prepares an engine.
func New(env *probe.Env, cat *catalog.Catalog, opt Options) *Engine {
	def := DefaultOptions()
	if opt.Repeats <= 0 {
		opt.Repeats = def.Repeats
	}
	if opt.Concurrency <= 0 {
		opt.Concurrency = def.Concurrency
	}
	if opt.EndpointBody <= 0 {
		opt.EndpointBody = def.EndpointBody
	}
	if opt.ThrottleLimit <= 0 {
		opt.ThrottleLimit = def.ThrottleLimit
	}
	e := &Engine{Env: env, Catalog: cat, Opt: opt, refCache: map[string]model.DNSAnswer{}}
	e.sem = make(chan struct{}, opt.Concurrency)
	if cat.DNS != nil {
		for _, id := range cat.DNS.ReferenceDoH {
			if r := cat.DNS.Resolver(id); r != nil {
				if s, ok := probe.DoHSpec(*r); ok {
					e.refSpecs = append(e.refSpecs, s)
				}
			}
		}
		if r := cat.DNS.Resolver("nsdi"); r != nil {
			for _, s := range probe.SpecsFor(*r) {
				if s.Transport == probe.TransportUDP {
					s := s
					e.nsdi = &s
				}
			}
		}
	}
	return e
}

func (e *Engine) acquire(ctx context.Context) bool {
	select {
	case e.sem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (e *Engine) release() { <-e.sem }

func (e *Engine) pause(ctx context.Context) {
	if e.Opt.Jitter <= 0 {
		return
	}
	d := e.Opt.Jitter/2 + time.Duration(rand.Int64N(int64(e.Opt.Jitter)))
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

func emit(events chan<- Event, ev Event) {
	if events != nil {
		events <- ev
	}
}

// NewReport creates an empty report with tool metadata filled in.
func (e *Engine) NewReport(netinfo model.NetworkInfo) *model.Report {
	return &model.Report{
		Schema:    model.ReportSchema,
		Tool:      model.ToolInfo{Name: "prosvet", Version: e.Opt.Version, Commit: e.Opt.Commit, OS: runtime.GOOS, Arch: runtime.GOARCH},
		StartedAt: time.Now().UTC(),
		Network:   netinfo,
	}
}

// Scan measures the selected targets. Events (optional) receive progress;
// the channel is not closed by Scan.
func (e *Engine) Scan(ctx context.Context, sel catalog.Selection, netinfo model.NetworkInfo, events chan<- Event) (*model.Report, error) {
	targets, _, err := e.Catalog.Select(sel)
	if err != nil {
		return nil, err
	}
	rep := e.NewReport(netinfo)
	rep.Options = model.ScanOptions{Repeats: e.Opt.Repeats, Categories: sel.Categories, Targets: sel.Targets, QUIC: e.Opt.QUIC, Demo: e.Opt.Demo}

	var baselines, rest []catalog.Target
	for _, t := range targets {
		if t.IsBaseline() {
			baselines = append(baselines, t)
		} else {
			rest = append(rest, t)
		}
	}
	total := len(targets)
	emit(events, Event{Kind: EventStarted, Total: total})

	cctx := classify.Context{Connectivity: true}
	if e.Opt.Precheck {
		emit(events, Event{Kind: EventPhase, Phase: PhasePrecheck, Total: total})
		cctx.Connectivity = e.precheck(ctx)
		if !cctx.Connectivity {
			rep.Connectivity = &model.Verdict{Kind: model.KindNoConnectivity, Confidence: model.High,
				Evidence: []model.Evidence{{Key: "ev.no_connectivity"}}}
		}
	}

	done := 0
	results := make([]model.TargetResult, 0, total)
	var mu sync.Mutex
	record := func(tr model.TargetResult) {
		mu.Lock()
		done++
		results = append(results, tr)
		d := done
		mu.Unlock()
		emit(events, Event{Kind: EventTarget, Done: d, Total: total, Target: &tr})
	}

	if len(baselines) > 0 {
		emit(events, Event{Kind: EventPhase, Phase: PhaseBaseline, Done: done, Total: total})
		var best float64
		var src string
		for _, t := range baselines {
			tr := e.measureTarget(ctx, t, cctx)
			if h := tr.Throttle; h != nil && h.Outcome == model.OK && h.Bytes >= classify.RateMinBody && h.ThroughputKbps > best {
				best, src = h.ThroughputKbps, t.ID
			}
			record(tr)
		}
		if best > 0 {
			rep.Baseline = &model.Baseline{Kbps: best, Source: src}
			cctx.BaselineKbps = best
		}
	}

	emit(events, Event{Kind: EventPhase, Phase: PhaseTargets, Done: done, Total: total})
	var wg sync.WaitGroup
	for _, t := range rest {
		wg.Add(1)
		go func(t catalog.Target) {
			defer wg.Done()
			record(e.measureTarget(ctx, t, cctx))
		}(t)
	}
	wg.Wait()

	if e.Opt.DNSChecks && e.Catalog.DNS != nil && e.wantDNS(sel) && ctx.Err() == nil {
		emit(events, Event{Kind: EventPhase, Phase: PhaseDNS, Done: done, Total: total})
		rep.DNS = e.DNSReport(ctx)
	}

	order := map[string]int{}
	for i, t := range targets {
		order[t.ID] = i
	}
	sort.SliceStable(results, func(i, j int) bool { return order[results[i].ID] < order[results[j].ID] })
	rep.Targets = results
	rep.FinishedAt = time.Now().UTC()
	rep.Recount()
	emit(events, Event{Kind: EventFinished, Done: done, Total: total, Report: rep})
	return rep, ctx.Err()
}

func (e *Engine) wantDNS(sel catalog.Selection) bool {
	if len(sel.Categories) == 0 && len(sel.Targets) == 0 {
		return e.Catalog.DNS.Default
	}
	for _, c := range sel.Categories {
		if c == e.Catalog.DNS.ID {
			return true
		}
	}
	return false
}

// precheck reports whether at least one control host is reachable.
func (e *Engine) precheck(ctx context.Context) bool {
	wl := e.Catalog.Whitelist
	if wl == nil {
		return true
	}
	var hosts []string
	for i, h := range wl.Domestic {
		if i >= 2 {
			break
		}
		hosts = append(hosts, h.Host)
	}
	for i, h := range wl.Foreign {
		if i >= 2 {
			break
		}
		hosts = append(hosts, h.Host)
	}
	if len(hosts) == 0 {
		return true
	}
	ok := make(chan bool, len(hosts))
	for _, h := range hosts {
		go func(h string) {
			ok <- e.reachable(ctx, h)
		}(h)
	}
	any := false
	for range hosts {
		if <-ok {
			any = true
		}
	}
	return any
}

// reachable resolves host and completes a TLS handshake (any certificate).
func (e *Engine) reachable(ctx context.Context, host string) bool {
	ans := e.Env.Resolve(ctx, probe.ResolverSpec{Transport: probe.TransportSystem}, host)
	ip := firstAddr(ans)
	if ip == "" {
		ref := e.reference(ctx, host)
		ip = firstAddr(ref)
	}
	if ip == "" {
		return false
	}
	r, _ := e.Env.TLS(ctx, ip, 443, probe.TLSOptions{Variant: model.VariantReal, Host: host})
	return r.Succeeded()
}

func firstAddr(a model.DNSAnswer) string {
	if a.Outcome == model.OK && len(a.Addrs) > 0 {
		return a.Addrs[0]
	}
	return ""
}

// reference returns the cached reference (DoH) answer for host.
func (e *Engine) reference(ctx context.Context, host string) model.DNSAnswer {
	e.mu.Lock()
	if a, ok := e.refCache[host]; ok {
		e.mu.Unlock()
		return a
	}
	e.mu.Unlock()
	var a model.DNSAnswer
	if len(e.refSpecs) == 0 {
		a = model.DNSAnswer{Resolver: "reference", Outcome: model.Skipped}
	} else {
		a = e.Env.ResolveFirst(ctx, e.refSpecs, host)
	}
	e.mu.Lock()
	e.refCache[host] = a
	e.mu.Unlock()
	return a
}
