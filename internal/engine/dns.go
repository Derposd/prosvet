package engine

import (
	"context"
	"sync"

	"github.com/Derposd/prosvet/internal/classify"
	"github.com/Derposd/prosvet/internal/model"
	"github.com/Derposd/prosvet/internal/probe"
)

// DNSReport runs the resolver matrix and the interception probes.
func (e *Engine) DNSReport(ctx context.Context) *model.DNSReport {
	cfg := e.Catalog.DNS
	rep := &model.DNSReport{}
	var specs []probe.ResolverSpec
	for _, r := range cfg.Resolvers {
		specs = append(specs, probe.SpecsFor(r)...)
	}
	control := "example.com"
	for _, d := range cfg.ProbeDomains {
		if d.Role == "control" {
			control = d.Name
			break
		}
	}

	// Reachability of every transport.
	status := make([]model.ResolverStatus, len(specs))
	e.parallel(ctx, len(specs), func(i int) {
		s := specs[i]
		st := model.ResolverStatus{ID: s.ID, Name: s.Name, Transport: s.Transport, Endpoint: s.Endpoint()}
		a := e.Env.Resolve(ctx, s, control)
		st.Outcome, st.RTTMs, st.Error = a.Outcome, a.RTTMs, a.Error
		if a.Outcome == model.NXDomain || a.Outcome == model.NoAnswer {
			st.Outcome = model.OK // the transport works; the name is just absent
		}
		status[i] = st
	})
	rep.Resolvers = status

	// Answers for every probe domain through every working transport.
	rep.Domains = make([]model.DomainCheck, len(cfg.ProbeDomains))
	for i, d := range cfg.ProbeDomains {
		rep.Domains[i] = model.DomainCheck{Name: d.Name, Role: d.Role, Answers: make([]model.DNSAnswer, len(specs))}
	}
	type job struct{ d, s int }
	var jobs []job
	for di := range cfg.ProbeDomains {
		for si := range specs {
			jobs = append(jobs, job{di, si})
		}
	}
	e.parallel(ctx, len(jobs), func(i int) {
		j := jobs[i]
		s := specs[j.s]
		if status[j.s].Outcome != model.OK {
			rep.Domains[j.d].Answers[j.s] = model.DNSAnswer{Resolver: s.Label(), Outcome: model.Skipped}
			return
		}
		rep.Domains[j.d].Answers[j.s] = e.Env.Resolve(ctx, s, cfg.ProbeDomains[j.d].Name)
	})

	rep.Interception = make([]model.InterceptionCheck, len(cfg.Interceptions))
	e.parallel(ctx, len(cfg.Interceptions), func(i int) {
		rep.Interception[i] = e.Env.Intercept(ctx, cfg.Interceptions[i])
	})
	classify.DNSFindings(rep)
	return rep
}

// parallel runs fn(0..n-1) bounded by the engine's concurrency.
func (e *Engine) parallel(ctx context.Context, n int, fn func(i int)) {
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		if !e.acquire(ctx) {
			break
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer e.release()
			fn(i)
		}(i)
	}
	wg.Wait()
}
