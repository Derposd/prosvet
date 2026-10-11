package engine

import (
	"context"
	"errors"

	"github.com/Derposd/prosvet/internal/catalog"
	"github.com/Derposd/prosvet/internal/classify"
	"github.com/Derposd/prosvet/internal/model"
	"github.com/Derposd/prosvet/internal/probe"
)

// ErrNoWhitelistConfig is returned when whitelist.yaml is missing.
var ErrNoWhitelistConfig = errors.New("whitelist.yaml is not loaded")

// Whitelist checks whether only domestic (allow-listed) services are reachable.
func (e *Engine) Whitelist(ctx context.Context, events chan<- Event) (*model.WhitelistResult, error) {
	wl := e.Catalog.Whitelist
	if wl == nil {
		return nil, ErrNoWhitelistConfig
	}
	res := &model.WhitelistResult{
		Domestic: make([]model.WhitelistCheck, len(wl.Domestic)),
		Foreign:  make([]model.WhitelistCheck, len(wl.Foreign)),
	}
	all := append(append([]catalog.WhitelistHost{}, wl.Domestic...), wl.Foreign...)
	total := len(all)
	emit(events, Event{Kind: EventStarted, Total: total})
	emit(events, Event{Kind: EventPhase, Phase: PhaseWL, Total: total})
	done := make(chan struct{}, total)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		n := 0
		for range done {
			n++
			emit(events, Event{Kind: EventPhase, Phase: PhaseWL, Done: n, Total: total})
		}
	}()
	defer func() { <-finished }()
	e.parallel(ctx, total, func(i int) {
		h := all[i]
		c := e.whitelistCheck(ctx, h)
		if i < len(wl.Domestic) {
			res.Domestic[i] = c
		} else {
			res.Foreign[i-len(wl.Domestic)] = c
		}
		done <- struct{}{}
	})
	close(done)
	th := classify.WhitelistThresholds{
		DomesticOK: wl.Thresholds.DomesticOK, ForeignMax: wl.Thresholds.ForeignMax,
		Dead: wl.Thresholds.Dead, Normal: wl.Thresholds.Normal,
	}
	classify.Whitelist(res, th)
	return res, ctx.Err()
}

// whitelistCheck tries up to two handshakes and reports the furthest stage reached.
func (e *Engine) whitelistCheck(ctx context.Context, h catalog.WhitelistHost) model.WhitelistCheck {
	c := model.WhitelistCheck{Host: h.Host, Org: h.Org}
	ans := e.Env.Resolve(ctx, probe.ResolverSpec{Transport: probe.TransportSystem}, h.Host)
	ip := firstAddr(ans)
	if ip == "" || ans.Stub != "" || ans.Bogon {
		c.Stage, c.Outcome = "dns", ans.Outcome
		if ans.Outcome == model.OK {
			c.Outcome = model.Error
		}
		return c
	}
	var last *model.TLSResult
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			e.pause(ctx)
		}
		r, _ := e.Env.TLS(ctx, ip, 443, probe.TLSOptions{Variant: model.VariantReal, Host: h.Host})
		last = r
		if r.Succeeded() {
			c.Stage, c.Outcome = "ok", model.OK
			if r.Cert != nil && r.Cert.RussianTrustedCA {
				c.CA = "russian-trusted"
			}
			return c
		}
	}
	c.Stage, c.Outcome = last.Stage, last.Outcome
	return c
}
