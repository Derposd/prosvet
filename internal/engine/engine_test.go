package engine

import (
	"context"
	"testing"
	"time"

	"github.com/Derposd/prosvet/internal/catalog"
	"github.com/Derposd/prosvet/internal/model"
	"github.com/Derposd/prosvet/internal/testnet"
)

// world builds the simulated censored network used by the integration tests.
func world(t *testing.T) *testnet.World {
	t.Helper()
	nx := &testnet.Record{NX: true}
	hosts := []testnet.Host{
		{Name: "ok.test", IP: "198.51.100.10"},
		{Name: "removed.test", IP: "198.51.100.11", System: nx, NSDI: nx},
		{Name: "stub.test", IP: "198.51.100.12", System: &testnet.Record{A: []string{"95.167.13.50"}}},
		{Name: "dropped.test", IP: "198.51.100.13", Block: "blackhole"},
		{Name: "refused.test", IP: "198.51.100.14", Block: "refuse"},
		{Name: "sni.test", IP: "198.51.100.15", Rules: map[string]testnet.Action{"$self": {Kind: testnet.Reset}}},
		{Name: "snidrop.test", IP: "198.51.100.16", Rules: map[string]testnet.Action{"$self": {Kind: testnet.Drop}}},
		{Name: "reset.test", IP: "198.51.100.17", TLS: testnet.Action{Kind: testnet.Reset}},
		{Name: "freeze.test", IP: "198.51.100.18", Rules: map[string]testnet.Action{"$self": {Kind: testnet.Freeze, FreezeAfter: 16 << 10}}},
		{Name: "slow.test", IP: "198.51.100.19", Rules: map[string]testnet.Action{"$self": {Kind: testnet.Rate, RateBps: 32000}}},
		{Name: "mitm.test", IP: "198.51.100.20", Rogue: true},
		{Name: "blockpage.test", IP: "198.51.100.21", TLS: testnet.Action{Kind: testnet.Reset}, HTTP80: "http://warning.rt.ru/?id=prosvet"},
		{Name: "baseline.test", IP: "198.51.100.30"},
		{Name: "dc.test", IP: "198.51.100.40", Block: "blackhole"},
	}
	w, err := testnet.NewWorld(hosts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	return w
}

func target(id string, eps ...catalog.Endpoint) catalog.Target {
	return catalog.Target{ID: id, Name: id, Category: "test", Endpoints: eps}
}

func host(h string) catalog.Endpoint { return catalog.Endpoint{Host: h} }

func testCatalog() *catalog.Catalog {
	cat := &catalog.Catalog{
		Categories: []*catalog.Category{{
			Version: 1, ID: "test", Default: true, Title: catalog.Text{"en": "Test"},
			Targets: []catalog.Target{
				target("ok", host("ok.test")),
				target("removed", host("removed.test")),
				target("stub", host("stub.test")),
				target("dropped", host("dropped.test")),
				target("refused", host("refused.test")),
				target("sni", host("sni.test")),
				target("snidrop", host("snidrop.test")),
				target("reset", host("reset.test")),
				{ID: "freeze", Name: "freeze", Category: "test", Endpoints: []catalog.Endpoint{host("freeze.test")}, ThrottleURL: "https://freeze.test/big"},
				{ID: "slow", Name: "slow", Category: "test", Endpoints: []catalog.Endpoint{host("slow.test")}, ThrottleURL: "https://slow.test/big"},
				target("mitm", host("mitm.test")),
				target("blockpage", catalog.Endpoint{Host: "blockpage.test", HTTP80: true}),
				target("partial", host("ok.test"), host("sni.test")),
				target("dc", catalog.Endpoint{Addr: "198.51.100.40:443"}),
				{ID: "baseline", Name: "baseline", Category: "test", Role: "baseline", Endpoints: []catalog.Endpoint{host("baseline.test")}, ThrottleURL: "https://baseline.test/big"},
			},
		}},
		DNS: testnet.DNSConfig(),
		Whitelist: &catalog.WhitelistConfig{
			Version: 1, Kind: "whitelist", ID: "whitelist",
			Domestic: []catalog.WhitelistHost{{Host: "ok.test"}, {Host: "baseline.test"}, {Host: "freeze.test"}},
			Foreign:  []catalog.WhitelistHost{{Host: "dropped.test"}, {Host: "reset.test"}, {Host: "snidrop.test"}},
		},
	}
	return cat
}

func testEngine(t *testing.T, w *testnet.World, cat *catalog.Catalog) *Engine {
	t.Helper()
	opt := DefaultOptions()
	opt.Jitter = 0
	opt.Concurrency = 24
	opt.QUIC = false
	opt.ThrottleLimit = 64 << 10
	opt.Version = "test"
	return New(w.Env(testnet.FastTimeouts()), cat, opt)
}

func TestScanClassifiesSimulatedCensorship(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	w := world(t)
	cat := testCatalog()
	e := testEngine(t, w, cat)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	events := make(chan Event, 256)
	var got []Event
	done := make(chan struct{})
	go func() {
		for ev := range events {
			got = append(got, ev)
		}
		close(done)
	}()
	rep, err := e.Scan(ctx, catalog.Selection{Categories: []string{"test"}}, model.NetworkInfo{Conn: "fixed"}, events)
	close(events)
	<-done
	if err != nil {
		t.Fatal(err)
	}
	if rep.Baseline == nil || rep.Baseline.Kbps <= 0 {
		t.Fatalf("baseline not measured: %+v", rep.Baseline)
	}

	want := map[string]struct {
		status  model.Status
		kind    model.Kind
		subtype string
	}{
		"ok":        {model.StatusOK, model.KindOK, ""},
		"removed":   {model.StatusBlocked, model.KindDNS, "nsdi_removed"},
		"stub":      {model.StatusBlocked, model.KindDNS, "stub"},
		"dropped":   {model.StatusBlocked, model.KindIPBlock, "drop"},
		"refused":   {model.StatusBlocked, model.KindIPBlock, "reject"},
		"sni":       {model.StatusBlocked, model.KindSNIDPI, "reset"},
		"snidrop":   {model.StatusBlocked, model.KindSNIDPI, "drop"},
		"reset":     {model.StatusBlocked, model.KindTLSReset, "reset"},
		"freeze":    {model.StatusThrottled, model.KindThrottleFreeze, "16-20kb"},
		"slow":      {model.StatusThrottled, model.KindThrottleRate, ""},
		"mitm":      {model.StatusBlocked, model.KindTLSMITM, "state_ca"},
		"blockpage": {model.StatusBlocked, model.KindBlockpage, "ru.rostelecom.warning"},
		"partial":   {model.StatusPartial, model.KindSNIDPI, "reset"},
		"dc":        {model.StatusBlocked, model.KindIPBlock, "drop"},
	}
	seen := map[string]bool{}
	for _, tr := range rep.Targets {
		seen[tr.ID] = true
		wt, ok := want[tr.ID]
		if !ok {
			continue
		}
		if tr.Status != wt.status || tr.Verdict.Kind != wt.kind || tr.Verdict.Subtype != wt.subtype {
			t.Errorf("%s: got %s/%s/%s, want %s/%s/%s\n  verdict: %+v\n  endpoints: %+v",
				tr.ID, tr.Status, tr.Verdict.Kind, tr.Verdict.Subtype, wt.status, wt.kind, wt.subtype, tr.Verdict, tr.Endpoints)
		}
	}
	for id := range want {
		if !seen[id] {
			t.Errorf("target %s missing from report", id)
		}
	}
	if rep.Summary.Total != len(want) {
		t.Errorf("summary total %d, want %d (baseline excluded)", rep.Summary.Total, len(want))
	}

	var started, finished, targets int
	for _, ev := range got {
		switch ev.Kind {
		case EventStarted:
			started++
		case EventFinished:
			finished++
		case EventTarget:
			targets++
		}
	}
	if started != 1 || finished != 1 || targets != len(want)+1 {
		t.Errorf("events: started=%d finished=%d targets=%d", started, finished, targets)
	}
}

func TestWhitelistActive(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	w := world(t)
	e := testEngine(t, w, testCatalog())
	res, err := e.Whitelist(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != model.WhitelistActive {
		t.Fatalf("verdict %s, domestic %d/%d foreign %d/%d: %+v", res.Verdict, res.DomesticOK, res.DomesticTotal, res.ForeignOK, res.ForeignTotal, res)
	}
	if res.FailureLevel != "handshake" && res.FailureLevel != "mixed" {
		t.Errorf("failure level %q", res.FailureLevel)
	}
}

func TestDNSReportDetectsInterception(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	w := world(t)
	// The censor transparently redirects queries for one public resolver to the NSDI.
	w.Dialer.Route(testnet.PublicDNS8+":53", w.NSDI.Addr)
	cat := testCatalog()
	cat.DNS.ProbeDomains = []catalog.ProbeDomain{{Name: "removed.test"}, {Name: "ok.test", Role: "control"}}
	cat.DNS.Interceptions = []catalog.Interception{
		{ID: "cf-whoami", Resolver: testnet.PublicDNS1, QName: "whoami.cloudflare", QClass: "CH", QType: "TXT", Expect: "nonempty"},
		{ID: "cf-colo", Resolver: testnet.PublicDNS1, QName: "id.server", QClass: "CH", QType: "TXT", Expect: "colo_code"},
		{ID: "g-leak", Resolver: testnet.PublicDNS8, QName: "removed.test", QType: "A", Expect: "noerror"},
	}
	e := testEngine(t, w, cat)
	rep := e.DNSReport(context.Background())
	byID := map[string]model.InterceptionCheck{}
	for _, ic := range rep.Interception {
		byID[ic.ID] = ic
	}
	if !byID["cf-whoami"].Passed || !byID["cf-colo"].Passed {
		t.Fatalf("clean resolver must pass: %+v", rep.Interception)
	}
	if byID["g-leak"].Passed {
		t.Fatal("intercepted resolver must fail")
	}
	var interception, tampering bool
	for _, f := range rep.Findings {
		interception = interception || f.Kind == "dns_interception"
		tampering = tampering || f.Kind == "system_resolver_tampering"
	}
	if !interception || !tampering {
		t.Fatalf("findings: %+v", rep.Findings)
	}
}
