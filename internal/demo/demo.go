// Package demo runs Prosvet against a simulated censored network on
// localhost, so anyone can see every verdict type without touching the real
// network (used by `prosvet demo`, screenshots and the README GIF).
package demo

import (
	"github.com/ordinarysim/prosvet/internal/catalog"
	"github.com/ordinarysim/prosvet/internal/engine"
	"github.com/ordinarysim/prosvet/internal/model"
	"github.com/ordinarysim/prosvet/internal/probe"
	"github.com/ordinarysim/prosvet/internal/testnet"
)

// Network describes the fake provider shown in demo reports (ASN from the
// documentation range, RFC 5398).
var Network = model.NetworkInfo{ASN: 64500, ISP: "Demo Telecom", Country: "RU", Region: "RU-MOW", Conn: "fixed", Source: "manual"}

func h(name, ip string) testnet.Host { return testnet.Host{Name: name, IP: ip} }

func rule(name string, a testnet.Action) map[string]testnet.Action {
	return map[string]testnet.Action{name: a}
}

// hosts defines how the simulated censor treats each demo service.
func hosts() []testnet.Host {
	nx := &testnet.Record{NX: true}
	return []testnet.Host{
		{Name: "chat.messenger-a.demo", IP: "198.51.100.11", Rules: rule("chat.messenger-a.demo", testnet.Action{Kind: testnet.Reset})},
		{Name: "dc.messenger-a.demo", IP: "198.51.100.12", Block: "blackhole"},
		{Name: "messenger-b.demo", IP: "198.51.100.13", System: nx, NSDI: nx},
		{Name: "media.messenger-b.demo", IP: "198.51.100.14", System: nx, NSDI: nx, Rules: rule("media.messenger-b.demo", testnet.Action{Kind: testnet.Drop})},
		h("messenger-c.demo", "198.51.100.15"),
		h("video-a.demo", "198.51.100.21"),
		{Name: "cdn.video-a.demo", IP: "198.51.100.22", Rules: rule("cdn.video-a.demo", testnet.Action{Kind: testnet.Freeze, FreezeAfter: 16 << 10})},
		{Name: "video-b.demo", IP: "198.51.100.23", Rules: rule("video-b.demo", testnet.Action{Kind: testnet.Rate, RateBps: 40000})},
		{Name: "social-a.demo", IP: "198.51.100.31", TLS: testnet.Action{Kind: testnet.Reset}, HTTP80: "http://warning.rt.ru/?id=demo"},
		{Name: "social-b.demo", IP: "198.51.100.32", System: &testnet.Record{A: []string{"95.167.13.50"}}},
		{Name: "social-c.demo", IP: "198.51.100.33", Block: "refuse"},
		{Name: "secure-site.demo", IP: "198.51.100.41", Rogue: true},
		h("gov-portal.demo", "198.51.100.51"),
		h("bank.demo", "198.51.100.52"),
		h("search.demo", "198.51.100.53"),
		h("mirror.demo", "198.51.100.60"),
	}
}

func t(id, name, cat string, eps ...catalog.Endpoint) catalog.Target {
	return catalog.Target{ID: id, Name: name, Category: cat, Endpoints: eps}
}

func host(name string) catalog.Endpoint { return catalog.Endpoint{Host: name} }

// Catalog returns the demo target lists.
func Catalog() *catalog.Catalog {
	cat := func(id string, ru, en string, ts ...catalog.Target) *catalog.Category {
		for i := range ts {
			ts[i].Category = id
		}
		return &catalog.Category{Version: 1, ID: id, Default: true, Title: catalog.Text{"ru": ru, "en": en}, Targets: ts}
	}
	video := t("video-a", "Video A", "video", host("video-a.demo"))
	video.ThrottleURL = "https://cdn.video-a.demo/big"
	slow := t("video-b", "Video B", "video", host("video-b.demo"))
	slow.ThrottleURL = "https://video-b.demo/big"
	base := t("baseline", "Domestic mirror", "domestic", host("mirror.demo"))
	base.Role = "baseline"
	base.ThrottleURL = "https://mirror.demo/big"
	dns := testnet.DNSConfig()
	dns.ProbeDomains = []catalog.ProbeDomain{{Name: "messenger-b.demo"}, {Name: "social-b.demo"}, {Name: "gov-portal.demo", Role: "control"}}
	dns.Interceptions = []catalog.Interception{
		{ID: "cloudflare-whoami", Resolver: testnet.PublicDNS1, QName: "whoami.cloudflare", QClass: "CH", QType: "TXT", Expect: "nonempty"},
		{ID: "google-nsdi-leak", Resolver: testnet.PublicDNS8, QName: "messenger-b.demo", QType: "A", Expect: "noerror"},
	}
	return &catalog.Catalog{
		Categories: []*catalog.Category{
			cat("messengers", "Мессенджеры", "Messengers",
				t("messenger-a", "Messenger A", "", host("chat.messenger-a.demo"), catalog.Endpoint{Addr: "198.51.100.12:443", Note: "DC"}),
				t("messenger-b", "Messenger B", "", host("messenger-b.demo"), host("media.messenger-b.demo")),
				t("messenger-c", "Messenger C", "", host("messenger-c.demo")),
			),
			cat("video", "Видео", "Video", video, slow),
			cat("social", "Соцсети", "Social networks",
				t("social-a", "Social A", "", catalog.Endpoint{Host: "social-a.demo", HTTP80: true}),
				t("social-b", "Social B", "", host("social-b.demo")),
				t("social-c", "Social C", "", host("social-c.demo")),
				t("secure-site", "Secure site", "", host("secure-site.demo")),
			),
			cat("domestic", "Отечественные сервисы", "Domestic services",
				t("gov-portal", "Gov portal", "", host("gov-portal.demo")),
				t("bank", "Bank", "", host("bank.demo")),
				t("search", "Search", "", host("search.demo")),
				base,
			),
		},
		DNS: dns,
		Whitelist: &catalog.WhitelistConfig{
			Version: 1, Kind: "whitelist", ID: "whitelist",
			Domestic: []catalog.WhitelistHost{{Host: "gov-portal.demo", Org: "Gov"}, {Host: "bank.demo", Org: "Bank"}, {Host: "search.demo", Org: "Search"}},
			Foreign:  []catalog.WhitelistHost{{Host: "chat.messenger-a.demo", Org: "Messenger A"}, {Host: "social-a.demo", Org: "Social A"}, {Host: "social-c.demo", Org: "Social C"}},
		},
	}
}

// Env is a running demo network.
type Env struct {
	World   *testnet.World
	Engine  *engine.Engine
	Catalog *catalog.Catalog
}

// Start launches the simulated network and returns an engine wired to it.
func Start(version string) (*Env, error) {
	w, err := testnet.NewWorld(hosts())
	if err != nil {
		return nil, err
	}
	// The censor transparently redirects one public resolver to the NSDI.
	w.Dialer.Route(testnet.PublicDNS8+":53", w.NSDI.Addr)
	cat := Catalog()
	opt := engine.DefaultOptions()
	opt.Jitter = 0
	opt.QUIC = false
	opt.Concurrency = 16
	opt.ThrottleLimit = 96 << 10
	opt.Version = version
	opt.Demo = true
	tm := probe.Timeouts{DNS: 1e9, Connect: 1.2e9, Handshake: 1.5e9, FirstByte: 1.5e9, Stall: 1e9, QUIC: 1e9}
	return &Env{World: w, Engine: engine.New(w.Env(tm), cat, opt), Catalog: cat}, nil
}

// Close stops the simulated network.
func (e *Env) Close() { e.World.Close() }
