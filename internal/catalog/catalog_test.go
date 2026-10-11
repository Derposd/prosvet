package catalog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ordinarysim/prosvet/targets"
)

func TestEmbeddedCatalogIsValid(t *testing.T) {
	c, err := Load(targets.FS)
	if err != nil {
		t.Fatalf("embedded catalog: %v", err)
	}
	if len(c.Categories) < 8 {
		t.Fatalf("expected at least 8 categories, got %d", len(c.Categories))
	}
	if c.DNS == nil || len(c.DNS.Resolvers) == 0 {
		t.Fatal("dns.yaml not loaded")
	}
	if c.Whitelist == nil || len(c.Whitelist.Domestic) == 0 || len(c.Whitelist.Foreign) == 0 {
		t.Fatal("whitelist.yaml not loaded")
	}
	if tg, _ := c.Target("telegram"); tg == nil || tg.Category != "messengers" {
		t.Fatal("telegram target missing or category not set")
	}
}

func TestMediaIsOptIn(t *testing.T) {
	c, err := Load(targets.FS)
	if err != nil {
		t.Fatal(err)
	}
	media := c.Category("media")
	if media == nil {
		t.Fatal("media category missing")
	}
	if media.Default {
		t.Fatal("media must be opt-in")
	}
	if media.Consent.Get("ru") == "" || media.Consent.Get("en") == "" {
		t.Fatal("media must carry a consent prompt in both languages")
	}
	sel, _, err := c.Select(Selection{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tg := range sel {
		if tg.Category == "media" {
			t.Fatalf("default selection must not include media target %s", tg.ID)
		}
	}
}

func TestSelect(t *testing.T) {
	c, err := Load(targets.FS)
	if err != nil {
		t.Fatal(err)
	}
	sel, cats, err := c.Select(Selection{Targets: []string{"telegram"}})
	if err != nil {
		t.Fatal(err)
	}
	var hasTelegram, hasBaseline bool
	for _, tg := range sel {
		hasTelegram = hasTelegram || tg.ID == "telegram"
		hasBaseline = hasBaseline || tg.IsBaseline()
	}
	if !hasTelegram || !hasBaseline {
		t.Fatalf("selection must contain telegram and baselines: %+v", sel)
	}
	if len(cats) == 0 {
		t.Fatal("categories of selection missing")
	}
	if _, _, err := c.Select(Selection{Targets: []string{"nope"}}); err == nil {
		t.Fatal("unknown target must fail")
	}
	all, _, _ := c.Select(Selection{All: true})
	def, _, _ := c.Select(Selection{})
	if len(all) <= len(def) {
		t.Fatal("--all must add opt-in targets")
	}
}

func TestEndpointDefaults(t *testing.T) {
	h := Endpoint{Host: "example.com", QUIC: true}
	if !h.Has(TestDNS) || !h.Has(TestTLS) || !h.Has(TestHTTP) || !h.Has(TestQUIC) {
		t.Fatalf("host defaults wrong: %v", h.EffectiveTests())
	}
	if h.EffectivePort() != 443 || h.EffectivePath() != "/" {
		t.Fatal("port/path defaults wrong")
	}
	a := Endpoint{Addr: "192.0.2.1:8443"}
	if a.Name() != "192.0.2.1" || a.EffectivePort() != 8443 || !a.Has(TestTCP) || a.Has(TestTLS) {
		t.Fatalf("addr defaults wrong: %v", a.EffectiveTests())
	}
}

func TestValidationErrors(t *testing.T) {
	bad := `version: 1
category: x
title: {en: X}
default: true
targets:
  - id: Bad_ID
    expect: maybe
    throttle_url: http://insecure.example
    endpoints:
      - { host: "not a host" }
      - { addr: "300.1.1.1:443" }
      - { addr: "192.0.2.1:443", tests: [http] }
      - { host: ok.example, tests: [teleport] }
`
	_, err := Load(fstest.MapFS{"x.yaml": {Data: []byte(bad)}})
	if err == nil {
		t.Fatal("expected validation errors")
	}
	for _, want := range []string{"invalid target id", "invalid expect", "throttle_url", "invalid host", "invalid addr", "needs a host", "unknown test"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	doc := "version: 1\ncategory: x\ntitle: {en: X}\ndefault: true\ntargtes: []\n"
	if _, err := Load(fstest.MapFS{"x.yaml": {Data: []byte(doc)}}); err == nil {
		t.Fatal("typo in field name must be rejected")
	}
}

func TestOverrides(t *testing.T) {
	dir := t.TempDir()
	doc := `version: 1
category: custom
title: {en: Custom, ru: Своё}
default: true
targets:
  - id: my-site
    name: My site
    endpoints:
      - { host: my.example.org }
`
	if err := os.WriteFile(filepath.Join(dir, "custom.yaml"), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadWithOverrides(targets.FS, dir)
	if err != nil {
		t.Fatal(err)
	}
	if tg, _ := c.Target("my-site"); tg == nil {
		t.Fatal("override file not loaded")
	}
	if tg, _ := c.Target("telegram"); tg == nil {
		t.Fatal("embedded files must still be present")
	}
}
