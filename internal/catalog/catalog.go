// Package catalog loads and validates the target lists (targets/*.yaml).
package catalog

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Text is a localised string map ({ru: ..., en: ...}).
type Text map[string]string

// Get returns the text for lang, falling back to English and then to any value.
func (t Text) Get(lang string) string {
	if s, ok := t[lang]; ok && s != "" {
		return s
	}
	if s, ok := t["en"]; ok && s != "" {
		return s
	}
	for _, s := range t {
		return s
	}
	return ""
}

// UnmarshalYAML accepts both a plain string and a {lang: text} map.
func (t *Text) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*t = Text{"en": n.Value}
		return nil
	}
	m := map[string]string{}
	if err := n.Decode(&m); err != nil {
		return err
	}
	*t = m
	return nil
}

// Endpoint is one host or address of a target.
type Endpoint struct {
	Host         string   `yaml:"host"`
	Addr         string   `yaml:"addr"`
	Port         int      `yaml:"port"`
	Path         string   `yaml:"path"`
	QUIC         bool     `yaml:"quic"`
	HTTP80       bool     `yaml:"http80"`
	Tests        []string `yaml:"tests"`
	QUICVersions []int    `yaml:"quic_versions"`
	Note         string   `yaml:"note"`
}

// Test names.
const (
	TestDNS      = "dns"
	TestTCP      = "tcp"
	TestTLS      = "tls"
	TestTLSNoSNI = "tls_nosni"
	TestHTTP     = "http"
	TestQUIC     = "quic"
	TestECH      = "ech"
)

var knownTests = map[string]bool{
	TestDNS: true, TestTCP: true, TestTLS: true, TestTLSNoSNI: true,
	TestHTTP: true, TestQUIC: true, TestECH: true,
}

// Name returns the host, or the IP for address endpoints.
func (e Endpoint) Name() string {
	if e.Host != "" {
		return e.Host
	}
	h, _, err := net.SplitHostPort(e.Addr)
	if err != nil {
		return e.Addr
	}
	return h
}

// EffectivePort returns the configured port (443 by default).
func (e Endpoint) EffectivePort() int {
	if e.Addr != "" {
		if _, p, err := net.SplitHostPort(e.Addr); err == nil {
			if n, err := strconv.Atoi(p); err == nil {
				return n
			}
		}
	}
	if e.Port != 0 {
		return e.Port
	}
	return 443
}

// EffectivePath returns the HTTP path ("/" by default).
func (e Endpoint) EffectivePath() string {
	if e.Path == "" {
		return "/"
	}
	return e.Path
}

// Has reports whether the endpoint runs the given test.
func (e Endpoint) Has(test string) bool {
	for _, t := range e.EffectiveTests() {
		if t == test {
			return true
		}
	}
	return false
}

// EffectiveTests returns the tests that run for this endpoint.
func (e Endpoint) EffectiveTests() []string {
	var tests []string
	if len(e.Tests) > 0 {
		tests = append(tests, e.Tests...)
	} else if e.Host != "" {
		tests = []string{TestDNS, TestTCP, TestTLS, TestHTTP}
	} else {
		tests = []string{TestTCP}
	}
	if e.QUIC && !contains(tests, TestQUIC) {
		tests = append(tests, TestQUIC)
	}
	return tests
}

// EffectiveQUICVersions returns the QUIC versions to probe ([1] by default).
func (e Endpoint) EffectiveQUICVersions() []int {
	if len(e.QUICVersions) == 0 {
		return []int{1}
	}
	return e.QUICVersions
}

// Target is one service.
type Target struct {
	ID          string     `yaml:"id"`
	Name        string     `yaml:"name"`
	Role        string     `yaml:"role"`
	Expect      string     `yaml:"expect"`
	Since       string     `yaml:"since"`
	Refs        []string   `yaml:"refs"`
	Notes       Text       `yaml:"notes"`
	ThrottleURL string     `yaml:"throttle_url"`
	Verified    *bool      `yaml:"verified"`
	Endpoints   []Endpoint `yaml:"endpoints"`

	// Category is filled in by the loader.
	Category string `yaml:"-"`
}

// IsBaseline reports whether the target is a domestic speed reference.
func (t Target) IsBaseline() bool { return t.Role == "baseline" }

// Category is one targets/*.yaml file with `targets:`.
type Category struct {
	Version int      `yaml:"version"`
	Kind    string   `yaml:"kind"`
	ID      string   `yaml:"category"`
	Title   Text     `yaml:"title"`
	Default bool     `yaml:"default"`
	Consent Text     `yaml:"consent"`
	Refs    []string `yaml:"refs"`
	Targets []Target `yaml:"targets"`

	File string `yaml:"-"`
}

// Resolver is a DNS resolver definition from dns.yaml.
type Resolver struct {
	ID   string   `yaml:"id"`
	Name Text     `yaml:"name"`
	Type string   `yaml:"type"`
	Role string   `yaml:"role"`
	Refs []string `yaml:"refs"`
	UDP  []string `yaml:"udp"`
	DoT  *struct {
		Host string `yaml:"host"`
		Addr string `yaml:"addr"`
	} `yaml:"dot"`
	DoH string `yaml:"doh"`
}

// ProbeDomain is a domain compared across resolvers.
type ProbeDomain struct {
	Name string `yaml:"name"`
	Role string `yaml:"role"`
	Note string `yaml:"note"`
}

// Interception is a transparent DNS proxy probe.
type Interception struct {
	ID       string `yaml:"id"`
	Resolver string `yaml:"resolver"`
	QName    string `yaml:"qname"`
	QClass   string `yaml:"qclass"`
	QType    string `yaml:"qtype"`
	Expect   string `yaml:"expect"`
}

// DNSConfig is dns.yaml.
type DNSConfig struct {
	Version       int            `yaml:"version"`
	Kind          string         `yaml:"kind"`
	ID            string         `yaml:"category"`
	Title         Text           `yaml:"title"`
	Default       bool           `yaml:"default"`
	Resolvers     []Resolver     `yaml:"resolvers"`
	ReferenceDoH  []string       `yaml:"doh_reference_order"`
	ProbeDomains  []ProbeDomain  `yaml:"probe_domains"`
	Interceptions []Interception `yaml:"interception"`
}

// Resolver returns the resolver with the given id.
func (d *DNSConfig) Resolver(id string) *Resolver {
	if d == nil {
		return nil
	}
	for i := range d.Resolvers {
		if d.Resolvers[i].ID == id {
			return &d.Resolvers[i]
		}
	}
	return nil
}

// WhitelistHost is one host of whitelist.yaml.
type WhitelistHost struct {
	Host string `yaml:"host"`
	Org  string `yaml:"org"`
	CA   string `yaml:"ca"`
}

// WhitelistConfig is whitelist.yaml.
type WhitelistConfig struct {
	Version    int      `yaml:"version"`
	Kind       string   `yaml:"kind"`
	ID         string   `yaml:"category"`
	Title      Text     `yaml:"title"`
	Default    bool     `yaml:"default"`
	Refs       []string `yaml:"refs"`
	Thresholds struct {
		DomesticOK float64 `yaml:"domestic_ok"`
		ForeignMax float64 `yaml:"foreign_max"`
		Dead       float64 `yaml:"dead"`
		Normal     float64 `yaml:"normal"`
	} `yaml:"thresholds"`
	Domestic []WhitelistHost `yaml:"domestic"`
	Foreign  []WhitelistHost `yaml:"foreign"`
}

// Catalog is the full set of loaded lists.
type Catalog struct {
	Categories []*Category
	DNS        *DNSConfig
	Whitelist  *WhitelistConfig
}

type header struct {
	Kind string `yaml:"kind"`
}

// Load reads every *.yaml from fsys (non-recursive).
func Load(fsys fs.FS) (*Catalog, error) {
	files, err := fs.Glob(fsys, "*.yaml")
	if err != nil {
		return nil, err
	}
	data := map[string][]byte{}
	for _, f := range files {
		b, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, err
		}
		data[f] = b
	}
	return parse(data)
}

// LoadWithOverrides loads the embedded lists and then the *.yaml files of dir;
// a file in dir replaces the embedded file of the same name.
func LoadWithOverrides(base fs.FS, dir string) (*Catalog, error) {
	if dir == "" {
		return Load(base)
	}
	data := map[string][]byte{}
	files, err := fs.Glob(base, "*.yaml")
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		b, err := fs.ReadFile(base, f)
		if err != nil {
			return nil, err
		}
		data[f] = b
	}
	over, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	if len(over) == 0 {
		return nil, fmt.Errorf("no *.yaml files in %s", dir)
	}
	for _, f := range over {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		data[filepath.Base(f)] = b
	}
	return parse(data)
}

func parse(data map[string][]byte) (*Catalog, error) {
	names := make([]string, 0, len(data))
	for n := range data {
		names = append(names, n)
	}
	sort.Strings(names)
	c := &Catalog{}
	for _, name := range names {
		b := data[name]
		var h header
		if err := yaml.Unmarshal(b, &h); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		switch h.Kind {
		case "", "targets":
			var cat Category
			if err := decodeStrict(b, &cat); err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			cat.File = name
			for i := range cat.Targets {
				cat.Targets[i].Category = cat.ID
			}
			c.Categories = append(c.Categories, &cat)
		case "resolvers":
			var d DNSConfig
			if err := decodeStrict(b, &d); err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			c.DNS = &d
		case "whitelist":
			var w WhitelistConfig
			if err := decodeStrict(b, &w); err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			c.Whitelist = &w
		default:
			return nil, fmt.Errorf("%s: unknown kind %q", name, h.Kind)
		}
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func decodeStrict(b []byte, v any) error {
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	return dec.Decode(v)
}

var (
	idRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	hostRe = regexp.MustCompile(`^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$`)
)

var validExpect = map[string]bool{"": true, "ok": true, "throttled": true, "partial": true, "blocked": true, "unknown": true}

// Validate checks ids, hosts, tests and references for consistency.
func (c *Catalog) Validate() error {
	var errs []error
	seenCat := map[string]bool{}
	seenTarget := map[string]string{}
	for _, cat := range c.Categories {
		if cat.Version != 1 {
			errs = append(errs, fmt.Errorf("%s: unsupported version %d", cat.File, cat.Version))
		}
		if !idRe.MatchString(cat.ID) {
			errs = append(errs, fmt.Errorf("%s: invalid category id %q", cat.File, cat.ID))
		}
		if seenCat[cat.ID] {
			errs = append(errs, fmt.Errorf("%s: duplicate category %q", cat.File, cat.ID))
		}
		seenCat[cat.ID] = true
		for _, t := range cat.Targets {
			where := cat.File + "/" + t.ID
			if !idRe.MatchString(t.ID) {
				errs = append(errs, fmt.Errorf("%s: invalid target id", where))
			}
			if prev, ok := seenTarget[t.ID]; ok {
				errs = append(errs, fmt.Errorf("%s: duplicate target id (also in %s)", where, prev))
			}
			seenTarget[t.ID] = cat.File
			if !validExpect[t.Expect] {
				errs = append(errs, fmt.Errorf("%s: invalid expect %q", where, t.Expect))
			}
			if t.Role != "" && t.Role != "baseline" && t.Role != "control" {
				errs = append(errs, fmt.Errorf("%s: invalid role %q", where, t.Role))
			}
			if t.ThrottleURL != "" {
				if u, err := url.Parse(t.ThrottleURL); err != nil || u.Scheme != "https" || u.Host == "" {
					errs = append(errs, fmt.Errorf("%s: throttle_url must be an https URL", where))
				}
			}
			if len(t.Endpoints) == 0 {
				errs = append(errs, fmt.Errorf("%s: no endpoints", where))
			}
			for _, e := range t.Endpoints {
				errs = append(errs, validateEndpoint(where, e)...)
			}
		}
	}
	if c.DNS != nil {
		for _, r := range c.DNS.Resolvers {
			for _, a := range r.UDP {
				if net.ParseIP(a) == nil {
					errs = append(errs, fmt.Errorf("dns/%s: invalid udp address %q", r.ID, a))
				}
			}
			if r.DoH != "" {
				if u, err := url.Parse(r.DoH); err != nil || u.Scheme != "https" {
					errs = append(errs, fmt.Errorf("dns/%s: doh must be an https URL", r.ID))
				}
			}
		}
		for _, id := range c.DNS.ReferenceDoH {
			if r := c.DNS.Resolver(id); r == nil || r.DoH == "" {
				errs = append(errs, fmt.Errorf("dns: doh_reference_order references %q without doh", id))
			}
		}
	}
	if c.Whitelist != nil {
		for _, h := range append(append([]WhitelistHost{}, c.Whitelist.Domestic...), c.Whitelist.Foreign...) {
			if !hostRe.MatchString(h.Host) {
				errs = append(errs, fmt.Errorf("whitelist: invalid host %q", h.Host))
			}
		}
	}
	return errors.Join(errs...)
}

func validateEndpoint(where string, e Endpoint) []error {
	var errs []error
	switch {
	case e.Host != "" && e.Addr != "":
		errs = append(errs, fmt.Errorf("%s: endpoint has both host and addr", where))
	case e.Host != "":
		if !hostRe.MatchString(e.Host) {
			errs = append(errs, fmt.Errorf("%s: invalid host %q", where, e.Host))
		}
	case e.Addr != "":
		h, p, err := net.SplitHostPort(e.Addr)
		if err != nil || net.ParseIP(h) == nil {
			errs = append(errs, fmt.Errorf("%s: invalid addr %q", where, e.Addr))
		} else if n, err := strconv.Atoi(p); err != nil || n <= 0 || n > 65535 {
			errs = append(errs, fmt.Errorf("%s: invalid port in %q", where, e.Addr))
		}
	default:
		errs = append(errs, fmt.Errorf("%s: endpoint needs host or addr", where))
	}
	for _, t := range e.Tests {
		if !knownTests[t] {
			errs = append(errs, fmt.Errorf("%s: unknown test %q", where, t))
		}
		if e.Addr != "" && (t == TestDNS || t == TestHTTP || t == TestQUIC || t == TestECH) {
			errs = append(errs, fmt.Errorf("%s: test %q needs a host endpoint", where, t))
		}
	}
	for _, v := range e.QUICVersions {
		if v != 1 && v != 2 {
			errs = append(errs, fmt.Errorf("%s: unsupported QUIC version %d", where, v))
		}
	}
	return errs
}

// Category returns a category by id.
func (c *Catalog) Category(id string) *Category {
	for _, cat := range c.Categories {
		if cat.ID == id {
			return cat
		}
	}
	return nil
}

// Target returns a target by id.
func (c *Catalog) Target(id string) (*Target, *Category) {
	for _, cat := range c.Categories {
		for i := range cat.Targets {
			if cat.Targets[i].ID == id {
				return &cat.Targets[i], cat
			}
		}
	}
	return nil, nil
}

// Selection describes which targets to scan.
type Selection struct {
	Categories []string
	Targets    []string
	All        bool // include opt-in categories
}

// Select returns the targets matching sel. Without explicit categories or
// targets, every default category is used. Baseline targets are always
// included so throttling can be judged.
func (c *Catalog) Select(sel Selection) ([]Target, []*Category, error) {
	var out []Target
	used := map[string]*Category{}
	add := func(t Target, cat *Category) {
		for _, o := range out {
			if o.ID == t.ID {
				return
			}
		}
		out = append(out, t)
		used[cat.ID] = cat
	}
	for _, id := range sel.Targets {
		t, cat := c.Target(id)
		if t == nil {
			return nil, nil, fmt.Errorf("unknown target %q", id)
		}
		add(*t, cat)
	}
	for _, id := range sel.Categories {
		cat := c.Category(id)
		if cat == nil {
			return nil, nil, fmt.Errorf("unknown category %q", id)
		}
		for _, t := range cat.Targets {
			add(t, cat)
		}
	}
	if len(sel.Targets) == 0 && len(sel.Categories) == 0 {
		for _, cat := range c.Categories {
			if cat.Default || sel.All {
				for _, t := range cat.Targets {
					add(t, cat)
				}
			}
		}
	}
	for _, cat := range c.Categories {
		for _, t := range cat.Targets {
			if t.IsBaseline() {
				add(t, cat)
			}
		}
	}
	var cats []*Category
	for _, cat := range c.Categories {
		if used[cat.ID] != nil {
			cats = append(cats, cat)
		}
	}
	return out, cats, nil
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
