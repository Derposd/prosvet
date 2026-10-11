// Package fingerprint matches DNS answers and HTTP responses against known
// block stubs and block pages.
package fingerprint

import (
	_ "embed"
	"net"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed fingerprints.yaml
var raw []byte

// DNSStub is a known stub address returned instead of the real one.
type DNSStub struct {
	ID  string `yaml:"id"`
	IP  string `yaml:"ip"`
	ISP string `yaml:"isp"`
}

// HTTPPage is a known block page indicator.
type HTTPPage struct {
	ID      string `yaml:"id"`
	Where   string `yaml:"where"` // location | body
	Match   string `yaml:"match"` // prefix | contains | exact
	Pattern string `yaml:"pattern"`
}

// DB is a fingerprint database.
type DB struct {
	DNS  []DNSStub  `yaml:"dns"`
	HTTP []HTTPPage `yaml:"http"`

	stubs map[string]string
}

var (
	defaultOnce sync.Once
	defaultDB   *DB
)

// Default returns the embedded fingerprint database.
func Default() *DB {
	defaultOnce.Do(func() {
		db, err := Parse(raw)
		if err != nil {
			panic("fingerprint: embedded database is invalid: " + err.Error())
		}
		defaultDB = db
	})
	return defaultDB
}

// Parse decodes a fingerprint database.
func Parse(b []byte) (*DB, error) {
	var db DB
	if err := yaml.Unmarshal(b, &db); err != nil {
		return nil, err
	}
	db.stubs = make(map[string]string, len(db.DNS))
	for _, s := range db.DNS {
		if ip := net.ParseIP(s.IP); ip != nil {
			db.stubs[ip.String()] = s.ID
		}
	}
	return &db, nil
}

// MatchDNS returns the fingerprint id when any address is a known stub.
func (db *DB) MatchDNS(addrs []string) string {
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			continue
		}
		if id, ok := db.stubs[ip.String()]; ok {
			return id
		}
	}
	return ""
}

// MatchHTTP returns the fingerprint id when the redirect location or body matches.
func (db *DB) MatchHTTP(location string, body []byte) string {
	b := string(body)
	for _, p := range db.HTTP {
		var subject string
		switch p.Where {
		case "location":
			subject = location
		case "body":
			subject = b
		default:
			continue
		}
		if subject == "" {
			continue
		}
		if match(p.Match, subject, p.Pattern) {
			return p.ID
		}
	}
	return ""
}

func match(kind, subject, pattern string) bool {
	switch kind {
	case "prefix":
		return strings.HasPrefix(subject, pattern)
	case "exact":
		return subject == pattern
	default:
		return strings.Contains(subject, pattern)
	}
}

// IsBogon reports whether ip is not a valid public unicast address
// (private, loopback, link-local, CGNAT, documentation, unspecified...).
func IsBogon(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	for _, n := range bogonNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

var bogonNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "255.255.255.255/32",
		"2001:db8::/32", "100::/64",
	} {
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			out = append(out, n)
		}
	}
	return out
}()
