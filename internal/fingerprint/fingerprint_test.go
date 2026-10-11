package fingerprint

import "testing"

func TestDefaultLoads(t *testing.T) {
	db := Default()
	if len(db.DNS) == 0 || len(db.HTTP) == 0 {
		t.Fatal("empty fingerprint database")
	}
	seen := map[string]bool{}
	for _, s := range db.DNS {
		if seen[s.ID] {
			t.Errorf("duplicate id %s", s.ID)
		}
		seen[s.ID] = true
	}
	for _, p := range db.HTTP {
		if seen[p.ID] {
			t.Errorf("duplicate id %s", p.ID)
		}
		seen[p.ID] = true
		if p.Pattern == "" || (p.Where != "location" && p.Where != "body") {
			t.Errorf("bad http fingerprint %+v", p)
		}
	}
}

func TestMatch(t *testing.T) {
	db := Default()
	if got := db.MatchDNS([]string{"1.1.1.1", "95.167.13.50"}); got != "ru.rostelecom.1" {
		t.Errorf("dns stub not matched: %q", got)
	}
	if got := db.MatchDNS([]string{"142.250.74.14"}); got != "" {
		t.Errorf("false positive: %q", got)
	}
	if got := db.MatchHTTP("http://warning.rt.ru/?id=17", nil); got != "ru.rostelecom.warning" {
		t.Errorf("location not matched: %q", got)
	}
	if got := db.MatchHTTP("", []byte("<h1>Доступ к запрашиваемому ресурсу закрыт.</h1>")); got != "ru.generic.closed" {
		t.Errorf("body not matched: %q", got)
	}
	if got := db.MatchHTTP("https://www.example.com/", []byte("hello")); got != "" {
		t.Errorf("false positive: %q", got)
	}
}

func TestIsBogon(t *testing.T) {
	for _, ip := range []string{"10.0.0.1", "127.0.0.1", "0.0.0.0", "100.64.1.1", "192.168.1.1", "::1", "fe80::1", "garbage"} {
		if !IsBogon(ip) {
			t.Errorf("%s should be bogon", ip)
		}
	}
	for _, ip := range []string{"1.1.1.1", "77.88.8.8", "2a00:1450:4001::200e"} {
		if IsBogon(ip) {
			t.Errorf("%s should not be bogon", ip)
		}
	}
}
