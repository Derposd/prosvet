package netinfo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNearestRegion(t *testing.T) {
	cases := []struct {
		lat, lon float64
		want     string
	}{
		{55.7386, 37.6068, "RU-MOW"}, // RIPEstat location of 77.88.8.8
		{59.93, 30.36, "RU-SPE"},
		{55.79, 49.12, "RU-TA"},
		{56.84, 60.61, "RU-SVE"},
		{43.59, 39.72, "RU-KDA"}, // Sochi
		{56.32, 38.13, "RU-MOS"}, // Sergiev Posad
	}
	for _, c := range cases {
		r := NearestRegion(c.lat, c.lon)
		if r == nil || r.Code != c.want {
			t.Errorf("%v,%v: got %+v want %s", c.lat, c.lon, r, c.want)
		}
	}
	if r := NearestRegion(48.85, 2.35); r != nil { // Paris
		t.Errorf("Paris must not map to a Russian region: %+v", r)
	}
}

func TestRegionsUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Regions() {
		if seen[r.Code] || !strings.HasPrefix(r.Code, "RU-") || r.RU == "" || r.EN == "" {
			t.Errorf("bad region %+v", r)
		}
		seen[r.Code] = true
	}
	if len(seen) != 83 {
		t.Errorf("expected 83 regions, got %d", len(seen))
	}
}

func TestCleanHolder(t *testing.T) {
	if got := cleanHolder("ROSTELECOM-AS PJSC Rostelecom"); got != "PJSC Rostelecom" {
		t.Errorf("got %q", got)
	}
	if got := cleanHolder("MTS PJSC"); got != "MTS PJSC" {
		t.Errorf("got %q", got)
	}
	if !isHosting("HETZNER-AS Hetzner Online GmbH") || isHosting("PJSC Rostelecom") {
		t.Error("hosting detection wrong")
	}
}

func fakeRIPE(t *testing.T, asn, holder string, lat, lon float64) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`"203.0.113.77"`)) })
	mux.HandleFunc("/network-info/data.json", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("resource") != "203.0.113.77" {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"asns": []string{asn}}})
	})
	mux.HandleFunc("/as-overview/data.json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"holder": holder}})
	})
	mux.HandleFunc("/maxmind-geo-lite/data.json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"located_resources": []any{
			map[string]any{"locations": []any{map[string]any{"country": "RU", "latitude": lat, "longitude": lon}}},
		}}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestDetect(t *testing.T) {
	srv := fakeRIPE(t, "31133", "MF-MGSM-AS PJSC MegaFon", 55.79, 49.12)
	info := Detect(context.Background(), Options{
		Client: srv.Client(), RIPEBase: srv.URL, EchoURLs: []string{srv.URL + "/echo"}, Lang: "ru",
		Local: &LocalInfo{Interface: "Wi-Fi"},
	})
	if info.ASN != 31133 || info.ISP != "PJSC MegaFon" || info.Region != "RU-TA" || info.RegionName != "Татарстан" || info.Conn != "mobile" {
		t.Fatalf("unexpected: %+v", info)
	}
	b, _ := json.Marshal(info)
	if strings.Contains(string(b), "203.0.113.77") {
		t.Fatal("public IP leaked into NetworkInfo")
	}
}

func TestDetectHostingFlagsVPN(t *testing.T) {
	srv := fakeRIPE(t, "24940", "HETZNER-AS Hetzner Online GmbH", 50.47, 12.37)
	info := Detect(context.Background(), Options{
		Client: srv.Client(), RIPEBase: srv.URL, EchoURLs: []string{srv.URL + "/echo"}, Local: &LocalInfo{},
	})
	if !info.VPNSuspected {
		t.Fatalf("hosting ASN must raise the VPN warning: %+v", info)
	}
}

func TestDetectOfflineAndManual(t *testing.T) {
	info := Detect(context.Background(), Options{Offline: true, ASN: 12389, Region: "ru-spe", Conn: "fixed", Lang: "en",
		Local: &LocalInfo{VPN: true, VPNReason: "interface wg0"}})
	if info.ASN != 12389 || info.Region != "RU-SPE" || info.RegionName != "Saint Petersburg" || info.Conn != "fixed" || !info.VPNSuspected || info.Source != "manual" {
		t.Fatalf("unexpected: %+v", info)
	}
}

func TestEchoParsers(t *testing.T) {
	for name, body := range map[string]string{
		"ripe":       `{"data":{"ip":"203.0.113.5"}}`,
		"yandex":     `"203.0.113.5"`,
		"cloudflare": "fl=1\nh=www.cloudflare.com\nip=203.0.113.5\nloc=RU\n",
		"plain":      "203.0.113.5\n",
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
		ip, err := echoIP(context.Background(), srv.Client(), srv.URL)
		srv.Close()
		if err != nil || ip != "203.0.113.5" {
			t.Errorf("%s: %q %v", name, ip, err)
		}
	}
}
