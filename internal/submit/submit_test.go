package submit

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ordinarysim/prosvet/internal/model"
)

func sampleReport() *model.Report {
	return &model.Report{
		Schema:     model.ReportSchema,
		Tool:       model.ToolInfo{Name: "prosvet", Version: "0.1.0"},
		FinishedAt: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC),
		Network:    model.NetworkInfo{ASN: 12389, ISP: "PJSC Rostelecom", Country: "RU", Region: "RU-MOW", Conn: "fixed", VPNReason: ""},
		Targets: []model.TargetResult{
			{ID: "telegram", Category: "messengers", Status: model.StatusBlocked,
				Verdict:   model.Verdict{Kind: model.KindIPBlock, Subtype: "drop", Confidence: model.High},
				Endpoints: []model.EndpointResult{{Name: "149.154.167.51", IP: "149.154.167.51"}}},
			{ID: "cloudflare", Category: "infra", Status: model.StatusThrottled,
				Verdict:  model.Verdict{Kind: model.KindThrottleFreeze, Subtype: "16-20kb", Confidence: model.High},
				Throttle: &model.HTTPResult{BytesBeforeStall: 16900}},
			{ID: "baseline-yandex", Role: "baseline", Category: "infra", Status: model.StatusOK},
		},
		DNS: &model.DNSReport{Findings: []model.DNSFinding{{Kind: "dns_interception", Resolvers: []string{"8.8.8.8"}}}},
	}
}

func TestBuildIsAnonymous(t *testing.T) {
	s, err := Build(sampleReport(), false)
	if err != nil {
		t.Fatal(err)
	}
	data, err := Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(data); err != nil {
		t.Fatalf("own output must validate: %v\n%s", err, data)
	}
	if regexp.MustCompile(`\d+\.\d+\.\d+\.\d+`).Match(data) {
		t.Fatalf("IP-like value leaked:\n%s", data)
	}
	if len(s.Results) != 2 {
		t.Fatalf("baseline must be excluded: %+v", s.Results)
	}
	if s.Results[1].StallKB != 16.5 {
		t.Fatalf("stall_kb = %v", s.Results[1].StallKB)
	}
	if s.Date != "2026-10-11" {
		t.Fatalf("date %s", s.Date)
	}
}

func TestBuildRefusals(t *testing.T) {
	r := sampleReport()
	r.Options.Demo = true
	if _, err := Build(r, false); !errors.Is(err, ErrDemo) {
		t.Fatalf("demo: %v", err)
	}
	r = sampleReport()
	r.Network.ASN = 0
	if _, err := Build(r, false); !errors.Is(err, ErrNoASN) {
		t.Fatalf("no asn: %v", err)
	}
	r = sampleReport()
	r.Network.VPNSuspected = true
	if _, err := Build(r, false); !errors.Is(err, ErrVPN) {
		t.Fatalf("vpn: %v", err)
	}
	if _, err := Build(r, true); err != nil {
		t.Fatalf("vpn allowed: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	good, _ := Build(sampleReport(), false)
	base, _ := Marshal(good)
	mutate := func(f func(m map[string]any)) []byte {
		var m map[string]any
		_ = json.Unmarshal(base, &m)
		f(m)
		b, _ := json.Marshal(m)
		return b
	}
	cases := map[string][]byte{
		"ip in isp":     mutate(func(m map[string]any) { m["network"].(map[string]any)["isp"] = "home 192.168.1.10" }),
		"ipv6":          mutate(func(m map[string]any) { m["network"].(map[string]any)["isp"] = "2a00:1450:4001:82a::200e" }),
		"unknown field": mutate(func(m map[string]any) { m["ip"] = "x" }),
		"bad schema":    mutate(func(m map[string]any) { m["schema"] = "other" }),
		"bad region":    mutate(func(m map[string]any) { m["network"].(map[string]any)["region"] = "Moscow, Tverskaya 1" }),
		"bad kind":      mutate(func(m map[string]any) { m["results"].([]any)[0].(map[string]any)["kind"] = "evil" }),
		"future date":   mutate(func(m map[string]any) { m["date"] = "2099-01-01" }),
		"bad target":    mutate(func(m map[string]any) { m["results"].([]any)[0].(map[string]any)["target"] = "../../etc" }),
		"huge":          append([]byte(`{"schema":"`), []byte(strings.Repeat("a", MaxSize))...),
	}
	for name, data := range cases {
		if err := Validate(data); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

func TestWrite(t *testing.T) {
	s, _ := Build(sampleReport(), false)
	dir := t.TempDir()
	p, err := Write(dir, s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(filepath.ToSlash(p), filepath.ToSlash(dir)+"/AS12389/2026-10-11-") {
		t.Fatalf("path %s", p)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(data); err != nil {
		t.Fatal(err)
	}
}
