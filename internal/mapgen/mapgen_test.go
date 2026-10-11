package mapgen

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Derposd/prosvet/internal/catalog"
	"github.com/Derposd/prosvet/internal/model"
	"github.com/Derposd/prosvet/internal/submit"
	"github.com/Derposd/prosvet/targets"
)

func sub(date string, asn int, region, conn string, results ...submit.Result) *submit.Submission {
	return &submit.Submission{Schema: submit.Schema, Tool: submit.Tool{Name: "prosvet", Version: "0.1.0"}, Date: date,
		Network: submit.Network{ASN: asn, ISP: "ISP " + region, Country: "RU", Region: region, Conn: conn}, Results: results}
}

func res(target, cat string, s model.Status, k model.Kind) submit.Result {
	return submit.Result{Target: target, Category: cat, Status: s, Kind: k, Confidence: model.High}
}

func writeAll(t *testing.T, dir string, subs ...*submit.Submission) {
	t.Helper()
	for _, s := range subs {
		if _, err := submit.Write(dir, s); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAggregate(t *testing.T) {
	dir := t.TempDir()
	writeAll(t, dir,
		sub("2026-09-01", 12389, "RU-MOW", "fixed", res("telegram", "messengers", model.StatusOK, model.KindOK)),
		sub("2026-09-10", 12389, "RU-MOW", "fixed", res("telegram", "messengers", model.StatusBlocked, model.KindSNIDPI)),
		sub("2026-09-10", 12389, "RU-MOW", "fixed", res("telegram", "messengers", model.StatusBlocked, model.KindIPBlock)),
		sub("2026-09-10", 12389, "RU-MOW", "fixed", res("telegram", "messengers", model.StatusOK, model.KindOK)),
		sub("2026-09-12", 31133, "RU-TA", "mobile", res("telegram", "messengers", model.StatusBlocked, model.KindIPBlock),
			res("youtube", "video", model.StatusPartial, model.KindDNS), res("custom-site", "x", model.StatusOK, model.KindOK)),
	)
	entries, problems, err := Load(dir)
	if err != nil || len(problems) != 0 {
		t.Fatalf("load: %v %v", err, problems)
	}
	cat, err := catalog.Load(targets.FS)
	if err != nil {
		t.Fatal(err)
	}
	d := Aggregate(entries, cat, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	if d.Submissions != 5 || len(d.Rows) != 2 || d.Updated != "2026-09-12" {
		t.Fatalf("counts: %+v", d)
	}
	if d.Rows[0].ASN != 12389 || d.Rows[0].Reports != 4 {
		t.Fatalf("rows sorted by reports: %+v", d.Rows)
	}
	c := d.Cells["12389|RU-MOW|fixed"]["telegram"]
	if c.Status != model.StatusBlocked || c.Date != "2026-09-10" || c.N != 4 {
		t.Fatalf("latest daily majority wrong: %+v", c)
	}
	ev := d.Events["telegram"]
	if len(ev) != 1 || ev[0].From != model.StatusOK || ev[0].To != model.StatusBlocked || ev[0].Date != "2026-09-10" {
		t.Fatalf("events: %+v", ev)
	}
	// catalog order: messengers before video; unknown targets in "other"
	if d.Targets[0].ID != "telegram" || d.Targets[len(d.Targets)-1].ID != "custom-site" || d.Categories[len(d.Categories)-1].ID != "other" {
		t.Fatalf("targets/categories: %+v %+v", d.Targets, d.Categories)
	}
	if len(d.Timeline["telegram"]) != 3 {
		t.Fatalf("timeline: %+v", d.Timeline["telegram"])
	}
	if len(d.Regions) != 2 || d.Regions[0].RU == "" {
		t.Fatalf("regions: %+v", d.Regions)
	}
}

func TestLoadRejectsMisplacedAndInvalid(t *testing.T) {
	dir := t.TempDir()
	s := sub("2026-09-01", 12389, "RU-MOW", "fixed", res("telegram", "messengers", model.StatusOK, model.KindOK))
	data, _ := submit.Marshal(s)
	mustWrite := func(rel string, b []byte) {
		p := filepath.Join(dir, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("AS999/2026-09-01-abcdef.json", data)           // wrong ASN directory
	mustWrite("AS12389/2026-09-02-abcdef.json", data)         // wrong date
	mustWrite("AS12389/notes-abcdef.json", data)              // bad name
	mustWrite("AS12389/2026-09-01-012345.json", []byte("{}")) // invalid content
	mustWrite("AS12389/2026-09-01-0a0b0c.json", data)         // valid
	entries, problems, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || len(problems) != 4 {
		t.Fatalf("entries %d problems %d: %v", len(entries), len(problems), problems)
	}
}

func TestBuildSiteAndIssue(t *testing.T) {
	dir := t.TempDir()
	results := filepath.Join(dir, "results")
	body := "### Results\n\n```json\n" + func() string {
		b, _ := submit.Marshal(sub("2026-09-05", 8359, "RU-SPE", "mobile", res("whatsapp", "messengers", model.StatusBlocked, model.KindDNS)))
		return string(b)
	}() + "```\n"
	path, err := FromIssue([]byte(body), results)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(filepath.ToSlash(path), "AS8359/2026-09-05-") {
		t.Fatalf("path %s", path)
	}
	if _, err := FromIssue([]byte("hello, no data here"), results); err == nil {
		t.Fatal("issue without JSON must fail")
	}
	if _, err := FromIssue([]byte("```json\n{\"schema\":\"prosvet.submission/v1\",\"isp\":\"10.0.0.1\"}\n```"), results); err == nil {
		t.Fatal("invalid submission must fail")
	}

	cat, _ := catalog.Load(targets.FS)
	out := filepath.Join(dir, "site")
	d, problems, err := Build(cat, Options{Results: results, Out: out, Now: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil || len(problems) != 0 {
		t.Fatalf("build: %v %v", err, problems)
	}
	for _, f := range []string{"index.html", "app.js", "map.css", "prosvet.css", "logo.svg", ".nojekyll", "data/map.json"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("missing %s", f)
		}
	}
	raw, _ := os.ReadFile(filepath.Join(out, "data", "map.json"))
	var back Data
	if err := json.Unmarshal(raw, &back); err != nil || back.Submissions != 1 || d.Sample {
		t.Fatalf("map.json: %v %+v", err, back)
	}
	if back.I18n["ru"]["map.title"] == "" || back.I18n["en"]["status.blocked"] == "" {
		t.Fatal("i18n strings missing in map.json")
	}
	html, _ := os.ReadFile(filepath.Join(out, "index.html"))
	for _, bad := range []string{"https://cdn", "googleapis", "<script>", "analytics"} {
		if strings.Contains(string(html), bad) {
			t.Errorf("index.html must not reference %q", bad)
		}
	}
}

func TestSampleDataIsLabelled(t *testing.T) {
	cat, _ := catalog.Load(targets.FS)
	out := t.TempDir()
	d, _, err := Build(cat, Options{Results: filepath.Join(out, "none"), Out: out, Sample: true})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Sample || d.Submissions == 0 {
		t.Fatalf("sample: %v %d", d.Sample, d.Submissions)
	}
	for _, r := range d.Rows {
		if r.ASN < 64496 || r.ASN > 64511 {
			t.Fatalf("sample data must use documentation ASNs, got %d", r.ASN)
		}
	}
}
