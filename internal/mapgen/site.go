package mapgen

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Derposd/prosvet/internal/brand"
	"github.com/Derposd/prosvet/internal/catalog"
	"github.com/Derposd/prosvet/internal/i18n"
	"github.com/Derposd/prosvet/internal/model"
	"github.com/Derposd/prosvet/internal/submit"
)

//go:embed site/*
var siteFS embed.FS

// Options configure a site build.
type Options struct {
	Results string // directory with submissions
	Out     string // output directory
	Assets  string // optional directory with social-preview.png
	Sample  bool   // add clearly-labelled sample data (never for deployment)
	Now     time.Time
}

// Build aggregates submissions and writes the static site.
func Build(cat *catalog.Catalog, opt Options) (*Data, []Problem, error) {
	if opt.Now.IsZero() {
		opt.Now = time.Now()
	}
	entries, problems, err := Load(opt.Results)
	if err != nil {
		return nil, problems, err
	}
	if opt.Sample {
		entries = append(entries, SampleEntries(cat, opt.Now)...)
	}
	data := Aggregate(entries, cat, opt.Now)
	data.Sample = opt.Sample
	data.Repo = brand.Repo
	keys := map[string]map[string]string{}
	for _, l := range i18n.Languages() {
		keys[l] = i18n.Keys(l)
	}
	data.I18n = I18nFrom(keys)

	if err := os.MkdirAll(filepath.Join(opt.Out, "data"), 0o750); err != nil {
		return nil, problems, err
	}
	files, err := fs.Glob(siteFS, "site/*")
	if err != nil {
		return nil, problems, err
	}
	for _, f := range files {
		b, err := siteFS.ReadFile(f)
		if err != nil {
			return nil, problems, err
		}
		if err := os.WriteFile(filepath.Join(opt.Out, filepath.Base(f)), b, 0o644); err != nil { //nolint:gosec // public static site
			return nil, problems, err
		}
	}
	extra := map[string][]byte{
		"prosvet.css": []byte(brand.CSS),
		"logo.svg":    []byte(brand.LogoSVG),
		".nojekyll":   nil,
	}
	if opt.Assets != "" {
		if b, err := os.ReadFile(filepath.Join(opt.Assets, "social-preview.png")); err == nil {
			extra["social-preview.png"] = b
		}
	}
	for name, b := range extra {
		if err := os.WriteFile(filepath.Join(opt.Out, name), b, 0o644); err != nil { //nolint:gosec // public static site
			return nil, problems, err
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(data); err != nil {
		return nil, problems, err
	}
	if err := os.WriteFile(filepath.Join(opt.Out, "data", "map.json"), buf.Bytes(), 0o644); err != nil { //nolint:gosec // public static site
		return nil, problems, err
	}
	return data, problems, nil
}

var jsonBlock = regexp.MustCompile("(?s)```(?:json)?\\s*(\\{.*?\\})\\s*```")

// ErrNoJSON is returned when an issue body contains no submission.
var ErrNoJSON = errors.New("no JSON submission found in the issue body")

// FromIssue extracts, validates and stores a submission pasted into an issue.
// It returns the written path relative to resultsDir's parent.
func FromIssue(body []byte, resultsDir string) (string, error) {
	raw := bytes.TrimSpace(body)
	if m := jsonBlock.FindSubmatch(raw); m != nil {
		raw = m[1]
	} else if i, j := bytes.IndexByte(raw, '{'), bytes.LastIndexByte(raw, '}'); i >= 0 && j > i {
		raw = raw[i : j+1]
	} else {
		return "", ErrNoJSON
	}
	if err := submit.Validate(raw); err != nil {
		return "", err
	}
	var s submit.Submission
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", err
	}
	return submit.Write(resultsDir, &s)
}

// SampleEntries generates deterministic, clearly fake data for layout testing.
// Sample ASNs come from the documentation range (RFC 5398).
func SampleEntries(cat *catalog.Catalog, now time.Time) []Entry {
	r := rand.New(rand.NewPCG(42, 7)) //nolint:gosec // deterministic sample data
	type net struct {
		asn    int
		isp    string
		region string
		conn   string
	}
	nets := []net{
		{64496, "Sample Telecom", "RU-MOW", "fixed"}, {64497, "Sample Mobile", "RU-MOW", "mobile"},
		{64498, "Example Net", "RU-SPE", "fixed"}, {64499, "Demo Broadband", "RU-TA", "fixed"},
		{64500, "Test Wireless", "RU-KDA", "mobile"}, {64501, "Placeholder ISP", "RU-SVE", "fixed"},
		{64502, "Mock Cellular", "RU-NVS", "mobile"},
	}
	var targets []catalog.Target
	if cat != nil {
		for _, c := range cat.Categories {
			if c.Default {
				for _, t := range c.Targets {
					if !t.IsBaseline() {
						targets = append(targets, t)
					}
				}
			}
		}
	}
	statuses := []model.Status{model.StatusOK, model.StatusOK, model.StatusThrottled, model.StatusPartial, model.StatusBlocked}
	kinds := map[model.Status][]model.Kind{
		model.StatusOK:        {model.KindOK},
		model.StatusThrottled: {model.KindThrottleFreeze, model.KindThrottleRate},
		model.StatusPartial:   {model.KindDNS, model.KindSNIDPI},
		model.StatusBlocked:   {model.KindSNIDPI, model.KindIPBlock, model.KindDNS},
	}
	var out []Entry
	for day := 45; day >= 0; day -= 3 {
		date := now.AddDate(0, 0, -day).UTC().Format("2006-01-02")
		for _, n := range nets {
			if r.IntN(3) == 0 {
				continue
			}
			s := submit.Submission{Schema: submit.Schema, Tool: submit.Tool{Name: "prosvet", Version: "sample"}, Date: date,
				Network: submit.Network{ASN: n.asn, ISP: n.isp, Country: "RU", Region: n.region, Conn: n.conn}}
			for i, t := range targets {
				base := statuses[(i*7+n.asn)%len(statuses)]
				if day > 30 && base == model.StatusBlocked && i%2 == 0 {
					base = model.StatusOK // shows "started blocking" events
				}
				ks := kinds[base]
				s.Results = append(s.Results, submit.Result{Target: t.ID, Category: t.Category, Status: base,
					Kind: ks[(i+n.asn)%len(ks)], Confidence: model.High})
			}
			out = append(out, Entry{Path: fmt.Sprintf("sample/AS%d/%s.json", n.asn, date), Sub: s})
		}
	}
	return out
}

// ValidatePaths checks specific files (e.g. those changed in a pull request).
func ValidatePaths(root string, paths []string) []Problem {
	var problems []Problem
	for _, p := range paths {
		if !strings.HasSuffix(p, ".json") {
			continue
		}
		if _, err := CheckFile(root, p); err != nil {
			problems = append(problems, Problem{Path: p, Err: err})
		}
	}
	return problems
}
