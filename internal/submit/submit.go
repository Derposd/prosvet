// Package submit builds and validates the anonymous result files that feed
// the public map (results/AS<asn>/<date>-<id>.json).
//
// A submission contains only: tool version, date (day precision), ASN,
// provider name, country, coarse region, connection type and per-target
// verdicts. No IP addresses, hostnames of the user, timings or raw data.
package submit

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/ordinarysim/prosvet/internal/brand"
	"github.com/ordinarysim/prosvet/internal/model"
)

// Schema identifies the submission format.
const Schema = "prosvet.submission/v1"

// MaxSize bounds a submission file.
const MaxSize = 64 << 10

// Submission is the anonymous result file.
type Submission struct {
	Schema    string      `json:"schema"`
	Tool      Tool        `json:"tool"`
	Date      string      `json:"date"`
	Network   Network     `json:"network"`
	Results   []Result    `json:"results"`
	Whitelist *Whitelist  `json:"whitelist,omitempty"`
	DNS       *DNSSummary `json:"dns,omitempty"`
}

// Tool identifies the producer.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Network is the anonymised network description.
type Network struct {
	ASN     int    `json:"asn"`
	ISP     string `json:"isp,omitempty"`
	Country string `json:"country,omitempty"`
	Region  string `json:"region,omitempty"`
	Conn    string `json:"conn"`
}

// Result is the verdict for one target.
type Result struct {
	Target     string           `json:"target"`
	Category   string           `json:"category"`
	Status     model.Status     `json:"status"`
	Kind       model.Kind       `json:"kind"`
	Subtype    string           `json:"subtype,omitempty"`
	Confidence model.Confidence `json:"confidence"`
	Secondary  []model.Kind     `json:"secondary,omitempty"`
	StallKB    float64          `json:"stall_kb,omitempty"`
}

// Whitelist is the whitelist-mode summary.
type Whitelist struct {
	Verdict       string `json:"verdict"`
	DomesticOK    int    `json:"domestic_ok"`
	DomesticTotal int    `json:"domestic_total"`
	ForeignOK     int    `json:"foreign_ok"`
	ForeignTotal  int    `json:"foreign_total"`
	Level         string `json:"level,omitempty"`
}

// DNSSummary lists DNS finding kinds.
type DNSSummary struct {
	Findings []string `json:"findings,omitempty"`
}

// Errors returned by Build.
var (
	ErrNoASN = errors.New("the provider (ASN) is unknown: run the scan with network detection or pass --asn")
	ErrVPN   = errors.New("a VPN or proxy seems active: the result would describe the VPN exit, not your provider")
	ErrDemo  = errors.New("demo reports cannot be submitted")
	ErrEmpty = errors.New("the report contains no results")
)

// Build converts a report into a submission. allowVPN skips the VPN check.
func Build(rep *model.Report, allowVPN bool) (*Submission, error) {
	if rep.Options.Demo {
		return nil, ErrDemo
	}
	if rep.Network.ASN == 0 {
		return nil, ErrNoASN
	}
	if rep.Network.VPNSuspected && !allowVPN {
		return nil, ErrVPN
	}
	date := rep.FinishedAt
	if date.IsZero() {
		date = time.Now()
	}
	s := &Submission{
		Schema: Schema,
		Tool:   Tool{Name: "prosvet", Version: rep.Tool.Version},
		Date:   date.UTC().Format("2006-01-02"),
		Network: Network{
			ASN: rep.Network.ASN, ISP: rep.Network.ISP, Country: rep.Network.Country,
			Region: rep.Network.Region, Conn: rep.Network.Conn,
		},
	}
	if s.Network.Conn == "" {
		s.Network.Conn = "unknown"
	}
	for _, t := range rep.Targets {
		if t.Role == "baseline" || t.Status == model.StatusUnreachable {
			continue
		}
		r := Result{
			Target: t.ID, Category: t.Category, Status: t.Status, Kind: t.Verdict.Kind,
			Subtype: t.Verdict.Subtype, Confidence: t.Verdict.Confidence, Secondary: t.Secondary,
		}
		if r.Confidence == "" {
			r.Confidence = model.Low
		}
		if t.Verdict.Kind == model.KindThrottleFreeze {
			if h := t.Throttle; h != nil && h.BytesBeforeStall > 0 {
				r.StallKB = float64(h.BytesBeforeStall*10/1024) / 10
			}
		}
		s.Results = append(s.Results, r)
	}
	if w := rep.Whitelist; w != nil {
		s.Whitelist = &Whitelist{Verdict: w.Verdict, DomesticOK: w.DomesticOK, DomesticTotal: w.DomesticTotal,
			ForeignOK: w.ForeignOK, ForeignTotal: w.ForeignTotal, Level: w.FailureLevel}
	}
	if d := rep.DNS; d != nil && len(d.Findings) > 0 {
		s.DNS = &DNSSummary{}
		for _, f := range d.Findings {
			s.DNS.Findings = append(s.DNS.Findings, f.Kind)
		}
	}
	if len(s.Results) == 0 && s.Whitelist == nil {
		return nil, ErrEmpty
	}
	return s, nil
}

// Marshal encodes the submission canonically.
func Marshal(s *Submission) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Path returns the repository path for s, e.g. results/AS12389/2026-10-11-1a2b3c.json.
func Path(dir string, s *Submission) string {
	var b [3]byte
	_, _ = rand.Read(b[:])
	return filepath.Join(dir, fmt.Sprintf("AS%d", s.Network.ASN), s.Date+"-"+hex.EncodeToString(b[:])+".json")
}

// Write stores the submission under dir and returns the file path.
func Write(dir string, s *Submission) (string, error) {
	data, err := Marshal(s)
	if err != nil {
		return "", err
	}
	if err := Validate(data); err != nil {
		return "", fmt.Errorf("internal error, refusing to write an invalid submission: %w", err)
	}
	p := Path(dir, s)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return "", err
	}
	return p, os.WriteFile(p, data, 0o600)
}

// IssueURL is the GitHub form for submitting a result file without git.
func IssueURL() string {
	return brand.RepoURL + "/issues/new?template=submit-results.yml"
}

var (
	dateRe   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	regionRe = regexp.MustCompile(`^[A-Z]{2}-[A-Z]{2,3}$`)
	idRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	verRe    = regexp.MustCompile(`^[0-9A-Za-z.+_-]{1,40}$`)
	ipv4Re   = regexp.MustCompile(`\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b`)
	ipv6Re   = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}\b`)
)

var (
	validStatus = map[model.Status]bool{model.StatusOK: true, model.StatusThrottled: true, model.StatusPartial: true,
		model.StatusBlocked: true, model.StatusUnknown: true}
	validConn = map[string]bool{"mobile": true, "fixed": true, "unknown": true}
	validConf = map[model.Confidence]bool{model.High: true, model.Medium: true, model.Low: true}
	validWL   = map[string]bool{model.WhitelistActive: true, model.WhitelistNormal: true, model.WhitelistDegraded: true, model.WhitelistNoConnectivity: true}
)

func validKind(k model.Kind) bool {
	for _, x := range model.AllKinds {
		if x == k {
			return true
		}
	}
	return false
}

// Validate checks a submission file: format, value ranges and privacy
// (it must not contain anything that looks like an IP address).
func Validate(data []byte) error {
	if len(data) > MaxSize {
		return fmt.Errorf("file is larger than %d bytes", MaxSize)
	}
	if ipv4Re.Match(data) || ipv6Re.Match(data) {
		return errors.New("file contains something that looks like an IP address")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s Submission
	if err := dec.Decode(&s); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if s.Schema != Schema {
		add("schema must be %q", Schema)
	}
	if s.Tool.Name != "prosvet" || !verRe.MatchString(s.Tool.Version) {
		add("invalid tool")
	}
	if !dateRe.MatchString(s.Date) {
		add("invalid date %q", s.Date)
	} else if d, err := time.Parse("2006-01-02", s.Date); err != nil || d.After(time.Now().Add(48*time.Hour)) || d.Year() < 2026 {
		add("date %q out of range", s.Date)
	}
	if s.Network.ASN <= 0 || s.Network.ASN > 4294967295 {
		add("invalid ASN")
	}
	if s.Network.Region != "" && !regionRe.MatchString(s.Network.Region) {
		add("invalid region %q", s.Network.Region)
	}
	if s.Network.Country != "" && len(s.Network.Country) != 2 {
		add("invalid country")
	}
	if len(s.Network.ISP) > 120 {
		add("isp too long")
	}
	if !validConn[s.Network.Conn] {
		add("invalid conn %q", s.Network.Conn)
	}
	if len(s.Results) == 0 && s.Whitelist == nil {
		add("no results")
	}
	if len(s.Results) > 500 {
		add("too many results")
	}
	seen := map[string]bool{}
	for _, r := range s.Results {
		switch {
		case !idRe.MatchString(r.Target):
			add("invalid target %q", r.Target)
		case seen[r.Target]:
			add("duplicate target %q", r.Target)
		case !idRe.MatchString(r.Category):
			add("invalid category for %s", r.Target)
		case !validStatus[r.Status]:
			add("invalid status for %s", r.Target)
		case !validKind(r.Kind):
			add("invalid kind for %s", r.Target)
		case !validConf[r.Confidence]:
			add("invalid confidence for %s", r.Target)
		case r.StallKB < 0 || r.StallKB > 1024:
			add("invalid stall_kb for %s", r.Target)
		case len(r.Subtype) > 64:
			add("subtype too long for %s", r.Target)
		}
		for _, k := range r.Secondary {
			if !validKind(k) {
				add("invalid secondary kind for %s", r.Target)
			}
		}
		seen[r.Target] = true
	}
	if w := s.Whitelist; w != nil {
		if !validWL[w.Verdict] || w.DomesticOK > w.DomesticTotal || w.ForeignOK > w.ForeignTotal || w.DomesticOK < 0 || w.ForeignOK < 0 {
			add("invalid whitelist block")
		}
	}
	return errors.Join(errs...)
}
