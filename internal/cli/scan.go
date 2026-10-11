package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Derposd/prosvet/internal/catalog"
	"github.com/Derposd/prosvet/internal/engine"
	"github.com/Derposd/prosvet/internal/model"
	"github.com/Derposd/prosvet/internal/netinfo"
	"github.com/Derposd/prosvet/internal/probe"
	"github.com/Derposd/prosvet/internal/report"
)

type scanFlags struct {
	targets      []string
	categories   []string
	all          bool
	repeats      int
	concurrency  int
	timeoutScale float64
	noQUIC       bool
	noDNS        bool
	offlineNet   bool
	asn          int
	region       string
	conn         string
	format       string
	output       string
}

func defaultScanFlags() scanFlags {
	return scanFlags{repeats: 3, concurrency: 12, timeoutScale: 1, format: "terminal"}
}

func (a *app) scanCmd() *cobra.Command {
	f := defaultScanFlags()
	b := a.b
	cmd := &cobra.Command{
		Use:   "scan",
		Short: b.T("cli.cmd.scan"),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.runScan(cmd.Context(), f)
		},
	}
	fl := cmd.Flags()
	fl.StringSliceVarP(&f.targets, "target", "t", nil, b.T("cli.flag.target"))
	fl.StringSliceVarP(&f.categories, "category", "c", nil, b.T("cli.flag.category"))
	fl.BoolVar(&f.all, "all", false, b.T("cli.flag.all"))
	fl.IntVar(&f.repeats, "repeats", f.repeats, b.T("cli.flag.repeats"))
	fl.IntVar(&f.concurrency, "concurrency", f.concurrency, b.T("cli.flag.concurrency"))
	fl.Float64Var(&f.timeoutScale, "timeout-scale", f.timeoutScale, b.T("cli.flag.timeout_scale"))
	fl.BoolVar(&f.noQUIC, "no-quic", false, b.T("cli.flag.no_quic"))
	fl.BoolVar(&f.noDNS, "no-dns", false, b.T("cli.flag.no_dns"))
	addNetFlags(cmd, &f, b.T)
	fl.StringVarP(&f.format, "format", "f", f.format, b.T("cli.flag.format"))
	fl.StringVarP(&f.output, "output", "o", "", b.T("cli.flag.output"))
	return cmd
}

func addNetFlags(cmd *cobra.Command, f *scanFlags, t func(string, ...string) string) {
	fl := cmd.Flags()
	fl.BoolVar(&f.offlineNet, "offline-netinfo", false, t("cli.flag.offline_netinfo"))
	fl.IntVar(&f.asn, "asn", 0, t("cli.flag.asn"))
	fl.StringVar(&f.region, "region", "", t("cli.flag.region"))
	fl.StringVar(&f.conn, "conn", "", t("cli.flag.conn"))
}

// consentOnce asks for the general measurement consent on first use.
func (a *app) consentOnce() error {
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil //nolint:nilerr // no config dir: just ask every time
	}
	marker := filepath.Join(dir, "prosvet", "consent")
	if _, err := os.Stat(marker); err == nil {
		return nil
	}
	if !a.confirm(a.b.T("cli.consent"), true) {
		fmt.Fprintln(a.stderr, a.b.T("cli.aborted"))
		return errAborted
	}
	if err := os.MkdirAll(filepath.Dir(marker), 0o700); err == nil {
		_ = os.WriteFile(marker, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600)
	}
	return nil
}

// optInConsent confirms categories that carry a consent prompt (e.g. media).
func (a *app) optInConsent(cats []*catalog.Category) error {
	for _, c := range cats {
		text := c.Consent.Get(a.b.Lang)
		if text == "" {
			continue
		}
		if !a.confirm(a.b.T("cli.consent_media", "category", c.Title.Get(a.b.Lang), "text", text), false) {
			fmt.Fprintln(a.stderr, a.b.T("cli.aborted"))
			return errAborted
		}
	}
	return nil
}

func (a *app) newEnv(scale float64) *probe.Env {
	env := probe.NewEnv(a.build.Version)
	env.Timeouts = probe.DefaultTimeouts().Scale(scale)
	return env
}

func (a *app) detectNetwork(ctx context.Context, env *probe.Env, f scanFlags) model.NetworkInfo {
	return netinfo.Detect(ctx, netinfo.Options{
		ASN: f.asn, Region: f.region, Conn: f.conn, Offline: f.offlineNet, Lang: a.b.Lang,
		Client: env.HTTPClient(10 * time.Second),
	})
}

func (a *app) runScan(ctx context.Context, f scanFlags) error {
	cat, err := a.catalog()
	if err != nil {
		return err
	}
	sel := catalog.Selection{Targets: splitList(f.targets), Categories: splitList(f.categories), All: f.all}
	_, cats, err := cat.Select(sel)
	if err != nil {
		return err
	}
	if err := a.consentOnce(); err != nil {
		return err
	}
	if err := a.optInConsent(cats); err != nil {
		return err
	}
	env := a.newEnv(f.timeoutScale)
	opt := engine.DefaultOptions()
	opt.Repeats, opt.Concurrency = f.repeats, f.concurrency
	opt.QUIC, opt.DNSChecks = !f.noQUIC, !f.noDNS
	opt.Version, opt.Commit = a.build.Version, a.build.Commit
	eng := engine.New(env, cat, opt)

	prog := newProgress(a.stderr, a.b)
	netinfo := a.detectNetwork(ctx, env, f)
	events := make(chan engine.Event, 64)
	done := make(chan struct{})
	go func() {
		prog.run(events)
		close(done)
	}()
	rep, scanErr := eng.Scan(ctx, sel, netinfo, events)
	close(events)
	<-done
	if rep == nil {
		return scanErr
	}
	if path, err := report.SaveLast(rep); err == nil && f.format == "terminal" && f.output == "" {
		defer fmt.Fprintln(a.stderr, a.b.T("cli.saved", "path", path))
	}
	if err := a.render(rep, cat, f.format, f.output); err != nil {
		return err
	}
	return scanErr
}

func splitList(in []string) []string {
	var out []string
	for _, s := range in {
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

// categoryTitles returns localised category titles.
func (a *app) categoryTitles(cat *catalog.Catalog) report.CategoryTitles {
	t := report.CategoryTitles{}
	if cat == nil {
		return t
	}
	for _, c := range cat.Categories {
		t[c.ID] = c.Title.Get(a.b.Lang)
	}
	return t
}
