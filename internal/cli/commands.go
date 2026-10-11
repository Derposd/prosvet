package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ordinarysim/prosvet/internal/catalog"
	"github.com/ordinarysim/prosvet/internal/engine"
	"github.com/ordinarysim/prosvet/internal/model"
	"github.com/ordinarysim/prosvet/internal/report"
	"github.com/ordinarysim/prosvet/internal/theme"
)

func (a *app) whitelistCmd() *cobra.Command {
	f := defaultScanFlags()
	cmd := &cobra.Command{
		Use:   "whitelist",
		Short: a.b.T("cli.cmd.whitelist"),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.runWhitelist(cmd.Context(), f)
		},
	}
	cmd.Flags().Float64Var(&f.timeoutScale, "timeout-scale", 1, a.b.T("cli.flag.timeout_scale"))
	cmd.Flags().StringVarP(&f.format, "format", "f", "terminal", a.b.T("cli.flag.format"))
	addNetFlags(cmd, &f, a.b.T)
	return cmd
}

func (a *app) runWhitelist(ctx context.Context, f scanFlags) error {
	cat, err := a.catalog()
	if err != nil {
		return err
	}
	if err := a.consentOnce(); err != nil {
		return err
	}
	env := a.newEnv(f.timeoutScale)
	opt := engine.DefaultOptions()
	opt.Version = a.build.Version
	eng := engine.New(env, cat, opt)
	netinfo := a.detectNetwork(ctx, env, f)
	events := make(chan engine.Event, 64)
	prog := newProgress(a.stderr, a.b)
	done := make(chan struct{})
	go func() {
		prog.run(events)
		close(done)
	}()
	res, err := eng.Whitelist(ctx, events)
	close(events)
	<-done
	if err != nil && res == nil {
		return err
	}
	rep := eng.NewReport(netinfo)
	rep.Whitelist = res
	rep.FinishedAt = rep.StartedAt
	if _, err := report.SaveLast(rep); err != nil {
		fmt.Fprintln(a.stderr, err)
	}
	if f.format == "json" {
		return report.WriteJSON(a.stdout, rep)
	}
	fmt.Fprintf(a.stdout, "%s %s\n", theme.Title.Render("Prosvet"), theme.Dim.Render("· "+a.b.T("whitelist.title")))
	v := report.Build(rep, a.b, nil)
	fmt.Fprintf(a.stdout, "%s %s\n", theme.Dim.Render("●"), v.Network.Line)
	for _, n := range v.Notices {
		fmt.Fprintln(a.stdout, theme.Warn.Render("⚠ "+n))
	}
	return report.WriteWhitelist(a.stdout, v.Whitelist, a.verbose)
}

func (a *app) targetsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "targets",
		Short: a.b.T("cli.cmd.targets"),
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			cat, err := a.catalog()
			if err != nil {
				return err
			}
			fmt.Fprintln(a.stdout, theme.Title.Render(a.b.T("cli.targets_header")))
			cats := append([]*catalog.Category(nil), cat.Categories...)
			sort.SliceStable(cats, func(i, j int) bool { return cats[i].Default && !cats[j].Default })
			for _, c := range cats {
				mark := ""
				if !c.Default {
					mark = theme.Warn.Render(" (opt-in)")
				}
				fmt.Fprintf(a.stdout, "\n%s%s\n", theme.Bold.Render(c.ID+" — "+c.Title.Get(a.b.Lang)), mark)
				for _, t := range c.Targets {
					var hosts []string
					for _, e := range t.Endpoints {
						hosts = append(hosts, e.Name())
					}
					fmt.Fprintf(a.stdout, "  %-18s %s %s\n", t.ID, t.Name, theme.Dim.Render(strings.Join(hosts, ", ")))
				}
			}
			return nil
		},
	}
}

func (a *app) versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: a.b.T("cli.cmd.version"),
		Args:  cobra.NoArgs,
		Run: func(*cobra.Command, []string) {
			fmt.Fprintf(a.stdout, "prosvet %s (%s, %s) %s/%s\n", a.build.Version, a.build.Commit, a.build.Date, runtime.GOOS, runtime.GOARCH)
		},
	}
}

func (a *app) reportCmd() *cobra.Command {
	var format, output, input string
	cmd := &cobra.Command{
		Use:   "report",
		Short: a.b.T("cli.cmd.report"),
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			rep, err := report.Load(input)
			if errors.Is(err, report.ErrNoReport) {
				return errors.New(a.b.T("cli.no_report"))
			}
			if err != nil {
				return err
			}
			cat, _ := a.catalog()
			return a.render(rep, cat, format, output)
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "terminal", a.b.T("cli.flag.format"))
	cmd.Flags().StringVarP(&output, "output", "o", "", a.b.T("cli.flag.output"))
	cmd.Flags().StringVarP(&input, "input", "i", "", a.b.T("cli.flag.input"))
	return cmd
}

// render writes rep in the requested format.
func (a *app) render(rep *model.Report, cat *catalog.Catalog, format, output string) error {
	w := a.stdout
	if output != "" {
		f, err := os.Create(output)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	v := report.Build(rep, a.b, a.categoryTitles(cat))
	switch strings.ToLower(format) {
	case "", "terminal", "text":
		return report.WriteTerminal(w, v, report.TerminalOptions{Verbose: a.verbose})
	case "json":
		return report.WriteJSON(w, rep)
	default:
		return fmt.Errorf("unknown format %q (terminal, json)", format)
	}
}
