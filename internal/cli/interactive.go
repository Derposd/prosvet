package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/Derposd/prosvet/internal/catalog"
	"github.com/Derposd/prosvet/internal/demo"
	"github.com/Derposd/prosvet/internal/engine"
	"github.com/Derposd/prosvet/internal/model"
	"github.com/Derposd/prosvet/internal/report"
	"github.com/Derposd/prosvet/internal/serve"
	"github.com/Derposd/prosvet/internal/submit"
	"github.com/Derposd/prosvet/internal/theme"
	"github.com/Derposd/prosvet/internal/tui"
)

func (a *app) consentMarker() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "prosvet", "consent")
}

func (a *app) needConsent() bool {
	m := a.consentMarker()
	if m == "" || a.yes {
		return false
	}
	_, err := os.Stat(m)
	return err != nil
}

func (a *app) saveConsent() {
	if m := a.consentMarker(); m != "" {
		if err := os.MkdirAll(filepath.Dir(m), 0o700); err == nil {
			_ = os.WriteFile(m, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600)
		}
	}
}

func saveReport(rep *model.Report) { _, _ = report.SaveLast(rep) }

func loadReport() (*model.Report, error) { return report.Load("") }

func (a *app) runTUI(ctx context.Context) error {
	cat, err := a.catalog()
	if err != nil {
		return err
	}
	f := defaultScanFlags()
	env := a.newEnv(1)
	return tui.Run(ctx, tui.Deps{
		Bundle:  a.b,
		Catalog: cat,
		NewEngine: func() *engine.Engine {
			opt := engine.DefaultOptions()
			opt.Version, opt.Commit = a.build.Version, a.build.Commit
			return engine.New(a.newEnv(1), cat, opt)
		},
		DetectNetwork: func(ctx context.Context) model.NetworkInfo { return a.detectNetwork(ctx, env, f) },
		NeedConsent:   a.needConsent(),
		SaveConsent:   a.saveConsent,
		SaveReport:    saveReport,
		LoadReport:    loadReport,
	})
}

func (a *app) demoCmd() *cobra.Command {
	var useTUI bool
	var format string
	cmd := &cobra.Command{
		Use:   "demo",
		Short: a.b.T("cli.cmd.demo"),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			env, err := demo.Start(a.build.Version)
			if err != nil {
				return err
			}
			defer env.Close()
			if useTUI {
				return tui.Run(cmd.Context(), tui.Deps{
					Bundle: a.b, Catalog: env.Catalog, Demo: true, AutoStart: true,
					NewEngine:     func() *engine.Engine { return env.Engine },
					DetectNetwork: func(context.Context) model.NetworkInfo { return demo.Network },
				})
			}
			fmt.Fprintln(a.stderr, theme.Warn.Render(a.b.T("cli.demo_note")))
			events := make(chan engine.Event, 64)
			done := make(chan struct{})
			go func() {
				newProgress(a.stderr, a.b).run(events)
				close(done)
			}()
			rep, err := env.Engine.Scan(cmd.Context(), catalog.Selection{}, demo.Network, events)
			close(events)
			<-done
			if rep == nil {
				return err
			}
			return a.render(rep, env.Catalog, format, "")
		},
	}
	cmd.Flags().BoolVar(&useTUI, "tui", false, "interactive TUI")
	cmd.Flags().StringVarP(&format, "format", "f", "terminal", a.b.T("cli.flag.format"))
	return cmd
}

func (a *app) serveCmd() *cobra.Command {
	var addr string
	var open, all, demoMode bool
	cmd := &cobra.Command{
		Use:   "serve",
		Short: a.b.T("cli.cmd.serve"),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ln, err := serve.Listen(addr)
			if err != nil {
				return err
			}
			if demoMode {
				return a.serveDemo(cmd.Context(), ln, open)
			}
			cat, err := a.catalog()
			if err != nil {
				return err
			}
			if err := a.consentOnce(); err != nil {
				return err
			}
			if all {
				var optIn []*catalog.Category
				for _, c := range cat.Categories {
					if len(c.Consent) > 0 {
						optIn = append(optIn, c)
					}
				}
				if err := a.optInConsent(optIn); err != nil {
					return err
				}
			}
			f := defaultScanFlags()
			env := a.newEnv(1)
			srv, err := serve.New(serve.Deps{
				Bundle: a.b, Catalog: cat, AllowOptIn: all,
				NewEngine: func() *engine.Engine {
					opt := engine.DefaultOptions()
					opt.Version, opt.Commit = a.build.Version, a.build.Commit
					return engine.New(a.newEnv(1), cat, opt)
				},
				DetectNetwork: func(ctx context.Context) model.NetworkInfo { return a.detectNetwork(ctx, env, f) },
				SaveReport:    saveReport,
				LoadReport:    loadReport,
			})
			if err != nil {
				return err
			}
			return a.runServer(cmd.Context(), srv, ln, open)
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8787", "listen address (loopback only)")
	cmd.Flags().BoolVar(&open, "open", false, "open the dashboard in the browser")
	cmd.Flags().BoolVar(&all, "all", false, a.b.T("cli.flag.all"))
	cmd.Flags().BoolVar(&demoMode, "demo", false, "serve the dashboard on the simulated demo network")
	return cmd
}

func (a *app) runServer(ctx context.Context, srv *serve.Server, ln net.Listener, open bool) error {
	url := "http://" + ln.Addr().String() + "/"
	fmt.Fprintf(a.stderr, "%s %s\n", theme.Title.Render("Prosvet"), url)
	fmt.Fprintln(a.stderr, theme.Dim.Render(a.b.T("dash.local_only")))
	if open {
		openBrowser(url)
	}
	return srv.Serve(ctx, ln)
}

// serveDemo runs the dashboard against the simulated network. Reports are
// kept in memory only, so the user's saved report is never overwritten.
func (a *app) serveDemo(ctx context.Context, ln net.Listener, open bool) error {
	env, err := demo.Start(a.build.Version)
	if err != nil {
		return err
	}
	defer env.Close()
	fmt.Fprintln(a.stderr, theme.Warn.Render(a.b.T("cli.demo_note")))
	srv, err := serve.New(serve.Deps{
		Bundle: a.b, Catalog: env.Catalog,
		NewEngine:     func() *engine.Engine { return env.Engine },
		DetectNetwork: func(context.Context) model.NetworkInfo { return demo.Network },
	})
	if err != nil {
		return err
	}
	return a.runServer(ctx, srv, ln, open)
}

func openBrowser(url string) {
	ctx := context.Background()
	var c *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		c = exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		c = exec.CommandContext(ctx, "open", url)
	default:
		c = exec.CommandContext(ctx, "xdg-open", url)
	}
	_ = c.Start()
}

func (a *app) submitCmd() *cobra.Command {
	var input, dir string
	var allowVPN bool
	cmd := &cobra.Command{
		Use:   "submit",
		Short: a.b.T("cli.cmd.submit"),
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			rep, err := report.Load(input)
			if errors.Is(err, report.ErrNoReport) {
				return errors.New(a.b.T("cli.no_report"))
			}
			if err != nil {
				return err
			}
			sub, err := submit.Build(rep, allowVPN)
			if err != nil {
				return err
			}
			data, err := submit.Marshal(sub)
			if err != nil {
				return err
			}
			fmt.Fprintln(a.stderr, theme.Bold.Render(a.b.T("cli.submit_preview")))
			fmt.Fprintln(a.stdout, string(data))
			if !a.confirm(a.b.T("cli.submit_confirm"), false) {
				fmt.Fprintln(a.stderr, a.b.T("cli.aborted"))
				return errAborted
			}
			path, err := submit.Write(dir, sub)
			if err != nil {
				return err
			}
			fmt.Fprintln(a.stderr, theme.Title.Render(a.b.T("cli.submit_written", "path", path)))
			fmt.Fprintln(a.stderr, a.b.T("cli.submit_next", "url", submit.IssueURL()))
			return nil
		},
	}
	cmd.Flags().StringVarP(&input, "input", "i", "", a.b.T("cli.flag.input"))
	cmd.Flags().StringVar(&dir, "dir", "results", "output directory (results/ in a clone of the repository)")
	cmd.Flags().BoolVar(&allowVPN, "allow-vpn", false, "submit even if a VPN seems active (not recommended)")
	return cmd
}
