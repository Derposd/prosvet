// Package cli implements the prosvet command line.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/Derposd/prosvet/internal/catalog"
	"github.com/Derposd/prosvet/internal/i18n"
	"github.com/Derposd/prosvet/targets"
)

// BuildInfo is injected at link time.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

// app holds state shared by all commands.
type app struct {
	build      BuildInfo
	b          *i18n.Bundle
	lang       string
	noColor    bool
	targetsDir string
	yes        bool
	verbose    bool
	brief      bool
	stdout     io.Writer
	stderr     io.Writer
	stdin      io.Reader
}

// Execute runs the CLI and returns the process exit code.
func Execute(build BuildInfo) int {
	a := &app{build: build, stdout: os.Stdout, stderr: os.Stderr, stdin: os.Stdin}
	a.lang = preparseLang(os.Args[1:])
	a.b = i18n.New(a.lang)
	root := a.rootCmd()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := root.ExecuteContext(ctx); err != nil {
		if !errors.Is(err, errAborted) {
			fmt.Fprintln(a.stderr, "prosvet:", err)
		}
		return 1
	}
	return 0
}

var errAborted = errors.New("aborted")

// preparseLang finds --lang before cobra parses flags, so help texts can be localised.
func preparseLang(args []string) string {
	for i, arg := range args {
		if v, ok := strings.CutPrefix(arg, "--lang="); ok {
			return v
		}
		if arg == "--lang" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return i18n.Detect()
}

func (a *app) rootCmd() *cobra.Command {
	b := a.b
	root := &cobra.Command{
		Use:           "prosvet",
		Short:         b.T("cli.short"),
		Long:          b.T("cli.long"),
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       a.build.Version,
		PersistentPreRun: func(*cobra.Command, []string) {
			if a.noColor || os.Getenv("NO_COLOR") != "" {
				lipgloss.SetColorProfile(termenv.Ascii)
			}
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if isTerminal(os.Stdout) && isTerminal(os.Stdin) {
				return a.runTUI(cmd.Context())
			}
			return a.runScan(cmd.Context(), defaultScanFlags())
		},
	}
	pf := root.PersistentFlags()
	pf.StringVar(&a.lang, "lang", a.lang, b.T("cli.flag.lang"))
	pf.BoolVar(&a.noColor, "no-color", false, b.T("cli.flag.no_color"))
	pf.StringVar(&a.targetsDir, "targets-dir", "", b.T("cli.flag.targets_dir"))
	pf.BoolVarP(&a.yes, "yes", "y", false, b.T("cli.flag.yes"))
	pf.BoolVarP(&a.verbose, "verbose", "v", false, b.T("cli.flag.verbose"))
	pf.BoolVar(&a.brief, "brief", false, b.T("cli.flag.brief"))

	root.AddCommand(a.scanCmd(), a.whitelistCmd(), a.targetsCmd(), a.versionCmd(), a.reportCmd(),
		a.submitCmd(), a.serveCmd(), a.demoCmd())
	return root
}

func (a *app) catalog() (*catalog.Catalog, error) {
	return catalog.LoadWithOverrides(targets.FS, a.targetsDir)
}

func isTerminal(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

// confirm asks a yes/no question on the terminal. Without a terminal it
// returns def. --yes always answers yes.
func (a *app) confirm(question string, def bool) bool {
	if a.yes {
		return true
	}
	if !isTerminal(os.Stdin) {
		return def
	}
	fmt.Fprint(a.stderr, question)
	var answer string
	_, _ = fmt.Fscanln(a.stdin, &answer)
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes" || answer == "д" || answer == "да"
}
