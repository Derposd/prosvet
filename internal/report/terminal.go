package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/Derposd/prosvet/internal/model"
	"github.com/Derposd/prosvet/internal/theme"
)

// TerminalOptions control the plain terminal output.
type TerminalOptions struct {
	Verbose bool // print every target's evidence and endpoints
	Brief   bool // only the status table, DNS findings and the summary
	Width   int
}

// WriteTerminal prints a human-friendly report.
func WriteTerminal(w io.Writer, v *View, opt TerminalOptions) error {
	var sb strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&sb, format, a...) }

	p("%s %s\n", theme.Title.Render("Prosvet"), theme.Dim.Render("· "+v.Tagline))
	if v.Demo {
		p("%s\n", theme.Warn.Render("⚠ "+v.DemoBanner))
	}
	p("%s %s\n", theme.Dim.Render("●"), v.Network.Line)
	if v.Started != "" {
		p("%s\n", theme.Dim.Render(strings.TrimSpace(v.Started+"  "+v.Duration)))
	}
	for _, n := range v.Notices {
		p("%s\n", theme.Warn.Render("⚠ "+n))
	}

	nameW := 4
	for _, g := range v.Groups {
		for _, t := range g.Targets {
			nameW = max(nameW, lipgloss.Width(t.Name))
		}
	}
	nameW = min(nameW, 28)
	statusW := 0
	for _, g := range v.Groups {
		for _, t := range g.Targets {
			statusW = max(statusW, lipgloss.Width(t.StatusText))
		}
	}

	for _, g := range v.Groups {
		p("\n%s\n", theme.Heading.Render(strings.ToUpper(g.Title)))
		for _, t := range g.Targets {
			name := t.Name
			if lipgloss.Width(name) > nameW {
				name = string([]rune(name)[:nameW-1]) + "…"
			}
			pad := strings.Repeat(" ", max(0, statusW-lipgloss.Width(t.StatusText)))
			line := fmt.Sprintf("  %s %-*s  %s", theme.Dot(t.Status), nameW, name, theme.StatusLabel(t.Status, t.StatusText))
			if t.Status != model.StatusOK {
				detail := t.KindTitle
				if t.Subtype != "" {
					detail += " — " + t.Subtype
				}
				line += pad + theme.Dim.Render("  "+detail+" · "+t.Confidence)
			} else if len(t.Secondary) > 0 {
				line += pad + theme.Dim.Render("  ("+strings.Join(t.Secondary, ", ")+")")
			}
			p("%s\n", line)
			if opt.Verbose {
				writeDetails(&sb, t, "      ")
			}
		}
	}

	if v.DNS != nil {
		p("\n%s\n", theme.Heading.Render(strings.ToUpper(v.Labels.DNS)))
		if len(v.DNS.Findings) == 0 {
			p("  %s %s\n", theme.Dot(model.StatusOK), theme.Dim.Render(v.Labels.DNSNone))
		}
		for _, f := range v.DNS.Findings {
			p("  %s %s\n", theme.Dot(model.StatusBlocked), f)
		}
	}
	if v.Whitelist != nil {
		writeWhitelist(&sb, v.Whitelist)
	}

	if !opt.Verbose && !opt.Brief && len(v.Problems) > 0 {
		p("\n%s\n", theme.Heading.Render(strings.ToUpper(v.Labels.Problems)))
		for i, t := range v.Problems {
			if i >= 8 {
				p("  %s\n", theme.Dim.Render(fmt.Sprintf("… +%d", len(v.Problems)-i)))
				break
			}
			p("  %s %s — %s\n", theme.Dot(t.Status), theme.Bold.Render(t.Name), t.KindTitle)
			p("    %s\n", dimLines(wrap(t.Explain, 96, "    ")))
			for j, e := range t.Evidence {
				if j >= 3 {
					break
				}
				p("    %s %s\n", theme.Dim.Render("·"), e)
			}
		}
	}

	if v.Baseline != "" {
		p("\n%s\n", theme.Dim.Render(v.Baseline))
	}
	p("\n%s\n", theme.Bold.Render(v.SummaryText))
	_, err := io.WriteString(w, sb.String())
	return err
}

func writeDetails(sb *strings.Builder, t TargetView, indent string) {
	if t.Status != model.StatusOK {
		fmt.Fprintf(sb, "%s%s\n", indent, dimLines(wrap(t.Explain, 92, indent)))
	}
	for _, e := range t.Evidence {
		fmt.Fprintf(sb, "%s· %s\n", indent, e)
	}
	for _, ep := range t.Endpoints {
		label := ep.KindTitle
		if ep.Subtype != "" {
			label += " — " + ep.Subtype
		}
		fmt.Fprintf(sb, "%s%s %s\n", indent, theme.Dim.Render(ep.Name+":"), label)
	}
	if t.Expect != "" {
		fmt.Fprintf(sb, "%s%s\n", indent, theme.Dim.Render(t.Expect))
	}
}

func writeWhitelist(sb *strings.Builder, w *WhitelistView) {
	status := model.StatusOK
	switch w.Verdict {
	case model.WhitelistActive:
		status = model.StatusBlocked
	case model.WhitelistDegraded:
		status = model.StatusPartial
	case model.WhitelistNoConnectivity:
		status = model.StatusUnreachable
	}
	fmt.Fprintf(sb, "\n%s %s\n", theme.Dot(status), theme.StatusLabel(status, w.Title))
	fmt.Fprintf(sb, "  %s\n", wrap(w.Explain, 96, "  "))
	fmt.Fprintf(sb, "  %s\n", theme.Dim.Render(w.Counts))
	if w.Level != "" {
		fmt.Fprintf(sb, "  %s\n", theme.Dim.Render("→ "+w.Level))
	}
}

// WriteWhitelist prints only a whitelist result.
func WriteWhitelist(w io.Writer, v *WhitelistView, verbose bool) error {
	var sb strings.Builder
	writeWhitelist(&sb, v)
	if verbose {
		for _, group := range [][]WLHostView{v.Domestic, v.Foreign} {
			sb.WriteString("\n")
			for _, h := range group {
				st := model.StatusOK
				if !h.OK {
					st = model.StatusBlocked
				}
				fmt.Fprintf(&sb, "  %s %-24s %s\n", theme.Dot(st), h.Host, theme.Dim.Render(h.Org+" "+h.Stage))
			}
		}
	}
	_, err := io.WriteString(w, sb.String())
	return err
}

// dimLines renders each line separately, so lipgloss does not pad lines of a
// multi-line block to the same width (which leaves trailing spaces).
func dimLines(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = theme.Dim.Render(l)
	}
	return strings.Join(lines, "\n")
}

// wrap breaks text into lines of at most width runes.
func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	var lines []string
	var cur []rune
	for _, w := range words {
		wr := []rune(w)
		if len(cur) > 0 && len(cur)+1+len(wr) > width {
			lines = append(lines, string(cur))
			cur = nil
		}
		if len(cur) > 0 {
			cur = append(cur, ' ')
		}
		cur = append(cur, wr...)
	}
	if len(cur) > 0 {
		lines = append(lines, string(cur))
	}
	return strings.Join(lines, "\n"+indent)
}
