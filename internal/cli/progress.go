package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ordinarysim/prosvet/internal/engine"
	"github.com/ordinarysim/prosvet/internal/i18n"
	"github.com/ordinarysim/prosvet/internal/theme"
)

// progress prints scan progress to stderr: a live single line on terminals,
// one line per phase otherwise.
type progress struct {
	w   io.Writer
	b   *i18n.Bundle
	tty bool
}

func newProgress(w io.Writer, b *i18n.Bundle) *progress {
	f, ok := w.(*os.File)
	return &progress{w: w, b: b, tty: ok && isTerminal(f)}
}

func (p *progress) run(events <-chan engine.Event) {
	width := 0
	clear := func() {
		if p.tty && width > 0 {
			fmt.Fprintf(p.w, "\r%s\r", strings.Repeat(" ", width))
			width = 0
		}
	}
	for ev := range events {
		switch ev.Kind {
		case engine.EventStarted:
			fmt.Fprintln(p.w, theme.Dim.Render(p.b.T("cli.scanning", "total", fmt.Sprint(ev.Total))))
		case engine.EventPhase:
			if ev.Phase == engine.PhaseWL && ev.Done > 0 {
				if p.tty {
					line := fmt.Sprintf("[%d/%d]", ev.Done, ev.Total)
					clear()
					fmt.Fprint(p.w, theme.Dim.Render(line))
					width = len(line)
				}
				continue
			}
			clear()
			fmt.Fprintln(p.w, theme.Dim.Render(p.b.T("cli.phase."+ev.Phase)))
		case engine.EventTarget:
			if !p.tty || ev.Target == nil {
				continue
			}
			t := ev.Target
			line := fmt.Sprintf("[%d/%d] %s — %s", ev.Done, ev.Total, t.Name, p.b.Status(t.Status))
			clear()
			fmt.Fprint(p.w, theme.Dot(t.Status)+" "+theme.Dim.Render(line))
			width = len([]rune(line)) + 2
		case engine.EventFinished:
			clear()
		}
	}
	clear()
}
