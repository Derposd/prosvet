// Command prosvet is a network diagnostics & censorship measurement tool.
package main

import (
	"os"
	"runtime/debug"

	"github.com/Derposd/prosvet/internal/cli"
)

// Set by the linker (see .goreleaser.yaml).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	v, c, d := version, commit, date
	if v == "dev" {
		// `go install …@vX.Y.Z` builds without linker flags: use module info.
		if bi, ok := debug.ReadBuildInfo(); ok {
			if bi.Main.Version != "" && bi.Main.Version != "(devel)" {
				v = bi.Main.Version
			}
			for _, s := range bi.Settings {
				switch s.Key {
				case "vcs.revision":
					if len(s.Value) >= 7 {
						c = s.Value[:7]
					}
				case "vcs.time":
					d = s.Value
				}
			}
		}
	}
	os.Exit(cli.Execute(cli.BuildInfo{Version: v, Commit: c, Date: d}))
}
