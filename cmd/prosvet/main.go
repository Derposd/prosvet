// Command prosvet is a network diagnostics & censorship measurement tool.
package main

import (
	"os"

	"github.com/ordinarysim/prosvet/internal/cli"
)

// Set by the linker (see .goreleaser.yaml).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	os.Exit(cli.Execute(cli.BuildInfo{Version: version, Commit: commit, Date: date}))
}
