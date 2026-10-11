// Package targets embeds the default target lists shipped with Prosvet.
//
// The YAML files in this directory are the source of truth; see README.md for the schema.
package targets

import "embed"

// FS holds every *.yaml file of this directory.
//
//go:embed *.yaml
var FS embed.FS
