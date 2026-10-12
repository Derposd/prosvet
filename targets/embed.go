// Package targets embeds the default target lists shipped with Prosvet.
//
// The YAML files in this directory are the source of truth; see README.md for the schema.
package targets

import "embed"

// FS holds every *.yaml file of this directory.
//
//go:embed *.yaml
var FS embed.FS

// Schema is the JSON Schema for the YAML files in this directory. It powers
// editor completion and is verified against every file by schema_test.go.
//
//go:embed schema.json
var Schema []byte
