// Package locales embeds the translation files. Every user-facing string of
// Prosvet lives in these YAML files; see CONTRIBUTING.md to add a language.
package locales

import "embed"

// FS holds every *.yaml translation file.
//
//go:embed *.yaml
var FS embed.FS
