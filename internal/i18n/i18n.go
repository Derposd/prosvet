// Package i18n loads the translation files and renders localised messages.
package i18n

import (
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/ordinarysim/prosvet/internal/model"
	"github.com/ordinarysim/prosvet/locales"
)

// Fallback is the language used for missing keys.
const Fallback = "en"

// Bundle renders messages for one language.
type Bundle struct {
	Lang     string
	msgs     map[string]string
	fallback map[string]string
}

var (
	loadOnce sync.Once
	catalogs map[string]map[string]string
	loadErr  error
)

func load() {
	catalogs = map[string]map[string]string{}
	files, err := fs.Glob(locales.FS, "*.yaml")
	if err != nil {
		loadErr = err
		return
	}
	for _, f := range files {
		b, err := fs.ReadFile(locales.FS, f)
		if err != nil {
			loadErr = err
			return
		}
		var tree map[string]any
		if err := yaml.Unmarshal(b, &tree); err != nil {
			loadErr = fmt.Errorf("%s: %w", f, err)
			return
		}
		flat := map[string]string{}
		flatten("", tree, flat)
		catalogs[strings.TrimSuffix(f, ".yaml")] = flat
	}
}

func flatten(prefix string, v any, out map[string]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, sub := range t {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			flatten(key, sub, out)
		}
	default:
		out[prefix] = fmt.Sprint(t)
	}
}

// Languages returns the available language codes.
func Languages() []string {
	loadOnce.Do(load)
	var out []string
	for l := range catalogs {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// Keys returns all keys of a language (for tests).
func Keys(lang string) map[string]string {
	loadOnce.Do(load)
	return catalogs[lang]
}

// New returns a bundle for lang ("" or unknown → detected/fallback).
func New(lang string) *Bundle {
	loadOnce.Do(load)
	if loadErr != nil {
		panic("i18n: embedded locales are invalid: " + loadErr.Error())
	}
	lang = Normalize(lang)
	if _, ok := catalogs[lang]; !ok {
		lang = Fallback
	}
	return &Bundle{Lang: lang, msgs: catalogs[lang], fallback: catalogs[Fallback]}
}

// Normalize maps locale strings like "ru_RU.UTF-8" or "ru-RU" to "ru".
func Normalize(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.IndexAny(s, "_-.@"); i > 0 {
		s = s[:i]
	}
	return s
}

// Has reports whether the key exists.
func (b *Bundle) Has(key string) bool {
	_, ok := b.msgs[key]
	if !ok {
		_, ok = b.fallback[key]
	}
	return ok
}

// T renders key with "name", "value" argument pairs.
func (b *Bundle) T(key string, kv ...string) string {
	args := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		args[kv[i]] = kv[i+1]
	}
	return b.TA(key, args)
}

// TA renders key with an argument map.
func (b *Bundle) TA(key string, args map[string]string) string {
	s, ok := b.msgs[key]
	if !ok {
		if s, ok = b.fallback[key]; !ok {
			return key
		}
	}
	for k, v := range args {
		s = strings.ReplaceAll(s, "{"+k+"}", v)
	}
	return s
}

// Evidence renders an evidence line.
func (b *Bundle) Evidence(e model.Evidence) string { return b.TA(e.Key, e.Args) }

// KindTitle returns the localised title of a verdict kind.
func (b *Bundle) KindTitle(k model.Kind) string { return b.T("kind." + string(k) + ".title") }

// KindExplain returns the plain-language explanation of a verdict kind.
func (b *Bundle) KindExplain(k model.Kind) string { return b.T("kind." + string(k) + ".explain") }

// Subtype returns the label of a verdict subtype ("" when unknown).
func (b *Bundle) Subtype(s string) string {
	if s == "" {
		return ""
	}
	if b.Has("subtype." + s) {
		return b.T("subtype." + s)
	}
	return s
}

// Status returns the localised status label.
func (b *Bundle) Status(s model.Status) string { return b.T("status." + string(s)) }

// Confidence returns the localised confidence label.
func (b *Bundle) Confidence(c model.Confidence) string { return b.T("conf." + string(c)) }

// Detect returns the preferred language from PROSVET_LANG, the POSIX locale
// variables or the operating system settings.
func Detect() string {
	for _, v := range []string{"PROSVET_LANG", "LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"} {
		if s := os.Getenv(v); s != "" && s != "C" && s != "POSIX" {
			if l := Normalize(strings.Split(s, ":")[0]); l != "" {
				return l
			}
		}
	}
	if l := osLanguage(); l != "" {
		return Normalize(l)
	}
	return Fallback
}
