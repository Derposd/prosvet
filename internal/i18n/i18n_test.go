package i18n

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/ordinarysim/prosvet/internal/model"
)

var placeholder = regexp.MustCompile(`\{[a-z_]+\}`)

func TestLocalesHaveSameKeysAndPlaceholders(t *testing.T) {
	langs := Languages()
	if len(langs) < 2 {
		t.Fatalf("expected at least ru and en, got %v", langs)
	}
	base := Keys(Fallback)
	for _, l := range langs {
		keys := Keys(l)
		for k, v := range base {
			other, ok := keys[k]
			if !ok {
				t.Errorf("%s: missing key %s", l, k)
				continue
			}
			a, b := placeholder.FindAllString(v, -1), placeholder.FindAllString(other, -1)
			sort.Strings(a)
			sort.Strings(b)
			if strings.Join(a, ",") != strings.Join(b, ",") {
				t.Errorf("%s: placeholders of %s differ: %v vs %v", l, k, a, b)
			}
		}
		for k := range keys {
			if _, ok := base[k]; !ok {
				t.Errorf("%s: extra key %s not in %s", l, k, Fallback)
			}
		}
	}
}

func TestEveryKindAndStatusIsTranslated(t *testing.T) {
	for _, lang := range Languages() {
		b := New(lang)
		for _, k := range model.AllKinds {
			for _, suffix := range []string{".title", ".explain"} {
				if !b.Has("kind." + string(k) + suffix) {
					t.Errorf("%s: kind %s%s missing", lang, k, suffix)
				}
			}
		}
		for _, s := range []model.Status{model.StatusOK, model.StatusThrottled, model.StatusPartial, model.StatusBlocked, model.StatusUnreachable, model.StatusUnknown} {
			if !b.Has("status." + string(s)) {
				t.Errorf("%s: status %s missing", lang, s)
			}
		}
	}
}

// TestEvidenceKeysExist scans the classifier sources for evidence keys.
func TestEvidenceKeysExist(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(file), "..", "classify")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`"(ev\.[a-z0-9_.]+)"`)
	b := New(Fallback)
	found := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), "_test.go") || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(src), -1) {
			found++
			if !b.Has(m[1]) {
				t.Errorf("evidence key %s used in %s is not translated", m[1], e.Name())
			}
		}
	}
	if found < 20 {
		t.Fatalf("only %d evidence keys found; scanner broken?", found)
	}
}

func TestRender(t *testing.T) {
	ru := New("ru_RU.UTF-8")
	if ru.Lang != "ru" {
		t.Fatalf("lang %s", ru.Lang)
	}
	got := ru.T("ev.runs", "agree", "2", "runs", "3")
	if got != "Наблюдалось в 2 из 3 попыток." {
		t.Fatalf("got %q", got)
	}
	if New("xx").Lang != Fallback {
		t.Fatal("unknown language must fall back")
	}
	if New("en").T("no.such.key") != "no.such.key" {
		t.Fatal("missing key must render as key")
	}
}

func TestDetectEnv(t *testing.T) {
	t.Setenv("PROSVET_LANG", "ru")
	if Detect() != "ru" {
		t.Fatal("PROSVET_LANG not honoured")
	}
	t.Setenv("PROSVET_LANG", "")
	t.Setenv("LC_ALL", "en_US.UTF-8")
	if Detect() != "en" {
		t.Fatal("LC_ALL not honoured")
	}
}
