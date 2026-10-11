// Package report renders scan reports (terminal, JSON, Markdown, HTML) and
// stores the last report locally.
package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Derposd/prosvet/internal/model"
)

// ErrNoReport is returned when no report has been saved yet.
var ErrNoReport = errors.New("no saved report")

// Dir returns the local data directory (created on demand).
func Dir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "prosvet")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// LastPath is where the most recent report is kept.
func LastPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "last-report.json"), nil
}

// SaveLast stores rep as the most recent report and returns the path.
func SaveLast(rep *model.Report) (string, error) {
	p, err := LastPath()
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp(filepath.Dir(p), "report-*.json")
	if err != nil {
		return "", err
	}
	if err := WriteJSON(f, rep); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(f.Name(), p); err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return p, nil
}

// Load reads a report from path ("" means the last saved report).
func Load(path string) (*model.Report, error) {
	if path == "" {
		p, err := LastPath()
		if err != nil {
			return nil, err
		}
		path = p
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoReport
	}
	if err != nil {
		return nil, err
	}
	var rep model.Report
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if rep.Schema != model.ReportSchema {
		return nil, fmt.Errorf("%s: unsupported schema %q", path, rep.Schema)
	}
	return &rep, nil
}

// WriteJSON writes the report as indented JSON.
func WriteJSON(w io.Writer, rep *model.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(rep)
}
