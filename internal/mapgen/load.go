// Package mapgen aggregates submitted result files into the data of the
// public map and writes the static site (no server, no external resources).
package mapgen

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ordinarysim/prosvet/internal/submit"
)

// Entry is one valid submission together with its repository path.
type Entry struct {
	Path string
	Sub  submit.Submission
}

// Problem describes a rejected file.
type Problem struct {
	Path string
	Err  error
}

func (p Problem) Error() string { return p.Path + ": " + p.Err.Error() }

var nameRe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2})-[0-9a-f]{6}\.json$`)

// CheckFile validates a submission file and its location
// (<root>/AS<asn>/<date>-<hex6>.json, matching the content).
func CheckFile(root, path string) (*submit.Submission, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := submit.Validate(data); err != nil {
		return nil, err
	}
	var s submit.Submission
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("file must be located at AS<asn>/<date>-<id>.json")
	}
	if parts[0] != "AS"+strconv.Itoa(s.Network.ASN) {
		return nil, fmt.Errorf("directory %s does not match ASN %d in the file", parts[0], s.Network.ASN)
	}
	m := nameRe.FindStringSubmatch(parts[1])
	if m == nil {
		return nil, fmt.Errorf("file name must look like <date>-<6 hex>.json")
	}
	if m[1] != s.Date {
		return nil, fmt.Errorf("file name date %s does not match %s in the file", m[1], s.Date)
	}
	return &s, nil
}

// Load reads every submission under root. Invalid files are returned as problems.
func Load(root string) ([]Entry, []Problem, error) {
	var entries []Entry
	var problems []Problem
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		s, checkErr := CheckFile(root, path)
		if checkErr != nil {
			problems = append(problems, Problem{Path: path, Err: checkErr})
			return nil //nolint:nilerr // an invalid file is reported, not fatal for the walk
		}
		entries = append(entries, Entry{Path: path, Sub: *s})
		return nil
	})
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Sub.Date != entries[j].Sub.Date {
			return entries[i].Sub.Date < entries[j].Sub.Date
		}
		return entries[i].Path < entries[j].Path
	})
	return entries, problems, err
}
