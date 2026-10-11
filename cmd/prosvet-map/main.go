// Command prosvet-map validates submitted result files and builds the static
// public map (used by GitHub Actions; can be run locally).
//
//	prosvet-map -results results -out site            # build the site
//	prosvet-map -results results -validate [files...] # validate (all or given files)
//	prosvet-map -results results -issue body.md       # store a submission pasted into an issue
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Derposd/prosvet/internal/catalog"
	"github.com/Derposd/prosvet/internal/mapgen"
	"github.com/Derposd/prosvet/targets"
)

func main() {
	results := flag.String("results", "results", "directory with submitted result files")
	out := flag.String("out", "site", "output directory for the static site")
	assets := flag.String("assets", "docs/assets", "directory with social-preview.png")
	validate := flag.Bool("validate", false, "only validate result files (all, or the files given as arguments)")
	issue := flag.String("issue", "", "file with an issue body containing a submission to store")
	sample := flag.Bool("sample", false, "add clearly labelled sample data (local layout testing only)")
	flag.Parse()

	switch {
	case *issue != "":
		body, err := os.ReadFile(*issue)
		if err != nil {
			fail(err)
		}
		path, err := mapgen.FromIssue(body, *results)
		if err != nil {
			fail(err)
		}
		fmt.Println(path)
	case *validate:
		var problems []mapgen.Problem
		if flag.NArg() > 0 {
			problems = mapgen.ValidatePaths(*results, flag.Args())
		} else {
			entries, p, err := mapgen.Load(*results)
			if err != nil {
				fail(err)
			}
			problems = p
			fmt.Printf("%d valid submission(s)\n", len(entries))
		}
		report(problems)
		if len(problems) > 0 {
			os.Exit(1)
		}
	default:
		cat, err := catalog.Load(targets.FS)
		if err != nil {
			fail(err)
		}
		data, problems, err := mapgen.Build(cat, mapgen.Options{Results: *results, Out: *out, Assets: *assets, Sample: *sample})
		if err != nil {
			fail(err)
		}
		report(problems)
		fmt.Printf("map: %d submissions, %d networks, %d services -> %s\n", data.Submissions, len(data.Rows), len(data.Targets), *out)
	}
}

func report(problems []mapgen.Problem) {
	for _, p := range problems {
		fmt.Fprintln(os.Stderr, "invalid:", p.Error())
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "prosvet-map:", err)
	os.Exit(1)
}
