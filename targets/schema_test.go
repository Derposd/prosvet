package targets

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

// schemaLine is the magic comment the YAML language server reads to find the
// schema. Every file in this directory must carry it so editors validate and
// complete these lists.
const schemaLine = "# yaml-language-server: $schema=schema.json"

func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(Schema))
	if err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("schema.json", doc); err != nil {
		t.Fatalf("add schema resource: %v", err)
	}
	sch, err := c.Compile("schema.json")
	if err != nil {
		t.Fatalf("schema does not compile: %v", err)
	}
	return sch
}

// yamlToJSON converts a YAML document to the generic JSON value the schema
// validator expects, mapping YAML timestamps and maps to JSON-shaped values.
func yamlToJSON(t *testing.T, raw []byte) any {
	t.Helper()
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var doc any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("decode YAML: %v", err)
	}
	// Round-trip through JSON so map[string]any / []any match the validator.
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("re-encode as JSON: %v", err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("re-read as JSON: %v", err)
	}
	return out
}

func TestTargetFilesMatchSchema(t *testing.T) {
	sch := compileSchema(t)
	files, err := fs.Glob(FS, "*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no target files embedded")
	}
	for _, name := range files {
		t.Run(name, func(t *testing.T) {
			raw, err := FS.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if err := sch.Validate(yamlToJSON(t, raw)); err != nil {
				t.Fatalf("%s does not match schema.json:\n%v", name, err)
			}
		})
	}
}

// Every list must point editors at the schema, otherwise completion silently
// stops working for files added later.
func TestTargetFilesReferenceSchema(t *testing.T) {
	files, err := fs.Glob(FS, "*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		raw, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), schemaLine) {
			t.Errorf("%s is missing %q", name, schemaLine)
		}
	}
}

// The schema must reject malformed files, so a broken list fails CI instead of
// shipping. These cases also prove the schema is not vacuously permissive.
func TestSchemaRejectsBrokenFiles(t *testing.T) {
	sch := compileSchema(t)
	cases := map[string]string{
		"unknown target field":   "version: 1\ncategory: x\ntitle: T\ndefault: true\ntargets:\n  - id: a\n    name: A\n    nope: 1\n    endpoints:\n      - host: example.com\n",
		"endpoint neither":       "version: 1\ncategory: x\ntitle: T\ndefault: true\ntargets:\n  - id: a\n    name: A\n    endpoints:\n      - port: 443\n",
		"endpoint both":          "version: 1\ncategory: x\ntitle: T\ndefault: true\ntargets:\n  - id: a\n    name: A\n    endpoints:\n      - host: example.com\n        addr: 1.1.1.1:443\n",
		"bad expect":             "version: 1\ncategory: x\ntitle: T\ndefault: true\ntargets:\n  - id: a\n    name: A\n    expect: maybe\n    endpoints:\n      - host: example.com\n",
		"unknown test":           "version: 1\ncategory: x\ntitle: T\ndefault: true\ntargets:\n  - id: a\n    name: A\n    endpoints:\n      - host: example.com\n        tests: [telepathy]\n",
		"missing required field": "version: 1\ntargets: []\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			value := yamlToJSON(t, []byte(doc))
			if err := sch.Validate(value); err == nil {
				t.Fatalf("schema accepted a broken file:\n%s", doc)
			}
		})
	}
}
