// Command goldgen produces golden engine.Result JSON for a set of fixtures, so
// the pure-JS engine reimplementation can be verified field-for-field against
// the original Go engine.
//
// It runs the real internal/engine with a deterministic fake resolver (canned
// DoH answers from the fixture), so no network is needed and output is stable.
//
//   go run ./cmd/goldgen            # regenerate testdata/golden/*.json
//   go run ./cmd/goldgen -check     # verify golden files are up to date
//
// The same testdata/fixtures.json is consumed by the JS test runner
// (test/run.mjs), which feeds the same canned answers to the JS engine and
// deep-compares its Result against these golden files.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"sing-vis/internal/dnsx"
	"sing-vis/internal/engine"
)

// fixtureFile is the on-disk shape of testdata/fixtures.json.
type fixtureFile struct {
	Cases []fixtureCase `json:"cases"`
}

type fixtureCase struct {
	Name           string                     `json:"name"`
	Config         json.RawMessage            `json:"config"` // a real JSON object
	Inputs         []string                   `json:"inputs"`
	Network        string                     `json:"network,omitempty"`
	Protocol       string                     `json:"protocol,omitempty"`
	AssumeResolved *bool                      `json:"assumeResolved,omitempty"` // default true
	DNS            map[string]cannedAnswer    `json:"dns,omitempty"`
	RuleSetFiles   map[string]fixtureRuleFile `json:"ruleSetFiles,omitempty"`
}

type cannedAnswer struct {
	IPv4  []string `json:"ipv4,omitempty"`
	IPv6  []string `json:"ipv6,omitempty"`
	Error string   `json:"error,omitempty"`
}

// fixtureRuleFile mirrors engine.RuleSetFile but lets "source" data be given as
// a JSON object (re-marshaled to text) for readability.
type fixtureRuleFile struct {
	Format string          `json:"format"`
	Data   json.RawMessage `json:"data"`
}

// fakeResolver returns canned DoH answers so route/DNS matching is deterministic.
type fakeResolver struct {
	answers map[string]cannedAnswer
}

func (f *fakeResolver) Server() string { return "fake-doh" }

func (f *fakeResolver) Resolve(_ context.Context, name string, _ string) (*dnsx.Result, error) {
	if a, ok := f.answers[name]; ok {
		return &dnsx.Result{Name: name, IPv4: a.IPv4, IPv6: a.IPv6, Error: a.Error}, nil
	}
	return &dnsx.Result{Name: name}, nil
}

func main() {
	check := flag.Bool("check", false, "verify golden files are up to date instead of writing")
	flag.Parse()

	root := repoRoot()
	fixturePath := filepath.Join(root, "testdata", "fixtures.json")
	goldenDir := filepath.Join(root, "testdata", "golden")

	raw, err := os.ReadFile(fixturePath)
	must(err)
	var ff fixtureFile
	must(json.Unmarshal(raw, &ff))

	if !*check {
		must(os.MkdirAll(goldenDir, 0o755))
	}

	seen := map[string]bool{}
	failed := false
	for _, c := range ff.Cases {
		if seen[c.Name] {
			fmt.Fprintf(os.Stderr, "duplicate fixture name %q\n", c.Name)
			os.Exit(1)
		}
		seen[c.Name] = true

		got, err := runCase(c)
		if err != nil {
			fmt.Fprintf(os.Stderr, "case %q: %v\n", c.Name, err)
			os.Exit(1)
		}
		out := filepath.Join(goldenDir, c.Name+".json")
		if *check {
			want, err := os.ReadFile(out)
			if err != nil || !bytes.Equal(want, got) {
				fmt.Fprintf(os.Stderr, "OUT OF DATE: %s\n", c.Name)
				failed = true
			}
			continue
		}
		must(os.WriteFile(out, got, 0o644))
		fmt.Printf("wrote %s\n", filepath.Base(out))
	}
	if failed {
		os.Exit(1)
	}
}

func runCase(c fixtureCase) ([]byte, error) {
	assume := true
	if c.AssumeResolved != nil {
		assume = *c.AssumeResolved
	}
	files := map[string]engine.RuleSetFile{}
	for k, v := range c.RuleSetFiles {
		files[k] = engine.RuleSetFile{Format: v.Format, Data: string(v.Data)}
	}
	res, err := engine.Analyze(context.Background(), engine.Request{
		Config:         string(c.Config),
		Inputs:         c.Inputs,
		RuleSetFiles:   files,
		Network:        c.Network,
		Protocol:       c.Protocol,
		AssumeResolved: assume,
		Resolver:       &fakeResolver{answers: c.DNS},
	})
	if err != nil {
		// Encode parse/analyze errors as a stable object so the JS side can assert
		// the same failure mode.
		return marshalIndent(map[string]string{"error": err.Error()})
	}
	return marshalIndent(res)
}

func marshalIndent(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func repoRoot() string {
	// goldgen lives at <root>/cmd/goldgen; walk up to the module root (has go.mod).
	dir, err := os.Getwd()
	must(err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	// Fallback: assume CWD is the repo root.
	wd, _ := os.Getwd()
	return wd
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
