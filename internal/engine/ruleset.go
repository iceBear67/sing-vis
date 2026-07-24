package engine

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
)

// ruleSetResolver loads and evaluates rule sets referenced by rules.
type ruleSetResolver struct {
	ctx      context.Context
	byTag    map[string]option.RuleSet
	files    map[string]RuleSetFile
	loaded   map[string]*loadedRuleSet
	warnings *[]string
	http     *http.Client
}

type loadedRuleSet struct {
	tag   string
	typ   string
	rules []option.HeadlessRule
	err   string
}

func newRuleSetResolver(ctx context.Context, cfg *Config, files map[string]RuleSetFile, warnings *[]string) *ruleSetResolver {
	byTag := map[string]option.RuleSet{}
	for _, rs := range cfg.RouteRuleSets {
		for _, tag := range rs.Tag {
			byTag[tag] = rs
		}
	}
	return &ruleSetResolver{
		ctx:      ctx,
		byTag:    byTag,
		files:    files,
		loaded:   map[string]*loadedRuleSet{},
		warnings: warnings,
		http:     &http.Client{Timeout: 20 * time.Second},
	}
}

func (r *ruleSetResolver) load(tag string) *loadedRuleSet {
	if l, ok := r.loaded[tag]; ok {
		return l
	}
	l := &loadedRuleSet{tag: tag}
	r.loaded[tag] = l // set early to avoid cycles

	rs, ok := r.byTag[tag]
	if !ok {
		l.err = "rule_set not defined in route.rule_set"
		return l
	}
	l.typ = rs.Type
	switch rs.Type {
	case "inline":
		l.rules = rs.InlineOptions.Rules
	case "local":
		r.loadFromFile(l, rs)
	case "remote":
		r.loadRemote(l, rs)
	default:
		l.err = "unsupported rule_set type: " + rs.Type
	}
	return l
}

func (r *ruleSetResolver) loadFromFile(l *loadedRuleSet, rs option.RuleSet) {
	// Local rule sets read from an on-disk path we don't have; the user uploads
	// the file content keyed by the rule-set tag (or its path).
	f, ok := r.files[l.tag]
	if !ok {
		f, ok = r.files[rs.LocalOptions.Path]
	}
	if !ok {
		l.err = fmt.Sprintf("local rule-set file not provided (upload the file for tag %q or path %q)", l.tag, rs.LocalOptions.Path)
		return
	}
	format := f.Format
	if format == "" {
		format = rs.Format
	}
	if format == "" {
		format = ruleSetFormatFromPath(rs.LocalOptions.Path)
	}
	data := []byte(f.Data)
	if format == "binary" {
		if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(f.Data)); err == nil {
			data = decoded
		}
	}
	r.parseInto(l, data, format)
}

func (r *ruleSetResolver) loadRemote(l *loadedRuleSet, rs option.RuleSet) {
	url := rs.RemoteOptions.URL
	if url == "" {
		l.err = "remote rule-set has no url"
		return
	}
	format := rs.Format
	if format == "" {
		format = ruleSetFormatFromPath(url)
	}
	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, url, nil)
	if err != nil {
		l.err = err.Error()
		return
	}
	req.Header.Set("User-Agent", "sing-box")
	resp, err := r.http.Do(req)
	if err != nil {
		l.err = "fetch failed: " + err.Error()
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		l.err = fmt.Sprintf("fetch failed: HTTP %d", resp.StatusCode)
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		l.err = err.Error()
		return
	}
	r.parseInto(l, data, format)
}

func (r *ruleSetResolver) parseInto(l *loadedRuleSet, data []byte, format string) {
	if format == "binary" {
		compat, err := srs.Read(bytes.NewReader(data), true)
		if err != nil {
			l.err = "parse binary rule-set: " + err.Error()
			return
		}
		plain, err := compat.Upgrade()
		if err != nil {
			l.err = err.Error()
			return
		}
		l.rules = plain.Rules
		return
	}
	// source format
	var compat option.PlainRuleSetCompat
	if err := sjson.UnmarshalContext(r.ctx, data, &compat); err != nil {
		l.err = "parse source rule-set: " + err.Error()
		return
	}
	plain, err := compat.Upgrade()
	if err != nil {
		l.err = err.Error()
		return
	}
	l.rules = plain.Rules
}

// evaluate matches a rule-set tag against the context. A rule set matches if ANY
// of its headless rules matches (OR).
func (r *ruleSetResolver) evaluate(tag string, ec *evalCtx, matchSource bool) *RuleSetEval {
	l := r.load(tag)
	out := &RuleSetEval{Tag: tag, Type: l.typ, MatchedIdx: -1, Count: len(l.rules)}
	if l.err != "" {
		out.Status = StatusUnknown
		out.Error = l.err
		return out
	}
	statuses := make([]string, 0, len(l.rules))
	var firstMatch, firstUnknown *RuleEval
	firstMatchIdx := -1
	for i, hr := range l.rules {
		re := ec.evalHeadless(hr)
		re.Index = i
		statuses = append(statuses, re.Status)
		if re.Status == StatusMatch && firstMatch == nil {
			c := re
			firstMatch = &c
			firstMatchIdx = i
		}
		if re.Status == StatusUnknown && firstUnknown == nil {
			c := re
			firstUnknown = &c
		}
	}
	out.Status = orStatus(statuses)
	// Attach a representative headless-rule detail (the decisive one) to keep the
	// payload small for large sets.
	switch out.Status {
	case StatusMatch:
		out.MatchedIdx = firstMatchIdx
		if firstMatch != nil {
			out.Rules = []RuleEval{*firstMatch}
		}
	case StatusUnknown:
		if firstUnknown != nil {
			out.Rules = []RuleEval{*firstUnknown}
		}
	}
	return out
}

// evalHeadless evaluates one headless rule (default or logical).
func (ec *evalCtx) evalHeadless(hr option.HeadlessRule) RuleEval {
	if hr.Type == "logical" {
		lo := hr.LogicalOptions
		mode := lo.Mode
		if mode == "" {
			mode = "and"
		}
		var subs []RuleEval
		var statuses []string
		for _, sub := range lo.Rules {
			se := ec.evalHeadless(sub)
			subs = append(subs, se)
			statuses = append(statuses, se.Status)
		}
		var status string
		if mode == "or" {
			status = orStatus(statuses)
		} else {
			status = andStatus(statuses)
		}
		if lo.Invert {
			status = invertStatus(status)
		}
		return RuleEval{Type: "logical", Mode: mode, Status: status, Invert: lo.Invert, Sub: subs, Summary: "logical " + mode}
	}
	mf := fieldsFromHeadless(hr.DefaultOptions)
	status, conds := ec.evalFields(mf)
	return RuleEval{Type: "default", Status: status, Invert: mf.invert, Conditions: conds, Summary: summarize(conds, mf.invert)}
}

func ruleSetFormatFromPath(path string) string {
	if strings.HasSuffix(strings.ToLower(path), ".srs") {
		return "binary"
	}
	return "source"
}
