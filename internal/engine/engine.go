// Package engine evaluates a sing-box configuration against a domain or IP and
// produces a step-by-step explanation of how DNS and route rules match.
package engine

import (
	"context"

	"sing-vis/internal/dnsx"
)

// RuleSetFile is an uploaded rule-set payload for a type:local rule set, keyed by
// the rule-set tag (or its configured path). Format is "source" or "binary"; for
// "binary" Data is base64-encoded, for "source" it is the raw JSON text.
type RuleSetFile struct {
	Format string `json:"format"`
	Data   string `json:"data"`
}

// Request bundles everything needed to analyze a set of inputs.
type Request struct {
	Config       string
	Inputs       []string
	RuleSetFiles map[string]RuleSetFile
	Network      string // optional assumed network: "", "tcp", "udp"
	// AssumeResolved pre-resolves domains via DoH before route matching so that
	// ip_cidr / IP rule-set rules can match the resolved addresses (matching user
	// intuition). When false, IP rules only match after an explicit resolve action.
	AssumeResolved bool
	Resolver       dnsx.Resolver
}

// Result is the top-level analysis response.
type Result struct {
	DoHServer string       `json:"dohServer"`
	Warnings  []string     `json:"warnings,omitempty"`
	Inputs    []InputTrace `json:"inputs"`
}

// Analyze is the entry point; implemented in analyze.go.
func Analyze(ctx context.Context, req Request) (*Result, error) {
	return analyze(ctx, req)
}
