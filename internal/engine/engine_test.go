package engine

import (
	"context"
	"testing"

	"sing-vis/internal/dnsx"
)

// fakeResolver returns canned DoH answers so route/DNS matching is testable
// offline (no network). Unknown names resolve to no addresses.
type fakeResolver struct {
	answers map[string]*dnsx.Result
}

func (f *fakeResolver) Server() string { return "fake-doh" }

func (f *fakeResolver) Resolve(_ context.Context, name string, _ string) (*dnsx.Result, error) {
	if r, ok := f.answers[name]; ok {
		return r, nil
	}
	return &dnsx.Result{Name: name}, nil
}

func analyzeOne(t *testing.T, cfg, input string, assumeResolved bool, res dnsx.Resolver) InputTrace {
	t.Helper()
	out, err := Analyze(context.Background(), Request{
		Config:         cfg,
		Inputs:         []string{input},
		AssumeResolved: assumeResolved,
		Resolver:       res,
	})
	if err != nil {
		t.Fatalf("Analyze(%q) error: %v", input, err)
	}
	if len(out.Inputs) != 1 {
		t.Fatalf("Analyze(%q): expected 1 input trace, got %d", input, len(out.Inputs))
	}
	return out.Inputs[0]
}

func routeOutbound(t *testing.T, it InputTrace) *RouteDecision {
	t.Helper()
	if it.Route == nil || it.Route.Decision == nil {
		t.Fatalf("input %q: missing route decision", it.Input)
	}
	return it.Route.Decision
}

func TestDomainSuffix(t *testing.T) {
	cfg := `{"route":{"rules":[{"domain_suffix":["google.com"],"outbound":"proxy"}],"final":"direct"}}`

	it := analyzeOne(t, cfg, "www.google.com", true, &fakeResolver{})
	d := routeOutbound(t, it)
	if d.Outbound != "proxy" || d.FromFinal {
		t.Errorf("www.google.com: got outbound=%q fromFinal=%v, want proxy/false", d.Outbound, d.FromFinal)
	}
	if it.Route.SelectedIndex != 0 {
		t.Errorf("www.google.com: selectedIndex=%d, want 0", it.Route.SelectedIndex)
	}

	it = analyzeOne(t, cfg, "example.org", true, &fakeResolver{})
	d = routeOutbound(t, it)
	if d.Outbound != "direct" || !d.FromFinal {
		t.Errorf("example.org: got outbound=%q fromFinal=%v, want direct/true", d.Outbound, d.FromFinal)
	}
}

func TestInlineRuleSet(t *testing.T) {
	cfg := `{"route":{
		"rules":[{"rule_set":["cn"],"outbound":"direct"}],
		"rule_set":[{"type":"inline","tag":"cn","rules":[{"domain_suffix":["baidu.com"]}]}],
		"final":"proxy"}}`

	it := analyzeOne(t, cfg, "www.baidu.com", true, &fakeResolver{})
	d := routeOutbound(t, it)
	if d.Outbound != "direct" {
		t.Errorf("www.baidu.com: outbound=%q, want direct", d.Outbound)
	}
	// The rule_set condition should report a match with a non-negative matched idx.
	step := it.Route.Steps[0]
	if step.Status != StatusMatch {
		t.Errorf("rule_set step status=%q, want match", step.Status)
	}
	var found bool
	for _, c := range step.Conditions {
		if c.Field == "rule_set" && c.RuleSet != nil {
			found = true
			if c.RuleSet.Status != StatusMatch || c.RuleSet.MatchedIdx != 0 {
				t.Errorf("rule_set eval: status=%q matchedIdx=%d, want match/0", c.RuleSet.Status, c.RuleSet.MatchedIdx)
			}
		}
	}
	if !found {
		t.Error("no rule_set condition found in step")
	}

	it = analyzeOne(t, cfg, "www.google.com", true, &fakeResolver{})
	if d := routeOutbound(t, it); d.Outbound != "proxy" || !d.FromFinal {
		t.Errorf("www.google.com: outbound=%q fromFinal=%v, want proxy/true", d.Outbound, d.FromFinal)
	}
}

func TestLogicalInvert(t *testing.T) {
	// Inverted logical rule: matches everything EXCEPT *.google.com.
	cfg := `{"route":{"rules":[
		{"type":"logical","mode":"and","invert":true,
		 "rules":[{"domain_suffix":["google.com"]}],"outbound":"not-google"}
	],"final":"proxy"}}`

	it := analyzeOne(t, cfg, "example.com", true, &fakeResolver{})
	if d := routeOutbound(t, it); d.Outbound != "not-google" {
		t.Errorf("example.com: outbound=%q, want not-google (inverted match)", d.Outbound)
	}

	it = analyzeOne(t, cfg, "www.google.com", true, &fakeResolver{})
	if d := routeOutbound(t, it); d.Outbound != "proxy" || !d.FromFinal {
		t.Errorf("www.google.com: outbound=%q fromFinal=%v, want proxy/true (inverted no-match)", d.Outbound, d.FromFinal)
	}
}

func TestResolveThenIPCIDR(t *testing.T) {
	cfg := `{"route":{"rules":[
		{"domain_suffix":["example.com"],"action":"resolve"},
		{"ip_cidr":["1.2.3.0/24"],"outbound":"matched-ip"}
	],"final":"proxy"}}`
	res := &fakeResolver{answers: map[string]*dnsx.Result{
		"host.example.com": {Name: "host.example.com", IPv4: []string{"1.2.3.4"}},
	}}

	// AssumeResolved=false: ip_cidr only matches after the explicit resolve action.
	it := analyzeOne(t, cfg, "host.example.com", false, res)
	if d := routeOutbound(t, it); d.Outbound != "matched-ip" {
		t.Errorf("host.example.com: outbound=%q, want matched-ip", d.Outbound)
	}
	// The resolve step should carry an effect line mentioning the resolved IP.
	if it.Route.Steps[0].Effect == "" {
		t.Error("resolve step missing effect line")
	}

	// A domain that resolves outside the CIDR falls through to final.
	res2 := &fakeResolver{answers: map[string]*dnsx.Result{
		"other.example.com": {Name: "other.example.com", IPv4: []string{"9.9.9.9"}},
	}}
	it = analyzeOne(t, cfg, "other.example.com", false, res2)
	if d := routeOutbound(t, it); d.Outbound != "proxy" || !d.FromFinal {
		t.Errorf("other.example.com: outbound=%q fromFinal=%v, want proxy/true", d.Outbound, d.FromFinal)
	}
}

func TestDNSServerSelection(t *testing.T) {
	cfg := `{"dns":{
		"servers":[
			{"tag":"proxy-dns","type":"https","server":"1.1.1.1","detour":"proxy"},
			{"tag":"local-dns","type":"udp","server":"223.5.5.5","detour":"direct"}
		],
		"rules":[{"domain_suffix":["cn.example"],"server":"local-dns"}],
		"final":"proxy-dns"}}`

	it := analyzeOne(t, cfg, "site.cn.example", true, &fakeResolver{})
	if it.DNS == nil || it.DNS.Decision == nil {
		t.Fatal("missing DNS decision")
	}
	d := it.DNS.Decision
	if d.Server != "local-dns" || d.FromFinal {
		t.Errorf("site.cn.example: dns server=%q fromFinal=%v, want local-dns/false", d.Server, d.FromFinal)
	}
	if d.ServerInfo == nil || d.ServerInfo.Detour != "direct" {
		t.Errorf("site.cn.example: dns detour=%v, want direct", d.ServerInfo)
	}

	it = analyzeOne(t, cfg, "other.example", true, &fakeResolver{})
	d = it.DNS.Decision
	if d.Server != "proxy-dns" || !d.FromFinal {
		t.Errorf("other.example: dns server=%q fromFinal=%v, want proxy-dns/true", d.Server, d.FromFinal)
	}
	if d.ServerInfo == nil || d.ServerInfo.Detour != "proxy" {
		t.Errorf("other.example: dns detour=%v, want proxy", d.ServerInfo)
	}
}

func TestRawIPInput(t *testing.T) {
	cfg := `{"route":{"rules":[{"ip_cidr":["10.0.0.0/8"],"outbound":"lan"}],"final":"wan"}}`

	it := analyzeOne(t, cfg, "10.1.2.3", true, &fakeResolver{})
	if it.Kind != "ip" {
		t.Errorf("10.1.2.3: kind=%q, want ip", it.Kind)
	}
	if it.DNS != nil {
		t.Error("raw IP should have no DNS trace")
	}
	if d := routeOutbound(t, it); d.Outbound != "lan" {
		t.Errorf("10.1.2.3: outbound=%q, want lan", d.Outbound)
	}

	it = analyzeOne(t, cfg, "8.8.8.8", true, &fakeResolver{})
	if d := routeOutbound(t, it); d.Outbound != "wan" || !d.FromFinal {
		t.Errorf("8.8.8.8: outbound=%q fromFinal=%v, want wan/true", d.Outbound, d.FromFinal)
	}
}

func TestPortHint(t *testing.T) {
	cfg := `{"route":{"rules":[{"port":[443],"outbound":"proxy"}],"final":"direct"}}`

	// An explicit host:port that matches selects the port rule's outbound.
	it := analyzeOne(t, cfg, "example.com:443", true, &fakeResolver{})
	if d := routeOutbound(t, it); d.Outbound != "proxy" || d.FromFinal {
		t.Errorf("example.com:443: outbound=%q fromFinal=%v, want proxy/false", d.Outbound, d.FromFinal)
	}
	if st := condStatus(t, it, "port"); st != StatusMatch {
		t.Errorf("example.com:443: port cond status=%q, want match", st)
	}

	// A non-matching port falls through to final.
	it = analyzeOne(t, cfg, "example.com:80", true, &fakeResolver{})
	if d := routeOutbound(t, it); d.Outbound != "direct" || !d.FromFinal {
		t.Errorf("example.com:80: outbound=%q fromFinal=%v, want direct/true", d.Outbound, d.FromFinal)
	}
	if st := condStatus(t, it, "port"); st != StatusNoMatch {
		t.Errorf("example.com:80: port cond status=%q, want no_match", st)
	}

	// Without a port the rule stays undeterminable (unknown), as before.
	it = analyzeOne(t, cfg, "example.com", true, &fakeResolver{})
	if st := condStatus(t, it, "port"); st != StatusUnknown {
		t.Errorf("example.com: port cond status=%q, want unknown", st)
	}

	// port_range honours the supplied port too (inclusive range).
	cfgRange := `{"route":{"rules":[{"port_range":["8000:9000"],"outbound":"proxy"}],"final":"direct"}}`
	it = analyzeOne(t, cfgRange, "example.com:8080", true, &fakeResolver{})
	if d := routeOutbound(t, it); d.Outbound != "proxy" {
		t.Errorf("example.com:8080: outbound=%q, want proxy", d.Outbound)
	}
	if st := condStatus(t, it, "port_range"); st != StatusMatch {
		t.Errorf("example.com:8080: port_range cond status=%q, want match", st)
	}

	// A raw IP with a port is still parsed as an IP (port stripped from the host).
	cfgIP := `{"route":{"rules":[{"port":[53],"outbound":"dns"}],"final":"direct"}}`
	it = analyzeOne(t, cfgIP, "1.1.1.1:53", true, &fakeResolver{})
	if it.Kind != "ip" {
		t.Errorf("1.1.1.1:53: kind=%q, want ip", it.Kind)
	}
	if d := routeOutbound(t, it); d.Outbound != "dns" {
		t.Errorf("1.1.1.1:53: outbound=%q, want dns", d.Outbound)
	}
}

func TestProtocolHint(t *testing.T) {
	cfg := `{"route":{"rules":[{"protocol":["tls"],"outbound":"proxy"}],"final":"direct"}}`

	// Without an assumed protocol the rule stays undeterminable (unknown).
	it := analyzeOne(t, cfg, "example.com", true, &fakeResolver{})
	if st := condStatus(t, it, "protocol"); st != StatusUnknown {
		t.Errorf("no protocol: status=%q, want unknown", st)
	}

	// With protocol=tls the rule matches and selects the outbound.
	out, err := Analyze(context.Background(), Request{
		Config: cfg, Inputs: []string{"example.com"}, AssumeResolved: true,
		Protocol: "tls", Resolver: &fakeResolver{},
	})
	if err != nil {
		t.Fatal(err)
	}
	it = out.Inputs[0]
	if d := routeOutbound(t, it); d.Outbound != "proxy" || d.FromFinal {
		t.Errorf("protocol=tls: outbound=%q fromFinal=%v, want proxy/false", d.Outbound, d.FromFinal)
	}
	if st := condStatus(t, it, "protocol"); st != StatusMatch {
		t.Errorf("protocol=tls: status=%q, want match", st)
	}

	// A different assumed protocol does not match → falls through to final.
	out, _ = Analyze(context.Background(), Request{
		Config: cfg, Inputs: []string{"example.com"}, AssumeResolved: true,
		Protocol: "http", Resolver: &fakeResolver{},
	})
	it = out.Inputs[0]
	if st := condStatus(t, it, "protocol"); st != StatusNoMatch {
		t.Errorf("protocol=http: status=%q, want no_match", st)
	}
	if d := routeOutbound(t, it); d.Outbound != "direct" || !d.FromFinal {
		t.Errorf("protocol=http: outbound=%q fromFinal=%v, want direct/final", d.Outbound, d.FromFinal)
	}
}

func TestProtocolSchemeOverride(t *testing.T) {
	cfg := `{"route":{"rules":[{"protocol":["rdp"],"outbound":"remote"}],"final":"direct"}}`

	// A URL scheme on the line sets the protocol for that input, with no default.
	it := analyzeOne(t, cfg, "rdp://10.0.0.5:3389", true, &fakeResolver{})
	if it.Kind != "ip" {
		t.Errorf("rdp://10.0.0.5:3389: kind=%q, want ip (host parsed, scheme/port stripped)", it.Kind)
	}
	if d := routeOutbound(t, it); d.Outbound != "remote" {
		t.Errorf("rdp://10.0.0.5:3389: outbound=%q, want remote", d.Outbound)
	}
	if st := condStatus(t, it, "protocol"); st != StatusMatch {
		t.Errorf("rdp://10.0.0.5:3389: protocol status=%q, want match", st)
	}

	// The per-line scheme overrides the request-level (toolbar) protocol.
	out, err := Analyze(context.Background(), Request{
		Config: cfg, Inputs: []string{"rdp://10.0.0.5:3389"}, AssumeResolved: true,
		Protocol: "tls", Resolver: &fakeResolver{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if d := out.Inputs[0].Route.Decision; d.Outbound != "remote" {
		t.Errorf("scheme override with Protocol=tls: outbound=%q, want remote", d.Outbound)
	}

	// A domain URL keeps its host and applies the scheme protocol.
	it = analyzeOne(t, cfg, "rdp://desktop.example.com", true, &fakeResolver{})
	if it.Kind != "domain" {
		t.Errorf("rdp://desktop.example.com: kind=%q, want domain", it.Kind)
	}
	if st := condStatus(t, it, "protocol"); st != StatusMatch {
		t.Errorf("rdp://desktop.example.com: protocol status=%q, want match", st)
	}

	// Without a scheme (and no default protocol) the same rule is undeterminable.
	it = analyzeOne(t, cfg, "10.0.0.5:3389", true, &fakeResolver{})
	if st := condStatus(t, it, "protocol"); st != StatusUnknown {
		t.Errorf("10.0.0.5:3389 (no scheme): protocol status=%q, want unknown", st)
	}
}

// condStatus returns the status of the first condition with the given field
// across all route steps.
func condStatus(t *testing.T, it InputTrace, field string) string {
	t.Helper()
	if it.Route == nil {
		t.Fatalf("input %q: no route trace", it.Input)
	}
	for _, s := range it.Route.Steps {
		for _, c := range s.Conditions {
			if c.Field == field {
				return c.Status
			}
		}
	}
	t.Fatalf("input %q: no %q condition found", it.Input, field)
	return ""
}

func TestInvalidInput(t *testing.T) {
	cfg := `{"route":{"rules":[],"final":"proxy"}}`
	it := analyzeOne(t, cfg, "not a valid host!!", true, &fakeResolver{})
	if it.Kind != "invalid" {
		t.Errorf("kind=%q, want invalid", it.Kind)
	}
}
