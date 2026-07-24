package engine

import (
	"net/netip"
	"strings"

	"github.com/sagernet/sing-box/option"
)

type actionInfo struct {
	typ       string
	outbound  string
	detail    string
	terminal  bool
	isResolve bool
	strategy  string
	server    string
}

func routeActionOf(r option.Rule) actionInfo {
	var a option.RuleAction
	if r.Type == "logical" {
		a = r.LogicalOptions.RuleAction
	} else {
		a = r.DefaultOptions.RuleAction
	}
	typ := a.Action
	if typ == "" {
		typ = "route"
	}
	ai := actionInfo{typ: typ}
	switch typ {
	case "route":
		ai.outbound = a.RouteOptions.Outbound
		ai.terminal = true
		ai.detail = "route → " + orDefault(ai.outbound, "(default outbound)")
	case "route-options":
		ai.detail = "route-options (non-terminal)"
	case "reject":
		m := a.RejectOptions.Method
		if m == "" {
			m = "default"
		}
		ai.terminal = true
		ai.detail = "reject (" + m + ")"
	case "hijack-dns":
		ai.terminal = true
		ai.detail = "hijack-dns"
	case "sniff":
		ai.detail = "sniff (non-terminal)"
	case "resolve":
		ai.isResolve = true
		ai.strategy = safeStrategy(a.ResolveOptions.Strategy)
		ai.server = a.ResolveOptions.Server
		ai.detail = "resolve"
		if ai.strategy != "" {
			ai.detail += " (" + ai.strategy + ")"
		}
	case "direct":
		ai.terminal = true
		ai.detail = "direct"
		ai.outbound = "direct"
	case "bypass":
		ai.outbound = a.BypassOptions.Outbound
		ai.terminal = ai.outbound != ""
		ai.detail = "bypass"
	default:
		ai.terminal = true
		ai.detail = typ
	}
	return ai
}

// matchRoute evaluates route rules top-to-bottom, first terminal match wins,
// handling non-terminal resolve/sniff actions and the final fallback.
func (ec *evalCtx) matchRoute(cfg *Config) *RouteTrace {
	tr := &RouteTrace{SelectedIndex: -1, Final: cfg.RouteFinal}
	hadConditional := false

	for i, r := range cfg.RouteRules {
		re := ec.evalRuleNode(r, false)
		re.Index = i
		re.Reached = true
		a := routeActionOf(r)
		re.ActionType = a.typ
		re.ActionText = a.detail
		re.Terminal = a.terminal

		switch re.Status {
		case StatusMatch:
			if a.isResolve {
				addrs := ec.performResolve(a.strategy)
				if len(addrs) > 0 {
					re.Effect = "resolved → " + strings.Join(addrStrings(addrs), ", ") + " (IP rules below can now match)"
				} else {
					re.Effect = "resolve produced no addresses"
				}
				tr.Steps = append(tr.Steps, re)
				continue
			}
			if !a.terminal {
				re.Effect = "matched but non-terminal; continues scanning"
				tr.Steps = append(tr.Steps, re)
				continue
			}
			tr.Steps = append(tr.Steps, re)
			tr.SelectedIndex = i
			tr.Decision = &RouteDecision{
				ActionType: a.typ,
				Outbound:   a.outbound,
				Detail:     a.detail,
				Assumed:    hadConditional,
			}
			return tr
		case StatusUnknown:
			if a.terminal {
				re.Effect = "could match here if its undetermined conditions hold"
				hadConditional = true
			}
			tr.Steps = append(tr.Steps, re)
		default:
			tr.Steps = append(tr.Steps, re)
		}
	}

	tr.Decision = &RouteDecision{
		ActionType: "route",
		Outbound:   effectiveRouteFinal(cfg),
		Detail:     "route → " + orDefault(effectiveRouteFinal(cfg), "(first outbound)"),
		FromFinal:  true,
		Assumed:    hadConditional,
	}
	return tr
}

// performResolve resolves the host via DoH and records the addresses so IP-based
// rules below can match. It reuses any cached resolution.
func (ec *evalCtx) performResolve(strategy string) []netip.Addr {
	if ec.host == "" || ec.resolver == nil {
		return ec.addresses
	}
	res, _ := ec.resolver.Resolve(ec.ctx, ec.host, strategy)
	if res == nil {
		return ec.addresses
	}
	addrs := parseAddrs(res.All(strategy))
	if len(addrs) > 0 {
		ec.setAddresses(addrs)
	}
	return addrs
}

func effectiveRouteFinal(cfg *Config) string {
	return cfg.RouteFinal // empty => sing-box uses the first outbound
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func safeStrategy(s option.DomainStrategy) (out string) {
	defer func() { _ = recover() }()
	return s.String()
}

func parseAddrs(ss []string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	return out
}

func addrStrings(addrs []netip.Addr) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out
}
