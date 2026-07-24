package engine

import (
	"github.com/sagernet/sing-box/option"
)

func dnsActionOf(r option.DNSRule) actionInfo {
	var a option.DNSRuleAction
	if r.Type == "logical" {
		a = r.LogicalOptions.DNSRuleAction
	} else {
		a = r.DefaultOptions.DNSRuleAction
	}
	typ := a.Action
	if typ == "" {
		typ = "route"
	}
	ai := actionInfo{typ: typ}
	switch typ {
	case "route":
		ai.server = a.RouteOptions.Server
		ai.terminal = true
		ai.detail = "route → server " + orDefault(ai.server, "(default)")
	case "route-options":
		ai.detail = "route-options (non-terminal)"
	case "reject":
		m := a.RejectOptions.Method
		if m == "" {
			m = "default"
		}
		ai.terminal = true
		ai.detail = "reject (" + m + ")"
	case "predefined":
		ai.terminal = true
		ai.detail = "predefined response"
	case "evaluate":
		ai.server = a.RouteOptions.Server
		ai.detail = "evaluate (non-terminal)"
	case "respond":
		ai.terminal = true
		ai.detail = "respond"
	default:
		ai.terminal = true
		ai.detail = typ
	}
	return ai
}

// matchDNS evaluates DNS rules for the host to determine which DNS server / DNS
// rule action is hit. Evaluated for one query type at a time: applications issue
// A and AAAA in parallel (happy eyeballs), and query_type rules can route — or
// reject — the two independently, so each is traced separately.
func (ec *evalCtx) matchDNS(cfg *Config, queryType uint16) *DNSTrace {
	prevQT := ec.queryType
	ec.queryType = queryType
	defer func() { ec.queryType = prevQT }()

	tr := &DNSTrace{QueryType: queryTypeName(queryType), MatchedIndex: -1, Final: cfg.effectiveDNSFinal()}
	hadConditional := false

	for i, r := range cfg.DNSRules {
		re := ec.evalDNSRuleNode(r)
		re.Index = i
		re.Reached = true
		a := dnsActionOf(r)
		re.ActionType = a.typ
		re.ActionText = a.detail
		re.Terminal = a.terminal

		switch re.Status {
		case StatusMatch:
			if !a.terminal {
				re.Effect = "matched but non-terminal; continues scanning"
				tr.Steps = append(tr.Steps, re)
				continue
			}
			tr.Steps = append(tr.Steps, re)
			tr.MatchedIndex = i
			tr.Decision = ec.dnsDecision(cfg, a, false, hadConditional)
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

	// Fall through to dns.final.
	final := cfg.effectiveDNSFinal()
	tr.Decision = ec.dnsDecision(cfg, actionInfo{typ: "route", server: final, terminal: true, detail: "route → server " + orDefault(final, "(first server)")}, true, hadConditional)
	if len(cfg.DNSRules) == 0 {
		tr.Note = "no DNS rules; the final server is always used"
	}
	return tr
}

func (ec *evalCtx) dnsDecision(cfg *Config, a actionInfo, fromFinal, assumed bool) *DNSDecision {
	d := &DNSDecision{
		ActionType: a.typ,
		Server:     a.server,
		Detail:     a.detail,
		FromFinal:  fromFinal,
		Assumed:    assumed,
	}
	if a.server != "" {
		d.ServerInfo = cfg.findDNSServer(a.server)
	}
	return d
}
