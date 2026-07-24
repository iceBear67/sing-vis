package engine

import (
	"strings"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// ---- field extraction ----

func fieldsFromRoute(r option.RawDefaultRule) matchFields {
	mf := matchFields{
		domain:        r.Domain,
		domainSuffix:  r.DomainSuffix,
		domainKeyword: r.DomainKeyword,
		domainRegex:   r.DomainRegex,
		ipCIDR:        r.IPCIDR,
		ipIsPrivate:   r.IPIsPrivate,
		srcIPCIDR:     r.SourceIPCIDR,
		srcIPIsPriv:   r.SourceIPIsPrivate,
		port:          r.Port,
		portRange:     r.PortRange,
		srcPort:       r.SourcePort,
		srcPortRange:  r.SourcePortRange,
		network:       r.Network,
		protocol:      r.Protocol,
		ruleSet:       r.RuleSet,
		rsMatchSource: r.RuleSetIPCIDRMatchSource || r.Deprecated_RulesetIPCIDRMatchSource,
		invert:        r.Invert,
	}
	addUnknownList(&mf, "inbound", r.Inbound)
	addUnknownList(&mf, "client", r.Client)
	addUnknownList(&mf, "auth_user", r.AuthUser)
	addUnknownList(&mf, "user", r.User)
	addUnknownList(&mf, "process_name", r.ProcessName)
	addUnknownList(&mf, "process_path", r.ProcessPath)
	addUnknownList(&mf, "process_path_regex", r.ProcessPathRegex)
	addUnknownList(&mf, "package_name", r.PackageName)
	addUnknownList(&mf, "package_name_regex", r.PackageNameRegex)
	addUnknownList(&mf, "wifi_ssid", r.WIFISSID)
	addUnknownList(&mf, "wifi_bssid", r.WIFIBSSID)
	addUnknownList(&mf, "source_mac_address", r.SourceMACAddress)
	addUnknownList(&mf, "source_hostname", r.SourceHostname)
	addUnknownList(&mf, "preferred_by", r.PreferredBy)
	addUnknownDeprecated(&mf, "geosite", r.Geosite)
	addUnknownDeprecated(&mf, "geoip", r.GeoIP)
	addUnknownDeprecated(&mf, "source_geoip", r.SourceGeoIP)
	if r.ClashMode != "" {
		mf.unknowns = append(mf.unknowns, condKV{"clash_mode", r.ClashMode})
	}
	if r.IPVersion != 0 {
		mf.unknowns = append(mf.unknowns, condKV{"ip_version", intStr(r.IPVersion)})
	}
	if r.NetworkIsExpensive {
		mf.unknowns = append(mf.unknowns, condKV{"network_is_expensive", "true"})
	}
	if r.NetworkIsConstrained {
		mf.unknowns = append(mf.unknowns, condKV{"network_is_constrained", "true"})
	}
	if len(r.NetworkType) > 0 {
		mf.unknowns = append(mf.unknowns, condKV{"network_type", interfaceTypes(r.NetworkType)})
	}
	return mf
}

func fieldsFromDNS(r option.RawDefaultDNSRule) matchFields {
	mf := matchFields{
		domain:        r.Domain,
		domainSuffix:  r.DomainSuffix,
		domainKeyword: r.DomainKeyword,
		domainRegex:   r.DomainRegex,
		srcIPCIDR:     r.SourceIPCIDR,
		srcIPIsPriv:   r.SourceIPIsPrivate,
		port:          r.Port,
		portRange:     r.PortRange,
		srcPort:       r.SourcePort,
		srcPortRange:  r.SourcePortRange,
		network:       r.Network,
		protocol:      r.Protocol,
		queryType:     r.QueryType,
		ruleSet:       r.RuleSet,
		rsMatchSource: r.RuleSetIPCIDRMatchSource || r.Deprecated_RulesetIPCIDRMatchSource,
		invert:        r.Invert,
	}
	// DNS ip_cidr / ip_is_private / ip_accept_any and response_* are response
	// filters, not query-routing conditions.
	if len(r.IPCIDR) > 0 {
		mf.dnsFilter = append(mf.dnsFilter, condKV{"ip_cidr", joinVals(r.IPCIDR)})
	}
	if r.IPIsPrivate {
		mf.dnsFilter = append(mf.dnsFilter, condKV{"ip_is_private", "true"})
	}
	if r.IPAcceptAny {
		mf.dnsFilter = append(mf.dnsFilter, condKV{"ip_accept_any", "true"})
	}
	if r.ResponseRcode != nil {
		mf.dnsFilter = append(mf.dnsFilter, condKV{"response_rcode", "set"})
	}
	if r.MatchResponse != nil {
		mf.dnsFilter = append(mf.dnsFilter, condKV{"match_response", "set"})
	}
	addUnknownList(&mf, "inbound", r.Inbound)
	addUnknownList(&mf, "auth_user", r.AuthUser)
	addUnknownList(&mf, "user", r.User)
	addUnknownList(&mf, "outbound", r.Outbound)
	addUnknownList(&mf, "process_name", r.ProcessName)
	addUnknownList(&mf, "process_path", r.ProcessPath)
	addUnknownList(&mf, "package_name", r.PackageName)
	addUnknownList(&mf, "wifi_ssid", r.WIFISSID)
	addUnknownList(&mf, "wifi_bssid", r.WIFIBSSID)
	addUnknownDeprecated(&mf, "geosite", r.Geosite)
	if r.ClashMode != "" {
		mf.unknowns = append(mf.unknowns, condKV{"clash_mode", r.ClashMode})
	}
	if r.IPVersion != 0 {
		mf.unknowns = append(mf.unknowns, condKV{"ip_version", intStr(r.IPVersion)})
	}
	return mf
}

func fieldsFromHeadless(r option.DefaultHeadlessRule) matchFields {
	mf := matchFields{
		domainKeyword: r.DomainKeyword,
		domainRegex:   r.DomainRegex,
		srcIPCIDR:     r.SourceIPCIDR,
		port:          r.Port,
		portRange:     r.PortRange,
		srcPort:       r.SourcePort,
		srcPortRange:  r.SourcePortRange,
		network:       r.Network,
		queryType:     r.QueryType,
		invert:        r.Invert,
	}
	// Prefer pre-compiled matchers (present in binary .srs rule sets).
	if r.DomainMatcher != nil {
		mf.rawDomain = r.DomainMatcher
	} else {
		mf.domain = r.Domain
		mf.domainSuffix = r.DomainSuffix
	}
	if r.IPSet != nil {
		mf.rawIPSet = r.IPSet
	} else {
		mf.ipCIDR = r.IPCIDR
	}
	if r.AdGuardDomainMatcher != nil || len(r.AdGuardDomain) > 0 {
		mf.unknowns = append(mf.unknowns, condKV{"adguard_domain", "«set»"})
	}
	addUnknownList(&mf, "process_name", r.ProcessName)
	addUnknownList(&mf, "process_path", r.ProcessPath)
	addUnknownList(&mf, "package_name", r.PackageName)
	addUnknownList(&mf, "wifi_ssid", r.WIFISSID)
	addUnknownList(&mf, "wifi_bssid", r.WIFIBSSID)
	if r.NetworkIsExpensive {
		mf.unknowns = append(mf.unknowns, condKV{"network_is_expensive", "true"})
	}
	if r.NetworkIsConstrained {
		mf.unknowns = append(mf.unknowns, condKV{"network_is_constrained", "true"})
	}
	if len(r.NetworkType) > 0 {
		mf.unknowns = append(mf.unknowns, condKV{"network_type", interfaceTypes(r.NetworkType)})
	}
	return mf
}

func addUnknownList(mf *matchFields, field string, v badoption.Listable[string]) {
	if len(v) > 0 {
		mf.unknowns = append(mf.unknowns, condKV{field, joinVals(v)})
	}
}

func addUnknownDeprecated(mf *matchFields, field string, v badoption.Listable[string]) {
	if len(v) > 0 {
		mf.unknowns = append(mf.unknowns, condKV{field + " (deprecated/removed)", joinVals(v)})
	}
}

func interfaceTypes(v badoption.Listable[option.InterfaceType]) string {
	parts := make([]string, 0, len(v))
	for _, t := range v {
		parts = append(parts, string(t))
	}
	return strings.Join(parts, ", ")
}

func intStr(i int) string { return joinVals([]string{itoa(i)}) }

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}

// ---- rule-node evaluation (conditions only; action handled by caller) ----

// evalRuleNode evaluates a route/DNS rule's match conditions recursively.
func (ec *evalCtx) evalRuleNode(r option.Rule, dns bool) RuleEval {
	if r.Type == "logical" {
		return ec.evalLogical(r.LogicalOptions.Mode, r.LogicalOptions.Rules, r.LogicalOptions.Invert, dns)
	}
	var mf matchFields
	if dns {
		// A DNS rule's default variant is carried on a separate type; caller
		// passes route-shaped rules only via evalDNSRuleNode. This branch is for
		// route rules.
	}
	mf = fieldsFromRoute(r.DefaultOptions.RawDefaultRule)
	status, conds := ec.evalFields(mf)
	return RuleEval{
		Type:       "default",
		Status:     status,
		Invert:     mf.invert,
		Conditions: conds,
		Summary:    summarize(conds, mf.invert),
	}
}

// evalDNSRuleNode evaluates a DNS rule's match conditions recursively.
func (ec *evalCtx) evalDNSRuleNode(r option.DNSRule) RuleEval {
	if r.Type == "logical" {
		return ec.evalLogicalDNS(r.LogicalOptions.Mode, r.LogicalOptions.Rules, r.LogicalOptions.Invert)
	}
	mf := fieldsFromDNS(r.DefaultOptions.RawDefaultDNSRule)
	status, conds := ec.evalFields(mf)
	return RuleEval{
		Type:       "default",
		Status:     status,
		Invert:     mf.invert,
		Conditions: conds,
		Summary:    summarize(conds, mf.invert),
	}
}

func (ec *evalCtx) evalLogical(mode string, rules []option.Rule, invert bool, dns bool) RuleEval {
	if mode == "" {
		mode = "and"
	}
	var subs []RuleEval
	var statuses []string
	for _, sub := range rules {
		se := ec.evalRuleNode(sub, dns)
		subs = append(subs, se)
		statuses = append(statuses, se.Status)
	}
	var status string
	if mode == "or" {
		status = orStatus(statuses)
	} else {
		status = andStatus(statuses)
	}
	if invert {
		status = invertStatus(status)
	}
	return RuleEval{Type: "logical", Mode: mode, Status: status, Invert: invert, Sub: subs, Summary: "logical " + mode}
}

func (ec *evalCtx) evalLogicalDNS(mode string, rules []option.DNSRule, invert bool) RuleEval {
	if mode == "" {
		mode = "and"
	}
	var subs []RuleEval
	var statuses []string
	for _, sub := range rules {
		se := ec.evalDNSRuleNode(sub)
		subs = append(subs, se)
		statuses = append(statuses, se.Status)
	}
	var status string
	if mode == "or" {
		status = orStatus(statuses)
	} else {
		status = andStatus(statuses)
	}
	if invert {
		status = invertStatus(status)
	}
	return RuleEval{Type: "logical", Mode: mode, Status: status, Invert: invert, Sub: subs, Summary: "logical " + mode}
}

func summarize(conds []CondEval, invert bool) string {
	if len(conds) == 0 {
		return "(match all)"
	}
	parts := make([]string, 0, len(conds))
	for _, c := range conds {
		v := c.Value
		if len(v) > 40 {
			v = v[:40] + "…"
		}
		parts = append(parts, c.Field+"="+v)
	}
	s := strings.Join(parts, " ")
	if invert {
		s = "NOT(" + s + ")"
	}
	return s
}
