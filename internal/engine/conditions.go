package engine

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/domain"
	"go4.org/netipx"

	"sing-vis/internal/dnsx"
)

// Condition groups (see docs/configuration/route/rule.md matching formula).
const (
	groupDestAddr = "dest_addr"
	groupSrcAddr  = "src_addr"
	groupDestPort = "dest_port"
	groupSrcPort  = "src_port"
	groupRuleSet  = "rule_set"
	groupOther    = "other"
)

// evalCtx carries the per-input matching state.
//
// It intentionally does NOT use sing-box's adapter.InboundContext: importing the
// adapter package pulls in the full outbound/dialer/sing-tun dependency tree,
// which does not compile for GOARCH=wasm. The only rule fields that depend on an
// InboundContext are domain / network / query_type, and those are matched here
// directly (domain via sing/common/domain, the source of truth reused verbatim
// by route/rule.DomainItem; network / query_type are plain membership tests).
type evalCtx struct {
	ctx          context.Context
	network      string // assumed connection network ("", "tcp", "udp")
	queryType    uint16 // DNS query type in effect (0 = unknown)
	host         string // lowercased domain (empty for IP input)
	destIsIP     bool
	destAddr     netip.Addr
	destPort     uint16 // destination port supplied on the input line (host:port)
	havePort     bool   // a destination port was supplied, so port rules are determinable
	protocol     string // assumed sniffed protocol ("" = unknown), e.g. tls/http/quic
	destResolved bool         // addresses populated (via resolve/assume)
	addresses    []netip.Addr // resolved/assumed destination addresses
	rs           *ruleSetResolver
	resolver     dnsx.Resolver
	resolved     *ResolvedInfo // cached DoH result for the host
}

// setAddresses records resolved destination addresses so IP-based conditions
// (ip_cidr, ip rule sets) can match them.
func (ec *evalCtx) setAddresses(addrs []netip.Addr) {
	ec.addresses = addrs
	ec.destResolved = true
}

// matchFields is the normalized, matchable subset shared by route, DNS and
// headless rules.
type matchFields struct {
	domain        []string
	domainSuffix  []string
	domainKeyword []string
	domainRegex   []string
	ipCIDR        []string
	ipIsPrivate   bool
	srcIPCIDR     []string
	srcIPIsPriv   bool
	port          []uint16
	portRange     []string
	srcPort       []uint16
	srcPortRange  []string
	network       []string
	protocol      []string
	queryType     []option.DNSQueryType
	ruleSet       []string
	rsMatchSource bool
	invert        bool

	// Pre-compiled matchers from binary (.srs) rule sets.
	rawDomain *domain.Matcher
	rawIPSet  *netipx.IPSet

	unknowns  []condKV // fields we cannot evaluate offline (assumptions)
	dnsFilter []condKV // DNS response-address filters (not applicable to query routing)
}

type condKV struct{ field, value string }

// orStatus combines OR-group members.
func orStatus(members []string) string {
	unknown := false
	for _, s := range members {
		if s == StatusMatch {
			return StatusMatch
		}
		if s == StatusUnknown {
			unknown = true
		}
	}
	if unknown {
		return StatusUnknown
	}
	return StatusNoMatch
}

// andStatus combines AND members.
func andStatus(members []string) string {
	unknown := false
	for _, s := range members {
		if s == StatusNoMatch {
			return StatusNoMatch
		}
		if s == StatusUnknown {
			unknown = true
		}
	}
	if unknown {
		return StatusUnknown
	}
	return StatusMatch
}

func invertStatus(s string) string {
	switch s {
	case StatusMatch:
		return StatusNoMatch
	case StatusNoMatch:
		return StatusMatch
	default:
		return StatusUnknown
	}
}

// evalFields evaluates a normalized rule against the context, producing an
// overall tri-state status and the per-condition breakdown. An empty rule
// (no conditions) matches everything.
func (ec *evalCtx) evalFields(mf matchFields) (string, []CondEval) {
	var conds []CondEval
	var groupStatuses []string // AND across non-empty groups + other conds

	// --- destination address group (OR) ---
	var da []string
	if len(mf.domain) > 0 {
		st, matched := ec.matchDomainExact(mf.domain)
		conds = append(conds, CondEval{Field: "domain", Value: joinVals(mf.domain), Group: groupDestAddr, Status: st, Matched: matched})
		da = append(da, st)
	}
	if len(mf.domainSuffix) > 0 {
		st, matched := ec.matchDomainSuffix(mf.domainSuffix)
		conds = append(conds, CondEval{Field: "domain_suffix", Value: joinVals(mf.domainSuffix), Group: groupDestAddr, Status: st, Matched: matched})
		da = append(da, st)
	}
	if len(mf.domainKeyword) > 0 {
		st, matched := ec.matchKeyword(mf.domainKeyword)
		conds = append(conds, CondEval{Field: "domain_keyword", Value: joinVals(mf.domainKeyword), Group: groupDestAddr, Status: st, Matched: matched})
		da = append(da, st)
	}
	if len(mf.domainRegex) > 0 {
		st, matched := ec.matchRegex(mf.domainRegex)
		conds = append(conds, CondEval{Field: "domain_regex", Value: joinVals(mf.domainRegex), Group: groupDestAddr, Status: st, Matched: matched})
		da = append(da, st)
	}
	if mf.rawDomain != nil {
		st := StatusNoMatch
		if ec.host != "" && mf.rawDomain.Match(ec.host) {
			st = StatusMatch
		}
		conds = append(conds, CondEval{Field: "domain/domain_suffix", Value: "«compiled set»", Group: groupDestAddr, Status: st})
		da = append(da, st)
	}
	if len(mf.ipCIDR) > 0 {
		st, matched, note := ec.matchIPCIDR(mf.ipCIDR, false)
		conds = append(conds, CondEval{Field: "ip_cidr", Value: joinVals(mf.ipCIDR), Group: groupDestAddr, Status: st, Matched: matched, Note: note})
		da = append(da, st)
	}
	if mf.rawIPSet != nil {
		st, note := ec.matchRawIPSet(mf.rawIPSet)
		conds = append(conds, CondEval{Field: "ip_cidr", Value: "«compiled set»", Group: groupDestAddr, Status: st, Note: note})
		da = append(da, st)
	}
	if mf.ipIsPrivate {
		st, note := ec.matchIPIsPrivate(false)
		conds = append(conds, CondEval{Field: "ip_is_private", Value: "true", Group: groupDestAddr, Status: st, Note: note})
		da = append(da, st)
	}
	if len(da) > 0 {
		groupStatuses = append(groupStatuses, orStatus(da))
	}

	// --- source address group (OR) — source is unknown offline ---
	var sa []string
	if len(mf.srcIPCIDR) > 0 {
		conds = append(conds, CondEval{Field: "source_ip_cidr", Value: joinVals(mf.srcIPCIDR), Group: groupSrcAddr, Status: StatusUnknown, Note: "client source address is unknown"})
		sa = append(sa, StatusUnknown)
	}
	if mf.srcIPIsPriv {
		conds = append(conds, CondEval{Field: "source_ip_is_private", Value: "true", Group: groupSrcAddr, Status: StatusUnknown, Note: "client source address is unknown"})
		sa = append(sa, StatusUnknown)
	}
	if len(sa) > 0 {
		groupStatuses = append(groupStatuses, orStatus(sa))
	}

	// --- destination port group (OR) ---
	// A bare domain/IP has no port, so port rules are UNKNOWN. When the input line
	// carries an explicit host:port, the given port is used and rules become
	// determinable (match / no_match).
	var dp []string
	if len(mf.port) > 0 {
		if ec.havePort {
			st, matched := ec.matchPort(mf.port)
			conds = append(conds, CondEval{Field: "port", Value: joinU16(mf.port), Group: groupDestPort, Status: st, Matched: matched, Note: fmt.Sprintf("destination port %d (from input)", ec.destPort)})
			dp = append(dp, st)
		} else {
			conds = append(conds, CondEval{Field: "port", Value: joinU16(mf.port), Group: groupDestPort, Status: StatusUnknown, Note: "destination port is not part of the query (add :port to the input to check)"})
			dp = append(dp, StatusUnknown)
		}
	}
	if len(mf.portRange) > 0 {
		if ec.havePort {
			st, matched := ec.matchPortRange(mf.portRange)
			conds = append(conds, CondEval{Field: "port_range", Value: joinVals(mf.portRange), Group: groupDestPort, Status: st, Matched: matched, Note: fmt.Sprintf("destination port %d (from input)", ec.destPort)})
			dp = append(dp, st)
		} else {
			conds = append(conds, CondEval{Field: "port_range", Value: joinVals(mf.portRange), Group: groupDestPort, Status: StatusUnknown, Note: "destination port is not part of the query (add :port to the input to check)"})
			dp = append(dp, StatusUnknown)
		}
	}
	if len(dp) > 0 {
		groupStatuses = append(groupStatuses, orStatus(dp))
	}

	// --- source port group (OR) — unknown ---
	var sp []string
	if len(mf.srcPort) > 0 {
		conds = append(conds, CondEval{Field: "source_port", Value: joinU16(mf.srcPort), Group: groupSrcPort, Status: StatusUnknown, Note: "client source port is unknown"})
		sp = append(sp, StatusUnknown)
	}
	if len(mf.srcPortRange) > 0 {
		conds = append(conds, CondEval{Field: "source_port_range", Value: joinVals(mf.srcPortRange), Group: groupSrcPort, Status: StatusUnknown, Note: "client source port is unknown"})
		sp = append(sp, StatusUnknown)
	}
	if len(sp) > 0 {
		groupStatuses = append(groupStatuses, orStatus(sp))
	}

	// --- rule_set group (OR across tags) ---
	if len(mf.ruleSet) > 0 {
		var rsStatuses []string
		for _, tag := range mf.ruleSet {
			rse := ec.rs.evaluate(tag, ec, mf.rsMatchSource)
			conds = append(conds, CondEval{Field: "rule_set", Value: tag, Group: groupRuleSet, Status: rse.Status, RuleSet: rse})
			rsStatuses = append(rsStatuses, rse.Status)
		}
		groupStatuses = append(groupStatuses, orStatus(rsStatuses))
	}

	// --- "other" fields (AND) ---
	if len(mf.network) > 0 {
		st := ec.matchNetwork(mf.network)
		note := ""
		if st == StatusUnknown {
			note = "connection network (tcp/udp) not specified"
		}
		conds = append(conds, CondEval{Field: "network", Value: joinVals(mf.network), Group: groupOther, Status: st, Note: note})
		groupStatuses = append(groupStatuses, st)
	}
	if len(mf.protocol) > 0 {
		st := ec.matchProtocol(mf.protocol)
		note := ""
		switch st {
		case StatusUnknown:
			note = "sniffed connection protocol not specified (set an assumed protocol to check)"
		case StatusMatch, StatusNoMatch:
			note = fmt.Sprintf("assumed protocol %q", ec.protocol)
		}
		conds = append(conds, CondEval{Field: "protocol", Value: joinVals(mf.protocol), Group: groupOther, Status: st, Note: note})
		groupStatuses = append(groupStatuses, st)
	}
	if len(mf.queryType) > 0 {
		st, matched := ec.matchQueryType(mf.queryType)
		conds = append(conds, CondEval{Field: "query_type", Value: queryTypeList(mf.queryType), Group: groupOther, Status: st, Matched: matched, Note: "evaluated for the DNS query type shown"})
		groupStatuses = append(groupStatuses, st)
	}
	// DNS response-address filters: not applicable to query-routing.
	for _, kv := range mf.dnsFilter {
		conds = append(conds, CondEval{Field: kv.field, Value: kv.value, Group: groupOther, Status: StatusUnknown, Note: "matches the DNS response addresses, evaluated after resolution"})
		groupStatuses = append(groupStatuses, StatusUnknown)
	}
	// Unknown/undeterminable fields (protocol, process, clash_mode, ...).
	for _, kv := range mf.unknowns {
		conds = append(conds, CondEval{Field: kv.field, Value: kv.value, Group: groupOther, Status: StatusUnknown, Note: "cannot be determined offline"})
		groupStatuses = append(groupStatuses, StatusUnknown)
	}

	status := StatusMatch
	if len(groupStatuses) > 0 {
		status = andStatus(groupStatuses)
	}
	if mf.invert {
		status = invertStatus(status)
	}
	return status, conds
}

// ---- individual matchers (reusing sing-box primitives where useful) ----

func (ec *evalCtx) matchDomainExact(domains []string) (string, string) {
	if ec.host == "" {
		return StatusNoMatch, ""
	}
	if domainMatcher(domains, nil).Match(ec.host) {
		for _, d := range domains {
			if strings.EqualFold(strings.TrimSuffix(d, "."), ec.host) {
				return StatusMatch, d
			}
		}
		return StatusMatch, ""
	}
	return StatusNoMatch, ""
}

func (ec *evalCtx) matchDomainSuffix(suffixes []string) (string, string) {
	if ec.host == "" {
		return StatusNoMatch, ""
	}
	if domainMatcher(nil, suffixes).Match(ec.host) {
		for _, s := range suffixes {
			if domainMatcher(nil, []string{s}).Match(ec.host) {
				return StatusMatch, s
			}
		}
		return StatusMatch, ""
	}
	return StatusNoMatch, ""
}

// domainMatcher builds a sing/common/domain matcher for the given exact domains
// and suffixes. This mirrors route/rule.NewDomainItem exactly (it calls
// domain.NewMatcher(domains, domainSuffixes, false)), so matching stays faithful
// to sing-box's succinct-set suffix logic without importing route/rule.
func domainMatcher(domains, suffixes []string) *domain.Matcher {
	return domain.NewMatcher(domains, suffixes, false)
}

func (ec *evalCtx) matchKeyword(keywords []string) (string, string) {
	if ec.host == "" {
		return StatusNoMatch, ""
	}
	for _, kw := range keywords {
		if kw != "" && strings.Contains(ec.host, strings.ToLower(kw)) {
			return StatusMatch, kw
		}
	}
	return StatusNoMatch, ""
}

func (ec *evalCtx) matchRegex(exprs []string) (string, string) {
	if ec.host == "" {
		return StatusNoMatch, ""
	}
	for _, e := range exprs {
		re, err := regexp.Compile(e)
		if err != nil {
			continue
		}
		if re.MatchString(ec.host) {
			return StatusMatch, e
		}
	}
	return StatusNoMatch, ""
}

// matchIPCIDR evaluates an ip_cidr condition. For a domain destination it is
// UNKNOWN until addresses are resolved; then it matches those addresses.
func (ec *evalCtx) matchIPCIDR(cidrs []string, isSource bool) (string, string, string) {
	if isSource {
		return StatusUnknown, "", "client source address is unknown"
	}
	addrs := ec.matchAddrs()
	if len(addrs) == 0 {
		if ec.host != "" {
			return StatusUnknown, "", "requires the resolved IP (domain not resolved for this evaluation)"
		}
		return StatusNoMatch, "", ""
	}
	for _, cidr := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if p.Contains(a.Unmap()) || p.Contains(a) {
				return StatusMatch, cidr, ""
			}
		}
	}
	return StatusNoMatch, "", ""
}

func (ec *evalCtx) matchRawIPSet(set *netipx.IPSet) (string, string) {
	addrs := ec.matchAddrs()
	if len(addrs) == 0 {
		if ec.host != "" {
			return StatusUnknown, "requires the resolved IP"
		}
		return StatusNoMatch, ""
	}
	for _, a := range addrs {
		if set.Contains(a.Unmap()) || set.Contains(a) {
			return StatusMatch, ""
		}
	}
	return StatusNoMatch, ""
}

func (ec *evalCtx) matchIPIsPrivate(isSource bool) (string, string) {
	if isSource {
		return StatusUnknown, "client source address is unknown"
	}
	addrs := ec.matchAddrs()
	if len(addrs) == 0 {
		if ec.host != "" {
			return StatusUnknown, "requires the resolved IP"
		}
		return StatusNoMatch, ""
	}
	for _, a := range addrs {
		if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
			return StatusMatch, ""
		}
	}
	return StatusNoMatch, ""
}

// matchAddrs returns the destination addresses available for IP matching.
func (ec *evalCtx) matchAddrs() []netip.Addr {
	if ec.destIsIP {
		return []netip.Addr{ec.destAddr}
	}
	return ec.addresses
}

func (ec *evalCtx) matchNetwork(networks []string) string {
	if ec.network == "" {
		return StatusUnknown
	}
	// route/rule.NetworkItem matches when the connection network is in the set.
	for _, n := range networks {
		if n == ec.network {
			return StatusMatch
		}
	}
	return StatusNoMatch
}

// matchPort evaluates a `port` condition against the destination port supplied
// on the input line. Callers guarantee ec.havePort is true.
func (ec *evalCtx) matchPort(ports []uint16) (string, string) {
	for _, p := range ports {
		if p == ec.destPort {
			return StatusMatch, fmt.Sprint(p)
		}
	}
	return StatusNoMatch, ""
}

// matchPortRange evaluates a `port_range` condition, mirroring sing-box's
// route/rule.PortRangeItem: each entry splits on the first ':', an empty low
// bound means 0 and a trailing ':' means 65535; a port matches when it falls in
// any [start, end] inclusive range. Callers guarantee ec.havePort is true.
func (ec *evalCtx) matchPortRange(ranges []string) (string, string) {
	for _, r := range ranges {
		i := strings.IndexByte(r, ':')
		if i < 0 {
			continue // malformed (sing-box rejects at parse time)
		}
		var start, end uint64 = 0, 0xFFFF
		if i > 0 {
			v, err := strconv.ParseUint(r[:i], 10, 16)
			if err != nil {
				continue
			}
			start = v
		}
		if i != len(r)-1 {
			v, err := strconv.ParseUint(r[i+1:], 10, 16)
			if err != nil {
				continue
			}
			end = v
		}
		if uint64(ec.destPort) >= start && uint64(ec.destPort) <= end {
			return StatusMatch, r
		}
	}
	return StatusNoMatch, ""
}

// matchProtocol evaluates a `protocol` condition against the assumed sniffed
// protocol. Like network it is UNKNOWN until a protocol is assumed; sing-box's
// route/rule.ProtocolItem matches when the sniffed protocol is in the set.
func (ec *evalCtx) matchProtocol(protocols []string) string {
	if ec.protocol == "" {
		return StatusUnknown
	}
	for _, p := range protocols {
		if strings.EqualFold(p, ec.protocol) {
			return StatusMatch
		}
	}
	return StatusNoMatch
}

func (ec *evalCtx) matchQueryType(types []option.DNSQueryType) (string, string) {
	if ec.queryType == 0 {
		return StatusUnknown, ""
	}
	// route/rule.QueryTypeItem matches when the query type is in the set.
	for _, t := range types {
		if uint16(t) == ec.queryType {
			return StatusMatch, queryTypeName(ec.queryType)
		}
	}
	return StatusNoMatch, ""
}

// ---- display helpers ----

func joinVals(v []string) string {
	if len(v) <= 4 {
		return strings.Join(v, ", ")
	}
	return strings.Join(v[:4], ", ") + fmt.Sprintf(", …(+%d)", len(v)-4)
}

func joinU16(v []uint16) string {
	parts := make([]string, 0, len(v))
	for _, p := range v {
		parts = append(parts, fmt.Sprint(p))
	}
	return joinVals(parts)
}

func queryTypeList(types []option.DNSQueryType) string {
	parts := make([]string, 0, len(types))
	for _, t := range types {
		parts = append(parts, queryTypeName(uint16(t)))
	}
	return strings.Join(parts, ", ")
}

var queryTypeNames = map[uint16]string{1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 12: "PTR", 33: "SRV", 65: "HTTPS", 64: "SVCB"}

func queryTypeName(t uint16) string {
	if n, ok := queryTypeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("TYPE%d", t)
}
