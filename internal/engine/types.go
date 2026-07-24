package engine

// Tri-state status for a condition / rule evaluation.
const (
	StatusMatch   = "match"
	StatusNoMatch = "no_match"
	StatusUnknown = "unknown" // depends on connection attributes we cannot know offline
)

// InputTrace is the analysis result for one input line (a domain or IP).
type InputTrace struct {
	Input    string        `json:"input"`
	Kind     string        `json:"kind"` // "domain" | "ip" | "invalid"
	Error    string        `json:"error,omitempty"`
	Resolved *ResolvedInfo `json:"resolved,omitempty"`
	DNS      *DNSTrace     `json:"dns,omitempty"`
	// DNSAAAA is the same DNS routing evaluated for the AAAA query a happy-eyeballs
	// client issues alongside the A query. Present only when the name actually has
	// AAAA records (otherwise that query never influences the connection).
	DNSAAAA *DNSTrace   `json:"dnsAAAA,omitempty"`
	Route   *RouteTrace `json:"route,omitempty"`
}

// ResolvedInfo holds the DoH resolution result for a domain.
type ResolvedInfo struct {
	Server string   `json:"server"`
	IPv4   []string `json:"ipv4,omitempty"`
	IPv6   []string `json:"ipv6,omitempty"`
	Error  string   `json:"error,omitempty"`
}

// DNSTrace explains which DNS rule (and thus which DNS server / action) a domain
// hits during DNS resolution.
type DNSTrace struct {
	QueryType    string       `json:"queryType"` // the query type used for evaluation (A or AAAA)
	Steps        []RuleEval   `json:"steps"`
	MatchedIndex int          `json:"matchedIndex"` // -1 => fell through to final
	Final        string       `json:"final"`        // dns.final server tag (or effective default)
	Decision     *DNSDecision `json:"decision"`
	Note         string       `json:"note,omitempty"`
}

// DNSDecision is the resolved outcome of DNS routing.
type DNSDecision struct {
	ActionType string         `json:"actionType"` // route|reject|predefined|route-options|...
	Server     string         `json:"server,omitempty"`
	Detail     string         `json:"detail,omitempty"`
	ServerInfo *DNSServerInfo `json:"serverInfo,omitempty"`
	FromFinal  bool           `json:"fromFinal"` // decided by dns.final, not a rule
	Assumed    bool           `json:"assumed"`   // decision relied on unknown-condition assumptions
}

// DNSServerInfo describes a configured DNS server referenced by a route action.
type DNSServerInfo struct {
	Tag     string `json:"tag"`
	Type    string `json:"type,omitempty"`
	Address string `json:"address,omitempty"`
	Detour  string `json:"detour,omitempty"` // outbound used to reach this DNS server
}

// RouteTrace explains which route rule / rule-set a domain or IP hits and the
// final outbound.
type RouteTrace struct {
	Steps         []RuleEval     `json:"steps"`
	SelectedIndex int            `json:"selectedIndex"` // -1 => fell through to final
	Final         string         `json:"final"`
	Decision      *RouteDecision `json:"decision"`
}

// RouteDecision is the resolved outcome of route matching.
type RouteDecision struct {
	ActionType string `json:"actionType"` // route|reject|hijack-dns
	Outbound   string `json:"outbound,omitempty"`
	Detail     string `json:"detail,omitempty"`
	FromFinal  bool   `json:"fromFinal"`
	Assumed    bool   `json:"assumed"`
}

// RuleEval is the evaluation of one rule (default or logical) in a rule list.
type RuleEval struct {
	Index      int        `json:"index"`
	Type       string     `json:"type"`   // "default" | "logical"
	Status     string     `json:"status"` // match|no_match|unknown
	Summary    string     `json:"summary"`
	ActionType string     `json:"actionType"`
	ActionText string     `json:"actionText"`
	Terminal   bool       `json:"terminal"`
	Reached    bool       `json:"reached"` // false for rules after the terminal match (not shown)
	Invert     bool       `json:"invert,omitempty"`
	Conditions []CondEval `json:"conditions,omitempty"`
	// Logical rule fields.
	Mode string     `json:"mode,omitempty"` // and|or
	Sub  []RuleEval `json:"sub,omitempty"`
	// Non-terminal side effects (resolve action results, notes).
	Effect string `json:"effect,omitempty"`
}

// CondEval is the evaluation of a single condition within a rule.
type CondEval struct {
	Field   string       `json:"field"`
	Value   string       `json:"value"`
	Group   string       `json:"group"` // dest_addr|src_addr|dest_port|src_port|other|rule_set
	Status  string       `json:"status"`
	Matched string       `json:"matched,omitempty"` // the specific value that matched, if known
	Note    string       `json:"note,omitempty"`
	RuleSet *RuleSetEval `json:"ruleSet,omitempty"`
}

// RuleSetEval is the evaluation of a referenced rule set.
type RuleSetEval struct {
	Tag        string     `json:"tag"`
	Type       string     `json:"type"`
	Status     string     `json:"status"`
	MatchedIdx int        `json:"matchedIdx"` // index of the matched headless rule, -1 if none
	Rules      []RuleEval `json:"rules,omitempty"`
	Count      int        `json:"count"`
	Error      string     `json:"error,omitempty"`
}
