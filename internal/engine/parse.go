package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
)

// Config is the parsed subset of a sing-box configuration relevant to routing.
type Config struct {
	RouteRules    []option.Rule
	RouteRuleSets []option.RuleSet
	RouteFinal    string

	DNSRules   []option.DNSRule
	DNSFinal   string
	DNSServers []DNSServerInfo

	Warnings []string
}

// ParseConfig parses a raw sing-box JSON (JSONC allowed) configuration into the
// routing-relevant structures, using sing-box's own option unmarshalers so that
// rule/action/rule-set dispatch is version-accurate.
func ParseConfig(text string) (*Config, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, fmt.Errorf("empty configuration")
	}
	ctx := context.Background()
	var raw map[string]json.RawMessage
	if err := sjson.UnmarshalContext(ctx, []byte(text), &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	cfg := &Config{}

	if rm, ok := raw["route"]; ok && len(rm) > 0 {
		var route struct {
			Rules   []option.Rule    `json:"rules"`
			RuleSet []option.RuleSet `json:"rule_set"`
			Final   string           `json:"final"`
		}
		if err := sjson.UnmarshalContext(ctx, rm, &route); err != nil {
			return nil, fmt.Errorf("route: %w", err)
		}
		cfg.RouteRules = route.Rules
		cfg.RouteRuleSets = route.RuleSet
		cfg.RouteFinal = route.Final
	}

	if rm, ok := raw["dns"]; ok && len(rm) > 0 {
		var dnsSec struct {
			Rules   []option.DNSRule  `json:"rules"`
			Final   string            `json:"final"`
			Servers []json.RawMessage `json:"servers"`
		}
		if err := sjson.UnmarshalContext(ctx, rm, &dnsSec); err != nil {
			return nil, fmt.Errorf("dns: %w", err)
		}
		cfg.DNSRules = dnsSec.Rules
		cfg.DNSFinal = dnsSec.Final
		cfg.DNSServers = parseDNSServers(dnsSec.Servers)
	}

	return cfg, nil
}

// parseDNSServers extracts display metadata from dns.servers generically so we
// don't need the DNS transport registry (which would pull in the whole protocol
// dependency tree).
func parseDNSServers(servers []json.RawMessage) []DNSServerInfo {
	var out []DNSServerInfo
	for _, raw := range servers {
		var m map[string]any
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		info := DNSServerInfo{
			Tag:     asString(m["tag"]),
			Type:    asString(m["type"]),
			Detour:  asString(m["detour"]),
			Address: firstString(m, "server", "address"),
		}
		out = append(out, info)
	}
	return out
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// findDNSServer returns the server info for a tag, if present.
func (c *Config) findDNSServer(tag string) *DNSServerInfo {
	for i := range c.DNSServers {
		if c.DNSServers[i].Tag == tag {
			return &c.DNSServers[i]
		}
	}
	return nil
}

// effectiveDNSFinal returns the DNS server tag used when no rule matches: the
// configured dns.final, or the first server tag if unset.
func (c *Config) effectiveDNSFinal() string {
	if c.DNSFinal != "" {
		return c.DNSFinal
	}
	if len(c.DNSServers) > 0 {
		return c.DNSServers[0].Tag
	}
	return ""
}
