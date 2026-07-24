package engine

import (
	"context"
	"net/netip"
	"strings"
)

func analyze(ctx context.Context, req Request) (*Result, error) {
	cfg, err := ParseConfig(req.Config)
	if err != nil {
		return nil, err
	}
	res := &Result{Warnings: append([]string{}, cfg.Warnings...)}
	if req.Resolver != nil {
		res.DoHServer = req.Resolver.Server()
	}
	rs := newRuleSetResolver(ctx, cfg, req.RuleSetFiles, &res.Warnings)

	for _, raw := range req.Inputs {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		res.Inputs = append(res.Inputs, analyzeInput(ctx, cfg, rs, req, line))
	}
	return res, nil
}

func analyzeInput(ctx context.Context, cfg *Config, rs *ruleSetResolver, req Request, line string) InputTrace {
	it := InputTrace{Input: line}
	host := normalizeInput(line)
	ec := &evalCtx{ctx: ctx, network: req.Network, rs: rs, resolver: req.Resolver}

	if addr, ok := parseIPInput(host); ok {
		it.Kind = "ip"
		ec.destIsIP = true
		ec.destAddr = addr
		it.Route = ec.matchRoute(cfg)
		return it
	}

	if !looksLikeDomain(host) {
		it.Kind = "invalid"
		it.Error = "not a valid domain or IP address"
		return it
	}

	it.Kind = "domain"
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	ec.host = host

	// Resolve via DoH for display and (optionally) to let IP rules match.
	if req.Resolver != nil {
		r, _ := req.Resolver.Resolve(ctx, host, "")
		if r != nil {
			it.Resolved = &ResolvedInfo{Server: req.Resolver.Server(), IPv4: r.IPv4, IPv6: r.IPv6, Error: r.Error}
			ec.resolved = it.Resolved
			if req.AssumeResolved {
				if addrs := parseAddrs(r.All("")); len(addrs) > 0 {
					ec.setAddresses(addrs)
				}
			}
		} else {
			it.Resolved = &ResolvedInfo{Server: req.Resolver.Server(), Error: "resolution failed"}
		}
	}

	it.DNS = ec.matchDNS(cfg)
	it.Route = ec.matchRoute(cfg)
	return it
}

// normalizeInput strips scheme, path, userinfo and a trailing :port so pasted
// URLs or host:port strings still analyze correctly.
func normalizeInput(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	s = strings.TrimSpace(s)
	// Strip a trailing :port for domains / IPv4 (but not raw IPv6 which has many colons).
	if strings.Count(s, ":") == 1 {
		host, port, ok := strings.Cut(s, ":")
		if ok && isAllDigits(port) && host != "" {
			s = host
		}
	}
	// Strip [ ] around bracketed IPv6.
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	return s
}

func parseIPInput(s string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, false
	}
	return addr, true
}

func looksLikeDomain(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_' || r == '*') {
			return false
		}
	}
	return true
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
