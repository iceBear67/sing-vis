package engine

import (
	"context"
	"net/netip"
	"strconv"
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
	host, port, hasPort, scheme := normalizeInput(line)
	// A URL scheme on the line (e.g. rdp://host:port) sets the assumed protocol
	// for this input only, overriding the request-wide protocol assumption.
	protocol := req.Protocol
	if scheme != "" {
		protocol = scheme
	}
	ec := &evalCtx{ctx: ctx, network: req.Network, protocol: protocol, rs: rs, resolver: req.Resolver, destPort: port, havePort: hasPort}

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

	it.DNS = ec.matchDNS(cfg, 1) // dns.TypeA
	// Happy eyeballs: clients query A and AAAA in parallel and will happily use
	// the IPv6 answer, so the AAAA query's own DNS path matters too. Skipped when
	// the name has no AAAA records — that query is then moot.
	if it.Resolved != nil && len(it.Resolved.IPv6) > 0 {
		it.DNSAAAA = ec.matchDNS(cfg, 28) // dns.TypeAAAA
	}
	it.Route = ec.matchRoute(cfg)
	return it
}

// normalizeInput separates a leading URL scheme, path/userinfo and a trailing
// :port from an input line so pasted URLs or host:port strings still analyze
// correctly. The scheme and port are returned (rather than discarded): the port
// lets port / port_range rules be evaluated, and the scheme (e.g. rdp, tls) is
// used as a per-line protocol assumption. Raw IPv6 literals (many colons) are
// left intact; bracketed IPv6 (`[v6]` / `[v6]:port`) is unwrapped.
func normalizeInput(s string) (host string, port uint16, hasPort bool, scheme string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return s, 0, false, ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		scheme = strings.ToLower(s[:i])
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	s = strings.TrimSpace(s)

	// Bracketed IPv6, optionally with a port: [2001:db8::1] or [2001:db8::1]:443.
	if strings.HasPrefix(s, "[") {
		if end := strings.IndexByte(s, ']'); end >= 0 {
			hostPart := s[1:end]
			if rest := s[end+1:]; strings.HasPrefix(rest, ":") {
				if p, ok := parsePort(rest[1:]); ok {
					return hostPart, p, true, scheme
				}
			}
			return hostPart, 0, false, scheme
		}
	}

	// Unbracketed host:port — a single colon distinguishes it from raw IPv6.
	if strings.Count(s, ":") == 1 {
		if h, ps, ok := strings.Cut(s, ":"); ok && h != "" {
			if p, pok := parsePort(ps); pok {
				return h, p, true, scheme
			}
		}
	}

	// Strip stray brackets around a bare IPv6 (no port).
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	return s, 0, false, scheme
}

// parsePort parses a decimal port in the valid 1–65535 range. Port 0 is treated
// as "no port".
func parsePort(s string) (uint16, bool) {
	if !isAllDigits(s) {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil || v == 0 {
		return 0, false
	}
	return uint16(v), true
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
