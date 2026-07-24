// Package main (cmd/srsdecode) reads a sing-box binary rule-set (.srs) and
// recovers it to plain source-format rules as JSON, so the pure-JS engine can
// match against it via its normal source path — no succinct-set / IP-set bit
// format has to be reimplemented in JS.
//
// This file holds the platform-independent decode logic, shared by the wasm
// entry point (browser) and the native CLI (tests + fixture generation).
package main

import (
	"bytes"
	"encoding/json"

	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/option"
)

// decode reads .srs bytes and returns { "version": N, "rules": [ ...source... ] }.
// recover=true so the compiled domain matcher / IP set are dumped back to
// domain / domain_suffix / ip_cidr lists.
func decode(data []byte) ([]byte, error) {
	compat, err := srs.Read(bytes.NewReader(data), true)
	if err != nil {
		return nil, err
	}
	plain, err := compat.Upgrade()
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"version": compat.Version,
		"rules":   serializeRules(plain.Rules),
	}
	return json.Marshal(out)
}

func serializeRules(rules []option.HeadlessRule) []map[string]any {
	out := make([]map[string]any, 0, len(rules))
	for _, r := range rules {
		out = append(out, serializeRule(r))
	}
	return out
}

func serializeRule(r option.HeadlessRule) map[string]any {
	if r.Type == "logical" {
		lo := r.LogicalOptions
		return map[string]any{
			"type":   "logical",
			"mode":   lo.Mode,
			"invert": lo.Invert,
			"rules":  serializeRules(lo.Rules),
		}
	}
	d := r.DefaultOptions
	m := map[string]any{}
	putStrings(m, "domain", d.Domain)
	putStrings(m, "domain_suffix", d.DomainSuffix)
	putStrings(m, "domain_keyword", d.DomainKeyword)
	putStrings(m, "domain_regex", d.DomainRegex)
	putStrings(m, "ip_cidr", d.IPCIDR)
	putStrings(m, "source_ip_cidr", d.SourceIPCIDR)
	if len(d.Port) > 0 {
		m["port"] = d.Port
	}
	putStrings(m, "port_range", d.PortRange)
	if len(d.SourcePort) > 0 {
		m["source_port"] = d.SourcePort
	}
	putStrings(m, "source_port_range", d.SourcePortRange)
	putStrings(m, "network", d.Network)
	if len(d.QueryType) > 0 {
		qt := make([]uint16, len(d.QueryType))
		for i, t := range d.QueryType {
			qt[i] = uint16(t)
		}
		m["query_type"] = qt
	}
	putStrings(m, "process_name", d.ProcessName)
	putStrings(m, "process_path", d.ProcessPath)
	putStrings(m, "package_name", d.PackageName)
	putStrings(m, "wifi_ssid", d.WIFISSID)
	putStrings(m, "wifi_bssid", d.WIFIBSSID)
	if d.NetworkIsExpensive {
		m["network_is_expensive"] = true
	}
	if d.NetworkIsConstrained {
		m["network_is_constrained"] = true
	}
	if len(d.NetworkType) > 0 {
		nt := make([]string, len(d.NetworkType))
		for i, t := range d.NetworkType {
			nt[i] = string(t)
		}
		m["network_type"] = nt
	}
	// AdGuard domain matching isn't evaluated offline; surface its presence so the
	// JS engine marks it UNKNOWN (both fields carry json:"-", so they wouldn't
	// round-trip through the normal marshaler).
	if d.AdGuardDomainMatcher != nil || len(d.AdGuardDomain) > 0 {
		m["adguard_domain_present"] = true
	}
	if d.Invert {
		m["invert"] = true
	}
	return m
}

func putStrings(m map[string]any, key string, v []string) {
	if len(v) > 0 {
		m[key] = v
	}
}
