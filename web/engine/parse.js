'use strict';

// Config parsing for the sing-vis JS engine: JSONC → normalized route/DNS rule
// nodes, rule-set definitions and DNS servers. Faithful to sing-box's option
// unmarshalers for the routing-relevant subset — Listable (single-or-array)
// normalization, rule/action dispatch, deprecated field aliases, and the exact
// field-extraction order the original engine (rules.go) relied on.
//
// Self-contained (no browser APIs). Exposes globalThis.SingvisParse.

(function (root) {
  // ---- JSONC → JSON ----
  // Strip // line comments and /* */ block comments (string-aware) and tolerate
  // trailing commas, then JSON.parse. sing-box accepts JSONC; being a superset is
  // acceptable for a visualizer.
  function stripJSONC(text) {
    let out = '';
    let i = 0;
    const n = text.length;
    let inStr = false, quote = '';
    while (i < n) {
      const c = text[i];
      if (inStr) {
        out += c;
        if (c === '\\') { out += text[i + 1] || ''; i += 2; continue; }
        if (c === quote) inStr = false;
        i++;
        continue;
      }
      if (c === '"' || c === '\'') { inStr = true; quote = c; out += c; i++; continue; }
      if (c === '/' && text[i + 1] === '/') { i += 2; while (i < n && text[i] !== '\n') i++; continue; }
      if (c === '/' && text[i + 1] === '*') { i += 2; while (i < n && !(text[i] === '*' && text[i + 1] === '/')) i++; i += 2; continue; }
      out += c; i++;
    }
    // Remove trailing commas before } or ].
    return out.replace(/,(\s*[}\]])/g, '$1');
  }

  function parseJSONC(text) {
    // Try strict JSON first (single-quoted strings aren't valid JSON, so the
    // stripper preserves them; JSON.parse will reject if actually used).
    return JSON.parse(stripJSONC(text));
  }

  function list(v) {
    if (v == null) return [];
    return Array.isArray(v) ? v : [v];
  }

  // ---- DNS query type names (miekg/dns subset used for parsing) ----
  const QTYPE_TO_NUM = {
    A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, HINFO: 13, MX: 15, TXT: 16, RP: 17,
    AFSDB: 18, SIG: 24, KEY: 25, AAAA: 28, LOC: 29, SRV: 33, NAPTR: 35, KX: 36,
    CERT: 37, DNAME: 39, OPT: 41, APL: 42, DS: 43, SSHFP: 44, IPSECKEY: 45,
    RRSIG: 46, NSEC: 47, DNSKEY: 48, DHCID: 49, NSEC3: 50, NSEC3PARAM: 51,
    TLSA: 52, SMIMEA: 53, HIP: 55, CDS: 59, CDNSKEY: 60, OPENPGPKEY: 61,
    CSYNC: 62, ZONEMD: 63, SVCB: 64, HTTPS: 65, SPF: 99, EUI48: 108, EUI64: 109,
    TKEY: 249, TSIG: 250, IXFR: 251, AXFR: 252, ANY: 255, URI: 256, CAA: 257,
  };

  function qtypeNum(v) {
    if (typeof v === 'number') return v & 0xffff;
    const s = String(v).toUpperCase();
    if (Object.prototype.hasOwnProperty.call(QTYPE_TO_NUM, s)) return QTYPE_TO_NUM[s];
    const m = /^TYPE(\d+)$/.exec(s);
    if (m) return Number(m[1]) & 0xffff;
    throw new Error('unknown DNS query type: ' + v);
  }

  // ---- display join helpers (mirror conditions.go joinVals/joinU16) ----
  function joinVals(v) {
    if (v.length <= 4) return v.join(', ');
    return v.slice(0, 4).join(', ') + `, …(+${v.length - 4})`;
  }
  function joinU16(v) { return joinVals(v.map(String)); }
  function itoa(i) { return String(i); }

  // ---- matchFields extraction ----
  function newMF() {
    return {
      domain: [], domainSuffix: [], domainKeyword: [], domainRegex: [],
      ipCIDR: [], ipIsPrivate: false, srcIPCIDR: [], srcIPIsPriv: false,
      port: [], portRange: [], srcPort: [], srcPortRange: [],
      network: [], protocol: [], queryType: [], ruleSet: [], rsMatchSource: false,
      invert: false, rawDomain: null, rawIPSet: null, unknowns: [], dnsFilter: [],
    };
  }

  function addUnknownList(mf, field, v) {
    const l = list(v);
    if (l.length > 0) mf.unknowns.push({ field, value: joinVals(l.map(String)) });
  }
  function addUnknownDeprecated(mf, field, v) {
    const l = list(v);
    if (l.length > 0) mf.unknowns.push({ field: field + ' (deprecated/removed)', value: joinVals(l.map(String)) });
  }

  function u16list(v) { return list(v).map((x) => Number(x) & 0xffff); }
  function strlist(v) { return list(v).map(String); }

  function fieldsFromRoute(r) {
    const mf = newMF();
    mf.domain = strlist(r.domain);
    mf.domainSuffix = strlist(r.domain_suffix);
    mf.domainKeyword = strlist(r.domain_keyword);
    mf.domainRegex = strlist(r.domain_regex);
    mf.ipCIDR = strlist(r.ip_cidr);
    mf.ipIsPrivate = r.ip_is_private === true;
    mf.srcIPCIDR = strlist(r.source_ip_cidr);
    mf.srcIPIsPriv = r.source_ip_is_private === true;
    mf.port = u16list(r.port);
    mf.portRange = strlist(r.port_range);
    mf.srcPort = u16list(r.source_port);
    mf.srcPortRange = strlist(r.source_port_range);
    mf.network = strlist(r.network);
    mf.protocol = strlist(r.protocol);
    mf.ruleSet = strlist(r.rule_set);
    mf.rsMatchSource = r.rule_set_ip_cidr_match_source === true || r.rule_set_ipcidr_match_source === true;
    mf.invert = r.invert === true;
    addUnknownList(mf, 'inbound', r.inbound);
    addUnknownList(mf, 'client', r.client);
    addUnknownList(mf, 'auth_user', r.auth_user);
    addUnknownList(mf, 'user', r.user);
    addUnknownList(mf, 'process_name', r.process_name);
    addUnknownList(mf, 'process_path', r.process_path);
    addUnknownList(mf, 'process_path_regex', r.process_path_regex);
    addUnknownList(mf, 'package_name', r.package_name);
    addUnknownList(mf, 'package_name_regex', r.package_name_regex);
    addUnknownList(mf, 'wifi_ssid', r.wifi_ssid);
    addUnknownList(mf, 'wifi_bssid', r.wifi_bssid);
    addUnknownList(mf, 'source_mac_address', r.source_mac_address);
    addUnknownList(mf, 'source_hostname', r.source_hostname);
    addUnknownList(mf, 'preferred_by', r.preferred_by);
    addUnknownDeprecated(mf, 'geosite', r.geosite);
    addUnknownDeprecated(mf, 'geoip', r.geoip);
    addUnknownDeprecated(mf, 'source_geoip', r.source_geoip);
    if (r.clash_mode) mf.unknowns.push({ field: 'clash_mode', value: String(r.clash_mode) });
    if (r.ip_version) mf.unknowns.push({ field: 'ip_version', value: itoa(r.ip_version) });
    if (r.network_is_expensive === true) mf.unknowns.push({ field: 'network_is_expensive', value: 'true' });
    if (r.network_is_constrained === true) mf.unknowns.push({ field: 'network_is_constrained', value: 'true' });
    if (list(r.network_type).length > 0) mf.unknowns.push({ field: 'network_type', value: strlist(r.network_type).join(', ') });
    return mf;
  }

  function fieldsFromDNS(r) {
    const mf = newMF();
    mf.domain = strlist(r.domain);
    mf.domainSuffix = strlist(r.domain_suffix);
    mf.domainKeyword = strlist(r.domain_keyword);
    mf.domainRegex = strlist(r.domain_regex);
    mf.srcIPCIDR = strlist(r.source_ip_cidr);
    mf.srcIPIsPriv = r.source_ip_is_private === true;
    mf.port = u16list(r.port);
    mf.portRange = strlist(r.port_range);
    mf.srcPort = u16list(r.source_port);
    mf.srcPortRange = strlist(r.source_port_range);
    mf.network = strlist(r.network);
    mf.protocol = strlist(r.protocol);
    mf.queryType = u16list(list(r.query_type).map(qtypeNum));
    mf.ruleSet = strlist(r.rule_set);
    mf.rsMatchSource = r.rule_set_ip_cidr_match_source === true || r.rule_set_ipcidr_match_source === true;
    mf.invert = r.invert === true;
    // DNS ip_cidr / ip_is_private / ip_accept_any and response_* are response
    // filters, not query-routing conditions.
    if (list(r.ip_cidr).length > 0) mf.dnsFilter.push({ field: 'ip_cidr', value: joinVals(strlist(r.ip_cidr)) });
    if (r.ip_is_private === true) mf.dnsFilter.push({ field: 'ip_is_private', value: 'true' });
    if (r.ip_accept_any === true) mf.dnsFilter.push({ field: 'ip_accept_any', value: 'true' });
    if (r.response_rcode != null) mf.dnsFilter.push({ field: 'response_rcode', value: 'set' });
    if (r.match_response != null) mf.dnsFilter.push({ field: 'match_response', value: 'set' });
    addUnknownList(mf, 'inbound', r.inbound);
    addUnknownList(mf, 'auth_user', r.auth_user);
    addUnknownList(mf, 'user', r.user);
    addUnknownList(mf, 'outbound', r.outbound);
    addUnknownList(mf, 'process_name', r.process_name);
    addUnknownList(mf, 'process_path', r.process_path);
    addUnknownList(mf, 'package_name', r.package_name);
    addUnknownList(mf, 'wifi_ssid', r.wifi_ssid);
    addUnknownList(mf, 'wifi_bssid', r.wifi_bssid);
    addUnknownDeprecated(mf, 'geosite', r.geosite);
    if (r.clash_mode) mf.unknowns.push({ field: 'clash_mode', value: String(r.clash_mode) });
    if (r.ip_version) mf.unknowns.push({ field: 'ip_version', value: itoa(r.ip_version) });
    return mf;
  }

  // fieldsFromHeadless handles source-format rule-set rules. Binary (.srs) rules
  // are decoded to this same source shape by the srs decoder, so this covers both.
  function fieldsFromHeadless(r) {
    const mf = newMF();
    mf.domainKeyword = strlist(r.domain_keyword);
    mf.domainRegex = strlist(r.domain_regex);
    mf.srcIPCIDR = strlist(r.source_ip_cidr);
    mf.port = u16list(r.port);
    mf.portRange = strlist(r.port_range);
    mf.srcPort = u16list(r.source_port);
    mf.srcPortRange = strlist(r.source_port_range);
    mf.network = strlist(r.network);
    mf.queryType = u16list(list(r.query_type).map(qtypeNum));
    mf.invert = r.invert === true;
    mf.domain = strlist(r.domain);
    mf.domainSuffix = strlist(r.domain_suffix);
    mf.ipCIDR = strlist(r.ip_cidr);
    if (list(r.adguard_domain).length > 0 || r.adguard_domain_present) {
      mf.unknowns.push({ field: 'adguard_domain', value: '«set»' });
    }
    addUnknownList(mf, 'process_name', r.process_name);
    addUnknownList(mf, 'process_path', r.process_path);
    addUnknownList(mf, 'package_name', r.package_name);
    addUnknownList(mf, 'wifi_ssid', r.wifi_ssid);
    addUnknownList(mf, 'wifi_bssid', r.wifi_bssid);
    if (r.network_is_expensive === true) mf.unknowns.push({ field: 'network_is_expensive', value: 'true' });
    if (r.network_is_constrained === true) mf.unknowns.push({ field: 'network_is_constrained', value: 'true' });
    if (list(r.network_type).length > 0) mf.unknowns.push({ field: 'network_type', value: strlist(r.network_type).join(', ') });
    return mf;
  }

  // ---- action detection (route.go / dns.go) ----
  function normStrategy(s) {
    if (!s || s === 'as_is') return '';
    return String(s);
  }

  function routeActionOf(r) {
    let typ = r.action || 'route';
    const ai = { typ, outbound: '', detail: '', terminal: false, isResolve: false, strategy: '', server: '' };
    switch (typ) {
      case 'route':
        ai.outbound = r.outbound || '';
        ai.terminal = true;
        ai.detail = 'route → ' + (ai.outbound || '(default outbound)');
        break;
      case 'route-options':
        ai.detail = 'route-options (non-terminal)';
        break;
      case 'reject': {
        const m = r.method || 'default';
        ai.terminal = true;
        ai.detail = 'reject (' + m + ')';
        break;
      }
      case 'hijack-dns':
        ai.terminal = true;
        ai.detail = 'hijack-dns';
        break;
      case 'sniff':
        ai.detail = 'sniff (non-terminal)';
        break;
      case 'resolve':
        ai.isResolve = true;
        ai.strategy = normStrategy(r.strategy);
        ai.server = r.server || '';
        ai.detail = 'resolve';
        if (ai.strategy) ai.detail += ' (' + ai.strategy + ')';
        break;
      case 'direct':
        ai.terminal = true;
        ai.detail = 'direct';
        ai.outbound = 'direct';
        break;
      case 'bypass':
        ai.outbound = r.outbound || '';
        ai.terminal = ai.outbound !== '';
        ai.detail = 'bypass';
        break;
      default:
        ai.terminal = true;
        ai.detail = typ;
    }
    return ai;
  }

  function dnsActionOf(r) {
    let typ = r.action || 'route';
    const ai = { typ, outbound: '', detail: '', terminal: false, isResolve: false, strategy: '', server: '' };
    switch (typ) {
      case 'route':
        ai.server = r.server || '';
        ai.terminal = true;
        ai.detail = 'route → server ' + (ai.server || '(default)');
        break;
      case 'route-options':
        ai.detail = 'route-options (non-terminal)';
        break;
      case 'reject': {
        const m = r.method || 'default';
        ai.terminal = true;
        ai.detail = 'reject (' + m + ')';
        break;
      }
      case 'predefined':
        ai.terminal = true;
        ai.detail = 'predefined response';
        break;
      case 'evaluate':
        ai.server = r.server || '';
        ai.detail = 'evaluate (non-terminal)';
        break;
      case 'respond':
        ai.terminal = true;
        ai.detail = 'respond';
        break;
      default:
        ai.terminal = true;
        ai.detail = typ;
    }
    return ai;
  }

  // ---- rule-node building ----
  function buildRouteNode(raw) {
    if (raw && raw.type === 'logical') {
      return {
        type: 'logical', mode: raw.mode || 'and', invert: raw.invert === true,
        sub: list(raw.rules).map(buildRouteNode),
      };
    }
    return { type: 'default', mf: fieldsFromRoute(raw || {}) };
  }
  function buildDNSNode(raw) {
    if (raw && raw.type === 'logical') {
      return {
        type: 'logical', mode: raw.mode || 'and', invert: raw.invert === true,
        sub: list(raw.rules).map(buildDNSNode),
      };
    }
    return { type: 'default', mf: fieldsFromDNS(raw || {}) };
  }
  // Headless rule nodes (rule sets) — no action.
  function buildHeadlessNode(raw) {
    if (raw && raw.type === 'logical') {
      return {
        type: 'logical', mode: raw.mode || 'and', invert: raw.invert === true,
        sub: list(raw.rules).map(buildHeadlessNode),
      };
    }
    return { type: 'default', mf: fieldsFromHeadless(raw || {}) };
  }

  // ---- rule-set definitions ----
  function ruleSetFormatFromPath(path) {
    return String(path || '').toLowerCase().endsWith('.srs') ? 'binary' : 'source';
  }

  function normalizeRuleSet(raw) {
    const tags = strlist(raw.tag);
    const type = raw.type || 'inline';
    const rs = { tags, type, format: raw.format || '' };
    if (type === 'inline') {
      rs.rules = list(raw.rules).map(buildHeadlessNode);
    } else if (type === 'local') {
      rs.path = raw.path || '';
      if (!rs.format) rs.format = ruleSetFormatFromPath(rs.path);
    } else if (type === 'remote') {
      rs.url = raw.url || '';
      if (!rs.format) rs.format = ruleSetFormatFromPath(rs.url);
    }
    return rs;
  }

  // ---- DNS servers ----
  function parseDNSServers(servers) {
    const out = [];
    for (const s of list(servers)) {
      if (!s || typeof s !== 'object') continue;
      out.push({
        tag: s.tag || '',
        type: s.type || '',
        detour: s.detour || '',
        address: (typeof s.server === 'string' && s.server) ? s.server : (typeof s.address === 'string' ? s.address : ''),
      });
    }
    return out;
  }

  // ---- top-level ----
  function parseConfig(text) {
    text = String(text || '').trim();
    if (text === '') throw new Error('empty configuration');
    let raw;
    try {
      raw = parseJSONC(text);
    } catch (e) {
      throw new Error('invalid JSON: ' + (e && e.message ? e.message : String(e)));
    }
    if (!raw || typeof raw !== 'object') throw new Error('invalid JSON: not an object');

    const cfg = {
      routeRules: [], routeRuleSets: [], routeFinal: '',
      dnsRules: [], dnsFinal: '', dnsServers: [], warnings: [],
    };

    const route = raw.route;
    if (route && typeof route === 'object') {
      cfg.routeRules = list(route.rules).map((r) => {
        const n = buildRouteNode(r);
        n.action = routeActionOf(r || {});
        return n;
      });
      cfg.routeRuleSets = list(route.rule_set).map(normalizeRuleSet);
      cfg.routeFinal = route.final || '';
    }

    const dns = raw.dns;
    if (dns && typeof dns === 'object') {
      cfg.dnsRules = list(dns.rules).map((r) => {
        const n = buildDNSNode(r);
        n.action = dnsActionOf(r || {});
        return n;
      });
      cfg.dnsFinal = dns.final || '';
      cfg.dnsServers = parseDNSServers(dns.servers);
    }
    return cfg;
  }

  root.SingvisParse = {
    parseConfig, joinVals, joinU16, fieldsFromHeadless, buildHeadlessNode,
    QTYPE_TO_NUM, qtypeNum,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
