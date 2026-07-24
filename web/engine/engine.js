'use strict';

// The sing-vis matching engine, ported from internal/engine (Go) to pure JS.
// Produces byte-for-byte the same engine.Result JSON the wasm build did, so the
// frontend is unchanged. Self-contained apart from SingvisIP (ip.js) and
// SingvisParse (parse.js); no browser APIs — the resolver and rule-set fetching
// are injected via `deps` so this runs identically in the worker and in Node.
//
// deps = {
//   resolver:  { resolve(name, strategy) -> Promise<{ipv4:[],ipv6:[],error?}> | null, server() -> string } | null,
//   ruleSetFiles: { [tagOrPath]: { format:'source'|'binary', data:string } },
//   fetchRuleSet: (url) -> Promise<{ ok, status, text?, bytes? }>,   // for type:remote
//   decodeSRS:  (bytesOrBase64) -> Promise<{rules:[...]}>,            // for binary format
// }

(function (root) {
  const IP = root.SingvisIP;
  const P = root.SingvisParse;
  const joinVals = P.joinVals, joinU16 = P.joinU16;

  const MATCH = 'match', NO_MATCH = 'no_match', UNKNOWN = 'unknown';

  // ---- tri-state combinators ----
  function orStatus(members) {
    let unknown = false;
    for (const s of members) { if (s === MATCH) return MATCH; if (s === UNKNOWN) unknown = true; }
    return unknown ? UNKNOWN : NO_MATCH;
  }
  function andStatus(members) {
    let unknown = false;
    for (const s of members) { if (s === NO_MATCH) return NO_MATCH; if (s === UNKNOWN) unknown = true; }
    return unknown ? UNKNOWN : MATCH;
  }
  function invertStatus(s) { return s === MATCH ? NO_MATCH : s === NO_MATCH ? MATCH : UNKNOWN; }

  // ---- query type display (engine's own small map) ----
  const QTYPE_NAME = { 1: 'A', 28: 'AAAA', 5: 'CNAME', 15: 'MX', 16: 'TXT', 12: 'PTR', 33: 'SRV', 65: 'HTTPS', 64: 'SVCB' };
  function queryTypeName(t) { return QTYPE_NAME[t] || ('TYPE' + t); }
  function queryTypeList(types) { return types.map(queryTypeName).join(', '); }

  // ---- output object constructors (mirror Go struct field order + omitempty) ----
  function condEval(o) {
    const c = { field: o.field, value: o.value, group: o.group, status: o.status };
    if (o.matched) c.matched = o.matched;
    if (o.note) c.note = o.note;
    if (o.ruleSet) c.ruleSet = o.ruleSet;
    return c;
  }
  function ruleEval(o) {
    const r = {
      index: o.index || 0, type: o.type, status: o.status, summary: o.summary || '',
      actionType: o.actionType || '', actionText: o.actionText || '',
      terminal: !!o.terminal, reached: !!o.reached,
    };
    if (o.invert) r.invert = true;
    if (o.conditions && o.conditions.length) r.conditions = o.conditions;
    if (o.mode) r.mode = o.mode;
    if (o.sub && o.sub.length) r.sub = o.sub;
    if (o.effect) r.effect = o.effect;
    return r;
  }

  // ---- matchers ----
  function trimDot(s) { return s.endsWith('.') ? s.slice(0, -1) : s; }

  function matchDomainExact(ec, domains) {
    if (ec.host === '') return [NO_MATCH, ''];
    const hit = domains.some((d) => trimDot(d) === ec.host); // case-sensitive succinct match
    if (!hit) return [NO_MATCH, ''];
    for (const d of domains) if (trimDot(d).toLowerCase() === ec.host.toLowerCase()) return [MATCH, d];
    return [MATCH, ''];
  }

  function suffixMatch(host, s) {
    if (s.length === 0) return false;
    if (s[0] === '.') return host.endsWith(s);
    return host === s || host.endsWith('.' + s);
  }
  function matchDomainSuffix(ec, suffixes) {
    if (ec.host === '') return [NO_MATCH, ''];
    for (const s of suffixes) if (suffixMatch(ec.host, s)) return [MATCH, s];
    return [NO_MATCH, ''];
  }

  function matchKeyword(ec, keywords) {
    if (ec.host === '') return [NO_MATCH, ''];
    for (const kw of keywords) if (kw !== '' && ec.host.includes(kw.toLowerCase())) return [MATCH, kw];
    return [NO_MATCH, ''];
  }

  function matchRegex(ec, exprs) {
    if (ec.host === '') return [NO_MATCH, ''];
    for (const e of exprs) {
      let re;
      try { re = new RegExp(e); } catch { continue; }
      if (re.test(ec.host)) return [MATCH, e];
    }
    return [NO_MATCH, ''];
  }

  function matchAddrs(ec) { return ec.destIsIP ? [ec.destAddr] : ec.addresses; }

  function matchIPCIDR(ec, cidrs, isSource) {
    if (isSource) return [UNKNOWN, '', 'client source address is unknown'];
    const addrs = matchAddrs(ec);
    if (addrs.length === 0) {
      if (ec.host !== '') return [UNKNOWN, '', 'requires the resolved IP (domain not resolved for this evaluation)'];
      return [NO_MATCH, '', ''];
    }
    for (const cidr of cidrs) {
      const p = IP.parsePrefix(cidr.trim());
      if (!p) continue;
      for (const a of addrs) if (IP.contains(p, a)) return [MATCH, cidr, ''];
    }
    return [NO_MATCH, '', ''];
  }

  function matchIPIsPrivate(ec, isSource) {
    if (isSource) return [UNKNOWN, 'client source address is unknown'];
    const addrs = matchAddrs(ec);
    if (addrs.length === 0) {
      if (ec.host !== '') return [UNKNOWN, 'requires the resolved IP'];
      return [NO_MATCH, ''];
    }
    for (const a of addrs) if (IP.isPrivateish(a)) return [MATCH, ''];
    return [NO_MATCH, ''];
  }

  function matchNetwork(ec, networks) {
    if (ec.network === '') return UNKNOWN;
    return networks.includes(ec.network) ? MATCH : NO_MATCH;
  }
  function matchPort(ec, ports) {
    for (const p of ports) if (p === ec.destPort) return [MATCH, String(p)];
    return [NO_MATCH, ''];
  }
  function matchPortRange(ec, ranges) {
    for (const r of ranges) {
      const i = r.indexOf(':');
      if (i < 0) continue;
      let start = 0, end = 0xFFFF;
      if (i > 0) { const v = parseInt(r.slice(0, i), 10); if (!Number.isInteger(v)) continue; start = v; }
      if (i !== r.length - 1) { const v = parseInt(r.slice(i + 1), 10); if (!Number.isInteger(v)) continue; end = v; }
      if (ec.destPort >= start && ec.destPort <= end) return [MATCH, r];
    }
    return [NO_MATCH, ''];
  }
  function matchProtocol(ec, protocols) {
    if (ec.protocol === '') return UNKNOWN;
    for (const p of protocols) if (p.toLowerCase() === ec.protocol.toLowerCase()) return MATCH;
    return NO_MATCH;
  }
  function matchQueryType(ec, types) {
    if (ec.queryType === 0) return [UNKNOWN, ''];
    for (const t of types) if (t === ec.queryType) return [MATCH, queryTypeName(ec.queryType)];
    return [NO_MATCH, ''];
  }

  // ---- evalFields: the AND-across-groups / OR-within-group matcher ----
  function evalFields(ec, mf) {
    const conds = [];
    const groupStatuses = [];

    // destination address group (OR)
    const da = [];
    if (mf.domain.length) { const [st, m] = matchDomainExact(ec, mf.domain); conds.push(condEval({ field: 'domain', value: joinVals(mf.domain), group: 'dest_addr', status: st, matched: m })); da.push(st); }
    if (mf.domainSuffix.length) { const [st, m] = matchDomainSuffix(ec, mf.domainSuffix); conds.push(condEval({ field: 'domain_suffix', value: joinVals(mf.domainSuffix), group: 'dest_addr', status: st, matched: m })); da.push(st); }
    if (mf.domainKeyword.length) { const [st, m] = matchKeyword(ec, mf.domainKeyword); conds.push(condEval({ field: 'domain_keyword', value: joinVals(mf.domainKeyword), group: 'dest_addr', status: st, matched: m })); da.push(st); }
    if (mf.domainRegex.length) { const [st, m] = matchRegex(ec, mf.domainRegex); conds.push(condEval({ field: 'domain_regex', value: joinVals(mf.domainRegex), group: 'dest_addr', status: st, matched: m })); da.push(st); }
    if (mf.ipCIDR.length) { const [st, m, note] = matchIPCIDR(ec, mf.ipCIDR, false); conds.push(condEval({ field: 'ip_cidr', value: joinVals(mf.ipCIDR), group: 'dest_addr', status: st, matched: m, note })); da.push(st); }
    if (mf.ipIsPrivate) { const [st, note] = matchIPIsPrivate(ec, false); conds.push(condEval({ field: 'ip_is_private', value: 'true', group: 'dest_addr', status: st, note })); da.push(st); }
    if (da.length) groupStatuses.push(orStatus(da));

    // source address group (OR) — unknown offline
    const sa = [];
    if (mf.srcIPCIDR.length) { conds.push(condEval({ field: 'source_ip_cidr', value: joinVals(mf.srcIPCIDR), group: 'src_addr', status: UNKNOWN, note: 'client source address is unknown' })); sa.push(UNKNOWN); }
    if (mf.srcIPIsPriv) { conds.push(condEval({ field: 'source_ip_is_private', value: 'true', group: 'src_addr', status: UNKNOWN, note: 'client source address is unknown' })); sa.push(UNKNOWN); }
    if (sa.length) groupStatuses.push(orStatus(sa));

    // destination port group (OR)
    const dp = [];
    if (mf.port.length) {
      if (ec.havePort) { const [st, m] = matchPort(ec, mf.port); conds.push(condEval({ field: 'port', value: joinU16(mf.port), group: 'dest_port', status: st, matched: m, note: `destination port ${ec.destPort} (from input)` })); dp.push(st); }
      else { conds.push(condEval({ field: 'port', value: joinU16(mf.port), group: 'dest_port', status: UNKNOWN, note: 'destination port is not part of the query (add :port to the input to check)' })); dp.push(UNKNOWN); }
    }
    if (mf.portRange.length) {
      if (ec.havePort) { const [st, m] = matchPortRange(ec, mf.portRange); conds.push(condEval({ field: 'port_range', value: joinVals(mf.portRange), group: 'dest_port', status: st, matched: m, note: `destination port ${ec.destPort} (from input)` })); dp.push(st); }
      else { conds.push(condEval({ field: 'port_range', value: joinVals(mf.portRange), group: 'dest_port', status: UNKNOWN, note: 'destination port is not part of the query (add :port to the input to check)' })); dp.push(UNKNOWN); }
    }
    if (dp.length) groupStatuses.push(orStatus(dp));

    // source port group (OR) — unknown
    const sp = [];
    if (mf.srcPort.length) { conds.push(condEval({ field: 'source_port', value: joinU16(mf.srcPort), group: 'src_port', status: UNKNOWN, note: 'client source port is unknown' })); sp.push(UNKNOWN); }
    if (mf.srcPortRange.length) { conds.push(condEval({ field: 'source_port_range', value: joinVals(mf.srcPortRange), group: 'src_port', status: UNKNOWN, note: 'client source port is unknown' })); sp.push(UNKNOWN); }
    if (sp.length) groupStatuses.push(orStatus(sp));

    // rule_set group (OR across tags)
    if (mf.ruleSet.length) {
      const rsStatuses = [];
      for (const tag of mf.ruleSet) {
        const rse = ec.rs.evaluate(tag, ec, mf.rsMatchSource);
        conds.push(condEval({ field: 'rule_set', value: tag, group: 'rule_set', status: rse.status, ruleSet: rse }));
        rsStatuses.push(rse.status);
      }
      groupStatuses.push(orStatus(rsStatuses));
    }

    // "other" fields (AND)
    if (mf.network.length) {
      const st = matchNetwork(ec, mf.network);
      const note = st === UNKNOWN ? 'connection network (tcp/udp) not specified' : '';
      conds.push(condEval({ field: 'network', value: joinVals(mf.network), group: 'other', status: st, note }));
      groupStatuses.push(st);
    }
    if (mf.protocol.length) {
      const st = matchProtocol(ec, mf.protocol);
      let note = '';
      if (st === UNKNOWN) note = 'sniffed connection protocol not specified (set an assumed protocol to check)';
      else note = `assumed protocol ${JSON.stringify(ec.protocol)}`;
      conds.push(condEval({ field: 'protocol', value: joinVals(mf.protocol), group: 'other', status: st, note }));
      groupStatuses.push(st);
    }
    if (mf.queryType.length) {
      const [st, m] = matchQueryType(ec, mf.queryType);
      conds.push(condEval({ field: 'query_type', value: queryTypeList(mf.queryType), group: 'other', status: st, matched: m, note: 'evaluated for the DNS query type shown' }));
      groupStatuses.push(st);
    }
    for (const kv of mf.dnsFilter) {
      conds.push(condEval({ field: kv.field, value: kv.value, group: 'other', status: UNKNOWN, note: 'matches the DNS response addresses, evaluated after resolution' }));
      groupStatuses.push(UNKNOWN);
    }
    for (const kv of mf.unknowns) {
      conds.push(condEval({ field: kv.field, value: kv.value, group: 'other', status: UNKNOWN, note: 'cannot be determined offline' }));
      groupStatuses.push(UNKNOWN);
    }

    let status = groupStatuses.length ? andStatus(groupStatuses) : MATCH;
    if (mf.invert) status = invertStatus(status);
    return { status, conds };
  }

  function summarize(conds, invert) {
    if (conds.length === 0) return '(match all)';
    const parts = conds.map((c) => {
      let v = c.value;
      if (v.length > 40) v = v.slice(0, 40) + '…';
      return c.field + '=' + v;
    });
    let s = parts.join(' ');
    if (invert) s = 'NOT(' + s + ')';
    return s;
  }

  // ---- rule-node evaluation ----
  function evalLogical(ec, node, evalChild) {
    const mode = node.mode || 'and';
    const subs = [], statuses = [];
    for (const sub of node.sub) { const se = evalChild(ec, sub); subs.push(se); statuses.push(se.status); }
    let status = mode === 'or' ? orStatus(statuses) : andStatus(statuses);
    if (node.invert) status = invertStatus(status);
    return ruleEval({ type: 'logical', mode, status, invert: node.invert, sub: subs, summary: 'logical ' + mode });
  }

  function evalRouteRuleNode(ec, node) {
    if (node.type === 'logical') return evalLogical(ec, node, evalRouteRuleNode);
    const { status, conds } = evalFields(ec, node.mf);
    return ruleEval({ type: 'default', status, invert: node.mf.invert, conditions: conds, summary: summarize(conds, node.mf.invert) });
  }
  function evalDNSRuleNode(ec, node) {
    if (node.type === 'logical') return evalLogical(ec, node, evalDNSRuleNode);
    const { status, conds } = evalFields(ec, node.mf);
    return ruleEval({ type: 'default', status, invert: node.mf.invert, conditions: conds, summary: summarize(conds, node.mf.invert) });
  }
  function evalHeadless(ec, node) {
    if (node.type === 'logical') return evalLogical(ec, node, evalHeadless);
    const { status, conds } = evalFields(ec, node.mf);
    return ruleEval({ type: 'default', status, invert: node.mf.invert, conditions: conds, summary: summarize(conds, node.mf.invert) });
  }

  // ---- rule-set resolver ----
  function newRuleSetResolver(cfg, deps, warnings) {
    const byTag = {};
    for (const rs of cfg.routeRuleSets) for (const tag of rs.tags) byTag[tag] = rs;
    const loaded = {};

    function ruleSetEval(o) {
      const e = { tag: o.tag, type: o.type || '', status: o.status, matchedIdx: o.matchedIdx };
      if (o.rules && o.rules.length) e.rules = o.rules;
      e.count = o.count || 0;
      if (o.error) e.error = o.error;
      return e;
    }

    function parseSource(l, text) {
      let compat;
      try { compat = JSON.parse(text); } catch (e) { l.err = 'parse source rule-set: ' + (e && e.message || e); return; }
      const version = compat && compat.version;
      if (version == null) { l.err = 'missing rule-set version'; return; }
      if (!(version >= 1 && version <= 5)) { l.err = 'unknown rule-set version: ' + version; return; }
      l.rules = (Array.isArray(compat.rules) ? compat.rules : []).map(P.buildHeadlessNode);
    }

    async function parseBinary(l, data) {
      if (!deps.decodeSRS) { l.err = 'binary rule-set decoding unavailable'; return; }
      let decoded;
      try { decoded = await deps.decodeSRS(data); } catch (e) { l.err = 'parse binary rule-set: ' + (e && e.message || e); return; }
      l.rules = (decoded && Array.isArray(decoded.rules) ? decoded.rules : []).map(P.buildHeadlessNode);
    }

    async function load(tag) {
      if (loaded[tag]) return loaded[tag];
      const l = { tag, typ: '', rules: [], err: '' };
      loaded[tag] = l;
      const rs = byTag[tag];
      if (!rs) { l.err = 'rule_set not defined in route.rule_set'; return l; }
      l.typ = rs.type;
      if (rs.type === 'inline') {
        l.rules = rs.rules;
      } else if (rs.type === 'local') {
        const files = deps.ruleSetFiles || {};
        let f = files[tag]; if (!f) f = files[rs.path];
        if (!f) { l.err = `local rule-set file not provided (upload the file for tag "${tag}" or path "${rs.path}")`; return l; }
        let format = f.format || rs.format;
        if (!format) format = (rs.path && rs.path.toLowerCase().endsWith('.srs')) ? 'binary' : 'source';
        if (format === 'binary') await parseBinary(l, f.data);
        else parseSource(l, f.data);
      } else if (rs.type === 'remote') {
        if (!rs.url) { l.err = 'remote rule-set has no url'; return l; }
        if (!deps.fetchRuleSet) { l.err = 'remote rule-set fetching unavailable'; return l; }
        let resp;
        try { resp = await deps.fetchRuleSet(rs.url); } catch (e) { l.err = 'fetch failed: ' + (e && e.message || e); return l; }
        if (!resp || !resp.ok) { l.err = 'fetch failed: HTTP ' + (resp ? resp.status : '?'); return l; }
        const format = rs.format || (rs.url.toLowerCase().endsWith('.srs') ? 'binary' : 'source');
        if (format === 'binary') await parseBinary(l, resp.bytes != null ? resp.bytes : resp.text);
        else parseSource(l, resp.text != null ? resp.text : '');
      } else {
        l.err = 'unsupported rule_set type: ' + rs.type;
      }
      return l;
    }

    function evaluate(tag, ec, matchSource) {
      const l = loaded[tag] || { tag, typ: '', rules: [], err: 'rule_set not loaded' };
      const out = { tag, type: l.typ, matchedIdx: -1, count: l.rules.length };
      if (l.err) { out.status = UNKNOWN; out.error = l.err; return ruleSetEval(out); }
      const statuses = [];
      let firstMatch = null, firstUnknown = null, firstMatchIdx = -1;
      for (let i = 0; i < l.rules.length; i++) {
        const re = evalHeadless(ec, l.rules[i]);
        re.index = i;
        statuses.push(re.status);
        if (re.status === MATCH && firstMatch === null) { firstMatch = re; firstMatchIdx = i; }
        if (re.status === UNKNOWN && firstUnknown === null) { firstUnknown = re; }
      }
      out.status = orStatus(statuses);
      if (out.status === MATCH) { out.matchedIdx = firstMatchIdx; if (firstMatch) out.rules = [firstMatch]; }
      else if (out.status === UNKNOWN) { if (firstUnknown) out.rules = [firstUnknown]; }
      return ruleSetEval(out);
    }

    // Preload every referenced rule set so evaluate() can stay synchronous.
    async function preload(tags) { for (const t of tags) await load(t); }

    return { evaluate, preload };
  }

  // ---- DNS server helpers ----
  function findDNSServer(cfg, tag) { return cfg.dnsServers.find((s) => s.tag === tag) || null; }
  function effectiveDNSFinal(cfg) { return cfg.dnsFinal || (cfg.dnsServers[0] ? cfg.dnsServers[0].tag : ''); }
  function serverInfoObj(si) {
    const o = { tag: si.tag };
    if (si.type) o.type = si.type;
    if (si.address) o.address = si.address;
    if (si.detour) o.detour = si.detour;
    return o;
  }
  function dnsDecision(cfg, a, fromFinal, assumed) {
    const d = { actionType: a.typ };
    if (a.server) d.server = a.server;
    if (a.detail) d.detail = a.detail;
    const si = a.server ? findDNSServer(cfg, a.server) : null;
    if (si) d.serverInfo = serverInfoObj(si);
    d.fromFinal = fromFinal;
    d.assumed = assumed;
    return d;
  }

  // ---- DNS matching ----
  function matchDNS(ec, cfg) {
    const prevQT = ec.queryType;
    ec.queryType = 1; // A
    try {
      const steps = [];
      let hadConditional = false;
      const finalTag = effectiveDNSFinal(cfg);
      for (let i = 0; i < cfg.dnsRules.length; i++) {
        const node = cfg.dnsRules[i];
        const re = evalDNSRuleNode(ec, node);
        re.index = i; re.reached = true;
        const a = node.action;
        re.actionType = a.typ; re.actionText = a.detail; re.terminal = a.terminal;
        if (re.status === MATCH) {
          if (!a.terminal) { re.effect = 'matched but non-terminal; continues scanning'; steps.push(re); continue; }
          steps.push(re);
          return dnsTrace(steps, i, finalTag, dnsDecision(cfg, a, false, hadConditional));
        } else if (re.status === UNKNOWN) {
          if (a.terminal) { re.effect = 'could match here if its undetermined conditions hold'; hadConditional = true; }
          steps.push(re);
        } else {
          steps.push(re);
        }
      }
      const finalAction = { typ: 'route', server: finalTag, terminal: true, detail: 'route → server ' + (finalTag || '(first server)') };
      const note = cfg.dnsRules.length === 0 ? 'no DNS rules; the final server is always used' : '';
      return dnsTrace(steps, -1, finalTag, dnsDecision(cfg, finalAction, true, hadConditional), note);
    } finally {
      ec.queryType = prevQT;
    }
  }
  function dnsTrace(steps, matchedIndex, finalTag, decision, note) {
    const tr = { queryType: 'A', steps: steps.length ? steps : null, matchedIndex, final: finalTag, decision };
    if (note) tr.note = note;
    return tr;
  }

  // ---- route matching ----
  function matchRoute(ec, cfg) {
    const steps = [];
    let hadConditional = false;
    for (let i = 0; i < cfg.routeRules.length; i++) {
      const node = cfg.routeRules[i];
      const re = evalRouteRuleNode(ec, node);
      re.index = i; re.reached = true;
      const a = node.action;
      re.actionType = a.typ; re.actionText = a.detail; re.terminal = a.terminal;
      if (re.status === MATCH) {
        if (a.isResolve) {
          const addrs = performResolve(ec, a.strategy);
          re.effect = addrs.length > 0
            ? 'resolved → ' + addrs.map(IP.toString).join(', ') + ' (IP rules below can now match)'
            : 'resolve produced no addresses';
          steps.push(re);
          continue;
        }
        if (!a.terminal) { re.effect = 'matched but non-terminal; continues scanning'; steps.push(re); continue; }
        steps.push(re);
        const dec = { actionType: a.typ };
        if (a.outbound) dec.outbound = a.outbound;
        if (a.detail) dec.detail = a.detail;
        dec.fromFinal = false; dec.assumed = hadConditional;
        return { steps, selectedIndex: i, final: cfg.routeFinal, decision: dec };
      } else if (re.status === UNKNOWN) {
        if (a.terminal) { re.effect = 'could match here if its undetermined conditions hold'; hadConditional = true; }
        steps.push(re);
      } else {
        steps.push(re);
      }
    }
    const finalOut = cfg.routeFinal;
    const dec = { actionType: 'route' };
    if (finalOut) dec.outbound = finalOut;
    dec.detail = 'route → ' + (finalOut || '(first outbound)');
    dec.fromFinal = true; dec.assumed = hadConditional;
    return { steps: steps.length ? steps : null, selectedIndex: -1, final: cfg.routeFinal, decision: dec };
  }

  function allAddrs(res, strategy) {
    const v4 = res.ipv4 || [], v6 = res.ipv6 || [];
    switch (strategy) {
      case 'ipv4_only': return v4.slice();
      case 'ipv6_only': return v6.slice();
      case 'prefer_ipv6': return v6.concat(v4);
      default: return v4.concat(v6);
    }
  }
  function parseAddrs(ss) { const out = []; for (const s of ss) { const a = IP.parseAddr(s); if (a) out.push(a); } return out; }

  function performResolve(ec, strategy) {
    if (ec.host === '' || !ec.resolvedRaw) return ec.addresses;
    const addrs = parseAddrs(allAddrs(ec.resolvedRaw, strategy));
    if (addrs.length > 0) { ec.addresses = addrs; ec.destResolved = true; }
    return addrs;
  }

  // ---- input normalization ----
  function isAllDigits(s) { return s.length > 0 && /^[0-9]+$/.test(s); }
  function parsePort(s) {
    if (!isAllDigits(s)) return null;
    const v = parseInt(s, 10);
    if (!(v > 0 && v <= 65535)) return null;
    return v;
  }
  function looksLikeDomain(s) {
    if (s === '' || s.length > 253) return false;
    return /^[a-zA-Z0-9._*-]+$/.test(s);
  }
  function normalizeInput(s) {
    s = s.trim();
    if (s === '') return { host: s, port: 0, hasPort: false, scheme: '' };
    let scheme = '';
    let i = s.indexOf('://');
    if (i >= 0) { scheme = s.slice(0, i).toLowerCase(); s = s.slice(i + 3); }
    i = s.indexOf('/'); if (i >= 0) s = s.slice(0, i);
    i = s.lastIndexOf('@'); if (i >= 0) s = s.slice(i + 1);
    s = s.trim();
    if (s.startsWith('[')) {
      const end = s.indexOf(']');
      if (end >= 0) {
        const hostPart = s.slice(1, end);
        const rest = s.slice(end + 1);
        if (rest.startsWith(':')) { const p = parsePort(rest.slice(1)); if (p != null) return { host: hostPart, port: p, hasPort: true, scheme }; }
        return { host: hostPart, port: 0, hasPort: false, scheme };
      }
    }
    if ((s.match(/:/g) || []).length === 1) {
      const idx = s.indexOf(':');
      const h = s.slice(0, idx), ps = s.slice(idx + 1);
      if (h !== '') { const p = parsePort(ps); if (p != null) return { host: h, port: p, hasPort: true, scheme }; }
    }
    s = s.replace(/^\[/, '').replace(/\]$/, '');
    return { host: s, port: 0, hasPort: false, scheme };
  }

  // ---- per-input driver ----
  async function analyzeInput(cfg, rs, req, deps, line) {
    const { host: rawHost, port, hasPort, scheme } = normalizeInput(line);
    const protocol = scheme !== '' ? scheme : (req.protocol || '');
    const ec = {
      network: req.network || '', protocol, rs, resolver: deps.resolver || null,
      destPort: port, havePort: hasPort, host: '', destIsIP: false, destAddr: null,
      addresses: [], destResolved: false, queryType: 0, resolvedRaw: null,
    };

    const ipAddr = IP.parseAddr(rawHost);
    if (ipAddr) {
      const it = { input: line, kind: 'ip' };
      ec.destIsIP = true; ec.destAddr = ipAddr;
      it.route = matchRoute(ec, cfg);
      return it;
    }
    if (!looksLikeDomain(rawHost)) {
      return { input: line, kind: 'invalid', error: 'not a valid domain or IP address' };
    }

    const it = { input: line, kind: 'domain' };
    ec.host = trimDot(rawHost).toLowerCase();

    if (deps.resolver) {
      let r = null;
      try { r = await deps.resolver.resolve(ec.host, ''); } catch { r = null; }
      if (r) {
        const resolved = { server: deps.resolver.server() };
        if (r.ipv4 && r.ipv4.length) resolved.ipv4 = r.ipv4;
        if (r.ipv6 && r.ipv6.length) resolved.ipv6 = r.ipv6;
        if (r.error) resolved.error = r.error;
        it.resolved = resolved;
        ec.resolvedRaw = r;
        if (req.assumeResolved) {
          const addrs = parseAddrs(allAddrs(r, ''));
          if (addrs.length > 0) { ec.addresses = addrs; ec.destResolved = true; }
        }
      } else {
        it.resolved = { server: deps.resolver.server(), error: 'resolution failed' };
      }
    }

    it.dns = matchDNS(ec, cfg);
    it.route = matchRoute(ec, cfg);
    return it;
  }

  // Collect rule-set tags referenced anywhere (route + dns, incl. logical subs).
  function collectTags(nodes, out) {
    for (const n of nodes) {
      if (n.type === 'logical') collectTags(n.sub, out);
      else for (const t of n.mf.ruleSet) out.add(t);
    }
  }

  // ---- top-level ----
  async function analyze(req, deps) {
    deps = deps || {};
    const cfg = P.parseConfig(req.config);
    const warnings = cfg.warnings.slice();
    const rs = newRuleSetResolver(cfg, deps, warnings);

    const tags = new Set();
    collectTags(cfg.routeRules, tags);
    collectTags(cfg.dnsRules, tags);
    await rs.preload(tags);

    const assumeResolved = req.assumeResolved !== false; // default true
    const reqN = { network: req.network || '', protocol: req.protocol || '', assumeResolved };

    const inputs = [];
    for (const raw of (req.inputs || [])) {
      const line = String(raw).trim();
      if (line === '' || line.startsWith('#')) continue;
      inputs.push(await analyzeInput(cfg, rs, reqN, deps, line));
    }

    const res = { dohServer: deps.resolver ? deps.resolver.server() : '' };
    if (warnings.length) res.warnings = warnings;
    res.inputs = inputs.length ? inputs : null;
    return res;
  }

  root.SingvisEngine = { analyze };
})(typeof globalThis !== 'undefined' ? globalThis : this);
