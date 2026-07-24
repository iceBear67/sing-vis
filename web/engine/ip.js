'use strict';

// IP address / CIDR utilities for the sing-vis matching engine, faithful to Go's
// net/netip semantics used by the original engine (ParseAddr, Prefix.Contains,
// IsPrivate/IsLoopback/IsLinkLocalUnicast). Addresses are represented as
// { b: Uint8Array(4|16), is4: bool }; IPv4-in-IPv6 inputs are unmapped to v4 so
// they match v4 prefixes exactly as netip's addr.Unmap() does.
//
// Self-contained (no DOM/browser APIs) so it runs in the worker and in Node.

(function (root) {
  function parseIPv4(ip) {
    const p = ip.split('.');
    if (p.length !== 4) return null;
    const b = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
      const s = p[i];
      // netip rejects empty octets and leading zeros ("01", "00").
      if (!/^\d{1,3}$/.test(s)) return null;
      if (s.length > 1 && s[0] === '0') return null;
      const n = Number(s);
      if (n > 255) return null;
      b[i] = n;
    }
    return b;
  }

  function parseIPv6(ip) {
    const pct = ip.indexOf('%');
    if (pct >= 0) ip = ip.slice(0, pct); // strip zone
    const halves = ip.split('::');
    if (halves.length > 2) return null;
    const toGroups = (str, out) => {
      if (str === '') return true;
      for (const g of str.split(':')) {
        if (g.indexOf('.') >= 0) { // embedded IPv4 tail
          const v4 = parseIPv4(g);
          if (!v4) return false;
          out.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
        } else {
          if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return false;
          out.push(parseInt(g, 16));
        }
      }
      return true;
    };
    const head = [];
    if (!toGroups(halves[0], head)) return null;
    let groups;
    if (halves.length === 2) {
      const tail = [];
      if (!toGroups(halves[1], tail)) return null;
      const missing = 8 - (head.length + tail.length);
      if (missing < 0) return null;
      groups = head.concat(new Array(missing).fill(0), tail);
    } else {
      groups = head;
    }
    if (groups.length !== 8) return null;
    const out = new Uint8Array(16);
    for (let i = 0; i < 8; i++) { out[i * 2] = (groups[i] >> 8) & 0xff; out[i * 2 + 1] = groups[i] & 0xff; }
    return out;
  }

  // Detect and unmap an IPv4-mapped IPv6 (::ffff:a.b.c.d) to a v4 address.
  function unmap(addr) {
    if (!addr || addr.is4) return addr;
    const b = addr.b;
    for (let i = 0; i < 10; i++) if (b[i] !== 0) return addr;
    if (b[10] !== 0xff || b[11] !== 0xff) return addr;
    return { b: new Uint8Array([b[12], b[13], b[14], b[15]]), is4: true };
  }

  // parseAddr mirrors netip.ParseAddr: accepts a bare IPv4 or IPv6 literal.
  function parseAddr(s) {
    s = String(s == null ? '' : s).trim();
    if (!s) return null;
    let b, is4;
    if (s.indexOf(':') === -1) { b = parseIPv4(s); is4 = true; }
    else { b = parseIPv6(s); is4 = false; }
    if (!b) return null;
    return unmap({ b, is4 });
  }

  // parsePrefix mirrors netip.ParsePrefix: "addr/bits".
  function parsePrefix(s) {
    s = String(s == null ? '' : s).trim();
    const slash = s.lastIndexOf('/');
    if (slash < 0) return null;
    const addr = parseAddr(s.slice(0, slash));
    if (!addr) return null;
    const bitsStr = s.slice(slash + 1);
    if (!/^\d{1,3}$/.test(bitsStr)) return null;
    const bits = Number(bitsStr);
    const max = addr.is4 ? 32 : 128;
    if (bits > max) return null;
    return { b: addr.b, is4: addr.is4, bits };
  }

  // contains reports whether prefix includes addr, comparing the high `bits`
  // bits (family must match, as with netip). Callers pass addr already unmapped.
  function contains(prefix, addr) {
    if (!prefix || !addr) return false;
    if (prefix.is4 !== addr.is4) return false;
    let bits = prefix.bits;
    let i = 0;
    while (bits >= 8) {
      if (prefix.b[i] !== addr.b[i]) return false;
      bits -= 8; i++;
    }
    if (bits > 0) {
      const mask = 0xff << (8 - bits) & 0xff;
      if ((prefix.b[i] & mask) !== (addr.b[i] & mask)) return false;
    }
    return true;
  }

  const P = (s) => parsePrefix(s);
  const V4_PRIVATE = [P('10.0.0.0/8'), P('172.16.0.0/12'), P('192.168.0.0/16')];
  const V6_ULA = P('fc00::/7');
  const V4_LOOPBACK = P('127.0.0.0/8');
  const V6_LOOPBACK = P('::1/128');
  const V4_LINKLOCAL = P('169.254.0.0/16');
  const V6_LINKLOCAL = P('fe80::/10');

  function isPrivate(a) {
    if (a.is4) return V4_PRIVATE.some((p) => contains(p, a));
    return contains(V6_ULA, a);
  }
  function isLoopback(a) { return contains(a.is4 ? V4_LOOPBACK : V6_LOOPBACK, a); }
  function isLinkLocalUnicast(a) { return contains(a.is4 ? V4_LINKLOCAL : V6_LINKLOCAL, a); }

  // isPrivateish combines the three, matching engine.matchIPIsPrivate.
  function isPrivateish(a) { return isPrivate(a) || isLoopback(a) || isLinkLocalUnicast(a); }

  // toString renders an address back to canonical text (RFC 5952) for the
  // resolved-IP effect line, matching netip.Addr.String: lowercase hex, longest
  // zero-run compressed (leftmost on a tie), runs shorter than 2 not compressed.
  function toString(a) {
    if (a.is4) return `${a.b[0]}.${a.b[1]}.${a.b[2]}.${a.b[3]}`;
    const g = [];
    for (let i = 0; i < 8; i++) g.push((a.b[i * 2] << 8) | a.b[i * 2 + 1]);
    let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
    for (let i = 0; i < 8; i++) {
      if (g[i] === 0) { if (curStart < 0) { curStart = i; curLen = 1; } else curLen++; }
      else { if (curLen > bestLen) { bestStart = curStart; bestLen = curLen; } curStart = -1; curLen = 0; }
    }
    if (curLen > bestLen) { bestStart = curStart; bestLen = curLen; }
    if (bestLen < 2) return g.map((x) => x.toString(16)).join(':');
    const head = g.slice(0, bestStart).map((x) => x.toString(16)).join(':');
    const tail = g.slice(bestStart + bestLen).map((x) => x.toString(16)).join(':');
    return head + '::' + tail;
  }

  root.SingvisIP = { parseAddr, parsePrefix, contains, isPrivateish, toString };
})(typeof globalThis !== 'undefined' ? globalThis : this);
