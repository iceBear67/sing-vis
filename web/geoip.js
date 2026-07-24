'use strict';

// Client-side IP geolocation using the metowolf qqwry.ipdb database
// (https://github.com/metowolf/qqwry.ipdb) in IPIP.net's `ipdb` binary format.
// Everything runs in the browser: the ~37 MB database is fetched once (default
// from the jsdelivr CDN), cached in IndexedDB, and queried locally — no lookup
// leaves the machine. The standard qqwry.ipdb carries an ISO-3166 `country_code`
// field, so a flag emoji comes straight from the record.
//
// Exposed as window.singvisGeo:
//   configure({enabled, url})   set options (call before ensureLoaded)
//   ensureLoaded()  -> Promise  load + parse (cache-first); resolves, never rejects
//   lookup(ipStr)   -> record|null   (only meaningful once status is 'ready')
//   getStatus()     -> { status, progress, error }
//   onChange(cb)    subscribe to status changes (for progress UI / re-annotation)
//
// Format reference (validated against the live file): a 4-byte big-endian length
// prefixes a JSON metadata header; the remainder is an 8-byte-per-node binary
// trie followed by a data block. Lookup walks the IP bit-by-bit (MSB first),
// IPv4 starting at a precomputed 96-bit offset, until it lands past node_count in
// the data block, then reads a 2-byte-length record split on tabs into fields.

(function () {
  const DEFAULT_URL = 'https://cdn.jsdelivr.net/npm/qqwry.ipdb/qqwry.ipdb';

  let opts = { enabled: true, url: DEFAULT_URL };
  let db = null;            // parsed database (see parse())
  let status = 'idle';      // idle | loading | ready | error | disabled
  let loaded = 0;           // bytes downloaded (decompressed) so far
  let total = 0;            // reliable decompressed total, or 0 when unknown
  let error = '';
  let inflight = null;      // in-progress ensureLoaded() promise
  const listeners = new Set();

  function notify() { listeners.forEach((cb) => { try { cb(getStatus()); } catch {} }); }
  function setStatus(s) { status = s; notify(); }

  function getStatus() {
    return { status, loaded, total, progress: total > 0 ? loaded / total : NaN, error, build: db && db.meta.build };
  }
  function onChange(cb) { listeners.add(cb); return () => listeners.delete(cb); }

  function configure(next) {
    const prevUrl = opts.url;
    opts = Object.assign({}, opts, next || {});
    if (!opts.url) opts.url = DEFAULT_URL;
    if (!opts.enabled) {
      // Keep any parsed db in memory but report disabled so nothing annotates.
      setStatus('disabled');
    } else if (opts.url !== prevUrl) {
      // Switching source invalidates the loaded db; a fresh ensureLoaded reloads.
      db = null;
      inflight = null;
      status = 'idle';
    } else if (db) {
      setStatus('ready');
    } else {
      status = status === 'error' ? 'idle' : status;
    }
  }

  // ---- ipdb parsing ----
  function parse(bytes) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const metaLen = dv.getUint32(0, false);
    const meta = JSON.parse(new TextDecoder('utf-8').decode(bytes.subarray(4, 4 + metaLen)));
    const data = bytes.subarray(4 + metaLen);
    const dataDV = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const nodeCount = meta.node_count;
    const langOffset = (meta.languages && typeof meta.languages.CN === 'number') ? meta.languages.CN : 0;
    const readNode = (node, index) => dataDV.getUint32(node * 8 + index * 4, false);
    // Precompute the IPv4 start offset by walking the 96-bit v4-in-v6 prefix.
    let node = 0;
    for (let i = 0; i < 96 && node < nodeCount; i++) node = readNode(node, i >= 80 ? 1 : 0);
    return { data, dataDV, nodeCount, fields: meta.fields, langOffset, v4offset: node, readNode, meta };
  }

  // ---- IP → bytes ----
  function ipv4ToBytes(ip) {
    const p = ip.split('.');
    if (p.length !== 4) return null;
    const b = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
      if (!/^\d{1,3}$/.test(p[i])) return null;
      const n = Number(p[i]);
      if (n > 255) return null;
      b[i] = n;
    }
    return b;
  }

  function ipv6ToBytes(ip) {
    const pct = ip.indexOf('%');
    if (pct >= 0) ip = ip.slice(0, pct);
    const halves = ip.split('::');
    if (halves.length > 2) return null;
    const toGroups = (str, out) => {
      if (str === '') return true;
      for (const g of str.split(':')) {
        if (g.indexOf('.') >= 0) {           // embedded IPv4 tail
          const v4 = ipv4ToBytes(g);
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

  function ipToBytes(ip) {
    ip = String(ip || '').trim();
    if (!ip) return null;
    return ip.indexOf(':') === -1 ? ipv4ToBytes(ip) : ipv6ToBytes(ip);
  }

  function flagEmoji(cc) {
    if (!/^[A-Z]{2}$/.test(cc)) return '';
    return String.fromCodePoint(...[...cc].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
  }

  function buildResult(fields, vals) {
    const rec = {};
    fields.forEach((f, i) => { rec[f] = (vals[i] || '').trim(); });
    const cc = (rec.country_code || '').toUpperCase();
    const raw = [rec.country_name, rec.region_name, rec.city_name, rec.district_name].filter(Boolean);
    const loc = [];
    for (const p of raw) if (loc[loc.length - 1] !== p) loc.push(p); // drop consecutive dupes (北京 北京)
    return { countryCode: cc, flag: flagEmoji(cc), location: loc.join(' '), isp: rec.isp_domain || '', fields: rec };
  }

  function lookup(ipStr) {
    if (!db) return null;
    const bytes = ipToBytes(ipStr);
    if (!bytes) return null;
    const bitCount = bytes.length === 4 ? 32 : 128;
    let node = bitCount === 32 ? db.v4offset : 0;
    for (let i = 0; i < bitCount; i++) {
      if (node > db.nodeCount) break;
      node = db.readNode(node, (bytes[i >> 3] >> (7 - (i % 8))) & 1);
    }
    if (node <= db.nodeCount) return null;
    const resolved = node - db.nodeCount + db.nodeCount * 8;
    if (resolved + 2 > db.data.length) return null;
    const size = db.dataDV.getUint16(resolved, false);
    if (resolved + 2 + size > db.data.length) return null;
    const text = new TextDecoder('utf-8').decode(db.data.subarray(resolved + 2, resolved + 2 + size));
    const parts = text.split('\t');
    return buildResult(db.fields, parts.slice(db.langOffset, db.langOffset + db.fields.length));
  }

  // ---- loading (cache-first, streamed with progress) ----
  const cacheKey = () => 'geodb:' + opts.url;

  async function fetchWithProgress(url) {
    const res = await fetch(url);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    // content-length is the COMPRESSED size when the CDN sends the file with
    // content-encoding (jsdelivr uses brotli), while the stream yields the
    // decompressed bytes — so only trust it as a total when uncompressed. When
    // compressed we report bytes downloaded (MB) instead of a bogus percentage.
    const encoded = (res.headers.get('content-encoding') || '').trim();
    const clen = Number(res.headers.get('content-length')) || 0;
    total = (clen && !encoded) ? clen : 0;
    if (!res.body || !res.body.getReader) {
      const buf = new Uint8Array(await res.arrayBuffer());
      loaded = buf.length; notify();
      return buf;
    }
    const reader = res.body.getReader();
    const chunks = [];
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      loaded += value.length;
      notify();
    }
    const out = new Uint8Array(loaded);
    let at = 0;
    for (const c of chunks) { out.set(c, at); at += c.length; }
    return out;
  }

  async function load() {
    setStatus('loading');
    loaded = 0; total = 0; error = '';
    const store = window.singvisStorage;
    try {
      let bytes = null;
      if (store && store.getBlob) {
        try {
          const cached = await store.getBlob(cacheKey());
          if (cached) bytes = new Uint8Array(cached);
        } catch { /* ignore cache read errors */ }
      }
      if (!bytes) {
        bytes = await fetchWithProgress(opts.url);
        if (store && store.putBlob) {
          try { await store.putBlob(cacheKey(), bytes.buffer); } catch { /* cache best-effort */ }
        }
      }
      db = parse(bytes);
      if (!opts.enabled) { setStatus('disabled'); return; }
      setStatus('ready');
    } catch (e) {
      error = (e && e.message) || String(e);
      db = null;
      setStatus('error');
    }
  }

  function ensureLoaded() {
    if (!opts.enabled) { setStatus('disabled'); return Promise.resolve(getStatus()); }
    if (db) { if (status !== 'ready') setStatus('ready'); return Promise.resolve(getStatus()); }
    if (inflight) return inflight;
    inflight = load().then(() => { inflight = null; return getStatus(); });
    return inflight;
  }

  window.singvisGeo = { configure, ensureLoaded, lookup, getStatus, onChange, DEFAULT_URL };
})();
