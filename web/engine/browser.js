'use strict';

// Browser-side dependency implementations for the sing-vis JS engine: the DoH
// resolver (fetch), remote rule-set fetching (fetch) and the lazy .srs decoder
// (a tiny Go/wasm loaded only when a config actually uses a binary rule set).
// Loaded in the worker via importScripts; exposes globalThis.SingvisBrowser.

(function (root) {
  const DEFAULT_DOH = 'https://1.1.1.1/dns-query';
  const TYPE_A = 1, TYPE_AAAA = 28;

  // ---- DoH JSON resolver ----
  function makeResolver(server) {
    server = server || DEFAULT_DOH;
    const cache = new Map();

    async function query(name, qtype) {
      const u = new URL(server);
      u.searchParams.set('name', name);
      u.searchParams.set('type', String(qtype));
      u.searchParams.set('ct', 'application/dns-json');
      const resp = await fetch(u.toString(), { headers: { Accept: 'application/dns-json' } });
      if (!resp.ok) throw new Error('DoH status ' + resp.status);
      const parsed = await resp.json();
      const out = [];
      for (const a of (parsed.Answer || [])) if (a.type === qtype) out.push(a.data);
      return out;
    }

    return {
      server: () => server,
      async resolve(name, strategy) {
        name = String(name || '').toLowerCase().replace(/\.$/, '');
        if (cache.has(name)) return cache.get(name);
        const res = { name, ipv4: [], ipv6: [], error: '' };
        let firstErr = null;
        if (strategy !== 'ipv6_only') {
          try { res.ipv4 = await query(name, TYPE_A); } catch (e) { firstErr = e; }
        }
        if (strategy !== 'ipv4_only') {
          try { res.ipv6 = await query(name, TYPE_AAAA); } catch (e) { if (!firstErr) firstErr = e; }
        }
        if (res.ipv4.length === 0 && res.ipv6.length === 0 && firstErr) {
          res.error = firstErr.message || String(firstErr);
          return res; // not cached, matching the Go resolver
        }
        cache.set(name, res);
        return res;
      },
    };
  }

  // ---- remote rule-set fetch ----
  async function fetchRuleSet(url) {
    const resp = await fetch(url, { headers: { 'User-Agent': 'sing-box' } });
    if (!resp.ok) return { ok: false, status: resp.status };
    const buf = new Uint8Array(await resp.arrayBuffer());
    let text = '';
    try { text = new TextDecoder('utf-8').decode(buf); } catch { text = ''; }
    return { ok: true, status: resp.status, bytes: buf, text };
  }

  // ---- lazy .srs decoder (Go/wasm) ----
  let srsReady = null;
  function ensureSRS() {
    if (srsReady) return srsReady;
    srsReady = new Promise((resolve, reject) => {
      let signaled;
      const started = new Promise((r) => { signaled = r; });
      root.singvisSRSReady = () => signaled();
      try { importScripts('wasm_exec.js'); } catch (e) { reject(new Error('failed to load wasm_exec.js: ' + e.message)); return; }
      const go = new root.Go();
      const run = (instance) => { go.run(instance); return started; };
      WebAssembly.instantiateStreaming(fetch('srs.wasm'), go.importObject)
        .then((res) => run(res.instance))
        .then(resolve, async () => {
          // Fallback for static hosts that don't send application/wasm.
          try {
            const resp = await fetch('srs.wasm');
            if (!resp.ok) throw new Error('HTTP ' + resp.status);
            const bytes = await resp.arrayBuffer();
            const res = await WebAssembly.instantiate(bytes, go.importObject);
            await run(res.instance);
            resolve();
          } catch (e) { reject(new Error('failed to load srs.wasm: ' + (e.message || e))); }
        });
    });
    return srsReady;
  }

  function bytesToBase64(bytes) {
    let bin = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(bin);
  }

  async function decodeSRS(input) {
    await ensureSRS();
    const b64 = typeof input === 'string' ? input : bytesToBase64(input);
    const json = await root.singvisDecodeSRS(b64);
    return JSON.parse(json);
  }

  // makeDeps assembles the deps object the engine consumes from a request.
  function makeDeps(request) {
    return {
      resolver: makeResolver(request.dohServer),
      ruleSetFiles: request.ruleSetFiles || {},
      fetchRuleSet,
      decodeSRS,
    };
  }

  root.SingvisBrowser = { makeDeps, makeResolver, fetchRuleSet, decodeSRS };
})(typeof globalThis !== 'undefined' ? globalThis : this);
