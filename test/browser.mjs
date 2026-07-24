// Worker-stack integration test. Runs the REAL browser files (worker.js,
// engine/*.js, engine/browser.js) inside a mocked Web Worker global — with a
// mocked fetch for DoH + rule-set URLs, and the ACTUAL shipped web/srs.wasm run
// through web/wasm_exec.js. This verifies the entire browser path offline:
// message protocol, deps wiring, DoH resolver, remote rule-set fetch, and the
// lazy .srs wasm decode → source-rule match.
//
// Requires ./build.sh to have produced web/srs.wasm + web/wasm_exec.js.

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import vm from 'node:vm';
import os from 'node:os';
import { webcrypto } from 'node:crypto';

const here = dirname(fileURLToPath(import.meta.url));
const root = dirname(here);
const web = join(root, 'web');

if (!existsSync(join(web, 'srs.wasm')) || !existsSync(join(web, 'wasm_exec.js'))) {
  console.error('web/srs.wasm or web/wasm_exec.js missing — run ./build.sh first');
  process.exit(2);
}

// Compile a source rule-set to .srs bytes with the native decoder, served as a
// remote binary rule set below.
const bin = join(os.tmpdir(), 'sing-vis-srsdecode');
execFileSync('go', ['build', '-o', bin, './cmd/srsdecode'], { cwd: root, stdio: 'inherit' });
const srsBytes = execFileSync(bin, ['-compile'], {
  input: JSON.stringify({ version: 2, rules: [{ domain_suffix: ['baidu.com'] }] }),
}).toString('utf8'); // base64
const srsBuf = Buffer.from(srsBytes, 'base64');

// ---- mocked worker global ----
const messages = [];
const dnsAnswers = { 'www.baidu.com': { A: ['110.242.68.3'], AAAA: [] } };

async function mockFetch(url, opts) {
  const u = String(url);
  if (u.startsWith('https://doh.test/')) {
    const q = new URL(u);
    const name = q.searchParams.get('name');
    const type = Number(q.searchParams.get('type'));
    const ans = dnsAnswers[name] || { A: [], AAAA: [] };
    const list = type === 1 ? ans.A : type === 28 ? ans.AAAA : [];
    return { ok: true, status: 200, async json() { return { Status: 0, Answer: list.map((d) => ({ name, type, data: d })) }; } };
  }
  if (u === 'https://rules.test/cn.srs') {
    return { ok: true, status: 200, async arrayBuffer() { return srsBuf.buffer.slice(srsBuf.byteOffset, srsBuf.byteOffset + srsBuf.byteLength); } };
  }
  if (u.endsWith('srs.wasm')) {
    const b = readFileSync(join(web, 'srs.wasm'));
    return { ok: true, status: 200, async arrayBuffer() { return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength); } };
  }
  throw new Error('unexpected fetch: ' + u);
}

const sandbox = {
  console, URL, TextEncoder, TextDecoder, WebAssembly, Uint8Array, Array, Object, JSON, Math, Date,
  Promise, Error, Reflect, Proxy, Map, Set, Symbol, ArrayBuffer, DataView, Number, String, Boolean,
  crypto: webcrypto, performance, btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
  atob: (s) => Buffer.from(s, 'base64').toString('binary'),
  setTimeout, clearTimeout, setInterval, clearInterval, fetch: mockFetch,
};
sandbox.globalThis = sandbox;
sandbox.self = sandbox;
sandbox.postMessage = (m) => messages.push(m);
sandbox.importScripts = (...files) => {
  for (const f of files) vm.runInContext(readFileSync(join(web, f), 'utf8'), sandbox, { filename: f });
};
vm.createContext(sandbox);

// Load the worker exactly as the browser would.
vm.runInContext(readFileSync(join(web, 'worker.js'), 'utf8'), sandbox, { filename: 'worker.js' });

const ready = messages.find((m) => m.type === 'ready');
if (!ready) { console.error('worker did not signal ready:', messages); process.exit(1); }

// Drive an analyze that uses a REMOTE BINARY (.srs) rule set + a resolved domain.
const request = {
  config: JSON.stringify({
    route: {
      rules: [{ rule_set: ['cn'], outbound: 'direct' }],
      rule_set: [{ type: 'remote', tag: 'cn', format: 'binary', url: 'https://rules.test/cn.srs' }],
      final: 'proxy',
    },
  }),
  inputs: ['www.baidu.com', 'www.google.com'],
  dohServer: 'https://doh.test/dns-query',
  assumeResolved: true,
};

await sandbox.onmessage({ data: { id: 1, request } });

// Wait for the async analyze (and lazy wasm load) to post its reply.
const reply = await new Promise((resolve, reject) => {
  const t0 = Date.now();
  (function poll() {
    const m = messages.find((x) => x.id === 1);
    if (m) return resolve(m);
    if (Date.now() - t0 > 20000) return reject(new Error('timeout waiting for worker reply'));
    setTimeout(poll, 20);
  })();
});

if (reply.error) { console.error('worker error:', reply.error); process.exit(1); }
const r = reply.result;
const baidu = r.inputs[0].route.decision.outbound;
const google = r.inputs[1].route.decision.outbound;
const rsStatus = r.inputs[0].route.steps[0].conditions.find((c) => c.field === 'rule_set').ruleSet.status;

let ok = true;
function check(name, got, want) { if (got !== want) { ok = false; console.log(`FAIL ${name}: got ${got}, want ${want}`); } }
check('baidu outbound', baidu, 'direct');
check('google outbound', google, 'proxy');
check('rule_set status (via wasm decode)', rsStatus, 'match');
check('dohServer echoed', r.dohServer, 'https://doh.test/dns-query');

console.log(ok ? '\nbrowser-stack integration: PASS (real srs.wasm + mocked fetch)' : '\nFAILED');
process.exit(ok ? 0 : 1);
