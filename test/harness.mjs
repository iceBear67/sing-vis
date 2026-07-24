// Shared plumbing for the fixture-driven engine tests.
//
// test/gen.mjs writes testdata/golden/*.json from these fixtures; test/run.mjs
// compares against them. Both go through runCase() here so a generated golden
// and a checked golden can never be produced by different request shapes.
//
// The engine files are plain classic scripts that attach to globalThis; we load
// them into this realm with node:vm so the exact same code runs here and in the
// browser worker.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';

const here = dirname(fileURLToPath(import.meta.url));
export const root = dirname(here);
export const goldenDir = join(root, 'testdata', 'golden');

export function loadEngine() {
  if (globalThis.SingvisEngine) return globalThis.SingvisEngine;
  for (const f of ['ip.js', 'parse.js', 'engine.js']) {
    const code = readFileSync(join(root, 'web', 'engine', f), 'utf8');
    vm.runInThisContext(code, { filename: f });
  }
  if (!globalThis.SingvisEngine) throw new Error('engine failed to load');
  return globalThis.SingvisEngine;
}

// A resolver seeded from a fixture's canned DNS answers.
export function cannedResolver(dns) {
  return {
    server: () => 'fake-doh',
    async resolve(name) {
      const a = (dns && dns[name]) || {};
      return { name, ipv4: a.ipv4 || [], ipv6: a.ipv6 || [], error: a.error || '' };
    },
  };
}

export function loadFixtures() {
  const ff = JSON.parse(readFileSync(join(root, 'testdata', 'fixtures.json'), 'utf8')).cases;
  const seen = new Set();
  for (const c of ff) {
    if (seen.has(c.name)) throw new Error(`duplicate fixture name ${JSON.stringify(c.name)}`);
    seen.add(c.name);
  }
  return ff;
}

// Run one fixture and return its Result.
//
// Note the two defaults deliberately disagree with the app's:
//   assumeResolved defaults to TRUE  (as it does in the app)
//   assumeHttps    defaults to FALSE (the app defaults it to true)
// assumeHttps is opt-in here so the older fixtures keep exercising the
// "port/protocol is unknown" branches that are the whole point of cases like
// protocol_hint_none and port_hint. Cases that want the https:443 injection
// set "assumeHttps": true explicitly.
export async function runCase(c) {
  const engine = loadEngine();
  const ruleSetFiles = {};
  for (const [k, v] of Object.entries(c.ruleSetFiles || {})) {
    ruleSetFiles[k] = { format: v.format, data: typeof v.data === 'string' ? v.data : JSON.stringify(v.data) };
  }
  try {
    return await engine.analyze(
      {
        config: JSON.stringify(c.config),
        inputs: c.inputs,
        network: c.network || '',
        protocol: c.protocol || '',
        assumeResolved: c.assumeResolved !== false,
        assumeHttps: c.assumeHttps === true,
      },
      { resolver: cannedResolver(c.dns), ruleSetFiles },
    );
  } catch (e) {
    return { error: e.message };
  }
}

// Golden files are 2-space JSON with a trailing newline.
export function encodeGolden(result) {
  return JSON.stringify(result, null, 2) + '\n';
}

// Deep-equal with a JSON path to the first difference.
export function diff(a, b, path = '') {
  if (a === b) return null;
  if (typeof a !== typeof b) return `${path}: type ${typeof a} != ${typeof b}`;
  if (a === null || b === null) return `${path}: ${JSON.stringify(a)} != ${JSON.stringify(b)}`;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b)) return `${path}: array vs non-array`;
    if (a.length !== b.length) return `${path}: length ${a.length} != ${b.length}`;
    for (let i = 0; i < a.length; i++) { const d = diff(a[i], b[i], `${path}[${i}]`); if (d) return d; }
    return null;
  }
  if (typeof a === 'object') {
    const ka = Object.keys(a).sort(), kb = Object.keys(b).sort();
    if (ka.join(',') !== kb.join(',')) return `${path}: keys {${ka}} != {${kb}}`;
    for (const k of ka) { const d = diff(a[k], b[k], `${path}.${k}`); if (d) return d; }
    return null;
  }
  return `${path}: ${JSON.stringify(a)} != ${JSON.stringify(b)}`;
}
