// Cross-language parity test: runs the pure-JS engine over testdata/fixtures.json
// with the same canned DoH answers the Go goldgen used, and deep-compares each
// Result against testdata/golden/<name>.json.
//
//   node test/run.mjs            # run all fixtures
//   node test/run.mjs domain     # run fixtures whose name includes "domain"
//
// The engine files are plain classic scripts that attach to globalThis; we load
// them into this realm with node:vm so the exact same code runs here and in the
// browser worker.

import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';

const here = dirname(fileURLToPath(import.meta.url));
const root = dirname(here);

function loadEngine() {
  for (const f of ['ip.js', 'parse.js', 'engine.js']) {
    const code = readFileSync(join(root, 'web', 'engine', f), 'utf8');
    vm.runInThisContext(code, { filename: f });
  }
  if (!globalThis.SingvisEngine) throw new Error('engine failed to load');
  return globalThis.SingvisEngine;
}

// A resolver seeded from a fixture's canned DNS answers.
function cannedResolver(dns) {
  return {
    server: () => 'fake-doh',
    async resolve(name) {
      const a = (dns && dns[name]) || {};
      return { name, ipv4: a.ipv4 || [], ipv6: a.ipv6 || [], error: a.error || '' };
    },
  };
}

// Deep-equal with a JSON path to the first difference.
function diff(a, b, path = '') {
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

const engine = loadEngine();
const filter = process.argv[2] || '';
const fixtures = JSON.parse(readFileSync(join(root, 'testdata', 'fixtures.json'), 'utf8')).cases;
const goldenDir = join(root, 'testdata', 'golden');

let pass = 0, fail = 0;
for (const c of fixtures) {
  if (filter && !c.name.includes(filter)) continue;
  const ruleSetFiles = {};
  for (const [k, v] of Object.entries(c.ruleSetFiles || {})) {
    ruleSetFiles[k] = { format: v.format, data: typeof v.data === 'string' ? v.data : JSON.stringify(v.data) };
  }
  let got;
  try {
    got = await engine.analyze(
      {
        config: JSON.stringify(c.config),
        inputs: c.inputs,
        network: c.network || '',
        protocol: c.protocol || '',
        assumeResolved: c.assumeResolved !== false,
      },
      { resolver: cannedResolver(c.dns), ruleSetFiles },
    );
  } catch (e) {
    got = { error: e.message };
  }
  const want = JSON.parse(readFileSync(join(goldenDir, c.name + '.json'), 'utf8'));
  const d = diff(got, want);
  if (d) {
    fail++;
    console.log(`FAIL ${c.name}\n     ${d}`);
  } else {
    pass++;
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
