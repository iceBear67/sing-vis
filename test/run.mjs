// Regression test: runs the pure-JS engine over testdata/fixtures.json with the
// same canned DoH answers, and deep-compares each Result against
// testdata/golden/<name>.json (written by test/gen.mjs from this same engine).
//
// A golden diff means behaviour CHANGED, not necessarily that it broke — read
// the diff, and if the change is intended, re-run `node test/gen.mjs`. The
// hand-written assertions at the bottom are the part that pins behaviour we
// believe is *correct*, so they survive a careless regeneration.
//
//   node test/run.mjs            # run all fixtures
//   node test/run.mjs domain     # run fixtures whose name includes "domain"

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { diff, goldenDir, loadFixtures, runCase } from './harness.mjs';

const filter = process.argv[2] && !process.argv[2].startsWith('-') ? process.argv[2] : '';
const fixtures = loadFixtures();

let pass = 0, fail = 0;
for (const c of fixtures) {
  if (filter && !c.name.includes(filter)) continue;
  const got = await runCase(c);
  let want;
  try {
    want = JSON.parse(readFileSync(join(goldenDir, c.name + '.json'), 'utf8'));
  } catch {
    fail++;
    console.log(`FAIL ${c.name}\n     no golden file — run: node test/gen.mjs`);
    continue;
  }
  const d = diff(got, want);
  if (d) {
    fail++;
    console.log(`FAIL ${c.name}\n     ${d}`);
  } else {
    pass++;
  }
}

// ---- explicit assertions ----
//
// Goldens only pin behaviour against itself. These spell out the expected value
// by hand, so a wrong-but-stable result still fails.

const outboundOf = (r, i) => r.inputs[i].route.decision.outbound || r.inputs[i].route.decision.detail;

async function assertCase(name, c, want) {
  const r = await runCase(c);
  const got = {};
  for (const k of Object.keys(want)) got[k] = want[k] === undefined ? undefined : outboundOf(r, Number(k));
  const d = diff(got, want);
  if (d) { fail++; console.log(`FAIL assert:${name}\n     ${d}`); } else { pass++; }
}

// assumeHttps injects https/443 for bare domains, leaves an explicit scheme or
// :port alone, and never touches raw IPs.
const httpsCfg = {
  route: {
    rules: [
      { protocol: ['rdp'], outbound: 'p-rdp' },
      { port: [3389], outbound: 'p-3389' },
      { protocol: ['tls'], outbound: 'p-tls' },
      { protocol: ['https'], outbound: 'p-https' },
      { port: [443], outbound: 'p-443' },
    ],
    final: 'direct',
  },
  outbounds: ['direct', 'p-rdp', 'p-3389', 'p-tls', 'p-https', 'p-443'].map((tag) => ({ tag, type: 'direct' })),
};
const httpsInputs = ['example.com', 'example.com:8080', 'tls://example.com', 'rdp://host.local:3389', '1.1.1.1'];

await assertCase('assumeHttps on', { config: httpsCfg, inputs: httpsInputs, assumeHttps: true, assumeResolved: false }, {
  0: 'p-https', // bare domain -> assumed https:443
  1: 'p-https', // explicit :8080 wins over the default port, protocol still https
  2: 'p-tls',   // explicit scheme wins over the default protocol
  3: 'p-rdp',
  4: 'direct',  // raw IP: no assumption, every protocol/port rule stays UNKNOWN
});

await assertCase('assumeHttps off', { config: httpsCfg, inputs: httpsInputs, assumeHttps: false, assumeResolved: false }, {
  0: 'direct',
  1: 'direct',  // :8080 is known, but no protocol rule can match
  2: 'p-tls',
  3: 'p-rdp',
  4: 'direct',
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
