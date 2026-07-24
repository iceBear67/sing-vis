// Regenerates testdata/golden/*.json from the JS engine.
//
//   node test/gen.mjs           # rewrite the golden files
//   node test/gen.mjs -check    # fail if any golden is stale (used in CI)
//
// These goldens are a REGRESSION baseline, not a correctness oracle: they are
// produced by the same engine test/run.mjs checks them against, so they pin
// current behaviour and make any unintended change show up as a diff. They do
// not, on their own, prove the matcher agrees with sing-box. Behaviour that
// must be *correct* rather than merely *stable* belongs in an assertion in
// test/run.mjs, where the expected value is written out by hand.
//
// Regenerating is therefore a deliberate act: read the diff before committing
// it, and only accept hunks you can explain.

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { encodeGolden, goldenDir, loadFixtures, runCase } from './harness.mjs';

const check = process.argv.includes('-check') || process.argv.includes('--check');
const fixtures = loadFixtures();
if (!check) mkdirSync(goldenDir, { recursive: true });

let wrote = 0, stale = 0;
for (const c of fixtures) {
  const got = encodeGolden(await runCase(c));
  const out = join(goldenDir, c.name + '.json');
  if (check) {
    let want = null;
    try { want = readFileSync(out, 'utf8'); } catch { want = null; }
    if (want !== got) { console.error(`OUT OF DATE: ${c.name}`); stale++; }
    continue;
  }
  writeFileSync(out, got);
  wrote++;
}

if (check) {
  if (stale) {
    console.error(`\n${stale} golden file(s) out of date — run: node test/gen.mjs`);
    process.exit(1);
  }
  console.log(`${fixtures.length} golden files up to date`);
} else {
  console.log(`wrote ${wrote} golden files`);
}
