// End-to-end test for the binary (.srs) rule-set path: compile a source rule-set
// to .srs with the native srsdecode (-compile), feed the bytes to the JS engine
// as an uploaded binary local rule-set, and assert the resulting route decision.
// decodeSRS is injected here by spawning the same native srsdecode the browser
// runs as wasm, so this exercises the real recover→source→match pipeline.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import vm from 'node:vm';
import os from 'node:os';

const here = dirname(fileURLToPath(import.meta.url));
const root = dirname(here);

// Build the native decoder once.
const bin = join(os.tmpdir(), 'sing-vis-srsdecode');
execFileSync('go', ['build', '-o', bin, './cmd/srsdecode'], { cwd: root, stdio: 'inherit' });

const compileSRS = (sourceObj) =>
  execFileSync(bin, ['-compile'], { input: JSON.stringify(sourceObj) }).toString('utf8');
const decodeSRS = (base64) => JSON.parse(execFileSync(bin, [], { input: base64 }).toString('utf8'));

for (const f of ['ip.js', 'parse.js', 'engine.js']) {
  vm.runInThisContext(readFileSync(join(root, 'web', 'engine', f), 'utf8'), { filename: f });
}
const engine = globalThis.SingvisEngine;

const cannedResolver = (dns) => ({
  server: () => 'fake-doh',
  async resolve(name) { const a = (dns && dns[name]) || {}; return { name, ipv4: a.ipv4 || [], ipv6: a.ipv6 || [], error: '' }; },
});

// Each case compiles `source` to .srs, references it as a local binary rule-set,
// and asserts (input -> expected outbound, expected rule_set status).
const cases = [
  {
    name: 'binary_domain_suffix',
    source: { version: 2, rules: [{ domain_suffix: ['baidu.com', '.qq.com'], domain: ['exact.cn'] }] },
    config: { route: { rules: [{ rule_set: ['cn'], outbound: 'direct' }], rule_set: [{ type: 'local', tag: 'cn', format: 'binary', path: 'cn.srs' }], final: 'proxy' } },
    expect: [
      { input: 'www.baidu.com', outbound: 'direct', rs: 'match' },
      { input: 'exact.cn', outbound: 'direct', rs: 'match' },
      { input: 'sub.qq.com', outbound: 'direct', rs: 'match' },
      { input: 'qq.com', outbound: 'proxy', rs: 'no_match' },       // .qq.com requires a subdomain
      { input: 'www.google.com', outbound: 'proxy', rs: 'no_match' },
    ],
  },
  {
    name: 'binary_ip_cidr',
    source: { version: 2, rules: [{ ip_cidr: ['1.2.3.0/24', '2001:db8::/32'] }] },
    config: { route: { rules: [{ rule_set: ['ips'], outbound: 'hit' }], rule_set: [{ type: 'local', tag: 'ips', format: 'binary', path: 'ips.srs' }], final: 'miss' } },
    expect: [
      { input: '1.2.3.9', outbound: 'hit', rs: 'match' },
      { input: '2001:db8::1', outbound: 'hit', rs: 'match' },
      { input: '9.9.9.9', outbound: 'miss', rs: 'no_match' },
    ],
  },
  {
    name: 'binary_logical_or',
    source: { version: 2, rules: [{ type: 'logical', mode: 'or', rules: [{ domain_suffix: ['a.org'] }, { domain_keyword: ['cdn'] }] }] },
    config: { route: { rules: [{ rule_set: ['combo'], outbound: 'hit' }], rule_set: [{ type: 'local', tag: 'combo', format: 'binary', path: 'combo.srs' }], final: 'miss' } },
    expect: [
      { input: 'x.a.org', outbound: 'hit', rs: 'match' },
      { input: 'foo.cdn.net', outbound: 'hit', rs: 'match' },
      { input: 'other.net', outbound: 'miss', rs: 'no_match' },
    ],
  },
];

function ruleSetStatusOf(it) {
  for (const s of (it.route.steps || [])) {
    for (const c of (s.conditions || [])) {
      if (c.field === 'rule_set' && c.ruleSet) return c.ruleSet.status;
    }
  }
  return null;
}

let pass = 0, fail = 0;
for (const c of cases) {
  const b64 = compileSRS(c.source);
  const ruleSetFiles = {};
  const tag = c.config.route.rule_set[0].tag;
  ruleSetFiles[tag] = { format: 'binary', data: b64 };
  const dns = { 'www.baidu.com': { ipv4: ['110.242.68.3'] }, 'sub.qq.com': { ipv4: ['121.14.77.201'] } };
  const res = await engine.analyze(
    { config: JSON.stringify(c.config), inputs: c.expect.map((e) => e.input), assumeResolved: true },
    { resolver: cannedResolver(dns), ruleSetFiles, decodeSRS: (data) => decodeSRS(data) },
  );
  for (let i = 0; i < c.expect.length; i++) {
    const e = c.expect[i];
    const it = res.inputs[i];
    const got = it.route.decision.outbound || '(final)';
    const rs = ruleSetStatusOf(it);
    if (got !== e.outbound || (e.rs && rs !== e.rs)) {
      fail++;
      console.log(`FAIL ${c.name} / ${e.input}: outbound=${got} (want ${e.outbound}), rule_set=${rs} (want ${e.rs})`);
    } else {
      pass++;
    }
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
