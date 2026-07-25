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

// ---- TUN capture ----
//
// Whether a destination is routed into a TUN at all is decided by the kernel
// before any rule runs, so these spell out the verdict rather than an outbound.
// The family split is the easy thing to get wrong: sing-box hands sing-tun
// separate v4/v6 route lists, so a route_address holding only IPv4 prefixes
// leaves IPv6 on the default route instead of excluding it.

const tun = (opts) => ({
  inbounds: [{ type: 'tun', tag: 'tun-in', address: ['172.19.0.1/30'], auto_route: true, ...opts }],
  route: { rules: [], final: 'proxy' },
});

async function assertCapture(name, c, want) {
  const r = await runCase(c);
  const got = {};
  for (const k of Object.keys(want)) {
    const cap = r.inputs[Number(k)].inbounds[0].capture;
    got[k] = cap ? cap.status : '(no capture)';
  }
  const d = diff(got, want);
  if (d) { fail++; console.log(`FAIL capture:${name}\n     ${d}`); } else { pass++; }
}

await assertCapture('route_exclude_address', {
  config: tun({ route_exclude_address: ['192.168.0.0/16'] }),
  inputs: ['192.168.1.10', '1.2.3.4'],
}, { 0: 'bypassed', 1: 'captured' });

await assertCapture('route_address is an allow-list', {
  config: tun({ route_address: ['1.2.3.0/24'] }),
  inputs: ['1.2.3.4', '8.8.8.8'],
}, { 0: 'captured', 1: 'bypassed' });

// v4-only route_address + a v6 TUN address: the v6 default route survives.
await assertCapture('route_address splits by family', {
  config: {
    inbounds: [{
      type: 'tun', tag: 'tun-in', address: ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
      auto_route: true, route_address: ['1.2.3.0/24'],
    }],
    route: { rules: [], final: 'proxy' },
  },
  inputs: ['8.8.8.8', '2001:db8::1'],
}, { 0: 'bypassed', 1: 'captured' });

// No v6 address on the TUN means sing-tun installs no v6 route at all.
await assertCapture('no IPv6 address means no IPv6 route', {
  config: tun({}), inputs: ['2001:db8::1', '1.2.3.4'],
}, { 0: 'bypassed', 1: 'captured' });

// route_exclude_address_set takes only the destination ip_cidr out of a set;
// the domain rule beside it contributes nothing, as in sing-box.
await assertCapture('route_exclude_address_set uses ip_cidr only', {
  config: {
    inbounds: [{ type: 'tun', tag: 'tun-in', address: ['172.19.0.1/30'], auto_route: true, route_exclude_address_set: ['cn-ip'] }],
    route: {
      rules: [],
      rule_set: [{ type: 'inline', tag: 'cn-ip', rules: [{ domain_suffix: ['cn'] }, { ip_cidr: ['223.5.5.0/24'] }] }],
      final: 'proxy',
    },
  },
  inputs: ['223.5.5.5', '1.2.3.4', 'a.cn'],
  dns: { 'a.cn': { ipv4: ['198.51.100.1'] } },
}, { 0: 'bypassed', 1: 'captured', 2: 'captured' });

// The 1.10 aliases feed the same lists as the fields that replaced them.
await assertCapture('deprecated inet4_route_exclude_address', {
  config: {
    inbounds: [{ type: 'tun', tag: 'tun-in', inet4_address: '172.19.0.1/30', auto_route: true, inet4_route_exclude_address: ['1.2.3.0/24'] }],
    route: { rules: [], final: 'proxy' },
  },
  inputs: ['1.2.3.4'],
}, { 0: 'bypassed' });

// Without auto_route sing-box installs nothing, so capture is the system's call.
await assertCapture('auto_route off is undetermined', {
  config: { inbounds: [{ type: 'tun', tag: 'tun-in', address: ['172.19.0.1/30'], route_exclude_address: ['1.2.3.0/24'] }], route: { rules: [], final: 'proxy' } },
  inputs: ['1.2.3.4'],
}, { 0: 'unknown' });

// A name resolving to both an excluded and a routed address can go either way.
await assertCapture('a split answer is partial', {
  config: tun({ route_exclude_address: ['203.0.113.0/24'] }),
  inputs: ['split.example.com'],
  dns: { 'split.example.com': { ipv4: ['203.0.113.9', '198.51.100.9'] } },
}, { 0: 'partial' });

// ---- inbound rules ----
//
// `inbound` is evaluated once per configured inbound, so the same input lands on
// different outbounds depending on which one accepted it — and stays UNKNOWN
// (never a silent no-match) in the inbound-agnostic trace.

async function assertPerInbound(name, c, want) {
  const r = await runCase(c);
  const got = {};
  for (const [k, tag] of Object.entries(want)) {
    const ib = r.inputs[0].inbounds.find((x) => x.tag === k);
    got[k] = ib ? ((ib.route || r.inputs[0].route).decision.outbound || '') : '(missing)';
  }
  const d = diff(got, want);
  if (d) { fail++; console.log(`FAIL inbound:${name}\n     ${d}`); } else { pass++; }
}

await assertPerInbound('inbound rule picks per inbound', {
  config: {
    inbounds: [
      { type: 'tun', tag: 'tun-in', address: ['172.19.0.1/30'], auto_route: true },
      { type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 2080 },
    ],
    route: { rules: [{ inbound: ['mixed-in'], outbound: 'from-proxy' }], final: 'direct' },
  },
  inputs: ['1.2.3.4'],
}, { 'tun-in': 'direct', 'mixed-in': 'from-proxy' });

// With no inbounds declared, one mixed inbound is assumed and flagged; it has no
// tag, so an `inbound` rule stays undetermined rather than reading as no-match.
{
  const r = await runCase({
    config: { route: { rules: [{ inbound: ['tun-in'], outbound: 'tunnelled' }], final: 'direct' } },
    inputs: ['1.2.3.4'],
  });
  const got = {
    count: r.inputs[0].inbounds.length,
    type: r.inputs[0].inbounds[0].type,
    assumed: r.inputs[0].inbounds[0].assumed,
    ruleStatus: r.inputs[0].route.steps[0].status,
    outbound: r.inputs[0].route.decision.outbound,
    assumedOutcome: r.inputs[0].route.decision.assumed,
  };
  const want = { count: 1, type: 'mixed', assumed: true, ruleStatus: 'unknown', outbound: 'direct', assumedOutcome: true };
  const d = diff(got, want);
  if (d) { fail++; console.log(`FAIL inbound:assumed mixed inbound\n     ${d}`); } else { pass++; }
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
