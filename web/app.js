'use strict';

/* ---------------- utilities ---------------- */
const $ = (sel, root = document) => root.querySelector(sel);
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
));

/* ---------------- engine worker ---------------- */
// The matching engine is pure JavaScript running inside a Web Worker (to keep
// DoH resolution and matching off the UI thread). It is ready immediately; a
// small .srs decoder wasm is loaded lazily by the worker only if a config uses a
// binary rule set. The worker is spun up on the first Analyze and reused.
const engineWorker = (() => {
  let worker = null;
  let readyPromise = null;
  let seq = 0;
  const pending = new Map();

  function ensure() {
    if (readyPromise) return readyPromise;
    worker = new Worker('worker.js');
    readyPromise = new Promise((resolve, reject) => {
      worker.onmessage = (e) => {
        const d = e.data || {};
        if (d.type === 'ready') { resolve(); return; }
        if (d.type === 'loaderror') { reject(new Error(d.error || 'failed to load engine')); return; }
        if (d.id != null && pending.has(d.id)) {
          const { resolve: res, reject: rej } = pending.get(d.id);
          pending.delete(d.id);
          if (d.error) rej(new Error(d.error)); else res(d.result);
        }
      };
      worker.onerror = (e) => reject(new Error(e.message || 'engine worker error'));
    });
    return readyPromise;
  }

  return {
    // Whether the engine is already initialized (used to tailor the spinner text).
    get ready() { return readyPromise !== null; },
    // Kick off loading without running an analysis.
    preload() { return ensure(); },
    async analyze(request) {
      await ensure();
      const id = ++seq;
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject });
        worker.postMessage({ id, request });
      });
    },
  };
})();

const storage = window.singvisStorage;

function toast(msg, kind = '') {
  const root = $('#toast-root');
  const t = document.createElement('div');
  t.className = 'toast ' + kind;
  t.textContent = msg;
  root.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity .3s'; setTimeout(() => t.remove(), 300); }, 3600);
}

const store = {
  get(k, def) { try { const v = localStorage.getItem('singvis.' + k); return v == null ? def : JSON.parse(v); } catch { return def; } },
  set(k, v) { try { localStorage.setItem('singvis.' + k, JSON.stringify(v)); } catch {} },
};

/* ---------------- app state ---------------- */
const state = {
  profiles: [],
  activeId: null,
  settings: { dohServer: 'https://1.1.1.1/dns-query' },
  draft: null,          // { id?, name, config, inputs, ruleSetFiles }
  lastResult: null,
  configIndex: null,    // the analyzed config, indexed for the excerpts in result cards
  analyzing: false,
};

const SAMPLE_CONFIG = `{
  "dns": {
    "servers": [
      { "tag": "proxy-dns", "type": "https", "server": "1.1.1.1", "detour": "proxy" },
      { "tag": "local-dns", "type": "udp", "server": "223.5.5.5", "detour": "direct" }
    ],
    "rules": [
      { "rule_set": ["geosite-cn"], "action": "route", "server": "local-dns" },
      { "domain_keyword": ["ads"], "action": "reject" }
    ],
    "final": "proxy-dns"
  },
  "route": {
    "rules": [
      { "domain_suffix": ["google.com", "openai.com"], "outbound": "proxy" },
      { "rule_set": ["geosite-cn"], "outbound": "direct" },
      { "rule_set": ["geoip-cn"], "outbound": "direct" }
    ],
    "rule_set": [
      { "type": "remote", "tag": "geosite-cn", "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs" },
      { "type": "remote", "tag": "geoip-cn", "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs" }
    ],
    "final": "proxy"
  }
}`;

/* ---------------- init ---------------- */
async function init() {
  $('#btn-settings').onclick = openSettings;
  $('#btn-new').onclick = () => newDraft();
  try {
    state.settings = await storage.getSettings();
  } catch (e) { /* keep defaults */ }
  initGeo();
  await loadProfiles();
  if (state.profiles.length) selectProfile(state.profiles[0].id);
  else newDraft();
}

async function loadProfiles() {
  try { state.profiles = (await storage.listProfiles()) || []; }
  catch (e) { state.profiles = []; }
  renderSidebar();
}

function renderSidebar() {
  const ul = $('#profile-list');
  if (!state.profiles.length) {
    ul.innerHTML = '<li class="empty-hint">No profiles yet. Create one to get started.</li>';
    return;
  }
  ul.innerHTML = state.profiles.map((p) => `
    <li class="profile-item ${p.id === state.activeId ? 'active' : ''}" data-id="${esc(p.id)}">
      <span class="name">${esc(p.name || 'Untitled')}</span>
      <span class="meta">updated ${new Date(p.updatedAt).toLocaleString()}</span>
    </li>`).join('');
  ul.querySelectorAll('.profile-item').forEach((li) => {
    li.onclick = () => selectProfile(li.dataset.id);
  });
}

async function selectProfile(id) {
  try {
    const p = await storage.getProfile(id);
    state.activeId = id;
    state.draft = { id: p.id, name: p.name || '', config: p.config || '', inputs: p.inputs || '', ruleSetFiles: p.ruleSetFiles || {} };
    state.lastResult = null;
    state.configIndex = null;
    renderSidebar();
    renderEditor();
  } catch (e) { toast('Failed to load profile: ' + e.message, 'err'); }
}

function newDraft() {
  state.activeId = null;
  state.draft = { name: '', config: SAMPLE_CONFIG, inputs: 'www.google.com\nbaidu.com\nopenai.com\n1.1.1.1', ruleSetFiles: {} };
  state.lastResult = null;
  state.configIndex = null;
  renderSidebar();
  renderEditor();
}

/* ---------------- editor ---------------- */
function renderEditor() {
  const d = state.draft;
  const network = store.get('network', '');
  const assume = store.get('assumeResolved', true);
  const files = Object.entries(d.ruleSetFiles || {});
  $('#content').innerHTML = `
    <div class="editor-pane">
    <div class="card">
      <div class="card-head">
        <h2>${state.activeId ? 'Edit profile' : 'New profile'}</h2>
        <div class="row" style="gap:8px">
          <button class="btn small" id="btn-save">💾 Save</button>
          ${state.activeId ? '<button class="btn small danger" id="btn-delete">Delete</button>' : ''}
        </div>
      </div>
      <div class="card-body">
        <div class="field">
          <label class="lbl">Profile name</label>
          <input type="text" id="f-name" placeholder="My profile" value="${esc(d.name)}" />
        </div>
        <div class="field">
          <label class="lbl">sing-box configuration <span class="hint">JSON (comments allowed)</span></label>
          <textarea id="f-config" class="code" spellcheck="false" placeholder="Paste your sing-box config…">${esc(d.config)}</textarea>
        </div>
        <div class="field">
          <label class="lbl">Local rule-set files <span class="hint">only needed for type:"local" rule sets — key by tag or path</span></label>
          <input type="file" id="f-files" multiple />
          <div class="file-list" id="file-list">
            ${files.map(([k, f]) => `
              <div class="file-row" data-key="${esc(k)}">
                <span class="fname">${esc(k)}</span>
                <span class="fmeta">${esc(f.format)} · ${f.data ? (f.format === 'binary' ? Math.round(f.data.length * 0.75) : f.data.length) : 0} bytes</span>
                <button class="btn small danger rm-file" data-key="${esc(k)}" style="margin-left:auto">remove</button>
              </div>`).join('')}
          </div>
        </div>
        <div class="field">
          <label class="lbl">Domains / IPs to check <span class="hint">one per line — domains or raw IPs; # comments ignored</span></label>
          <textarea id="f-inputs" class="inputs" spellcheck="false" placeholder="example.com&#10;1.1.1.1&#10;rdp://10.0.0.5:3389">${esc(d.inputs)}</textarea>
          <div class="hint input-help">
            Append <code>:port</code> to evaluate <code>port</code> / <code>port_range</code> rules.
            Prefix a line with a scheme — e.g. <code>rdp://10.0.0.5:3389</code>, <code>tls://example.com</code> —
            to set that line's assumed <b>protocol</b> (so <code>protocol</code> rules match instead of showing <code>UNKNOWN?</code>).
          </div>
        </div>
      </div>
    </div>

    <div class="toolbar">
      <button class="btn primary" id="btn-analyze">▶ Analyze</button>
      <label class="check" title="Pre-resolve domains via DoH so ip_cidr / IP rule-set rules can match the resolved address">
        <input type="checkbox" id="opt-assume" ${assume ? 'checked' : ''}/> Resolve IPs for IP rules
      </label>
      <div class="field" style="max-width:140px;margin:0">
        <select id="opt-network" title="Assumed connection network for rules that filter on tcp/udp">
          <option value="" ${network === '' ? 'selected' : ''}>network: any</option>
          <option value="tcp" ${network === 'tcp' ? 'selected' : ''}>network: tcp</option>
          <option value="udp" ${network === 'udp' ? 'selected' : ''}>network: udp</option>
        </select>
      </div>
      <span class="spacer"></span>
      <span class="muted mono" id="doh-indicator">DoH: ${esc(state.settings.dohServer || '—')}</span>
      <span class="muted mono geo-status" id="geo-indicator"></span>
    </div>
    </div>

    <div class="results-pane">
      <div id="results"></div>
    </div>
  `;

  $('#btn-save').onclick = saveProfile;
  const del = $('#btn-delete'); if (del) del.onclick = deleteProfile;
  $('#btn-analyze').onclick = analyze;
  $('#f-files').onchange = handleFiles;
  $('#opt-assume').onchange = (e) => store.set('assumeResolved', e.target.checked);
  $('#opt-network').onchange = (e) => store.set('network', e.target.value);
  $('#file-list').querySelectorAll('.rm-file').forEach((b) => {
    b.onclick = () => { delete state.draft.ruleSetFiles[b.dataset.key]; syncDraftFromForm(); renderEditor(); };
  });
  if (window.singvisEditor) {
    singvisEditor.attach($('#f-config'), 'json');
    singvisEditor.attach($('#f-inputs'), 'hosts');
  }
  updateGeoIndicator();
  if (state.lastResult) renderResults(state.lastResult);
}

function syncDraftFromForm() {
  const d = state.draft;
  const n = $('#f-name'); if (n) d.name = n.value;
  const c = $('#f-config'); if (c) d.config = c.value;
  const i = $('#f-inputs'); if (i) d.inputs = i.value;
}

function handleFiles(e) {
  const files = Array.from(e.target.files || []);
  syncDraftFromForm();
  let pending = files.length;
  if (!pending) return;
  files.forEach((file) => {
    const isBinary = /\.srs$/i.test(file.name);
    const reader = new FileReader();
    reader.onload = () => {
      let data, format;
      if (isBinary) {
        const bytes = new Uint8Array(reader.result);
        let bin = ''; for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        data = btoa(bin); format = 'binary';
      } else { data = reader.result; format = 'source'; }
      state.draft.ruleSetFiles[file.name] = { format, data };
      if (--pending === 0) renderEditor();
    };
    if (isBinary) reader.readAsArrayBuffer(file); else reader.readAsText(file);
  });
}

async function saveProfile() {
  syncDraftFromForm();
  const d = state.draft;
  if (!d.name.trim()) { toast('Please enter a profile name', 'err'); return; }
  const payload = { name: d.name.trim(), config: d.config, inputs: d.inputs, ruleSetFiles: d.ruleSetFiles };
  if (state.activeId) payload.id = state.activeId;
  try {
    const saved = await storage.saveProfile(payload);
    state.activeId = saved.id;
    await loadProfiles();
    await selectProfile(saved.id);
    toast('Profile saved', 'ok');
  } catch (e) { toast('Save failed: ' + e.message, 'err'); }
}

async function deleteProfile() {
  if (!state.activeId) return;
  if (!confirm('Delete this profile?')) return;
  try {
    await storage.deleteProfile(state.activeId);
    await loadProfiles();
    if (state.profiles.length) selectProfile(state.profiles[0].id); else newDraft();
    toast('Profile deleted', 'ok');
  } catch (e) { toast('Delete failed: ' + e.message, 'err'); }
}

/* ---------------- analyze ---------------- */
async function analyze() {
  syncDraftFromForm();
  const d = state.draft;
  const inputs = d.inputs.split('\n').map((s) => s.trim()).filter(Boolean);
  if (!inputs.length) { toast('Add at least one domain or IP', 'err'); return; }
  // Start (or reuse) the geo database load so results can be annotated; the
  // ~37 MB download happens at most once and is cached afterward.
  if (state.settings.geoEnabled && window.singvisGeo) { singvisGeo.ensureLoaded(); updateGeoIndicator(); }
  const btn = $('#btn-analyze');
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Analyzing…';
  $('#results').innerHTML = `<div class="placeholder"><span class="spinner"></span> Resolving &amp; matching…</div>`;
  try {
    const result = await engineWorker.analyze({
      config: d.config,
      inputs,
      ruleSetFiles: d.ruleSetFiles,
      dohServer: state.settings.dohServer,
      network: store.get('network', ''),
      assumeResolved: store.get('assumeResolved', true),
    });
    state.lastResult = result;
    // Snapshot the config that produced this result, so the excerpts shown in
    // the cards keep matching the results even if the textarea is edited after.
    state.configIndex = buildConfigIndex(d.config);
    renderResults(result);
  } catch (e) {
    $('#results').innerHTML = `<div class="card"><div class="card-body" style="color:var(--reject)">⚠ ${esc(e.message)}</div></div>`;
  } finally {
    btn.disabled = false; btn.innerHTML = '▶ Analyze';
  }
}

/* ---------------- IP geolocation (qqwry.ipdb) ---------------- */
function initGeo() {
  if (!window.singvisGeo) return;
  singvisGeo.configure({ enabled: !!state.settings.geoEnabled, url: state.settings.geoUrl || undefined });
  singvisGeo.onChange(() => {
    updateGeoIndicator();
    const r = document.getElementById('results');
    if (r) annotateGeo(r);
  });
}

// updateGeoIndicator reflects the geo database status in the toolbar.
function updateGeoIndicator() {
  const el = document.getElementById('geo-indicator');
  if (!el || !window.singvisGeo) return;
  const s = singvisGeo.getStatus();
  let txt = '', title = '';
  if (state.settings.geoEnabled) {
    if (s.status === 'loading') {
      let amt;
      if (s.total > 0) amt = ' ' + Math.min(100, Math.round((s.loaded / s.total) * 100)) + '%';
      else amt = ' ' + (s.loaded / 1048576).toFixed(1) + ' MB';
      txt = '· Geo: downloading' + amt + '…';
    } else if (s.status === 'ready') {
      txt = '· Geo: qqwry ✓';
      title = 'IP geolocation via qqwry.ipdb';
    } else if (s.status === 'error') {
      txt = '· Geo: unavailable';
      title = s.error ? ('geo database error: ' + s.error) : '';
    }
  }
  el.textContent = txt;
  el.title = title;
}

// annotateGeo fills every empty [data-geo-ip] slot under root with a flag +
// location, once the database is ready. Safe to call repeatedly.
function annotateGeo(root) {
  if (!root || !window.singvisGeo || singvisGeo.getStatus().status !== 'ready') return;
  root.querySelectorAll('[data-geo-ip]').forEach((el) => {
    if (el.dataset.geoDone) return;
    el.dataset.geoDone = '1';
    const g = singvisGeo.lookup(el.dataset.geoIp);
    if (!g) return;
    const text = g.location || g.countryCode;
    if (!g.flag && !text) return;
    el.title = [g.location, g.isp].filter(Boolean).join(' · ');
    el.innerHTML = `${g.flag ? `<span class="flag">${g.flag}</span>` : ''}${text ? `<span class="geo-loc">${esc(text)}</span>` : ''}`;
  });
}

// inputIP extracts the bare IP from an IP input line (stripping scheme, path,
// brackets and a trailing :port) so it can be geolocated.
function inputIP(it) {
  if (!it || it.kind !== 'ip') return '';
  let s = String(it.input || '').trim();
  const sc = s.indexOf('://'); if (sc >= 0) s = s.slice(sc + 3);
  const sl = s.indexOf('/'); if (sl >= 0) s = s.slice(0, sl);
  if (s[0] === '[') { const e = s.indexOf(']'); return e >= 0 ? s.slice(1, e) : s.slice(1); }
  if ((s.match(/:/g) || []).length === 1) s = s.split(':')[0];
  return s;
}

/* ---------------- config excerpts ---------------- */
// The result cards quote the rule they are explaining straight from the analyzed
// config. The rule lists are indexed by position, which is exactly what a trace
// step's `index` refers to, so no matching heuristics are needed. Parsed with the
// engine's own JSONC parser so what is quoted is what the engine read.
function buildConfigIndex(text) {
  let cfg;
  try { cfg = window.SingvisParse ? SingvisParse.parseJSONC(text) : JSON.parse(text); }
  catch { return null; }
  if (!cfg || typeof cfg !== 'object') return null;
  const arr = (v) => (Array.isArray(v) ? v : []);
  const route = cfg.route && typeof cfg.route === 'object' ? cfg.route : {};
  const dns = cfg.dns && typeof cfg.dns === 'object' ? cfg.dns : {};
  // Null-prototype: tags come from the config, and a set tagged "constructor"
  // must not resolve to something off Object.prototype.
  const idx = { route: arr(route.rules), dns: arr(dns.rules), ruleSets: Object.create(null) };
  for (const rs of arr(route.rule_set)) {
    if (!rs || typeof rs !== 'object') continue;
    for (const tag of (Array.isArray(rs.tag) ? rs.tag : [rs.tag])) {
      if (typeof tag === 'string' && tag) idx.ruleSets[tag] = rs;
    }
  }
  return idx;
}

// ruleConfig returns the config object behind a trace step: `dns.rules[i]` for a
// DNS trace, `route.rules[i]` for a route trace.
function ruleConfig(kind, index) {
  const idx = state.configIndex;
  if (!idx || !(index >= 0)) return undefined;
  return (kind === 'dns' ? idx.dns : idx.route)[index];
}

// Like JSON.stringify(v, null, 2), except a short array of primitives stays on
// one line — `"domain_suffix": ["google.com"]` rather than three lines. The
// excerpt is reference material, so it should stay compact enough not to outweigh
// the analysis above it.
function formatConfigJSON(v, depth = 0) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  const pad = '  '.repeat(depth), inner = '  '.repeat(depth + 1);
  if (Array.isArray(v)) {
    if (!v.length) return '[]';
    if (v.every((x) => x === null || typeof x !== 'object')) {
      const oneLine = '[' + v.map((x) => JSON.stringify(x)).join(', ') + ']';
      if (oneLine.length + pad.length <= 72) return oneLine;
    }
    return '[\n' + v.map((x) => inner + formatConfigJSON(x, depth + 1)).join(',\n') + '\n' + pad + ']';
  }
  const keys = Object.keys(v);
  if (!keys.length) return '{}';
  return '{\n' + keys.map((k) => inner + JSON.stringify(k) + ': ' + formatConfigJSON(v[k], depth + 1)).join(',\n') + '\n' + pad + '}';
}

function renderConfigExcerpt(label, obj) {
  if (obj === undefined || obj === null) return '';
  let json;
  try { json = formatConfigJSON(obj); } catch { return ''; }
  if (typeof json !== 'string') return '';
  const body = window.singvisEditor ? singvisEditor.highlightJSON(json) : esc(json);
  return `<div class="cfg-excerpt">
      <div class="cfg-label">${esc(label)}</div>
      <pre class="cfg-json"><code>${body}</code></pre>
    </div>`;
}

/* ---------------- condition reference ---------------- */
// What each condition actually tests, in one line — so an expanded rule explains
// *why* it landed where it did, not just that it did. The wording tracks the
// matchers in engine/engine.js, which mirror sing-box's own semantics.
const FIELD_DOC = {
  domain: 'the whole domain equals one of these values (case-insensitive; a trailing dot is ignored)',
  domain_suffix: 'the domain equals a value or ends with "." + value — "example.com" also covers "a.example.com", while a value written with a leading dot matches subdomains only',
  domain_keyword: 'the value appears anywhere inside the domain, as a plain substring',
  domain_regex: 'the regular expression matches anywhere in the domain — anchor it with ^ / $ to pin it down',
  ip_cidr: 'the destination address falls inside one of these prefixes; for a domain that is its resolved address',
  ip_is_private: 'the destination address is loopback, link-local, or private space (RFC 1918 / unique-local)',
  source_ip_cidr: 'the client\'s own address — a property of the live connection, so it cannot be known from a domain alone',
  source_ip_is_private: 'the client\'s own address — a property of the live connection, so it cannot be known from a domain alone',
  port: 'the destination port equals one of these values',
  port_range: 'the destination port falls inside an inclusive start:end range; either side may be left open',
  source_port: 'the client\'s source port — picked per connection, so it cannot be known here',
  source_port_range: 'the client\'s source port — picked per connection, so it cannot be known here',
  network: 'the transport the connection uses, tcp or udp',
  protocol: 'the application protocol sing-box sniffs from the first bytes of the connection (tls, http, quic, …)',
  query_type: 'the DNS record type being asked for — clients typically ask A and AAAA in parallel',
  rule_set: 'the set matches when ANY headless rule inside it matches; the rules within a set are OR-ed',
  inbound: 'which configured inbound accepted the connection',
  client: 'the client software sing-box identified',
  auth_user: 'the inbound user that authenticated',
  user: 'the inbound user that authenticated',
  process_name: 'the local program that opened the connection — only visible to sing-box at runtime',
  process_path: 'the local program that opened the connection — only visible to sing-box at runtime',
  process_path_regex: 'the local program that opened the connection — only visible to sing-box at runtime',
  package_name: 'the Android app that opened the connection',
  package_name_regex: 'the Android app that opened the connection',
  wifi_ssid: 'the Wi-Fi network the device is currently on',
  wifi_bssid: 'the Wi-Fi access point the device is currently on',
  source_mac_address: 'the client\'s hardware address, seen only on the live connection',
  source_hostname: 'the client\'s hostname, seen only on the live connection',
  preferred_by: 'which client requested this route',
  clash_mode: 'the Clash mode selected right now (global / rule / direct) — live runtime state',
  ip_version: 'whether the connection ends up on IPv4 or IPv6, decided when it is actually made',
  network_type: 'the kind of network interface in use (wifi / cellular / …)',
  network_is_expensive: 'whether the device is on a metered network',
  network_is_constrained: 'whether the device is in low-data mode',
  geosite: 'removed in sing-box 1.8 — migrate it to a rule_set',
  geoip: 'removed in sing-box 1.8 — migrate it to a rule_set',
  source_geoip: 'removed in sing-box 1.8 — migrate it to a rule_set',
};

// In a DNS rule these same field names mean something different: they filter the
// *answer* after it comes back, so they never influence which server is queried.
const DNS_RESPONSE_DOC = {
  ip_cidr: 'inside a DNS rule this filters the addresses in the answer, after resolution — it does not decide which server is asked',
  ip_is_private: 'inside a DNS rule this filters the addresses in the answer, after resolution — it does not decide which server is asked',
  ip_accept_any: 'accepts an answer holding any address at all; applies to the response, not to the query',
  response_rcode: 'matches the response code of the answer, so it applies only once the query has been answered',
  match_response: 'matches against the answer itself, so it applies only once the query has been answered',
};

// criterionOf picks the reference line for one condition. Group tells the two
// meanings of ip_cidr apart: "dest_addr" is the connection's destination, while
// "other" is where the DNS response filters land.
function criterionOf(c) {
  const field = String(c.field || '').replace(/ \(deprecated\/removed\)$/, '');
  const doc = (c.group === 'other' ? DNS_RESPONSE_DOC[field] : '') || FIELD_DOC[field];
  return typeof doc === 'string' ? doc : '';
}

/* ---------------- results rendering ---------------- */
function statusBadge(status) {
  const label = { match: 'MATCH', no_match: 'no match', unknown: 'UNKNOWN?' }[status] || status;
  return `<span class="badge ${status}">${label}</span>`;
}

function renderResults(result) {
  const root = $('#results');
  if (!result.inputs || !result.inputs.length) { root.innerHTML = '<div class="placeholder">No inputs.</div>'; return; }
  const warn = (result.warnings && result.warnings.length)
    ? `<div class="assume-warn">⚠ ${result.warnings.map(esc).join('<br>')}</div>` : '';
  root.innerHTML = warn + result.inputs.map((it, i) => renderInputCard(it, i)).join('');
  root.querySelectorAll('.result-head').forEach((h) => {
    h.onclick = () => h.closest('.result-card').classList.toggle('open');
  });
  root.querySelectorAll('.step-head').forEach((h) => {
    h.onclick = (e) => { e.stopPropagation(); h.closest('.step').classList.toggle('expanded'); };
  });
  annotateGeo(root);
}

function renderInputCard(it, idx) {
  const chips = [];
  if (it.kind === 'invalid') {
    chips.push(`<span class="chip reject"><span class="k">error</span><span class="v">${esc(it.error || 'invalid')}</span></span>`);
  } else {
    if (it.dns && it.dns.decision) chips.push(dnsChip(it.dns.decision));
    if (it.dnsAAAA && it.dnsAAAA.decision && !sameDNSOutcome(it.dns, it.dnsAAAA)) chips.push(dnsChip(it.dnsAAAA.decision, 'DNS AAAA'));
    if (it.route && it.route.decision) chips.push(routeChip(it.route.decision));
    const ip = inputIP(it);
    if (ip) chips.push(`<span class="chip geo-chip" data-geo-ip="${esc(ip)}"></span>`);
  }
  const open = idx === 0 ? 'open' : '';
  return `
    <div class="card result-card ${open}">
      <div class="result-head">
        <span class="input-name" title="${esc(it.input)}">${esc(it.input)}</span>
        <span class="badge kind-${esc(it.kind)}">${esc(it.kind)}</span>
        <div class="outcome-chips">${chips.join('')}</div>
        <span class="caret">▶</span>
      </div>
      <div class="result-body">
        ${it.kind === 'invalid' ? `<p class="muted">${esc(it.error || 'Could not parse this input.')}</p>` : ''}
        ${renderResolved(it.resolved)}
        ${it.dns ? `<div class="section-title">DNS routing <span class="st-hint">which server / DNS action</span></div>${renderTrace(it.dns, 'dns')}` : ''}
        ${renderDNSAAAA(it)}
        ${it.route ? `<div class="section-title">Route matching <span class="st-hint">which rule / outbound</span></div>${renderTrace(it.route, 'route')}` : ''}
      </div>
    </div>`;
}

function dnsChip(dec, label) {
  const k = esc(label || 'DNS');
  if (dec.actionType === 'reject') return `<span class="chip reject"><span class="k">${k}</span><span class="v">reject</span></span>`;
  const server = dec.server || (dec.actionType);
  const detour = dec.serverInfo && dec.serverInfo.detour ? ` <span class="k">via</span> ${esc(dec.serverInfo.detour)}` : '';
  return `<span class="chip dns"><span class="k">${k}</span><span class="v">${esc(server)}</span>${detour}</span>`;
}

// Two DNS traces land on the same outcome when they pick the same rule and the
// same action/server — i.e. the query type made no difference.
function sameDNSOutcome(a, b) {
  if (!a || !b) return false;
  const x = a.decision || {}, y = b.decision || {};
  return a.matchedIndex === b.matchedIndex && x.actionType === y.actionType &&
    (x.server || '') === (y.server || '') && !!x.fromFinal === !!y.fromFinal && !!x.assumed === !!y.assumed;
}

// Happy eyeballs: a client queries A and AAAA in parallel and will use whichever
// answers first, so the AAAA query's DNS path matters too — a `query_type: AAAA`
// reject rule is the common way it diverges. The engine only emits this trace
// for names that actually have AAAA records; it's rendered in full only when the
// path really differs, so the usual case doesn't duplicate the whole trace.
function renderDNSAAAA(it) {
  if (!it.dnsAAAA) return '';
  if (sameDNSOutcome(it.dns, it.dnsAAAA)) {
    return `<p class="muted" style="margin-top:6px">The AAAA query (happy eyeballs) takes the same DNS path.</p>`;
  }
  return `<div class="section-title">DNS routing · AAAA <span class="st-hint">the query happy eyeballs sends alongside</span></div>${renderTrace(it.dnsAAAA, 'dns')}`;
}

function routeChip(dec) {
  if (dec.actionType === 'reject') return `<span class="chip reject"><span class="k">route</span><span class="v">reject</span></span>`;
  if (dec.actionType === 'hijack-dns') return `<span class="chip route"><span class="k">route</span><span class="v">hijack-dns</span></span>`;
  return `<span class="chip route"><span class="k">route</span><span class="v">${esc(dec.outbound || '(default)')}</span></span>`;
}

function renderResolved(r) {
  if (!r) return '';
  if (r.error && !(r.ipv4 && r.ipv4.length) && !(r.ipv6 && r.ipv6.length)) {
    return `<div class="section-title">Resolved <span class="st-hint">via DoH</span></div><p class="muted">resolution failed: ${esc(r.error)}</p>`;
  }
  const ipChip = (ip) => `<span class="ip-chip">${esc(ip)}<span class="geo-slot" data-geo-ip="${esc(ip)}"></span></span>`;
  const v4 = (r.ipv4 || []).map(ipChip).join('');
  const v6 = (r.ipv6 || []).map(ipChip).join('');
  if (!v4 && !v6) return `<div class="section-title">Resolved <span class="st-hint">via DoH</span></div><p class="muted">no A/AAAA records</p>`;
  return `<div class="section-title">Resolved <span class="st-hint">via ${esc(r.server)}</span></div><div class="ip-chips">${v4}${v6}</div>`;
}

function renderTrace(trace, kind) {
  const steps = (trace.steps || []).map((s) => renderStep(s, kind, trace)).join('');
  const stepsHtml = steps ? `<div class="steps">${steps}</div>` : `<p class="muted">No ${kind === 'dns' ? 'DNS' : 'route'} rules — the final is used directly.</p>`;
  const note = trace.note ? `<p class="muted" style="margin-top:6px">${esc(trace.note)}</p>` : '';
  return stepsHtml + note + renderDecision(trace.decision, kind);
}

function renderStep(s, kind, trace) {
  const selected = (kind === 'route' && trace.selectedIndex === s.index) || (kind === 'dns' && trace.matchedIndex === s.index);
  const cls = ['step', 's-' + s.status];
  if (selected) cls.push('s-selected');
  if (s.status === 'no_match') cls.push('dimmed');
  const conds = s.type === 'logical' ? renderLogical(s) : (s.conditions || []).map(renderCond).join('');
  const effect = s.effect ? `<div class="effect">↳ ${esc(s.effect)}</div>` : '';
  const detailInner = (conds || '<span class="muted">no conditions (matches all)</span>') +
    renderRuleLogic(s) +
    renderConfigExcerpt(`${kind === 'dns' ? 'dns' : 'route'}.rules[${s.index}]`, ruleConfig(kind, s.index));
  return `
    <div class="step ${cls.join(' ')}">
      <div class="step-head">
        <span class="idx">${s.index}</span>
        ${statusBadge(s.status)}
        <span class="summary" title="${esc(s.summary)}">${esc(s.summary)}</span>
        <span class="action-text">${esc(s.actionText || '')}</span>
      </div>
      ${effect}
      <div class="step-detail">${detailInner}</div>
    </div>`;
}

function renderLogical(s) {
  const subs = (s.sub || []).map((sub) => {
    const inner = sub.type === 'logical' ? renderLogical(sub) : (sub.conditions || []).map(renderCond).join('');
    return `<div class="ruleset-box"><div class="rs-head">${statusBadge(sub.status)} <span class="mono">${esc(sub.summary)}</span></div>${inner}</div>`;
  }).join('');
  return `<div class="muted" style="margin-bottom:6px">logical <b>${esc(s.mode || 'and')}</b>${s.invert ? ' (inverted)' : ''}:</div>${subs}`;
}

function renderCond(c) {
  const matched = c.matched ? `<span class="matched-val">✓ ${esc(c.matched)}</span>` : '';
  const note = c.note ? `<div class="cnote">${esc(c.note)}</div>` : '';
  const crit = criterionOf(c);
  const criterion = crit ? `<div class="criterion">tests: ${esc(crit)}</div>` : '';
  const rs = c.ruleSet ? renderRuleSet(c.ruleSet) : '';
  // Key column (what was tested + verdict) beside a value column that reads top
  // down in decreasing importance: the values, then the engine's note, then the
  // reference line.
  return `
    <div class="cond">
      <div class="ck">
        <span class="cf">${esc(c.field)}</span>
        ${statusBadge(c.status)}
      </div>
      <div class="cvals">
        <div class="cv-line"><span class="group-tag">${esc(c.group)}</span> <span class="cv">${esc(c.value)}</span> ${matched}</div>
        ${note}
        ${criterion}
      </div>
    </div>${rs}`;
}

// Spell out how the individual condition results became the rule's verdict:
// sing-box ORs the conditions inside one group (any destination address, any
// port…) and ANDs the groups together. UNKNOWN survives an AND, so a condition
// that can't be determined offline never silently turns into a "no match".
function orOf(statuses) {
  if (statuses.includes('match')) return 'match';
  return statuses.includes('unknown') ? 'unknown' : 'no_match';
}
function renderRuleLogic(s) {
  const conds = s.conditions || [];
  if (conds.length < 2 && !s.invert) return ''; // a single condition IS the verdict
  const order = [], byGroup = new Map();
  for (const c of conds) {
    if (!byGroup.has(c.group)) { byGroup.set(c.group, []); order.push(c.group); }
    byGroup.get(c.group).push(c.status);
  }
  const parts = order.map((g) => {
    const sts = byGroup.get(g);
    const any = sts.length > 1 ? ' <span class="op">any of</span>' : '';
    return `<span class="lg-group">${esc(g)}</span>${any} ${statusBadge(orOf(sts))}`;
  });
  const invert = s.invert ? ' <span class="op">then inverted</span>' : '';
  return `<div class="rule-logic" title="Conditions in the same group are OR-ed, the groups are AND-ed; an UNKNOWN survives the AND so it can never pass silently as a no-match.">
      ${parts.join('<span class="op">and</span>')}${invert}
      <span class="arrow">→</span> <span class="op">rule</span> ${statusBadge(s.status)}
    </div>`;
}

function renderRuleSet(rs) {
  const inner = (rs.rules || []).map((r) => {
    const cs = r.type === 'logical' ? renderLogical(r) : (r.conditions || []).map(renderCond).join('');
    return `<div style="margin-top:6px">${statusBadge(r.status)} <span class="mono">${esc(r.summary)}</span>${cs}</div>`;
  }).join('');
  const err = rs.error ? `<div class="rs-err">⚠ ${esc(rs.error)}</div>` : '';
  const matched = rs.matchedIdx >= 0 ? ` · matched rule #${rs.matchedIdx}` : '';
  // Where the set came from (url / path / inline) is the piece of context the
  // decoded rules alone don't give you.
  const def = state.configIndex ? state.configIndex.ruleSets[rs.tag] : undefined;
  return `
    <div class="ruleset-box">
      <div class="rs-head">${statusBadge(rs.status)} <b>rule_set</b> <span class="mono">${esc(rs.tag)}</span>
        <span class="rs-meta">(${esc(rs.type || '?')} · ${rs.count || 0} rule${rs.count === 1 ? '' : 's'}${matched})</span>
      </div>
      ${err}${inner}
      ${renderConfigExcerpt(`route.rule_set · ${rs.tag}`, def)}
    </div>`;
}

function renderDecision(dec, kind) {
  if (!dec) return '';
  const assumed = dec.assumed ? `<span class="badge unknown" title="An earlier rule with undeterminable conditions (e.g. protocol/port) could change this outcome">depends on assumptions</span>` : '';
  const fromFinal = dec.fromFinal ? `<span class="badge final">via ${kind === 'dns' ? 'dns.final' : 'route.final'}</span>` : '';
  if (kind === 'dns') {
    const cls = dec.actionType === 'reject' ? 'reject' : 'route';
    let value, sub = '';
    if (dec.actionType === 'reject') { value = 'reject'; }
    else if (dec.actionType === 'predefined' || dec.actionType === 'respond') { value = dec.actionType; }
    else {
      value = dec.server || '(default)';
      if (dec.serverInfo) {
        const si = dec.serverInfo;
        sub = `<span class="d-sub">${esc(si.type || '')}${si.address ? ' · ' + esc(si.address) : ''}${si.detour ? ' · via outbound <b>' + esc(si.detour) + '</b>' : ''}</span>`;
      }
    }
    return `<div class="decision ${cls}">
      <span class="d-label">DNS action</span>
      <span class="d-kind">${esc(dec.actionType)}</span><span class="arrow">→</span>
      <span class="d-value">${esc(value)}</span>${sub} ${fromFinal} ${assumed}
    </div>`;
  }
  // route
  let cls = 'route', value;
  if (dec.actionType === 'reject') { cls = 'reject'; value = 'reject'; }
  else if (dec.actionType === 'hijack-dns') { value = 'hijack-dns'; }
  else { value = dec.outbound || '(default outbound)'; }
  return `<div class="decision ${cls}">
    <span class="d-label">Final outbound</span>
    <span class="d-value">${esc(value)}</span>
    ${dec.detail && dec.actionType === 'reject' ? `<span class="d-sub">${esc(dec.detail)}</span>` : ''}
    ${fromFinal} ${assumed}
  </div>`;
}

/* ---------------- settings ---------------- */
// testDoH issues the same DoH JSON query the engine's resolver uses (a CORS
// "simple request": GET with an Accept: application/dns-json header) so the
// Settings dialog can confirm an endpoint actually resolves from the browser.
async function testDoH(server) {
  const u = new URL(server);
  u.searchParams.set('name', 'example.com');
  u.searchParams.set('type', '1');
  u.searchParams.set('ct', 'application/dns-json');
  const resp = await fetch(u.toString(), { headers: { Accept: 'application/dns-json' } });
  if (!resp.ok) throw new Error('HTTP ' + resp.status);
  const j = await resp.json();
  return (j.Answer || []).filter((a) => a.type === 1).map((a) => a.data);
}

function openSettings() {
  const root = $('#modal-root');
  root.innerHTML = `
    <div class="modal-backdrop" id="settings-backdrop">
      <div class="modal">
        <div class="card-head"><h2>Settings</h2><button class="btn ghost small" id="s-close">✕</button></div>
        <div class="card-body">
          <div class="field">
            <label class="lbl">HTTPS DNS (DoH) endpoint <span class="hint">DoH JSON API · must allow CORS</span></label>
            <input type="url" id="s-doh" value="${esc(state.settings.dohServer || '')}" placeholder="https://1.1.1.1/dns-query" />
            <div class="row" style="gap:8px;margin-top:6px;align-items:center">
              <button class="btn small" id="s-doh-test">Test resolver</button>
              <span class="muted" id="s-doh-result"></span>
            </div>
          </div>
          <div class="field">
            <label class="lbl">Quick presets</label>
            <div class="row" style="gap:6px">
              ${['https://1.1.1.1/dns-query', 'https://sm2.doh.pub/dns-query']
                .map((u) => `<button class="btn small preset" data-url="${esc(u)}">${esc(u.replace('https://', '').replace('/dns-query', ''))}</button>`).join('')}
            </div>
          </div>
          <hr class="sep" />
          <div class="field">
            <label class="check">
              <input type="checkbox" id="s-geo" ${state.settings.geoEnabled ? 'checked' : ''}/>
              Annotate IP geolocation (归属地 + flag)
            </label>
            <div class="hint" style="margin-top:4px">Downloads the qqwry.ipdb database (~37 MB) once from the URL below, then caches it in your browser. Lookups stay local — nothing is uploaded.</div>
          </div>
          <div class="field">
            <label class="lbl">Geo database URL <span class="hint">ipdb format · must allow CORS</span></label>
            <input type="url" id="s-geourl" value="${esc(state.settings.geoUrl || (window.singvisGeo && singvisGeo.DEFAULT_URL) || '')}" placeholder="https://cdn.jsdelivr.net/npm/qqwry.ipdb/qqwry.ipdb" />
          </div>
          <div class="row" style="justify-content:flex-end;margin-top:6px">
            <button class="btn primary" id="s-save">Save</button>
          </div>
        </div>
      </div>
    </div>`;
  const close = () => { root.innerHTML = ''; };
  $('#s-close').onclick = close;
  $('#settings-backdrop').onclick = (e) => { if (e.target.id === 'settings-backdrop') close(); };
  root.querySelectorAll('.preset').forEach((b) => b.onclick = () => { $('#s-doh').value = b.dataset.url; });
  $('#s-doh-test').onclick = async () => {
    const server = $('#s-doh').value.trim() || 'https://1.1.1.1/dns-query';
    const btn = $('#s-doh-test'), out = $('#s-doh-result');
    btn.disabled = true; out.className = 'muted'; out.textContent = 'testing…';
    try {
      const ips = await testDoH(server);
      if (ips.length) { out.className = 'ok-text'; out.textContent = '✓ example.com → ' + ips.join(', '); }
      else { out.className = 'warn-text'; out.textContent = '⚠ responded, but no A records returned'; }
    } catch (e) {
      out.className = 'err-text'; out.textContent = '✗ ' + ((e && e.message) || 'request failed') + ' — check the URL / CORS';
    } finally { btn.disabled = false; }
  };
  $('#s-save').onclick = async () => {
    const dohServer = $('#s-doh').value.trim() || 'https://1.1.1.1/dns-query';
    const geoEnabled = $('#s-geo').checked;
    const geoUrl = $('#s-geourl').value.trim() || (window.singvisGeo && singvisGeo.DEFAULT_URL) || '';
    try {
      state.settings = await storage.saveSettings({ dohServer, geoEnabled, geoUrl });
      const ind = $('#doh-indicator'); if (ind) ind.textContent = 'DoH: ' + state.settings.dohServer;
      if (window.singvisGeo) {
        singvisGeo.configure({ enabled: geoEnabled, url: geoUrl });
        if (geoEnabled) singvisGeo.ensureLoaded();
      }
      updateGeoIndicator();
      if (state.lastResult && document.getElementById('results')) renderResults(state.lastResult);
      close(); toast('Settings saved', 'ok');
    } catch (e) { toast('Save failed: ' + e.message, 'err'); }
  };
}

init();
