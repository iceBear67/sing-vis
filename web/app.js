'use strict';

/* ---------------- utilities ---------------- */
const $ = (sel, root = document) => root.querySelector(sel);
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
));

/* ---------------- wasm engine worker ---------------- */
// The matching engine runs as WebAssembly inside a Web Worker. It is loaded
// lazily on the first Analyze (the wasm is several MB) and reused thereafter.
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
    renderSidebar();
    renderEditor();
  } catch (e) { toast('Failed to load profile: ' + e.message, 'err'); }
}

function newDraft() {
  state.activeId = null;
  state.draft = { name: '', config: SAMPLE_CONFIG, inputs: 'www.google.com\nbaidu.com\nopenai.com\n1.1.1.1', ruleSetFiles: {} };
  state.lastResult = null;
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
          <textarea id="f-inputs" class="inputs" spellcheck="false" placeholder="example.com&#10;1.1.1.1">${esc(d.inputs)}</textarea>
        </div>
      </div>
    </div>

    <div class="toolbar">
      <button class="btn primary" id="btn-analyze">▶ Analyze</button>
      <label class="check" title="Pre-resolve domains via DoH so ip_cidr / IP rule-set rules can match the resolved address">
        <input type="checkbox" id="opt-assume" ${assume ? 'checked' : ''}/> Resolve IPs for IP rules
      </label>
      <div class="field" style="max-width:150px;margin:0">
        <select id="opt-network" title="Assumed connection network for rules that filter on tcp/udp">
          <option value="" ${network === '' ? 'selected' : ''}>network: any</option>
          <option value="tcp" ${network === 'tcp' ? 'selected' : ''}>network: tcp</option>
          <option value="udp" ${network === 'udp' ? 'selected' : ''}>network: udp</option>
        </select>
      </div>
      <span class="spacer"></span>
      <span class="muted mono" id="doh-indicator">DoH: ${esc(state.settings.dohServer || '—')}</span>
    </div>

    <div id="results"></div>
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
  const btn = $('#btn-analyze');
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Analyzing…';
  const loadingEngine = !engineWorker.ready;
  $('#results').innerHTML = `<div class="placeholder"><span class="spinner"></span> ${loadingEngine ? 'Loading engine (first run, ~a few MB)…' : 'Resolving &amp; matching…'}</div>`;
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
    renderResults(result);
  } catch (e) {
    $('#results').innerHTML = `<div class="card"><div class="card-body" style="color:var(--reject)">⚠ ${esc(e.message)}</div></div>`;
  } finally {
    btn.disabled = false; btn.innerHTML = '▶ Analyze';
  }
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
}

function renderInputCard(it, idx) {
  const chips = [];
  if (it.kind === 'invalid') {
    chips.push(`<span class="chip reject"><span class="k">error</span><span class="v">${esc(it.error || 'invalid')}</span></span>`);
  } else {
    if (it.dns && it.dns.decision) chips.push(dnsChip(it.dns.decision));
    if (it.route && it.route.decision) chips.push(routeChip(it.route.decision));
  }
  const open = idx === 0 ? 'open' : '';
  return `
    <div class="card result-card ${open}">
      <div class="result-head">
        <span class="input-name">${esc(it.input)}</span>
        <span class="badge kind-${esc(it.kind)}">${esc(it.kind)}</span>
        <div class="outcome-chips">${chips.join('')}</div>
        <span class="caret">▶</span>
      </div>
      <div class="result-body">
        ${it.kind === 'invalid' ? `<p class="muted">${esc(it.error || 'Could not parse this input.')}</p>` : ''}
        ${renderResolved(it.resolved)}
        ${it.dns ? `<div class="section-title">DNS routing (which server / dns action)</div>${renderTrace(it.dns, 'dns')}` : ''}
        ${it.route ? `<div class="section-title">Route matching (which rule / outbound)</div>${renderTrace(it.route, 'route')}` : ''}
      </div>
    </div>`;
}

function dnsChip(dec) {
  if (dec.actionType === 'reject') return `<span class="chip reject"><span class="k">DNS</span><span class="v">reject</span></span>`;
  const server = dec.server || (dec.actionType);
  const detour = dec.serverInfo && dec.serverInfo.detour ? ` <span class="k">via</span> ${esc(dec.serverInfo.detour)}` : '';
  return `<span class="chip dns"><span class="k">DNS</span><span class="v">${esc(server)}</span>${detour}</span>`;
}

function routeChip(dec) {
  if (dec.actionType === 'reject') return `<span class="chip reject"><span class="k">route</span><span class="v">reject</span></span>`;
  if (dec.actionType === 'hijack-dns') return `<span class="chip route"><span class="k">route</span><span class="v">hijack-dns</span></span>`;
  return `<span class="chip route"><span class="k">route</span><span class="v">${esc(dec.outbound || '(default)')}</span></span>`;
}

function renderResolved(r) {
  if (!r) return '';
  if (r.error && !(r.ipv4 && r.ipv4.length) && !(r.ipv6 && r.ipv6.length)) {
    return `<div class="section-title">Resolved (DoH)</div><p class="muted">resolution failed: ${esc(r.error)}</p>`;
  }
  const v4 = (r.ipv4 || []).map((ip) => `<span class="ip-chip">${esc(ip)}</span>`).join('');
  const v6 = (r.ipv6 || []).map((ip) => `<span class="ip-chip">${esc(ip)}</span>`).join('');
  if (!v4 && !v6) return `<div class="section-title">Resolved (DoH)</div><p class="muted">no A/AAAA records</p>`;
  return `<div class="section-title">Resolved via ${esc(r.server)}</div><div class="ip-chips">${v4}${v6}</div>`;
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
  const detailInner = conds || '<span class="muted">no conditions (matches all)</span>';
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
  const rs = c.ruleSet ? renderRuleSet(c.ruleSet) : '';
  return `
    <div class="cond">
      <span class="cf">${esc(c.field)} ${statusBadge(c.status)}</span>
      <span class="group-tag">${esc(c.group)}</span>
      <span class="cv">${esc(c.value)} ${matched}</span>
      ${note}
    </div>${rs}`;
}

function renderRuleSet(rs) {
  const inner = (rs.rules || []).map((r) => {
    const cs = r.type === 'logical' ? renderLogical(r) : (r.conditions || []).map(renderCond).join('');
    return `<div style="margin-top:6px">${statusBadge(r.status)} <span class="mono">${esc(r.summary)}</span>${cs}</div>`;
  }).join('');
  const err = rs.error ? `<div class="rs-err">⚠ ${esc(rs.error)}</div>` : '';
  const matched = rs.matchedIdx >= 0 ? ` · matched rule #${rs.matchedIdx}` : '';
  return `
    <div class="ruleset-box">
      <div class="rs-head">${statusBadge(rs.status)} <b>rule_set</b> <span class="mono">${esc(rs.tag)}</span>
        <span class="rs-meta">(${esc(rs.type || '?')} · ${rs.count || 0} rules${matched})</span>
      </div>
      ${err}${inner}
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
      <span class="d-value">${esc(dec.actionType)}</span><span class="arrow">→</span>
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
          </div>
          <div class="field">
            <label class="lbl">Quick presets</label>
            <div class="row" style="gap:6px">
              ${['https://1.1.1.1/dns-query', 'https://dns.google/dns-query', 'https://dns.quad9.net/dns-query', 'https://dns.alidns.com/dns-query']
                .map((u) => `<button class="btn small preset" data-url="${esc(u)}">${esc(u.replace('https://', '').replace('/dns-query', ''))}</button>`).join('')}
            </div>
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
  $('#s-save').onclick = async () => {
    const dohServer = $('#s-doh').value.trim() || 'https://1.1.1.1/dns-query';
    try {
      state.settings = await storage.saveSettings({ dohServer });
      const ind = $('#doh-indicator'); if (ind) ind.textContent = 'DoH: ' + state.settings.dohServer;
      close(); toast('Settings saved', 'ok');
    } catch (e) { toast('Save failed: ' + e.message, 'err'); }
  };
}

init();
