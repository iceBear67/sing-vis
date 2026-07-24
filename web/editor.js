'use strict';

// Lightweight syntax highlighting for plain <textarea>s — no Monaco, no build
// step, no dependencies. It layers a highlighted <pre> backdrop *behind* a
// transparent textarea and keeps the two scroll-synced, so native editing
// (caret, selection, undo, IME) is fully preserved. The textarea remains the
// single source of truth — app.js keeps reading `.value` as before.
//
// Exposed as window.singvisEditor. Call attach(textareaEl, mode) after the
// textarea is in the DOM; mode is 'json' (config, JSONC) or 'hosts' (the
// domain/IP list). Re-attaching an already-wrapped textarea is a no-op, so it is
// safe to call every time the editor is re-rendered.

(function () {
  function escHTML(s) {
    return String(s).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
  }

  // ---- JSON / JSONC tokenizer ----
  // Order matters: comments, then strings, numbers, literals, punctuation. The
  // string pattern forbids newlines so an unterminated string while typing only
  // colours the current line (JSON strings never span lines anyway).
  const JSON_RE = /(\/\/[^\n]*)|(\/\*[\s\S]*?\*\/)|("(?:\\.|[^"\\\n])*"?)|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|\b(true|false|null)\b|([{}\[\],:])/g;

  function highlightJSON(text) {
    let out = '';
    let last = 0;
    let m;
    JSON_RE.lastIndex = 0;
    while ((m = JSON_RE.exec(text)) !== null) {
      if (m.index > last) out += escHTML(text.slice(last, m.index));
      const tok = m[0];
      if (m[1] != null || m[2] != null) {
        out += `<span class="tok-comment">${escHTML(tok)}</span>`;
      } else if (m[3] != null) {
        // A string immediately followed by ':' is an object key.
        const isKey = /^\s*:/.test(text.slice(JSON_RE.lastIndex));
        out += `<span class="${isKey ? 'tok-key' : 'tok-str'}">${escHTML(tok)}</span>`;
      } else if (m[4] != null) {
        out += `<span class="tok-num">${escHTML(tok)}</span>`;
      } else if (m[5] != null) {
        out += `<span class="tok-lit">${escHTML(tok)}</span>`;
      } else {
        out += `<span class="tok-punc">${escHTML(tok)}</span>`;
      }
      last = JSON_RE.lastIndex;
      if (m.index === JSON_RE.lastIndex) JSON_RE.lastIndex++; // guard against zero-width matches
    }
    out += escHTML(text.slice(last));
    return out;
  }

  // ---- host list tokenizer ----
  // Full-line `#` comments are dimmed; a trailing `:port` (bare host or
  // bracketed IPv6) is accented so the extra routing hint stands out. Raw IPv6
  // literals (unbracketed, many colons) are left as plain host text.
  const PORT_RE = /^(\[[^\]]+\]|[^\[\]:\s]+):(\d+)$/;

  function highlightHosts(text) {
    return text.split('\n').map((line) => {
      if (line.trim() === '') return escHTML(line);
      if (/^\s*#/.test(line)) return `<span class="tok-comment">${escHTML(line)}</span>`;
      const lead = line.match(/^\s*/)[0];
      const trail = line.match(/\s*$/)[0];
      const core = line.slice(lead.length, line.length - trail.length);
      const pm = core.match(PORT_RE);
      let body;
      if (pm) {
        body = escHTML(pm[1]) + `<span class="tok-port">:${escHTML(pm[2])}</span>`;
      } else {
        body = escHTML(core);
      }
      return escHTML(lead) + body + escHTML(trail);
    }).join('\n');
  }

  function attach(textarea, mode) {
    if (!textarea || textarea.dataset.ceAttached === '1') return;
    textarea.dataset.ceAttached = '1';

    const wrap = document.createElement('div');
    wrap.className = 'code-editor ce-' + mode;
    const pre = document.createElement('pre');
    pre.className = 'ce-backdrop';
    pre.setAttribute('aria-hidden', 'true');
    const code = document.createElement('code');
    pre.appendChild(code);

    textarea.parentNode.insertBefore(wrap, textarea);
    wrap.appendChild(pre);
    wrap.appendChild(textarea);
    textarea.classList.add('ce-input');

    const hl = mode === 'json' ? highlightJSON : highlightHosts;
    // The trailing newline keeps the backdrop at least as tall as the textarea
    // when the text ends on a blank line.
    const render = () => { code.innerHTML = hl(textarea.value) + '\n'; };
    const sync = () => { pre.scrollTop = textarea.scrollTop; pre.scrollLeft = textarea.scrollLeft; };
    textarea.addEventListener('input', () => { render(); sync(); });
    textarea.addEventListener('scroll', sync);
    render();
    sync();
  }

  window.singvisEditor = { attach, highlightJSON, highlightHosts };
})();
