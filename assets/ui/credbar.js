/*!
 * obol ui — credbar.js — the credential switcher.
 * Collects every credential the engagement has picked up (logged in engagement.credentials +
 * proven in facts) and surfaces them as an always-visible sidebar bar. Activating one fills the
 * engagement params (user / secret / domain), which is what the command templater reads — so a
 * single click re-populates every command preview across the console with that identity.
 * The full cred×host reuse matrix (routes/creds.js) shares this module's gather().
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }

  // Identity key for dedupe + active-match: who + which secret.
  function keyOf(c) {
    return String(c.user || '').toLowerCase() + '|' + String(c.domain || '').toLowerCase()
      + '|' + (c.secret || c.nthash || '');
  }

  // Gather deduped credentials from the engagement ledger + proven facts.
  function gather(eng, fs) {
    eng = eng || (OBOL.store && OBOL.store.active());
    fs = fs || (OBOL.store && OBOL.store.factSet());
    var out = [], seen = {};
    function push(c) { var k = keyOf(c); if (!c.user || seen[k]) return; seen[k] = 1; out.push(c); }
    ((eng && eng.credentials) || []).forEach(function (c) {
      push({ user: c.user || c.username || '', domain: c.domain || '', secret: c.secret || c.password || '',
        nthash: c.nthash || c.hash || '', type: c.secretType || ((c.nthash || c.hash) ? 'NT' : ((c.secret || c.password) ? 'PW' : '?')),
        source: 'logged' });
    });
    ((fs && fs.facts) || []).forEach(function (f) {
      if (f.state !== 'supported') return;
      if (f.kind !== 'credential.available' && f.kind !== 'credential.plaintext' && f.kind !== 'credential.admin') return;
      var v = f.value || {}; if (!v.user) return;
      var dom = v.domain || (String(f.scope || '').indexOf('domain:') === 0 ? f.scope.slice(7) : '');
      push({ user: v.user, domain: dom, secret: v.password || '', nthash: v.nthash || v.hash || '',
        type: (v.nthash || v.hash) ? 'NT' : (v.password ? 'PW' : '?'), source: 'proven', scope: f.scope });
    });
    return out;
  }

  // The key of the credential currently filling commands (matches the engagement params).
  function activeKey(eng) {
    eng = eng || (OBOL.store && OBOL.store.active());
    var p = (eng && eng.params) || {};
    if (!p.username) return '';
    return keyOf({ user: p.username, domain: p.domain, secret: p.password, nthash: p.nthash });
  }

  // Make this credential the active one: push it into params so every command re-fills.
  function activate(cred) {
    if (!cred) return;
    OBOL.store.update(function (eng) {
      eng.params = eng.params || {};
      eng.params.username = cred.user || '';
      eng.params.password = cred.secret || '';
      eng.params.nthash = cred.nthash || '';
      if (cred.domain) eng.params.domain = cred.domain;
    }, 'params');
    if (OBOL.app && OBOL.app.renderSidebar) OBOL.app.renderSidebar();
    if (OBOL.router) OBOL.router.render();
    U.toast('Using ' + (cred.domain ? cred.domain + '\\' : '') + cred.user);
  }

  function typeLabel(t) { return t === 'NT' ? 'nthash' : (t === 'PW' ? 'password' : 'no secret'); }
  function maskSecret(c) {
    var s = c.secret || c.nthash || '';
    if (!s) return '—';
    return c.type === 'NT' ? (s.slice(0, 8) + '…') : '••••••••';
  }

  // Render the switcher into the sidebar container.
  function render() {
    var el = document.getElementById('cred-switch');
    if (!el) return;
    var creds = gather();
    render._creds = creds;
    if (!creds.length) {
      el.innerHTML = '<div class="cred-empty">None yet — credentials appear here as you prove or add them, ready to fill commands.</div>';
      return;
    }
    var active = activeKey();
    el.innerHTML = creds.map(function (c, i) {
      var on = keyOf(c) === active;
      var secret = c.secret || c.nthash || '';
      return '<div class="cred-row' + (on ? ' active' : '') + '" data-cred="' + i + '" role="button" tabindex="0"'
        + ' aria-pressed="' + (on ? 'true' : 'false') + '" title="Fill commands with ' + esc(c.user) + '">'
        + '<div class="cred-top">'
        + '<span class="cred-dot" aria-hidden="true"></span>'
        + '<span class="cred-user">' + esc(c.user) + '</span>'
        + '<span class="cred-type ct-' + (c.type === 'NT' ? 'nt' : 'pw') + '">' + esc(typeLabel(c.type)) + '</span>'
        + (secret ? '<button class="cred-copy" type="button" data-copy="' + U.attr(secret) + '" title="Copy secret" aria-label="Copy secret">⧉</button>' : '')
        + '</div>'
        + '<div class="cred-sub">'
        + (c.domain ? '<span class="cred-dom">' + esc(c.domain) + '\\</span>' : '')
        + '<span class="cred-secret">' + esc(maskSecret(c)) + '</span>'
        + '</div>'
        + '</div>';
    }).join('');
  }

  // Wire delegated handlers once.
  function mount() {
    var el = document.getElementById('cred-switch');
    if (!el || el._wired) return;
    el._wired = true;
    U.on(el, 'click', '.cred-copy', function (e, t) {
      if (e.stopPropagation) e.stopPropagation();
      U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Secret copied' : 'Copy failed', ok ? '' : 'err'); });
    });
    U.on(el, 'click', '.cred-row', function (e, t) {
      if (e.target && e.target.closest('.cred-copy')) return;
      activate((render._creds || [])[+t.getAttribute('data-cred')]);
    });
    el.addEventListener('keydown', function (e) {
      var row = e.target && e.target.classList && e.target.classList.contains('cred-row') ? e.target : null;
      if (row && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); activate((render._creds || [])[+row.getAttribute('data-cred')]); }
    });
  }

  OBOL.creds = { keyOf: keyOf, gather: gather, activeKey: activeKey, activate: activate };
  OBOL.credbar = { render: render, mount: mount };
})(typeof globalThis !== 'undefined' ? globalThis : this);
