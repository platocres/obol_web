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

  // Add a manually-entered credential (a hash or any other secret) to the engagement ledger, so it
  // joins the switcher and can fill commands. Type: 'PW' password, 'NT' NT hash, 'OT' other secret.
  function add(c) {
    OBOL.store.update(function (eng) {
      eng.credentials = eng.credentials || [];
      eng.credentials.push({ user: c.user, domain: c.domain || '', source: 'logged', secretType: c.type,
        secret: c.type === 'NT' ? '' : (c.secret || ''), nthash: c.type === 'NT' ? (c.secret || '') : '' });
    }, 'credentials');
  }

  // Remove a manually-added (logged) credential; proven-fact creds are managed via the Facts panel.
  function remove(cred) {
    OBOL.store.update(function (eng) {
      eng.credentials = (eng.credentials || []).filter(function (c) {
        return keyOf({ user: c.user || c.username, domain: c.domain, secret: c.secret || c.password, nthash: c.nthash || c.hash }) !== keyOf(cred);
      });
    }, 'credentials');
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

  function typeLabel(t) { return t === 'NT' ? 'nthash' : (t === 'PW' ? 'password' : (t === 'OT' ? 'secret' : 'no secret')); }
  function typeClass(t) { return t === 'NT' ? 'ct-nt' : (t === 'OT' ? 'ct-ot' : 'ct-pw'); }
  // Redaction is opt-in (the report's per-engagement Redact Secrets toggle). Off by default, so the
  // switcher shows the credential you actually recovered rather than dots.
  function redactOn() { try { return !!(OBOL.store.active().ui || {}).reportRedact; } catch (e) { return false; } }
  function maskSecret(c, redact) {
    var s = c.secret || c.nthash || '';
    if (!s) return '—';
    if (redact) return (c.type === 'NT' || c.type === 'OT') ? (s.slice(0, 8) + (s.length > 8 ? '…' : '')) : '••••••••';
    // Not redacting: show the real secret. A long hash is truncated ONLY for the narrow sidebar —
    // never masked — with the full value in the row's title tooltip and the copy button.
    if ((c.type === 'NT' || c.type === 'OT') && s.length > 14) return s.slice(0, 14) + '…';
    return s.length > 20 ? (s.slice(0, 20) + '…') : s;
  }

  var addOpen = false;
  function addForm() {
    return '<div class="cred-add-form">'
      + '<input class="cf-fld cf-user" type="text" placeholder="user" autocomplete="off" spellcheck="false">'
      + '<input class="cf-fld cf-domain" type="text" placeholder="domain (optional)" autocomplete="off" spellcheck="false">'
      + '<div class="cf-row">'
      + '<select class="cf-type" aria-label="Secret type"><option value="PW">password</option><option value="NT">NT hash</option><option value="OT">other secret</option></select>'
      + '<input class="cf-fld cf-secret" type="text" placeholder="secret / hash" autocomplete="off" spellcheck="false">'
      + '</div>'
      + '<div class="cf-actions"><button class="cf-save btn-mini" type="button">Add</button>'
      + '<button class="cf-cancel btn-ghost-mini" type="button">Cancel</button></div>'
      + '</div>';
  }

  // Render the switcher into the sidebar container.
  function render() {
    var el = document.getElementById('cred-switch');
    if (!el) return;
    var creds = gather();
    render._creds = creds;
    var active = activeKey();
    var redact = redactOn();
    var rows = creds.map(function (c, i) {
      var on = keyOf(c) === active;
      var secret = c.secret || c.nthash || '';
      var secretLabel = c.type === 'NT' ? 'hash' : (c.type === 'OT' ? 'secret' : 'password');
      // Layout: the two value rows read cleanly (name, then domain\secret), and a dedicated action row
      // carries two LABELLED copy buttons so it is obvious which one lifts the username vs. the secret —
      // no more two bare icons stacked in the corner. Clicking the card body still selects the credential.
      return '<div class="cred-row' + (on ? ' active' : '') + '" data-cred="' + i + '" role="button" tabindex="0"'
        + ' aria-pressed="' + (on ? 'true' : 'false') + '" title="Click to fill commands with ' + esc(c.user) + '">'
        + '<div class="cred-top">'
        + '<span class="cred-dot" aria-hidden="true"></span>'
        + '<span class="cred-user">' + esc(c.user) + '</span>'
        + '<span class="cred-type ' + typeClass(c.type) + '">' + esc(typeLabel(c.type)) + '</span>'
        + (c.source === 'logged' ? '<button class="cred-del" type="button" data-cred="' + i + '" title="Remove credential" aria-label="Remove credential">×</button>' : '')
        + '</div>'
        + '<div class="cred-sub">'
        + (c.domain ? '<span class="cred-dom">' + esc(c.domain) + '\\</span>' : '')
        + '<span class="cred-secret"' + (!redact && secret ? ' title="' + U.attr(secret) + '"' : '') + '>' + esc(maskSecret(c, redact)) + '</span>'
        + '</div>'
        + '<div class="cred-actions">'
        + (c.user ? '<button class="cred-copy cred-copy-user" type="button" data-copy="' + U.attr(c.user) + '" data-what="Username" title="Copy username"><span class="cc-ico" aria-hidden="true">⧉</span> user</button>' : '')
        + (secret ? '<button class="cred-copy cred-copy-secret" type="button" data-copy="' + U.attr(secret) + '" data-what="Secret" title="Copy ' + secretLabel + '"><span class="cc-ico" aria-hidden="true">⧉</span> ' + secretLabel + '</button>' : '')
        + '</div>'
        + '</div>';
    }).join('');
    var empty = creds.length ? '' : '<div class="cred-empty">None yet — prove one from Evidence, or add one below.</div>';
    var adder = addOpen ? addForm()
      : '<button class="cred-add-btn" type="button">+ Add Credential</button>';
    el.innerHTML = empty + rows + adder;
  }

  // Wire delegated handlers once.
  function mount() {
    var el = document.getElementById('cred-switch');
    if (!el || el._wired) return;
    el._wired = true;
    U.on(el, 'click', '.cred-copy', function (e, t) {
      if (e.stopPropagation) e.stopPropagation();
      var what = t.getAttribute('data-what') || 'Value';
      U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? (what + ' copied') : 'Copy failed', ok ? '' : 'err'); });
    });
    U.on(el, 'click', '.cred-del', function (e, t) {
      if (e.stopPropagation) e.stopPropagation();
      remove((render._creds || [])[+t.getAttribute('data-cred')]);
    });
    U.on(el, 'click', '.cred-row', function (e, t) {
      if (e.target && (e.target.closest('.cred-copy') || e.target.closest('.cred-del'))) return;
      activate((render._creds || [])[+t.getAttribute('data-cred')]);
    });
    el.addEventListener('keydown', function (e) {
      var row = e.target && e.target.classList && e.target.classList.contains('cred-row') ? e.target : null;
      if (row && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); activate((render._creds || [])[+row.getAttribute('data-cred')]); }
    });
    // add-credential form: open / cancel / save (store change re-renders the whole sidebar)
    U.on(el, 'click', '.cred-add-btn', function () { addOpen = true; render(); var u = el.querySelector('.cf-user'); if (u) u.focus(); });
    U.on(el, 'click', '.cf-cancel', function () { addOpen = false; render(); });
    U.on(el, 'click', '.cf-save', function () {
      var user = (el.querySelector('.cf-user') || {}).value, secret = (el.querySelector('.cf-secret') || {}).value;
      var domain = (el.querySelector('.cf-domain') || {}).value, type = (el.querySelector('.cf-type') || {}).value || 'PW';
      user = (user || '').trim(); secret = (secret || '').trim();
      if (!user) { U.toast('Enter a username', 'err'); return; }
      if (!secret) { U.toast('Enter the secret / hash', 'err'); return; }
      addOpen = false; // close before add() so the store-change re-render draws the collapsed state
      add({ user: user, domain: (domain || '').trim(), secret: secret, type: type });
      U.toast('Credential added: ' + user);
    });
    el.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && e.target && e.target.classList && e.target.classList.contains('cf-fld')) {
        e.preventDefault(); var b = el.querySelector('.cf-save'); if (b) b.click();
      }
    });
  }

  OBOL.creds = { keyOf: keyOf, gather: gather, activeKey: activeKey, activate: activate, add: add, remove: remove };
  OBOL.credbar = { render: render, mount: mount };
})(typeof globalThis !== 'undefined' ? globalThis : this);
