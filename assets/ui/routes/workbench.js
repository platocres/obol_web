/*!
 * obol ui, routes/workbench.js, THE WORKBENCH (global, per-browser, not per-engagement).
 * The "borrowed back ends": client-side utilities that answer a situation right here, with no network
 * and no execution. Reverse-shell builder, hash identifier, encoder (mini CyberChef), JWT decoder,
 * GTFOBins browser, wordlist picker. Each FILLS from the active engagement's parameters and credentials
 * when there is one, and works perfectly standalone when there is not.
 *
 * Boundary: presentation only. The Workbench reads OBOL.store + the fact ledger + OBOL.workbench logic.
 * It never writes a pack command, never changes what the coach ranks. Editing LHOST/LPORT here writes
 * back to the one engagement store (OBOL.store), so the Workbench and the coach never disagree.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }

  var W = function () { return OBOL.workbench || {}; };

  // Sub-tabs. Only the built ones are wired; the rest show a short "coming online" panel until their
  // phase lands, so the shell is navigable from the first commit.
  var TABS = [
    { id: 'revshell', label: 'Reverse Shell' },
    { id: 'hashid', label: 'Hash ID' },
    { id: 'encoder', label: 'Encoder' },
    { id: 'jwt', label: 'JWT' },
    { id: 'gtfobins', label: 'GTFOBins' },
    { id: 'wordlists', label: 'Wordlists' },
  ];
  function tabIds() { return TABS.map(function (t) { return t.id; }); }

  var _tab = 'revshell';
  // Reverse-shell builder state (module-local; LHOST/LPORT seed from the engagement and sync back).
  var _rs = { id: 'bash-i', enc: 'plain' };

  function activeParams() { var e = OBOL.store.active(); return (e && e.params) || {}; }
  function rsSeed() {
    var p = activeParams();
    return { lhost: p.lhost || '', lport: p.lport || '4444' };
  }
  function linkedNote() {
    var e = OBOL.store.active();
    if (!e) return 'No engagement active. Type your values below. They work standalone here.';
    return 'Linked to ' + esc(OBOL.store.runLabel(e)) + '. Values fill from its parameters and save back to it.';
  }

  // ── Reverse Shell Builder ──────────────────────────────────────────────────────────────────
  function rsPickerHtml() {
    var wb = W(), list = wb.REVSHELLS || [];
    function group(os, title) {
      var items = list.filter(function (e) { return e.os === os; });
      return '<div class="wb-rs-group"><div class="wb-rs-group-h">' + esc(title) + '</div><div class="wb-rs-opts">'
        + items.map(function (e) {
          var on = e.id === _rs.id;
          return '<button type="button" class="wb-rs-opt' + (on ? ' on' : '') + '" data-rs-id="' + esc(e.id) + '"'
            + ' aria-pressed="' + (on ? 'true' : 'false') + '">' + esc(e.name) + '</button>';
        }).join('') + '</div></div>';
    }
    return group('linux', 'Linux') + group('windows', 'Windows');
  }

  // The output region: the filled command, encoding toggles, the note, and the matching listener.
  // Read on first render and re-read imperatively on every change so inputs never lose focus.
  function rsOutHtml() {
    var wb = W(), entry = wb.revShell(_rs.id);
    if (!entry) return '';
    var lhostEl = document.getElementById('wb-rs-lhost');
    var lportEl = document.getElementById('wb-rs-lport');
    var seed = rsSeed();
    var lhost = lhostEl ? lhostEl.value : seed.lhost;
    var lport = lportEl ? lportEl.value : seed.lport;
    var vals = { lhost: lhost, lport: lport };
    var plain = wb.fill(entry.tpl, vals);

    // which encodings this shell offers
    var enc = entry.enc || [];
    var modes = [{ id: 'plain', label: 'Plain' }];
    if (enc.indexOf('b64') >= 0) modes.push({ id: 'b64', label: 'Base64 Runner' });
    if (enc.indexOf('psenc') >= 0) modes.push({ id: 'psenc', label: 'Base64 (-EncodedCommand)' });
    if (!modes.some(function (m) { return m.id === _rs.enc; })) _rs.enc = 'plain';

    var shown = plain, encExplain = '';
    if (_rs.enc === 'b64') {
      shown = wb.linuxB64Runner(plain);
      encExplain = 'Base64-wrapped so quotes, &amp; and redirects survive being pasted into a target field. The box decodes it and runs the same shell. This is the OSCP-taught trick for bad characters.';
    } else if (_rs.enc === 'psenc') {
      shown = 'powershell -nop -w hidden -enc ' + wb.psEnc(plain);
      encExplain = 'PowerShell -EncodedCommand: the script as UTF-16LE, then base64. One token, no quoting to break. This is exactly how OffSec teaches it for the OSCP.';
    }

    var chips = modes.map(function (m) {
      var on = m.id === _rs.enc;
      return '<button type="button" class="wb-chip' + (on ? ' on' : '') + '" data-rs-enc="' + esc(m.id) + '"'
        + ' aria-pressed="' + (on ? 'true' : 'false') + '">' + esc(m.label) + '</button>';
    }).join('');

    var listener = wb.listenerFor(entry, vals);

    return '<div class="wb-enc-row" role="group" aria-label="Encoding">' + chips + '</div>'
      + (encExplain ? '<p class="wb-enc-note">' + encExplain + '</p>' : '')
      + '<div class="wb-field-l">Run This On The Target</div>'
      + '<div class="wb-cmd"><code>' + esc(shown) + '</code>'
      + '<button class="btn-copy" data-copy="' + U.attr(shown) + '" title="Copy" aria-label="Copy command">copy</button></div>'
      + '<div class="wb-field-l">Catch It On Kali First</div>'
      + '<div class="wb-cmd wb-cmd-listener"><code>' + esc(listener) + '</code>'
      + '<button class="btn-copy" data-copy="' + U.attr(listener) + '" title="Copy" aria-label="Copy listener">copy</button></div>'
      + '<p class="wb-note">' + esc(entry.note) + '</p>';
  }

  function revshellPanel() {
    var seed = rsSeed();
    return '<div class="wb-panel wb-revshell">'
      + '<p class="wb-linked">' + linkedNote() + '</p>'
      + '<div class="wb-params">'
      + '<label class="wb-param"><span>LHOST (Your Kali)</span>'
      + '<input id="wb-rs-lhost" type="text" value="' + U.attr(seed.lhost) + '" placeholder="10.10.14.2" autocomplete="off" spellcheck="false"></label>'
      + '<label class="wb-param"><span>LPORT</span>'
      + '<input id="wb-rs-lport" type="text" value="' + U.attr(seed.lport) + '" placeholder="4444" autocomplete="off" spellcheck="false"></label>'
      + '<span class="wb-hint">Not sure of your LHOST? On Kali: <code>ip addr show tun0</code></span>'
      + '</div>'
      + '<div class="wb-rs-pick" role="group" aria-label="Reverse shell type">' + rsPickerHtml() + '</div>'
      + '<div id="wb-rs-out" class="wb-rs-out">' + rsOutHtml() + '</div>'
      + '</div>';
  }

  function stubPanel(label) {
    return '<div class="wb-panel wb-stub"><p class="wb-note">' + esc(label)
      + ' is coming online in this build. The Reverse Shell Builder is ready now, the rest land next.</p></div>';
  }

  function panelFor(tab) {
    if (tab === 'revshell') return revshellPanel();
    var t = TABS.filter(function (x) { return x.id === tab; })[0];
    return stubPanel(t ? t.label : 'This tool');
  }

  function render(ctx) {
    var arg = (ctx.args && ctx.args[0]) || '';
    if (tabIds().indexOf(arg) >= 0) _tab = arg;

    var tabbar = TABS.map(function (t) {
      var on = t.id === _tab;
      return '<a class="wb-tab' + (on ? ' active' : '') + '" href="#/workbench/' + t.id + '"'
        + (on ? ' aria-current="page"' : '') + '>' + esc(t.label) + '</a>';
    }).join('');

    return '<section class="wb">'
      + '<h1 class="route-h1">Workbench</h1>'
      + '<p class="route-sub">Client-side utilities that answer your situation right here. No network, no execution. '
      + 'They fill from your active engagement and work standalone.</p>'
      + '<nav class="wb-tabs" aria-label="Workbench tools">' + tabbar + '</nav>'
      + panelFor(_tab);
  }

  function refreshRsOut() {
    var out = document.getElementById('wb-rs-out');
    if (out) out.innerHTML = rsOutHtml();
  }
  function syncParam(key, val) {
    if (!OBOL.store.active()) return;
    OBOL.store.update(function (e) { e.params = e.params || {}; e.params[key] = val; }, 'params');
  }

  function mounted(ctx) {
    var mount = ctx.mount;

    // copy buttons (shared handler)
    U.on(mount, 'click', '.btn-copy', function (e, t) {
      U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Copied' : 'Copy failed', ok ? '' : 'err'); });
    });

    // reverse-shell: pick a shell
    U.on(mount, 'click', '.wb-rs-opt', function (e, t) {
      _rs.id = t.getAttribute('data-rs-id');
      // reflect selection without a full re-render (keeps LHOST/LPORT focus + values)
      var opts = mount.querySelectorAll('.wb-rs-opt');
      for (var i = 0; i < opts.length; i++) {
        var on = opts[i] === t;
        opts[i].classList.toggle('on', on);
        opts[i].setAttribute('aria-pressed', on ? 'true' : 'false');
      }
      refreshRsOut();
    });

    // reverse-shell: encoding toggle (delegated: the chips live inside the refreshed region)
    U.on(mount, 'click', '.wb-chip', function (e, t) {
      _rs.enc = t.getAttribute('data-rs-enc') || 'plain';
      refreshRsOut();
    });

    // reverse-shell: LHOST / LPORT edits recompute and save back to the engagement
    U.on(mount, 'input', '#wb-rs-lhost', function (e, t) { syncParam('lhost', t.value); refreshRsOut(); });
    U.on(mount, 'input', '#wb-rs-lport', function (e, t) { syncParam('lport', t.value); refreshRsOut(); });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.workbench = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
