/*!
 * obol ui — routes/creds.js — the credential reuse matrix + one-click retarget.
 * Credentials × hosts grid; a cell reflects proven auth/admin on that host for that identity
 * (conservative — derived from facts, never assumed). Click a cred / host / cell to refill the
 * engagement params (user/secret/domain/target) across the whole console.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }

  // Gather credentials via the shared collector (engagement.credentials + proven facts),
  // so the reuse matrix and the sidebar switcher always agree on the credential set.
  function gatherCreds() { return OBOL.creds.gather(); }

  // Cell status for cred×host: derived from facts scoped to that host.
  function cellStatus(cred, host) {
    var f = OBOL.store.factSetForTarget(host.ip);
    var admin = f.has('access.admin') || f.has('access.system') || f.has('access.root');
    // a proven credential.available on this host with the same user = valid here
    var validHere = f.facts.some(function (x) {
      return x.state === 'supported' && (x.kind === 'credential.available' || x.kind.indexOf('.authenticated') > 0)
        && String((x.value || {}).user || '').toLowerCase() === cred.user.toLowerCase();
    });
    if (validHere && admin) return { c: 'ADM', cls: 'cell-adm' };
    if (validHere) return { c: '✓', cls: 'cell-ok' };
    return { c: '·', cls: 'cell-none' };
  }

  function render() {
    var eng = OBOL.store.active();
    var hosts = (eng.targets || []);
    var creds = gatherCreds();
    if (!creds.length) {
      return '<section class="creds-route"><h1 class="route-h1">Credentials</h1>'
        + '<p class="route-sub">No credentials yet. Add them in the sidebar params (User/Password/NT hash), or paste output that proves a credential on Evidence — they will appear here as a reuse matrix.</p></section>';
    }
    var head = '<th class="cm-corner">cred \\ host</th>' + hosts.map(function (h) {
      return '<th class="cm-host" data-host="' + esc(h.ip) + '"><button class="cm-hostbtn" data-host="' + esc(h.ip) + '">' + esc(h.ip) + '</button></th>';
    }).join('');
    var rows = creds.map(function (cred, i) {
      var cells = hosts.map(function (h) {
        var s = cellStatus(cred, h);
        return '<td class="cm-cell ' + s.cls + '"><button class="cm-cellbtn ' + s.cls + '" data-cred="' + i + '" data-host="' + esc(h.ip) + '" aria-label="aim ' + esc(cred.user) + ' at ' + esc(h.ip) + '">' + s.c + '</button></td>';
      }).join('');
      return '<tr><th class="cm-cred"><button class="cm-credbtn" data-cred="' + i + '"><span class="cm-user">' + esc(cred.user) + '</span>'
        + '<span class="cm-type">' + esc(cred.type) + '</span></button></th>' + cells + '</tr>';
    }).join('');

    // stash creds for handlers
    render._creds = creds;

    return '<section class="creds-route"><h1 class="route-h1">Credentials</h1>'
      + '<p class="route-sub">Reuse matrix — <strong>ADM</strong> = admin proven, <strong>✓</strong> = valid, <strong>·</strong> = untested. Click a credential, a host, or a cell to retarget the whole console to it.</p>'
      + '<div class="cm-scroll"><table class="cm-table"><thead><tr>' + head + '</tr></thead><tbody>' + rows + '</tbody></table></div>'
      + '</section>';
  }

  function retargetCred(cred) {
    OBOL.store.update(function (eng) {
      eng.params = eng.params || {};
      eng.params.username = cred.user;
      if (cred.secret) eng.params.password = cred.secret;
      if (cred.nthash) eng.params.nthash = cred.nthash;
    }, 'params');
    OBOL.app.renderSidebar();
    U.toast('Retargeted to ' + cred.user);
  }
  function retargetHost(ip) {
    OBOL.store.update(function (eng) { eng.params = eng.params || {}; eng.params.target = ip; }, 'params');
    OBOL.app.renderSidebar();
    U.toast('Target → ' + ip);
  }

  function mounted(ctx) {
    var creds = render._creds || [];
    U.on(ctx.mount, 'click', '.cm-credbtn', function (e, t) { retargetCred(creds[+t.getAttribute('data-cred')]); });
    U.on(ctx.mount, 'click', '.cm-hostbtn', function (e, t) { retargetHost(t.getAttribute('data-host')); });
    U.on(ctx.mount, 'click', '.cm-cellbtn', function (e, t) {
      retargetHost(t.getAttribute('data-host'));
      retargetCred(creds[+t.getAttribute('data-cred')]);
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.creds = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
