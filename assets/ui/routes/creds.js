/*!
 * obol ui — routes/creds.js — the engagement's credential ledger / ops center.
 * The ONE place every credential of every kind obol has seen lives: working creds, found-but-untested,
 * captured hashes to crack, and enumerated usernames. For each: its secret (shown + copy), where it came
 * from, which hosts it works on, and which flag its access level unlocked. Plus live per-type lists
 * (usernames, passwords, NT hashes, AS-REP, Kerberoast, combos) you can copy or write to loot/, and a
 * one-click Load that arms the whole console with ANY credential (the nav dropdown stays proven-only).
 * Presentation only: everything is derived from the fact ledger; the matrix/retarget reuse the store.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }
  function attr(s) { return U.attr(s); }

  // Pull the account out of a Kerberos hash string so a roasted hash still names who it is.
  function asrepUser(h) { var m = /\$krb5asrep\$(?:\d+\$)?([^@*$\s:]+)@/i.exec(h || ''); return m ? m[1] : ''; }
  function tgsUser(h) { var m = /\$krb5tgs\$(?:\d+\$)?\*([^$*\s]+)\$/i.exec(h || ''); return m ? m[1] : ''; }
  function hostFromScope(scope) { return String(scope || '').indexOf('host:') === 0 ? scope.slice(5) : ''; }

  // cred × host status, conservative: valid if a proven credential/auth fact names this user on the host,
  // admin if the host is also owned. (The existing matrix semantics, reused for the "works on" column.)
  function cellStatus(cred, host) {
    var f = OBOL.store.factSetForTarget(host.ip);
    var admin = f.has('access.admin') || f.has('access.system') || f.has('access.root');
    var validHere = f.facts.some(function (x) {
      return x.state === 'supported' && (x.kind === 'credential.available' || x.kind.indexOf('.authenticated') > 0)
        && String((x.value || {}).user || '').toLowerCase() === String(cred.user || '').toLowerCase();
    });
    if (validHere && admin) return { c: 'ADM', cls: 'cell-adm', level: 'admin' };
    if (validHere) return { c: '✓', cls: 'cell-ok', level: 'valid' };
    return { c: '·', cls: 'cell-none', level: '' };
  }

  function worksOnFor(e, hosts) {
    if (!e.user || (e.type !== 'PW' && e.type !== 'NT')) return [];
    var out = [];
    hosts.forEach(function (h) { var s = cellStatus(e, h); if (s.level) out.push({ ip: h.ip, hostname: h.hostname || '', level: s.level }); });
    return out;
  }

  // Which flag's required access level this credential provided, from the hosts it works on. Local needs
  // a valid login; root needs admin. Honest: "had the access this flag needed on this host", derived.
  function unlockedFor(e, hosts) {
    var out = [];
    (e.worksOn || []).forEach(function (w) {
      var f = OBOL.store.factSetForTarget(w.ip);
      var root = (f.values('objective.root_flag') || [])[0];
      var local = (f.values('objective.local_flag') || [])[0] || (f.values('objective.flag') || [])[0];
      if (root && root.flag && w.level === 'admin') out.push({ host: w.hostname || w.ip, slot: 'root', flag: root.flag });
      if (local && local.flag) out.push({ host: w.hostname || w.ip, slot: 'local', flag: local.flag });
    });
    return out;
  }

  function uniqSort(arr) {
    var s = {}, o = [];
    arr.forEach(function (x) { x = String(x == null ? '' : x).trim(); if (x && !s[x]) { s[x] = 1; o.push(x); } });
    return o.sort(function (a, b) { return a.toLowerCase() < b.toLowerCase() ? -1 : 1; });
  }
  function isRealUser(u) { return u && u.charAt(0) !== '('; }

  function buildLists(entries) {
    var users = [], pws = [], ntlm = [], asrep = [], tgs = [], combos = [];
    entries.forEach(function (e) {
      if (isRealUser(e.user)) users.push(e.user);
      if (e.secret) pws.push(e.secret);
      if (e.nthash && isRealUser(e.user)) ntlm.push(e.user + ':' + e.nthash);
      if (e.secret && isRealUser(e.user)) combos.push(e.user + ':' + e.secret);
      if (e.type === 'AS-REP' && e.krbhash) asrep.push(e.krbhash);
      if (e.type === 'TGS' && e.krbhash) tgs.push(e.krbhash);
    });
    return {
      users: uniqSort(users), passwords: uniqSort(pws), ntlm: uniqSort(ntlm),
      asrep: uniqSort(asrep), kerberoast: uniqSort(tgs), combos: uniqSort(combos),
    };
  }

  // The full ledger: every credential-ish thing, deduped, enriched with worksOn/status/unlocked.
  function buildVault() {
    var eng = OBOL.store.active() || {};
    var fs = OBOL.store.factSet();
    var hosts = eng.targets || [];
    var facts = (fs.facts || []).filter(function (f) { return f.state === 'supported'; });
    var entries = [], seen = {};
    function add(e) {
      e.user = (e.user || '').trim();
      if (!e.user && !e.secret && !e.nthash && !e.krbhash) return;
      var k = e.user.toLowerCase() + '|' + (e.domain || '').toLowerCase() + '|' + (e.secret || e.nthash || e.krbhash || '') + '|' + (e.type || '');
      if (seen[k]) return; seen[k] = 1;
      entries.push(e);
    }
    // 1) proven + logged creds (plaintext / NT)
    (OBOL.creds.gather(eng, fs) || []).forEach(function (c) {
      add({ user: c.user, domain: c.domain, secret: c.secret || '', nthash: c.nthash || '',
        type: (c.nthash && !c.secret) ? 'NT' : 'PW', from: hostFromScope(c.scope), src: c.source || '' });
    });
    // 2) NT hashes (secretsdump / SAM entries) — pass-the-hash usable
    facts.filter(function (f) { return f.kind === 'hash.ntlm'; }).forEach(function (f) {
      ((f.value || {}).entries || []).forEach(function (e) {
        if (!e.user) return;
        add({ user: e.user, domain: e.domain || '', secret: '', nthash: e.nthash || '', type: 'NT', from: hostFromScope(f.scope), src: 'dump' });
      });
    });
    // 3) AS-REP / Kerberoast — crackable
    facts.filter(function (f) { return f.kind === 'hash.asrep'; }).forEach(function (f) {
      ((f.value || {}).hashes || []).forEach(function (h) { add({ user: asrepUser(h) || '(as-rep)', domain: '', krbhash: h, type: 'AS-REP', from: '', src: 'roast' }); });
    });
    facts.filter(function (f) { return f.kind === 'hash.tgs'; }).forEach(function (f) {
      ((f.value || {}).hashes || []).forEach(function (h) { add({ user: tgsUser(h) || '(tgs)', domain: '', krbhash: h, type: 'TGS', from: '', src: 'roast' }); });
    });
    // 4) krbtgt (golden-ticket material)
    facts.filter(function (f) { return f.kind === 'hash.krbtgt'; }).forEach(function (f) {
      if ((f.value || {}).nthash) add({ user: 'krbtgt', domain: '', nthash: f.value.nthash, type: 'KRBTGT', from: hostFromScope(f.scope), src: 'dump' });
    });
    // 5) candidates that carry a real secret (machine account, GPP)
    facts.filter(function (f) { return f.kind === 'credential.candidate'; }).forEach(function (f) {
      var v = f.value || {};
      if (v.kind === 'machine_account' && v.user) add({ user: v.user, domain: v.domain || '', secret: v.password || '', type: 'PW', from: hostFromScope(f.scope), src: 'addcomputer' });
      if (v.kind === 'gpp_cpassword') (v.values || []).forEach(function (pw) { add({ user: v.user || '(gpp)', domain: v.domain || '', secret: pw, type: 'PW', from: hostFromScope(f.scope), src: 'gpp' }); });
    });
    // 6) enumerated usernames with no secret yet
    var userSeen = {}; entries.forEach(function (e) { if (e.user) userSeen[e.user.toLowerCase()] = 1; });
    facts.filter(function (f) { return f.kind === 'ad.user_list'; }).forEach(function (f) {
      ((f.value || {}).users || []).forEach(function (u) {
        var lu = String(u || '').toLowerCase();
        if (u && !userSeen[lu]) { userSeen[lu] = 1; add({ user: u, domain: '', type: 'USER', from: '', src: 'enum' }); }
      });
    });

    entries.forEach(function (e) {
      e.worksOn = worksOnFor(e, hosts);
      e.status = e.type === 'USER' ? 'user'
        : (e.type === 'AS-REP' || e.type === 'TGS' || e.type === 'KRBTGT') ? 'crack'
          : (e.worksOn.length ? 'working' : 'found');
      e.unlocked = unlockedFor(e, hosts);
    });
    return { entries: entries, lists: buildLists(entries), hosts: hosts };
  }

  // ---- rendering ----
  var LIST_META = [
    ['users', 'Usernames', 'users.txt'], ['passwords', 'Passwords', 'passwords.txt'],
    ['ntlm', 'NT Hashes', 'ntlm.txt'], ['asrep', 'AS-REP', 'asrep.hashes'],
    ['kerberoast', 'Kerberoast', 'kerberoast.hashes'], ['combos', 'Combos', 'combos.txt'],
  ];
  function listsStrip(lists) {
    var chips = LIST_META.filter(function (m) { return (lists[m[0]] || []).length; }).map(function (m) {
      var n = lists[m[0]].length;
      return '<button type="button" class="cv-list-chip" data-list="' + m[0] + '" aria-expanded="false">'
        + '<span class="cv-list-k">' + esc(m[1]) + '</span><span class="cv-list-n">' + n + '</span></button>';
    }).join('');
    if (!chips) return '';
    return '<div class="cv-lists"><div class="cv-lists-h">Lists, as you go</div><div class="cv-lists-row">' + chips + '</div>'
      + '<div class="cv-list-panel" id="cv-list-panel" hidden></div></div>';
  }
  function listPanelHtml(key, lists) {
    var meta = LIST_META.filter(function (m) { return m[0] === key; })[0]; if (!meta) return '';
    var items = lists[key] || [];
    var joined = items.join('\n');
    var workdir = ((OBOL.store.active() || {}).params || {}).workdir || '';
    var dir = (workdir && workdir !== '.') ? workdir.replace(/\/+$/, '') + '/loot' : 'loot';
    var fileCmd = 'cat > ' + dir + '/' + meta[2] + " <<'EOF'\n" + joined + '\nEOF';
    return '<div class="cv-list-panel-in"><div class="cv-list-panel-h"><span>' + esc(meta[1]) + ' · ' + items.length + '</span>'
      + '<span class="cv-list-acts"><button type="button" class="cv-mini" data-copyval="' + attr(joined) + '">Copy List</button>'
      + '<button type="button" class="cv-mini" data-copyval="' + attr(fileCmd) + '">Copy As ' + esc(meta[2]) + '</button></span></div>'
      + '<pre class="cv-list-pre">' + esc(joined) + '</pre></div>';
  }

  function flagChip(u) {
    return '<span class="cv-flag"><span class="cv-flag-slot ' + esc(u.slot) + '">' + OBOL.ic('flag') + ' ' + esc(u.slot) + '</span> '
      + esc(u.host) + ' <code class="cv-copy" data-copyval="' + attr(u.flag) + '" title="Copy flag">' + esc(u.flag.length > 20 ? u.flag.slice(0, 18) + '…' : u.flag) + '</code></span>';
  }
  function secretCell(e) {
    if (e.secret) return '<code class="cv-copy" data-copyval="' + attr(e.secret) + '" title="Copy password">' + esc(e.secret) + '</code>';
    if (e.nthash) return '<code class="cv-copy" data-copyval="' + attr(e.nthash) + '" title="Copy NT hash">' + esc(e.nthash) + '</code>';
    if (e.krbhash) return '<code class="cv-copy cv-krb" data-copyval="' + attr(e.krbhash) + '" title="Copy hash">' + esc(e.krbhash.length > 42 ? e.krbhash.slice(0, 40) + '…' : e.krbhash) + '</code>';
    return '<span class="cv-none">no secret yet</span>';
  }
  function worksCell(e) {
    if (e.type === 'USER') return '<span class="cv-none">—</span>';
    if (!e.worksOn.length) return '<span class="cv-none">untested</span>';
    return e.worksOn.map(function (w) {
      return '<span class="cv-host ' + (w.level === 'admin' ? 'adm' : 'ok') + '">' + esc(w.hostname || w.ip) + (w.level === 'admin' ? ' ADM' : '') + '</span>';
    }).join(' ');
  }
  function loadBtn(e, i) {
    if (e.type === 'AS-REP' || e.type === 'TGS') return '<a class="cv-load crack" href="#/workbench/hash">Crack →</a>';
    return '<button type="button" class="cv-load" data-load="' + i + '">Load</button>';
  }

  var GROUPS = [
    ['working', 'Working'], ['found', 'Found, Untested'], ['crack', 'To Crack'], ['user', 'Usernames Seen'],
  ];
  function row(e, i) {
    var ident = '<span class="cv-user">' + esc(e.user || '(unknown)') + '</span>'
      + (e.domain ? '<span class="cv-dom">@' + esc(e.domain) + '</span>' : '');
    var combo = (isRealUser(e.user) && (e.secret || e.nthash)) ? '<button type="button" class="cv-chip" data-copyval="'
      + attr(e.user + ':' + (e.secret || e.nthash)) + '" title="Copy user:secret">user:secret</button>' : '';
    return '<tr>'
      + '<td class="cv-id">' + ident + combo + '</td>'
      + '<td class="cv-sec">' + secretCell(e) + '</td>'
      + '<td><span class="cv-type cv-type-' + esc(e.type.toLowerCase().replace(/[^a-z]/g, '')) + '">' + esc(e.type) + '</span></td>'
      + '<td class="cv-from">' + (e.from ? esc(e.from) : '<span class="cv-none">' + (e.src === 'logged' ? 'by hand' : '—') + '</span>') + '</td>'
      + '<td class="cv-works">' + worksCell(e) + '</td>'
      + '<td class="cv-unlocked">' + (e.unlocked.length ? e.unlocked.map(flagChip).join(' ') : '<span class="cv-none">—</span>') + '</td>'
      + '<td class="cv-act">' + loadBtn(e, i) + '</td>'
      + '</tr>';
  }

  function matrixHtml(entries, hosts) {
    var creds = entries.filter(function (e) { return e.type === 'PW' || e.type === 'NT'; });
    if (!creds.length || !hosts.length) return '';
    var head = '<th class="cm-corner">cred \\ host</th>' + hosts.map(function (h) {
      return '<th class="cm-host"><button class="cm-hostbtn" data-host="' + esc(h.ip) + '">' + esc(h.hostname || h.ip) + '</button></th>';
    }).join('');
    var rows = creds.map(function (c) {
      var cells = hosts.map(function (h) {
        var s = cellStatus(c, h);
        return '<td class="cm-cell ' + s.cls + '"><button class="cm-cellbtn ' + s.cls + '" data-load-cred="' + c._i + '" data-host="' + esc(h.ip) + '">' + s.c + '</button></td>';
      }).join('');
      return '<tr><th class="cm-cred"><button class="cm-credbtn" data-load-cred="' + c._i + '"><span class="cm-user">' + esc(c.user) + '</span><span class="cm-type">' + esc(c.type) + '</span></button></th>' + cells + '</tr>';
    }).join('');
    return '<details class="cv-matrix"><summary>Reuse Matrix (cred × host)</summary>'
      + '<div class="cm-scroll"><table class="cm-table"><thead><tr>' + head + '</tr></thead><tbody>' + rows + '</tbody></table></div></details>';
  }

  function render() {
    var vault = buildVault();
    vault.entries.forEach(function (e, i) { e._i = i; });
    render._entries = vault.entries;
    render._lists = vault.lists;
    if (!vault.entries.length) {
      return '<section class="creds-route"><h1 class="route-h1">Credentials</h1>'
        + '<p class="route-sub">The engagement\'s credential ledger. Nothing captured yet, add a credential in the sidebar params, or paste tool output that proves one, dumps hashes, or enumerates users on Evidence, and everything collects here.</p></section>';
    }
    var byGroup = {};
    vault.entries.forEach(function (e) { (byGroup[e.status] = byGroup[e.status] || []).push(e); });
    var tables = GROUPS.filter(function (g) { return byGroup[g[0]] && byGroup[g[0]].length; }).map(function (g) {
      var list = byGroup[g[0]];
      var head = g[0] === 'user'
        ? '<tr><th>User</th><th>Type</th><th>From</th><th></th></tr>'
        : '<tr><th>Identity</th><th>Secret</th><th>Type</th><th>From</th><th>Works On</th><th>Unlocked</th><th></th></tr>';
      var body = list.map(function (e) {
        if (g[0] === 'user') {
          return '<tr><td class="cv-id"><span class="cv-user">' + esc(e.user) + '</span></td>'
            + '<td><span class="cv-type cv-type-user">USER</span></td><td class="cv-from"><span class="cv-none">—</span></td>'
            + '<td class="cv-act"><button type="button" class="cv-load" data-load="' + e._i + '">Load User</button></td></tr>';
        }
        return row(e, e._i);
      }).join('');
      return '<div class="cv-group"><h2 class="cv-group-h cv-g-' + g[0] + '">' + esc(g[1]) + '<span class="cv-group-n">' + list.length + '</span></h2>'
        + '<div class="cv-tablewrap"><table class="cv-table cv-table-' + g[0] + '"><thead>' + head + '</thead><tbody>' + body + '</tbody></table></div></div>';
    }).join('');

    return '<section class="creds-route"><h1 class="route-h1">Credentials</h1>'
      + '<p class="route-sub">Every credential of every kind obol has seen this engagement: its secret, where it came from, which hosts it works on, and which flag its access unlocked. Click a secret or flag to copy it, <strong>Load</strong> arms the whole console with any credential.</p>'
      + listsStrip(vault.lists)
      + tables
      + matrixHtml(vault.entries, vault.hosts)
      + '</section>';
  }

  function loadEntry(e) {
    if (!e) return;
    OBOL.store.update(function (eng) {
      eng.params = eng.params || {};
      eng.params.username = e.user || '';
      if (e.domain) eng.params.domain = e.domain;
      // plaintext fills password (and clears a stale hash); an NT hash fills nthash for pass-the-hash.
      if (e.secret) { eng.params.password = e.secret; eng.params.nthash = ''; }
      else if (e.nthash) { eng.params.nthash = e.nthash; eng.params.password = ''; }
    }, 'params');
    if (OBOL.app && OBOL.app.renderSidebar) OBOL.app.renderSidebar();
    U.toast('Console armed with ' + (e.user || 'credential'));
  }

  function mounted(ctx) {
    var mount = ctx.mount;
    var entries = render._entries || [], lists = render._lists || {};
    // copy any value
    U.on(mount, 'click', '[data-copyval]', function (e, t) {
      U.copy(t.getAttribute('data-copyval')).then(function (ok) { U.toast(ok ? 'Copied' : 'Copy failed', ok ? '' : 'err'); });
    });
    // expand / collapse a list panel
    U.on(mount, 'click', '.cv-list-chip', function (e, t) {
      var key = t.getAttribute('data-list');
      var panel = mount.querySelector('#cv-list-panel');
      var open = t.getAttribute('aria-expanded') === 'true';
      mount.querySelectorAll('.cv-list-chip').forEach(function (c) { c.setAttribute('aria-expanded', 'false'); });
      if (open) { panel.hidden = true; panel.innerHTML = ''; return; }
      t.setAttribute('aria-expanded', 'true');
      panel.innerHTML = listPanelHtml(key, lists);
      panel.hidden = false;
    });
    // Load any credential into the console
    U.on(mount, 'click', '[data-load]', function (e, t) { loadEntry(entries[+t.getAttribute('data-load')]); });
    U.on(mount, 'click', '[data-load-cred]', function (e, t) {
      loadEntry(entries[+t.getAttribute('data-load-cred')]);
      var ip = t.getAttribute('data-host');
      if (ip) OBOL.store.update(function (eng) { eng.params = eng.params || {}; eng.params.target = ip; }, 'params');
    });
    U.on(mount, 'click', '.cm-hostbtn', function (e, t) {
      OBOL.store.update(function (eng) { eng.params = eng.params || {}; eng.params.target = t.getAttribute('data-host'); }, 'params');
      if (OBOL.app && OBOL.app.renderSidebar) OBOL.app.renderSidebar();
      U.toast('Target → ' + t.getAttribute('data-host'));
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.creds = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
