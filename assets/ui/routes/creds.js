/*!
 * obol ui — routes/creds.js — the engagement's credential ledger, organized BY HOST.
 * The one place every credential of every kind obol has seen lives. Working and found creds are grouped
 * under the host they work on / were collected from; domain-roasted hashes to crack and bare enumerated
 * usernames get their own sections. For each cred: its secret (shown + copy), type, where it came from,
 * and which flag its access unlocked. A one-click Load arms the whole console with ANY credential (the
 * nav dropdown stays proven-only). Plus always-visible, copyable per-type lists (usernames, passwords,
 * NT hashes, AS-REP, Kerberoast, combos) you can copy or write to loot/. Derived from the fact ledger.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }
  function attr(s) { return U.attr(s); }

  function asrepUser(h) { var m = /\$krb5asrep\$(?:\d+\$)?([^@*$\s:]+)@/i.exec(h || ''); return m ? m[1] : ''; }
  function tgsUser(h) { var m = /\$krb5tgs\$(?:\d+\$)?\*([^$*\s]+)\$/i.exec(h || ''); return m ? m[1] : ''; }
  function hostFromScope(scope) { return String(scope || '').indexOf('host:') === 0 ? scope.slice(5) : ''; }
  function domFromScope(scope) { return String(scope || '').indexOf('domain:') === 0 ? scope.slice(7) : ''; }
  function isRealUser(u) { return u && u.charAt(0) !== '('; }
  // machine / service / built-in accounts, folded away so a host's human accounts read clean.
  function isMachineAccount(u) {
    u = String(u || ''); var lu = u.toLowerCase();
    return /\$$/.test(u) || /^sm_/i.test(u) || /^\$/.test(u) || /^healthmailbox/i.test(u)
      || lu === 'guest' || lu === 'defaultaccount' || lu === 'krbtgt';
  }

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
    if (!e.user || (e.type !== 'PW' && e.type !== 'NT' && e.type !== 'KRBTGT')) return [];
    var out = [];
    hosts.forEach(function (h) { var s = cellStatus(e, h); if (s.level) out.push({ ip: h.ip, hostname: h.hostname || '', level: s.level }); });
    return out;
  }
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
    return { users: uniqSort(users), passwords: uniqSort(pws), ntlm: uniqSort(ntlm), asrep: uniqSort(asrep), kerberoast: uniqSort(tgs), combos: uniqSort(combos) };
  }

  function buildVault() {
    var eng = OBOL.store.active() || {};
    var fs = OBOL.store.factSet();
    var hosts = eng.targets || [];
    var hostMap = {}; hosts.forEach(function (h) { hostMap[h.ip] = h.hostname || h.ip; });
    var facts = (fs.facts || []).filter(function (f) { return f.state === 'supported'; });
    var entries = [], seen = {};
    function add(e, scope) {
      e.user = (e.user || '').trim();
      if (!e.user && !e.secret && !e.nthash && !e.krbhash) return;
      // Kerberos hashes dedupe by (type, user): the salt/nonce differs per capture, but you only crack
      // the account once, so two AS-REPs for the same user are one line here.
      var isKrb = e.type === 'AS-REP' || e.type === 'TGS';
      var k = isKrb ? (e.type + '|' + e.user.toLowerCase())
        : (e.user.toLowerCase() + '|' + (e.domain || '').toLowerCase() + '|' + (e.secret || e.nthash || '') + '|' + e.type);
      if (seen[k]) return; seen[k] = 1;
      e.scopeHost = hostFromScope(scope);
      e.scopeDom = domFromScope(scope);
      entries.push(e);
    }
    (OBOL.creds.gather(eng, fs) || []).forEach(function (c) {
      add({ user: c.user, domain: c.domain, secret: c.secret || '', nthash: c.nthash || '', type: (c.nthash && !c.secret) ? 'NT' : 'PW', src: c.source || '' }, c.scope);
    });
    facts.filter(function (f) { return f.kind === 'hash.ntlm'; }).forEach(function (f) {
      ((f.value || {}).entries || []).forEach(function (e) { if (e.user) add({ user: e.user, domain: e.domain || '', secret: '', nthash: e.nthash || '', type: 'NT', src: 'dump' }, f.scope); });
    });
    facts.filter(function (f) { return f.kind === 'hash.asrep'; }).forEach(function (f) {
      ((f.value || {}).hashes || []).forEach(function (h) { add({ user: asrepUser(h) || '(as-rep)', domain: '', krbhash: h, type: 'AS-REP', src: 'roast' }, f.scope); });
    });
    facts.filter(function (f) { return f.kind === 'hash.tgs'; }).forEach(function (f) {
      ((f.value || {}).hashes || []).forEach(function (h) { add({ user: tgsUser(h) || '(tgs)', domain: '', krbhash: h, type: 'TGS', src: 'roast' }, f.scope); });
    });
    facts.filter(function (f) { return f.kind === 'hash.krbtgt'; }).forEach(function (f) {
      if ((f.value || {}).nthash) add({ user: 'krbtgt', domain: '', nthash: f.value.nthash, type: 'KRBTGT', src: 'dump' }, f.scope);
    });
    facts.filter(function (f) { return f.kind === 'credential.candidate'; }).forEach(function (f) {
      var v = f.value || {};
      if (v.kind === 'machine_account' && v.user) add({ user: v.user, domain: v.domain || '', secret: v.password || '', type: 'PW', src: 'addcomputer' }, f.scope);
      if (v.kind === 'gpp_cpassword') (v.values || []).forEach(function (pw) { add({ user: v.user || '(gpp)', domain: v.domain || '', secret: pw, type: 'PW', src: 'gpp' }, f.scope); });
    });
    var userSeen = {}; entries.forEach(function (e) { if (e.user) userSeen[e.user.toLowerCase()] = 1; });
    facts.filter(function (f) { return f.kind === 'ad.user_list'; }).forEach(function (f) {
      ((f.value || {}).users || []).forEach(function (u) {
        var lu = String(u || '').toLowerCase();
        if (u && !userSeen[lu]) { userSeen[lu] = 1; add({ user: u, domain: '', type: 'USER', src: 'enum' }, f.scope); }
      });
    });

    // users we hold a plaintext password for — their Kerberos hashes are already cracked, so they drop
    // out of "To Crack" (honest: derived from the ledger, since the plaintext is the crack result).
    var cracked = {};
    entries.forEach(function (e) { if (e.secret && isRealUser(e.user)) cracked[e.user.toLowerCase()] = 1; });

    var out = [];
    entries.forEach(function (e) {
      if ((e.type === 'AS-REP' || e.type === 'TGS') && cracked[e.user.toLowerCase()]) return; // already cracked
      e.worksOn = worksOnFor(e, hosts);
      e.status = e.type === 'USER' ? 'user'
        : (e.type === 'AS-REP' || e.type === 'TGS') ? 'crack'
          : (e.worksOn.length ? 'working' : 'found');
      e.unlocked = unlockedFor(e, hosts);
      e.from = e.scopeHost ? (hostMap[e.scopeHost] || e.scopeHost) : (e.scopeDom ? e.scopeDom : (e.src === 'logged' ? 'by hand' : ''));
      out.push(e);
    });
    return { entries: out, lists: buildLists(out), hosts: hosts, hostMap: hostMap };
  }

  // ---- lists (always visible + directly copyable) ----
  var LIST_META = [
    ['users', 'Usernames', 'users.txt'], ['passwords', 'Passwords', 'passwords.txt'],
    ['ntlm', 'NT Hashes', 'ntlm.txt'], ['asrep', 'AS-REP', 'asrep.hashes'],
    ['kerberoast', 'Kerberoast', 'kerberoast.hashes'], ['combos', 'Combos', 'combos.txt'],
  ];
  function lootDir() {
    var wd = ((OBOL.store.active() || {}).params || {}).workdir || '';
    return (wd && wd !== '.') ? wd.replace(/\/+$/, '') + '/loot' : 'loot';
  }
  function listsBlock(lists) {
    var rows = LIST_META.filter(function (m) { return (lists[m[0]] || []).length; }).map(function (m) {
      var items = lists[m[0]], joined = items.join('\n');
      var fileCmd = 'cat > ' + lootDir() + '/' + m[2] + " <<'EOF'\n" + joined + '\nEOF';
      var preview = items.slice(0, 4).join(', ') + (items.length > 4 ? ', …' : '');
      return '<div class="cv-list-row">'
        + '<div class="cv-list-main"><span class="cv-list-k">' + esc(m[1]) + '</span><span class="cv-list-n">' + items.length + '</span>'
        + '<span class="cv-list-prev">' + esc(preview) + '</span></div>'
        + '<div class="cv-list-acts"><button type="button" class="cv-mini" data-copyval="' + attr(joined) + '">Copy</button>'
        + '<button type="button" class="cv-mini cv-mini-ghost" data-copyval="' + attr(fileCmd) + '" title="Copy a heredoc that writes it to ' + esc(lootDir()) + '/' + esc(m[2]) + '">Copy As File</button></div></div>';
    }).join('');
    if (!rows) return '';
    return '<div class="cv-lists"><div class="cv-lists-h">Copyable Lists<span class="cv-lists-sub">one click to the clipboard, grows as you go</span></div>' + rows + '</div>';
  }

  // ---- a credential row ----
  function flagChip(u) {
    return '<span class="cv-flag"><span class="cv-flag-slot ' + esc(u.slot) + '">' + OBOL.ic('flag') + ' ' + esc(u.slot) + '</span> '
      + '<code class="cv-copy" data-copyval="' + attr(u.flag) + '" title="Copy flag value">' + esc(u.flag.length > 20 ? u.flag.slice(0, 18) + '…' : u.flag) + '</code></span>';
  }
  function secretCell(e) {
    if (e.secret) return '<code class="cv-copy" data-copyval="' + attr(e.secret) + '" title="Copy password">' + esc(e.secret) + '</code>';
    if (e.nthash) return '<code class="cv-copy" data-copyval="' + attr(e.nthash) + '" title="Copy NT hash">' + esc(e.nthash) + '</code>';
    if (e.krbhash) return '<code class="cv-copy cv-krb" data-copyval="' + attr(e.krbhash) + '" title="Copy hash">' + esc(e.krbhash.length > 46 ? e.krbhash.slice(0, 44) + '…' : e.krbhash) + '</code>';
    return '<span class="cv-none">no secret yet</span>';
  }
  function typeBadge(t) { return '<span class="cv-type cv-type-' + esc(t.toLowerCase().replace(/[^a-z]/g, '')) + '">' + esc(t) + '</span>'; }
  function loadBtn(e) {
    if (e.type === 'AS-REP' || e.type === 'TGS') return '<a class="cv-load crack" href="#/workbench/hashid">Crack →</a>';
    return '<button type="button" class="cv-load" data-load="' + e._i + '">Load</button>';
  }
  function placeBadge(e) {
    if (e._place === 'admin') return '<span class="cv-place adm">Admin here</span>';
    if (e._place === 'valid') return '<span class="cv-place ok">Valid here</span>';
    if (e._place === 'found') return '<span class="cv-place found">Collected here, untested</span>';
    return '';
  }
  function hostRow(e, thisIp) {
    var ident = '<span class="cv-user">' + esc(e.user || '(unknown)') + '</span>' + (e.domain ? '<span class="cv-dom">@' + esc(e.domain) + '</span>' : '');
    var combo = (isRealUser(e.user) && (e.secret || e.nthash)) ? '<button type="button" class="cv-chip" data-copyval="' + attr(e.user + ':' + (e.secret || e.nthash)) + '" title="Copy user:secret">user:secret</button>' : '';
    var fromNote = (e.scopeHost && e.scopeHost !== thisIp && e._place !== 'found') ? '<div class="cv-fromnote">from ' + esc(e.from) + '</div>' : '';
    return '<tr>'
      + '<td class="cv-id">' + ident + combo + fromNote + '</td>'
      + '<td class="cv-sec">' + secretCell(e) + '</td>'
      + '<td>' + typeBadge(e.type) + '</td>'
      + '<td>' + placeBadge(e) + '</td>'
      + '<td class="cv-unlocked">' + (e.unlocked.length ? e.unlocked.map(flagChip).join(' ') : '<span class="cv-none">—</span>') + '</td>'
      + '<td class="cv-act">' + loadBtn(e) + '</td></tr>';
  }
  function hostTable(rows, thisIp) {
    var human = rows.filter(function (e) { return !isMachineAccount(e.user); });
    var machine = rows.filter(function (e) { return isMachineAccount(e.user); });
    var head = '<tr><th>Identity</th><th>Secret</th><th>Type</th><th>On This Host</th><th>Unlocked</th><th></th></tr>';
    var body = human.map(function (e) { return hostRow(e, thisIp); }).join('')
      || '<tr><td colspan="6" class="cv-none">Only machine / service accounts here.</td></tr>';
    var mach = machine.length
      ? '<details class="cv-machine"><summary>Machine &amp; Service Accounts (' + machine.length + ')</summary>'
        + '<div class="cv-tablewrap"><table class="cv-table"><thead>' + head + '</thead><tbody>'
        + machine.map(function (e) { return hostRow(e, thisIp); }).join('') + '</tbody></table></div></details>'
      : '';
    return '<div class="cv-tablewrap"><table class="cv-table"><thead>' + head + '</thead><tbody>' + body + '</tbody></table></div>' + mach;
  }

  function render() {
    var vault = buildVault();
    vault.entries.forEach(function (e, i) { e._i = i; });
    render._entries = vault.entries;
    if (!vault.entries.length) {
      return '<section class="creds-route"><h1 class="route-h1">Credentials</h1>'
        + '<p class="route-sub">The engagement\'s credential ledger, grouped by host. Nothing captured yet, add a credential in the sidebar params, or paste tool output that proves one, dumps hashes, or enumerates users on Evidence, and everything collects here.</p></section>';
    }
    // group working / found under a host (works-on hosts, else the host it was collected from)
    var byHost = {}; vault.hosts.forEach(function (h) { byHost[h.ip] = []; });
    var crack = [], users = [], other = [];
    vault.entries.forEach(function (e) {
      if (e.status === 'user') { users.push(e); return; }
      if (e.status === 'crack') { crack.push(e); return; }
      if (e.worksOn && e.worksOn.length) {
        e.worksOn.forEach(function (w) { if (byHost[w.ip]) byHost[w.ip].push(Object.assign({}, e, { _place: w.level })); else other.push(e); });
      } else if (e.scopeHost && byHost[e.scopeHost]) {
        byHost[e.scopeHost].push(Object.assign({}, e, { _place: 'found' }));
      } else { other.push(e); }
    });

    function hostCard(h) {
      var rows = byHost[h.ip]; if (!rows || !rows.length) return '';
      var owned = rows.some(function (e) { return e._place === 'admin'; });
      var valid = rows.some(function (e) { return e._place === 'valid'; });
      var badge = owned ? '<span class="cv-hbadge adm">Owned</span>' : valid ? '<span class="cv-hbadge ok">Access</span>' : '<span class="cv-hbadge found">Loot</span>';
      return '<div class="cv-host"><div class="cv-host-h"><span class="cv-host-name">' + esc(h.hostname || h.ip) + '</span>'
        + (h.hostname ? '<span class="cv-host-ip">' + esc(h.ip) + '</span>' : '') + badge
        + '<span class="cv-host-n">' + rows.length + ' cred' + (rows.length === 1 ? '' : 's') + '</span></div>'
        + hostTable(rows, h.ip) + '</div>';
    }
    var hostCards = vault.hosts.map(hostCard).join('');

    var crackSec = crack.length ? ('<div class="cv-sec-block"><h2 class="cv-sec-h cv-s-crack">To Crack<span class="cv-sec-n">' + crack.length + '</span></h2>'
      + '<p class="cv-sec-sub">Roasted hashes that need cracking (they leave this list once you hold the plaintext). <a href="#/workbench/hashid">Open the cracker →</a></p>'
      + '<div class="cv-tablewrap"><table class="cv-table"><thead><tr><th>Identity</th><th>Hash</th><th>Type</th><th>From</th><th></th></tr></thead><tbody>'
      + crack.map(function (e) {
        return '<tr><td class="cv-id"><span class="cv-user">' + esc(e.user) + '</span></td><td class="cv-sec">' + secretCell(e) + '</td>'
          + '<td>' + typeBadge(e.type) + '</td><td class="cv-from">' + (e.from ? esc(e.from) : '<span class="cv-none">—</span>') + '</td>'
          + '<td class="cv-act">' + loadBtn(e) + '</td></tr>';
      }).join('') + '</tbody></table></div></div>') : '';

    var otherSec = other.length ? ('<div class="cv-sec-block"><h2 class="cv-sec-h cv-s-found">Not Tied To A Host<span class="cv-sec-n">' + other.length + '</span></h2>'
      + '<div class="cv-tablewrap"><table class="cv-table"><thead><tr><th>Identity</th><th>Secret</th><th>Type</th><th>From</th><th>Unlocked</th><th></th></tr></thead><tbody>'
      + other.map(function (e) {
        return '<tr><td class="cv-id"><span class="cv-user">' + esc(e.user) + '</span>' + (e.domain ? '<span class="cv-dom">@' + esc(e.domain) + '</span>' : '') + '</td>'
          + '<td class="cv-sec">' + secretCell(e) + '</td><td>' + typeBadge(e.type) + '</td><td class="cv-from">' + (e.from ? esc(e.from) : '<span class="cv-none">—</span>') + '</td>'
          + '<td class="cv-unlocked">' + (e.unlocked.length ? e.unlocked.map(flagChip).join(' ') : '<span class="cv-none">—</span>') + '</td>'
          + '<td class="cv-act">' + loadBtn(e) + '</td></tr>';
      }).join('') + '</tbody></table></div></div>') : '';

    var userSec = users.length ? ('<div class="cv-sec-block"><h2 class="cv-sec-h cv-s-user">Usernames Seen<span class="cv-sec-n">' + users.length + '</span></h2>'
      + '<p class="cv-sec-sub">Accounts enumerated with no secret yet. Grab the full list from Usernames above, or Load one to target it.</p>'
      + '<div class="cv-userchips">' + users.map(function (e) {
        return '<span class="cv-userchip"><button type="button" class="cv-copy" data-copyval="' + attr(e.user) + '" title="Copy username">' + esc(e.user) + '</button>'
          + '<button type="button" class="cv-userload" data-load="' + e._i + '" title="Target this user">use</button></span>';
      }).join('') + '</div></div>') : '';

    return '<section class="creds-route"><h1 class="route-h1">Credentials</h1>'
      + '<p class="route-sub">Every credential of every kind obol has seen this engagement, grouped by the host it works on or came from. Click a secret or flag to copy it. <strong>Load</strong> arms the whole console with any credential.</p>'
      + listsBlock(vault.lists)
      + (hostCards || '')
      + crackSec + otherSec + userSec
      + '</section>';
  }

  function loadEntry(e) {
    if (!e) return;
    OBOL.store.update(function (eng) {
      eng.params = eng.params || {};
      eng.params.username = e.user || '';
      if (e.domain) eng.params.domain = e.domain;
      if (e.secret) { eng.params.password = e.secret; eng.params.nthash = ''; }
      else if (e.nthash) { eng.params.nthash = e.nthash; eng.params.password = ''; }
    }, 'params');
    if (OBOL.app && OBOL.app.renderSidebar) OBOL.app.renderSidebar();
    U.toast('Console armed with ' + (e.user || 'credential'));
  }

  function mounted(ctx) {
    var mount = ctx.mount, entries = render._entries || [];
    U.on(mount, 'click', '[data-copyval]', function (e, t) {
      U.copy(t.getAttribute('data-copyval')).then(function (ok) { U.toast(ok ? 'Copied' : 'Copy failed', ok ? '' : 'err'); });
    });
    U.on(mount, 'click', '[data-load]', function (e, t) { loadEntry(entries[+t.getAttribute('data-load')]); });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.creds = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
