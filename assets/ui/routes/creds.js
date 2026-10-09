/*!
 * obol ui — routes/creds.js — the engagement's credential ledger, grouped by the host each cred was
 * found on / works on. The one place every credential of every kind obol has seen lives: working
 * creds, found-but-untested, roasted hashes to crack, krbtgt/golden-ticket material, and enumerated
 * usernames. Per cred: secret (shown + copy), type, where it came from, which flag its access unlocked,
 * a one-click Load (arms the whole console), and Cracked / Used toggles you set and obol remembers.
 * Each host group is collapsible; machine/service accounts fold away. Copyable per-type lists expand to
 * the full set, copy to the clipboard, copy as a loot/ heredoc, or get marked "created" so the file is
 * tracked in the Workspace (with its contents in the hover preview). All derived from the fact ledger.
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
  function isMachineAccount(u) {
    u = String(u || ''); var lu = u.toLowerCase();
    return /\$$/.test(u) || /^sm_/i.test(u) || /^\$/.test(u) || /^healthmailbox/i.test(u)
      || lu === 'guest' || lu === 'defaultaccount' || lu === 'krbtgt';
  }
  function credKey(e) { return [String(e.user || '').toLowerCase(), e.secret || e.nthash || e.krbhash || '', e.type].join('|'); }

  // ---- persisted per-cred marks (cracked / used) and collapse state ----
  function marks() { var e = OBOL.store.active() || {}; return (e.creds && e.creds.marks) || {}; }
  function toggleMark(key, field) {
    OBOL.store.update(function (eng) {
      eng.creds = eng.creds || {}; eng.creds.marks = eng.creds.marks || {};
      var m = eng.creds.marks[key] = eng.creds.marks[key] || {}; m[field] = !m[field];
    }, 'creds');
  }
  function openKey(id) { return 'obol.cv:' + (OBOL.store.activeId() || '') + ':' + id; }
  function isOpen(id, def) { try { var v = localStorage.getItem(openKey(id)); return v == null ? def : v === '1'; } catch (e) { return def; } }

  // Per-credential status on a host. ADMIN is only claimed when THIS user is the one proven admin
  // (an access.admin/credential.admin fact whose identity/user matches), never just because someone
  // owns the box: on HTB Forest svc-alfresco is a valid foothold you escalate FROM, not an admin.
  function cellStatus(cred, host) {
    var f = OBOL.store.factSetForTarget(host.ip);
    var u = String(cred.user || '').toLowerCase();
    if (!u) return { level: '' };
    function ident(v) { return String((v && (v.identity || v.user)) || '').toLowerCase(); }
    var adminHere = false, validHere = false;
    (f.facts || []).forEach(function (x) {
      if (x.state !== 'supported') return;
      var v = x.value || {};
      if ((x.kind === 'access.admin' || x.kind === 'access.system' || x.kind === 'access.root') && ident(v) === u) adminHere = true;
      else if (x.kind === 'credential.admin' && String(v.user || '').toLowerCase() === u) adminHere = true;
      else if ((x.kind === 'credential.available' || x.kind.indexOf('.authenticated') > 0) && String(v.user || '').toLowerCase() === u) validHere = true;
    });
    if (adminHere) return { level: 'admin' };
    if (validHere) return { level: 'valid' };
    return { level: '' };
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
    // the domain controller, if we can tell: domain-scoped dumps/roasts were collected there.
    var dcIp = '';
    hosts.forEach(function (h) { if (dcIp) return; var f = OBOL.store.factSetForTarget(h.ip); if (f.has('ad.dc_candidate') || f.has('ad.domain_known') || f.has('ad.base_dn')) dcIp = h.ip; });
    if (!dcIp && hosts.length === 1) dcIp = hosts[0].ip;
    var facts = (fs.facts || []).filter(function (f) { return f.state === 'supported'; });
    var entries = [], seen = {};
    function add(e, scope) {
      e.user = (e.user || '').trim();
      if (!e.user && !e.secret && !e.nthash && !e.krbhash) return;
      var isKrb = e.type === 'AS-REP' || e.type === 'TGS';
      var k = isKrb ? (e.type + '|' + e.user.toLowerCase())
        : (e.user.toLowerCase() + '|' + (e.domain || '').toLowerCase() + '|' + (e.secret || e.nthash || '') + '|' + e.type);
      if (seen[k]) return; seen[k] = 1;
      e.scopeHost = hostFromScope(scope); e.scopeDom = domFromScope(scope);
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
      ((f.value || {}).users || []).forEach(function (u) { var lu = String(u || '').toLowerCase(); if (u && !userSeen[lu]) { userSeen[lu] = 1; add({ user: u, domain: '', type: 'USER', src: 'enum' }, f.scope); } });
    });

    var plain = {}; entries.forEach(function (e) { if (e.secret && isRealUser(e.user)) plain[e.user.toLowerCase()] = 1; });
    var mk = marks();
    var out = [];
    entries.forEach(function (e) {
      var isKrb = e.type === 'AS-REP' || e.type === 'TGS';
      e.worksOn = worksOnFor(e, hosts);
      e.status = e.type === 'USER' ? 'user' : isKrb ? 'crack' : (e.worksOn.length ? 'working' : 'found');
      e.unlocked = unlockedFor(e, hosts);
      e.from = e.scopeHost ? (hostMap[e.scopeHost] || e.scopeHost) : (e.scopeDom || (e.src === 'logged' ? 'by hand' : ''));
      // where it was FOUND: the host scope, else the DC (domain dumps/roasts), else the domain bucket.
      e.foundIp = (e.scopeHost && hostMap[e.scopeHost]) ? e.scopeHost : (e.scopeDom ? (dcIp || '') : '');
      var m = mk[credKey(e)] || {};
      e.autoCracked = isKrb && !!plain[e.user.toLowerCase()];
      e.cracked = e.autoCracked || !!m.cracked;
      e.used = !!m.used;
      out.push(e);
    });
    return { entries: out, lists: buildLists(out), hosts: hosts, hostMap: hostMap, domain: (eng.params || {}).domain || '' };
  }

  // ---- lists ----
  var LIST_META = [
    ['users', 'Usernames', 'users.txt'], ['passwords', 'Passwords', 'passwords.txt'],
    ['ntlm', 'NT Hashes', 'ntlm.txt'], ['asrep', 'AS-REP', 'asrep.hashes'],
    ['kerberoast', 'Kerberoast', 'kerberoast.hashes'], ['combos', 'Combos', 'combos.txt'],
  ];
  function lootDir() { var wd = ((OBOL.store.active() || {}).params || {}).workdir || ''; return (wd && wd !== '.') ? wd.replace(/\/+$/, '') + '/loot' : 'loot'; }
  function listRel(file) { return 'loot/' + file; }
  function createdFile(file) {
    var added = (((OBOL.store.active() || {}).workspace || {}).overrides || {}).added || [];
    return added.some(function (a) { return a && a.path === listRel(file); });
  }
  function toggleCreated(file, text) {
    OBOL.store.update(function (eng) {
      eng.workspace = eng.workspace || {}; eng.workspace.overrides = eng.workspace.overrides || {};
      var added = eng.workspace.overrides.added = eng.workspace.overrides.added || [];
      var rel = listRel(file), i = -1;
      added.forEach(function (a, idx) { if (a && a.path === rel) i = idx; });
      if (i >= 0) added.splice(i, 1); else added.push({ path: rel, source: 'manual', at: Date.now(), content: text });
    }, 'ws');
  }
  // a neon-glass section header (the "Your Next Move" border treatment): an accent left bar, a glowing
  // label, and a one-line explanation of the section.
  function shead(label, desc) {
    return '<div class="cv-shead"><span class="cv-shead-l">' + esc(label) + '</span><span class="cv-shead-d">' + esc(desc) + '</span></div>';
  }
  function listsBlock(lists) {
    var rows = LIST_META.filter(function (m) { return (lists[m[0]] || []).length; }).map(function (m) {
      var items = lists[m[0]], joined = items.join('\n');
      var fileCmd = 'cat > ' + lootDir() + '/' + m[2] + " <<'EOF'\n" + joined + '\nEOF';
      var preview = items.slice(0, 5).join(', ') + (items.length > 5 ? ', …' : '');
      var created = createdFile(m[2]);
      return '<details class="cv-list" data-cvkey="list:' + m[0] + '"' + (isOpen('list:' + m[0], false) ? ' open' : '') + '>'
        + '<summary class="cv-list-sum"><span class="cv-list-tw"><span class="cv-list-k">' + esc(m[1]) + '</span><span class="cv-list-n">' + items.length + '</span>'
        + '<span class="cv-list-prev">' + esc(preview) + '</span></span>'
        + '<span class="cv-list-acts">'
        + '<button type="button" class="cv-mini" data-copyval="' + attr(joined) + '">Copy</button>'
        + '<button type="button" class="cv-mini cv-mini-ghost" data-copyval="' + attr(fileCmd) + '" title="Copy a heredoc that writes ' + esc(lootDir()) + '/' + esc(m[2]) + '">Copy As File</button>'
        + '<button type="button" class="cv-made' + (created ? ' on' : '') + '" data-made="' + attr(m[2]) + '" data-made-text="' + attr(joined) + '" title="Mark that you wrote this file locally, so it is tracked in your Workspace">' + (created ? '✓ In loot/' : 'Mark Created') + '</button>'
        + '</span></summary>'
        + '<pre class="cv-list-pre">' + esc(joined) + '</pre></details>';
    }).join('');
    if (!rows) return '';
    return shead('Copyable Lists', 'One click to the clipboard, grows as you go. Click a list to inspect it in full, then copy, save to loot/, or mark it written.')
      + '<div class="cv-lists">' + rows + '</div>';
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
  function statusCell(e, groupIp) {
    var here = (e.worksOn || []).filter(function (w) { return w.ip === groupIp; })[0];
    if (here) return '<span class="cv-place ' + (here.level === 'admin' ? 'adm' : 'ok') + '">' + (here.level === 'admin' ? 'Admin here' : 'Valid here') + '</span>';
    var elsewhere = (e.worksOn || []).map(function (w) { return w.hostname || w.ip; });
    if (elsewhere.length) return '<span class="cv-place ok">Works on ' + esc(elsewhere.join(', ')) + '</span>';
    if (e.type === 'AS-REP' || e.type === 'TGS') return e.cracked ? '<span class="cv-place ok">Cracked</span>' : '<span class="cv-place crack">Needs crack</span>';
    return '<span class="cv-place found">Untested</span>';
  }
  function actionsCell(e) {
    var k = credKey(e);
    var primary = (e.type === 'AS-REP' || e.type === 'TGS') && !e.cracked
      ? '<a class="cv-load crack" href="#/workbench/hashid">Crack &rarr;</a>'
      : '<button type="button" class="cv-load" data-load="' + e._i + '">Load</button>';
    var tgl = '<span class="cv-tgls">'
      + '<button type="button" class="cv-tgl' + (e.cracked ? ' on' : '') + '" data-mark="cracked" data-key="' + attr(k) + '"' + (e.autoCracked ? ' disabled title="Plaintext is known, so this is cracked"' : '') + '>Cracked</button>'
      + '<button type="button" class="cv-tgl' + (e.used ? ' on' : '') + '" data-mark="used" data-key="' + attr(k) + '">Used</button></span>';
    return primary + tgl;
  }
  function credRow(e, groupIp) {
    var ident = '<span class="cv-user">' + esc(e.user || '(unknown)') + '</span>' + (e.domain ? '<span class="cv-dom">@' + esc(e.domain) + '</span>' : '');
    var combo = (isRealUser(e.user) && (e.secret || e.nthash)) ? '<button type="button" class="cv-chip" data-copyval="' + attr(e.user + ':' + (e.secret || e.nthash)) + '" title="Copy user:secret">user:secret</button>' : '';
    var fromNote = (e.scopeHost && e.scopeHost !== groupIp) ? '<div class="cv-fromnote">from ' + esc(e.from) + '</div>' : '';
    return '<tr class="' + (e.used ? 'cv-r-used' : '') + '">'
      + '<td class="cv-id">' + ident + combo + fromNote + '</td>'
      + '<td class="cv-sec">' + secretCell(e) + '</td>'
      + '<td>' + typeBadge(e.type) + '</td>'
      + '<td>' + statusCell(e, groupIp) + '</td>'
      + '<td class="cv-unlocked">' + (e.unlocked.length ? e.unlocked.map(flagChip).join(' ') : '<span class="cv-none">—</span>') + '</td>'
      + '<td class="cv-act">' + actionsCell(e) + '</td></tr>';
  }
  function credTable(rows, groupIp) {
    var human = rows.filter(function (e) { return !isMachineAccount(e.user); });
    var machine = rows.filter(function (e) { return isMachineAccount(e.user); });
    var head = '<tr><th>Identity</th><th>Secret</th><th>Type</th><th>Status</th><th>Unlocked</th><th>Actions</th></tr>';
    var body = human.map(function (e) { return credRow(e, groupIp); }).join('')
      || '<tr><td colspan="6" class="cv-none">Only machine / service accounts here.</td></tr>';
    var mach = machine.length
      ? '<details class="cv-machine"><summary>Machine &amp; Service Accounts (' + machine.length + ')</summary>'
        + '<div class="cv-tablewrap"><table class="cv-table"><thead>' + head + '</thead><tbody>'
        + machine.map(function (e) { return credRow(e, groupIp); }).join('') + '</tbody></table></div></details>'
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
    // group every secret-bearing cred by the host it was found on (works-on host wins for placement,
    // else the host/DC it was collected from); usernames get their own section.
    var byHost = {}; vault.hosts.forEach(function (h) { byHost[h.ip] = []; });
    var domainRows = [], handRows = [], users = [];
    vault.entries.forEach(function (e) {
      if (e.status === 'user') { users.push(e); return; }
      var ip = (e.worksOn && e.worksOn[0] && byHost[e.worksOn[0].ip]) ? e.worksOn[0].ip : e.foundIp;
      if (ip && byHost[ip]) byHost[ip].push(e);
      else if (e.src === 'logged') handRows.push(e);
      else domainRows.push(e);
    });

    function group(id, title, ip, rows, badge, defOpen) {
      if (!rows.length) return '';
      var open = isOpen('g:' + id, defOpen);
      return '<details class="cv-host" data-cvkey="g:' + id + '"' + (open ? ' open' : '') + '>'
        + '<summary class="cv-host-h"><span class="cv-host-name">' + esc(title) + '</span>'
        + (ip && vault.hostMap[ip] && vault.hostMap[ip] !== title ? '' : '') + badge
        + '<span class="cv-host-n">' + rows.length + ' cred' + (rows.length === 1 ? '' : 's') + '</span></summary>'
        + credTable(rows, ip || '') + '</details>';
    }
    var hostCards = vault.hosts.map(function (h) {
      var rows = byHost[h.ip]; if (!rows.length) return '';
      // the host badge is host-LEVEL: the box is Owned if anything got admin on it, even when no single
      // credential in this list is the proven admin (e.g. admin reached via ACL abuse / DCSync).
      var hf = OBOL.store.factSetForTarget(h.ip);
      var owned = hf.has('access.admin') || hf.has('access.system') || hf.has('access.root');
      var valid = rows.some(function (e) { return (e.worksOn || []).some(function (w) { return w.ip === h.ip; }); });
      var badge = owned ? '<span class="cv-hbadge adm">Owned</span>' : valid ? '<span class="cv-hbadge ok">Access</span>' : '<span class="cv-hbadge found">Loot</span>';
      var title = (h.hostname || h.ip) + (h.hostname ? '  ' + h.ip : '');
      // default open unless it is a big loot-only pile
      var defOpen = rows.length <= 12 || owned || valid;
      return group('h:' + h.ip, title, h.ip, rows, badge, defOpen);
    }).join('');

    var domainCard = domainRows.length
      ? group('domain', 'Domain' + (vault.domain ? ' · ' + vault.domain : ''), '', domainRows, '<span class="cv-hbadge found">Collected</span>', domainRows.length <= 12)
      : '';
    var handCard = handRows.length ? group('hand', 'Added By Hand', '', handRows, '<span class="cv-hbadge found">Manual</span>', true) : '';

    var userSec = users.length ? ('<details class="cv-userbox" data-cvkey="users"' + (isOpen('users', users.length <= 24) ? ' open' : '') + '>'
      + '<summary class="cv-userbox-h">Usernames Seen<span class="cv-sec-n">' + users.length + '</span><span class="cv-userbox-sub">Enumerated accounts with no secret yet</span></summary>'
      + '<div class="cv-userchips">' + users.map(function (e) {
        return '<span class="cv-userchip"><button type="button" class="cv-copy" data-copyval="' + attr(e.user) + '" title="Copy username">' + esc(e.user) + '</button>'
          + '<button type="button" class="cv-userload" data-load="' + e._i + '" title="Target this user">use</button></span>';
      }).join('') + '</div></details>') : '';

    return '<section class="creds-route"><h1 class="route-h1">Credentials</h1>'
      + '<p class="route-sub">Every credential of every kind obol has seen this engagement, grouped by the host it works on or came from. Click a secret or flag to copy it. <strong>Load</strong> arms the whole console with any credential; <strong>Cracked</strong> / <strong>Used</strong> are yours to set and obol remembers them.</p>'
      + listsBlock(vault.lists)
      + ((hostCards || domainCard || handCard) ? shead('Credentials By Host', 'Grouped by the host each credential works on, or the host it was collected from.') : '')
      + (hostCards || '') + domainCard + handCard + userSec
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
    var mount = ctx.mount;
    // Bind the delegated handlers ONCE on the persistent #view. The route re-renders on a mark toggle,
    // and mounted() re-runs on every render; without this guard each handler would stack and fire twice
    // (e.g. Mark Created would toggle on then off, a net no-op). Handlers read render._entries fresh.
    if (!mount._cvBound) {
      mount._cvBound = true;
      U.on(mount, 'click', '[data-copyval]', function (e, t) {
        e.preventDefault(); e.stopPropagation();
        U.copy(t.getAttribute('data-copyval')).then(function (ok) { U.toast(ok ? 'Copied' : 'Copy failed', ok ? '' : 'err'); });
      });
      U.on(mount, 'click', '[data-load]', function (e, t) { e.preventDefault(); e.stopPropagation(); loadEntry((render._entries || [])[+t.getAttribute('data-load')]); });
      // mark a list written to loot/ (tracked in the Workspace, contents in its hover preview) — in place
      U.on(mount, 'click', '[data-made]', function (e, t) {
        e.preventDefault(); e.stopPropagation();
        var file = t.getAttribute('data-made');
        toggleCreated(file, t.getAttribute('data-made-text') || '');
        var on = createdFile(file);
        t.classList.toggle('on', on); t.textContent = on ? '✓ In loot/' : 'Mark Created';
        U.toast(on ? 'Tracked in Workspace, loot/' + file : 'Removed from Workspace');
      });
      // cracked / used toggles (persisted, then re-render so status/actions update)
      U.on(mount, 'click', '[data-mark]', function (e, t) {
        e.preventDefault(); e.stopPropagation();
        if (t.disabled) return;
        toggleMark(t.getAttribute('data-key'), t.getAttribute('data-mark'));
        OBOL.router.render();
      });
    }
    // remember each collapsible group / list open state per browser (toggle does not bubble); these are
    // fresh nodes every render, so bind each once by its own flag.
    Array.prototype.forEach.call(mount.querySelectorAll('details[data-cvkey]'), function (d) {
      if (d._cvToggleBound) return; d._cvToggleBound = true;
      d.addEventListener('toggle', function () { try { localStorage.setItem(openKey(d.getAttribute('data-cvkey')), d.open ? '1' : '0'); } catch (x) {} });
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.creds = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
