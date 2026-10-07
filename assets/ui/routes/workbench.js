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
    { id: 'sqli', label: 'Manual SQLi' },
    { id: 'explain', label: 'Explain Output' },
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

  // Hash Identifier.
  // Gather the hashes this engagement has already captured, so the student can identify one with a tap.
  function engagementHashes() {
    var out = [], fs;
    try { fs = OBOL.store.factSet(); } catch (e) { return out; }
    if (!fs || !fs.values) return out;
    fs.values('hash.ntlm').forEach(function (v) { if (v.nthash) out.push({ label: (v.user || 'user') + ' (NTLM)', hash: v.nthash }); });
    fs.values('hash.krbtgt').forEach(function (v) { if (v.nthash) out.push({ label: 'krbtgt (NTLM)', hash: v.nthash }); });
    fs.values('hash.asrep').forEach(function (v) { (v.hashes || []).forEach(function (h, i) { out.push({ label: 'AS-REP #' + (i + 1), hash: h }); }); });
    fs.values('hash.tgs').forEach(function (v) { (v.hashes || []).forEach(function (h, i) { out.push({ label: 'TGS #' + (i + 1), hash: h }); }); });
    ['credential.available', 'credential.plaintext'].forEach(function (k) {
      fs.values(k).forEach(function (v) { var h = v.nthash || v.hash; if (h && /^[0-9a-fA-F]{32}$/.test(h)) out.push({ label: (v.user || 'cred') + ' (NTLM)', hash: h }); });
    });
    var seen = {};
    return out.filter(function (x) { if (seen[x.hash]) return false; seen[x.hash] = 1; return true; });
  }

  var HASH_REFS = '<div class="wb-refs"><span class="wb-refs-l">Learn More</span>'
    + '<a href="https://hashcat.net/wiki/doku.php?id=example_hashes" target="_blank" rel="noopener">hashcat example hashes</a>'
    + '<a href="https://crackstation.net/" target="_blank" rel="noopener">CrackStation (unsalted lookup)</a></div>';

  function hashOutHtml(value) {
    var wb = W();
    if (!value || !value.trim()) return '<p class="wb-note">Paste a hash above and obol will name it, give you the hashcat mode and a ready crack command.</p>';
    var r = wb.identifyHash(value);
    if (!r.candidates.length) return '<p class="wb-note">' + esc(r.note || 'No confident match.') + '</p>' + HASH_REFS;

    var cards = r.candidates.map(function (c, i) {
      var modeBadge = (c.mode != null)
        ? '<span class="wb-mode">hashcat -m ' + esc(c.mode) + '</span>'
        : '<span class="wb-mode wb-mode-none">no hashcat mode</span>';
      var johnBadge = c.john ? '<span class="wb-john">john: ' + esc(c.john) + '</span>' : '';
      var hcCmd = wb.hashcatCmd(c.mode);
      var jnCmd = wb.johnCmd(c.john);
      var cmds = '';
      if (hcCmd) cmds += '<div class="wb-cmd"><code>' + esc(hcCmd) + '</code><button class="btn-copy" data-copy="' + U.attr(hcCmd) + '" aria-label="Copy hashcat command">copy</button></div>';
      if (jnCmd) cmds += '<div class="wb-cmd"><code>' + esc(jnCmd) + '</code><button class="btn-copy" data-copy="' + U.attr(jnCmd) + '" aria-label="Copy john command">copy</button></div>';
      return '<div class="wb-hash-card' + (i === 0 ? ' top' : '') + '">'
        + '<div class="wb-hash-head">' + (i === 0 ? '<span class="wb-likely">Most Likely</span>' : '')
        + '<span class="wb-hash-name">' + esc(c.name) + '</span>' + modeBadge + johnBadge + '</div>'
        + (c.note ? '<p class="wb-hash-note">' + esc(c.note) + '</p>' : '')
        + cmds + '</div>';
    }).join('');
    var multi = r.candidates.length > 1 ? '<p class="wb-note">More than one hash has this shape. The most likely is first; the context (where you found it) decides.</p>' : '';
    return multi + cards + HASH_REFS;
  }

  function hashidPanel() {
    var hashes = engagementHashes();
    var chips = hashes.length
      ? '<div class="wb-field-l">From This Engagement</div><div class="wb-fill-chips">'
        + hashes.map(function (h) {
          return '<button type="button" class="wb-fill-chip" data-hash="' + U.attr(h.hash) + '">' + esc(h.label) + '</button>';
        }).join('') + '</div>'
      : '';
    return '<div class="wb-panel wb-hashid">'
      + '<p class="wb-linked">' + linkedNote() + '</p>'
      + chips
      + '<div class="wb-field-l">Hash</div>'
      + '<textarea id="wb-hash-in" class="wb-textarea" rows="2" placeholder="Paste a hash (or a full user:rid:lm:nt::: line)" autocomplete="off" spellcheck="false"></textarea>'
      + '<div id="wb-hash-out" class="wb-hash-out">' + hashOutHtml('') + '</div>'
      + '</div>';
  }

  // Encoder (mini CyberChef).
  function isMostlyPrintable(s) {
    if (!s) return false;
    var good = 0;
    for (var i = 0; i < s.length; i++) { var c = s.charCodeAt(i); if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c >= 160) good++; }
    return good / s.length >= 0.85;
  }
  function xformRow(label, note, val) {
    return '<div class="wb-xform">'
      + '<div class="wb-xform-h"><span class="wb-xform-l">' + esc(label) + '</span>'
      + '<span class="wb-xform-note">' + esc(note) + '</span></div>'
      + '<div class="wb-cmd"><code>' + esc(val) + '</code>'
      + '<button class="btn-copy" data-copy="' + U.attr(val) + '" aria-label="Copy ' + U.attr(label) + '">copy</button></div></div>';
  }
  function encoderOutHtml(value) {
    var wb = W();
    if (!value) return '<p class="wb-note">Type or paste anything above. obol shows every common encoding at once, and the matching decode when the input looks encoded.</p>';
    var rows = '';
    rows += xformRow('Base64', 'The everyday encoding. Good for the OSCP base64-then-decode trick.', wb.b64(value));
    rows += xformRow('URL Encode', 'Percent-encode the characters a URL would choke on.', wb.urlEnc(value));
    rows += xformRow('URL Encode (Every Byte)', 'Aggressive: encode every byte. Useful when a filter blocks specific characters.', wb.urlEncAll(value));
    rows += xformRow('Hex', 'Raw bytes as hex.', wb.hexEnc(value));
    rows += xformRow('ROT13', 'A simple letter rotation (not encryption, just obfuscation).', wb.rot13(value));
    rows += xformRow('${IFS} Spaces', 'Swap spaces for ${IFS} so a space-filtering command injection still runs.', wb.ifsEvade(value));

    // decodes, only when the input actually looks like that format
    var dec = '';
    if (/^[A-Za-z0-9+/=\s]+$/.test(value) && value.replace(/\s/g, '').length >= 4) {
      var b = wb.b64decode(value);
      if (b && isMostlyPrintable(b)) dec += xformRow('Base64 Decode', 'Your input looked like base64, so here it is decoded.', b);
    }
    if (wb.hexDecode(value) !== null && value.replace(/\s/g, '').length >= 2) {
      var h = wb.hexDecode(value);
      if (h && isMostlyPrintable(h)) dec += xformRow('Hex Decode', 'Your input looked like hex, so here it is decoded.', h);
    }
    if (value.indexOf('%') >= 0) {
      var u = wb.urlDecode(value);
      if (u !== null && u !== value) dec += xformRow('URL Decode', 'Your input had percent-encoding, so here it is decoded.', u);
    }
    return rows + (dec ? '<div class="wb-field-l">Looks Encoded: Decoded For You</div>' + dec : '');
  }
  function encoderPanel() {
    return '<div class="wb-panel wb-encoder">'
      + '<div class="wb-field-l">Input</div>'
      + '<textarea id="wb-enc-in" class="wb-textarea" rows="2" placeholder="Type or paste anything" autocomplete="off" spellcheck="false"></textarea>'
      + '<div id="wb-enc-out" class="wb-enc-out">' + encoderOutHtml('') + '</div></div>';
  }

  // JWT decoder.
  var JWT_REFS = '<div class="wb-refs"><span class="wb-refs-l">Learn More</span>'
    + '<a href="https://jwt.io/" target="_blank" rel="noopener">jwt.io</a>'
    + '<a href="https://portswigger.net/web-security/jwt" target="_blank" rel="noopener">PortSwigger: JWT attacks</a></div>';
  function jwtSeg(label, obj) {
    var json;
    try { json = JSON.stringify(obj, null, 2); } catch (e) { json = String(obj); }
    return '<div class="wb-field-l">' + esc(label) + '</div>'
      + '<div class="wb-cmd"><code>' + esc(json) + '</code>'
      + '<button class="btn-copy" data-copy="' + U.attr(json) + '" aria-label="Copy ' + U.attr(label) + '">copy</button></div>';
  }
  function jwtOutHtml(value) {
    if (!value || !value.trim()) return '<p class="wb-note">Paste a JWT (it starts with eyJ...). obol decodes the header and payload and flags what is worth attacking. It decodes, it does not verify: a decoded token is not a trusted token.</p>';
    var r = W().decodeJwt(value);
    if (!r.ok) return '<p class="wb-note">' + esc(r.error) + '</p>' + JWT_REFS;
    var flags = r.flags.length
      ? '<div class="wb-field-l">Worth A Look</div>' + r.flags.map(function (f) { return '<p class="wb-enc-note">' + esc(f) + '</p>'; }).join('')
      : '';
    return jwtSeg('Header', r.header) + jwtSeg('Payload', r.payload)
      + '<div class="wb-field-l">Signature</div><div class="wb-cmd"><code>' + esc(r.signature || '(none)') + '</code></div>'
      + flags
      + '<p class="wb-note">This is a decode, not a verification. obol never has the signing key, so it cannot tell you the token is genuine, only what it claims.</p>'
      + JWT_REFS;
  }
  function jwtPanel() {
    return '<div class="wb-panel wb-jwt">'
      + '<div class="wb-field-l">Token</div>'
      + '<textarea id="wb-jwt-in" class="wb-textarea" rows="3" placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...." autocomplete="off" spellcheck="false"></textarea>'
      + '<div id="wb-jwt-out" class="wb-jwt-out">' + jwtOutHtml('') + '</div></div>';
  }

  // GTFOBins browser.
  var GTFO_FN_LABELS = {
    shell: 'Shell', command: 'Command', 'reverse-shell': 'Reverse Shell',
    'non-interactive-reverse-shell': 'Reverse Shell (non-interactive)', 'bind-shell': 'Bind Shell',
    'file-read': 'File Read', 'file-write': 'File Write', 'file-download': 'File Download',
    'file-upload': 'File Upload', 'library-load': 'Library Load', sudo: 'Sudo', suid: 'SUID',
    capabilities: 'Capabilities', 'limited-suid': 'Limited SUID', download: 'Download', upload: 'Upload',
  };
  function gtfoFnLabel(n) { return GTFO_FN_LABELS[n] || U.titleCase(String(n).replace(/-/g, ' ')); }

  function engagementBins() {
    var out = [], fs;
    try { fs = OBOL.store.factSet(); } catch (e) { return out; }
    if (!fs || !fs.values) return out;
    (fs.values('privesc.sudo_binary') || []).forEach(function (v) { if (v && v.bin) out.push({ label: v.bin + ' (sudo)', bin: v.bin }); });
    (fs.values('privesc.suid_candidate') || []).forEach(function (v) { (v && v.paths || []).forEach(function (p) { out.push({ label: (OBOL.resolve.binKey(p)) + ' (SUID)', bin: p }); }); });
    var seen = {};
    return out.filter(function (x) { var k = OBOL.resolve.binKey(x.bin); if (seen[k]) return false; seen[k] = 1; return true; });
  }

  function gtfoOutHtml(value) {
    var R = OBOL.resolve;
    if (!value || !value.trim()) return '<p class="wb-note">Type a binary you can run as sudo, or one that is SUID, and obol shows the exact GTFOBins escapes with the authoritative page one tap away.</p>';
    var q = value.trim();
    var fns = R.gtfoFunctions(q);
    var link = '<a class="wb-gtfo-link" href="' + U.attr(fns.url) + '" target="_blank" rel="noopener">Open ' + esc(fns.bin) + ' on GTFOBins</a>';
    if (fns.known && fns.inlined) {
      var blocks = fns.functions.map(function (f) {
        var codes = f.codes.map(function (c) {
          return '<div class="wb-cmd"><code>' + esc(c) + '</code><button class="btn-copy" data-copy="' + U.attr(c) + '" aria-label="Copy">copy</button></div>';
        }).join('');
        return '<div class="wb-gtfo-fn"><div class="wb-field-l">' + esc(gtfoFnLabel(f.name)) + '</div>' + codes + '</div>';
      }).join('');
      return '<div class="wb-gtfo-head"><span class="wb-gtfo-bin">' + esc(fns.bin) + '</span>' + link + '</div>'
        + '<p class="wb-note">Replace any path or filename with your own. For a sudo escape, prefix with sudo; for SUID, GTFOBins marks the privilege-keeping form.</p>'
        + blocks;
    }
    if (fns.known) {
      return '<div class="wb-gtfo-head"><span class="wb-gtfo-bin">' + esc(fns.bin) + '</span>' + link + '</div>'
        + '<p class="wb-note">GTFOBins knows this binary, but its escape uses an inherit directive obol will not inline (guessing it could be wrong). Open the page above for the exact, current steps.</p>';
    }
    // not an exact match: suggest names
    var sug = R.gtfoSuggest(q);
    if (sug.length) {
      return '<p class="wb-note">No exact match for "' + esc(q) + '". Did you mean:</p>'
        + '<div class="wb-fill-chips">' + sug.map(function (n) {
          return '<button type="button" class="wb-gtfo-sug" data-bin="' + U.attr(n) + '">' + esc(n) + '</button>';
        }).join('') + '</div>';
    }
    return '<p class="wb-note">GTFOBins has no entry for "' + esc(q) + '". Not every binary is exploitable, that is normal. Check the SUID/sudo list again, or try a different one.</p>';
  }
  function gtfobinsPanel() {
    var bins = engagementBins();
    var chips = bins.length
      ? '<div class="wb-field-l">From This Engagement</div><div class="wb-fill-chips">'
        + bins.map(function (b) { return '<button type="button" class="wb-gtfo-sug" data-bin="' + U.attr(b.bin) + '">' + esc(b.label) + '</button>'; }).join('')
        + '</div>'
      : '';
    return '<div class="wb-panel wb-gtfobins">'
      + '<p class="wb-linked">' + linkedNote() + '</p>'
      + chips
      + '<div class="wb-field-l">Binary</div>'
      + '<input id="wb-gtfo-in" class="wb-input" type="text" placeholder="e.g. find, vim, python, tar" autocomplete="off" spellcheck="false">'
      + '<div id="wb-gtfo-out" class="wb-gtfo-out">' + gtfoOutHtml('') + '</div></div>';
  }

  // Wordlist picker.
  var STACK_TAGS = ['iis', 'apache', 'nginx', 'php', 'aspnet', 'wordpress', 'api', 'rest', 'windows', 'linux'];
  function detectStack() {
    var tags = {}, fs;
    try { fs = OBOL.store.factSet(); } catch (e) { return []; }
    if (!fs || !fs.facts) return [];
    var blob = '';
    fs.facts.forEach(function (f) { try { blob += ' ' + f.kind + ' ' + JSON.stringify(f.value || {}); } catch (e) {} });
    blob = blob.toLowerCase();
    if (/asp\.net|aspnet|\.aspx/.test(blob)) tags.aspnet = 1;
    STACK_TAGS.forEach(function (t) { if (blob.indexOf(t) >= 0) tags[t] = 1; });
    return Object.keys(tags);
  }

  var _wl = { task: 'dirs' };
  function wlOutHtml() {
    var wb = W();
    var stack = detectStack();
    var target = activeParams().target || '';
    var lists = wb.pickWordlists(_wl.task, stack);
    var anyMatch = lists.some(function (l) { return l.matched; });
    var head = anyMatch
      ? '<p class="wb-note">Ranked for your detected stack (' + esc(stack.join(', ')) + '). The best fit is first.</p>'
      : '';
    var rows = lists.map(function (l) {
      var cmd = wb.wordlistCmd(_wl.task, l.path, target);
      return '<div class="wb-wl-card' + (l.matched ? ' top' : '') + '">'
        + '<div class="wb-wl-head">' + (l.matched ? '<span class="wb-likely">Your Stack</span>' : '') + '<span class="wb-wl-name">' + esc(l.name) + '</span></div>'
        + '<p class="wb-hash-note">' + esc(l.note) + '</p>'
        + '<div class="wb-cmd"><code>' + esc(l.path) + '</code><button class="btn-copy" data-copy="' + U.attr(l.path) + '" aria-label="Copy path">copy</button></div>'
        + '<div class="wb-cmd"><code>' + esc(cmd) + '</code><button class="btn-copy" data-copy="' + U.attr(cmd) + '" aria-label="Copy command">copy</button></div>'
        + '</div>';
    }).join('');
    return head + '<div class="wb-wl-list">' + rows + '</div>';
  }
  function wordlistsPanel() {
    var wb = W();
    var tabs = (wb.WORDLIST_TASKS || []).map(function (t) {
      var on = t.id === _wl.task;
      return '<button type="button" class="wb-chip' + (on ? ' on' : '') + '" data-wl-task="' + esc(t.id) + '" aria-pressed="' + (on ? 'true' : 'false') + '">' + esc(t.label) + '</button>';
    }).join('');
    return '<div class="wb-panel wb-wordlists">'
      + '<p class="wb-linked">' + linkedNote() + '</p>'
      + '<div class="wb-field-l">What Are You Attacking?</div>'
      + '<div class="wb-enc-row" role="group" aria-label="Wordlist task">' + tabs + '</div>'
      + '<div id="wb-wl-out" class="wb-wl-out">' + wlOutHtml() + '</div></div>';
  }

  // Manual SQLi builder.
  var _sqli = { dbms: 'mysql', ctx: 'string' };
  function sqliState() {
    function iv(id) { var el = document.getElementById(id); var n = el ? parseInt(el.value, 10) : NaN; return n > 0 ? n : 0; }
    var tEl = document.getElementById('wb-sqli-table');
    return { dbms: _sqli.dbms, ctx: _sqli.ctx, cols: iv('wb-sqli-cols'), vis: iv('wb-sqli-vis'), table: tEl ? tEl.value.trim() : '' };
  }
  function sqliOutHtml() {
    var wb = W();
    var b = wb.sqliBuild(sqliState());
    var intro = '<p class="wb-note">' + esc(b.dbms.note) + '</p>';
    var cards = b.phases.map(function (ph) {
      var items = ph.items.map(function (it) {
        return '<div class="wb-sqli-item"><div class="wb-xform-note">' + esc(it.label) + '</div>'
          + '<div class="wb-cmd"><code>' + esc(it.payload) + '</code>'
          + '<button class="btn-copy" data-copy="' + U.attr(it.payload) + '" aria-label="Copy payload">copy</button></div></div>';
      }).join('');
      return '<div class="wb-sqli-phase"><div class="wb-field-l">' + esc(ph.title) + '</div>'
        + '<p class="wb-hash-note">' + esc(ph.note) + '</p>' + items + '</div>';
    }).join('');
    return intro + cards;
  }
  function sqliPanel() {
    var dbmsBtns = W().sqliDbmsList().map(function (d) {
      var on = d.id === _sqli.dbms;
      return '<button type="button" class="wb-chip' + (on ? ' on' : '') + '" data-sqli-dbms="' + esc(d.id) + '" aria-pressed="' + (on ? 'true' : 'false') + '">' + esc(d.name) + '</button>';
    }).join('');
    var ctxBtns = [['string', 'String (quoted)'], ['numeric', 'Numeric']].map(function (c) {
      var on = c[0] === _sqli.ctx;
      return '<button type="button" class="wb-chip' + (on ? ' on' : '') + '" data-sqli-ctx="' + c[0] + '" aria-pressed="' + (on ? 'true' : 'false') + '">' + esc(c[1]) + '</button>';
    }).join('');
    return '<div class="wb-panel wb-sqli">'
      + '<p class="wb-linked">Manual by design: you run every query yourself and paste the result back, so obol builds the next payload. No automation, no sqlmap, which keeps it OSCP exam-legal.</p>'
      + '<div class="wb-field-l">Database Engine</div>'
      + '<div class="wb-enc-row" role="group" aria-label="Database engine">' + dbmsBtns + '</div>'
      + '<div class="wb-field-l">Injection Context</div>'
      + '<div class="wb-enc-row" role="group" aria-label="Injection context">' + ctxBtns + '</div>'
      + '<div class="wb-field-l">What You Have Found (Fill As You Go)</div>'
      + '<div class="wb-params">'
      + '<label class="wb-param"><span>Columns</span><input id="wb-sqli-cols" type="text" inputmode="numeric" placeholder="e.g. 3" autocomplete="off"></label>'
      + '<label class="wb-param"><span>Visible Column</span><input id="wb-sqli-vis" type="text" inputmode="numeric" placeholder="e.g. 2" autocomplete="off"></label>'
      + '<label class="wb-param"><span>Table</span><input id="wb-sqli-table" type="text" placeholder="e.g. users" autocomplete="off" spellcheck="false"></label>'
      + '</div>'
      + '<div id="wb-sqli-out" class="wb-sqli-out">' + sqliOutHtml() + '</div>'
      + '<div class="wb-refs"><span class="wb-refs-l">Learn More</span>'
      + '<a href="https://portswigger.net/web-security/sql-injection" target="_blank" rel="noopener">PortSwigger: SQL injection</a>'
      + '<a href="https://portswigger.net/web-security/sql-injection/cheat-sheet" target="_blank" rel="noopener">SQLi cheat sheet</a></div>'
      + '</div>';
  }

  // Explain This Output (parser annotate mode).
  function explainOutHtml(text, facts) {
    var wb = W();
    if (!facts || !facts.length) {
      return '<p class="wb-note">obol did not mint any facts from that. Either it is not output from a tool obol parses, or the command line that produced it would help routing. Add the command above and try again. This is honest: if the engine would record nothing, there is nothing to annotate.</p>';
    }
    var ann = wb.annotateOutput(text, facts);
    var src = '<div class="wb-ex-src" role="img" aria-label="Your output with the fact-producing lines highlighted">'
      + ann.lines.map(function (ln) {
          var hit = ln.factIdxs.length;
          var badge = hit ? '<span class="wb-ex-badge">' + esc(ln.factIdxs.map(function (i) { return '#' + (i + 1); }).join(' ')) + '</span>' : '';
          return '<div class="wb-ex-line' + (hit ? ' hit' : '') + '">' + badge + '<code>' + esc(ln.text || ' ') + '</code></div>';
        }).join('') + '</div>';
    var cards = ann.facts.map(function (a) {
      var from = a.lineNos.length
        ? 'From line' + (a.lineNos.length > 1 ? 's' : '') + ' ' + a.lineNos.map(function (n) { return n + 1; }).join(', ')
        : 'Derived (no single line)';
      return '<div class="wb-ex-fact"><div class="wb-ex-fh"><span class="wb-ex-num">#' + (a.index + 1) + '</span>'
        + '<code>' + esc(a.kind) + '</code><span class="wb-ex-from">' + esc(from) + '</span></div>'
        + '<p class="wb-ex-proves"><strong>Proves:</strong> ' + esc(a.explain.proves) + '</p>'
        + '<p class="wb-ex-caveat"><strong>Does Not Prove:</strong> ' + esc(a.explain.caveat) + '</p></div>';
    }).join('');
    return '<div class="wb-field-l">Your Output (' + facts.length + ' fact' + (facts.length === 1 ? '' : 's') + ' minted)</div>' + src
      + '<div class="wb-field-l">What obol Learned</div><div class="wb-ex-facts">' + cards + '</div>';
  }
  function explainPanel() {
    return '<div class="wb-panel wb-explain">'
      + '<p class="wb-linked">Paste tool output and obol shows which lines mint which facts, what each one proves in plain language, and what it does not. It annotates the real facts the engine would record, it never invents one.</p>'
      + '<div class="wb-field-l">Command (Optional, Helps Routing)</div>'
      + '<input id="wb-ex-cmd" class="wb-input" type="text" placeholder="e.g. nmap -sC -sV 10.10.10.5" autocomplete="off" spellcheck="false">'
      + '<div class="wb-field-l">Output</div>'
      + '<textarea id="wb-ex-in" class="wb-textarea" rows="8" placeholder="Paste the tool output here" autocomplete="off" spellcheck="false"></textarea>'
      + '<button id="wb-ex-go" class="wb-go" type="button">Explain This Output</button>'
      + '<div id="wb-ex-out" class="wb-ex-out"></div></div>';
  }

  function stubPanel(label) {
    return '<div class="wb-panel wb-stub"><p class="wb-note">' + esc(label)
      + ' is coming online in this build. The Reverse Shell Builder is ready now, the rest land next.</p></div>';
  }

  function panelFor(tab) {
    if (tab === 'revshell') return revshellPanel();
    if (tab === 'hashid') return hashidPanel();
    if (tab === 'encoder') return encoderPanel();
    if (tab === 'jwt') return jwtPanel();
    if (tab === 'gtfobins') return gtfobinsPanel();
    if (tab === 'wordlists') return wordlistsPanel();
    if (tab === 'sqli') return sqliPanel();
    if (tab === 'explain') return explainPanel();
    var t = TABS.filter(function (x) { return x.id === tab; })[0];
    return stubPanel(t ? t.label : 'This tool');
  }

  function render(ctx) {
    var arg = (ctx.args && ctx.args[0]) || '';
    if (tabIds().indexOf(arg) >= 0) _tab = arg;
    // a deep link may target a specific wordlist task (e.g. #/workbench/wordlists/subdomains)
    if (_tab === 'wordlists') {
      var sub = (ctx.args && ctx.args[1]) || '';
      var okTask = (W().WORDLIST_TASKS || []).some(function (t) { return t.id === sub; });
      if (okTask) _wl.task = sub;
    }

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
    U.on(mount, 'click', '.wb-chip[data-rs-enc]', function (e, t) {
      _rs.enc = t.getAttribute('data-rs-enc') || 'plain';
      refreshRsOut();
    });

    // reverse-shell: LHOST / LPORT edits recompute and save back to the engagement
    U.on(mount, 'input', '#wb-rs-lhost', function (e, t) { syncParam('lhost', t.value); refreshRsOut(); });
    U.on(mount, 'input', '#wb-rs-lport', function (e, t) { syncParam('lport', t.value); refreshRsOut(); });

    // hash identifier: identify on input; quick-fill chips drop a captured hash into the box
    U.on(mount, 'input', '#wb-hash-in', function (e, t) {
      var out = document.getElementById('wb-hash-out');
      if (out) out.innerHTML = hashOutHtml(t.value);
    });
    U.on(mount, 'click', '.wb-fill-chip', function (e, t) {
      var box = document.getElementById('wb-hash-in');
      if (!box) return;
      box.value = t.getAttribute('data-hash') || '';
      var out = document.getElementById('wb-hash-out');
      if (out) out.innerHTML = hashOutHtml(box.value);
      box.focus();
    });

    // encoder: recompute every transform on input
    U.on(mount, 'input', '#wb-enc-in', function (e, t) {
      var out = document.getElementById('wb-enc-out');
      if (out) out.innerHTML = encoderOutHtml(t.value);
    });

    // jwt: decode on input
    U.on(mount, 'input', '#wb-jwt-in', function (e, t) {
      var out = document.getElementById('wb-jwt-out');
      if (out) out.innerHTML = jwtOutHtml(t.value);
    });

    // gtfobins: look up on input; suggestion / engagement chips fill the box
    U.on(mount, 'input', '#wb-gtfo-in', function (e, t) {
      var out = document.getElementById('wb-gtfo-out');
      if (out) out.innerHTML = gtfoOutHtml(t.value);
    });
    U.on(mount, 'click', '.wb-gtfo-sug', function (e, t) {
      var box = document.getElementById('wb-gtfo-in');
      if (!box) return;
      box.value = t.getAttribute('data-bin') || '';
      var out = document.getElementById('wb-gtfo-out');
      if (out) out.innerHTML = gtfoOutHtml(box.value);
      box.focus();
    });

    // manual sqli: DBMS + context buttons re-render the phases; the found-values inputs refine them
    function sqliRefresh() { var out = document.getElementById('wb-sqli-out'); if (out) out.innerHTML = sqliOutHtml(); }
    U.on(mount, 'click', '.wb-chip[data-sqli-dbms]', function (e, t) {
      _sqli.dbms = t.getAttribute('data-sqli-dbms') || 'mysql';
      var btns = mount.querySelectorAll('.wb-chip[data-sqli-dbms]');
      for (var i = 0; i < btns.length; i++) { var on = btns[i] === t; btns[i].classList.toggle('on', on); btns[i].setAttribute('aria-pressed', on ? 'true' : 'false'); }
      sqliRefresh();
    });
    U.on(mount, 'click', '.wb-chip[data-sqli-ctx]', function (e, t) {
      _sqli.ctx = t.getAttribute('data-sqli-ctx') || 'string';
      var btns = mount.querySelectorAll('.wb-chip[data-sqli-ctx]');
      for (var i = 0; i < btns.length; i++) { var on = btns[i] === t; btns[i].classList.toggle('on', on); btns[i].setAttribute('aria-pressed', on ? 'true' : 'false'); }
      sqliRefresh();
    });
    U.on(mount, 'input', '#wb-sqli-cols', sqliRefresh);
    U.on(mount, 'input', '#wb-sqli-vis', sqliRefresh);
    U.on(mount, 'input', '#wb-sqli-table', sqliRefresh);

    // explain output: load the real parser bundle on demand, parse the paste, then annotate it
    U.on(mount, 'click', '#wb-ex-go', function () {
      var out = document.getElementById('wb-ex-out');
      var inEl = document.getElementById('wb-ex-in');
      var cmdEl = document.getElementById('wb-ex-cmd');
      var text = inEl ? inEl.value : '';
      if (!text.trim()) { if (out) out.innerHTML = '<p class="wb-note">Paste some output first.</p>'; return; }
      if (out) out.innerHTML = '<p class="wb-note">Parsing...</p>';
      var done = function () {
        if (!OBOL.parsers || !OBOL.parsers.analyzeTerminal) { if (out) out.innerHTML = '<p class="wb-note">The parser bundle did not load. Check your connection and try again.</p>'; return; }
        var scope = 'host:' + (activeParams().target || 'target');
        var res;
        try { res = OBOL.parsers.analyzeTerminal(text, { command: (cmdEl && cmdEl.value) || '', scope: scope }); }
        catch (e) { if (out) out.innerHTML = '<p class="wb-note">The parser hit an error on that input.</p>'; return; }
        if (out) out.innerHTML = explainOutHtml(text, (res && res.facts) || []);
      };
      if (OBOL.parsers && OBOL.parsers.analyzeTerminal) { done(); }
      else if (OBOL.lazy && OBOL.lazy.loadGroup) { OBOL.lazy.loadGroup('parsers').then(done, done); }
      else { done(); }
    });

    // wordlists: switch task, re-rank
    U.on(mount, 'click', '.wb-chip[data-wl-task]', function (e, t) {
      _wl.task = t.getAttribute('data-wl-task') || 'dirs';
      var chips = mount.querySelectorAll('.wb-chip[data-wl-task]');
      for (var i = 0; i < chips.length; i++) {
        var on = chips[i] === t;
        chips[i].classList.toggle('on', on);
        chips[i].setAttribute('aria-pressed', on ? 'true' : 'false');
      }
      var out = document.getElementById('wb-wl-out');
      if (out) out.innerHTML = wlOutHtml();
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.workbench = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
