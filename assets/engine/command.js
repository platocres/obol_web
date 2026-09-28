/*!
 * obol engine — command.js
 * Command templating: build the {{token}} context from proven facts + engagement params,
 * fill a command template, and render an action's command variants. Faithful JS port of the
 * relevant parts of obol-local/obol/board.py (command_context / fill_template / fill_command).
 *
 * Browser adaptation: there is no Workspace. Callers pass a FactSet (OBOL.facts.FactSet) and
 * an engagement `params` object (target/domain/username/password/lhost/…). Facts-derived
 * tokens fill from proven facts; `extra` pins specific values and wins over both.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  var SHELL_VALUE_TOKENS = { password: true, nthash: true };
  var LIT_OPEN = '\x00OBOL_LBRACE\x00';
  var LIT_CLOSE = '\x00OBOL_RBRACE\x00';

  // POSIX shell single-quote quoting (equivalent of Python shlex.quote for our needs).
  function shellQuote(s) {
    s = String(s);
    if (s === '') return "''";
    if (/^[A-Za-z0-9_@%+=:,.\/-]+$/.test(s)) return s;
    return "'" + s.replace(/'/g, "'\\''") + "'";
  }

  function firstVal(facts, kind) {
    var v = facts.values(kind);
    return v.length ? v[0] : null;
  }

  // Open ports as sorted numbers, from port:NNN facts (recon output).
  function openPorts(facts) {
    var ports = [];
    for (var i = 0; i < facts.facts.length; i++) {
      var f = facts.facts[i];
      if (f.state !== OBOL.facts.ProofState.SUPPORTED) continue;
      if (f.kind.indexOf('port:') === 0) {
        var n = parseInt(f.kind.split(':')[1], 10);
        if (!isNaN(n)) ports.push(n);
      }
    }
    // also honor a ports.open summary fact carrying a list
    var summary = firstVal(facts, 'ports.open');
    if (summary && Array.isArray(summary.ports)) {
      summary.ports.forEach(function (p) { var n = parseInt(p, 10); if (!isNaN(n)) ports.push(n); });
    }
    ports = ports.filter(function (v, i, a) { return a.indexOf(v) === i; });
    ports.sort(function (a, b) { return a - b; });
    return ports;
  }

  // Map obol_web engagement params to the base token context (ws.inputs analog).
  function paramsToInputs(params) {
    params = params || {};
    var ctx = {};
    Object.keys(params).forEach(function (k) {
      var v = params[k];
      if (v === null || v === undefined || v === '') return;
      ctx[k] = v;
    });
    // common aliases obol_web uses
    if (params.username && !ctx.user) ctx.user = params.username;
    if (params.target && !ctx.target) ctx.target = params.target;
    if (params.rhost && !ctx.target) ctx.target = params.rhost;
    return ctx;
  }

  // Build the {{token}} context from facts + params (+ extra which wins).
  function buildContext(facts, opts) {
    opts = opts || {};
    var params = opts.params || {};
    var extra = opts.extra || {};
    var tgt = opts.target || params.target || params.rhost || '';

    var ctx = Object.assign({ target: tgt || '<target>' }, paramsToInputs(params));
    if (tgt) ctx.target = tgt;

    var ports = openPorts(facts);
    if (ports.length) ctx.nmap_ports = ports.join(',');

    var dom = firstVal(facts, 'ad.domain_known');
    if (dom && dom.name) {
      ctx.domain = dom.name;
      ctx.basedn = dom.name.split('.').map(function (p) { return 'DC=' + p; }).join(',');
      ctx.dc = dom.name;
    }
    if (!ctx.basedn) {
      var bases = facts.values('ad.base_dn');
      for (var i = 0; i < bases.length; i++) {
        var bd = bases[i].base_dn || bases[i].basedn || '';
        if (bd) { ctx.basedn = bd; break; }
      }
    }
    // domain from params if facts didn't provide it, derive basedn
    if (!ctx.domain && params.domain) ctx.domain = params.domain;
    if (ctx.domain && !ctx.basedn) {
      ctx.basedn = ctx.domain.split('.').map(function (p) { return 'DC=' + p; }).join(',');
    }

    // lhost: params-pinned, else a listener fact, else leave for operator
    if (!ctx.lhost) {
      var lo = firstVal(facts, 'listener.open');
      if (lo && lo.lhost) ctx.lhost = lo.lhost;
    }
    // iface: the operator's attacker interface (responder -I, mitm6 -i, …). Pinned from the engagement's
    // configured VM interface, defaulting to tun0 — the VPN adapter for HTB/OSCP-style labs.
    if (!ctx.iface) ctx.iface = params.lhost_iface || 'tun0';

    // credentials: prefer credential.available then credential.plaintext. IDENTITY-COHERENT fill — never
    // pair one credential's username with another's secret. `-u svc-alfresco -H <administrator-hash>` just
    // fails auth; the user and the secret must come from the SAME credential. When params already pin a
    // user, fill that same user's secret; otherwise adopt the first credential wholesale.
    var creds = facts.values('credential.available');
    if (!creds.length) creds = facts.values('credential.plaintext');
    function _lc(x) { return String(x == null ? '' : x).toLowerCase(); }
    if (ctx.user) {
      for (var c = 0; c < creds.length; c++) {
        if (_lc(creds[c].user) !== _lc(ctx.user)) continue;
        if (!ctx.password && creds[c].password) ctx.password = creds[c].password;
        var nhm = creds[c].nthash || creds[c].hash;
        if (!ctx.nthash && nhm) ctx.nthash = nhm;
        if (!ctx.domain && creds[c].domain) ctx.domain = creds[c].domain;
        break;
      }
    } else if (creds.length) {
      var c0 = creds[0];
      if (c0.user) ctx.user = c0.user;
      if (c0.password && !ctx.password) ctx.password = c0.password;
      var nh0 = c0.nthash || c0.hash;
      if (nh0 && !ctx.nthash) ctx.nthash = nh0;
      if (c0.domain && !ctx.domain) ctx.domain = c0.domain;
    }

    // ADCS ca/template/pfx
    var adcs = firstVal(facts, 'adcs.vulnerable');
    if (adcs) {
      if (adcs.ca && !ctx.ca_name) ctx.ca_name = adcs.ca;
      if (adcs.templates && adcs.templates.length && !ctx.template) ctx.template = adcs.templates[0];
    }
    var certs = facts.values('credential.certificate');
    for (var ci = 0; ci < certs.length; ci++) {
      if (certs[ci].files && certs[ci].files.length) { ctx.pfx = certs[ci].files[0]; break; }
    }

    // DC identity
    if (!ctx.dc_netbios || !ctx.dc_account) {
      var dcName = '';
      var dcCands = facts.values('ad.dc_candidate');
      for (var d = 0; d < dcCands.length; d++) {
        dcName = dcCands[d].name || dcCands[d].hostname || dcCands[d].netbios || '';
        if (dcName) break;
      }
      if (!dcName) {
        var hns = facts.values('host.hostname');
        for (var h = 0; h < hns.length; h++) { dcName = hns[h].name || hns[h].hostname || ''; if (dcName) break; }
      }
      if (dcName) {
        var short = dcName.split('.')[0];
        if (!ctx.dc_netbios) ctx.dc_netbios = short;
        if (!ctx.dc_account) ctx.dc_account = short + '$';
      }
    }

    // domain SID
    var sids = facts.values('ad.domain_sid');
    for (var s = 0; s < sids.length; s++) { if (sids[s].sid) { ctx.domain_sid = sids[s].sid; break; } }

    // BloodHound cash-in tokens from first abusable edge
    var paths = facts.values('ad.attack_paths');
    for (var p = 0; p < paths.length; p++) {
      var fa = paths[p].first_action || {};
      if (fa.target) {
        if (!ctx.group) ctx.group = fa.target;
        if (!ctx.target_sam) ctx.target_sam = fa.target;
        break;
      }
    }
    // …and, when BloodHound wasn't run, from a bloodyAD `get writable` lead (ad.acl_lead). obol does NOT
    // guess which single group is the winner (that would hard-code one lab's path): it ranks the abusable
    // groups the lead actually shows and lets the operator try them until one unlocks with evidence.
    //   {{group}}                — the top-ranked candidate to try first (a starting point, not the answer)
    //   {{abuse_groups_quoted}}  — every reasonable candidate, quoted & space-joined, for a ONE-SHOT sweep
    //                              (`for g in {{abuse_groups_quoted}}; do add groupMember "$g" …`)
    // Ranking is try-order only; whichever add actually sticks (and then unlocks DCSync) is the real path.
    if (ctx.group === undefined || ctx.target_sam === undefined || ctx.abuse_groups_quoted === undefined) {
      // The standard high-value AD groups, in the order worth trying: direct-DA first, then the groups
      // whose membership yields domain control (WriteDACL→DCSync, SeBackup, service install, DLL-on-DC).
      var ABUSE_PRIORITY = ['domain admins', 'enterprise admins', 'administrators',
        'exchange windows permissions', 'account operators', 'organization management',
        'backup operators', 'server operators', 'dnsadmins', 'print operators',
        'group policy creator owners', 'key admins', 'enterprise key admins'];
      var leadTargets = [];
      facts.values('ad.acl_lead').forEach(function (v) {
        (v.targets || []).forEach(function (tgt) { if (tgt && leadTargets.indexOf(tgt) < 0) leadTargets.push(tgt); });
      });
      // Candidates = the reasonable, known-abusable groups the lead shows, in priority order. When the
      // lead names none of them (or there is no lead yet), fall back to the usual suspects so the sweep
      // still tries every group worth trying rather than forming an empty loop.
      var lowerSet = {};
      leadTargets.forEach(function (t) { lowerSet[String(t).toLowerCase()] = t; });
      var candidates = [];
      ABUSE_PRIORITY.forEach(function (g) { if (lowerSet[g]) candidates.push(lowerSet[g]); });
      if (!candidates.length) candidates = ABUSE_PRIORITY.map(function (g) { return g.replace(/\b\w/g, function (c) { return c.toUpperCase(); }); });
      if (ctx.group === undefined) ctx.group = candidates[0] || leadTargets[0] || '';
      if (ctx.target_sam === undefined) ctx.target_sam = candidates[0] || leadTargets[0] || '';
      if (ctx.abuse_groups_quoted === undefined) ctx.abuse_groups_quoted = candidates.map(function (g) { return '"' + String(g).replace(/(["\\$`])/g, '\\$1') + '"'; }).join(' ');
    }

    // flag-hunt tokens from the engagement profile (which flag names the hunt searches)
    if (OBOL.profile) {
      var fc = OBOL.profile.resolveFlagConfig(opts.profile || {});
      if (!ctx.flag_inames_linux) ctx.flag_inames_linux = OBOL.profile.linuxInameExpr(fc.names);
      if (!ctx.flag_names_windows) ctx.flag_names_windows = OBOL.profile.windowsNameList(fc.names);

      // Per-slot flag file PATHS for the on-host capture step. Prefer a path obol actually LOCATED (a
      // nxc/smb spider, or a prior read) so step 3/4 fill with the real file — the user's Desktop, the
      // platform's own name — instead of a guessed placeholder; else a profile-aware default.
      var _flagName = function (slot) {
        var ns = fc.names || [];
        for (var i = 0; i < ns.length; i++) if ((fc.slots || {})[ns[i]] === slot) return ns[i];
        return slot === 'root' ? 'root.txt' : 'user.txt';
      };
      var _locatedPath = function (slot) {
        var kinds = ['objective.flag_located', slot === 'root' ? 'objective.root_flag' : 'objective.local_flag'];
        for (var k = 0; k < kinds.length; k++) {
          var vs = (facts && facts.values) ? (facts.values(kinds[k]) || []) : [];
          for (var i = 0; i < vs.length; i++) if (vs[i] && vs[i].path && vs[i].slot === slot) return vs[i].path;
        }
        return '';
      };
      var _isLinux = facts && facts.has && (facts.has('foothold.linux') || facts.has('access.shell') || facts.has('os.linux'))
        && !facts.has('foothold.windows') && !facts.has('os.windows');
      if (ctx.flag_path_local === undefined) {
        ctx.flag_path_local = _locatedPath('local') || (_isLinux
          ? ('/home/' + (ctx.user || '<user>') + '/' + _flagName('local'))
          : ('C:\\Users\\' + (ctx.user || '<user>') + '\\Desktop\\' + _flagName('local')));
      }
      if (ctx.flag_path_root === undefined) {
        ctx.flag_path_root = _locatedPath('root') || (_isLinux
          ? ('/root/' + _flagName('root'))
          : ('C:\\Users\\Administrator\\Desktop\\' + _flagName('root')));
      }
    }

    // workspace output-directory tokens ({{scandir}} etc.) — from opts.workspace when the caller
    // supplies it (OBOL.workspace.tokens(eng)), else relative fallbacks so commands still form.
    var wsd = opts.workspace || { root: '.', scandir: 'scans', lootdir: 'loot', exploitdir: 'exploit', wwwdir: 'www', proofdir: 'proof' };
    ['root', 'scandir', 'lootdir', 'exploitdir', 'wwwdir', 'proofdir'].forEach(function (k) {
      if (ctx[k] === undefined && wsd[k] !== undefined) ctx[k] = wsd[k];
    });

    // loot-materialized file tokens ({{userlist}}/{{hashfile}}/{{wordlist}}) — resolve to stable
    // paths under the workspace loot/ dir so the roast that writes {{hashfile}} and the crack that
    // reads it agree, and {{userlist}} points at the file obol can materialize from ad.user_list.
    // Only fills for an action the caller identified (opts.action); params still win over these.
    if (OBOL.loot && opts.action) {
      var lt = OBOL.loot.tokensFor(opts.action, facts, wsd, params);
      Object.keys(lt).forEach(function (k) {
        if (ctx[k] === undefined && lt[k] !== undefined && lt[k] !== '') ctx[k] = lt[k];
      });
    }

    // extra wins
    Object.keys(extra).forEach(function (k) {
      var v = extra[k];
      if (v !== null && v !== undefined && v !== '') ctx[k] = v;
    });
    return ctx;
  }

  // Substitute known {{tokens}}; leave unknown placeholders visible (they signal a dependency).
  function fillTemplate(text, facts, opts) {
    if (!text) return '';
    var cmd = String(text).split('\\{\\{').join(LIT_OPEN).split('\\}\\}').join(LIT_CLOSE);
    var ctx = buildContext(facts, opts);
    Object.keys(ctx).forEach(function (key) {
      var placeholder = '{{' + key + '}}';
      var sval = String(ctx[key]);
      if (SHELL_VALUE_TOKENS[key] && shellQuote(sval) !== sval) {
        var quoted = shellQuote(sval);
        cmd = cmd.split("'" + placeholder + "'").join(quoted)
                 .split('"' + placeholder + '"').join(quoted)
                 .split(placeholder).join(quoted);
      } else {
        cmd = cmd.split(placeholder).join(sval);
      }
    });
    return cmd.split(LIT_OPEN).join('{{').split(LIT_CLOSE).join('}}');
  }

  // Fill a command variant of an action (0-based). Returns {tool, run, note, filled, webNote}.
  // obol web is the hands-on edition: where an action carries a web-suited command (`web` on a
  // variant, or `web_command` on the action) — one tuned for a human who must copy/paste or attach
  // the output by hand, not a terminal reading it off disk — that form is preferred here. A
  // `web_note` carries the matching hands-on guidance (e.g. "large output → tee to a file and
  // attach it in Evidence"). Neither field exists in obol-local's mined data; both are additive.
  function fillCommand(action, facts, opts, index) {
    opts = opts || {};
    index = index || 0;
    var commands = (action.commands && action.commands.length) ? action.commands : [{ run: action.command, tool: action.tool }];
    if (index < 0 || index >= commands.length) index = 0;
    var c = commands[index] || {};
    var run = c.web || c.run || action.web_command || action.command || '';
    return {
      tool: c.tool || action.tool || '',
      note: c.note || '',
      webNote: c.web_note || action.web_note || '',
      win: !!c.win,   // a box-ending move — the coach flags it "PWN THIS TARGET"
      run: run,
      // thread the action so the loot glue can resolve {{userlist}}/{{hashfile}} for THIS move.
      filled: fillTemplate(run, facts, opts.action === action ? opts : Object.assign({}, opts, { action: action })),
    };
  }

  // All variants of an action, filled — for the coach to show "many commands".
  function fillAll(action, facts, opts) {
    var commands = (action.commands && action.commands.length) ? action.commands : [{ run: action.command, tool: action.tool }];
    return commands.map(function (c, i) { return fillCommand(action, facts, opts, i); });
  }

  // The distinctive ACTION tokens of a command — the verbs/subcommands that say WHAT it does, with the
  // tool name, flags, param values (target/domain/user/secret/…), paths, numbers and shell scaffolding
  // stripped out. Two commands with the same action tokens are "the same move" regardless of which host or
  // credential filled them, so this is how obol tells that a suggested command is one you already ran.
  // Long flags that only say WHERE/HOW to connect, not what the move does — dropped so `--host`/`--dc-ip`
  // don't drown out the real action, and so a run with `--detail` matches one without it.
  var _PLUMBING_FLAGS = { host: 1, 'dc-ip': 1, 'dc-host': 1, dns: 1, domain: 1, port: 1, timeout: 1, detail: 1,
    json: 1, threads: 1, jitter: 1, nameserver: 1, 'no-pass': 1, gc: 1, 'min-rate': 1 };
  // Bare words that are shell scaffolding or output plumbing, never an action.
  var _NOISE_WORDS = { 'for': 1, 'in': 1, 'do': 1, 'done': 1, 'then': 1, 'fi': 1, 'else': 1, 'echo': 1,
    'sudo': 1, 'while': 1, 'tee': 1, 'cat': 1 };
  // Short flags that DEFINE the action and must be kept — `-x`/`-X` (execute a command) is the whole
  // difference between `nxc smb …` (validate the credential) and `nxc smb … -x '<cmd>'` (run a command),
  // so dropping it made running the validator wrongly mark the exec command as already run.
  var _ACTION_SHORT_FLAGS = { x: 1 };
  function _actionSig(cmd, params) {
    // Process the WHOLE pipeline (do NOT stop at the first pipe): the transform after a `|` — awk / grep /
    // sort in a HANDOFF — is exactly what distinguishes `nxc … --users | tee` from `… | awk | grep | sort`,
    // so two commands that share a prefix but differ downstream must NOT collapse to the same signature.
    var toks = String(cmd || '').trim().split(/\s+/);
    var vals = {};
    ['target', 'domain', 'username', 'user', 'password', 'nthash', 'lhost', 'lport', 'rhost'].forEach(function (k) {
      var v = params && params[k]; if (v) vals[String(v).toLowerCase()] = 1;
    });
    var out = {};
    // Include the leading tool token too (i=0): the tool IS distinctive — `certipy find` and
    // `sccmhunter find` share the `find` subcommand but are NOT the same move, so dropping the tool made
    // one wrongly match the other. Shell keywords (`for`/`while`/`sudo`) fall out via the noise filter.
    for (var i = 0; i < toks.length; i++) {
      var raw = toks[i];
      if (/^(?:\||\|\||&&|;|>|>>|<)$/.test(raw)) continue;        // shell operators
      var t = raw.replace(/^["']+|["']+$/g, '');                  // strip surrounding quotes
      if (!t || t.indexOf('{{') >= 0) continue;                   // empty, or an unfilled template value slot

      if (t.charAt(0) === '-') {
        if (t.charAt(1) === '-' && t.length > 3) {                // long flag: keep action ones (--users), drop plumbing
          var lf = t.replace(/^--/, '').toLowerCase();
          if (!vals[lf] && !_PLUMBING_FLAGS[lf]) out[lf] = 1;
        } else {                                                  // short flag: drop plumbing (-u/-p/-d), keep action (-x)
          var sf = t.replace(/^-+/, '').toLowerCase();
          if (_ACTION_SHORT_FLAGS[sf]) out[sf] = 1;
        }
        continue;
      }
      var lt = t.toLowerCase();
      if (vals[lt] || _NOISE_WORDS[lt]) continue;                 // param value or shell/plumbing word
      if (/^\d+$/.test(t) || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(t)) continue; // number or IP
      if (/[\/@\\=]/.test(t) || t.indexOf('$') >= 0) continue;    // path/email/kv or shell var ($g)
      if (lt.length < 2) continue;
      out[lt] = 1;
    }
    return out;
  }
  // Has a command with these same action tokens already been run (is it in the activity ledger)? Used by
  // the coach to demote a suggested variant you have already executed, so it stops re-offering it.
  function commandWasRun(filledCmd, activities, params) {
    var sig = _actionSig(filledCmd, params), keys = Object.keys(sig);
    // Only DISTINCTIVE commands are confidently "already run": a verb+object enumeration or grant has 3+
    // action tokens (`bloodyad get writable`, `nxc ldap --users`, `bloodyad add dcsync`). A generic
    // tool+mode invocation — `nxc smb` (validate), `evil-winrm`, `impacket-psexec`, `certipy find` — is a
    // re-runnable check/shell that recurs across many moves; marking it run is high-confusion, low-value,
    // and is exactly what wrongly flagged an UNRUN `nxc smb` as ✓ ran. Bias to under-marking: re-suggesting
    // a command is a mild annoyance, wrongly hiding one you still need is the failure that keeps biting.
    if (keys.length < 3) return false;
    function covers(cmd) {
      if (!cmd) return false;
      var asig = _actionSig(cmd, params);
      for (var k = 0; k < keys.length; k++) { if (!asig[keys[k]]) return false; }
      return true;
    }
    for (var a = 0; a < (activities || []).length; a++) {
      var act = activities[a] || {};
      // Match the honest command OR the recovered dispatch label — an ATTACHED dump has no typed command,
      // so obol's recovered routing signature is the only record of what actually ran.
      if (covers(act.command) || covers(act.dispatch)) return true;
    }
    return false;
  }

  // Which {{tokens}} in a template are still unfilled (dependencies the operator must supply).
  function unfilledTokens(filledText) {
    var out = [], re = /\{\{([a-zA-Z0-9_]+)\}\}/g, m;
    while ((m = re.exec(filledText)) !== null) { if (out.indexOf(m[1]) === -1) out.push(m[1]); }
    return out;
  }

  OBOL.command = {
    shellQuote: shellQuote,
    openPorts: openPorts,
    buildContext: buildContext,
    fillTemplate: fillTemplate,
    fillCommand: fillCommand,
    fillAll: fillAll,
    commandWasRun: commandWasRun,
    unfilledTokens: unfilledTokens,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
