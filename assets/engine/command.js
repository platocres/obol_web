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

    // credentials: prefer credential.available then credential.plaintext
    var creds = facts.values('credential.available');
    if (!creds.length) creds = facts.values('credential.plaintext');
    if (creds.length) {
      if (creds[0].user && !ctx.user) ctx.user = creds[0].user;
      if (creds[0].password && !ctx.password) ctx.password = creds[0].password;
    }
    for (var c = 0; c < creds.length; c++) {
      var nt = creds[c].nthash || creds[c].hash;
      if (nt) { ctx.nthash = nt; break; }
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

  // Fill a command variant of an action (0-based). Returns {tool, run, note, filled}.
  function fillCommand(action, facts, opts, index) {
    opts = opts || {};
    index = index || 0;
    var commands = (action.commands && action.commands.length) ? action.commands : [{ run: action.command, tool: action.tool }];
    if (index < 0 || index >= commands.length) index = 0;
    var c = commands[index] || {};
    return {
      tool: c.tool || action.tool || '',
      note: c.note || '',
      run: c.run || action.command || '',
      filled: fillTemplate(c.run || action.command || '', facts, opts),
    };
  }

  // All variants of an action, filled — for the coach to show "many commands".
  function fillAll(action, facts, opts) {
    var commands = (action.commands && action.commands.length) ? action.commands : [{ run: action.command, tool: action.tool }];
    return commands.map(function (c, i) { return fillCommand(action, facts, opts, i); });
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
    unfilledTokens: unfilledTokens,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
