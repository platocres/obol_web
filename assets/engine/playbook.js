/*!
 * obol engine — playbook.js — turn a set of chosen pack commands into a runnable, parameterized bash
 * script. Pure over its arguments (no store reads/writes): the Checklist route owns the selection
 * (eng.playbook = [{id, idx}]) and passes it here to resolve and render.
 *
 * Variabilization: a command's param {{tokens}} ({{target}}, {{lhost}}, ...) become shell variables
 * ($TARGET, $LHOST, ...) so editing the header block re-targets the whole script. Every other token
 * (loot/workspace/fact-derived, e.g. {{hashfile}}) is filled to its concrete value by the normal
 * command filler; anything still unresolved is left as a <placeholder> the operator fills in.
 * Boundary: static, browser-local, no execution. The script is a copy/download/save artifact the
 * human runs themselves.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  // param token -> shell variable name. {{user}} and {{username}} both map to $USER.
  var PARAM_VARS = [
    ['target', 'TARGET'], ['domain', 'DOMAIN'], ['username', 'USER'], ['user', 'USER'],
    ['password', 'PASS'], ['nthash', 'NTHASH'], ['lhost', 'LHOST'], ['lport', 'LPORT'],
  ];
  var VAR_ORDER = ['TARGET', 'DOMAIN', 'USER', 'PASS', 'NTHASH', 'LHOST', 'LPORT'];

  function cmdsOf(a) {
    return (a && a.commands && a.commands.length) ? a.commands : [{ run: (a && a.command) || '', tool: a && a.tool }];
  }

  // [{id, idx}] -> [{id, idx, action, title, tool, note, template}], dropping entries the pack no longer has.
  function resolve(items, pack) {
    var byId = {}; (pack || []).forEach(function (a) { byId[a.id] = a; });
    return (items || []).map(function (it) {
      var a = byId[it.id]; if (!a) return null;
      var cmds = cmdsOf(a), c = cmds[it.idx] || cmds[0] || {};
      return { id: it.id, idx: it.idx, action: a, title: a.title || a.id, tool: c.tool || a.tool || '', note: c.note || '', template: c.run || a.command || '' };
    }).filter(Boolean);
  }

  // Replace the param {{tokens}} in a raw template with "$VAR" (quote-safe), recording which vars were
  // used. Leaves every non-param token untouched for the normal filler to resolve next.
  function toVars(template) {
    var tpl = String(template || ''), used = {};
    PARAM_VARS.forEach(function (pair) {
      var tok = pair[0], V = pair[1];
      var body = '\\{\\{' + tok + '\\}\\}';
      var any = new RegExp(body);
      if (any.test(tpl)) {
        used[V] = 1;
        tpl = tpl.replace(new RegExp("'" + body + "'", 'g'), '"$' + V + '"')
                 .replace(new RegExp('"' + body + '"', 'g'), '"$' + V + '"')
                 .replace(new RegExp(body, 'g'), '"$' + V + '"');
      }
    });
    return { tpl: tpl, used: used };
  }

  // One item -> { run, used }. Param tokens become $VARS; the rest is filled concretely; leftovers
  // become <placeholder>.
  function renderLine(item, facts, opts) {
    var v = toVars(item.template);
    var o = {}; for (var k in opts) if (Object.prototype.hasOwnProperty.call(opts, k)) o[k] = opts[k];
    o.action = item.action;
    var run = (OBOL.command && OBOL.command.fillTemplate) ? OBOL.command.fillTemplate(v.tpl, facts, o) : v.tpl;
    run = String(run).replace(/\{\{([a-z0-9_.:-]+)\}\}/gi, '<$1>');
    return { run: run.trim(), used: v.used };
  }

  function shellEsc(s) { return String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/`/g, '\\`').replace(/\$/g, '\\$'); }

  // Build the full bash script. ctx = { params, facts, profile, workspace, name }.
  function buildScript(items, ctx) {
    ctx = ctx || {};
    var params = ctx.params || {};
    var opts = { params: params, profile: ctx.profile, workspace: ctx.workspace };
    var usedAll = {}, body = [];
    (items || []).forEach(function (it, i) {
      var r = renderLine(it, ctx.facts, opts);
      if (!r.run) return;
      Object.keys(r.used).forEach(function (V) { usedAll[V] = 1; });
      var note = it.note ? ('  (' + String(it.note).replace(/[\r\n]+/g, ' ') + ')') : '';
      body.push('# [' + (i + 1) + '] ' + String(it.title).replace(/[\r\n]+/g, ' ') + note);
      body.push(r.run);
      body.push('');
    });
    var valOf = { TARGET: params.target, DOMAIN: params.domain, USER: params.username || params.user,
      PASS: params.password, NTHASH: params.nthash, LHOST: params.lhost, LPORT: params.lport };
    var varLines = VAR_ORDER.filter(function (V) { return usedAll[V]; }).map(function (V) {
      var val = valOf[V];
      return V + '="' + (val ? shellEsc(val) : ('<' + V.toLowerCase() + '>')) + '"';
    });
    var stamp = (function () { try { return new Date().toISOString().slice(0, 16).replace('T', ' '); } catch (e) { return ''; } })();
    var head = [
      '#!/usr/bin/env bash',
      '# obol playbook' + (ctx.name ? (': ' + String(ctx.name).replace(/[\r\n]+/g, ' ')) : ''),
      '# Generated ' + stamp + ' UTC. Review every command before running; set any <placeholder> values.',
      'set -o pipefail',
      '',
    ];
    if (varLines.length) head = head.concat(varLines, ['']);
    head = head.concat([
      'LOG="obol-playbook-$(date +%Y%m%d-%H%M%S).log"',
      'exec > >(tee -a "$LOG") 2>&1',
      '',
    ]);
    return head.join('\n') + body.join('\n') + '\n';
  }

  OBOL.playbook = { resolve: resolve, renderLine: renderLine, buildScript: buildScript, PARAM_VARS: PARAM_VARS };
  if (typeof module !== 'undefined' && module.exports) { module.exports = OBOL.playbook; }
})(typeof globalThis !== 'undefined' ? globalThis : this);
