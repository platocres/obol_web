/*!
 * obol ui — routes/playbooks.js — PLAYBOOKS (ordered runbooks).
 * A playbook is a named, ordered batch of pack actions — not a second engine. This surface
 * lists the shipped runbooks (applicable ones, whose first step is offered on the current
 * facts, highlighted), and expanding one shows the step plan with each command FILLED from the
 * active engagement's facts + params (honoring per-step cmd variant + args_extra), per-step
 * require_approval marked, copy-per-step, and an "Export .sh" download. obol never runs a step —
 * it generates the command text for a human to review and run externally.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;

  function esc(s) { return U.esc(s); }
  function phaseChip(phase) {
    if (!phase) return '';
    return '<span class="ph-chip ph-' + esc(phase) + '">' + esc(phase) + '</span>';
  }

  // Fill one step's command variant (cmd is 1-based) from facts+params, appending args_extra.
  function fillStep(step, facts, opts) {
    if (!step.action) return { tool: '', run: '', note: '', missing: true };
    var index = (step.cmd || 1) - 1;
    var v = OBOL.command.fillCommand(step.action, facts, opts, index);
    var extra = step.args_extra ? OBOL.command.fillTemplate(step.args_extra, facts, opts) : '';
    return {
      tool: v.tool,
      run: v.filled + (extra ? ' ' + extra : ''),
      note: v.note || step.note || '',
    };
  }

  // The raw (unfilled) template for a step's variant — used to collect referenced {{tokens}}.
  function rawRun(step) {
    var a = step.action; if (!a) return '';
    var cmds = (a.commands && a.commands.length) ? a.commands : [{ run: a.command }];
    var idx = (step.cmd || 1) - 1; if (idx < 0 || idx >= cmds.length) idx = 0;
    var base = (cmds[idx] && cmds[idx].run) || a.command || '';
    return base + ' ' + (step.args_extra || '');
  }

  function referencedTokens(resolved) {
    var out = [], re = /\{\{([a-zA-Z0-9_]+)\}\}/g, m;
    resolved.forEach(function (s) {
      var t = rawRun(s);
      while ((m = re.exec(t)) !== null) { if (out.indexOf(m[1]) === -1) out.push(m[1]); }
    });
    return out;
  }

  function shVar(k) { return String(k).toUpperCase().replace(/[^A-Z0-9_]/g, '_'); }

  // Build a runnable bash script for a playbook: shebang, caveat header, set -o pipefail, a
  // variables preamble from engagement params (referenced {{k}} -> shell vars), then one
  // commented section per step with the filled command.
  function exportScript(pb, facts, opts) {
    var resolved = OBOL.playbooks.resolveSteps(pb);
    var ctx = OBOL.command.buildContext(facts, opts);
    var L = [];
    L.push('#!/usr/bin/env bash');
    L.push('#');
    L.push('# OBOL playbook — ' + pb.title + ' (' + pb.name + ')');
    if (pb.description) L.push('# ' + pb.description);
    L.push('#');
    L.push('# CAVEAT: obol generates command text only — it NEVER runs anything. Review every');
    L.push('# command, confirm the target is in scope, and run each step yourself. A run is not');
    L.push('# a win: prove the result. Steps marked [REQUIRES APPROVAL] are noisy/risky.');
    L.push('# Generated ' + new Date().toISOString().slice(0, 10) + ' — browser-local, no backend.');
    L.push('set -o pipefail');
    L.push('');

    // variables preamble — referenced tokens that the engagement can currently fill.
    var refs = referencedTokens(resolved);
    var pre = [];
    refs.forEach(function (k) {
      var val = ctx[k];
      if (val === undefined || val === null || val === '') return;
      if (String(val).charAt(0) === '<') return; // placeholder like <target> — leave unset
      pre.push(shVar(k) + '=' + OBOL.command.shellQuote(String(val)));
    });
    if (pre.length) {
      L.push('# Variables from the active engagement (values are already inlined below;');
      L.push('# these are here for reference / reuse).');
      L = L.concat(pre);
      L.push('');
    }

    // one commented section per step, with the filled command.
    resolved.forEach(function (step, i) {
      var head = '# --- Step ' + (i + 1) + ': ' + step.label;
      if (step.require_approval) head += '   [REQUIRES APPROVAL]';
      head += ' ---';
      L.push(head);
      if (step.note) L.push('# ' + step.note);
      if (!step.action) { L.push('# (unresolved action: ' + step.action_id + ' — not in current packs)'); L.push(''); return; }
      var f = fillStep(step, facts, opts);
      var unfilled = OBOL.command.unfilledTokens(f.run);
      if (unfilled.length) L.push('# needs: ' + unfilled.join(', '));
      L.push(f.run);
      L.push('');
    });

    return L.join('\n') + '\n';
  }

  function download(name, text, mime) {
    var blob = new Blob([text], { type: mime });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = name;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  }

  function stepRow(step, i, facts, opts) {
    var approval = step.require_approval
      ? '<span class="pill pill-warn" title="Noisy/risky — obol crafts on approval, never silently">requires approval</span>'
      : '';
    if (!step.action) {
      return '<li class="pb-step pb-step-missing">'
        + '<div class="pb-step-head"><span class="pb-step-n">' + (i + 1) + '</span>'
        + '<span class="pb-step-label">' + esc(step.label) + '</span>' + approval + '</div>'
        + '<div class="coach-empty">Action <code>' + esc(step.action_id) + '</code> is not in the current packs.</div>'
        + '</li>';
    }
    var f = fillStep(step, facts, opts);
    var unfilled = OBOL.command.unfilledTokens(f.run);
    var warn = unfilled.length
      ? '<div class="cmd-needs">needs: ' + unfilled.map(function (t) { return '<code>' + esc(t) + '</code>'; }).join(', ') + '</div>'
      : '';
    var note = f.note ? '<div class="cmd-note">' + esc(f.note) + '</div>' : '';
    return '<li class="pb-step">'
      + '<div class="pb-step-head"><span class="pb-step-n">' + (i + 1) + '</span>'
      + '<span class="pb-step-label">' + esc(step.label) + '</span>' + approval
      + '<span class="pb-step-aid" title="pack action">' + esc(step.action_id) + '</span></div>'
      + '<div class="cmd">'
      + '<div class="cmd-head"><span class="cmd-tag">' + esc(f.tool || 'cmd') + '</span>'
      + '<button class="btn-copy" data-copy="' + U.attr(f.run) + '" title="Copy command">copy</button></div>'
      + '<pre class="cmd-run"><code>' + esc(f.run) + '</code></pre>'
      + note + warn
      + '</div></li>';
  }

  function playbookCard(pb, facts, opts, isApplicable) {
    var resolved = OBOL.playbooks.resolveSteps(pb);
    var head = '<summary class="pb-summary">'
      + '<span class="pb-title">' + esc(pb.title || pb.name) + '</span>'
      + phaseChip(pb.phase)
      + (isApplicable ? '<span class="pill pill-ok" title="First step is offered on your current facts">applicable now</span>' : '')
      + '<span class="pb-count">' + resolved.length + ' step' + (resolved.length === 1 ? '' : 's') + '</span>'
      + '</summary>';
    var body = '<div class="pb-body">'
      + (pb.description ? '<p class="pb-desc">' + esc(pb.description) + '</p>' : '')
      + '<div class="pb-toolbar"><button class="btn-primary btn-export" data-pb="' + U.attr(pb.name) + '">Export .sh</button></div>'
      + '<ol class="pb-steps">'
      + resolved.map(function (s, i) { return stepRow(s, i, facts, opts); }).join('')
      + '</ol></div>';
    return '<details class="pb-card' + (isApplicable ? ' pb-applicable' : '') + '" data-pb="' + U.attr(pb.name) + '"'
      + (isApplicable ? ' open' : '') + '>' + head + body + '</details>';
  }

  function render(ctx) {
    var eng = OBOL.store.active();
    var facts = OBOL.store.factSet();
    var opts = { params: (eng && eng.params) || {}, profile: (eng && eng.profile) || {}, workspace: OBOL.workspace.tokens(eng) };

    var all = OBOL.playbooks.list();
    var applicable = OBOL.playbooks.applicable(facts);
    var appSet = {};
    applicable.forEach(function (p) { appSet[p.name] = true; });

    var html = '<section class="playbooks">';
    html += '<h1 class="route-h1">Playbooks</h1>';
    html += '<p class="route-sub">Ordered runbooks — a named batch of pack actions run as one deliberate move. '
      + 'Each step is an existing pack action; obol only generates the command text, gated per step. '
      + 'Applicable runbooks (first step offered on your current facts) are highlighted.</p>';

    if (!all.length) {
      html += '<div class="coach-empty">No playbooks loaded. Build the bundle with <code>node tools/build-playbooks.js</code>.</div>';
      return html + '</section>';
    }

    // Applicable first, then by phase/name (mirrors obol-local applicable_playbooks sort).
    var ordered = all.slice().sort(function (a, b) {
      var aa = appSet[a.name] ? 0 : 1, ba = appSet[b.name] ? 0 : 1;
      if (aa !== ba) return aa - ba;
      if ((a.phase || '') !== (b.phase || '')) return (a.phase || '').localeCompare(b.phase || '');
      return a.name.localeCompare(b.name);
    });

    html += '<div class="pb-meta">' + applicable.length + ' of ' + all.length + ' applicable now</div>';
    html += '<div class="pb-list">';
    ordered.forEach(function (pb) { html += playbookCard(pb, facts, opts, !!appSet[pb.name]); });
    html += '</div>';

    html += '</section>';
    return html;
  }

  function mounted(ctx) {
    var mount = ctx.mount;

    U.on(mount, 'click', '.btn-copy', function (e, t) {
      U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Command copied' : 'Copy failed', ok ? '' : 'err'); });
    });

    U.on(mount, 'click', '.btn-export', function (e, t) {
      e.preventDefault();
      var name = t.getAttribute('data-pb');
      var pb = OBOL.playbooks.get(name);
      if (!pb) { U.toast('Playbook not found', 'err'); return; }
      var eng = OBOL.store.active();
      var facts = OBOL.store.factSet();
      var opts = { params: (eng && eng.params) || {}, profile: (eng && eng.profile) || {}, workspace: OBOL.workspace.tokens(eng) };
      download(pb.name + '.sh', exportScript(pb, facts, opts), 'text/x-shellscript');
      U.toast('Exported ' + pb.name + '.sh');
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.playbooks = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
