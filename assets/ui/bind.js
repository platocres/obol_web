/*!
 * obol ui — bind.js — the shared ENGAGEMENT-BINDING bar (reused by Tools and the Library Commands lens).
 *
 * One calm neon-glass band that answers "what will these commands fill with?": the target, the active
 * identity (every credential the ledger and the facts know, masked with hover-reveal), the open ports,
 * and a wordlist. It writes the engagement params the rest of obol already reads, and exposes
 * OBOL.bind.context() in the nested shape the Tool Builder autofill consumes (target.* / context.* /
 * workspace.*). Identity selection is LOCAL by default (it only steers the previews here); "Make
 * Active" is the explicit, engagement-wide pin via OBOL.creds.activate. A manual-fill toggle turns all
 * autofill off so a standalone user supplies every parameter. Presentation only, one store, one filler.
 * House style: no em or en dashes.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }
  function attr(s) { return U.attr ? U.attr(s) : esc(s); }

  var DEFAULT_WORDLIST = '/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt';
  // A compact, self-contained palette of the wordlists a student reaches for most. Grouped so the chips
  // read as "directories / files / subdomains / passwords" without needing the Workbench engine loaded.
  var WORDLISTS = [
    { label: 'raft small', path: '/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt', kind: 'web' },
    { label: 'raft medium dirs', path: '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt', kind: 'web' },
    { label: 'common.txt', path: '/usr/share/seclists/Discovery/Web-Content/common.txt', kind: 'web' },
    { label: 'dirb common', path: '/usr/share/wordlists/dirb/common.txt', kind: 'web' },
    { label: 'subdomains 5k', path: '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt', kind: 'dns' },
    { label: 'rockyou', path: '/usr/share/wordlists/rockyou.txt', kind: 'pw' },
  ];

  // ---- state (per engagement, under eng.ui.bind) ----
  function eng() { try { return OBOL.store.active(); } catch (e) { return null; } }
  function params() { var e = eng(); return (e && e.params) || {}; }
  function state() { var e = eng(); return (e && e.ui && e.ui.bind) || {}; }
  function setState(patch, reason) {
    OBOL.store.update(function (e) { e.ui = e.ui || {}; e.ui.bind = Object.assign({}, e.ui.bind || {}, patch); }, reason || 'bind');
  }
  function setParam(key, val) { OBOL.store.update(function (e) { e.params = e.params || {}; e.params[key] = val; }, 'params'); }
  function facts() { try { return OBOL.store.factSet(); } catch (e) { return new OBOL.facts.FactSet([]); } }

  // The selected (local) identity, resolved from the stored key against the live credential set.
  function identities() { try { return OBOL.creds.gather(); } catch (e) { return []; } }
  function selectedIdentity() {
    var key = state().identityKey;
    if (!key) return null;
    var list = identities();
    for (var i = 0; i < list.length; i++) { if (OBOL.creds.keyOf(list[i]) === key) return list[i]; }
    return null;
  }

  // ---- the context the Tool Builder autofill reads ----
  // Manual mode returns an empty context (nothing autofills, the operator types every field). Otherwise
  // target/domain/username/port/wordlist flow from the engagement, with the LOCAL identity overriding
  // the active-params identity for previews here.
  function context() {
    if (state().manual) return { target: {}, context: {}, workspace: {} };
    var p = params(), id = selectedIdentity();
    var tgt = p.target || p.rhost || '';
    var ti = {}; try { ti = OBOL.store.targetIdentity && OBOL.store.targetIdentity(tgt) || {}; } catch (e) {}
    return {
      target: { value: tgt, ip: p.rhost || p.ip || tgt, hostname: p.hostname || ti.hostname || ti.fqdn || '' },
      context: {
        domain: (id && id.domain) || p.domain || ti.domain || '',
        username: (id && id.user) || p.username || '',
        port: state().port || '',
      },
      workspace: {
        wordlist: state().wordlist || p.wordlist || DEFAULT_WORDLIST,
        outputDir: p.outputDir || 'loot',
        hashfile: p.hashfile || 'hashes.txt',
      },
    };
  }

  // ---- render ----
  function chip(txt, dataAttrs, cls) { return '<button type="button" class="bind-chip' + (cls ? ' ' + cls : '') + '"' + (dataAttrs || '') + '>' + esc(txt) + '</button>'; }

  function identityRow() {
    var list = identities();
    var selKey = state().identityKey;
    var activeKey = ''; try { activeKey = OBOL.creds.activeKey(); } catch (e) {}
    if (!list.length) {
      return '<div class="bind-row"><span class="bind-lab">Identity</span>'
        + '<span class="bind-note">No credentials yet. Prove one from Evidence, or add one in the sidebar, and it appears here.</span></div>';
    }
    var chips = list.map(function (c) {
      var k = OBOL.creds.keyOf(c);
      var on = k === selKey || (!selKey && k === activeKey);
      var tcls = c.type === 'NT' ? 'bt-nt' : (c.type === 'OT' ? 'bt-ot' : 'bt-pw');
      var who = (c.domain ? c.domain + '\\' : '') + c.user;
      return '<button type="button" class="bind-id' + (on ? ' on' : '') + '" data-id-key="' + attr(k) + '"'
        + ' aria-pressed="' + (on ? 'true' : 'false') + '" title="Use ' + attr(who) + ' in these commands">'
        + '<span class="bind-id-who">' + esc(who) + '</span>'
        + '<span class="bind-id-type ' + tcls + '">' + esc(c.type === 'NT' ? 'hash' : (c.type === 'OT' ? 'secret' : 'pw')) + '</span>'
        + (k === activeKey ? '<span class="bind-id-act" title="Active engagement-wide">active</span>' : '')
        + '</button>';
    }).join('');
    var sel = selectedIdentity();
    var secretBox = '';
    if (sel) {
      var secret = sel.secret || sel.nthash || '';
      secretBox = '<div class="bind-secret">'
        + '<span class="bind-lab">Secret</span>'
        + (secret
          ? '<code class="bind-mask" data-secret="' + attr(secret) + '" title="Hover to reveal">' + esc('*'.repeat(Math.min(12, secret.length))) + '</code>'
            + '<button type="button" class="bind-chip bind-reveal">Reveal</button>'
            + '<button type="button" class="bind-chip bind-copy-secret" data-copy="' + attr(secret) + '">Copy</button>'
          : '<span class="bind-note">No secret stored for this identity.</span>')
        + (OBOL.creds.keyOf(sel) !== activeKey ? '<button type="button" class="bind-chip bind-makeactive">Make Active</button>' : '<span class="bind-note">This identity is active engagement-wide.</span>')
        + '</div>';
    }
    return '<div class="bind-row"><span class="bind-lab">Identity</span><div class="bind-ids">' + chips + '</div></div>' + secretBox;
  }

  function portsRow() {
    var open = [];
    try { open = OBOL.command.openPorts(facts()) || []; } catch (e) {}
    if (!open.length) return '';
    var cur = String(state().port || '');
    var chips = open.map(function (p) {
      return '<button type="button" class="bind-chip bind-port' + (String(p) === cur ? ' on' : '') + '" data-port="' + attr(p) + '">' + esc(p) + '</button>';
    }).join('');
    return '<div class="bind-row"><span class="bind-lab">Open Ports</span><div class="bind-chips">' + chips
      + (cur ? '<button type="button" class="bind-chip bind-port-clear">clear</button>' : '') + '</div></div>';
  }

  function wordlistRow() {
    var cur = state().wordlist || params().wordlist || '';
    var chips = WORDLISTS.map(function (w) {
      return '<button type="button" class="bind-chip bind-wl' + (w.path === cur ? ' on' : '') + '" data-wl="' + attr(w.path) + '" title="' + attr(w.path) + '">' + esc(w.label) + '</button>';
    }).join('');
    return '<div class="bind-row"><span class="bind-lab">Wordlist</span><div class="bind-chips">' + chips + '</div></div>';
  }

  // render(opts) -> the band HTML. opts.compact shrinks it for the Library lens bar.
  function render(opts) {
    opts = opts || {};
    var p = params(), st = state();
    var tgt = p.target || p.rhost || '';
    var manual = !!st.manual;
    var head = '<div class="bind-head"><span class="bind-title">Engagement Binding</span>'
      + '<label class="bind-manual" title="Turn off autofill and type every parameter yourself">'
      + '<input type="checkbox" class="bind-manual-cb"' + (manual ? ' checked' : '') + '> <span>Manual Fill</span></label></div>';
    var targetRow = '<div class="bind-row"><span class="bind-lab">Target</span>'
      + '<input type="text" class="bind-target" value="' + attr(tgt) + '" placeholder="10.10.10.10 or host.domain" autocomplete="off" spellcheck="false"' + (manual ? ' disabled' : '') + '></div>';
    var body = manual
      ? '<div class="bind-row"><span class="bind-note">Manual fill is on. Autofill is paused, every command starts blank for you to complete.</span></div>'
      : (targetRow + identityRow() + portsRow() + wordlistRow());
    return '<section class="bind' + (opts.compact ? ' bind-compact' : '') + ' cv-shead cv-sh-teal">' + head + body + '</section>';
  }

  // ---- mount ----
  // mount(el, opts): wire delegated handlers on the band's container. opts.onChange() fires after any
  // binding change so the host can re-render its command previews. The band re-renders itself in place.
  function mount(el, opts) {
    opts = opts || {};
    if (!el) return;
    function changed() { try { el.innerHTML = render(opts); } catch (e) {} if (opts.onChange) try { opts.onChange(); } catch (e) {} }

    U.on(el, 'change', '.bind-manual-cb', function (e, t) { setState({ manual: !!t.checked }, 'bind-manual'); changed(); });
    U.on(el, 'input', '.bind-target', function (e, t) { setParam('target', t.value.trim()); if (opts.onChange) opts.onChange(); });
    U.on(el, 'change', '.bind-target', function (e, t) { setParam('target', t.value.trim()); changed(); });
    U.on(el, 'click', '.bind-id', function (e, t) {
      var key = t.getAttribute('data-id-key');
      setState({ identityKey: state().identityKey === key ? '' : key }, 'bind-id'); changed();
    });
    U.on(el, 'click', '.bind-makeactive', function () { var id = selectedIdentity(); if (id) OBOL.creds.activate(id); changed(); });
    U.on(el, 'click', '.bind-reveal', function (e, t) {
      var mask = el.querySelector('.bind-mask'); if (!mask) return;
      var showing = mask.getAttribute('data-shown') === '1';
      mask.textContent = showing ? '*'.repeat(Math.min(12, (mask.getAttribute('data-secret') || '').length)) : (mask.getAttribute('data-secret') || '');
      mask.setAttribute('data-shown', showing ? '0' : '1');
      t.textContent = showing ? 'Reveal' : 'Hide';
    });
    U.on(el, 'click', '.bind-copy-secret', function (e, t) { U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Secret copied' : 'Copy failed', ok ? '' : 'err'); }); });
    U.on(el, 'click', '.bind-port', function (e, t) { setState({ port: t.getAttribute('data-port') }, 'bind-port'); changed(); });
    U.on(el, 'click', '.bind-port-clear', function () { setState({ port: '' }, 'bind-port'); changed(); });
    U.on(el, 'click', '.bind-wl', function (e, t) {
      var path = t.getAttribute('data-wl');
      var next = state().wordlist === path ? '' : path;
      setState({ wordlist: next }, 'bind-wl');
      setParam('wordlist', next);
      changed();
    });
  }

  OBOL.bind = { render: render, mount: mount, context: context, selectedIdentity: selectedIdentity, DEFAULT_WORDLIST: DEFAULT_WORDLIST };
})(typeof globalThis !== 'undefined' ? globalThis : this);
