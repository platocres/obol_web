/*!
 * obol ui - pivotstation.js - the shared Pivot Station card (OBOL.pivotStationUI), used by the Tools
 * tab AND the Cruise tab. A downloadable local-half tunnel .sh plus the on-host copy-chips, filled from
 * the engagement (LHOST, foothold host, the discovered internal subnet) by OBOL.pivotkit. obol writes
 * both halves; you run them. Nothing executes here. House style: no em or en dashes.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }
  function attr(s) { return U.attr ? U.attr(s) : esc(s); }

  function downloadText(filename, text) {
    try {
      var blob = new Blob([text], { type: 'text/x-shellscript' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a'); a.href = url; a.download = filename;
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
      return true;
    } catch (e) { return false; }
  }
  function factKinds() { try { return OBOL.store.factSet().kinds(); } catch (e) { return {}; } }
  function pivotSubnets() {
    try {
      var fs = OBOL.store.factSet(), subs = [];
      (fs.facts || []).forEach(function (f) { if ((f.kind === 'scan.local.routes' || f.kind === 'scan.local.interfaces') && f.state === 'supported' && f.value && f.value.subnets) subs = subs.concat(f.value.subnets); });
      return subs.filter(function (v, i, a) { return a.indexOf(v) === i; });
    } catch (e) { return []; }
  }
  function pivotCtx() {
    var manual = OBOL.bind && OBOL.bind.isManual && OBOL.bind.isManual();
    var p = (OBOL.store.active() || {}).params || {};
    var id = (OBOL.bind && OBOL.bind.effectiveIdentity) ? OBOL.bind.effectiveIdentity() : null;
    var subs = pivotSubnets();
    var chosen = ((OBOL.store.active() || {}).ui || {}).pivotSubnet;
    var chosenPort = ((OBOL.store.active() || {}).ui || {}).pivotPort;
    var pivotHost = manual ? '' : (p.target || p.rhost || '');
    var sshUser = (id && id.user) || (manual ? '' : p.username) || (manual ? '' : 'user');
    var fk = factKinds();
    var detOs = (OBOL.pivotkit && OBOL.pivotkit.detectTargetOs) ? OBOL.pivotkit.detectTargetOs(fk) : 'auto';
    return {
      lhost: p.lhost || '',
      pivotHost: pivotHost,
      sshUser: sshUser || (manual ? '' : 'user'),
      subnet: chosen || subs[0] || '',
      port: chosenPort || '11601',
      os: detOs === 'windows' ? 'windows' : 'linux',
      detectedOs: detOs,
    };
  }

  // card(open) -> the pivot station card HTML (same markup the Tools tab uses).
  function card(open) {
    return '<article class="tool-card station-card pivot-station lane-pivot' + (open ? ' open' : '') + '" data-station-id="pivot">'
      + '<div class="tool-card-head" role="button" tabindex="0" aria-expanded="' + (open ? 'true' : 'false') + '">'
      + '<div class="tool-card-title"><span class="station-badge">Kit</span><span class="tool-card-name">Pivot &amp; Tunnel</span><span class="tool-card-chev" aria-hidden="true">▾</span></div>'
      + '<p class="tool-card-sum">Zero-config local tunnel launcher: auto-detects tun0, picks a free port, and negotiates the best available tunnel (sshuttle, Ligolo-ng, or Chisel) for your discovered internal subnet.</p></div>'
      + '<div class="tool-body"></div></article>';
  }

  // mount(body) -> render and wire the pivot station into a .tool-body element.
  function mount(body) {
    if (!OBOL.pivotkit) { body.innerHTML = '<p class="tb-hint">Pivot kit engine still loading, try again in a moment.</p>'; return; }
    if (body.parentNode && body._obolMounted) {
      var fresh = body.cloneNode(false);
      body.parentNode.replaceChild(fresh, body);
      body = fresh;
    }
    body._obolMounted = true;
    var PK = OBOL.pivotkit;
    function draw() {
      var c = pivotCtx();
      var fk = factKinds();
      var savedMode = ((OBOL.store.active() || {}).ui || {}).pivotTransport;
      var cur = savedMode || 'auto';
      if (cur !== 'auto' && !PK.transportById(cur)) cur = 'auto';
      var effectiveId = (cur === 'auto') ? PK.selectTransport(fk) : cur;
      var subs = pivotSubnets();

      var subnetChips = (subs.length
        ? subs.map(function (s) { return '<button type="button" class="bind-chip pv-sub' + (s === c.subnet ? ' on' : '') + '" data-sub="' + attr(s) + '">' + esc(s) + '</button>'; }).join('')
        : '<span class="bind-note">Run Stage 3 On-Host Triage (or paste <code>ip route</code> / <code>ipconfig</code>) to auto-detect, or enter a CIDR:</span>')
        + '<input type="text" class="bind-input pv-subnet-input" value="' + attr(c.subnet) + '" placeholder="10.10.10.0/24" spellcheck="false" autocomplete="off" aria-label="Internal subnet CIDR">';

      var autoLabel = (cur === 'auto')
        ? ('Auto-Negotiate (prefers ' + ((PK.transportById(effectiveId) || {}).label || 'Ligolo-ng') + ', falls back automatically)')
        : ('Pinned: ' + ((PK.transportById(cur) || {}).label || cur));

      var onhostLin = PK.onHostLines(effectiveId, c, 'linux');
      var onhostWin = PK.onHostLines(effectiveId, c, 'windows');
      var ohRows = '';
      if (onhostLin.length || onhostWin.length) {
        var showLin = (c.detectedOs !== 'windows');
        var showWin = (c.detectedOs !== 'linux');
        ohRows = '<div class="tb-gloss"><div class="tb-gloss-lab">On The Target (if using Ligolo-ng / Chisel agent)</div>'
          + (showLin ? onhostLin.map(function (l) { return '<div class="shk-pay"><div class="shk-pay-h"><span class="shk-pay-os linux">linux</span><button type="button" class="bind-chip pv-copy" data-copy="' + attr(l) + '">copy</button></div><code class="shk-pay-cmd">' + esc(l) + '</code></div>'; }).join('') : '')
          + (showWin ? onhostWin.map(function (l) { return '<div class="shk-pay"><div class="shk-pay-h"><span class="shk-pay-os windows">windows</span><button type="button" class="bind-chip pv-copy" data-copy="' + attr(l) + '">copy</button></div><code class="shk-pay-cmd">' + esc(l) + '</code></div>'; }).join('') : '')
          + '</div>';
      } else {
        ohRows = '<p class="tb-hint">SSH tunnel mode is all-local on Kali - nothing needs to run on the target.</p>';
      }

      var tchips = '<button type="button" class="tb-engine' + (cur === 'auto' ? ' on' : '') + '" data-transport="auto">Auto (Best Available)</button>'
        + PK.transports().map(function (t) {
          return '<button type="button" class="tb-engine' + (t.id === cur ? ' on' : '') + '" data-transport="' + esc(t.id) + '" title="' + attr(t.teach) + '">' + esc(t.label) + '</button>';
        }).join('');
      var ports = ['11601', '443', '8443', '80', '53'];
      var portChips = ports.map(function (p) {
        return '<button type="button" class="bind-chip pv-port' + (String(p) === String(c.port) ? ' on' : '') + '" data-port="' + attr(p) + '">' + esc(p) + '</button>';
      }).join('')
      + '<input type="text" class="bind-input pv-port-input" value="' + attr(c.port) + '" placeholder="11601" style="width:78px;" spellcheck="false" autocomplete="off" aria-label="Egress port">';

      var overridesOpen = (cur !== 'auto') ? ' open' : '';
      var overridesHtml = '<details class="pv-overrides"' + overridesOpen + '>'
        + '<summary class="pv-overrides-sum">Manual transport / port override <span>(' + esc(autoLabel) + ')</span></summary>'
        + '<div class="pv-overrides-body">'
        + '<div class="station-engines"><span class="tb-engines-lab">Transport</span>' + tchips + '</div>'
        + '<div class="bind-row"><span class="bind-lab">Preferred Port</span><div class="bind-chips">' + portChips + '</div></div>'
        + '</div></details>';

      body.innerHTML = '<div class="shk">'
        + '<div class="bind-row"><span class="bind-lab">Internal Subnet</span><div class="bind-chips">' + subnetChips + '</div></div>'
        + '<div class="shk-actions">'
        + '<button type="button" class="btn-primary pv-dl">' + (cur === 'auto' ? 'Download Auto-Pivot (.sh)' : 'Download Local Half (.sh)') + '</button>'
        + '<span class="tb-hint">LHOST <code>' + esc(c.lhost || 'auto-detect tun0') + '</code> &middot; via <code>' + esc(c.pivotHost || 'foothold') + '</code> &middot; Run in a dedicated terminal tab (cleans up on Ctrl-C).</span>'
        + '</div>'
        + ohRows
        + overridesHtml
        + '</div>';
    }
    function updateCommands() {
      var c = pivotCtx();
      var fk = factKinds();
      var savedMode = ((OBOL.store.active() || {}).ui || {}).pivotTransport || 'auto';
      var effectiveId = (savedMode === 'auto' || !PK.transportById(savedMode)) ? PK.selectTransport(fk) : savedMode;
      var showLin = (c.detectedOs !== 'windows');
      var showWin = (c.detectedOs !== 'linux');
      var all = (showLin ? PK.onHostLines(effectiveId, c, 'linux') : []).concat(showWin ? PK.onHostLines(effectiveId, c, 'windows') : []);
      var rows = body.querySelectorAll('.shk-pay');
      for (var i = 0; i < rows.length && i < all.length; i++) {
        var cmdEl = rows[i].querySelector('.shk-pay-cmd');
        var btnEl = rows[i].querySelector('.pv-copy');
        if (cmdEl) cmdEl.textContent = all[i];
        if (btnEl) btnEl.setAttribute('data-copy', all[i]);
      }
    }
    draw();
    U.on(body, 'click', '.tb-engine', function (e, t) { OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.pivotTransport = t.getAttribute('data-transport'); }, 'pivot-transport'); draw(); });
    U.on(body, 'click', '.pv-sub', function (e, t) { OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.pivotSubnet = t.getAttribute('data-sub'); }, 'pivot-subnet'); draw(); });
    U.on(body, 'input', '.pv-subnet-input', function (e, t) {
      OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.pivotSubnet = t.value.trim(); }, 'pivot-subnet');
      updateCommands();
    });
    U.on(body, 'click', '.pv-port', function (e, t) {
      OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.pivotPort = t.getAttribute('data-port'); }, 'pivot-port');
      draw();
    });
    U.on(body, 'input', '.pv-port-input', function (e, t) {
      OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.pivotPort = t.value.trim(); }, 'pivot-port');
      updateCommands();
    });
    U.on(body, 'click', '.pv-copy', function (e, t) { U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Copied' : 'Copy failed', ok ? '' : 'err'); }); });
    U.on(body, 'click', '.pv-dl', function () {
      var c = pivotCtx();
      var fk = factKinds();
      var cur = ((OBOL.store.active() || {}).ui || {}).pivotTransport || 'auto';
      if (cur === 'auto' || !PK.transportById(cur)) {
        if (!c.subnet) { U.toast('Enter or select the internal subnet CIDR first.', 'err'); return; }
        var okAuto = downloadText('obol-pivot-auto.sh', PK.autoKit(c, fk));
        U.toast(okAuto ? 'Auto-pivot script downloaded' : 'Download blocked by the browser', okAuto ? '' : 'err');
        return;
      }
      var needsSubnet = ((PK.transportById(cur) || {}).requires || []).indexOf('SUBNET') >= 0;
      if (needsSubnet && !c.subnet) { U.toast('This tunnel needs the internal subnet. Pick or type a CIDR first.', 'err'); return; }
      var okd = downloadText('obol-pivot-' + cur + '.sh', PK.localKit(cur, c));
      U.toast(okd ? 'Pivot local half downloaded' : 'Download blocked by the browser', okd ? '' : 'err');
    });
  }

  OBOL.pivotStationUI = { card: card, mount: mount, downloadText: downloadText };
})(typeof globalThis !== 'undefined' ? globalThis : this);
