/*!
 * obol ui — pivotstation.js — the shared Pivot Station card (OBOL.pivotStationUI), used by the Tools
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
    var p = (OBOL.store.active() || {}).params || {};
    var id = (OBOL.bind && OBOL.bind.effectiveIdentity) ? OBOL.bind.effectiveIdentity() : null;
    var subs = pivotSubnets();
    var chosen = ((OBOL.store.active() || {}).ui || {}).pivotSubnet;
    return { lhost: p.lhost || '', pivotHost: p.target || p.rhost || '', sshUser: (id && id.user) || p.username || 'user', subnet: chosen || subs[0] || '', port: '11601', os: 'linux' };
  }

  // card(open) -> the pivot station card HTML (same markup the Tools tab uses).
  function card(open) {
    return '<article class="tool-card station-card pivot-station lane-pivot' + (open ? ' open' : '') + '" data-station-id="pivot">'
      + '<div class="tool-card-head" role="button" tabindex="0" aria-expanded="' + (open ? 'true' : 'false') + '">'
      + '<div class="tool-card-title"><span class="station-badge">Kit</span><span class="tool-card-name">Pivot &amp; Tunnel</span><span class="tool-card-chev" aria-hidden="true">▾</span></div>'
      + '<p class="tool-card-sum">Download the local half of a tunnel (filled with your LHOST and the discovered subnet) and copy the on-host half to the target. obol writes both; you run both.</p></div>'
      + '<div class="tool-body"></div></article>';
  }

  // mount(body) -> render and wire the pivot station into a .tool-body element.
  function mount(body) {
    if (!OBOL.pivotkit) { body.innerHTML = '<p class="tb-hint">Pivot kit engine still loading, try again in a moment.</p>'; return; }
    var PK = OBOL.pivotkit;
    function draw() {
      var c = pivotCtx();
      var cur = ((OBOL.store.active() || {}).ui || {}).pivotTransport || PK.selectTransport(factKinds());
      if (!PK.transportById(cur)) cur = 'ligolo';
      var subs = pivotSubnets();
      var tchips = PK.transports().map(function (t) { return '<button type="button" class="tb-engine' + (t.id === cur ? ' on' : '') + '" data-transport="' + esc(t.id) + '" title="' + attr(t.teach) + '">' + esc(t.label) + '</button>'; }).join('');
      var teach = (PK.transportById(cur) || {}).teach || '';
      var subnetChips = subs.length
        ? subs.map(function (s) { return '<button type="button" class="bind-chip pv-sub' + (s === c.subnet ? ' on' : '') + '" data-sub="' + attr(s) + '">' + esc(s) + '</button>'; }).join('')
        : '<span class="bind-note">No internal subnet yet. From the foothold, run <code>ip route</code> (or ipconfig) and paste it into Evidence; the subnet fills here.</span>';
      var onhost = PK.onHostLines(cur, c, 'linux'), onhostWin = PK.onHostLines(cur, c, 'windows');
      var ohRows = onhost.length
        ? '<div class="tb-gloss"><div class="tb-gloss-lab">On The Target (copy and run)</div>'
          + onhost.map(function (l) { return '<div class="shk-pay"><div class="shk-pay-h"><span class="shk-pay-os linux">linux</span><button type="button" class="bind-chip pv-copy" data-copy="' + attr(l) + '">copy</button></div><code class="shk-pay-cmd">' + esc(l) + '</code></div>'; }).join('')
          + onhostWin.map(function (l) { return '<div class="shk-pay"><div class="shk-pay-h"><span class="shk-pay-os windows">windows</span><button type="button" class="bind-chip pv-copy" data-copy="' + attr(l) + '">copy</button></div><code class="shk-pay-cmd">' + esc(l) + '</code></div>'; }).join('')
          + '</div>'
        : '<p class="tb-hint">This transport is all local, nothing runs on the target.</p>';
      body.innerHTML = '<div class="shk">'
        + '<div class="station-engines"><span class="tb-engines-lab">Transport</span>' + tchips + '<span class="tb-engine-teach">' + esc(teach) + '</span></div>'
        + '<div class="bind-row"><span class="bind-lab">Internal Subnet</span><div class="bind-chips">' + subnetChips + '</div></div>'
        + '<div class="shk-actions"><button type="button" class="pv-dl">Download Local Half (.sh)</button>'
        + '<span class="tb-hint">LHOST ' + esc(c.lhost || 'set it in the sidebar') + ' &middot; via ' + esc(c.pivotHost || 'foothold') + '. obol writes it; you run it on your own box.</span></div>'
        + ohRows + '</div>';
    }
    draw();
    U.on(body, 'click', '.tb-engine', function (e, t) { OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.pivotTransport = t.getAttribute('data-transport'); }, 'pivot-transport'); draw(); });
    U.on(body, 'click', '.pv-sub', function (e, t) { OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.pivotSubnet = t.getAttribute('data-sub'); }, 'pivot-subnet'); draw(); });
    U.on(body, 'click', '.pv-copy', function (e, t) { U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Copied' : 'Copy failed', ok ? '' : 'err'); }); });
    U.on(body, 'click', '.pv-dl', function () {
      var c = pivotCtx();
      var cur = ((OBOL.store.active() || {}).ui || {}).pivotTransport || PK.selectTransport(factKinds());
      if (!PK.transportById(cur)) cur = 'ligolo';
      if (!c.subnet) { U.toast('Set the internal subnet first', 'err'); return; }
      var okd = downloadText('obol-pivot-' + cur + '.sh', PK.localKit(cur, c));
      U.toast(okd ? 'Pivot local half downloaded' : 'Download blocked by the browser', okd ? '' : 'err');
    });
  }

  OBOL.pivotStationUI = { card: card, mount: mount, downloadText: downloadText };
})(typeof globalThis !== 'undefined' ? globalThis : this);
