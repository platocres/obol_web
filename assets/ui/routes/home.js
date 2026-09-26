/*!
 * obol ui — routes/home.js — engagement dashboard: context, coverage, recent evidence,
 * and a jump to the coach. Derived entirely from the active engagement's facts/state.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }

  function render() {
    var eng = OBOL.store.active();
    if (!eng) return '<section class="home"><h1 class="route-h1">No engagement</h1></section>';
    var facts = OBOL.store.factSet();
    var pack = OBOL.packs.actions();
    var ranked = OBOL.pack.nextActions(facts, pack);
    var phaseIdx = OBOL.phases.frontierIndex(facts);
    var reached = OBOL.phases.targetPhase(facts);

    // phase spine
    var spine = OBOL.phases.PHASES.map(function (p, i) {
      var on = i <= OBOL.phases.phaseIndex(reached);
      var cur = i === phaseIdx;
      return '<span class="spine-node ph-' + esc(p) + (on ? ' reached' : '') + (cur ? ' frontier' : '') + '">' + esc(p) + '</span>';
    }).join('<span class="spine-sep">›</span>');

    var acts = (eng.activities || []).slice(0, 6);
    var recent = acts.length ? acts.map(function (a) {
      return '<li class="feed-item"><span class="feed-cmd">' + esc((a.command || a.source || 'evidence').slice(0, 80)) + '</span>'
        + (a.produced && a.produced.length ? '<span class="feed-facts">+' + a.produced.length + ' facts</span>' : '') + '</li>';
    }).join('') : '<li class="facts-empty">No evidence recorded yet.</li>';

    return '<section class="home">'
      + '<h1 class="route-h1">' + esc(eng.name) + '</h1>'
      + '<div class="home-spine">' + spine + '</div>'
      + '<div class="home-cards">'
      + '<div class="hc"><div class="hc-n">' + (eng.targets || []).length + '</div><div class="hc-l">targets</div></div>'
      + '<div class="hc"><div class="hc-n">' + Object.keys(facts.kinds()).length + '</div><div class="hc-l">proven facts</div></div>'
      + '<div class="hc"><div class="hc-n">' + ranked.length + '</div><div class="hc-l">available moves</div></div>'
      + '<div class="hc"><div class="hc-n">' + (eng.credentials || []).length + '</div><div class="hc-l">credentials</div></div>'
      + '</div>'
      + '<div class="home-next"><h2 class="coach-sec-h">Best next move</h2>'
      + (ranked.length ? ('<div class="home-move"><strong>' + esc(ranked[0].title) + '</strong><p>' + esc(U.firstSentence(ranked[0].hypothesis || '')) + '</p><a class="btn-primary" href="#/path">Open the coach →</a></div>')
        : '<div class="coach-empty">Add a target fact or paste a scan on Evidence to begin.</div>')
      + '</div>'
      + '<div class="home-feed"><h2 class="coach-sec-h">Recent evidence</h2><ul class="feed">' + recent + '</ul></div>'
      + '</section>';
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.home = { render: render };
})(typeof globalThis !== 'undefined' ? globalThis : this);
