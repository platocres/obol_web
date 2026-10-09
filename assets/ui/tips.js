/*!
 * obol ui — tips.js — the calm tip feed that lives next to the Focus button in the context bar.
 * Cycles OBOL.TIPS one at a time, slowly (20s), pausing on hover. A "›" advances manually; a "×" turns
 * tips off (persisted per browser); when off, a quiet lightbulb remains to turn them back on. Honors
 * prefers-reduced-motion (no auto-advance, no fade). The ctxbar includes html() in its row and calls
 * refresh() after each render; only user actions (off/on) re-render the bar, the 20s cycle just swaps
 * the text in place so it never disrupts the pills or an open select.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U && U.esc ? U.esc(String(s == null ? '' : s)) : String(s == null ? '' : s); }

  var OFF_KEY = 'obol.tips-off';
  var CYCLE_MS = 20000;
  var IS_MAC = (function () { try { return /mac/i.test(navigator.platform || navigator.userAgent || ''); } catch (e) { return false; } })();
  var REDUCED = (function () { try { return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch (e) { return false; } })();

  var BULB = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 18h6"/><path d="M10 22h4"/><path d="M12 2a7 7 0 0 0-4 12.7c.6.5 1 1.3 1 2.1V17h6v-.2c0-.8.4-1.6 1-2.1A7 7 0 0 0 12 2z"/></svg>';
  var CHEV = '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m9 6 6 6-6 6"/></svg>';
  var EX = '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18"/></svg>';

  var idx = 0, _timer = null, _hover = false, _wired = false;

  function tips() { return (OBOL.TIPS && OBOL.TIPS.length) ? OBOL.TIPS : []; }
  function isOff() { try { return localStorage.getItem(OFF_KEY) === '1'; } catch (e) { return false; } }
  function setOff(v) { try { v ? localStorage.setItem(OFF_KEY, '1') : localStorage.removeItem(OFF_KEY); } catch (e) {} }

  function current() {
    var list = tips(); if (!list.length) return '';
    var t = list[((idx % list.length) + list.length) % list.length] || '';
    return IS_MAC ? t.replace(/Ctrl\+K/g, '⌘K') : t;
  }

  function html() {
    if (!tips().length) return '';
    if (isOff()) {
      return '<button type="button" class="tipfeed-on" title="Show tips" aria-label="Show tips">' + BULB + '</button>';
    }
    return '<div class="tipfeed" role="note" aria-label="obol tip">'
      + '<span class="tipfeed-ic" aria-hidden="true">' + BULB + '</span>'
      + '<span class="tipfeed-text">' + esc(current()) + '</span>'
      + '<button type="button" class="tipfeed-next" title="Next tip" aria-label="Next tip">' + CHEV + '</button>'
      + '<button type="button" class="tipfeed-off" title="Turn off tips" aria-label="Turn off tips">' + EX + '</button>'
      + '</div>';
  }

  function setText(el) {
    if (!el) return;
    if (REDUCED) { el.textContent = current(); return; }
    el.classList.add('is-fade');
    setTimeout(function () { el.textContent = current(); el.classList.remove('is-fade'); }, 160);
  }

  function advance(manual) {
    idx++;
    setText(document.querySelector('.tipfeed-text'));
    if (manual) restartTimer();
  }

  function stopTimer() { if (_timer) { clearInterval(_timer); _timer = null; } }
  function ensureTimer() {
    if (_timer || REDUCED || isOff()) return;
    _timer = setInterval(function () {
      if (isOff() || _hover) return;
      if (!document.querySelector('.tipfeed-text')) return;   // not on a screen with the feed
      advance(false);
    }, CYCLE_MS);
  }
  function restartTimer() { stopTimer(); ensureTimer(); }

  // Render (or re-render) the feed into its header slot, then make sure the cycle is running. Called once
  // at boot and again whenever the user toggles tips off/on (the 20s cycle itself just swaps the text).
  function mount() {
    var slot = document.getElementById('tip-slot');
    if (slot) slot.innerHTML = html();
    wire();
    ensureTimer();
  }

  function wire() {
    if (_wired) return; _wired = true;
    document.addEventListener('click', function (e) {
      var t = e.target;
      if (t.closest && t.closest('.tipfeed-next')) { e.preventDefault(); advance(true); return; }
      if (t.closest && t.closest('.tipfeed-off')) { e.preventDefault(); setOff(true); stopTimer(); mount(); return; }
      if (t.closest && t.closest('.tipfeed-on')) { e.preventDefault(); setOff(false); mount(); return; }
    });
    // pause the cycle while the pointer is over the feed
    document.addEventListener('mouseover', function (e) { if (e.target.closest && e.target.closest('.tipfeed')) _hover = true; });
    document.addEventListener('mouseout', function (e) { if (e.target.closest && e.target.closest('.tipfeed')) _hover = false; });
  }

  OBOL.tips = { html: html, mount: mount, refresh: mount, isOff: isOff };
})(typeof globalThis !== 'undefined' ? globalThis : this);
