/*!
 * obol ui — util.js — tiny DOM/util helpers (no framework).
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function attr(s) { return esc(s); }

  // First sentence of a longer string (for one-line "why").
  function firstSentence(s) {
    s = String(s || '').trim();
    var m = s.match(/^(.*?[.!?])(\s|$)/);
    return m ? m[1] : s;
  }

  function copy(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).then(function () { return true; }, function () { return fallbackCopy(text); });
    }
    return Promise.resolve(fallbackCopy(text));
  }
  function fallbackCopy(text) {
    try {
      var ta = document.createElement('textarea');
      ta.value = text; ta.setAttribute('readonly', ''); ta.style.position = 'absolute'; ta.style.left = '-9999px';
      document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
      return true;
    } catch (e) { return false; }
  }

  var _toastEl = null;
  function toast(msg, kind) {
    try {
      if (!_toastEl) {
        _toastEl = document.createElement('div');
        _toastEl.className = 'obol-toast';
        _toastEl.setAttribute('role', 'status');
        _toastEl.setAttribute('aria-live', 'polite');
        document.body.appendChild(_toastEl);
      }
      _toastEl.textContent = msg;
      _toastEl.className = 'obol-toast show' + (kind ? (' ' + kind) : '');
      clearTimeout(_toastEl._t);
      _toastEl._t = setTimeout(function () { _toastEl.className = 'obol-toast'; }, 2200);
    } catch (e) {}
  }

  // Delegated click helper: on(container, selector, handler).
  function on(container, evt, selector, handler) {
    container.addEventListener(evt, function (e) {
      var t = e.target.closest(selector);
      if (t && container.contains(t)) handler(e, t);
    });
  }

  OBOL.util = { esc: esc, attr: attr, firstSentence: firstSentence, copy: copy, toast: toast, on: on };
})(typeof globalThis !== 'undefined' ? globalThis : this);
