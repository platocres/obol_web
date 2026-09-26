/*!
 * obol engine — workspace.js
 * Models the on-disk working directory the operator runs commands from (their Kali box), so obol
 * web can fill concrete output paths into suggested commands and tell the user exactly where a
 * file landed and how to attach it. obol web never touches the filesystem — this only *generates*
 * paths and a one-time scaffold command; the operator runs it and attaches the results.
 *
 * The attacker box is Kali/Linux, so paths are POSIX. The layout mirrors obol-local's `scans/`
 * convention (tool output → scans/). Default root is box-centric on labs, engagement-centric on
 * exams. Pure + self-contained (window / worker / node).
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  var LAYOUT = { scans: 'scans', loot: 'loot', exploit: 'exploit', www: 'www', proof: 'proof' };
  var DEFAULT_BASE = '~/engagements';

  function slugify(s) {
    return String(s || '').trim().toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 64) || 'run';
  }
  // Sanitize a working-directory path the operator typed/pasted. obol drops the path into generated
  // commands UNQUOTED (e.g. `-oN <root>/scans/…`), so a stray shell metacharacter — a `]`, or worse a
  // `;`/backtick/`$(…)` — would leak into a command they paste into their own terminal. Strip shell-
  // special characters and whitespace; keep ordinary POSIX path characters (~ / . _ - and word chars).
  function sanitizeRoot(s) {
    return String(s == null ? '' : s).trim()
      .replace(/[;&|`$(){}\[\]<>*?!'"\\\s]+/g, '')
      .replace(/\/{2,}/g, '/').replace(/\/+$/, '');
  }
  // Join POSIX path parts, collapsing duplicate slashes (a leading ~ or / is preserved).
  function join() {
    var parts = [].slice.call(arguments).filter(function (p) { return p !== undefined && p !== null && p !== ''; });
    return parts.join('/').replace(/([^:])\/{2,}/g, '$1/').replace(/\/+$/, '') || '/';
  }
  // Lab runs are box-centric (a dir per box); exams are engagement-centric (one dir for the exam).
  function slugFor(eng, isExam) {
    if (!eng) return 'run';
    if (!isExam) {
      var t = (eng.targets || [])[0];
      if (t && (t.hostname || t.ip)) return slugify(t.hostname || t.ip);
    }
    return slugify(eng.name);
  }
  function defaultRoot(base, eng, isExam) { return join(base || DEFAULT_BASE, slugFor(eng, isExam)); }
  function rootFor(eng) { return (eng && eng.workspace && eng.workspace.root) ? sanitizeRoot(eng.workspace.root) : ''; }
  function isConfigured(eng) { return !!rootFor(eng); }

  // Concrete output directories as {{token}} values. With no workspace set they fall back to
  // relative dirs (scans/, loot/…) so commands still form — just not absolute.
  function dirs(eng) {
    var r = rootFor(eng);
    function d(k) { return r ? join(r, LAYOUT[k]) : LAYOUT[k]; }
    return { root: r || '.', scandir: d('scans'), lootdir: d('loot'), exploitdir: d('exploit'), wwwdir: d('www'), proofdir: d('proof') };
  }
  var tokens = dirs;

  // The one-time "set up your workspace" command — create the tree and cd into it.
  function scaffold(eng) {
    var r = rootFor(eng);
    var subs = Object.keys(LAYOUT).map(function (k) { return LAYOUT[k]; }).join(',');
    return r ? ('mkdir -p ' + r + '/{' + subs + '} && cd ' + r) : ('mkdir -p {' + subs + '}');
  }

  OBOL.workspace = {
    LAYOUT: LAYOUT, DEFAULT_BASE: DEFAULT_BASE,
    slugify: slugify, sanitizeRoot: sanitizeRoot, join: join, slugFor: slugFor, defaultRoot: defaultRoot,
    rootFor: rootFor, isConfigured: isConfigured, dirs: dirs, tokens: tokens, scaffold: scaffold,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
