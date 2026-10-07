/*!
 * obol engine - resolve.js - OBOL.resolve
 *
 * The reference resolver: it turns a FACT into the exact, pre-filled answer, not a generic link. The first
 * resolver is GTFOBins. The parser already identifies the specific sudo / SUID binary (host.js mints
 * privesc.sudo_binary {bin,...} and privesc.suid_candidate {paths:[...]}); this looks that binary up in the
 * bundled GTFOBins data (data/gtfobins.js, distilled from gtfobins.github.io, GPL-3.0) and returns the exact
 * shell escape for the sudo or SUID context, plus the deep link to the authoritative page.
 *
 * Pure and UI-free. The Next Steps canvas (path.js) renders what this returns; the Workbench reuses it too.
 * Accuracy note: the sudo form is GTFOBins' first shell code prefixed with `sudo `; the SUID form prefers the
 * `-p` variant GTFOBins publishes. The deep link is always offered so the exact page can be confirmed.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var R = OBOL.resolve = OBOL.resolve || {};

  // a binary name or path -> its GTFOBins key (basename, lowercased)
  R.binKey = function (name) { return String(name == null ? '' : name).split('/').pop().trim().toLowerCase(); };

  R.gtfobinsUrl = function (binOrKey) { return 'https://gtfobins.github.io/gtfobins/' + R.binKey(binOrKey) + '/'; };

  // The exact shell escape for a context. context: 'sudo' | 'suid'. Returns null when GTFOBins has no shell
  // escape for the binary (so the caller can stay quiet rather than invent one).
  R.gtfoEscape = function (binOrPath, context) {
    var key = R.binKey(binOrPath);
    var g = (OBOL.GTFOBINS || {})[key];
    if (!g) return null;
    var shell = (g.shell && g.shell.length) ? g.shell : (g.command || []);
    if (!shell.length) return null;
    var command;
    if (context === 'suid') {
      // prefer the variant GTFOBins marks for SUID (keeps privileges, typically via a -p on the shell)
      var p = null;
      for (var i = 0; i < shell.length; i++) { if (/(^|\s|["'])-p(\s|$|["'])/.test(shell[i]) || /\/sh\s+-p/.test(shell[i])) { p = shell[i]; break; } }
      command = p || shell[0];
    } else { // sudo (default)
      command = 'sudo ' + shell[0];
    }
    return { bin: key, context: context === 'suid' ? 'suid' : 'sudo', command: command, url: R.gtfobinsUrl(key) };
  };

  // Is this a GTFOBins binary at all (even one whose escape we cannot inline, e.g. the `inherit` ones)?
  R.gtfoKnown = function (binOrPath) {
    var key = R.binKey(binOrPath);
    if ((OBOL.GTFOBINS || {})[key]) return true;
    return (OBOL.GTFOBINS_ALL || []).indexOf(key) >= 0;
  };

  // The full lookup: a command when we can inline it, otherwise a link when GTFOBins knows the binary but the
  // escape cannot be inlined faithfully (inherit cases). `known` is false only when GTFOBins has no entry.
  R.gtfoLookup = function (binOrPath, context) {
    var key = R.binKey(binOrPath);
    var esc = R.gtfoEscape(binOrPath, context);
    return { bin: key, url: R.gtfobinsUrl(key), command: esc ? esc.command : null,
      context: context === 'suid' ? 'suid' : 'sudo', known: R.gtfoKnown(key) };
  };

  // Which moves get a GTFOBins resolver block, and in which context.
  var MOVE_CTX = { 'sudo-abuse': 'sudo', 'suid-gtfobins': 'suid' };

  // Read the relevant facts for a move and return the resolved escapes. Fact-driven: uses the binaries the
  // parser already identified from pasted sudo -l / find -perm output. Returns null when the move is not a
  // GTFOBins move. items is [] when the move applies but nothing is identified yet (the caller can still show
  // the manual lookup box).
  R.gtfobinsForMove = function (moveId, facts) {
    var ctx = MOVE_CTX[moveId];
    if (!ctx) return null;
    var names = [];
    try {
      if (ctx === 'sudo') {
        (facts.values('privesc.sudo_binary') || []).forEach(function (v) { if (v && v.bin) names.push(v.bin); });
      } else if (ctx === 'suid') {
        (facts.values('privesc.suid_candidate') || []).forEach(function (v) { (v && v.paths || []).forEach(function (p) { names.push(p); }); });
      }
    } catch (e) {}
    var seen = {}, items = [];
    names.forEach(function (n) {
      var key = R.binKey(n);
      if (seen[key]) return;
      var look = R.gtfoLookup(n, ctx);
      if (look.known) { seen[key] = 1; items.push(look); }
    });
    return { context: ctx, items: items.slice(0, 6) };
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
