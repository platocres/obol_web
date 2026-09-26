/*!
 * obol ui — ingest.js — the shared evidence-ingest core (no DOM).
 * Parses a paste/file with the conservative parsers, mints only proven facts, and records the
 * command+output (capped) as verbatim report evidence. Both the Evidence route and the coach's
 * inline per-command ingestion call this, so paste-anywhere behaves identically.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  // Derive the command line from a full-terminal paste when the operator didn't type one.
  var TOOL_HEAD = /^(sudo\s+)?(nmap|rustscan|masscan|netexec|nxc|crackmapexec|cme|smbclient|smbmap|rpcclient|enum4linux[\w-]*|ldapsearch|kerbrute|impacket[\w.-]*|GetNPUsers[\w.]*|GetUserSPNs[\w.]*|secretsdump[\w.]*|evil-winrm|ffuf|feroxbuster|gobuster|wfuzz|nikto|whatweb|curl|wget|sqlmap|hydra|john|hashcat|responder|bloodhound[\w.-]*|sharphound[\w.-]*|dig|host|snmpwalk|ssh|ftp)\b/i;
  function deriveCommand(text) {
    var lines = String(text || '').split(/\r?\n/);
    for (var i = 0; i < lines.length && i < 40; i++) {
      var ln = lines[i];
      var m = ln.match(/^\s*(?:\$|#|>|PS[^>]*>|[\w.-]+@[\w.-]+:[^$#]*[$#])\s*(.+\S)\s*$/);
      if (m && TOOL_HEAD.test(m[1].trim())) return m[1].trim();
      if (TOOL_HEAD.test(ln.trim())) return ln.trim();
    }
    return '';
  }

  function ready() { return !!(OBOL.parsers && OBOL.parsers.parseActionOutput); }
  // Resolve to true once the (lazily-loaded) parser group is available.
  function ensureParsers() {
    if (ready()) return Promise.resolve(true);
    if (OBOL.lazy && OBOL.lazy.loadGroup) return OBOL.lazy.loadGroup('parsers').then(ready).catch(function () { return false; });
    return Promise.resolve(false);
  }

  // Parse + mint + record. No DOM, no toast — the caller renders the outcome.
  //   opts = { text, command?, source?, fileName?, actionId? }
  // returns { ok, added, facts, cmd, lines, fileName } or { ok:false, reason:'empty'|'parsers'|'error', error? }
  function run(opts) {
    opts = opts || {};
    var text = opts.text || '';
    if (!text.trim()) return { ok: false, reason: 'empty' };
    if (!ready()) return { ok: false, reason: 'parsers' };
    var cmd = (opts.command && opts.command.trim()) ? opts.command.trim() : deriveCommand(text);
    var eng = OBOL.store.active();
    var params = (eng && eng.params) || {};
    var scope = 'host:' + (params.target || 'target');
    var res, parseError = '';
    try {
      res = OBOL.parsers.parseActionOutput({ command: cmd, stdout: text, source: opts.fileName || cmd || 'paste', scope: scope, domain: params.domain || '' });
    } catch (e) { res = { facts: [] }; parseError = (e && e.message) || 'parse failed'; }
    if (res && res.error) parseError = res.error; // a sub-parser threw but earlier facts survived
    var facts = (res && res.facts) || [];
    var added = OBOL.store.addFacts(facts, 'evidence');
    var CAP = 24000;
    var lines = text.split(/\r?\n/).length;
    var stored = text.length > CAP
      ? (text.slice(0, CAP) + '\n… [truncated — ' + (text.length - CAP) + ' more chars, ' + lines + ' lines total]')
      : text;
    OBOL.store.update(function (e) {
      e.activities = e.activities || [];
      e.activities.unshift({ at: Date.now(), command: cmd, source: opts.source || 'paste', tool: (cmd.split(/\s+/)[0] || 'paste'),
        target: params.target || '', scope: scope, file: opts.fileName || '', action_id: opts.actionId || '',
        produced: facts.map(function (f) { return f.kind; }), stdout: stored, sample: text.slice(0, 400) });
    }, 'activity');
    if (OBOL.app && OBOL.app.renderSidebar) OBOL.app.renderSidebar();
    return { ok: true, added: added, facts: facts, cmd: cmd, lines: lines, fileName: opts.fileName || '', parseError: parseError };
  }

  OBOL.ingest = { run: run, deriveCommand: deriveCommand, ensureParsers: ensureParsers, ready: ready };
})(typeof globalThis !== 'undefined' ? globalThis : this);
