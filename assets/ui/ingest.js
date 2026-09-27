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
      var raw = lines[i], t = raw.trim();
      // Derive ONLY from a prompt-anchored line — a genuine terminal paste always carries the prompt,
      // and requiring it is what keeps tool OUTPUT (nmap's "Nmap scan report for 10.x", "Host is up
      // …") from being mistaken for a command. Handles the kali two-line prompt (└─$ / └─#),
      // user@host:cwd$/#, a bare $/#, and PowerShell (PS …>). No prompt → '' (caller keeps its own
      // command). The sigil must actually be stripped (pm/ps differ from the trimmed line).
      var pm = raw.replace(/^.*?[$#]\s+/, '').trim();       // after "…$ " / "…# "
      if (pm !== t && TOOL_HEAD.test(pm)) return pm;
      var ps = raw.replace(/^\s*PS[^>]*>\s+/i, '').trim();  // PowerShell "PS …> "
      if (ps !== t && TOOL_HEAD.test(ps)) return ps;
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
    // Route on what the paste ACTUALLY shows (its prompt/command line) over the move's canned
    // command, so pasting any tool's output into any move's box still reaches the right parser and
    // mints its facts — the coach is proof-gated, so out-of-order evidence just unlocks the right
    // moves. Fall back to the caller's command only when the paste carries no command line of its own
    // (e.g. raw redirected output); nmap XML still self-identifies from its <nmaprun args>.
    var derived = deriveCommand(text);
    var cmd = derived || (opts.command && opts.command.trim()) || '';
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
