/*!
 * obol engine — loot.js
 * Fact → file glue for command tokens (the AD-chain seam; port of obol-local/obol/loot.py).
 *
 * Some pack commands need a *file*, not just a value: AS-REP / Kerberoast roasting reads a
 * {{userlist}} and writes a {{hashfile}}; cracking reads that same hashfile against a {{wordlist}}.
 * obol already PROVES the user list as an `ad.user_list` fact and the roasted hashes as
 * `hash.asrep`/`hash.tgs`, but nothing turned those facts into the file the command consumes — so a
 * roast command could be offered yet render with a bare, unfilled `{{userlist}}` placeholder.
 *
 * Browser adaptation: obol web never touches the filesystem, so it cannot *write* loot/users.txt.
 * Instead it does two things this module supplies:
 *   1. resolve {{userlist}}/{{hashfile}}/{{wordlist}} to stable paths under the workspace loot/ dir,
 *      so the roast that WRITES {{hashfile}} and the crack that READS it agree on one path; and
 *   2. hand the operator a copy-paste command (a single-quoted heredoc of the exact names/hashes
 *      obol proved) that materializes that file on their own box.
 *
 * Deterministic + idempotent: the same facts produce the same file contents at the same paths.
 * Operator-pinned inputs (engagement params named userlist/hashfile/wordlist) always win.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  var DEFAULT_WORDLIST = '/usr/share/wordlists/rockyou.txt';

  function join(dir, name) {
    dir = String(dir == null ? '' : dir).replace(/\/+$/, '');
    return dir ? (dir + '/' + name) : name;
  }

  // Every proven ad.user_list username, deduped (case-insensitively) and sorted — mirrors
  // loot.py.materialize_userlist so the file obol names matches the one it would write.
  function usernames(facts) {
    if (!facts || !facts.values) return [];
    var seen = {}, out = [];
    facts.values('ad.user_list').forEach(function (v) {
      ((v && v.users) || []).forEach(function (u) {
        u = String(u == null ? '' : u).trim();
        var key = u.toLowerCase();
        if (u && !seen[key]) { seen[key] = true; out.push(u); }
      });
    });
    out.sort(function (a, b) { var la = a.toLowerCase(), lb = b.toLowerCase(); return la < lb ? -1 : (la > lb ? 1 : 0); });
    return out;
  }

  // Order-stable, deduped hashes proven under a roast fact kind (hash.asrep / hash.tgs).
  function hashesOf(facts, kind) {
    if (!facts || !facts.values) return [];
    var seen = {}, out = [];
    facts.values(kind).forEach(function (v) {
      ((v && v.hashes) || []).forEach(function (h) {
        h = String(h == null ? '' : h).trim();
        if (h && !seen[h]) { seen[h] = true; out.push(h); }
      });
    });
    return out;
  }

  // asrep / tgs / hashes — the basename a roast writes and its crack reads, so both resolve to the
  // SAME file. Derived from the action id + produces/requires tags (mirrors loot.py._hash_name).
  function hashName(action) {
    action = action || {};
    var tags = String(action.id || '').toLowerCase() + ' '
      + [].concat(action.produces || [], action.requires_all || []).join(' ').toLowerCase();
    if (tags.indexOf('asrep') >= 0) return 'asrep';
    if (tags.indexOf('tgs') >= 0 || tags.indexOf('kerber') >= 0) return 'tgs';
    return 'hashes';
  }

  function lootDir(dirs) { return (dirs && dirs.lootdir) || 'loot'; }
  function userlistPath(dirs) { return join(lootDir(dirs), 'users.txt'); }
  function hashfilePath(dirs, action) { return join(lootDir(dirs), hashName(action) + '.hashes'); }
  function wordlistPath(inputs) { return (String((inputs && inputs.wordlist) || '').trim()) || DEFAULT_WORDLIST; }

  // The roast fact kind that backs a hashfile basename (so a crack can be materialized straight
  // from proven facts even when the roast printed the hash to stdout instead of a file).
  var _HASHFILE_FACT_KIND = { asrep: 'hash.asrep', tgs: 'hash.tgs' };

  // The loot-derived {{token}} values for an action. Operator-pinned inputs win, so this only
  // supplies a token the operator has not set. `userlist` resolves only once a user list is PROVEN
  // (nothing to point at otherwise, so the placeholder stays as a live dependency signal);
  // `hashfile`/`wordlist` always resolve to their stable paths.
  function tokensFor(action, facts, dirs, inputs) {
    inputs = inputs || {};
    var out = {};
    if (!inputs.userlist && usernames(facts).length) out.userlist = userlistPath(dirs);
    if (!inputs.hashfile) out.hashfile = hashfilePath(dirs, action);
    if (!inputs.wordlist) out.wordlist = wordlistPath(inputs);
    return out;
  }

  // A copy-paste command that WRITES a file on the operator's box (obol web can't touch disk).
  // A single-quoted heredoc keeps every line literal — no shell expansion of $names or backticks.
  function writeFileCommand(path, lines) {
    if (!path || !lines || !lines.length) return '';
    return 'cat > ' + path + " <<'EOF'\n" + lines.join('\n') + '\nEOF';
  }

  // Materialize the proven user list to {{userlist}} — '' when none is proven yet.
  function userlistCommand(facts, dirs) {
    var users = usernames(facts);
    return users.length ? writeFileCommand(userlistPath(dirs), users) : '';
  }

  // Materialize the proven roast hashes to {{hashfile}} — '' when none proven for this kind.
  function hashfileCommand(facts, action, dirs) {
    var kind = _HASHFILE_FACT_KIND[hashName(action)];
    if (!kind) return '';
    var hashes = hashesOf(facts, kind);
    return hashes.length ? writeFileCommand(hashfilePath(dirs, action), hashes) : '';
  }

  // Does an action's command template consume a given {{token}} (before substitution)?
  function actionUsesToken(action, name) {
    if (!action) return false;
    var tok = '{{' + name + '}}';
    var cmds = (action.commands && action.commands.length) ? action.commands : [{ run: action.command }];
    for (var i = 0; i < cmds.length; i++) {
      var run = (cmds[i] && (cmds[i].web || cmds[i].run)) || '';
      if (run.indexOf(tok) >= 0) return true;
    }
    return String(action.web_command || action.command || '').indexOf(tok) >= 0;
  }

  OBOL.loot = {
    DEFAULT_WORDLIST: DEFAULT_WORDLIST,
    usernames: usernames, hashesOf: hashesOf, hashName: hashName,
    userlistPath: userlistPath, hashfilePath: hashfilePath, wordlistPath: wordlistPath,
    tokensFor: tokensFor, writeFileCommand: writeFileCommand,
    userlistCommand: userlistCommand, hashfileCommand: hashfileCommand,
    actionUsesToken: actionUsesToken,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
