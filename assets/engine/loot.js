/*!
 * obol engine — loot.js
 * Fact → file glue for command tokens (the AD-chain seam; port of ).
 *
 * Some pack commands need a *file*, not just a value: AS-REP / Kerberoast roasting reads a
 * {{userlist}} and writes a {{hashfile}}; cracking reads that same hashfile against a {{wordlist}}.
 * obol already PROVES the user list as an `ad.user_list` fact and the roasted hashes as
 * `hash.asrep`/`hash.tgs`, but nothing turned those facts into the file the command consumes — so a
 * roast command could be offered yet render with a bare, unfilled `{{userlist}}` placeholder.
 *
 * Browser adaptation: obol never touches the filesystem, so it cannot *write* loot/users.txt.
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
  // A user DISCOVERY command (SMTP VRFY enum, an RID/finger sweep) uses {{userlist}} to FIND users, not
  // to spray a list you already hold, so it must be runnable before any user is proven. It seeds a short
  // common-names list (the same shortlist the blind brute uses), which the operator can widen. A SPRAY
  // move is told apart by being gated on a proven user list (ad.user_list / web.users); that one keeps
  // pointing at the materialized list and stays an honest "unlocks once you have a user list" signal.
  var DEFAULT_NAMES = '/usr/share/seclists/Usernames/top-usernames-shortlist.txt';

  function join(dir, name) {
    dir = String(dir == null ? '' : dir).replace(/\/+$/, '');
    return dir ? (dir + '/' + name) : name;
  }

  // Every proven ad.user_list username, deduped (case-insensitively) and sorted — mirrors
  // loot.py.materialize_userlist so the file obol names matches the one it would write.
  // Noise that must never land in loot/users.txt: machine accounts (end with $), and the Exchange system
  // mailboxes (SM_*) and health mailboxes (HealthMailbox*) that an LDAP --users dump is full of. Feeding
  // these to kerbrute / spraying / AS-REP roasting wastes requests and, for a bad list, trips
  // KDC_ERR_C_PRINCIPAL_UNKNOWN. Mirrors the pack's awk HANDOFF filter so the one-command heredoc and the
  // hand-rolled pipeline agree. Real accounts (Administrator, krbtgt, svc-*, people) are kept.
  function isNoiseUser(u) {
    return /\$$/.test(u) || /^SM_/.test(u) || /^HealthMailbox/i.test(u) || u === '-Username-';
  }
  function usernames(facts) {
    if (!facts || !facts.values) return [];
    var seen = {}, out = [];
    facts.values('ad.user_list').forEach(function (v) {
      ((v && v.users) || []).forEach(function (u) {
        u = String(u == null ? '' : u).trim();
        var key = u.toLowerCase();
        if (u && !isNoiseUser(u) && !seen[key]) { seen[key] = true; out.push(u); }
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
  // SAME file. Derived from the action id + produces/requires tags.
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

  // Is this move a SPRAY (it is gated on a proven user list) rather than a DISCOVERY move? A spray must
  // not run before enumeration, so its {{userlist}} stays unfilled (the dependency signal) until the
  // list is materialized; a discovery move seeds a default names list so it is runnable from the start.
  function spraysUserList(action) {
    var g = [].concat((action && action.requires_all) || [], (action && action.requires_any) || []);
    return g.indexOf('ad.user_list') >= 0 || g.indexOf('web.users') >= 0;
  }

  // The loot-derived {{token}} values for an action. Operator-pinned inputs win, so this only
  // supplies a token the operator has not set. `userlist` resolves to the PROVEN list once enumerated;
  // before that it stays unfilled for a spray move (a live dependency signal) but seeds a default names
  // list for a discovery move (so VRFY enum and friends are runnable at once); `hashfile`/`wordlist`
  // always resolve to their stable paths.
  function tokensFor(action, facts, dirs, inputs) {
    inputs = inputs || {};
    var out = {};
    if (!inputs.userlist) {
      if (usernames(facts).length) out.userlist = userlistPath(dirs);
      else if (!spraysUserList(action)) out.userlist = DEFAULT_NAMES;
    }
    if (!inputs.hashfile) out.hashfile = hashfilePath(dirs, action);
    if (!inputs.wordlist) out.wordlist = wordlistPath(inputs);
    return out;
  }

  // A copy-paste command that WRITES a file on the operator's box (obol can't touch disk).
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
