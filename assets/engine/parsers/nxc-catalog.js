/*!
 * obol engine — parsers/nxc-catalog.js
 *
 * The NetExec (nxc) CAPABILITY CATALOG + a generic, data-driven parser driver. nxc is the preferred tool,
 * and the goal is EXHAUSTIVE coverage: every protocol × flag × module we offer as a move/command has (1) a
 * declared fact it produces (or is marked informational), (2) a gate + locus for move generation, and (3) a
 * parser that mints that fact from the command's real output — proven by tests/engine/nxc-switch-parsers.js,
 * which pastes real output (success → fact, denied/empty → nothing).
 *
 * Design: ONE catalog, ONE driver. Capabilities already covered by the hand-written parsers
 * (directory.js / creds.js — shares, --ntds/--sam, roasting, laps, rid-brute, coerce, exec) carry
 * `existing: true` and the driver leaves them to those parsers (facts dedupe either way); the test still
 * verifies them end-to-end. Capabilities the hand-written parsers miss carry an `extract(text, ws, C)` the
 * driver runs. Informational enumeration (group/disk/session listings with no graph-actionable fact) carries
 * `informational: true`: recognized, mints nothing, and the test asserts it mints no payoff.
 *
 * locus is R for every nxc capability (remote, run from Kali) by definition.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var C = OBOL._parserCommon;
  var mkFact = C.mkFact, _add = C._add, S = C.ProofState.SUPPORTED;

  function dom(ws) { return C._scope_for_domain(ws, C._domain_from_facts ? C._domain_from_facts(ws) : ''); }
  function host(ws) { return 'host:' + ws.target; }
  // nxc output lines are "PROTO  host  port  hostname  <status> message"; strip the banner prefix to read
  // the payload, and only act on success lines ([+] / module OK), never on [-]/denied/error lines.
  function payloadLines(text) {
    return String(text || '').split(/\r?\n/).map(function (l) {
      return l.replace(/^\s*(?:SMB|LDAP|WINRM|MSSQL|RDP|FTP|SSH|WMI|VNC|NFS|[A-Z_]+)\s+\S+\s+\d+\s+\S+\s+/i, '').trim();
    }).filter(Boolean);
  }
  function hasDenied(text) { return /\[-\]|access[_ ]denied|logon failure|STATUS_|authentication failed|error/i.test(text); }
  // Filenames that routinely hold credentials/secrets — the "useful results" filter for a spider dump.
  var LOOT_HINT_RE = /passw|pwd|cred|secret|unattend|sysprep|web\.config|\.config\b|id_rsa|id_ed25519|\.ppk|\.kdbx|\.key\b|vnc|vpn|\.bak\b|backup|\.vmdk|\.ovpn|\.pfx\b|\.ps1\b|connection|database|\.kee?pass|autologin|\.gpg|\.pgp/i;
  // Stored-credential modules (mRemoteNG, WinSCP, PuTTY, Veeam, KeePass trigger, registry autologon…) all
  // print recovered user/password pairs in a handful of shapes. Pull them as candidate credentials.
  function modCreds(text, ws, kind) {
    var out = [], seen = {};
    payloadLines(text).forEach(function (l) {
      var m = l.match(/(?:user(?:name)?|login)\s*[:=]\s*(\S+).*?(?:pass(?:word)?|pwd)\s*[:=]\s*(\S+)/i)
        || l.match(/^(\S+):([^:\s]{3,})$/);
      var pw = l.match(/(?:pass(?:word)?|pwd)\s*[:=]\s*(\S{3,})/i);
      if (m && !seen[l]) { seen[l] = 1; out.push({ kind: 'credential.candidate', scope: host(ws), value: { kind: kind, user: m[1], password: m[2], tool: 'nxc' } }); }
      else if (pw && !m && !seen[l]) { seen[l] = 1; out.push({ kind: 'credential.candidate', scope: host(ws), value: { kind: kind, password: pw[1], tool: 'nxc' } }); }
    });
    return out;
  }

  // ─────────────────────────── the catalog ───────────────────────────
  // Each entry: { id, proto, flag|module, produces:[...], locus:'R',
  //   existing?:true | informational?:true | extract:fn(text,ws,C)->[{kind,value}] , gate:[...] (for moves) }
  var CAT = [

    // ========================= SMB =========================
    { id: 'smb-auth', proto: 'smb', validate: true, produces: ['credential.available'], existing: true,
      gate: ['smb.reachable', 'port:445', 'credential.candidate', 'credential.available'] },
    { id: 'smb-shares', proto: 'smb', flag: '--shares', produces: ['smb.shares'], existing: true,
      gate: ['smb.reachable', 'port:445'] },
    { id: 'smb-rid-brute', proto: 'smb', flag: '--rid-brute', produces: ['ad.user_list'], existing: true,
      gate: ['smb.reachable', 'port:445'] },
    { id: 'smb-ntds', proto: 'smb', flag: '--ntds', produces: ['loot.ntds', 'hash.ntlm', 'hash.krbtgt'], existing: true,
      gate: ['access.admin', 'ad.control_paths'] },
    { id: 'smb-sam', proto: 'smb', flag: '--sam', produces: ['hash.ntlm', 'credential.candidate'], existing: true,
      gate: ['access.admin', 'access.system'] },
    { id: 'smb-exec', proto: 'smb', flag: '-x', produces: ['foothold.windows'], existing: true,
      gate: ['credential.available', 'hash.ntlm'] },

    // --- SMB gaps the hand-written parsers miss (driver fills these) ---
    { id: 'smb-users', proto: 'smb', flag: '--users', produces: ['ad.user_list'],
      gate: ['smb.reachable', 'port:445'],
      extract: function (text, ws) {
        var users = C._usernames(text);
        return users.length ? [{ kind: 'ad.user_list', scope: dom(ws), value: { users: users, count: users.length, method: 'nxc-smb' } }] : [];
      } },
    { id: 'smb-lsa', proto: 'smb', flag: '--lsa', produces: ['credential.candidate'],
      gate: ['access.admin', 'access.system'],
      extract: function (text, ws) {
        // LSA secrets: DCC2 cached hashes ($DCC2$) and cleartext service-account secrets (DOMAIN\svc$:plaintext,
        // _SC_<svc>:password). The NT-hash lines are already minted by the secretsdump parser; here we add the
        // cleartext/cached material as candidate credentials.
        var out = [], seen = {};
        payloadLines(text).forEach(function (l) {
          var m = l.match(/^([A-Za-z0-9_.$\\-]+)\s*:\s*(\$DCC2\$\S+|[^:\s]{4,})$/);
          if (m && !/^[a-f0-9]{32}$/i.test(m[2]) && !seen[l]) { seen[l] = 1; out.push({ kind: 'credential.candidate', scope: host(ws), value: { kind: 'lsa_secret', principal: m[1], material: m[2], tool: 'nxc' } }); }
        });
        return out;
      } },
    { id: 'smb-dpapi', proto: 'smb', flag: '--dpapi', produces: ['credential.candidate', 'credential.plaintext'],
      gate: ['access.admin', 'access.system'],
      extract: function (text, ws) {
        var out = [];
        payloadLines(text).forEach(function (l) {
          var m = l.match(/\[(?:SYSTEM|CREDENTIAL|CHROME|.*)\].*?(?:password|secret)\s*:\s*(\S+)/i) || l.match(/\b([^\s:]+):([^\s:]{4,})\s*$/);
          if (m) out.push({ kind: 'credential.plaintext', scope: host(ws), value: { kind: 'dpapi', detail: l, tool: 'nxc' } });
        });
        return out;
      } },
    { id: 'smb-loggedon', proto: 'smb', flag: '--loggedon-users', produces: ['ad.user_list'],
      gate: ['smb.reachable', 'credential.available'],
      extract: function (text, ws) {
        var users = C._usernames(text);
        return users.length ? [{ kind: 'ad.user_list', scope: dom(ws), value: { users: users, count: users.length, method: 'nxc-loggedon', note: 'users with a live session on this host (lateral-movement targets)' } }] : [];
      } },
    { id: 'smb-gpp-password', proto: 'smb', module: 'gpp_password', produces: ['credential.candidate'],
      gate: ['smb.reachable', 'port:445'],
      extract: function (text, ws) {
        // nxc -M gpp_password prints decrypted creds: "Usernames: ['svc']" / "Passwords: ['pw']" (or user:pass).
        var us = (text.match(/Usernames?\s*:\s*\[?['"]?([^'"\]\n]+)/i) || [])[1];
        var ps = (text.match(/Passwords?\s*:\s*\[?['"]?([^'"\]\n]+)/i) || [])[1];
        if (us || ps) return [{ kind: 'credential.candidate', scope: host(ws), value: { kind: 'gpp_cpassword', user: us && us.trim(), password: ps && ps.trim(), tool: 'nxc', via: 'gpp_password' } }];
        return [];
      } },
    { id: 'smb-gpp-autologin', proto: 'smb', module: 'gpp_autologin', produces: ['credential.candidate'],
      gate: ['smb.reachable', 'port:445'],
      extract: function (text, ws) {
        var us = (text.match(/Usernames?\s*:\s*\[?['"]?([^'"\]\n]+)/i) || [])[1];
        var ps = (text.match(/Passwords?\s*:\s*\[?['"]?([^'"\]\n]+)/i) || [])[1];
        return (us || ps) ? [{ kind: 'credential.candidate', scope: host(ws), value: { kind: 'gpp_autologin', user: us && us.trim(), password: ps && ps.trim(), tool: 'nxc' } }] : [];
      } },
    { id: 'smb-lsassy', proto: 'smb', module: 'lsassy', produces: ['hash.ntlm', 'credential.plaintext'],
      gate: ['access.admin', 'access.system'],
      extract: function (text, ws) {
        // lsassy lines: "[+] domain\user  <nthash>" or "domain\user  lm:nt" or "domain\user  <plaintext>".
        var out = [], seen = {};
        payloadLines(text).forEach(function (l) {
          l = l.replace(/^\[[-+*!]\]\s*/, '');
          var m = l.match(/^([A-Za-z0-9_.-]+\\[^\s]+)\s+(?:[a-f0-9]{32}:)?([a-f0-9]{32})\b/i);
          if (m && !seen[m[2]]) { seen[m[2]] = 1; out.push({ kind: 'hash.ntlm', scope: host(ws), value: { user: m[1], nthash: m[2].toLowerCase(), tool: 'nxc', via: 'lsassy' } }); return; }
          var p = l.match(/^([A-Za-z0-9_.-]+\\[^\s]+)\s+([^\s:][^\s]{2,})$/);
          if (p && !/^[a-f0-9]{32}$/i.test(p[2]) && !seen[l]) { seen[l] = 1; out.push({ kind: 'credential.plaintext', scope: host(ws), value: { user: p[1], password: p[2], tool: 'nxc', via: 'lsassy' } }); }
        });
        return out;
      } },
    { id: 'smb-nanodump', proto: 'smb', module: 'nanodump', produces: ['hash.ntlm', 'credential.plaintext'],
      gate: ['access.admin', 'access.system'],
      extract: function (text, ws) { return CAT_BY_ID['smb-lsassy'].extract(text, ws); } },
    { id: 'smb-spider-plus', proto: 'smb', module: 'spider_plus', produces: ['loot.files', 'credential.candidate'],
      gate: ['smb.reachable', 'credential.available'],
      extract: function (text, ws) {
        // spider_plus crawls readable shares and writes a JSON manifest; its output names the saved file and
        // the files found. The manifest itself is loot.files; any found file whose NAME matches the
        // credential-material hints is a candidate secret worth pulling (the "filter for useful results"
        // signal — see the spider-secrets move).
        var out = [];
        if (/spider_plus|saved\s+(?:output|share)|found:|\.json\b/i.test(text)) {
          out.push({ kind: 'loot.files', scope: host(ws), value: { kind: 'spider_manifest', detail: 'nxc spider_plus crawl of readable shares', tool: 'nxc' } });
        }
        var hits = [];
        payloadLines(text).forEach(function (l) {
          if (LOOT_HINT_RE.test(l)) { var m = l.match(/[^\s\/\\]+\.[A-Za-z0-9]{1,8}\b|[^\s\/\\]*(?:passw|cred|secret|unattend|backup)[^\s\/\\]*/i); if (m) hits.push(m[0]); }
        });
        if (hits.length) out.push({ kind: 'credential.candidate', scope: host(ws), value: { kind: 'spider_secret_file', files: hits.slice(0, 50), count: hits.length, tool: 'nxc', note: 'filenames matching credential-material hints — pull and inspect' } });
        return out;
      } },
    { id: 'smb-wdigest', proto: 'smb', module: 'wdigest', produces: ['config.review'],
      gate: ['access.admin', 'access.system'],
      extract: function (text, ws) {
        return /enable|success|\[\+\]/i.test(text) ? [{ kind: 'config.review', scope: host(ws), value: { kind: 'wdigest_uselogoncredential', detail: 'WDigest cleartext-credential caching toggled (re-dump LSASS after a logon)', tool: 'nxc' } }] : [];
      } },

    { id: 'smb-spider', proto: 'smb', flag: '--spider', produces: ['loot.files', 'credential.candidate'],
      gate: ['smb.reachable', 'credential.available'],
      extract: function (text, ws) { return CAT_BY_ID['smb-spider-plus'].extract(text, ws); } },
    { id: 'smb-coerce-plus', proto: 'smb', module: 'coerce_plus', produces: ['ad.coerced_auth'],
      gate: ['ad.dc_candidate', 'credential.available'],
      extract: function (text, ws) {
        return /vulnerable|attack success|received connection|coerc|petitpotam|printerbug|dfscoerce|efsr|\[\+\]/i.test(text)
          ? [{ kind: 'ad.coerced_auth', scope: dom(ws), value: { detail: 'authentication coerced via nxc coerce_plus', tool: 'nxc' } }] : [];
      } },
    { id: 'smb-gen-relay-list', proto: 'smb', flag: '--gen-relay-list', informational: true, produces: [], gate: ['smb.reachable', 'port:445'] },

    // --- SMB LSASS-dump family (all emit domain\user → hash/plaintext like lsassy) ---
    { id: 'smb-handlekatz', proto: 'smb', module: 'handlekatz', produces: ['hash.ntlm', 'credential.plaintext'],
      gate: ['access.admin', 'access.system'], extract: function (text, ws) { return CAT_BY_ID['smb-lsassy'].extract(text, ws); } },
    { id: 'smb-procdump', proto: 'smb', module: 'procdump', produces: ['hash.ntlm', 'credential.plaintext'],
      gate: ['access.admin', 'access.system'], extract: function (text, ws) { return CAT_BY_ID['smb-lsassy'].extract(text, ws); } },
    { id: 'smb-masky', proto: 'smb', module: 'masky', produces: ['hash.ntlm', 'credential.plaintext'],
      gate: ['access.admin', 'access.system'], extract: function (text, ws) { return CAT_BY_ID['smb-lsassy'].extract(text, ws); } },

    // --- SMB privileged dumps / registry secrets ---
    { id: 'smb-backup-operator', proto: 'smb', module: 'backup_operator', produces: ['loot.ntds', 'hash.ntlm'],
      gate: ['privesc.windows_privilege', 'access.admin'],
      extract: function (text, ws) {
        // SeBackupPrivilege → remote registry-hive / NTDS dump: emits the same user:rid:lm:nt::: lines.
        var out = [], seen = {};
        payloadLines(text).forEach(function (l) {
          var m = l.match(/^([^\s:]+):\d+:[a-f0-9]{32}:([a-f0-9]{32}):::/i);
          if (m && !seen[m[2]]) { seen[m[2]] = 1; out.push({ kind: 'hash.ntlm', scope: host(ws), value: { user: m[1], nthash: m[2].toLowerCase(), tool: 'nxc', via: 'backup_operator' } }); }
        });
        if (out.length || /ntds|sam\s+dumped|backupoperator|SeBackup/i.test(text)) out.push({ kind: 'loot.ntds', scope: host(ws), value: { method: 'backup_operator', tool: 'nxc' } });
        return out;
      } },
    { id: 'smb-reg-winlogon', proto: 'smb', module: 'reg-winlogon', produces: ['credential.candidate'],
      gate: ['access.admin', 'access.system'], extract: function (text, ws) { return modCreds(text, ws, 'autologon'); } },
    { id: 'smb-reg-query', proto: 'smb', module: 'reg-query', produces: ['credential.candidate'],
      gate: ['access.admin', 'access.system'], extract: function (text, ws) { return modCreds(text, ws, 'registry_secret'); } },

    // --- SMB stored-application credentials ---
    { id: 'smb-veeam', proto: 'smb', module: 'veeam', produces: ['credential.candidate'],
      gate: ['access.admin'], extract: function (text, ws) { return modCreds(text, ws, 'veeam'); } },
    { id: 'smb-mremoteng', proto: 'smb', module: 'mremoteng', produces: ['credential.candidate'],
      gate: ['foothold.windows', 'access.admin'], extract: function (text, ws) { return modCreds(text, ws, 'mremoteng'); } },
    { id: 'smb-winscp', proto: 'smb', module: 'winscp', produces: ['credential.candidate'],
      gate: ['foothold.windows', 'access.admin'], extract: function (text, ws) { return modCreds(text, ws, 'winscp'); } },
    { id: 'smb-putty', proto: 'smb', module: 'putty', produces: ['credential.candidate'],
      gate: ['foothold.windows', 'access.admin'], extract: function (text, ws) { return modCreds(text, ws, 'putty'); } },
    { id: 'smb-keepass-discover', proto: 'smb', module: 'keepass_discover', informational: true, produces: [], gate: ['foothold.windows', 'access.admin'] },
    { id: 'smb-keepass-trigger', proto: 'smb', module: 'keepass_trigger', produces: ['credential.candidate'],
      gate: ['access.admin', 'access.system'], extract: function (text, ws) { return modCreds(text, ws, 'keepass_master'); } },

    // --- SMB privilege / downgrade leads ---
    { id: 'smb-install-elevated', proto: 'smb', module: 'install_elevated', produces: ['privesc.always_install_elevated'],
      gate: ['foothold.windows'],
      extract: function (text, ws) {
        return /alwaysinstallelevated.*(?:1|enabled|vulnerable)|both.*registry keys|\[\+\].*elevated/i.test(text)
          ? [{ kind: 'privesc.always_install_elevated', scope: host(ws), value: { detail: 'AlwaysInstallElevated set in both HKLM+HKCU', tool: 'nxc' } }] : [];
      } },
    { id: 'smb-pre2k', proto: 'smb', module: 'pre2k', produces: ['credential.candidate'],
      gate: ['smb.reachable', 'port:445'],
      extract: function (text, ws) {
        // pre-created (pre-Win2000) computer accounts authenticate with the lowercased machine name as the
        // password — a usable credential candidate.
        var out = [];
        payloadLines(text).forEach(function (l) { var m = l.match(/([A-Za-z0-9_-]+\$)\s*:\s*([A-Za-z0-9_-]+)/); if (m) out.push({ kind: 'credential.candidate', scope: dom(ws), value: { kind: 'pre2k_computer', user: m[1], password: m[2], tool: 'nxc' } }); });
        return out;
      } },
    { id: 'smb-ntlmv1', proto: 'smb', module: 'ntlmv1', produces: ['config.review'],
      gate: ['smb.reachable', 'port:445'],
      extract: function (text, ws) { return /ntlmv1.*(?:enabled|allow|vulnerable)|lmcompatibilitylevel\s*[:=]\s*[0-2]/i.test(text) ? [{ kind: 'config.review', scope: host(ws), value: { kind: 'ntlmv1_enabled', detail: 'NTLMv1 permitted — crackable/relayable', tool: 'nxc' } }] : []; } },

    // --- SMB defensive / coercion-enabler checks (informational leads) ---
    { id: 'smb-enum-av', proto: 'smb', module: 'enum_av', produces: ['defense.control'],
      gate: ['access.admin', 'access.system'],
      extract: function (text, ws) { return /defender|antivirus|edr|crowdstrike|carbon|sentinel|\bav\b/i.test(text) ? [{ kind: 'defense.control', scope: host(ws), value: { kind: 'av_edr', detail: payloadLines(text).slice(0, 10).join('; '), tool: 'nxc' } }] : []; } },
    { id: 'smb-spooler', proto: 'smb', module: 'spooler', informational: true, produces: [], gate: ['smb.reachable', 'port:445'] },
    { id: 'smb-webdav', proto: 'smb', module: 'webdav', informational: true, produces: [], gate: ['smb.reachable', 'port:445'] },
    { id: 'smb-runasppl', proto: 'smb', module: 'runasppl', informational: true, produces: [], gate: ['access.admin', 'access.system'] },

    // --- SMB informational enumeration (recognized, no graph-actionable fact) ---
    { id: 'smb-groups', proto: 'smb', flag: '--groups', informational: true, produces: [], gate: ['smb.reachable', 'credential.available'] },
    { id: 'smb-local-groups', proto: 'smb', flag: '--local-groups', informational: true, produces: [], gate: ['smb.reachable', 'credential.available'] },
    { id: 'smb-sessions', proto: 'smb', flag: '--sessions', informational: true, produces: [], gate: ['smb.reachable', 'credential.available'] },
    { id: 'smb-disks', proto: 'smb', flag: '--disks', informational: true, produces: [], gate: ['smb.reachable', 'credential.available'] },
    { id: 'smb-computers', proto: 'smb', flag: '--computers', informational: true, produces: [], gate: ['smb.reachable', 'credential.available'] },
    { id: 'smb-pass-pol', proto: 'smb', flag: '--pass-pol', informational: true, produces: [], gate: ['smb.reachable', 'port:445'] },

    // ========================= LDAP =========================
    { id: 'ldap-auth', proto: 'ldap', validate: true, produces: ['credential.available'], existing: true,
      gate: ['ldap.reachable', 'port:389', 'credential.candidate', 'credential.available'] },
    { id: 'ldap-users', proto: 'ldap', flag: '--users', produces: ['ad.user_list'], existing: true,
      gate: ['ldap.reachable', 'port:389'] },
    { id: 'ldap-asreproast', proto: 'ldap', flag: '--asreproast', produces: ['hash.asrep', 'credential.candidate'], existing: true,
      gate: ['ad.user_list', 'ldap.reachable'] },
    { id: 'ldap-kerberoasting', proto: 'ldap', flag: '--kerberoasting', produces: ['hash.tgs', 'credential.candidate'], existing: true,
      gate: ['credential.available', 'ldap.reachable'] },
    { id: 'ldap-bloodhound', proto: 'ldap', flag: '--bloodhound', produces: ['ad.graph.collected', 'ad.attack_paths'], existing: true,
      gate: ['credential.available'] },
    { id: 'ldap-laps', proto: 'ldap', module: 'laps', produces: ['credential.candidate'], existing: true,
      gate: ['credential.available', 'ldap.reachable', 'ad.control_paths'] },

    // --- LDAP gaps the hand-written parsers miss ---
    { id: 'ldap-admin-count', proto: 'ldap', flag: '--admin-count', produces: ['ad.user_list'],
      gate: ['credential.available', 'ldap.reachable'],
      extract: function (text, ws) {
        var users = C._usernames(text);
        return users.length ? [{ kind: 'ad.user_list', scope: dom(ws), value: { users: users, count: users.length, method: 'nxc-admin-count', note: 'adminCount=1 privileged accounts (high-value targets)' } }] : [];
      } },
    { id: 'ldap-trusted-for-delegation', proto: 'ldap', flag: '--trusted-for-delegation', produces: ['ad.unconstrained', 'ad.attack_paths'],
      gate: ['credential.available', 'ldap.reachable'],
      extract: function (text, ws) {
        var out = [], lines = payloadLines(text);
        var unconstrained = lines.some(function (l) { return /unconstrained/i.test(l); });
        var any = lines.some(function (l) { return /\$|delegat|constrained/i.test(l); });
        if (unconstrained) out.push({ kind: 'ad.unconstrained', scope: dom(ws), value: { detail: 'accounts trusted for unconstrained delegation', tool: 'nxc' } });
        else if (any) out.push({ kind: 'ad.attack_paths', scope: dom(ws), value: { kind: 'delegation', detail: 'constrained/RBCD delegation accounts', tool: 'nxc' } });
        return out;
      } },
    { id: 'ldap-find-delegation', proto: 'ldap', flag: '--find-delegation', produces: ['ad.unconstrained', 'ad.attack_paths'],
      gate: ['credential.available', 'ldap.reachable'],
      extract: function (text, ws) { return CAT_BY_ID['ldap-trusted-for-delegation'].extract(text, ws); } },
    { id: 'ldap-gmsa', proto: 'ldap', flag: '--gmsa', produces: ['ad.gmsa', 'credential.candidate'],
      gate: ['credential.available', 'ldap.reachable'],
      extract: function (text, ws) {
        var out = [], lines = payloadLines(text);
        if (lines.some(function (l) { return /gmsa|managedpassword|msDS-ManagedPassword/i.test(l); })) {
          out.push({ kind: 'ad.gmsa', scope: dom(ws), value: { detail: 'gMSA accounts present', tool: 'nxc' } });
          lines.forEach(function (l) {
            var m = l.match(/Account:\s*(\S+)\s+NTLM:\s*([a-f0-9]{32})/i);
            if (m) out.push({ kind: 'credential.candidate', scope: dom(ws), value: { kind: 'gmsa', user: m[1], nthash: m[2].toLowerCase(), tool: 'nxc' } });
          });
        }
        return out;
      } },
    { id: 'ldap-daclread', proto: 'ldap', module: 'daclread', produces: ['ad.acl_lead'],
      gate: ['credential.available', 'ldap.reachable'],
      extract: function (text, ws) {
        return /WriteDacl|GenericAll|GenericWrite|WriteOwner|ForceChangePassword|AllExtendedRights|WriteProperty|trustee/i.test(text)
          ? [{ kind: 'ad.acl_lead', scope: dom(ws), value: { detail: 'DACL abuse right found via nxc daclread', tool: 'nxc' } }] : [];
      } },
    { id: 'ldap-group-mem', proto: 'ldap', module: 'group-mem', produces: ['ad.user_list'],
      gate: ['credential.available', 'ldap.reachable'],
      extract: function (text, ws) {
        var users = C._usernames(text);
        return users.length ? [{ kind: 'ad.user_list', scope: dom(ws), value: { users: users, count: users.length, method: 'nxc-group-mem', note: 'members of the queried group' } }] : [];
      } },
    { id: 'ldap-password-not-required', proto: 'ldap', flag: '--password-not-required', produces: ['ad.user_list'],
      gate: ['credential.available', 'ldap.reachable'],
      extract: function (text, ws) {
        var users = C._usernames(text);
        return users.length ? [{ kind: 'ad.user_list', scope: dom(ws), value: { users: users, count: users.length, method: 'nxc-passnotreq', note: 'PASSWD_NOTREQD accounts (try a blank password)' } }] : [];
      } },

    { id: 'ldap-adcs', proto: 'ldap', module: 'adcs', produces: ['adcs.vulnerable'],
      gate: ['credential.available', 'ldap.reachable'],
      extract: function (text, ws) {
        // nxc ldap -M adcs lists CAs / templates; a vulnerable ESC template is the ADCS lead (→ adcs-esc /
        // certifried / cert-authenticate). A plain CA listing with no ESC verdict is just enumeration.
        return /ESC\d|vulnerable|enrollee supplies subject|ENROLLEE_SUPPLIES_SUBJECT|EDITF_ATTRIBUTESUBJECTALTNAME/i.test(text)
          ? [{ kind: 'adcs.vulnerable', scope: dom(ws), value: { detail: 'vulnerable ADCS template/CA via nxc adcs', tool: 'nxc' } }] : [];
      } },
    { id: 'ldap-user-desc', proto: 'ldap', module: 'user-desc', produces: ['credential.candidate'],
      gate: ['credential.available', 'ldap.reachable'],
      extract: function (text, ws) {
        // Passwords left in the AD 'description' attribute — a classic. Mint any description that looks like
        // it carries a secret as a candidate credential.
        var out = [];
        payloadLines(text).forEach(function (l) { if (/pass|pwd|cred|login|temp|welcome|changeme|default/i.test(l) && /[:=]|description/i.test(l)) out.push({ kind: 'credential.candidate', scope: dom(ws), value: { kind: 'ad_description', detail: l.slice(0, 160), tool: 'nxc' } }); });
        return out;
      } },
    { id: 'ldap-get-desc-users', proto: 'ldap', module: 'get-desc-users', produces: ['credential.candidate'],
      gate: ['credential.available', 'ldap.reachable'], extract: function (text, ws) { return CAT_BY_ID['ldap-user-desc'].extract(text, ws); } },
    { id: 'ldap-pre2k', proto: 'ldap', module: 'pre2k', produces: ['credential.candidate'],
      gate: ['ldap.reachable', 'port:389'], extract: function (text, ws) { return CAT_BY_ID['smb-pre2k'].extract(text, ws); } },
    { id: 'ldap-enum-trusts', proto: 'ldap', module: 'enum_trusts', produces: ['ad.trusts'],
      gate: ['credential.available', 'ldap.reachable'],
      extract: function (text, ws) { return /trust|forest|outbound|inbound|bidirectional/i.test(text) ? [{ kind: 'ad.trusts', scope: dom(ws), value: { detail: 'domain/forest trusts via nxc enum_trusts', tool: 'nxc' } }] : []; } },
    { id: 'ldap-ldap-checker', proto: 'ldap', module: 'ldap-checker', produces: ['config.review'],
      gate: ['ldap.reachable', 'port:389'],
      extract: function (text, ws) { return /signing\s*(?:not|is not|none)|channel binding\s*(?:not|never)|not (?:enforced|required)/i.test(text) ? [{ kind: 'config.review', scope: host(ws), value: { kind: 'ldap_signing_not_enforced', detail: 'LDAP signing / channel binding not enforced — relayable', tool: 'nxc' } }] : []; } },

    // --- LDAP informational ---
    { id: 'ldap-maq', proto: 'ldap', module: 'maq', informational: true, produces: [], gate: ['credential.available', 'ldap.reachable'] },
    { id: 'ldap-query', proto: 'ldap', flag: '--query', informational: true, produces: [], gate: ['credential.available', 'ldap.reachable'] },
    { id: 'ldap-whoami', proto: 'ldap', module: 'whoami', informational: true, produces: [], gate: ['credential.available', 'ldap.reachable'] },
    { id: 'ldap-subnets', proto: 'ldap', module: 'subnets', informational: true, produces: [], gate: ['credential.available', 'ldap.reachable'] },
    { id: 'ldap-sid-brute', proto: 'ldap', flag: '--sid-brute', informational: true, produces: [], gate: ['credential.available', 'ldap.reachable'] },

    // ========================= WINRM =========================
    { id: 'winrm-auth', proto: 'winrm', validate: true, produces: ['credential.available', 'foothold.windows'], existing: true,
      gate: ['winrm.reachable', 'port:5985', 'credential.available', 'hash.ntlm'] },
    { id: 'winrm-exec', proto: 'winrm', flag: '-x', produces: ['foothold.windows'], existing: true,
      gate: ['credential.available', 'hash.ntlm', 'winrm.reachable'] },
    { id: 'winrm-exec-ps', proto: 'winrm', flag: '-X', produces: ['foothold.windows'], existing: true,
      gate: ['credential.available', 'hash.ntlm', 'winrm.reachable'] },

    // ========================= MSSQL =========================
    { id: 'mssql-auth', proto: 'mssql', validate: true, produces: ['db.session'], existing: true,
      gate: ['service.ms-sql-s', 'port:1433', 'credential.available', 'credential.candidate'] },
    { id: 'mssql-exec', proto: 'mssql', flag: '-x', produces: ['foothold.windows'], existing: true,
      gate: ['db.session'] },
    { id: 'mssql-exec-ps', proto: 'mssql', flag: '-X', produces: ['foothold.windows'], existing: true,
      gate: ['db.session'] },
    { id: 'mssql-query', proto: 'mssql', flag: '-q', informational: true, produces: [], gate: ['db.session'] },
    { id: 'mssql-priv', proto: 'mssql', module: 'mssql_priv', informational: true, produces: [], gate: ['db.session'] },
    { id: 'mssql-coerce', proto: 'mssql', module: 'mssql_coerce', produces: ['ad.coerced_auth'],
      gate: ['db.session'],
      extract: function (text, ws) { return /received connection|coerc|\[\+\].*success|ntlmv2/i.test(text) ? [{ kind: 'ad.coerced_auth', scope: dom(ws), value: { detail: 'auth coerced via MSSQL (xp_dirtree/xp_fileexist)', tool: 'nxc' } }] : []; } },

    // ========================= RDP =========================
    { id: 'rdp-auth', proto: 'rdp', validate: true, produces: ['rdp.authenticated'], existing: true,
      gate: ['rdp.reachable', 'port:3389', 'credential.available', 'hash.ntlm'] },
    { id: 'rdp-screenshot', proto: 'rdp', flag: '--screenshot', informational: true, produces: [], gate: ['rdp.reachable', 'port:3389'] },
    { id: 'rdp-nla-screenshot', proto: 'rdp', flag: '--nla-screenshot', informational: true, produces: [], gate: ['rdp.reachable', 'port:3389'] },

    // ========================= FTP =========================
    { id: 'ftp-auth', proto: 'ftp', validate: true, produces: ['loot.files'],
      gate: ['ftp.reachable', 'port:21'],
      extract: function (text, ws) {
        // nxc ftp login success often prints a directory listing; a readable listing is loot to pull.
        var listing = payloadLines(text).some(function (l) { return /^[-dlpscbr][-rwxsStT]{9}\s|\d{2}:\d{2}\s|\b(?:drwx|<DIR>)\b/.test(l); });
        return listing ? [{ kind: 'loot.files', scope: host(ws), value: { kind: 'ftp_listing', detail: 'readable FTP directory via nxc', tool: 'nxc' } }] : [];
      } },
    { id: 'ftp-ls', proto: 'ftp', flag: '--ls', produces: ['loot.files'],
      gate: ['ftp.reachable', 'port:21'],
      extract: function (text, ws) { return CAT_BY_ID['ftp-auth'].extract(text, ws); } },

    // ========================= SSH =========================
    { id: 'ssh-auth', proto: 'ssh', validate: true, produces: ['credential.available'], existing: true,
      gate: ['ssh.reachable', 'port:22', 'credential.candidate', 'credential.available'] },
    { id: 'ssh-exec', proto: 'ssh', flag: '-x', produces: ['foothold.linux', 'access.shell'], existing: true,
      gate: ['credential.available', 'ssh.reachable'] },
    { id: 'ssh-sudo-check', proto: 'ssh', flag: '--sudo-check', informational: true, produces: [], gate: ['credential.available', 'ssh.reachable'] },

    // ========================= WMI =========================
    { id: 'wmi-exec', proto: 'wmi', flag: '-x', produces: ['foothold.windows'], existing: true,
      gate: ['credential.available', 'hash.ntlm'] },
    { id: 'wmi-exec-ps', proto: 'wmi', flag: '-X', produces: ['foothold.windows'],
      gate: ['credential.available', 'hash.ntlm'],
      extract: function (text, ws) {
        // nxc wmi -X runs PowerShell; its output is arbitrary (not always an identity line), so key the
        // foothold on the exec-success marker (Pwn3d!) rather than on recognising the command output.
        return /\(Pwn3d!\)/i.test(text) ? [{ kind: 'foothold.windows', scope: host(ws), value: { service: 'wmi', method: 'wmiexec-ps', tool: 'nxc' } }] : [];
      } },

    // ========================= NFS =========================
    { id: 'nfs-shares', proto: 'nfs', flag: '--shares', produces: ['loot.files'],
      gate: ['port:2049', 'nfs.reachable'],
      extract: function (text, ws) {
        var exports = payloadLines(text).filter(function (l) { return /^\//.test(l) || /\s(?:rw|ro)\b/.test(l); });
        return exports.length ? [{ kind: 'loot.files', scope: host(ws), value: { kind: 'nfs_exports', exports: exports.slice(0, 50), count: exports.length, tool: 'nxc', note: 'NFS exports — mount and read (watch for no_root_squash)' } }] : [];
      } },

    // ========================= VNC =========================
    { id: 'vnc-auth', proto: 'vnc', validate: true, produces: ['access.desktop'],
      gate: ['port:5900', 'port:5901', 'vnc.reachable'],
      extract: function (text, ws) {
        // nxc vnc [+] ... (Pwn3d!) / "No password" means a usable desktop (no-auth or a working VNC password).
        return (/\(Pwn3d!\)|no password|\[\+\]/i.test(text) && !hasDenied(text))
          ? [{ kind: 'access.desktop', scope: host(ws), value: { service: 'vnc', detail: 'reachable VNC desktop (no-auth or valid password)', tool: 'nxc' } }] : [];
      } }
  ];

  var CAT_BY_ID = {}; CAT.forEach(function (e) { CAT_BY_ID[e.id] = e; });
  OBOL._nxcCatalog = CAT;
  OBOL._nxcCatalogById = CAT_BY_ID;

  // Which capabilities does a command invoke? Matches the protocol + each flag/module token present.
  function match(command) {
    var lc = String(command || '').toLowerCase();
    var protoM = lc.match(/\bnxc\s+(smb|ldap|winrm|mssql|rdp|ftp|ssh|wmi|vnc|nfs)\b/) || lc.match(/\bnetexec\s+(smb|ldap|winrm|mssql|rdp|ftp|ssh|wmi|vnc|nfs)\b/);
    var proto = protoM ? protoM[1] : null;
    if (!proto) return [];
    return CAT.filter(function (e) {
      if (e.proto !== proto) return false;
      if (e.module) return new RegExp('-m\\s+' + e.module + '\\b', 'i').test(lc);
      if (e.flag) { var f = e.flag.replace(/[-]/g, '\\-'); return new RegExp('(^|\\s)' + f + '(\\s|$|=)', 'i').test(command); }
      // A validate-only entry with its own extractor (e.g. ftp-auth → loot.files from a listing) runs when
      // no flag/module is present on the command; plain auth-success (credential.available) stays with
      // _parse_nxc_common, so these two don't collide.
      if (e.validate && e.extract) return !/(^|\s)(-M\s|--)/.test(command);
      return false;
    });
  }

  function _parse_nxc_capability(text, command, ws, source, facts) {
    if (hasDenied(text) && !/\[\+\]/.test(text)) return; // a pure failure/denied paste mints nothing
    match(command).forEach(function (e) {
      if (!e.extract || e.existing || e.informational) return;
      var got;
      try { got = e.extract(text, ws, C) || []; } catch (x) { got = []; }
      got.forEach(function (f) { _add(facts, mkFact(f.kind, f.scope || host(ws), f.value || {}, S, source)); });
    });
  }
  C._parse_nxc_capability = _parse_nxc_capability;

})(typeof globalThis !== 'undefined' ? globalThis : this);
