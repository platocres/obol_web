/*!
 * obol engine - parsers/nxc-catalog.js
 *
 * The NetExec (nxc) CAPABILITY CATALOG + a generic, data-driven parser driver. nxc is the preferred tool,
 * and the goal is EXHAUSTIVE coverage: every protocol x flag x module we offer as a move/command has (1) a
 * declared fact it produces (or is marked informational), (2) a gate + locus for move generation, and (3) a
 * parser that mints that fact from the command's real output - proven by tests/engine/legacy/nxc-switch-parsers.js,
 * which pastes real output (success -> fact, denied/empty -> nothing).
 *
 * Design: ONE catalog, ONE driver. Capabilities already covered by the hand-written parsers
 * (directory.js / creds.js - shares, --ntds/--sam, roasting, laps, rid-brute, coerce, exec) carry
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
      return l.replace(/^\s*(?:SMB|LDAP|WINRM|MSSQL|RDP|FTP|SSH|WMI|VNC|NFS|[A-Z0-9_-]+)\s+\S+\s+\d+\s+\S+\s+/i, '').trim();
    }).filter(Boolean);
  }
  function hasDenied(text) { return /\[-\]|access[_ ]denied|logon failure|STATUS_|authentication failed|error/i.test(text); }
  // Filenames that routinely hold credentials/secrets - the "useful results" filter for a spider dump.
  var LOOT_HINT_RE = /passw|pwd|cred|secret|unattend|sysprep|web\.config|\.config\b|id_rsa|id_ed25519|\.ppk|\.kdbx|\.key\b|vnc|vpn|\.bak\b|backup|\.vmdk|\.ovpn|\.pfx\b|\.ps1\b|connection|database|\.kee?pass|autologin|\.gpg|\.pgp/i;
  // Stored-credential modules (mRemoteNG, WinSCP, PuTTY, Veeam, KeePass trigger, registry autologon...) all
  // print recovered user/password pairs in a handful of shapes. Pull them as candidate credentials.
  function modCreds(text, ws, kind) {
    var out = [], seen = {};
    payloadLines(text).forEach(function (l) {
      var m = l.match(/(?:user(?:name)?|login|ssid)[ \t]*[:=][ \t]*(\S+)[^\r\n]{0,160}?(?:pass(?:word)?|pwd|key)[ \t]*[:=][ \t]*(\S+)/i)
        || l.match(/^(\S+):([^:\s]{3,})$/);
      var pw = l.match(/(?:pass(?:word)?|pwd|key)[ \t]*[:=][ \t]*(\S{3,})/i);
      if (m && !seen[l]) { seen[l] = 1; out.push({ kind: 'credential.candidate', scope: host(ws), value: { kind: kind, user: m[1], password: m[2], tool: 'nxc' } }); }
      else if (pw && !m && !seen[l]) { seen[l] = 1; out.push({ kind: 'credential.candidate', scope: host(ws), value: { kind: kind, password: pw[1], tool: 'nxc' } }); }
    });
    return out;
  }

  // --------------------------- the catalog ---------------------------
  // Each entry: { id, proto, flag|module, produces:[...], locus:'R',
  //   existing?:true | informational?:true | extract:fn(text,ws,C)->[{kind,value}] , gate:[...] (for moves) }
  var CAT = [

    // ========================= SMB =========================
    { id: 'smb-auth', proto: 'smb', validate: true, produces: ['credential.available'], existing: true,
      gate: ['smb.reachable', 'port:445', 'credential.candidate', 'credential.available'] },
    { id: 'smb-shares', proto: 'smb', flag: '--shares', produces: ['smb.shares', 'smb.writable_share'], existing: true,
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
    { id: 'smb-dpapi', proto: 'smb', flag: '--dpapi', produces: ['credential.candidate', 'credential.plaintext', 'credential.available'],
      gate: ['access.admin', 'access.system'],
      extract: function (text, ws) {
        var out = [];
        payloadLines(text).forEach(function (l) {
          var up = l.match(/\[(?:SYSTEM|CREDENTIAL|CHROME|[^\]]+)\][ \t]*([^\s:]+\\[^\s:]+|[A-Za-z0-9_.-]+)[ \t]+-[ \t]+(?:password|secret)[ \t]*:[ \t]*(\S+)/i);
          var m = l.match(/\[(?:SYSTEM|CREDENTIAL|CHROME|[^\]]*)\][^\r\n]{0,200}?(?:password|secret)[ \t]*:[ \t]*(\S+)/i) || l.match(/\b([^\s:]+):([^\s:]{4,})\s*$/);
          if (m) {
            var pw = up ? up[2] : (m[2] || m[1]);
            var usr = up ? up[1] : (m[2] ? m[1] : undefined);
            out.push({ kind: 'credential.plaintext', scope: host(ws), value: { kind: 'dpapi', user: usr, password: pw, detail: l, tool: 'nxc' } });
            out.push({ kind: 'credential.candidate', scope: host(ws), value: { kind: 'dpapi', user: usr, password: pw, detail: l, tool: 'nxc' } });
            if (usr && pw) out.push({ kind: 'credential.available', scope: host(ws), value: { user: usr, password: pw, method: 'dpapi', service: 'smb' } });
          }
        });
        return out;
      } },
    { id: 'smb-loggedon', proto: 'smb', flag: '--loggedon-users', produces: ['ad.user_list'],
      gate: ['smb.reachable', 'credential.available'],
      extract: function (text, ws) {
        var users = C._usernames(text);
        return users.length ? [{ kind: 'ad.user_list', scope: dom(ws), value: { users: users, count: users.length, method: 'nxc-loggedon', note: 'users with a live session on this host (lateral-movement targets)' } }] : [];
      } },
    { id: 'smb-gpp-password', proto: 'smb', module: 'gpp_password', produces: ['credential.candidate', 'credential.plaintext', 'credential.available'],
      gate: ['smb.reachable', 'port:445'],
      extract: function (text, ws) {
        // nxc -M gpp_password prints decrypted creds: "Usernames: ['svc']" / "Found cpassword: pw" or "Passwords: ['pw']".
        var us = (text.match(/Usernames?\s*:\s*\[?['"]?([^'"\]\r\n]+)/i) || [])[1];
        var ps = (text.match(/(?:Found\s*c?passwords?|Passwords?)\s*:\s*\[?['"]?([^'"\]\r\n]+)/i) || [])[1];
        if (!us && !ps) return [];
        var rawUser = us ? us.trim() : '';
        var cleanPass = ps ? ps.trim() : '';
        var domPart = '';
        if (rawUser.indexOf('\\') >= 0) {
          var parts = rawUser.split(/\\+/);
          domPart = parts[0].trim();
          rawUser = parts[parts.length - 1].trim();
        }
        var cleanUser = rawUser.replace(/\s*\([^)]*\)\s*$/, '').trim();
        var domName = domPart || (C && C._domain_from_facts ? C._domain_from_facts(ws) : '') || (ws && ws.domain) || '';
        var out = [{ kind: 'credential.candidate', scope: host(ws), value: { kind: 'gpp_cpassword', user: cleanUser || rawUser, password: cleanPass, domain: domName, tool: 'nxc', via: 'gpp_password' } }];
        if (cleanUser && cleanPass) {
          out.push({ kind: 'credential.plaintext', scope: host(ws), value: { kind: 'gpp_plaintext', user: cleanUser, password: cleanPass, domain: domName, via: 'gpp_password' } });
          out.push({ kind: 'credential.available', scope: host(ws), value: { user: cleanUser, password: cleanPass, domain: domName, method: 'gpp-decrypt', via: 'gpp_password' } });
        }
        return out;
      } },
    { id: 'smb-gpp-autologin', proto: 'smb', module: 'gpp_autologin', produces: ['credential.candidate', 'credential.plaintext', 'credential.available'],
      gate: ['smb.reachable', 'port:445'],
      extract: function (text, ws) {
        var us = (text.match(/Usernames?\s*:\s*\[?['"]?([^'"\]\r\n]+)/i) || [])[1];
        var ps = (text.match(/(?:Found\s*c?passwords?|Passwords?)\s*:\s*\[?['"]?([^'"\]\r\n]+)/i) || [])[1];
        if (!us && !ps) return [];
        var rawUser = us ? us.trim() : '';
        var cleanPass = ps ? ps.trim() : '';
        var cleanUser = rawUser.split(/\\+/).pop().replace(/\s*\([^)]*\)\s*$/, '').trim();
        var domName = (C && C._domain_from_facts ? C._domain_from_facts(ws) : '') || (ws && ws.domain) || '';
        var out = [{ kind: 'credential.candidate', scope: host(ws), value: { kind: 'gpp_autologin', user: cleanUser || rawUser, password: cleanPass, tool: 'nxc', via: 'gpp_password' } }];
        if (cleanUser && cleanPass) {
          out.push({ kind: 'credential.plaintext', scope: host(ws), value: { kind: 'gpp_plaintext', user: cleanUser, password: cleanPass, domain: domName, via: 'gpp_password' } });
          out.push({ kind: 'credential.available', scope: host(ws), value: { user: cleanUser, password: cleanPass, domain: domName, method: 'gpp-decrypt', via: 'gpp_password' } });
        }
        return out;
      } },
    { id: 'smb-lsassy', proto: 'smb', module: 'lsassy', produces: ['hash.ntlm', 'credential.plaintext', 'credential.candidate', 'credential.available'],
      gate: ['access.admin', 'access.system'],
      extract: function (text, ws) {
        // lsassy lines: "[+] domain\user  <nthash>" or "domain\user  lm:nt" or "domain\user  <plaintext>".
        var out = [], seen = {};
        payloadLines(text).forEach(function (l) {
          l = l.replace(/^\[[-+*!]\]\s*/, '');
          var m = l.match(/^([A-Za-z0-9_.-]+\\[^\s]+)\s+(?:[a-f0-9]{32}:)?([a-f0-9]{32})\b/i);
          if (m && !seen[m[2]]) {
            seen[m[2]] = 1;
            var nt = m[2].toLowerCase();
            out.push({ kind: 'hash.ntlm', scope: host(ws), value: { user: m[1], nthash: nt, tool: 'nxc', via: 'lsassy' } });
            out.push({ kind: 'credential.candidate', scope: host(ws), value: { kind: 'lsass_ntlm', user: m[1], nthash: nt, tool: 'nxc', via: 'lsassy' } });
            return;
          }
          var p = l.match(/^([A-Za-z0-9_.-]+\\[^\s]+)\s+([^\s:][^\s]{2,})$/);
          if (p && !/^[a-f0-9]{32}$/i.test(p[2]) && !seen[l]) {
            seen[l] = 1;
            out.push({ kind: 'credential.plaintext', scope: host(ws), value: { user: p[1], password: p[2], tool: 'nxc', via: 'lsassy' } });
            out.push({ kind: 'credential.candidate', scope: host(ws), value: { kind: 'lsass_plaintext', user: p[1], password: p[2], tool: 'nxc', via: 'lsassy' } });
            out.push({ kind: 'credential.available', scope: host(ws), value: { user: p[1], password: p[2], method: 'lsassy', service: 'smb' } });
          }
        });
        return out;
      } },
    { id: 'smb-nanodump', proto: 'smb', module: 'nanodump', produces: ['hash.ntlm', 'credential.plaintext', 'credential.candidate', 'credential.available'],
      gate: ['access.admin', 'access.system'],
      extract: function (text, ws) { return CAT_BY_ID['smb-lsassy'].extract(text, ws); } },
    { id: 'smb-spider-plus', proto: 'smb', module: 'spider_plus', produces: ['loot.files', 'credential.candidate'],
      gate: ['smb.reachable', 'credential.available'],
      extract: function (text, ws) {
        // spider_plus crawls readable shares and writes a JSON manifest; its output names the saved file and
        // the files found. The manifest itself is loot.files; any found file whose NAME matches the
        // credential-material hints is a candidate secret worth pulling (the "filter for useful results"
        // signal - see the spider-secrets move).
        var out = [];
        if (/spider_plus|saved\s+(?:output|share)|found:|\.json\b/i.test(text)) {
          out.push({ kind: 'loot.files', scope: host(ws), value: { kind: 'spider_manifest', detail: 'nxc spider_plus crawl of readable shares', tool: 'nxc' } });
        }
        var hits = [];
        payloadLines(text).forEach(function (l) {
          if (LOOT_HINT_RE.test(l)) { var m = l.match(/[^\s\/\\]{1,120}\.[A-Za-z0-9]{1,8}\b|[^\s\/\\]{0,80}(?:passw|cred|secret|unattend|backup)[^\s\/\\]{0,80}/i); if (m) hits.push(m[0]); }
        });
        if (hits.length) out.push({ kind: 'credential.candidate', scope: host(ws), value: { kind: 'spider_secret_file', files: hits.slice(0, 50), count: hits.length, tool: 'nxc', note: 'filenames matching credential-material hints - pull and inspect' } });
        return out;
      } },
    { id: 'smb-wdigest', proto: 'smb', module: 'wdigest', produces: ['config.review'],
      gate: ['access.admin', 'access.system'],
      extract: function (text, ws) {
        return /enable|success|\[\+\]/i.test(text) ? [{ kind: 'config.review', scope: host(ws), value: { kind: 'wdigest_uselogoncredential', detail: 'WDigest cleartext-credential caching toggled (re-dump LSASS after a logon)', tool: 'nxc' } }] : [];
      } },

    { id: 'smb-enum-trusts', proto: 'smb', module: 'enum_trusts', produces: ['ad.trusts'], existing: true,
      gate: ['smb.reachable', 'credential.available'] },
    { id: 'smb-laps', proto: 'smb', flag: '--laps', produces: ['ad.laps_lead', 'credential.candidate'], existing: true,
      gate: ['smb.reachable', 'credential.available'] },
    { id: 'smb-timeroast', proto: 'smb', module: 'timeroast', produces: ['hash.sntp'], existing: true,
      gate: ['smb.reachable'] },
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

    // --- SMB LSASS-dump family (all emit domain\user -> hash/plaintext like lsassy) ---
    { id: 'smb-handlekatz', proto: 'smb', module: 'handlekatz', produces: ['hash.ntlm', 'credential.plaintext', 'credential.candidate', 'credential.available'],
      gate: ['access.admin', 'access.system'], extract: function (text, ws) { return CAT_BY_ID['smb-lsassy'].extract(text, ws); } },
    { id: 'smb-procdump', proto: 'smb', module: 'procdump', produces: ['hash.ntlm', 'credential.plaintext', 'credential.candidate', 'credential.available'],
      gate: ['access.admin', 'access.system'], extract: function (text, ws) { return CAT_BY_ID['smb-lsassy'].extract(text, ws); } },
    { id: 'smb-masky', proto: 'smb', module: 'masky', produces: ['hash.ntlm', 'credential.plaintext', 'credential.candidate', 'credential.available'],
      gate: ['access.admin', 'access.system'], extract: function (text, ws) { return CAT_BY_ID['smb-lsassy'].extract(text, ws); } },

    // --- SMB privileged dumps / registry secrets ---
    { id: 'smb-backup-operator', proto: 'smb', module: 'backup_operator', produces: ['loot.ntds', 'hash.ntlm'],
      gate: ['privesc.windows_privilege', 'access.admin'],
      extract: function (text, ws) {
        // SeBackupPrivilege -> remote registry-hive / NTDS dump: emits the same user:rid:lm:nt::: lines.
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
    { id: 'smb-keepass-discover', proto: 'smb', module: 'keepass_discover', produces: ['loot.keepass_dump', 'loot.files'],
      gate: ['foothold.windows', 'access.admin'],
      extract: function (text, ws) {
        if (/\.kdbx\b|keepass[^\r\n]{0,80}?found|found[^\r\n]{0,80}?\.kdbx/i.test(text) && !hasDenied(text)) {
          var m = text.match(/[A-Za-z]:\\[^\r\n"']{1,260}?\.kdbx\b|\/[^\s"']{1,260}?\.kdbx\b/i);
          return [
            { kind: 'loot.keepass_dump', scope: host(ws), value: { path: m ? m[0] : 'Database.kdbx', detail: 'KeePass .kdbx database discovered via nxc keepass_discover', tool: 'nxc' } },
            { kind: 'loot.files', scope: host(ws), value: { kind: 'keepass_kdbx', path: m ? m[0] : 'Database.kdbx', tool: 'nxc' } }
          ];
        }
        return [];
      } },
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
        // password - a usable credential candidate.
        var out = [];
        payloadLines(text).forEach(function (l) { var m = l.match(/([A-Za-z0-9_-]{1,64}\$)[ \t]*:[ \t]*([A-Za-z0-9_-]{1,64})/); if (m) out.push({ kind: 'credential.candidate', scope: dom(ws), value: { kind: 'pre2k_computer', user: m[1], password: m[2], tool: 'nxc' } }); });
        return out;
      } },
    { id: 'smb-ntlmv1', proto: 'smb', module: 'ntlmv1', produces: ['config.review'],
      gate: ['smb.reachable', 'port:445'],
      extract: function (text, ws) { return /ntlmv1.*(?:enabled|allow|vulnerable)|lmcompatibilitylevel\s*[:=]\s*[0-2]/i.test(text) ? [{ kind: 'config.review', scope: host(ws), value: { kind: 'ntlmv1_enabled', detail: 'NTLMv1 permitted - crackable/relayable', tool: 'nxc' } }] : []; } },

    // --- SMB defensive / coercion-enabler checks ---
    { id: 'smb-enum-av', proto: 'smb', module: 'enum_av', produces: ['defense.control'],
      gate: ['access.admin', 'access.system'],
      extract: function (text, ws) { return /defender|antivirus|edr|crowdstrike|carbon|sentinel|\bav\b/i.test(text) ? [{ kind: 'defense.control', scope: host(ws), value: { kind: 'av_edr', detail: payloadLines(text).slice(0, 10).join('; '), tool: 'nxc' } }] : []; } },
    { id: 'smb-spooler', proto: 'smb', module: 'spooler', produces: ['ad.coerced_auth'],
      gate: ['smb.reachable', 'port:445'],
      extract: function (text, ws) {
        return /spooler service (?:is )?(?:enabled|running)/i.test(text) && !/disabled|not running/i.test(text)
          ? [{ kind: 'ad.coerced_auth', scope: dom(ws), value: { detail: 'Print Spooler service enabled (coercion vector available)', tool: 'nxc', via: 'spooler' } }] : [];
      } },
    { id: 'smb-webdav', proto: 'smb', module: 'webdav', produces: ['ad.coerced_auth'],
      gate: ['smb.reachable', 'port:445'],
      extract: function (text, ws) {
        return /webclient service (?:is )?(?:enabled|running)/i.test(text) && !/disabled|not running/i.test(text)
          ? [{ kind: 'ad.coerced_auth', scope: dom(ws), value: { detail: 'WebClient service enabled (HTTP-to-LDAP/SMB coercion available)', tool: 'nxc', via: 'webdav' } }] : [];
      } },
    { id: 'smb-runasppl', proto: 'smb', module: 'runasppl', produces: ['defense.control'],
      gate: ['access.admin', 'access.system'],
      extract: function (text, ws) {
        return /runasppl.*(?:enabled|1|true)/i.test(text) && !/runasppl.*(?:disabled|not enabled|\b0\b|false)/i.test(text)
          ? [{ kind: 'defense.control', scope: host(ws), value: { kind: 'lsass_ppl', detail: 'RunAsPPL (LSASS Protected Process Light) enabled', tool: 'nxc' } }] : [];
      } },

    // --- SMB CVE-confirmation modules: a VULNERABLE verdict mints the fact that promotes the exploit move ---
    { id: 'smb-ms17-010', proto: 'smb', module: 'ms17-010', produces: ['smb.ms17_010'],
      gate: ['smb.reachable', 'port:445'],
      extract: function (text, ws) { return /\bvulnerable\b/i.test(text) && !/not\s+vulnerable/i.test(text) ? [{ kind: 'smb.ms17_010', scope: host(ws), value: { verdict: 'vulnerable', tool: 'nxc', cve: 'MS17-010' } }] : []; } },
    { id: 'smb-zerologon', proto: 'smb', module: 'zerologon', produces: ['ad.zerologon'],
      gate: ['ad.dc_candidate', 'smb.reachable'],
      extract: function (text, ws) { return /vulnerable|exploitable/i.test(text) && !/not\s+vulnerable/i.test(text) ? [{ kind: 'ad.zerologon', scope: host(ws), value: { verdict: 'vulnerable', tool: 'nxc', cve: 'CVE-2020-1472' } }] : []; } },
    { id: 'smb-smbghost', proto: 'smb', module: 'smbghost', produces: ['vuln.smbghost'],
      gate: ['smb.reachable', 'port:445'],
      extract: function (text, ws) { return /vulnerable/i.test(text) && !/not\s+vulnerable/i.test(text) ? [{ kind: 'vuln.smbghost', scope: host(ws), value: { verdict: 'vulnerable', tool: 'nxc', cve: 'CVE-2020-0796' } }] : []; } },
    { id: 'smb-nopac', proto: 'smb', module: 'nopac', produces: ['ad.nopac'],
      gate: ['credential.available', 'ad.dc_candidate'],
      extract: function (text, ws) {
        return (/\bvulnerable\b|TGT\s+with\s+PAC\s+size|\bnoPac\b.*(?:\[\+\]|vulnerable)/i.test(text)) && !/not\s+vulnerable/i.test(text)
          ? [{ kind: 'ad.nopac', scope: dom(ws), value: { verdict: 'vulnerable', tool: 'nxc', cve: 'CVE-2021-42278/CVE-2021-42287' } }] : [];
      } },
    { id: 'smb-printnightmare', proto: 'smb', module: 'printnightmare', produces: ['vuln.printnightmare'],
      gate: ['smb.reachable', 'port:445'],
      extract: function (text, ws) {
        return /\bvulnerable\b/i.test(text) && !/not\s+vulnerable/i.test(text)
          ? [{ kind: 'vuln.printnightmare', scope: host(ws), value: { verdict: 'vulnerable', tool: 'nxc', cve: 'CVE-2021-34527' } }] : [];
      } },
    { id: 'smb-enum-cve', proto: 'smb', module: 'enum_cve', produces: ['ad.zerologon', 'vuln.printnightmare', 'vuln.smbghost', 'ad.nopac', 'adcs.vulnerable', 'exploit.candidate'],
      gate: ['smb.reachable', 'port:445'],
      extract: function (text, ws) {
        if (!/vulnerable|cve-\d{4}-\d+/i.test(text) || /not\s+vulnerable|0\s+cve/i.test(text)) return [];
        var out = [];
        if (/cve-2020-1472|zerologon/i.test(text)) out.push({ kind: 'ad.zerologon', scope: host(ws), value: { verdict: 'vulnerable', tool: 'nxc', cve: 'CVE-2020-1472', via: 'enum_cve' } });
        if (/cve-2021-34527|cve-2021-1675|printnightmare/i.test(text)) out.push({ kind: 'vuln.printnightmare', scope: host(ws), value: { verdict: 'vulnerable', tool: 'nxc', cve: 'CVE-2021-34527', via: 'enum_cve' } });
        if (/cve-2020-0796|smbghost/i.test(text)) out.push({ kind: 'vuln.smbghost', scope: host(ws), value: { verdict: 'vulnerable', tool: 'nxc', cve: 'CVE-2020-0796', via: 'enum_cve' } });
        if (/cve-2021-42278|cve-2021-42287|nopac|samaccountname/i.test(text)) out.push({ kind: 'ad.nopac', scope: dom(ws), value: { verdict: 'vulnerable', tool: 'nxc', cve: 'CVE-2021-42278', via: 'enum_cve' } });
        if (/cve-2022-26923|certifried/i.test(text)) out.push({ kind: 'adcs.vulnerable', scope: dom(ws), value: { verdict: 'vulnerable', tool: 'nxc', cve: 'CVE-2022-26923', via: 'enum_cve' } });
        if (!out.length && /cve-\d{4}-\d+/i.test(text)) {
          var cves = text.match(/CVE-\d{4}-\d+/gi) || [];
          out.push({ kind: 'exploit.candidate', scope: host(ws), value: { cves: cves, detail: 'unpatched CVEs flagged by nxc enum_cve: ' + cves.join(', '), tool: 'nxc' } });
        }
        return out;
      } },

    // --- SMB more stored-application credentials ---
    { id: 'smb-rdcman', proto: 'smb', module: 'rdcman', produces: ['credential.candidate'],
      gate: ['foothold.windows', 'access.admin'], extract: function (text, ws) { return modCreds(text, ws, 'rdcman'); } },
    { id: 'smb-iis', proto: 'smb', module: 'iis', produces: ['credential.candidate'],
      gate: ['foothold.windows', 'access.admin'], extract: function (text, ws) { return modCreds(text, ws, 'iis_apppool'); } },
    { id: 'smb-firefox', proto: 'smb', module: 'firefox', produces: ['credential.candidate'],
      gate: ['foothold.windows', 'access.admin'], extract: function (text, ws) { return modCreds(text, ws, 'firefox'); } },
    { id: 'smb-powershell-history', proto: 'smb', module: 'powershell_history', produces: ['credential.candidate'],
      gate: ['foothold.windows', 'access.admin'], extract: function (text, ws) { return modCreds(text, ws, 'ps_history'); } },
    { id: 'smb-met-inject', proto: 'smb', module: 'met_inject', produces: ['foothold.windows'],
      gate: ['access.admin', 'access.system'],
      extract: function (text, ws) { return /\(Pwn3d!\)|injected|meterpreter|session opened/i.test(text) && !hasDenied(text) ? [{ kind: 'foothold.windows', scope: host(ws), value: { method: 'met_inject', tool: 'nxc' } }] : []; } },
    // SCF/URL/LNK drop on a writable share -> captures SMB auth from any user who browses it (pair with Responder).
    { id: 'smb-slinky', proto: 'smb', module: 'slinky', produces: ['config.review'],
      gate: ['smb.authenticated', 'credential.available'],
      extract: function (text, ws) { return /added|\.url|\.lnk|dropped|\[\+\]/i.test(text) && !hasDenied(text) ? [{ kind: 'config.review', scope: host(ws), value: { kind: 'malicious_file_drop', detail: 'URL/LNK planted on a writable share - run Responder to capture browsing users NetNTLM', tool: 'nxc' } }] : []; } },
    { id: 'smb-scuffy', proto: 'smb', module: 'scuffy', produces: ['config.review'],
      gate: ['smb.authenticated', 'credential.available'],
      extract: function (text, ws) { return CAT_BY_ID['smb-slinky'].extract(text, ws); } },

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
    { id: 'ldap-active-users', proto: 'ldap', flag: '--active-users', produces: ['ad.user_list'],
      gate: ['ldap.reachable', 'port:389'],
      extract: function (text, ws) {
        var users = C._usernames(text);
        return users.length ? [{ kind: 'ad.user_list', scope: dom(ws), value: { users: users, count: users.length, method: 'nxc-active-users' } }] : [];
      } },
    { id: 'ldap-groups', proto: 'ldap', flag: '--groups', informational: true, produces: [], gate: ['ldap.reachable', 'port:389'] },
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
        var knownDc = String((ws && (ws.dc_hostname || ws.dcHost || ws.hostname)) || '').split('.')[0].toLowerCase();
        function isDcPrincipalLine(l) {
          if (/\b(?:SERVER_TRUST_ACCOUNT|OU=Domain Controllers|Domain Controller)\b/i.test(l)) return true;
          var m = /\b([A-Za-z0-9._-]+)\$/.exec(l);
          if (m) {
            var base = m[1].split('.')[0].toLowerCase();
            if ((knownDc && base === knownDc) || /^dc\d*$/.test(base)) return true;
          }
          return false;
        }
        var nonDcUnconstrained = lines.filter(function (l) {
          if (/unconstrained/i.test(l)) return !isDcPrincipalLine(l);
          // nxc --trusted-for-delegation sometimes prints bare principal names (without the word "unconstrained")
          if (/^[A-Za-z0-9._-]+\$?\s*$/.test(l.trim()) || /\b[A-Za-z0-9._-]+\$(?=\s|$|[),;:])/.test(l)) {
            if (!/constrained|rbcd|allowedtodelegate/i.test(l) && !isDcPrincipalLine(l)) return false;
          }
          return false;
        });
        var constrainedOrRbcd = lines.some(function (l) { return /\b(?:constrained|rbcd|allowedtodelegate|allowedtoact)/i.test(l) && !/unconstrained/i.test(l); });
        var nonDcMachineOnly = !nonDcUnconstrained.length && !constrainedOrRbcd && lines.some(function (l) {
          return /\b[A-Za-z0-9._-]+\$(?=\s|$|[),;:])/.test(l) && !/unconstrained|constrained/i.test(l) && !isDcPrincipalLine(l);
        });
        if (nonDcUnconstrained.length) out.push({ kind: 'ad.unconstrained', scope: dom(ws), value: { detail: 'non-DC accounts trusted for unconstrained delegation', evidence: nonDcUnconstrained.slice(0, 4), tool: 'nxc' } });
        else if (constrainedOrRbcd || nonDcMachineOnly) out.push({ kind: 'ad.attack_paths', scope: dom(ws), value: { kind: 'delegation', detail: 'constrained/RBCD delegation accounts', tool: 'nxc' } });
        return out;
      } },
    { id: 'ldap-find-delegation', proto: 'ldap', flag: '--find-delegation', produces: ['ad.unconstrained', 'ad.attack_paths'],
      gate: ['credential.available', 'ldap.reachable'],
      extract: function (text, ws) { return CAT_BY_ID['ldap-trusted-for-delegation'].extract(text, ws); } },
    { id: 'ldap-gmsa', proto: 'ldap', flag: '--gmsa', produces: ['ad.gmsa', 'credential.candidate', 'credential.available', 'hash.ntlm'],
      gate: ['credential.available', 'ldap.reachable'],
      extract: function (text, ws) {
        var out = [], lines = payloadLines(text);
        if (lines.some(function (l) { return /gmsa|managedpassword|msDS-ManagedPassword/i.test(l); })) {
          out.push({ kind: 'ad.gmsa', scope: dom(ws), value: { detail: 'gMSA accounts present', tool: 'nxc' } });
          lines.forEach(function (l) {
            var m = l.match(/Account:\s*(\S+)\s+NTLM:\s*([a-f0-9]{32})/i);
            if (m) {
              var nthash = m[2].toLowerCase();
              out.push({ kind: 'credential.candidate', scope: dom(ws), value: { kind: 'gmsa', user: m[1], nthash: nthash, tool: 'nxc' } });
              out.push({ kind: 'credential.available', scope: dom(ws), value: { user: m[1], nthash: nthash, method: 'gmsa', service: 'ldap' } });
              out.push({ kind: 'hash.ntlm', scope: dom(ws), value: { count: 1, user: m[1], nthash: nthash } });
            }
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
        C.reAll(/Member:\s*([^\s,]+)/gi, text).forEach(function (m) {
          var u = C._clean_username(m[1] || '');
          if (C._valid_username(u) && users.indexOf(u) < 0) users.push(u);
        });
        users = C.uniqueSortedCI(users);
        return users.length ? [{ kind: 'ad.user_list', scope: dom(ws), value: { users: users, count: users.length, method: 'nxc-group-mem', note: 'members of the queried group' } }] : [];
      } },
    { id: 'ldap-password-not-required', proto: 'ldap', flag: '--password-not-required', produces: ['ad.user_list'],
      gate: ['credential.available', 'ldap.reachable'],
      extract: function (text, ws) {
        var users = C._usernames(text);
        return users.length ? [{ kind: 'ad.user_list', scope: dom(ws), value: { users: users, count: users.length, method: 'nxc-passnotreq', note: 'PASSWD_NOTREQD accounts (try a blank password)' } }] : [];
      } },

    { id: 'ldap-adcs', proto: 'ldap', module: 'adcs', produces: ['adcs.vulnerable', 'config.review'],
      gate: ['credential.available', 'ldap.reachable'],
      extract: function (text, ws) {
        // nxc ldap -M adcs lists CAs / templates; a vulnerable ESC template is the ADCS lead (-> adcs-esc /
        // certifried / cert-authenticate). A plain CA listing with PKI Enrollment Server / CN discovery mints config.review.
        if (/ESC\d|vulnerable|enrollee supplies subject|ENROLLEE_SUPPLIES_SUBJECT|EDITF_ATTRIBUTESUBJECTALTNAME/i.test(text)) {
          return [{ kind: 'adcs.vulnerable', scope: dom(ws), value: { detail: 'vulnerable ADCS template/CA via nxc adcs', tool: 'nxc' } }];
        }
        var srvM = /Found PKI Enrollment Server:\s*(\S+)/i.exec(text);
        var cnM = /Found CN:\s*([^\r\n]+)/i.exec(text);
        if (srvM || cnM) {
          var crVal = { kind: 'adcs_ca_discovered', detail: 'ADCS PKI Enrollment Server discovered via nxc adcs', tool: 'nxc' };
          if (srvM) crVal.server = srvM[1].trim();
          if (cnM) crVal.ca = cnM[1].trim();
          return [{ kind: 'config.review', scope: host(ws), value: crVal }];
        }
        return [];
      } },
    { id: 'ldap-badsuccessor', proto: 'ldap', module: 'badsuccessor', produces: ['ad.acl_lead', 'ad.control_paths', 'kerberos.tickets'],
      gate: ['credential.available', 'ldap.reachable'],
      extract: function (text, ws) {
        var out = [];
        var hasDmsaPerm = (/(?:Users|Principals|Accounts|Objects)\s+with\s+permissions\s+to\s+create\s+dMSA\s+objects|can\s+create\s+dMSA\s+objects|vulnerable\s+to\s+BadSuccessor|msDS-DelegatedManagedServiceAccount|\[\+\]\s*BADSUCCESSOR\b[^\r\n]*(?:found|allows|writable|OU=)/i.test(text))
          && !/\b(?:no|0)\s+(?:users|principals|accounts|ous?)\b[^\r\n]{0,40}?\b(?:with\s+permissions|found)\b|\bnot\s+vulnerable\b/i.test(text);
        var ticketM = /(?:(?:Service|TGT)\s+)?ticket\s+saved\s+to\s+['"]?([^\s'"]+\.(?:ccache|kirbi))['"]?|\bSaving\s+ticket\s+(?:in|to)\s+['"]?([^\s'"]+\.(?:ccache|kirbi))['"]?/i.exec(text);
        var ticketFile = ticketM ? (ticketM[1] || ticketM[2] || '').trim() : '';
        if (hasDmsaPerm) {
          out.push({ kind: 'ad.acl_lead', scope: dom(ws), value: { right: 'CreateChild-dMSA', detail: 'dMSA creation permission found via nxc badsuccessor', tool: 'nxc' } });
          out.push({ kind: 'ad.control_paths', scope: dom(ws), value: { right: 'CreateChild-dMSA', method: 'badsuccessor', tool: 'nxc' } });
        }
        if (ticketFile) {
          out.push({ kind: 'kerberos.tickets', scope: dom(ws), value: { file: ticketFile, files: [ticketFile], tool: 'nxc-badsuccessor' } });
          if (!hasDmsaPerm) {
            out.push({ kind: 'ad.acl_lead', scope: dom(ws), value: { right: 'CreateChild-dMSA', detail: 'dMSA ticket acquired via nxc badsuccessor', tool: 'nxc' } });
            out.push({ kind: 'ad.control_paths', scope: dom(ws), value: { right: 'CreateChild-dMSA', ticket: ticketFile, method: 'badsuccessor', tool: 'nxc' } });
          }
        }
        return out;
      } },
    { id: 'ldap-user-desc', proto: 'ldap', module: 'user-desc', produces: ['credential.candidate'],
      gate: ['credential.available', 'ldap.reachable'],
      extract: function (text, ws) {
        // Passwords left in the AD 'description' attribute - a classic. Mint any description that looks like
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
      extract: function (text, ws) { return /signing\s*(?:not|is not|none)|channel binding\s*(?:not|never)|not (?:enforced|required)/i.test(text) ? [{ kind: 'config.review', scope: host(ws), value: { kind: 'ldap_signing_not_enforced', detail: 'LDAP signing / channel binding not enforced - relayable', tool: 'nxc' } }] : []; } },

    // --- LDAP quota & informational ---
    { id: 'ldap-maq', proto: 'ldap', module: 'maq', produces: ['ad.maq_allow'],
      gate: ['credential.available', 'ldap.reachable'],
      extract: function (text, ws) {
        var m = text.match(/MachineAccountQuota\s*[:=]\s*(\d+)/i);
        var q = m ? parseInt(m[1], 10) : 0;
        return q >= 1 ? [{ kind: 'ad.maq_allow', scope: dom(ws), value: { quota: q, detail: 'MachineAccountQuota is ' + q + ' (domain users can add machine accounts)', tool: 'nxc' } }] : [];
      } },
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
    { id: 'mssql-query', proto: 'mssql', flag: '-q', produces: ['db.session', 'db.databases'], existing: true, gate: ['db.session'] },
    { id: 'mssql-priv', proto: 'mssql', module: 'mssql_priv', produces: ['db.session', 'mssql.sysadmin'],
      gate: ['db.session'],
      extract: function (text, ws) {
        if (/sysadmin|can impersonate|\(Pwn3d!\)|\[\+\].*admin/i.test(text) && !hasDenied(text)) {
          return [
            { kind: 'db.session', scope: host(ws), value: { service: 'mssql', privileged: true, tool: 'nxc' } },
            { kind: 'mssql.sysadmin', scope: host(ws), value: { detail: 'MSSQL sysadmin privilege confirmed or impersonated via nxc mssql_priv', tool: 'nxc' } }
          ];
        }
        return [];
      } },
    { id: 'mssql-coerce', proto: 'mssql', module: 'mssql_coerce', produces: ['ad.coerced_auth'],
      gate: ['db.session'],
      extract: function (text, ws) { return /received connection|coerc|\[\+\].*success|ntlmv2/i.test(text) ? [{ kind: 'ad.coerced_auth', scope: dom(ws), value: { detail: 'auth coerced via MSSQL (xp_dirtree/xp_fileexist)', tool: 'nxc' } }] : []; } },

    // ========================= RDP =========================
    { id: 'rdp-auth', proto: 'rdp', validate: true, produces: ['rdp.authenticated'], existing: true,
      gate: ['rdp.reachable', 'port:3389', 'credential.available', 'hash.ntlm'] },
    { id: 'rdp-exec', proto: 'rdp', flag: '-x', produces: ['foothold.windows'],
      gate: ['rdp.authenticated', 'rdp.reachable', 'port:3389'],
      extract: function (text, ws) {
        if (hasDenied(text)) return [];
        return /\(Pwn3d!\)|Executed command/i.test(text) ? [{ kind: 'foothold.windows', scope: host(ws), value: { service: 'rdp', method: 'rdp-exec', tool: 'nxc' } }] : [];
      } },
    { id: 'rdp-exec-ps', proto: 'rdp', flag: '-X', produces: ['foothold.windows'],
      gate: ['rdp.authenticated', 'rdp.reachable', 'port:3389'],
      extract: function (text, ws) {
        if (hasDenied(text)) return [];
        return /\(Pwn3d!\)|Executed command/i.test(text) ? [{ kind: 'foothold.windows', scope: host(ws), value: { service: 'rdp', method: 'rdp-exec-ps', tool: 'nxc' } }] : [];
      } },
    { id: 'rdp-screenshot', proto: 'rdp', flag: '--screenshot', produces: ['loot.files'], gate: ['rdp.reachable', 'port:3389'],
      extract: function (text, ws) {
        if (hasDenied(text)) return [];
        var m = text.match(/screenshot[^\r\n]*?\bsaved(?:\s+to)?\s+([^\s"']+\.png)\b/i)
          || text.match(/\bsaved(?:\s+screenshot)?(?:\s+to)?\s+([^\s"']+\.png)\b/i)
          || (/screenshot/i.test(text) && text.match(/([^\s"']{1,200}?\.png)\b/i));
        return m ? [{ kind: 'loot.files', scope: host(ws), value: { kind: 'rdp_screenshot', path: m[1], detail: 'RDP desktop screenshot saved by NetExec (--screenshot)', tool: 'nxc' } }] : [];
      } },
    { id: 'rdp-nla-screenshot', proto: 'rdp', flag: '--nla-screenshot', produces: ['loot.files'], gate: ['rdp.reachable', 'port:3389'],
      extract: function (text, ws) { return CAT_BY_ID['rdp-screenshot'].extract(text, ws); } },
    // --screentime sets how long the RDP session stays up for --screenshot: same capture, so it reuses the screenshot parser.
    { id: 'rdp-screentime', proto: 'rdp', flag: '--screentime', produces: ['loot.files'], gate: ['rdp.reachable', 'port:3389'],
      extract: function (text, ws) { return CAT_BY_ID['rdp-screenshot'].extract(text, ws); } },

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
    { id: 'ssh-sudo-check', proto: 'ssh', flag: '--sudo-check', produces: ['privesc.sudo_rights', 'foothold.linux'],
      gate: ['credential.available', 'ssh.reachable'],
      extract: function (text, ws) {
        if ((/\[\+\].*sudo|can run sudo|\(Pwn3d!\)|ALL\s*=\s*\(/i.test(text)) && !/cannot run sudo|not in the sudoers|\[-\]/i.test(text)) {
          return [
            { kind: 'privesc.sudo_rights', scope: host(ws), value: { detail: 'sudo rights confirmed via nxc ssh --sudo-check', tool: 'nxc' } },
            { kind: 'foothold.linux', scope: host(ws), value: { service: 'ssh', method: 'nxc-ssh-sudo', tool: 'nxc' } }
          ];
        }
        return [];
      } },

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
    { id: 'nfs-shares', proto: 'nfs', flag: '--shares', produces: ['loot.files', 'privesc.nfs_no_root_squash'],
      gate: ['port:2049', 'nfs.reachable'],
      extract: function (text, ws) {
        var exports = payloadLines(text).filter(function (l) { return /^\//.test(l) || /\s(?:rw|ro)\b/.test(l); });
        var out = [];
        if (exports.length) out.push({ kind: 'loot.files', scope: host(ws), value: { kind: 'nfs_exports', exports: exports.slice(0, 50), count: exports.length, tool: 'nxc', note: 'NFS exports - mount and read (watch for no_root_squash)' } });
        if (/no_root_squash|root\s+escape\s*:\s*true/i.test(text)) {
          out.push({ kind: 'privesc.nfs_no_root_squash', scope: host(ws), value: { detail: 'NFS share exported with no_root_squash / root escape enabled', tool: 'nxc' } });
        }
        return out;
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

  var MODULE_BANNER_MAP = {
    'gpp_pass': 'smb-gpp-password',
    'gpp_password': 'smb-gpp-password',
    'gpp_autologin': 'smb-gpp-autologin',
    'lsassy': 'smb-lsassy',
    'nanodump': 'smb-nanodump',
    'handlekatz': 'smb-handlekatz',
    'procdump': 'smb-procdump',
    'masky': 'smb-masky',
    'spider_plus': 'smb-spider-plus',
    'wdigest': 'smb-wdigest',
    'coerce_plus': 'smb-coerce-plus',
    'petitpotam': 'smb-coerce-plus',
    'dfscoerce': 'smb-coerce-plus',
    'shadowcoerce': 'smb-coerce-plus',
    'printerbug': 'smb-coerce-plus',
    'backup_operator': 'smb-backup-operator',
    'reg-winlogon': 'smb-reg-winlogon',
    'reg-query': 'smb-reg-query',
    'veeam': 'smb-veeam',
    'mremoteng': 'smb-mremoteng',
    'winscp': 'smb-winscp',
    'putty': 'smb-putty',
    'keepass_discover': 'smb-keepass-discover',
    'keepass_trigger': 'smb-keepass-trigger',
    'install_elevated': 'smb-install-elevated',
    'pre2k': 'smb-pre2k',
    'ntlmv1': 'smb-ntlmv1',
    'enum_av': 'smb-enum-av',
    'spooler': 'smb-spooler',
    'webdav': 'smb-webdav',
    'runasppl': 'smb-runasppl',
    'ms17-010': 'smb-ms17-010',
    'zerologon': 'smb-zerologon',
    'smbghost': 'smb-smbghost',
    'nopac': 'smb-nopac',
    'printnightmare': 'smb-printnightmare',
    'enum_cve': 'smb-enum-cve',
    'rdcman': 'smb-rdcman',
    'iis': 'smb-iis',
    'firefox': 'smb-firefox',
    'powershell_history': 'smb-powershell-history',
    'met_inject': 'smb-met-inject',
    'slinky': 'smb-slinky',
    'scuffy': 'smb-scuffy',
    'daclread': 'ldap-daclread',
    'group-mem': 'ldap-group-mem',
    'adcs': 'ldap-adcs',
    'badsuccessor': 'ldap-badsuccessor',
    'badsucce': 'ldap-badsuccessor',
    'user-desc': 'ldap-user-desc',
    'get-desc-users': 'ldap-get-desc-users',
    'enum_trusts': 'ldap-enum-trusts',
    'ldap-checker': 'ldap-ldap-checker',
    'maq': 'ldap-maq',
    'mssql_priv': 'mssql-priv',
    'mssql_coerce': 'mssql-coerce'
  };

  // Which capabilities does a command invoke? Matches the protocol + each flag/module token present.
  function match(command, text) {
    var lc = String(command || '').toLowerCase();
    var protoM = lc.match(/\b(?:nxc|netexec|crackmapexec|cme)\s+(smb|ldap|winrm|mssql|rdp|ftp|ssh|wmi|vnc|nfs)\b/);
    if (!protoM && text) {
      protoM = /^\s*(SMB|LDAP|WINRM|MSSQL|RDP|FTP|SSH|WMI|VNC|NFS)\s+\d{1,3}(?:\.\d{1,3}){3}\s+\d+/im.exec(text);
    }
    var proto = protoM ? protoM[1].toLowerCase() : null;
    var out = [];
    if (proto) {
      out = CAT.filter(function (e) {
        if (e.proto !== proto) return false;
        if (e.module) {
          if (e.module === 'coerce_plus' && /-m\s+(?:coerce_plus|petitpotam|dfscoerce|shadowcoerce|printerbug)\b/i.test(lc)) return true;
          return new RegExp('-m\\s+' + e.module + '\\b', 'i').test(lc);
        }
        if (e.flag) { var f = e.flag.replace(/[-]/g, '\\-'); return new RegExp('(^|\\s)' + f + '(\\s|$|=)', 'i').test(command); }
        // A validate-only entry with its own extractor (e.g. ftp-auth -> loot.files from a listing) runs when
        // no flag/module is present on the command; plain auth-success (credential.available) stays with
        // _parse_nxc_common, so these two don't collide.
        if (e.validate && e.extract) return !/(^|\s)(-M\s|--)/i.test(command);
        return false;
      });
    }
    if (text) {
      var bannerRe = /^\s*([A-Z0-9_.-]{3,20})\s+\d{1,3}(?:\.\d{1,3}){3}\s+\d+\s+\S+/gm, bm;
      while ((bm = bannerRe.exec(text)) !== null) {
        var bKey = bm[1].toLowerCase().replace(/\.+$/, '');
        var catId = MODULE_BANNER_MAP[bKey];
        if (catId && CAT_BY_ID[catId] && out.indexOf(CAT_BY_ID[catId]) < 0) {
          out.push(CAT_BY_ID[catId]);
        }
      }
      if (!command || !/(^|\s)(-M\s|--)/i.test(command)) {
        if (/\[(?:SYSTEM|CREDENTIAL|CHROME)\].*?(?:password|secret)\s*:/i.test(text) && out.indexOf(CAT_BY_ID['smb-dpapi']) < 0) out.push(CAT_BY_ID['smb-dpapi']);
        if ((/Account:\s*\S+\s+NTLM:\s*[a-f0-9]{32}/i.test(text) || /msDS-ManagedPassword/i.test(text)) && out.indexOf(CAT_BY_ID['ldap-gmsa']) < 0) out.push(CAT_BY_ID['ldap-gmsa']);
        if (/^\s*LDAP\s+\S+\s+\d+\s+\S+\s+.*\bunconstrained\b/im.test(text) && out.indexOf(CAT_BY_ID['ldap-trusted-for-delegation']) < 0) out.push(CAT_BY_ID['ldap-trusted-for-delegation']);
        if (/^\s*NFS\s+\S+\s+\d+\s+\S+\s+.*(?:\s(?:rw|ro)\b|\s\/)/im.test(text) && out.indexOf(CAT_BY_ID['nfs-shares']) < 0) out.push(CAT_BY_ID['nfs-shares']);
      }
    }
    return out;
  }

  function _parse_nxc_capability(text, command, ws, source, facts) {
    if (hasDenied(text) && !/\[\+\]/.test(text) && !/\bvulnerable\b/i.test(text)) return; // a pure failure/denied paste mints nothing
    match(command, text).forEach(function (e) {
      if (!e || !e.extract || e.existing || e.informational) return;
      var got;
      try { got = e.extract(text, ws, C) || []; } catch (x) { got = []; }
      got.forEach(function (f) { _add(facts, mkFact(f.kind, f.scope || host(ws), f.value || {}, S, source)); });
    });
    if (/-m\s+wifi\b/i.test(command || '') || /^\s*WIFI\s+\d{1,3}(?:\.\d{1,3}){3}\s+\d+/im.test(text || '')) {
      modCreds(text, ws, 'wifi').forEach(function (f) {
        _add(facts, mkFact(f.kind, f.scope || host(ws), f.value || {}, S, source));
      });
    }
  }
  C._parse_nxc_capability = _parse_nxc_capability;

})(typeof globalThis !== 'undefined' ? globalThis : this);
