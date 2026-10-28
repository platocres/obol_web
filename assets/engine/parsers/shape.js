/*!
 * obol engine - parsers/shape.js
 * The output-shape fallback (Approach A): a final pass that recognizes common tool output by its
 * SHAPE, not by the command that produced it, so a paste with no command line (or a command the
 * dispatcher does not key on) still yields the facts the shape unambiguously proves.
 *
 * It is strictly additive and conservative:
 *   - every branch is guarded by `facts` it would duplicate, so it only fills gaps the command-keyed
 *     dispatch left, and never changes a result a real parser already produced;
 *   - every recognizer is anchored (line-start port rows, a real HTTP status line / Server header, a
 *     literal $krb5asrep$ / $krb5tgs$ hash token), so prose and unrelated output mint nothing;
 *   - hash shapes delegate to the real hash parsers, so the fact TYPE is always correct.
 * Facts are never invented: a shape that does not match adds nothing.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var C = OBOL._parserCommon;
  if (!C || !C.mkFact) return;
  var mkFact = C.mkFact, _add = C._add, S = C.ProofState.SUPPORTED;

  function hasKind(facts, kind) { return facts.some(function (f) { return f.kind === kind; }); }
  function hasPrefix(facts, pre) { return facts.some(function (f) { return f.kind && f.kind.indexOf(pre) === 0; }); }
  function uniqNums(arr) { var s = {}; arr.forEach(function (n) { s[n] = 1; }); return Object.keys(s).map(Number).sort(function (a, b) { return a - b; }); }

  function _parse_shape(text, ws, source, facts) {
    text = String(text || '');
    if (text.length > 10485760) text = text.slice(0, 10485760);
    if (C._normalize_cr) text = C._normalize_cr(text);
    if (C._strip_tmux_split) text = C._strip_tmux_split(text);
    if (C._unwrap_kerberos_hashes) text = C._unwrap_kerberos_hashes(text);
    if (!text.trim()) return;
    var h = 'host:' + ws.target;

    // (1) A bare "N/tcp open service" port table (or gnmap / masscan / rustscan row), pasted without an
    //     nmap command line. The row pattern is anchored and excludes open|filtered.
    if (!hasPrefix(facts, 'port:') && /(?:\d\/(?:tcp|udp)\b|\bOpen\s+\S+:\d+|\d\/open\/)/i.test(text)) {
      var rowRe = /^[ \t]*(\d{1,5})\/(tcp|udp)[ \t]+open(?![|\w])(?:[ \t]+(\S+))?/i;
      var discRe = /Discovered open port (\d{1,5})\/(tcp|udp) on \S+/i;
      var rustRe = /^\s*Open\s+(?:\d{1,3}(?:\.\d{1,3}){3}|\[?[0-9a-fA-F:]+\]?):(\d{1,5})\s*$/i;
      var gnmapRe = /\b(\d{1,5})\/open\/(tcp|udp)\/[^\/,\r\n]*\/([^\/,\s\r\n]*)/gi;
      var summary = [], seen = {};
      function addShapePort(port, proto, service) {
        if (!port || port > 65535) return;
        proto = (proto || 'tcp').toLowerCase();
        var key = port + '/' + proto;
        if (seen[key]) return; seen[key] = 1;
        service = (service || '').trim();
        var value = { port: port, protocol: proto, via: 'shape' };
        if (service && service.toLowerCase() !== 'open') value.service = service;
        _add(facts, mkFact('port:' + port, h, value, S, source));
        if (value.service && C._normalize_service) _add(facts, mkFact('service.' + C._normalize_service(value.service), h, value, S, source));
        if (C._parse_service_reachability) C._parse_service_reachability(port, proto, value.service || '', ws, source, facts);
        summary.push(port);
      }
      text.split(/\r?\n/).forEach(function (line) {
        var mm = rowRe.exec(line);
        if (mm) { addShapePort(parseInt(mm[1], 10), mm[2], mm[3]); return; }
        var dm = discRe.exec(line);
        if (dm) { addShapePort(parseInt(dm[1], 10), dm[2], ''); return; }
        var rm = rustRe.exec(line);
        if (rm) { addShapePort(parseInt(rm[1], 10), 'tcp', ''); return; }
        var gm;
        gnmapRe.lastIndex = 0;
        while ((gm = gnmapRe.exec(line)) !== null) {
          addShapePort(parseInt(gm[1], 10), gm[2], gm[3]);
        }
      });
      if (summary.length) {
        _add(facts, mkFact('ports.open', h, { ports: uniqNums(summary), via: 'shape' }, S, source));
        if (!hasKind(facts, 'host.os_family') && C._add_os_from_text) {
          var osPortText = text.replace(/^\s*\d+\/(?:tcp|udp)\s+(?:closed|filtered|unfiltered|open\|filtered)\b[^\r\n]*$/gim, '');
          C._add_os_from_text(osPortText, ws, source, facts, 'shape', 'medium', true);
        }
      }
    }

    // (2) A bare HTTP response (a real status line, or a Server header), pasted without a web-client
    //     command. The dispatcher gates its HTTP parsers on curl/whatweb/wget/etc., so a raw response
    //     saved to a file mints nothing. A status line or a Server header is an unambiguous web signal.
    var isNslookup = /^Server:[ \t]*\S+[ \t]*\r?\nAddress(?:es)?[ \t]*:/im.test(text);
    var isHttpShape = !isNslookup && (/^(?:<\s*)?HTTP\/[0-9.]+\s+\d{3}\b/im.test(text) || /^(?:<\s*)?Server:[ \t]*\S/im.test(text));
    if (isHttpShape && !hasKind(facts, 'http.reachable')) {
      _add(facts, mkFact('http.reachable', h, { via: 'shape' }, S, source));
      var servers = [];
      (text.match(/^(?:<\s*)?Server:[ \t]*(.+)$/gim) || []).forEach(function (l) {
        var v = l.replace(/^(?:<\s*)?Server:[ \t]*/i, '').trim();
        if (v && servers.indexOf(v) < 0) servers.push(v);
      });
      var webServers = servers.filter(function (hdr) { return !(C._isNonWebServerHeader && C._isNonWebServerHeader(hdr)); });
      if (webServers.length) _add(facts, mkFact('web.server', h, { headers: webServers.slice(0, 10), via: 'shape' }, S, source));
      if (!hasKind(facts, 'host.os_family') && C._add_os_from_text) {
        var hdrEndIdx = text.search(/\r?\n\r?\n|<html\b|<!doctype\b/i);
        var httpHdrBlock = hdrEndIdx >= 0 ? text.slice(0, hdrEndIdx) : text.slice(0, 4096);
        C._add_os_from_text(httpHdrBlock, ws, source, facts, 'shape', 'medium', true);
      }
    }

    // (3) A crackable-hash blob, pasted without the tool that produced it. Skip if the paste is
    //     already cracking output (e.g. hashcat --show `<hash>:<plaintext>`), so the plaintext isn't
    //     re-appended into the hash token.
    var isCrack = (C._is_cracking_command && C._is_cracking_command(source)) || /\$krb5(?:asrep|tgs)\$[^\s:]+\$[0-9a-f]{32,}:[^\s:]+/i.test(text);
    if (!isCrack && /\$krb5asrep\$/i.test(text) && !hasKind(facts, 'hash.asrep') && C._parse_asrep_hashes) C._parse_asrep_hashes(text, ws, source, facts);
    if (!isCrack && /\$krb5tgs\$/i.test(text) && !hasKind(facts, 'hash.tgs') && C._parse_tgs_hashes) C._parse_tgs_hashes(text, ws, source, facts);
    if (/^(?:ServicePrincipalName\s+Name|Name\s+MemberOf\s+PasswordLastSet)/im.test(text) && !hasKind(facts, 'ad.user_list') && C._parse_impacket_roast_table) {
      C._parse_impacket_roast_table(text, ws, source, facts);
    }

    // (4) Share download output or GPP cpassword XML/grep without command
    if (text.indexOf('getting file ') >= 0 && !hasKind(facts, 'loot.files') && C._parse_share_inventory) {
      C._parse_share_inventory(text, ws, 'smbclient', source, facts);
    }
    if ((text.indexOf('cpassword=') >= 0 || text.indexOf('cpassword =') >= 0) && !facts.some(function (f) { return f && (f.kind === 'loot.gpp' || (f.kind === 'credential.candidate' && f.value && (f.value.kind === 'gpp' || f.value.kind === 'gpp_cpassword'))); }) && C._parse_gpp_artifacts) {
      C._parse_gpp_artifacts(text, ws, source, facts);
    }

    // (5) Ligolo-ng tunnel establishment or session shape pasted without command
    if ((/(\[Tunnel\] Interface ligolo is UP|session connected|Agent joined:)/i.test(text) || /ligolo-proxy[^\r\n]{0,80}?listening/i.test(text)) && !hasKind(facts, 'tunnel.route')) {
      _add(facts, mkFact('tunnel.route', h, { via: 'ligolo', shape: true }, S, source));
      _add(facts, mkFact('pivot.active', h, { via: 'ligolo', shape: true }, S, source));
    }

    // (6) Raw SQLite database dump or table schema shape pasted without command
    if ((text.indexOf('|') >= 0 || /SQLite format 3|CREATE TABLE\s+/i.test(text)) && /(SQLite format 3|CREATE TABLE\s+(?:partners|users|accounts|credentials)|^\s*\d+\|[a-zA-Z0-9_.-]+\|\$2[aby]\$)/im.test(text) && !hasKind(facts, 'loot.material')) {
      _add(facts, mkFact('loot.material', h, { kind: 'sqlite_db', via: 'shape' }, S, source));
    }

    // (7) Ping TTL heuristic: TTL 60..64 -> Linux os_hint, TTL 124..128 -> Windows os_hint (promote = false)
    if (!hasKind(facts, 'host.os_family') && !hasKind(facts, 'host.os_hint') && C._add_os_observation && /ttl=/i.test(text)) {
      var mTtl = /\b\d+\s+bytes\s+from\s+\S+[^\r\n]{0,120}?\bttl=(\d{1,3})\b/i.exec(text) || /Reply from \S+:\s+bytes=\d+\s+time[=<]\S+\s+TTL=(\d{1,3})/i.exec(text);
      if (mTtl) {
        var ttl = parseInt(mTtl[1], 10);
        if (ttl >= 60 && ttl <= 64) {
          C._add_os_observation(facts, ws, source, 'linux', mTtl[0], 'medium', 'ping-ttl', false);
        } else if (ttl >= 124 && ttl <= 128) {
          C._add_os_observation(facts, ws, source, 'windows', mTtl[0], 'medium', 'ping-ttl', false);
        }
      }
    }

    // (8) Un-keyed OS / kernel / version shapes (uname -a, /proc/version, uname -r, /etc/os-release, lsb_release, ver, sudo -V, pkexec --version)
    // Skip raw HTTP HTML bodies unless the HTTP response also proves RCE / LFI (e.g. uid=0(root) or root:x:0:0:).
    var isWebRceShape = /uid=\d+\([A-Za-z0-9_.-]+\)|^root:[x*!]:0:0:/m.test(text);
    if (!isHttpShape || isWebRceShape) {
      if (!hasKind(facts, 'host.kernel')) {
        var mUname = C._UNAME_RE && C._UNAME_RE.exec(text);
        var mProcVer = !mUname && /Linux version\s+([0-9][^\s]+)/i.exec(text);
        var mBareKernel = !mUname && !mProcVer && /^\s*([2-6]\.\d+\.\d+-(?:[0-9A-Za-z.+_-]*(?:generic|amd64|i[3-6]86|arm64|el\d|kali|debian|ubuntu|arch|alpine)[0-9A-Za-z.+_-]*|\d+-[A-Za-z0-9.+_-]+))\s*$/m.exec(text);
        if (mUname || mProcVer || mBareKernel) {
          var kStr = mUname ? ((mUname.groups && mUname.groups.kernel) || mUname[2]) : (mProcVer ? mProcVer[1] : mBareKernel[1].trim());
          var archStr = mUname ? ((mUname.groups && mUname.groups.arch) || mUname[3]) : '';
          var kLine = (mUname ? mUname[0] : (mProcVer ? mProcVer[0] : mBareKernel[0])).trim();
          _add(facts, mkFact('host.kernel', h, { kernel: kStr, via: 'shape' }, S, source));
          if (archStr && !hasKind(facts, 'host.arch')) {
            _add(facts, mkFact('host.arch', h, { arch: archStr, via: 'shape' }, S, source));
          }
          if (C._add_os_observation) {
            var kProd = C._os_product_from_label ? C._os_product_from_label(kLine, 'linux') : null;
            C._add_os_observation(facts, ws, source, 'linux', kLine, 'high', 'uname', true, kProd);
          }
          var isRemoteSnmpOrScan = /\b(?:snmpwalk|snmp-check|onesixtyone|nmap)\b/i.test(source || '');
          if (!isRemoteSnmpOrScan && C._check_linux_kernel_vulns) C._check_linux_kernel_vulns(kStr, ws, source, facts);
        }
        var mWinVer = /Microsoft Windows \[Version\s+([0-9.]+)\]/i.exec(text);
        if (mWinVer) {
          var wVer = mWinVer[1].trim();
          _add(facts, mkFact('host.kernel', h, { kernel: wVer, tool: 'ver', via: 'shape' }, S, source));
          if (C._add_os_observation) {
            C._add_os_observation(facts, ws, source, 'windows', mWinVer[0], 'high', 'ver', true, 'Windows ' + wVer);
          }
        }
      }
      var mOsRel = /PRETTY_NAME\s*=\s*["']?([^"'\r\n]+)["']?/i.exec(text) || /Distributor ID:\s*(\S+)/i.exec(text);
      if (mOsRel && C._add_os_observation) {
        C._add_os_observation(facts, ws, source, 'linux', mOsRel[0], 'high', 'os-release', true, mOsRel[1].trim());
      }
      var mSudoV = /Sudo(?:\s+version|\s+policy\s+plugin\s+version)\s+(1\.(?:8\.(?:[2-9]|[12]\d|3[01])|9\.[0-5](?:p1)?))\b/i.exec(text);
      if (mSudoV && !hasKind(facts, 'vuln.baron_samedit')) {
        _add(facts, mkFact('vuln.baron_samedit', h, { version: mSudoV[1], cve: 'CVE-2021-3156', via: 'shape', lead: true }, S, source));
      }
      var mPkexec = /pkexec\s+version\s+(0\.(?:0\d\d|10[0-5]))\b/i.exec(text);
      if (mPkexec && !hasKind(facts, 'vuln.polkit')) {
        _add(facts, mkFact('vuln.polkit', h, { version: mPkexec[1], cve: 'CVE-2021-4034', via: 'shape', lead: true }, S, source));
      }
    }

    _parse_family_resemblance(text, ws, source, facts);
  }

  function _parse_family_resemblance(text, ws, source, facts) {
    text = String(text || '');
    if (text.length > 10485760) text = text.slice(0, 10485760);
    if (!text.trim()) return;
    var h = 'host:' + ws.target;
    var domScope = C._scope_for_domain ? C._scope_for_domain(ws) : h;
    var lines = text.split(/\r?\n/);

    // 1. AD ACL / Object Control Family
    // Lines containing both an ACL right token and a target/principal identifier
    var isHttpResp = /^(?:<\s*)?HTTP\/[12](?:\.\d)?\s+\d{3}\b/im.test(text);
    var isKnownLinux = (ws && (ws.facts || ws.seedFacts) || []).some(function (f) {
      return f && f.scope === h && (f.kind === 'foothold.linux' || (f.kind === 'host.os_family' && f.value && f.value.family === 'linux'));
    });
    if (!hasKind(facts, 'ad.acl_lead') && !hasKind(facts, 'ad.control_paths') && !isHttpResp && !isKnownLinux) {
      var aclRightRe = /\b(GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword|AddMember|AddSelf|AllExtendedRights|AddKeyCredentialLink|ReadLAPSPassword|ReadGMSAPassword|WriteSPN|WriteProperty)\b/i;
      var aclPrincipalRe = /(?:CN=|DC=|@|(?<![a-zA-Z0-9._-])[a-zA-Z0-9._-]{1,64}\\[a-zA-Z0-9._-]{1,64}|\bDomain Admins\b|\bBackup Operators\b|\bDnsAdmins\b|\bUsers\b|\bComputers\b)/i;
      var matchedAclRight = '', matchedPrincipal = '';
      for (var i = 0; i < lines.length; i++) {
        var l = lines[i];
        var mr = aclRightRe.exec(l);
        if (!mr) continue;
        var mp = aclPrincipalRe.exec(l);
        if (mp) {
          matchedAclRight = mr[1];
          matchedPrincipal = mp[0];
          break;
        }
      }
      if (matchedAclRight) {
        _add(facts, mkFact('ad.acl_lead', domScope, { right: matchedAclRight, principal: matchedPrincipal, via: 'shape' }, S, source));

      }
    }

    // 2. ADCS / Certificate Template Family
    // Output containing both a CA/template header and an explicit vulnerability/ESC signal
    if (!hasKind(facts, 'adcs.vulnerable')) {
      var adcsHeaderRe = /(?:CA Name|Template Name|pKIEnrollmentService|Certipy|Certificate Authorities)/i;
      var adcsVulnRe = /(?:Enrollee\s*Supplies\s*Subject["']?\s*:\s*(?:True|true)|ENROLLEE_SUPPLIES_SUBJECT|\bESC[1-9]\d?\b|\[!\]\s*Vulnerabilities)/i;
      if (adcsHeaderRe.test(text) && adcsVulnRe.test(text)) {
        var esc = [];
        if (/\bESC1\b|Enrollee\s*Supplies\s*Subject["']?\s*:\s*(?:True|true)|ENROLLEE_SUPPLIES_SUBJECT/i.test(text)) esc.push('ESC1');
        var escM = text.match(/\bESC([2-9]|1[0-5])\b/gi) || [];
        escM.forEach(function (e) {
          var up = e.toUpperCase();
          if (esc.indexOf(up) < 0) esc.push(up);
        });
        _add(facts, mkFact('adcs.vulnerable', domScope, { esc: esc, via: 'shape' }, S, source));
      }
    }

    // 3. Kerberos SPN & AS-REP Directory Entry Family
    // Output containing both an identity field and either a <service>/<host> SPN pattern or DONT_REQ_PREAUTH
    if (!hasKind(facts, 'ad.user_list')) {
      var idFieldRe = /(?:sAMAccountName|\bcn:|\bUser:)\s*[:=]\s*([A-Za-z0-9._-]+)/gi;
      var spnRe = /\b(MSSQLSvc|HTTP|cifs|ldap|host|wsman|krbtgt|exchangeMDB)\/(?![0-9]+(?:\.[0-9]+)?\b)([A-Za-z0-9._-]*[A-Za-z][A-Za-z0-9._-]*)/i;
      var asrepRe = /(?:DONT_REQ_PREAUTH|UF_DONT_REQUIRE_PREAUTH|DoesNotRequirePreAuth\s*:\s*True)/i;
      if (spnRe.test(text) || asrepRe.test(text)) {
        var foundUsers = [], foundUsersSeen = Object.create(null), mId;
        while ((mId = idFieldRe.exec(text)) !== null) {
          var uName = mId[1];
          if (uName && !foundUsersSeen[uName] && !/\//.test(uName)) { foundUsersSeen[uName] = 1; foundUsers.push(uName); }
        }
        if (foundUsers.length) {
          _add(facts, mkFact('ad.user_list', domScope, { users: foundUsers, count: foundUsers.length, via: 'shape' }, S, source));
        }
      }
    }

    // 4. Share Table Family
    // Multi-line table containing at least one standard share alongside permission tokens (READ, WRITE, Disk)
    if (!hasKind(facts, 'smb.shares')) {
      var stdShareRe = /(?:^|\s)(?:IPC\$|ADMIN\$|C\$|SYSVOL|NETLOGON)(?=\s|$)/i;
      var permRe = /\b(READ|WRITE|Disk)\b/i;
      if (stdShareRe.test(text) && permRe.test(text)) {
        _add(facts, mkFact('smb.shares', h, { via: 'shape' }, S, source));
        var hasRead = false, hasWrite = false;
        for (var j = 0; j < lines.length; j++) {
          var row = lines[j];
          if (/(?:^|\s)(?:IPC\$|PRINT\$)(?=\s|$)/i.test(row) || /\bNO\s+ACCESS\b/i.test(row)) continue;
          if (/\bREAD\b/i.test(row)) hasRead = true;
          if (/\bWRITE\b/i.test(row)) hasWrite = true;
        }
        if (hasRead && !hasKind(facts, 'smb.readable_share')) _add(facts, mkFact('smb.readable_share', h, { via: 'shape' }, S, source));
        if (hasWrite && !hasKind(facts, 'smb.writable_share')) _add(facts, mkFact('smb.writable_share', h, { via: 'shape' }, S, source));
      }
    }
  }
  C._parse_family_resemblance = _parse_family_resemblance;

  C._parse_shape = _parse_shape;

  // ---- known-exploit fingerprint recognizer ---------------------------------------------------
  // When pasted service/version output (an nmap -sV banner, a whatweb line, a CHANGELOG, an nmap
  // vuln-script verdict) names a product+version, or a CVE/handshake token, that a promoted
  // known-exploit module targets, mint a vuln.<name> LEAD so the coach lights that exact module.
  // Strictly conservative and anchored on specific version/product/CVE tokens, so unrelated output
  // mints nothing. A lead is a candidate to try, never proof of exploitation: the module's own
  // produces fact (a real shell) is what proves the box, exactly as the proof discipline requires.
  var VULN_SIGS = [
    { fact: 'vuln.vsftpd_234', re: /\bvsftpd[\s_-]*2\.3\.4\b/i, cve: 'CVE-2011-2523' },
    { fact: 'vuln.proftpd_modcopy', re: /\bproftpd\s+1\.3\.5[a-z]?\b|\bmod_copy\b/i, cve: 'CVE-2015-3306' },
    { fact: 'vuln.samba_usermap', re: /\bsamba\s+(?:smbd\s+)?3\.0\.2[0-5][a-d]?\b|(?:^|[^A-Za-z0-9-])smb-vuln-cve2007-2447\b(?![\s\S]{0,120}?\bNOT\s+VULNERABLE\b)[\s\S]{0,120}?\bVULNERABLE\b/i, cve: 'CVE-2007-2447' },
    { fact: 'vuln.smbghost', re: /\bSMBGhost\b|CVE-2020-0796/i, cve: 'CVE-2020-0796' },
    { fact: 'vuln.bluekeep', re: /\bBlueKeep\b|CVE-2019-0708|(?:^|[^A-Za-z0-9-])rdp-vuln-ms19-0708\b(?![\s\S]{0,120}?\bNOT\s+VULNERABLE\b)[\s\S]{0,120}?\bVULNERABLE\b/i, cve: 'CVE-2019-0708' },
    { fact: 'vuln.shellshock', re: /\bShellshock\b|CVE-2014-6271|\/cgi-bin\/|\bmod_cgi\b/i, cve: 'CVE-2014-6271' },
    { fact: 'vuln.heartbleed', re: /\bHeartbleed\b|CVE-2014-0160|(?:^|[^A-Za-z0-9-])ssl-heartbleed\b(?![\s\S]{0,120}?\bNOT\s+VULNERABLE\b)[\s\S]{0,120}?\bVULNERABLE\b/i, cve: 'CVE-2014-0160' },
    { fact: 'vuln.drupalgeddon2', re: /\bDrupalgeddon|CVE-2018-7600|\bDrupal\s*[78]\.\d/i, cve: 'CVE-2018-7600' },
    { fact: 'vuln.phpmyadmin_lfi', re: /\bphpMyAdmin\s*4\.8(?:\.[01])?(?![.\d])\b|CVE-2018-12613/i, cve: 'CVE-2018-12613' },
    { fact: 'vuln.webmin', re: /\b(?:MiniServ|Webmin)[\/\s]+1\.(?:89\d|9[0-2]\d|9(?![.\d]))\b|CVE-2019-15107/i, cve: 'CVE-2019-15107' },
    { fact: 'vuln.usermin', re: /\bUsermin\b/i, cve: '' },
    { fact: 'vuln.usermin_rce', re: /\bUsermin\s*(?:v?1\.[89]|1\.820)|EDB-50234/i, cve: 'EDB-50234' },
    { fact: 'vuln.ofbiz', re: /\bOFBiz\b|CVE-2020-9496/i, cve: 'CVE-2020-9496' },
    { fact: 'vuln.cacti', re: /\bCacti\b|CVE-2022-46169/i, cve: 'CVE-2022-46169' },
    { fact: 'vuln.zabbix', re: /\bZabbix\b|CVE-2022-23131/i, cve: 'CVE-2022-23131' },
    { fact: 'vuln.splunk', re: /\bSplunk\b|CVE-2023-46214/i, cve: '' },
    { fact: 'vuln.text4shell', re: /\bText4Shell\b|commons[-_. ]?text|CVE-2022-42889/i, cve: 'CVE-2022-42889' },
    { fact: 'vuln.freeswitch', re: /\bFreeSWITCH\b|\bmod_event_socket\b/i, cve: '' },
    { fact: 'vuln.jdwp', re: /JDWP-?Handshake|Java Debug Wire/i, cve: '' },
    { fact: 'vuln.aerospike', re: /\bAerospike\s+(?:Server|Enterprise|Community|Database|\d)|3000\/tcp\s+open[^\r\n]{0,80}?aerospike|CVE-2020-13151/i, cve: 'CVE-2020-13151' },
    { fact: 'vuln.aerospike_udf', re: /\bAerospike[^\r\n]{0,60}?\b5\.[01]\b|cve-2020-13151/i, cve: 'CVE-2020-13151' },
    { fact: 'vuln.pico_cms', re: /Pico CMS|Pico v[0-9.]+/i, cve: '' },
    { fact: 'vuln.screen_suid', re: /screen-4\.5\.0|GNU Screen 4\.5\.0|Screen version 4\.05\.00/i, cve: 'CVE-2017-5618' },
    { fact: 'vuln.wifi_mouse', re: /\b(?:WiFi|Mobile)\s*Mouse\b|(?<!General Purpose )\bMouse\s*Server\b/i, cve: '' },
    { fact: 'vuln.solr', re: /\bApache Solr\b|\bSolr[^\r\n]{0,60}?(?:8\.[0-3]|7\.|6\.|5\.)|CVE-2019-17558/i, cve: 'CVE-2019-17558' },
    { fact: 'vuln.achat', re: /\bA(?:Chat|chat)\s*(?:v?0\.150|beta7)|CVE-2015-8278/i, cve: 'CVE-2015-8278' },
    { fact: 'vuln.nibbleblog', re: /\bNibbleblog\b|CVE-2015-6967/i, cve: 'CVE-2015-6967' },
    { fact: 'vuln.iis6_webdav', re: /Microsoft[- ]IIS(?: httpd|\/)?\s*6\.0[^\r\n]{0,120}?WebDAV|CVE-2017-7269|ScStoragePathFromUrl|ExplodingCan/i, cve: 'CVE-2017-7269' },
    { fact: 'vuln.prtg', re: /PRTG Network Monitor|Paessler PRTG/i, cve: '' },
    { fact: 'vuln.gitlab', re: /GitLab Community Edition|GitLab Enterprise Edition/i, cve: '' },
    { fact: 'vuln.october_cms', re: /\bOctober\s*CMS(?:\s*(?:v?1\.[0-9.]+|Build\s*\d+))?/i, cve: '' },
    { fact: 'vuln.rejetto_hfs', re: /HttpFileServer\s*2\.[0-3]|\bHFS\s*2\.[0-3]|\brejetto\b/i, cve: 'CVE-2014-6287' },
    { fact: 'vuln.coldfusion', re: /\bColdFusion\s*(?:8|9|10|MX)\b|\/CFIDE\/|CVE-2010-2861/i, cve: 'CVE-2010-2861' },
    { fact: 'vuln.oracle_tns', re: /Oracle TNS Listener|TNSLSNR|1521\/tcp\s+open[^\r\n]{0,80}?oracle/i, cve: '' },
    { fact: 'vuln.h2_console', re: /H2 Database|h2-console|(?:8082|9092)\/tcp\s+open[^\r\n]{0,80}?h2/i, cve: '' },
    { fact: 'vuln.chkrootkit', re: /\bchkrootkit\s+0\.[0-4][0-9]?\b|CVE-2014-0476/i, cve: 'CVE-2014-0476' },
    { fact: 'vuln.zabbix_agent', re: /Zabbix Agent|10050\/tcp\s+open[^\r\n]{0,80}?zabbix/i, cve: '' },
    { fact: 'vuln.myfaces_jsf', re: /javax\.faces\.ViewState|Apache MyFaces|\bMyFaces\b/i, cve: '' },
    { fact: 'vuln.node_serialize', re: /node-serialize|_\$\$ND_FUNC\$\$_/i, cve: 'CVE-2017-5941' },
    { fact: 'vuln.gitea', re: /\bGitea\b|Git with a cup of tea/i, cve: '' },
  ];
  var _VULN_SIGS_HINT_RE = /(?:CVE-\d{4}-|EDB-\d+|vsftpd|proftpd|mod_copy|samba|smbd|SMBGhost|BlueKeep|rdp-vuln|Shellshock|cgi-bin|mod_cgi|Heartbleed|Drupal|phpMyAdmin|MiniServ|Webmin|Usermin|OFBiz|Cacti|Zabbix|Splunk|Text4Shell|commons|FreeSWITCH|mod_event_socket|JDWP|Java Debug|Aerospike|Pico|screen-4\.5|Screen 4|Mouse|Solr|AChat|Nibbleblog|IIS|WebDAV|ScStoragePathFromUrl|ExplodingCan|PRTG|GitLab|October|HttpFileServer|HFS|rejetto|ColdFusion|CFIDE|Oracle TNS|TNSLSNR|1521\/tcp|H2 Database|h2-console|8082\/tcp|9092\/tcp|chkrootkit|10050\/tcp|MyFaces|ViewState|node-serialize|ND_FUNC|Gitea|cup of tea)/i;
  function _parse_vulnmatch(text, ws, source, facts) {
    text = String(text || ''); if (!text.trim() || !_VULN_SIGS_HINT_RE.test(text)) return;
    var cleanText = /\b(?:closed|filtered|unfiltered|open\|filtered)\b/i.test(text)
      ? text.replace(/^\s*\d+\/(?:tcp|udp)\s+(?:closed|filtered|unfiltered|open\|filtered)\b[^\r\n]*$/gim, '')
      : text;
    var h = 'host:' + ws.target;
    for (var i = 0; i < VULN_SIGS.length; i++) {
      var s = VULN_SIGS[i];
      if (s.re.test(cleanText) && !hasKind(facts, s.fact)) {
        _add(facts, mkFact(s.fact, h, { cve: s.cve || null, via: 'vulnmatch', lead: true }, S, source));
      }
    }
  }
  C._parse_vulnmatch = _parse_vulnmatch;
  function parse(text, scope, cmd, existingFacts) {
    var textStr = String(text || '');
    if (C._ANSI_RE) textStr = textStr.replace(C._ANSI_RE, '');
    if (!textStr.trim()) return [];
    var s = String(scope || '').trim();
    var target = (s.indexOf('host:') === 0 ? s.slice(5) : (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(s) ? s : '')) || 'target';
    var seed = Array.isArray(existingFacts) ? existingFacts.slice() : [];
    var ws = { target: target, domainSeed: '', seedFacts: seed, facts: seed };
    var source = cmd ? (C._ANSI_RE ? String(cmd).replace(C._ANSI_RE, '') : String(cmd)) : 'shape';
    var baseFacts = seed.slice();
    var initialLen = baseFacts.length;
    _parse_shape(textStr, ws, source, baseFacts);
    _parse_vulnmatch(textStr, ws, source, baseFacts);
    return baseFacts.slice(initialLen);
  }
  OBOL.parsers = OBOL.parsers || {};
  OBOL.parsers.shape = { parse: parse };
})(typeof globalThis !== 'undefined' ? globalThis : this);
