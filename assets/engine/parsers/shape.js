/*!
 * obol engine — parsers/shape.js
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
    if (!text.trim()) return;
    var h = 'host:' + ws.target;

    // (1) A bare "N/tcp open service" port table, pasted without an nmap command line. The dispatcher
    //     only runs the nmap parser when the command contains "nmap", so a copy-pasted port list (or
    //     greppable row) otherwise mints nothing. The row pattern is anchored to the line start, so
    //     only a genuine open-port line matches. We mint the port facts (and the derived reachability),
    //     but NOT the scan.nmap.* profile facts: we cannot know the scan profile from the shape alone.
    if (!hasPrefix(facts, 'port:')) {
      // Line by line (not a global regex): a per-line anchored test cannot skip a row the way a greedy
      // trailing match in a globally-iterated regex can.
      var rowRe = /^[ \t]*(\d{1,5})\/(tcp|udp)[ \t]+open\b(?:[ \t]+(\S+))?/i;
      var summary = [], seen = {};
      text.split(/\r?\n/).forEach(function (line) {
        var mm = rowRe.exec(line);
        if (!mm) return;
        var port = parseInt(mm[1], 10);
        if (!port || port > 65535) return;
        var proto = mm[2].toLowerCase();
        var key = port + '/' + proto;
        if (seen[key]) return; seen[key] = 1;
        var service = (mm[3] || '').trim();
        var value = { port: port, protocol: proto, via: 'shape' };
        if (service && service.toLowerCase() !== 'open') value.service = service;
        _add(facts, mkFact('port:' + port, h, value, S, source));
        if (value.service && C._normalize_service) _add(facts, mkFact('service.' + C._normalize_service(value.service), h, value, S, source));
        if (C._parse_service_reachability) C._parse_service_reachability(port, proto, value.service || '', ws, source, facts);
        summary.push(port);
      });
      if (summary.length) _add(facts, mkFact('ports.open', h, { ports: uniqNums(summary), via: 'shape' }, S, source));
    }

    // (2) A bare HTTP response (a real status line, or a Server header), pasted without a web-client
    //     command. The dispatcher gates its HTTP parsers on curl/whatweb/wget/etc., so a raw response
    //     saved to a file mints nothing. A status line or a Server header is an unambiguous web signal.
    if (!hasKind(facts, 'http.reachable') && (/^HTTP\/[0-9.]+\s+\d{3}\b/im.test(text) || /^Server:[ \t]*\S/im.test(text))) {
      _add(facts, mkFact('http.reachable', h, { via: 'shape' }, S, source));
      var servers = [];
      (text.match(/^Server:[ \t]*(.+)$/gim) || []).forEach(function (l) {
        var v = l.replace(/^Server:[ \t]*/i, '').trim();
        if (v && servers.indexOf(v) < 0) servers.push(v);
      });
      var webServers = servers.filter(function (hdr) { return !(C._isNonWebServerHeader && C._isNonWebServerHeader(hdr)); });
      if (webServers.length) _add(facts, mkFact('web.server', h, { headers: webServers.slice(0, 10), via: 'shape' }, S, source));
    }

    // (3) A crackable-hash blob, pasted without the tool that produced it. The AS-REP / TGS hash tokens
    //     are self-identifying, so route them to the real hash parsers (which emit the correct fact
    //     type and structured value); the guard keeps it from double-running when the command already did.
    if (/\$krb5asrep\$/i.test(text) && !hasKind(facts, 'hash.asrep') && C._parse_asrep_hashes) C._parse_asrep_hashes(text, ws, source, facts);
    if (/\$krb5tgs\$/i.test(text) && !hasKind(facts, 'hash.tgs') && C._parse_tgs_hashes) C._parse_tgs_hashes(text, ws, source, facts);

    // (4) Share download output or GPP cpassword XML/grep without command
    if (text.indexOf('getting file ') >= 0 && !hasKind(facts, 'loot.files') && C._parse_share_inventory) {
      C._parse_share_inventory(text, ws, 'smbclient', source, facts);
    }
    if ((text.indexOf('cpassword=') >= 0 || text.indexOf('cpassword =') >= 0) && !hasKind(facts, 'credential.candidate') && C._parse_gpp_artifacts) {
      C._parse_gpp_artifacts(text, ws, source, facts);
    }

    // (5) Ligolo-ng tunnel establishment or session shape pasted without command
    if ((/(\[Tunnel\] Interface ligolo is UP|session connected|Agent joined:)/i.test(text) || /ligolo-proxy.*listening/i.test(text)) && !hasKind(facts, 'tunnel.route')) {
      _add(facts, mkFact('tunnel.route', h, { via: 'ligolo', shape: true }, S, source));
      _add(facts, mkFact('pivot.active', h, { via: 'ligolo', shape: true }, S, source));
    }

    // (6) Raw SQLite database dump or table schema shape pasted without command
    if (/(SQLite format 3|CREATE TABLE\s+(?:partners|users|accounts|credentials)|^\s*\d+\|[a-zA-Z0-9_.-]+\|\$2[aby]\$)/im.test(text) && !hasKind(facts, 'loot.material')) {
      _add(facts, mkFact('loot.material', h, { kind: 'sqlite_db', via: 'shape' }, S, source));
    }
  }

  C._parse_shape = _parse_shape;

  // ---- known-exploit fingerprint recognizer ---------------------------------------------------
  // When pasted service/version output (an nmap -sV banner, a whatweb line, a CHANGELOG, an nmap
  // vuln-script verdict) names a product+version, or a CVE/handshake token, that a promoted
  // known-exploit module targets, mint a vuln.<name> LEAD so the coach lights that exact module.
  // Strictly conservative and anchored on specific version/product/CVE tokens, so unrelated output
  // mints nothing. A lead is a candidate to try, never proof of exploitation: the module's own
  // produces fact (a real shell) is what proves the box, exactly as the proof discipline requires.
  var VULN_SIGS = [
    { fact: 'vuln.vsftpd_234', re: /vsftpd[\s_-]*2\.3\.4/i, cve: 'CVE-2011-2523' },
    { fact: 'vuln.proftpd_modcopy', re: /ProFTPD\s*1\.3\.5/i, cve: 'CVE-2015-3306' },
    { fact: 'vuln.samba_usermap', re: /Samba\s*3\.0\.2[0-5]/i, cve: 'CVE-2007-2447' },
    { fact: 'vuln.smbghost', re: /SMBGhost|CVE-2020-0796/i, cve: 'CVE-2020-0796' },
    { fact: 'vuln.bluekeep', re: /BlueKeep|CVE-2019-0708|rdp-vuln-ms19-0708/i, cve: 'CVE-2019-0708' },
    { fact: 'vuln.shellshock', re: /Shellshock|CVE-2014-6271|\/cgi-bin\/|mod_cgi/i, cve: 'CVE-2014-6271' },
    { fact: 'vuln.heartbleed', re: /Heartbleed|CVE-2014-0160|ssl-heartbleed/i, cve: 'CVE-2014-0160' },
    { fact: 'vuln.drupalgeddon2', re: /Drupalgeddon|CVE-2018-7600|Drupal\s*[78]\.\d/i, cve: 'CVE-2018-7600' },
    { fact: 'vuln.phpmyadmin_lfi', re: /phpMyAdmin\s*4\.8(\.[01])?\b|CVE-2018-12613/i, cve: 'CVE-2018-12613' },
    { fact: 'vuln.webmin', re: /MiniServ\s*1\.9|Webmin\s*1\.9|CVE-2019-15107/i, cve: 'CVE-2019-15107' },
    { fact: 'vuln.usermin', re: /\bUsermin\b/i, cve: '' },
    { fact: 'vuln.usermin_rce', re: /Usermin\s*(?:v?1\.[89]|1\.820)|EDB-50234/i, cve: 'EDB-50234' },
    { fact: 'vuln.ofbiz', re: /\bOFBiz\b|CVE-2020-9496/i, cve: 'CVE-2020-9496' },
    { fact: 'vuln.cacti', re: /\bCacti\b|CVE-2022-46169/i, cve: 'CVE-2022-46169' },
    { fact: 'vuln.zabbix', re: /\bZabbix\b|CVE-2022-23131/i, cve: 'CVE-2022-23131' },
    { fact: 'vuln.splunk', re: /\bSplunk\b|CVE-2023-46214/i, cve: '' },
    { fact: 'vuln.text4shell', re: /Text4Shell|commons[-_. ]?text|CVE-2022-42889/i, cve: 'CVE-2022-42889' },
    { fact: 'vuln.freeswitch', re: /FreeSWITCH|mod_event_socket/i, cve: '' },
    { fact: 'vuln.jdwp', re: /JDWP-?Handshake|Java Debug Wire/i, cve: '' },
    { fact: 'vuln.aerospike', re: /\bAerospike\b|CVE-2020-13151/i, cve: 'CVE-2020-13151' },
    { fact: 'vuln.aerospike_udf', re: /Aerospike.*5\.[01]|cve-2020-13151/i, cve: 'CVE-2020-13151' },
    { fact: 'vuln.pico_cms', re: /Pico CMS|Pico v[0-9.]+/i, cve: '' },
    { fact: 'vuln.screen_suid', re: /screen-4\.5\.0|GNU Screen 4\.5\.0/i, cve: 'CVE-2017-5618' },
    { fact: 'vuln.wifi_mouse', re: /WiFi\s*Mouse|Mobile\s*Mouse|Mouse\s*Server/i, cve: '' },
    { fact: 'vuln.solr', re: /Apache Solr|Solr.*(?:8\.[0-3]|7\.|6\.|5\.)|CVE-2019-17558/i, cve: 'CVE-2019-17558' },
    { fact: 'vuln.achat', re: /A(?:Chat|chat)\s*(?:v?0\.150|beta7)|CVE-2015-8278/i, cve: 'CVE-2015-8278' },
    { fact: 'vuln.nibbleblog', re: /Nibbleblog|CVE-2015-6967/i, cve: 'CVE-2015-6967' },
    { fact: 'vuln.iis6_webdav', re: /Microsoft[- ]IIS(?: httpd|\/)?\s*6\.0.*WebDAV|CVE-2017-7269|ScStoragePathFromUrl|ExplodingCan/i, cve: 'CVE-2017-7269' },
    { fact: 'vuln.prtg', re: /PRTG Network Monitor|Paessler PRTG/i, cve: '' },
    { fact: 'vuln.gitlab', re: /GitLab Community Edition|GitLab Enterprise Edition/i, cve: '' },
    { fact: 'vuln.october_cms', re: /October\s*(?:CMS)?\s*(?:v?1\.[0-9.]+|Build\s*\d+)?/i, cve: '' },
    { fact: 'vuln.rejetto_hfs', re: /HttpFileServer\s*2\.[0-3]|HFS\s*2\.[0-3]|rejetto/i, cve: 'CVE-2014-6287' },
    { fact: 'vuln.coldfusion', re: /ColdFusion(?:\s*(?:8|9|10))?|CFIDE/i, cve: 'CVE-2010-2861' },
    { fact: 'vuln.oracle_tns', re: /Oracle TNS Listener|TNSLSNR|1521\/tcp.*oracle/i, cve: '' },
    { fact: 'vuln.h2_console', re: /H2 Database|h2-console|8082\/tcp.*h2/i, cve: '' },
    { fact: 'vuln.chkrootkit', re: /chkrootkit(?:\s*(?:0\.[0-4][0-9]?))?/i, cve: 'CVE-2014-0476' },
    { fact: 'vuln.zabbix_agent', re: /Zabbix Agent|10050\/tcp.*zabbix/i, cve: '' },
    { fact: 'vuln.myfaces_jsf', re: /javax\.faces\.ViewState|Apache MyFaces|MyFaces/i, cve: '' },
    { fact: 'vuln.node_serialize', re: /node-serialize|_\$\$ND_FUNC\$\$_/i, cve: 'CVE-2017-5941' },
    { fact: 'vuln.gitea', re: /\bGitea\b|Git with a cup of tea/i, cve: '' },
  ];
  function _parse_vulnmatch(text, ws, source, facts) {
    text = String(text || ''); if (!text.trim()) return;
    var h = 'host:' + ws.target;
    for (var i = 0; i < VULN_SIGS.length; i++) {
      var s = VULN_SIGS[i];
      if (s.re.test(text) && !hasKind(facts, s.fact)) {
        _add(facts, mkFact(s.fact, h, { cve: s.cve || null, via: 'vulnmatch', lead: true }, S, source));
      }
    }
  }
  C._parse_vulnmatch = _parse_vulnmatch;
})(typeof globalThis !== 'undefined' ? globalThis : this);
