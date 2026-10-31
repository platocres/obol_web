/*!
 * obol engine - parsers/pivot.js - connectivity parsers (interfaces/subnets + live tunnels).
 *
 * Powers the engagement-hub connectivity view: from a foothold's own interface/route dump, mint the
 * subnets it can reach (and flag it multihomed); from a pivot tool's setup output, mint the live
 * tunnel. These are the already-declared pivot-lane facts (scan.local.interfaces / scan.local.routes /
 * host.multihomed / tunnel.socks|route|dns), read from pasted output. Conservative: every fact is
 * content-gated, and loopback / link-local / multicast / reserved addresses are never a subnet.
 *
 * Covers the real shapes an operator pastes on either side of a pivot:
 *   interfaces - Linux `ip a`/`ip -4 a`, ifconfig, Windows ipconfig
 *   routes     - Linux `ip route`, `netstat -rn` (Destination/Gateway/Genmask), Windows `route print`
 *                (Network Destination/Netmask) - the last two carry the netmask as a dotted quad in a
 *                column, so a netmask-aware row reader handles both without caring about column order
 *   neighbours - Linux `ip neigh`, Linux/Windows `arp -a`: the adjacent hosts the foothold has talked
 *                to (scan.local.neighbors) - the shortlist to aim a pivot scan at
 *   listeners  - Windows `netstat -ano`, Linux `netstat -tlnp`/`ss -tlnp`: services it is listening on,
 *                internal-bound ones included (scan.local.listeners) - the classic pivot targets
 *   resolvers  - `/etc/resolv.conf`, Windows DNS Servers: the internal DNS (scan.local.dns)
 *   tunnels    - chisel (reverse SOCKS), ssh -D (dynamic SOCKS), ligolo-ng + sshuttle (routed),
 *                dnscat2 (DNS) - recognized from the command AND from the tool's own success banner,
 *                so pasting just the output still lights the connectivity edge.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var C = OBOL._parserCommon; if (!C) return;
  var mkFact = C.mkFact, _add = C._add, S = C.ProofState.SUPPORTED;

  // A routable unicast IPv4: not loopback, not link-local, not multicast (224-239), not reserved
  // (240-255), not the unspecified / broadcast address. No host interface or real subnet is any of
  // these, so excluding them keeps the map honest.
  function isRoutable(ip) {
    var o = String(ip).split('.'); if (o.length !== 4) return false;
    for (var i = 0; i < 4; i++) { var n = +o[i]; if (!(o[i] !== '' && n >= 0 && n <= 255)) return false; }
    var a = +o[0];
    return a !== 127 && a < 224 && !(a === 169 && +o[1] === 254) && ip !== '0.0.0.0';
  }
  function isHostIp(ip) {
    if (!isRoutable(ip)) return false;
    var o = String(ip).split('.');
    var last = +o[3];
    return last !== 0 && last !== 255;
  }
  function isPrivateHostIp(ip) {
    if (!isHostIp(ip)) return false;
    var o = String(ip).split('.').map(Number);
    return o[0] === 10 || (o[0] === 172 && o[1] >= 16 && o[1] <= 31) || (o[0] === 192 && o[1] === 168);
  }
  // Prefix length of a dotted-quad netmask, or -1 if it is not a valid contiguous mask. Rejects
  // 0.0.0.0 (default) and the degenerate ends so only real subnet masks (e.g. /8../30) count.
  function maskPrefix(mask) {
    var o = String(mask).split('.').map(Number);
    if (o.length !== 4 || o.some(function (x) { return isNaN(x) || x < 0 || x > 255; })) return -1;
    var bits = ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
    var p = 0; for (var i = 31; i >= 0; i--) { if ((bits >>> i) & 1) p++; else break; }
    var canon = p === 0 ? 0 : (p === 32 ? 0xFFFFFFFF : ((0xFFFFFFFF << (32 - p)) >>> 0));
    return (canon >>> 0) === bits ? p : -1;
  }
  function netCidr(ip, pfx) {
    var p = ip.split('.').map(Number);
    var bits = (p[0] * 16777216 + p[1] * 65536 + p[2] * 256 + p[3]) >>> 0;
    var mask = pfx <= 0 ? 0 : (pfx >= 32 ? 0xFFFFFFFF : ((0xFFFFFFFF << (32 - pfx)) >>> 0));
    var net = (bits & mask) >>> 0;
    return [(net >>> 24) & 255, (net >>> 16) & 255, (net >>> 8) & 255, net & 255].join('.') + '/' + pfx;
  }

  var _NXC_LINE_PFX_RE = /^\s*(?:SMB|WINRM|WMI|RPC|SSH|LDAP|MSSQL|RDP|FTP)\s+\S+\s+\d+\s+\S+\s+/gm;

  function _parse_local_net(text, ws, source, facts) {
    var h = 'host:' + ws.target, ifaces = [], subnets = {}, seen = {}, m;
    var cleanText = String(text || '').replace(_NXC_LINE_PFX_RE, '');
    function addSubnet(net, pfx) { if (isRoutable(net) && pfx >= 8 && pfx <= 30) subnets[netCidr(net, pfx)] = 1; }

    // Linux `ip a` / `ip -4 a`: "inet 172.16.5.10/24"
    var reCidr = /\binet6?\s+(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})\b/gi;
    while ((m = reCidr.exec(cleanText))) { var ip = m[1], pfx = +m[2]; if (!isRoutable(ip) || seen[ip]) continue; seen[ip] = 1; ifaces.push({ ip: ip, cidr: ip + '/' + pfx }); addSubnet(ip, pfx); }
    // ifconfig: "inet 172.16.5.10  netmask 255.255.255.0" (or "inet addr:...  Mask:...")
    var reMask = /\binet\s+(?:addr:)?(\d{1,3}(?:\.\d{1,3}){3})\b[\s\S]{0,60}?(?:netmask|Mask:)\s*(\d{1,3}(?:\.\d{1,3}){3})/gi;
    while ((m = reMask.exec(cleanText))) { var ip2 = m[1]; if (!isRoutable(ip2) || seen[ip2]) continue; var pfx2 = maskPrefix(m[2]); if (pfx2 < 0) continue; seen[ip2] = 1; ifaces.push({ ip: ip2, cidr: ip2 + '/' + pfx2 }); addSubnet(ip2, pfx2); }
    // Windows ipconfig: "IPv4 Address. . . : 172.16.5.10" then optional "Subnet Mask . . . : 255.255.255.0"
    var reWin = /IPv4 Address[^\n:]*:\s*(\d{1,3}(?:\.\d{1,3}){3})(?:\s*\(Preferred\))?(?:[\s\S]{0,160}?Subnet Mask[^\n:]*:\s*(\d{1,3}(?:\.\d{1,3}){3}))?/gi;
    while ((m = reWin.exec(cleanText))) { var ip3 = m[1]; if (!isRoutable(ip3) || seen[ip3]) continue; var pfx3 = m[2] ? maskPrefix(m[2]) : 24; if (pfx3 < 0) continue; seen[ip3] = 1; ifaces.push({ ip: ip3, cidr: ip3 + '/' + pfx3 }); addSubnet(ip3, pfx3); }
    // PowerShell Get-NetIPAddress: "IPAddress : 172.16.5.10 ... PrefixLength : 24"
    var rePsNet = /IPAddress\s*:\s*(\d{1,3}(?:\.\d{1,3}){3})[\s\S]{0,200}?PrefixLength\s*:\s*(\d{1,2})\b/gi;
    while ((m = rePsNet.exec(cleanText))) { var ip4 = m[1], pfx4 = +m[2]; if (!isRoutable(ip4) || seen[ip4]) continue; seen[ip4] = 1; ifaces.push({ ip: ip4, cidr: ip4 + '/' + pfx4 }); addSubnet(ip4, pfx4); }
    // Linux `ip route`: "172.16.6.0/24 dev eth1 ..." / "... via ..."
    var reRoute = /(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})\s+(?:dev|via|proto|scope)/gi;
    while ((m = reRoute.exec(cleanText))) { addSubnet(m[1], +m[2]); }
    // `netstat -rn` (Destination Gateway Genmask ...) and Windows `route print` (Network Destination
    // Netmask Gateway ...): both put a dotted-quad network and a dotted-quad netmask on the same row,
    // in different columns. Read the first routable quad as the network and the first valid netmask
    // quad on the line as the mask, so column order does not matter and header rows (no quads) skip.
    cleanText.split(/\r?\n/).forEach(function (line) {
      if (/\binet6?\b/i.test(line) || /\//.test(line)) return;     // handled by the CIDR / ifconfig readers above
      var quads = line.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g);
      if (!quads || quads.length < 2) return;
      var net = quads[0]; if (!isRoutable(net)) return;
      for (var i = 1; i < quads.length; i++) {
        var p = maskPrefix(quads[i]);
        if (p >= 8 && p <= 30 && netCidr(net, p) === (net + '/' + p)) { addSubnet(net, p); break; }
      }
    });

    var subs = Object.keys(subnets);
    var internalSubs = (ws && ws.target && isRoutable(ws.target))
      ? subs.filter(function (s) { var pfx = +(s.split('/')[1] || 24); return netCidr(ws.target, pfx) !== s; })
      : subs;
    if (ifaces.length) _add(facts, mkFact('scan.local.interfaces', h, { interfaces: ifaces.slice(0, 12), subnets: subs.slice(0, 12) }, S, source));
    if (subs.length) _add(facts, mkFact('scan.local.routes', h, { subnets: subs.slice(0, 16) }, S, source));
    if (ifaces.length >= 2) {
      _add(facts, mkFact('host.multihomed', h, { interfaces: ifaces.length }, S, source));
      _add(facts, mkFact('pivot.candidate', h, { interfaces: ifaces.slice(0, 12), subnets: (internalSubs.length ? internalSubs : subs).slice(0, 12) }, S, source));
    } else if (subs.length >= 2 && internalSubs.length >= 1) {
      _add(facts, mkFact('pivot.candidate', h, { interfaces: ifaces.slice(0, 12), subnets: internalSubs.slice(0, 12) }, S, source));
    }
  }

  function _isValidChiselRemoteHost(host) {
    var s = String(host || '').trim();
    if (!s || /^socks$/i.test(s) || /^\d+$/.test(s)) return false;
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(s)) {
      return s.split('.').every(function (o) { var n = +o; return n >= 0 && n <= 255; });
    }
    if (/^\[[0-9a-fA-F:]+\]$/.test(s)) return true;
    return /[A-Za-z]/.test(s) && /^[A-Za-z0-9_.-]+$/.test(s);
  }

  function _hasValidChiselForwardSpec(cmdStr) {
    var re = /(?:^|\s)(?:(\d{1,3}(?:\.\d{1,3}){3}):)?(\d{1,5}):(\[[0-9a-fA-F:]+\]|[A-Za-z0-9_.-]+):(\d{1,5})(?=\s|$)/g, fm;
    while ((fm = re.exec(cmdStr)) !== null) {
      var lp = +fm[2], rp = +fm[4];
      if (lp >= 1 && lp <= 65535 && rp >= 1 && rp <= 65535 && _isValidChiselRemoteHost(fm[3])) return true;
    }
    return false;
  }

  function _parse_chisel(text, a1, a2, a3, a4) {
    var ws, source = 'chisel', facts = [], command = '';
    if (a1 && typeof a1 === 'object' && !Array.isArray(a1)) {
      ws = a1;
      if (Array.isArray(a3)) {
        source = typeof a2 === 'string' ? a2 : 'chisel';
        facts = a3;
        command = typeof a4 === 'string' ? a4 : '';
      } else if (Array.isArray(a4)) {
        command = typeof a2 === 'string' ? a2 : '';
        source = typeof a3 === 'string' ? a3 : (command || 'chisel');
        facts = a4;
      } else {
        command = typeof a2 === 'string' ? a2 : '';
        source = typeof a3 === 'string' ? a3 : (command || 'chisel');
      }
    } else {
      command = typeof a1 === 'string' ? a1 : '';
      facts = Array.isArray(a2) ? a2 : [];
      var ipM = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/.exec(command) || /\b(\d{1,3}(?:\.\d{1,3}){3})\b/.exec(String(text || ''));
      ws = { target: ipM ? ipM[1] : 'unknown' };
      source = command || 'chisel';
    }
    var t = String(text || ''), cmd = String(command || '');
    var combined = cmd + '\n' + t;
    if (/^\s*(?:man|which|whereis|type|help)\s+chisel(?:[_-][A-Za-z0-9._-]+|\d+)?(?:\.exe)?\b/i.test(cmd) || /\bUsage:\s*chisel(?:[_-][A-Za-z0-9._-]+|\d+)?(?:\.exe)?\b|--help\b/i.test(combined)) {
      return facts;
    }
    var hasActiveBanner = /(?:(?:client|server):\s+Connected\s*\(Latency|\b(?:c|client|server):\s*Connected\b|session#\d+:\s*tun:|tun:\s*proxy#[^\r\n]*:\s*Listening\b|server:\s+Listening on\s+https?:\/\/|(?:client|server):\s+Connecting to ws:\/\/\S+)/i.test(t);
    var hasErr = /connection refused|permission denied|authentication failed|timed?\s*out|could not connect|cannot connect|unreachable|fatal|fata\[|server died|exiting|error:/i.test(t);
    if (hasErr && !/(?:(?:client|server):\s+Connected\s*\(Latency|\b(?:c|client|server):\s*Connected\b|session#\d+:\s*tun:|tun:\s*proxy#[^\r\n]*:\s*Listening\b)/i.test(t)) {
      return facts;
    }
    var isChisel = /\bchisel(?:[_-][A-Za-z0-9._-]+|\d+)?(?:\.exe)?\b/i.test(cmd) ||
      /\bchisel(?:[_-][A-Za-z0-9._-]+|\d+)?(?:\.exe)?\b/i.test(t) ||
      /\b(?:client|server):\s+(?:Connecting to ws:\/\/|Reverse tunnelling enabled|Fingerprint\s+[0-9a-f]{2}:|Connected\s*\(Latency)|\bsession#\d+:\s*tun:\s*proxy#|\btun:\s*proxy#R:/i.test(t);
    if (!isChisel) return facts;

    var cmdHasTunnelSpec = /\bchisel(?:[_-][A-Za-z0-9._-]+|\d+)?(?:\.exe)?\s+(?:client|server)\b/i.test(cmd) &&
      (/\bR:(?:socks|\d)/i.test(cmd) || /--reverse\b/i.test(cmd) || _hasValidChiselForwardSpec(cmd));
    var textHasChiselProof = hasActiveBanner ||
      (/\bchisel(?:[_-][A-Za-z0-9._-]+|\d+)?(?:\.exe)?\b/i.test(t) && /(?:Connected\b|Connected\s*\(|Listening on|tun:\s|proxy#(?:R:|\d)|session#\d+|R:socks)/i.test(t));
    if (!textHasChiselProof && !(cmdHasTunnelSpec && !hasErr)) return facts;

    var h = 'host:' + ((ws && ws.target) || 'unknown');
    var isSocks = /(?:^|[\s:=>])R?(?:(?:\d{1,3}(?:\.\d{1,3}){3}:)?(?:\d{1,5}:)?)?socks\b/i.test(combined);
    var mode = isSocks ? 'socks' : 'port-forward';

    _add(facts, mkFact('pivot.active', h, { tool: 'chisel', via: 'chisel', mode: mode }, S, source));
    if (isSocks) {
      _add(facts, mkFact('tunnel.socks', h, { via: 'chisel' }, S, source));
    }

    var portSet = {}, forwards = [], fwdSeen = {}, m;
    function recordFwd(lp, rh, rp) {
      if (!(lp >= 1 && lp <= 65535 && rp >= 1 && rp <= 65535)) return;
      var hostStr = rh || '127.0.0.1';
      if (!_isValidChiselRemoteHost(hostStr)) return;
      portSet[lp] = 1;
      portSet[rp] = 1;
      var fk = lp + '=>' + hostStr.toLowerCase() + ':' + rp;
      if (!fwdSeen[fk]) {
        fwdSeen[fk] = 1;
        forwards.push({ local_port: lp, remote_host: hostStr, remote_port: rp });
      }
    }

    var rSpecRe = /(?:^|[\s"'])R:(?:(\d{1,3}(?:\.\d{1,3}){3}):)?(\d{1,5})(?::(\[[0-9a-fA-F:]+\]|[A-Za-z0-9_.-]+)(?::(\d{1,5}))?)?(?=$|[\s"'])/gi;
    while ((m = rSpecRe.exec(combined)) !== null) {
      if (m[3] && /^socks$/i.test(m[3])) continue;
      var rLp = +m[2];
      if (m[3] && m[4]) {
        if (!_isValidChiselRemoteHost(m[3])) continue;
        recordFwd(rLp, m[3], +m[4]);
      } else if (m[3] && /^\d{1,5}$/.test(m[3])) {
        recordFwd(rLp, '127.0.0.1', +m[3]);
      } else if (!m[3]) {
        recordFwd(rLp, '127.0.0.1', rLp);
      }
    }

    var proxyRe = /\bproxy#(?:R:)?(?:(\d{1,3}(?:\.\d{1,3}){3}):)?(\d{1,5})=>(?:(\[[0-9a-fA-F:]+\]|[A-Za-z0-9_.-]+):)?(\d{1,5})\b/gi;
    while ((m = proxyRe.exec(t)) !== null) {
      if (m[3] && !_isValidChiselRemoteHost(m[3])) continue;
      recordFwd(+m[2], m[3] || '127.0.0.1', +m[4]);
    }

    if (/\bchisel(?:[_-][A-Za-z0-9._-]+|\d+)?(?:\.exe)?\s+client\b/i.test(cmd)) {
      var fwdSpecRe = /(?:^|\s)(?:(\d{1,3}(?:\.\d{1,3}){3}):)?(\d{1,5}):(\[[0-9a-fA-F:]+\]|[A-Za-z0-9_.-]+):(\d{1,5})(?=\s|$)/g;
      while ((m = fwdSpecRe.exec(cmd)) !== null) {
        if (!_isValidChiselRemoteHost(m[3])) continue;
        recordFwd(+m[2], m[3], +m[4]);
      }
    }

    var uniqPorts = Object.keys(portSet).map(Number).sort(function (a, b) { return a - b; });
    if (uniqPorts.length) {
      _add(facts, mkFact('pivot.ports', h, { ports: uniqPorts, forwards: forwards, via: 'chisel' }, S, source));
      var _TUNNELED_DB_MAP = { 5432: 'postgresql', 3306: 'mysql', 1433: 'mssql', 6379: 'redis', 27017: 'mongodb' };
      uniqPorts.forEach(function (p) {
        var eng = _TUNNELED_DB_MAP[p];
        if (!eng) return;
        var pVal = { port: p, protocol: 'tcp', service: eng, tunneled: true, via: 'chisel' };
        _add(facts, mkFact('port:' + p, h, pVal, S, source));
        _add(facts, mkFact('service.' + eng, h, pVal, S, source));
      });
    }
    return facts;
  }

  // The setup / status output that confirms a live pivot channel from this foothold. Recognized from
  // the command where the command is the proof (ssh -D is silent), and from the tool's own success
  // banner so a pasted output alone still counts. Conservative: a tool name plus a real success token.
  function _parse_tunnel(text, ws, source, facts, command) {
    var h = 'host:' + ws.target, lc = String(command || '').toLowerCase(), t = String(text || ''), cmd = String(command || '');
    var hasPositiveTunnel = /(?:session#\d+.*tun:|tun:\s*proxy#|Connected\s*\(Latency|(?:client|server):\s+(?:Connecting to ws:\/\/|Listening on\s+https?:\/\/)|\bsession\b.*(?:established|opened)|Agent joined|session \d+ opened|Interface\s+\S+\s+(?:created|up)|\[Tunnel\] Interface ligolo|\bc\s*:\s*Connected\b|client:\s*Connected|Entering interactive session|new session|obol:fact:pivot_active)/i.test(t);
    if (/connection refused|permission denied|authentication failed|timed?\s*out|could not connect|cannot connect|unreachable|fatal|fata\[|server died|exiting|error:/i.test(t) && !hasPositiveTunnel) return;

    // obol sync token: obol:fact:pivot_active | subnet=... | via=... | host=...
    var syncRe = /obol:fact:pivot_active\s*\|\s*subnet=([^\s|]+)\s*\|\s*via=([^\s|]+)\s*\|\s*host=([^\s|]+)/i;
    var sm = syncRe.exec(t);
    if (sm) {
      var sSubnet = sm[1], sVia = sm[2].toLowerCase(), sHost = sm[3];
      var syncScope = sHost ? ('host:' + sHost) : h;
      if (sVia === 'chisel' || sVia === 'ssh-dynamic') {
        _add(facts, mkFact('tunnel.socks', syncScope, { subnet: sSubnet, via: sVia, host: sHost, port: 1080 }, S, source));
      } else {
        _add(facts, mkFact('tunnel.route', syncScope, { subnet: sSubnet, via: sVia, host: sHost }, S, source));
      }
      _add(facts, mkFact('pivot.active', syncScope, { subnet: sSubnet, via: sVia, host: sHost }, S, source));
    }

    // chisel reverse SOCKS and reverse/local TCP port-forwards.
    _parse_chisel(t, ws, source, facts, cmd);
    // ssh dynamic port-forward (-D): silent tool, so the command is the proof.
    if (/\bssh\b[^\n]*\s-[a-z]*d(?:\s+\S+)?\b/i.test(cmd) || /(^|\s)-D\s*\d+/.test(cmd))
      _add(facts, mkFact('tunnel.socks', h, { via: 'ssh-dynamic' }, S, source));
    // ligolo-ng routed tunnel: the command, or an "Agent joined" / tunnel-up banner.
    if (/\bligolo\b/.test(lc) || /\bagent(?:\.exe)?\s+-connect\b/i.test(lc) || (/ligolo/i.test(t) && /(agent joined|tunnel started|route added|listening on|ligolo-ng|session|interface ligolo is up)/i.test(t)) || /\bAgent joined\b/i.test(t) || /\[Tunnel\] Interface ligolo is UP/i.test(t)) {
      _add(facts, mkFact('tunnel.route', h, { via: 'ligolo' }, S, source));
      _add(facts, mkFact('pivot.active', h, { via: 'ligolo' }, S, source));
    }
    // sshuttle transparent route: the command, or its "Connected to server." line.
    if (/\bsshuttle\b/.test(lc) || (/sshuttle/i.test(t) && /connected to server/i.test(t)) || (/client:\s*Connected to server/i.test(t)))
      _add(facts, mkFact('tunnel.route', h, { via: 'sshuttle' }, S, source));
    // dnscat2 DNS channel: the command, or a session-established banner.
    if (/\bdnscat/.test(lc) || (/dnscat/i.test(t) && /(Session \d|New window|Session established|established|window -i)/i.test(t)))
      _add(facts, mkFact('tunnel.dns', h, { via: 'dnscat2' }, S, source));
  }

  // Adjacent hosts from the foothold's own ARP/neighbour cache - the machines it has actually talked to
  // on its segments, which is the shortlist to aim a pivot scan at. Linux `ip neigh` ("10.0.0.1 dev eth0
  // lladdr aa:.. REACHABLE"), Linux `arp -a` ("? (10.0.0.1) at aa:.. [ether] on eth0"), Windows `arp -a`
  // ("  10.0.0.1    aa-bb-..  dynamic"). Conservative: only routable unicast IPs, and only a line that
  // also carries a MAC (a real cache entry), so a bare address list or an error paste mints nothing.
  function _parse_local_neighbors(text, ws, source, facts) {
    var h = 'host:' + ws.target, hosts = {}, mac = /[0-9a-f]{2}([:-])[0-9a-f]{2}(?:\1[0-9a-f]{2}){4}/i;
    String(text).split(/\r?\n/).forEach(function (line) {
      if (!mac.test(line)) return;                       // a neighbour entry resolves to a MAC
      if (/\b(?:INCOMPLETE|FAILED)\b/i.test(line)) return; // an unresolved cache slot is not a reachable host
      if (/\bff[:-]ff[:-]ff[:-]ff[:-]ff[:-]ff\b/i.test(line)) return; // broadcast MAC is not a neighbour host
      var ip = (line.match(/(\d{1,3}(?:\.\d{1,3}){3})/) || [])[1];
      if (ip && isHostIp(ip)) hosts[ip] = 1;
    });
    var list = Object.keys(hosts);
    if (list.length) _add(facts, mkFact('scan.local.neighbors', h, { hosts: list.slice(0, 32) }, S, source));
  }

  // Services the foothold is listening on - including ones bound to an internal interface that are
  // invisible from outside, so reaching them means pivoting. Windows `netstat -ano`, Linux `netstat
  // -tlnp` / `ss -tlnp`. Only rows in a LISTEN(ING) state; a listener on 0.0.0.0 / :: / 127.0.0.1 is
  // recorded too (a localhost-only service is the classic pivot target). Conservative: no state token,
  // no fact.
  function _parse_local_listeners(text, ws, source, facts) {
    var h = 'host:' + ws.target, ports = {};
    String(text).split(/\r?\n/).forEach(function (line) {
      if (!/\bLISTEN(?:ING)?\b/i.test(line)) return;
      // the local address is the one before the state; take the last :port on the local side
      var m = line.match(/(?:^|\s|\[)(?:\d{1,3}(?:\.\d{1,3}){3}(?:%[A-Za-z0-9_.-]+)?|\*|::|[0-9a-f:]*\]?):(\d{1,5})\b/gi);
      if (!m) return;
      var first = m[0], port = +((first.match(/:(\d{1,5})\b/) || [])[1]);
      if (port >= 1 && port <= 65535) ports[port] = 1;
    });
    var list = Object.keys(ports).map(Number).sort(function (a, b) { return a - b; });
    if (list.length) _add(facts, mkFact('scan.local.listeners', h, { ports: list.slice(0, 48) }, S, source));
  }

  // The foothold's own resolvers - the internal DNS servers (often a DC) that name the rest of the
  // estate. Linux `/etc/resolv.conf` ("nameserver 10.0.0.2"), Windows ipconfig /all ("DNS Servers . . :
  // 10.0.0.2"). Conservative: only routable unicast servers; a commented or empty file mints nothing.
  function _parse_local_dns(text, ws, source, facts) {
    var h = 'host:' + ws.target, servers = {}, m;
    var reNs = /^\s*nameserver\s+(\d{1,3}(?:\.\d{1,3}){3})/gim;
    while ((m = reNs.exec(text))) { if (isPrivateHostIp(m[1])) servers[m[1]] = 1; }
    var reWin = /DNS Servers[^\n:]*:\s*((?:\d{1,3}\.){3}\d{1,3}(?:[\s\S]{0,40}?\d{1,3}(?:\.\d{1,3}){3})*)/gi;
    while ((m = reWin.exec(text))) { (m[1].match(/\d{1,3}(?:\.\d{1,3}){3}/g) || []).forEach(function (ip) { if (isPrivateHostIp(ip)) servers[ip] = 1; }); }
    var list = Object.keys(servers);
    if (list.length) _add(facts, mkFact('scan.local.dns', h, { servers: list.slice(0, 8) }, S, source));
  }

  C._parse_local_net = _parse_local_net;
  C._parse_chisel = _parse_chisel;
  C._parse_tunnel = _parse_tunnel;
  C._parse_local_neighbors = _parse_local_neighbors;
  C._parse_local_listeners = _parse_local_listeners;
  C._parse_local_dns = _parse_local_dns;

  OBOL.parsers = OBOL.parsers || {};
  OBOL.parsers.pivot = Object.assign(OBOL.parsers.pivot || {}, {
    _parse_local_net: _parse_local_net,
    _parse_chisel: _parse_chisel,
    _parse_tunnel: _parse_tunnel,
    _parse_local_neighbors: _parse_local_neighbors,
    _parse_local_listeners: _parse_local_listeners,
    _parse_local_dns: _parse_local_dns
  });
  if (typeof module !== 'undefined' && module.exports) { module.exports = OBOL.parsers.pivot; }
})(typeof globalThis !== 'undefined' ? globalThis : this);
