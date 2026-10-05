/*!
 * obol engine — parsers/pivot.js — connectivity parsers (interfaces/subnets + live tunnels).
 *
 * Powers the engagement-hub connectivity view: from a foothold's own interface/route dump, mint the
 * subnets it can reach (and flag it multihomed); from a pivot tool's setup output, mint the live
 * tunnel. These are the already-declared pivot-lane facts (scan.local.interfaces / scan.local.routes /
 * host.multihomed / tunnel.socks|route|dns), read from pasted output. Conservative: every fact is
 * content-gated, and loopback / link-local / multicast / reserved addresses are never a subnet.
 *
 * Covers the real shapes an operator pastes on either side of a pivot:
 *   interfaces — Linux `ip a`/`ip -4 a`, ifconfig, Windows ipconfig
 *   routes     — Linux `ip route`, `netstat -rn` (Destination/Gateway/Genmask), Windows `route print`
 *                (Network Destination/Netmask) — the last two carry the netmask as a dotted quad in a
 *                column, so a netmask-aware row reader handles both without caring about column order
 *   tunnels    — chisel (reverse SOCKS), ssh -D (dynamic SOCKS), ligolo-ng + sshuttle (routed),
 *                dnscat2 (DNS) — recognized from the command AND from the tool's own success banner,
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

  function _parse_local_net(text, ws, source, facts) {
    var h = 'host:' + ws.target, ifaces = [], subnets = {}, seen = {}, m;
    function addSubnet(net, pfx) { if (isRoutable(net) && pfx >= 1 && pfx <= 30) subnets[netCidr(net, pfx)] = 1; }

    // Linux `ip a` / `ip -4 a`: "inet 172.16.5.10/24"
    var reCidr = /\binet6?\s+(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})\b/gi;
    while ((m = reCidr.exec(text))) { var ip = m[1], pfx = +m[2]; if (!isRoutable(ip) || seen[ip]) continue; seen[ip] = 1; ifaces.push({ ip: ip, cidr: ip + '/' + pfx }); addSubnet(ip, pfx); }
    // ifconfig: "inet 172.16.5.10  netmask 255.255.255.0" (or "inet addr:...  Mask:...")
    var reMask = /\binet\s+(?:addr:)?(\d{1,3}(?:\.\d{1,3}){3})\b[\s\S]{0,60}?(?:netmask|Mask:)\s*(\d{1,3}(?:\.\d{1,3}){3})/gi;
    while ((m = reMask.exec(text))) { var ip2 = m[1]; if (!isRoutable(ip2) || seen[ip2]) continue; var pfx2 = maskPrefix(m[2]); if (pfx2 < 0) continue; seen[ip2] = 1; ifaces.push({ ip: ip2, cidr: ip2 + '/' + pfx2 }); addSubnet(ip2, pfx2); }
    // Windows ipconfig: "IPv4 Address. . . : 172.16.5.10" then "Subnet Mask . . . : 255.255.255.0"
    var reWin = /IPv4 Address[^\n:]*:\s*(\d{1,3}(?:\.\d{1,3}){3})[\s\S]{0,160}?Subnet Mask[^\n:]*:\s*(\d{1,3}(?:\.\d{1,3}){3})/gi;
    while ((m = reWin.exec(text))) { var ip3 = m[1]; if (!isRoutable(ip3) || seen[ip3]) continue; var pfx3 = maskPrefix(m[2]); if (pfx3 < 0) continue; seen[ip3] = 1; ifaces.push({ ip: ip3, cidr: ip3 + '/' + pfx3 }); addSubnet(ip3, pfx3); }
    // Linux `ip route`: "172.16.6.0/24 dev eth1 ..." / "... via ..."
    var reRoute = /(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})\s+(?:dev|via|proto|scope)/gi;
    while ((m = reRoute.exec(text))) { addSubnet(m[1], +m[2]); }
    // `netstat -rn` (Destination Gateway Genmask ...) and Windows `route print` (Network Destination
    // Netmask Gateway ...): both put a dotted-quad network and a dotted-quad netmask on the same row,
    // in different columns. Read the first routable quad as the network and the first valid netmask
    // quad on the line as the mask, so column order does not matter and header rows (no quads) skip.
    String(text).split(/\r?\n/).forEach(function (line) {
      if (/\binet6?\b/i.test(line) || /\//.test(line)) return;     // handled by the CIDR / ifconfig readers above
      var quads = line.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g);
      if (!quads || quads.length < 2) return;
      var net = quads[0]; if (!isRoutable(net)) return;
      for (var i = 1; i < quads.length; i++) { var p = maskPrefix(quads[i]); if (p >= 1 && p <= 30) { addSubnet(net, p); break; } }
    });

    var subs = Object.keys(subnets);
    if (ifaces.length) _add(facts, mkFact('scan.local.interfaces', h, { interfaces: ifaces.slice(0, 12), subnets: subs.slice(0, 12) }, S, source));
    if (subs.length) _add(facts, mkFact('scan.local.routes', h, { subnets: subs.slice(0, 16) }, S, source));
    if (ifaces.length >= 2) _add(facts, mkFact('host.multihomed', h, { interfaces: ifaces.length }, S, source));
  }

  // The setup / status output that confirms a live pivot channel from this foothold. Recognized from
  // the command where the command is the proof (ssh -D is silent), and from the tool's own success
  // banner so a pasted output alone still counts. Conservative: a tool name plus a real success token.
  function _parse_tunnel(text, ws, source, facts, command) {
    var h = 'host:' + ws.target, lc = String(command || '').toLowerCase(), t = String(text || ''), cmd = String(command || '');
    // chisel reverse SOCKS: the command carrying R:socks, or the client/server success banner.
    if ((/\bchisel\b/.test(lc) && /r:socks/i.test(lc)) || (/\bchisel\b/i.test(t) && /(Connected\b|Connected \(|Listening on|tun:\s|proxy#\d|session|R:socks)/i.test(t)))
      _add(facts, mkFact('tunnel.socks', h, { via: 'chisel' }, S, source));
    // ssh dynamic port-forward (-D): silent tool, so the command is the proof.
    if (/\bssh\b[^\n]*\s-[a-z]*d(?:\s+\S+)?\b/i.test(cmd) || /(^|\s)-D\s*\d+/.test(cmd))
      _add(facts, mkFact('tunnel.socks', h, { via: 'ssh-dynamic' }, S, source));
    // ligolo-ng routed tunnel: the command, or an "Agent joined" / tunnel-up banner.
    if (/\bligolo\b/.test(lc) || (/ligolo/i.test(t) && /(agent joined|tunnel started|route added|listening on|ligolo-ng|session)/i.test(t)) || /\bAgent joined\b/.test(t))
      _add(facts, mkFact('tunnel.route', h, { via: 'ligolo' }, S, source));
    // sshuttle transparent route: the command, or its "Connected to server." line.
    if (/\bsshuttle\b/.test(lc) || (/sshuttle/i.test(t) && /connected to server/i.test(t)) || (/client:\s*Connected to server/i.test(t)))
      _add(facts, mkFact('tunnel.route', h, { via: 'sshuttle' }, S, source));
    // dnscat2 DNS channel: the command, or a session-established banner.
    if (/\bdnscat/.test(lc) || (/dnscat/i.test(t) && /(Session \d|New window|Session established|established|window -i)/i.test(t)))
      _add(facts, mkFact('tunnel.dns', h, { via: 'dnscat2' }, S, source));
  }

  C._parse_local_net = _parse_local_net;
  C._parse_tunnel = _parse_tunnel;
})(typeof globalThis !== 'undefined' ? globalThis : this);
