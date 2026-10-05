/*!
 * obol engine — parsers/pivot.js — connectivity parsers (interfaces/subnets + live tunnels).
 *
 * Powers the engagement-hub connectivity view: from a foothold's own interface/route dump, mint the
 * subnets it can reach (and flag it multihomed); from a pivot tool's setup output, mint the live
 * tunnel. These are the already-declared pivot-lane facts (scan.local.interfaces / scan.local.routes /
 * host.multihomed / tunnel.socks|route|dns), now actually read from pasted output. Conservative:
 * every fact is content-gated and the operator's loopback/link-local is never a subnet.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var C = OBOL._parserCommon; if (!C) return;
  var mkFact = C.mkFact, _add = C._add, S = C.ProofState.SUPPORTED;

  function isRoutable(ip) {
    var o = String(ip).split('.'); if (o.length !== 4) return false;
    for (var i = 0; i < 4; i++) { var n = +o[i]; if (!(o[i] !== '' && n >= 0 && n <= 255)) return false; }
    return +o[0] !== 127 && !(+o[0] === 169 && +o[1] === 254) && ip !== '0.0.0.0' && ip !== '255.255.255.255';
  }
  function maskToPrefix(mask) {
    var bits = mask.split('.').map(function (o) { return ('00000000' + (+o).toString(2)).slice(-8); }).join('');
    var z = bits.indexOf('0'); return z < 0 ? 32 : z;
  }
  function netCidr(ip, pfx) {
    var p = ip.split('.').map(Number);
    var bits = (p[0] * 16777216 + p[1] * 65536 + p[2] * 256 + p[3]) >>> 0;
    var mask = pfx <= 0 ? 0 : (pfx >= 32 ? 0xFFFFFFFF : ((0xFFFFFFFF << (32 - pfx)) >>> 0));
    var net = (bits & mask) >>> 0;
    return [(net >>> 24) & 255, (net >>> 16) & 255, (net >>> 8) & 255, net & 255].join('.') + '/' + pfx;
  }

  // `ip a` / ifconfig / ipconfig / `ip route` / `route print` on a pivot host → its interfaces and the
  // subnets it sits on or routes to. A host with two or more routable interfaces is a pivot.
  function _parse_local_net(text, ws, source, facts) {
    var h = 'host:' + ws.target, ifaces = [], subnets = {}, seen = {}, m;
    // Linux `ip a`: "inet 172.16.5.10/24"
    var reCidr = /\binet\s+(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})\b/gi;
    while ((m = reCidr.exec(text))) { var ip = m[1], pfx = +m[2]; if (!isRoutable(ip) || seen[ip]) continue; seen[ip] = 1; ifaces.push({ ip: ip, cidr: ip + '/' + pfx }); subnets[netCidr(ip, pfx)] = 1; }
    // ifconfig: "inet 172.16.5.10  netmask 255.255.255.0" (or "inet addr:...  Mask:...")
    var reMask = /\binet\s+(?:addr:)?(\d{1,3}(?:\.\d{1,3}){3})\b[\s\S]{0,60}?(?:netmask|Mask:)\s*(\d{1,3}(?:\.\d{1,3}){3})/gi;
    while ((m = reMask.exec(text))) { var ip2 = m[1]; if (!isRoutable(ip2) || seen[ip2]) continue; seen[ip2] = 1; var pfx2 = maskToPrefix(m[2]); ifaces.push({ ip: ip2, cidr: ip2 + '/' + pfx2 }); subnets[netCidr(ip2, pfx2)] = 1; }
    // Windows ipconfig: "IPv4 Address. . . : 172.16.5.10" then "Subnet Mask . . . : 255.255.255.0"
    var reWin = /IPv4 Address[^\n:]*:\s*(\d{1,3}(?:\.\d{1,3}){3})[\s\S]{0,160}?Subnet Mask[^\n:]*:\s*(\d{1,3}(?:\.\d{1,3}){3})/gi;
    while ((m = reWin.exec(text))) { var ip3 = m[1]; if (!isRoutable(ip3) || seen[ip3]) continue; seen[ip3] = 1; var pfx3 = maskToPrefix(m[2]); ifaces.push({ ip: ip3, cidr: ip3 + '/' + pfx3 }); subnets[netCidr(ip3, pfx3)] = 1; }
    // routes: "172.16.6.0/24 dev eth1" / "... via ..."
    var reRoute = /(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})\s+(?:dev|via|proto|scope)/gi;
    while ((m = reRoute.exec(text))) { var rnet = m[1], rp = +m[2]; if (+rnet.split('.')[0] !== 127 && rnet !== '0.0.0.0') subnets[netCidr(rnet, rp)] = 1; }
    var subs = Object.keys(subnets);
    if (ifaces.length) _add(facts, mkFact('scan.local.interfaces', h, { interfaces: ifaces.slice(0, 12), subnets: subs.slice(0, 12) }, S, source));
    if (subs.length) _add(facts, mkFact('scan.local.routes', h, { subnets: subs.slice(0, 16) }, S, source));
    if (ifaces.length >= 2) _add(facts, mkFact('host.multihomed', h, { interfaces: ifaces.length }, S, source));
  }

  // The setup / status output that confirms a live pivot channel from this foothold.
  function _parse_tunnel(text, ws, source, facts, command) {
    var h = 'host:' + ws.target, lc = String(command || '').toLowerCase(), t = String(text || '');
    if (/\bchisel\b/.test(lc) && (/R:socks/i.test(lc) || /Connected|tun:\s*proxy|listening on|R:socks/i.test(t))) _add(facts, mkFact('tunnel.socks', h, { via: 'chisel' }, S, source));
    if (/ssh\s+[^\n]*-[a-z]*d\b/i.test(lc) || /(^|\s)-D\s+\d+/.test(String(command || ''))) _add(facts, mkFact('tunnel.socks', h, { via: 'ssh-dynamic' }, S, source));
    if (/\bligolo\b/.test(lc) || (/ligolo/i.test(t) && /(agent joined|session|tunnel started|route added|Agent joined)/i.test(t))) _add(facts, mkFact('tunnel.route', h, { via: 'ligolo' }, S, source));
    if (/\bsshuttle\b/.test(lc) || /Connected to server\.?/i.test(t) && /sshuttle/i.test(t)) _add(facts, mkFact('tunnel.route', h, { via: 'sshuttle' }, S, source));
    if (/\bdnscat/.test(lc) || (/dnscat/i.test(t) && /(Session \d+|New window|established)/i.test(t))) _add(facts, mkFact('tunnel.dns', h, { via: 'dnscat2' }, S, source));
  }

  C._parse_local_net = _parse_local_net;
  C._parse_tunnel = _parse_tunnel;
})(typeof globalThis !== 'undefined' ? globalThis : this);
