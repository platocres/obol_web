/* Pivot setup parsers (parsers/pivot.js, via the real dispatcher): a foothold's interface/route dump
 * mints the subnets it reaches and flags it multihomed, across every shape an operator pastes (ip a,
 * ifconfig, Windows ipconfig, ip route, netstat -rn, Windows route print); a pivot tool's own success
 * banner mints the live tunnel for the right kind. Conservative: loopback / link-local / multicast /
 * default routes mint no subnet, and a benign paste mints nothing. */
'use strict';
var path = require('path');
var R = path.join(__dirname, '..', '..');
function req(p) { return require(path.join(R, p)); }
req('assets/engine/facts.js'); req('assets/engine/phases.js'); req('assets/engine/pack.js');
req('assets/engine/profile.js'); req('assets/engine/command.js'); req('assets/engine/workspace.js');
var OBOL = globalThis.OBOL;
req('assets/engine/parsers/common.js');
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'pivot', 'shape'].forEach(function (m) { req('assets/engine/parsers/' + m + '.js'); });
req('assets/engine/parsers/index.js');

var fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }
function run(cmd, out) { var r = OBOL.parsers.parseActionOutput({ command: cmd, stdout: out, scope: 'host:10.10.10.10', domain: 'acme.local' }); return r.facts || []; }
function kinds(cmd, out) { return run(cmd, out).map(function (f) { return f.kind; }); }
function subnets(cmd, out) {
  var f = run(cmd, out).filter(function (x) { return x.kind === 'scan.local.routes' || x.kind === 'scan.local.interfaces'; });
  var s = {}; f.forEach(function (x) { (x.value.subnets || []).forEach(function (n) { s[n] = 1; }); }); return Object.keys(s);
}
function has(arr, v) { return arr.indexOf(v) >= 0; }

// ---- interfaces: Linux ip a → interfaces + subnet + multihomed (two routable NICs) ----
var ipa = '1: lo: <LOOPBACK> \n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,UP>\n    inet 10.10.14.9/24 brd 10.10.14.255 scope global eth0\n3: eth1: <BROADCAST,UP>\n    inet 172.16.5.10/24 brd 172.16.5.255 scope global eth1';
ok(has(kinds('ip a', ipa), 'scan.local.interfaces'), 'ip a mints scan.local.interfaces');
ok(has(kinds('ip a', ipa), 'host.multihomed'), 'two routable NICs flag the host multihomed');
ok(has(subnets('ip a', ipa), '172.16.5.0/24') && !has(subnets('ip a', ipa), '127.0.0.0/8'), 'ip a yields the internal /24 and never loopback');

// ---- ifconfig netmask form ----
var ifc = 'eth1: flags=4163<UP>\n        inet 172.16.5.10  netmask 255.255.255.0  broadcast 172.16.5.255';
ok(has(subnets('ifconfig', ifc), '172.16.5.0/24'), 'ifconfig netmask form yields the /24');

// ---- Windows ipconfig ----
var ipc = 'Ethernet adapter Ethernet1:\n   IPv4 Address. . . . . . . . . . . : 172.16.5.10\n   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n   Default Gateway . . . . . . . . . : 172.16.5.1';
ok(has(subnets('ipconfig', ipc), '172.16.5.0/24'), 'Windows ipconfig yields the /24');

// ---- Linux ip route ----
var iproute = 'default via 10.10.14.1 dev eth0\n10.10.14.0/24 dev eth0 proto kernel scope link src 10.10.14.9\n172.16.5.0/24 dev eth1 proto kernel scope link src 172.16.5.10';
ok(has(subnets('ip route', iproute), '172.16.5.0/24'), 'ip route yields the routed internal /24');

// ---- netstat -rn (Destination / Gateway / Genmask columns; mask is the 3rd quad) ----
var netstat = 'Kernel IP routing table\nDestination     Gateway         Genmask         Flags   MSS Window  irtt Iface\n0.0.0.0         10.10.14.1      0.0.0.0         UG        0 0          0 eth0\n172.16.5.0      0.0.0.0         255.255.255.0   U         0 0          0 eth1';
ok(has(subnets('netstat -rn', netstat), '172.16.5.0/24'), 'netstat -rn yields the /24 from the Genmask column');

// ---- Windows route print (Network Destination / Netmask columns; mask is the 2nd quad) ----
var routeprint = 'IPv4 Route Table\nNetwork Destination        Netmask          Gateway       Interface  Metric\n          0.0.0.0          0.0.0.0      172.16.5.1    172.16.5.10     20\n       172.16.5.0    255.255.255.0         On-link     172.16.5.10    276\n        224.0.0.0        240.0.0.0         On-link     172.16.5.10    276';
ok(has(subnets('route print', routeprint), '172.16.5.0/24'), 'Windows route print yields the /24 from the Netmask column');
ok(!has(subnets('route print', routeprint), '224.0.0.0/4') && subnets('route print', routeprint).every(function (n) { return n.indexOf('224.') !== 0; }), 'route print never yields the multicast 224.0.0.0 row');

// ---- conservative: a benign paste with no net info mints nothing ----
ok(kinds('ip a', 'command not found: ip').length === 0, 'an error paste mints no connectivity fact');

// ---- tunnels: each tool recognized from its own success banner (no command needed) ----
ok(has(kinds('', 'INFO[0005] Agent joined. name=CORP\\\\user remoteaddr="172.16.5.10:51000"'), 'tunnel.route'), 'ligolo "Agent joined" banner mints tunnel.route');
ok(has(kinds('', 'chisel client 10.10.14.9:8080 R:socks\n2026/01/01 server: Connected (Latency 1.2ms)'), 'tunnel.socks'), 'chisel "Connected" banner mints tunnel.socks (from output, no command)');
ok(has(kinds('ssh -D 1080 -N bob@10.10.10.10', ''), 'tunnel.socks'), 'ssh -D command mints tunnel.socks (silent tool, command is the proof)');
ok(has(kinds('sshuttle -r bob@10.10.10.10 172.16.5.0/24', 'client: Connected to server.'), 'tunnel.route'), 'sshuttle connected mints tunnel.route');
ok(has(kinds('', 'dnscat2> New window created: 1\nSession established!'), 'tunnel.dns'), 'dnscat2 session banner mints tunnel.dns');
// conservative: an unrelated mention of a tool name with no success token mints no tunnel
ok(!has(kinds('man chisel', 'chisel is a fast TCP/UDP tunnel. Usage: chisel server|client'), 'tunnel.socks'), 'a chisel help/man page mints no tunnel');

console.log('\nPIVOT PARSER SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
