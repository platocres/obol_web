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
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'pivot', 'dns', 'shape'].forEach(function (m) { req('assets/engine/parsers/' + m + '.js'); });
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

// ---- neighbours: Linux `ip neigh` → adjacent hosts (scan.local.neighbors), only resolved entries ----
function hostsOf(cmd, out) { var f = run(cmd, out).filter(function (x) { return x.kind === 'scan.local.neighbors'; }); var s = {}; f.forEach(function (x) { (x.value.hosts || []).forEach(function (n) { s[n] = 1; }); }); return Object.keys(s); }
var ipneigh = '10.10.14.1 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n172.16.5.1 dev eth1 lladdr aa:bb:cc:dd:ee:02 STALE\n172.16.5.99 dev eth1  INCOMPLETE\n127.0.0.1 dev lo lladdr 00:00:00:00:00:00 PERMANENT';
ok(has(kinds('ip neigh show', ipneigh), 'scan.local.neighbors'), 'ip neigh mints scan.local.neighbors');
ok(has(hostsOf('ip neigh show', ipneigh), '172.16.5.1') && has(hostsOf('ip neigh show', ipneigh), '10.10.14.1'), 'ip neigh yields the resolved adjacent hosts');
ok(!has(hostsOf('ip neigh show', ipneigh), '172.16.5.99') && !has(hostsOf('ip neigh show', ipneigh), '127.0.0.1'), 'ip neigh drops the INCOMPLETE slot and loopback');
// Windows arp -a
var arpa = 'Interface: 172.16.5.10 --- 0x5\n  Internet Address      Physical Address      Type\n  172.16.5.1            aa-bb-cc-dd-ee-02     dynamic\n  172.16.5.255          ff-ff-ff-ff-ff-ff     static';
ok(has(hostsOf('arp -a', arpa), '172.16.5.1'), 'Windows arp -a yields the dynamic neighbour');
ok(kinds('ip neigh show', 'Nothing to show.').length === 0, 'an empty neighbour cache mints nothing');

// ---- listeners: Windows `netstat -ano` → listening ports (scan.local.listeners), LISTEN rows only ----
function portsOf(cmd, out) { var f = run(cmd, out).filter(function (x) { return x.kind === 'scan.local.listeners'; }); var s = {}; f.forEach(function (x) { (x.value.ports || []).forEach(function (n) { s[n] = 1; }); }); return Object.keys(s).map(Number); }
var nstat = 'Active Connections\n  Proto  Local Address          Foreign Address        State           PID\n  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4\n  TCP    127.0.0.1:5985         0.0.0.0:0              LISTENING       4\n  TCP    172.16.5.10:3389       10.10.14.9:51000      ESTABLISHED     1200';
ok(has(portsOf('netstat -ano', nstat), 445) && has(portsOf('netstat -ano', nstat), 5985), 'netstat -ano yields the listening ports (0.0.0.0 and localhost-only)');
ok(!has(portsOf('netstat -ano', nstat), 51000), 'netstat -ano does not count an ESTABLISHED connection as a listener');
// Linux ss -tlnp
var ss = 'State    Recv-Q   Send-Q   Local Address:Port   Peer Address:Port\nLISTEN   0        128      127.0.0.1:3306       0.0.0.0:*\nLISTEN   0        128      0.0.0.0:22           0.0.0.0:*';
ok(has(portsOf('ss -tlnp', ss), 3306) && has(portsOf('ss -tlnp', ss), 22), 'ss -tlnp yields the listening ports incl. the localhost-only 3306');

// ---- resolvers: /etc/resolv.conf and Windows DNS Servers → scan.local.dns ----
function dnsOf(cmd, out) { var f = run(cmd, out).filter(function (x) { return x.kind === 'scan.local.dns'; }); var s = {}; f.forEach(function (x) { (x.value.servers || []).forEach(function (n) { s[n] = 1; }); }); return Object.keys(s); }
var resolv = '# generated\nsearch acme.local\nnameserver 10.10.14.2\nnameserver 127.0.0.53';
ok(has(dnsOf('cat /etc/resolv.conf', resolv), '10.10.14.2') && !has(dnsOf('cat /etc/resolv.conf', resolv), '127.0.0.53'), 'resolv.conf yields the internal resolver and drops the loopback stub');
var winDns = '   Connection-specific DNS Suffix  . : acme.local\n   DNS Servers . . . . . . . . . . . : 10.10.14.2\n                                       10.10.14.3';
ok(has(dnsOf('ipconfig /all', winDns), '10.10.14.2') && has(dnsOf('ipconfig /all', winDns), '10.10.14.3'), 'Windows DNS Servers yields both resolvers');
ok(kinds('cat /etc/resolv.conf', '# all commented out\n#nameserver 1.1.1.1').length === 0, 'a fully-commented resolv.conf mints nothing');

// ---- internal resolver (parsers/dns.js): dig/nslookup/AXFR → domain + DC candidate, unlocking AD ----
function scopesOf(cmd, out, kind) { return run(cmd, out).filter(function (x) { return x.kind === kind; }).map(function (x) { return x.scope; }); }
var digSrv = ';; ANSWER SECTION:\n_ldap._tcp.dc._msdcs.acme.local. 600 IN SRV 0 100 389 dc01.acme.local.\n\n;; ADDITIONAL SECTION:\ndc01.acme.local.\t3600\tIN\tA\t10.10.14.2';
ok(has(kinds('dig @10.10.14.2 -t SRV _ldap._tcp.dc._msdcs.acme.local', digSrv), 'ad.domain_known'), 'dig SRV mints ad.domain_known');
ok(has(scopesOf('dig @10.10.14.2 -t SRV _ldap._tcp.dc._msdcs.acme.local', digSrv, 'ad.dc_candidate'), 'host:10.10.14.2'), 'dig SRV + additional A mints the DC candidate at its real IP');
var axfr = 'acme.local.\t86400\tIN\tSOA\tdc01.acme.local. hostmaster.acme.local. 1 900 600 86400 3600\nacme.local.\t86400\tIN\tNS\tdc01.acme.local.\ndc01.acme.local.\t3600\tIN\tA\t10.10.14.2\nweb01.acme.local.\t3600\tIN\tA\t10.10.14.50';
var axk = kinds('dig @10.10.14.2 AXFR acme.local', axfr);
ok(has(axk, 'ad.domain_known') && has(axk, 'ad.dc_candidate') && has(axk, 'dns.zone'), 'a successful AXFR mints the domain, the DC (from SOA/NS + A), and a zone receipt');
ok(scopesOf('dig @10.10.14.2 AXFR acme.local', axfr, 'ad.dc_candidate').indexOf('host:10.10.14.2') >= 0, 'AXFR pins the DC to the authoritative host address');
// nslookup SRV form
var nsl = 'Server:  10.10.14.2\n_ldap._tcp.dc._msdcs.acme.local  SRV service location:\n          priority = 0\n          svr hostname   = dc01.acme.local\ndc01.acme.local internet address = 10.10.14.2';
ok(has(kinds('nslookup -type=SRV _ldap._tcp.dc._msdcs.acme.local 10.10.14.2', nsl), 'ad.dc_candidate') || has(kinds('nslookup -type=SRV _ldap._tcp.dc._msdcs.acme.local 10.10.14.2', nsl), 'ad.domain_known'), 'nslookup SRV output is recognized');
// conservative: a refused transfer / NXDOMAIN mints nothing
ok(kinds('dig @10.10.14.2 AXFR acme.local', '; Transfer failed.\n; communications error to 10.10.14.2#53: connection refused').length === 0, 'a refused zone transfer mints nothing');
ok(kinds('dig @10.10.14.2 nonexist.acme.local', ';; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1').length === 0, 'an NXDOMAIN answer mints nothing');

console.log('\nPIVOT PARSER SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
