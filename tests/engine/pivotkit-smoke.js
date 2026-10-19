/* pivotkit-smoke.js - OBOL.pivotkit (the Pivot Station). Asserts the transport is auto-chosen from
 * facts, every local-half .sh is valid bash and fills the engagement context with no token leak, and
 * the on-host lines fill for Linux and Windows. */
'use strict';
var cp = require('child_process'), fs = require('fs'), os = require('os'), path = require('path');
require('../../assets/engine/pivotkit.js');
var PK = globalThis.OBOL.pivotkit;

var fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

// Check for available, working bash binary (Git Bash on Windows or system bash)
var bashBin = (function () {
  if (process.platform === 'win32') {
    var gitBash = 'C:\\Program Files\\Git\\bin\\bash.exe';
    if (fs.existsSync(gitBash)) return gitBash;
  }
  try {
    var test = cp.spawnSync('bash', ['-c', 'exit 0']);
    return test.status === 0 ? 'bash' : null;
  } catch (e) {
    return null;
  }
})();

// 1) transport auto-selection
ok(PK.selectTransport(['service.ssh', 'credential.available']) === 'sshuttle', 'ssh creds -> sshuttle');
ok(PK.selectTransport(['foothold.linux']) === 'ligolo', 'foothold, no ssh creds -> ligolo');
ok(PK.selectTransport([]) === 'ligolo', 'default -> ligolo');

var CTX = { lhost: '10.10.14.5', pivotHost: '10.10.10.7', sshUser: 'bob', subnet: '172.16.5.0/24', port: '11601' };

// 2) each local kit is valid bash, fills the context, no token leak
PK.transports().forEach(function (t) {
  var kit = PK.localKit(t.id, CTX);
  ok(kit.indexOf('#!/usr/bin/env bash') === 0, t.id + ': local kit starts with a shebang');
  ok(!/\{\{|LHOST=\"LHOST\"|FOOTHOLD/.test(kit) || /LHOST=\"10\.10\.14\.5\"/.test(kit), t.id + ': local kit fills the context');
  ok(kit.indexOf('172.16.5.0/24') >= 0, t.id + ': local kit carries the subnet');
  var tmp = path.join(os.tmpdir(), 'obol-pivot-' + t.id + '.sh');
  fs.writeFileSync(tmp, kit);
  if (bashBin) {
    var r = cp.spawnSync(bashBin, ['-n', tmp], { encoding: 'utf8' });
    ok(r.status === 0, t.id + ': local kit passes bash -n' + (r.status === 0 ? '' : ' (' + (r.stderr || '').trim() + ')'));
  } else {
    ok(true, t.id + ': bash not available, skipping bash -n');
  }
  try { fs.unlinkSync(tmp); } catch (e) {}

  // Defensive checks from TASK-04:
  ok(kit.indexOf('LIVE_TUN=') >= 0, t.id + ': contains VPN drift check');
  ok(kit.indexOf('obol:fact:pivot_active') >= 0, t.id + ': contains obol:fact:pivot_active sync token');
  if (t.id === 'ligolo') {
    ok(kit.indexOf('trap cleanup EXIT INT TERM') >= 0, 'ligolo: contains trap cleanup EXIT INT TERM');
    ok(kit.indexOf('sudo -v') >= 0, 'ligolo: contains upfront sudo -v priming');
  }

  // the server MUST run in the foreground (exec, not backgrounded) or the tunnel dies when the script exits.
  var lines = kit.trim().split('\n');
  ok(/^exec /.test(lines[lines.length - 1]), t.id + ': server runs in the foreground (last line is exec)');
  ok(!/ &\s*$/m.test(kit) && kit.indexOf('-proxy -selfcert -laddr 0.0.0.0:' + CTX.port + ' &') < 0, t.id + ': no backgrounded server (& then exit) kills the tunnel');
  // the install check names the real BINARY, not the transport id.
  ok(kit.indexOf('command -v ' + (t.bin || t.id)) >= 0, t.id + ': install check probes the binary ' + (t.bin || t.id));
  // unfilled-placeholder guard present.
  ok(kit.indexOf('is not set, fill it') >= 0, t.id + ': guards against unfilled LHOST/PIVOT/SUBNET');
});
// a kit built with no context must refuse to run broken (placeholder guard), not emit LHOST="LHOST" bare.
ok(/case .*LHOST\|PIVOT\|SUBNET\|FOOTHOLD/.test(PK.localKit('ligolo', {})), 'empty-context kit still carries the placeholder guard');

// 3) on-host lines fill (agent transports) and are empty (ssh transports)
var lig = PK.onHostLines('ligolo', CTX, 'linux');
ok(lig.length && lig.join(' ').indexOf('10.10.14.5:11601') >= 0, 'ligolo on-host line connects back to LHOST:PORT');
ok(PK.onHostLines('ligolo', CTX, 'windows').join(' ').indexOf('agent.exe') >= 0, 'ligolo windows on-host uses agent.exe');
ok(PK.onHostLines('chisel', CTX, 'linux').join(' ').indexOf('R:1080:socks') >= 0, 'chisel on-host sets up the reverse SOCKS');
var chisWin = PK.onHostLines('chisel', CTX, 'windows').join(' ');
ok(chisWin.indexOf('chisel.exe') >= 0 && chisWin.indexOf('chisel.exe.exe') < 0, 'chisel windows on-host uses chisel.exe (no .exe.exe)');
ok(PK.localKit('ligolo', Object.assign({}, CTX, { os: 'windows' })).indexOf('agent.exe') >= 0, 'localKit reflects Windows on-host lines when ctx.os is windows');
ok(PK.onHostLines('sshuttle', CTX, 'linux').length === 0, 'sshuttle has no on-host half (all local)');

// 4) the placeholder guard only checks the vars THIS transport uses, so an SSH SOCKS tunnel (needs just the
// foothold) does not abort on an unset LHOST or SUBNET it never references.
function guardLine(id) { return (PK.localKit(id, {}).split('\n').filter(function (l) { return l.indexOf('for v in') >= 0; })[0] || ''); }
ok(/for v in PIVOT; do/.test(guardLine('ssh-dynamic')), 'ssh-dynamic guards only PIVOT (not LHOST/SUBNET)');
ok(/for v in PIVOT SUBNET; do/.test(guardLine('sshuttle')), 'sshuttle guards PIVOT + SUBNET');
ok(/for v in LHOST SUBNET; do/.test(guardLine('ligolo')), 'ligolo guards LHOST + SUBNET');
ok(/for v in LHOST; do/.test(guardLine('chisel')), 'chisel guards only LHOST');

// 5) parseActionOutput recognizes the obol:fact:pivot_active sync token
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/pack.js');
require('../../assets/engine/profile.js');
require('../../assets/engine/command.js');
require('../../assets/engine/workspace.js');
require('../../assets/engine/parsers/common.js');
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'pivot', 'dns', 'blockers', 'shape'].forEach(function (m) {
  require('../../assets/engine/parsers/' + m + '.js');
});
require('../../assets/engine/parsers/index.js');

var tokenLine = 'obol:fact:pivot_active | subnet=172.16.2.0/24 | via=ligolo | host=10.10.11.23';
var parsed = globalThis.OBOL.parsers.parseActionOutput({ command: '', stdout: tokenLine, scope: 'host:10.10.11.23' });
var pKinds = (parsed.facts || []).map(function (f) { return f.kind; });
ok(pKinds.indexOf('pivot.active') >= 0, 'sync token mints pivot.active');
ok(pKinds.indexOf('tunnel.route') >= 0, 'sync token mints tunnel.route');
var ligRoute = (parsed.facts || []).filter(function (f) { return f.kind === 'tunnel.route'; })[0];
ok(ligRoute && ligRoute.value && ligRoute.value.subnet === '172.16.2.0/24' && ligRoute.value.via === 'ligolo' && ligRoute.value.host === '10.10.11.23', 'tunnel.route carries subnet, via, and host');

var socksLine = 'obol:fact:pivot_active | subnet=172.16.2.0/24 | via=chisel | host=10.10.11.23';
var socksParsed = globalThis.OBOL.parsers.parseActionOutput({ command: '', stdout: socksLine, scope: 'host:10.10.11.23' });
var sKinds = (socksParsed.facts || []).map(function (f) { return f.kind; });
ok(sKinds.indexOf('pivot.active') >= 0, 'chisel sync token mints pivot.active');
ok(sKinds.indexOf('tunnel.socks') >= 0, 'chisel sync token mints tunnel.socks');
var chiselSocks = (socksParsed.facts || []).filter(function (f) { return f.kind === 'tunnel.socks'; })[0];
ok(chiselSocks && chiselSocks.value && chiselSocks.value.port === 1080 && chiselSocks.value.via === 'chisel', 'tunnel.socks carries port 1080 and via chisel');

if (fail) { console.error('pivotkit-smoke: ' + fail + ' FAIL'); process.exit(1); }
console.log('pivotkit-smoke: OK');
