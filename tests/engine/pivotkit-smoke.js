/* pivotkit-smoke.js — OBOL.pivotkit (the Pivot Station). Asserts the transport is auto-chosen from
 * facts, every local-half .sh is valid bash and fills the engagement context with no token leak, and
 * the on-host lines fill for Linux and Windows. */
'use strict';
var cp = require('child_process'), fs = require('fs'), os = require('os'), path = require('path');
require('../../assets/engine/pivotkit.js');
var PK = globalThis.OBOL.pivotkit;

var fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

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
  var r = cp.spawnSync('bash', ['-n', tmp], { encoding: 'utf8' });
  ok(r.status === 0, t.id + ': local kit passes bash -n' + (r.status === 0 ? '' : ' (' + (r.stderr || '').trim() + ')'));
  try { fs.unlinkSync(tmp); } catch (e) {}
});

// 3) on-host lines fill (agent transports) and are empty (ssh transports)
var lig = PK.onHostLines('ligolo', CTX, 'linux');
ok(lig.length && lig.join(' ').indexOf('10.10.14.5:11601') >= 0, 'ligolo on-host line connects back to LHOST:PORT');
ok(PK.onHostLines('ligolo', CTX, 'windows').join(' ').indexOf('agent.exe') >= 0, 'ligolo windows on-host uses agent.exe');
ok(PK.onHostLines('chisel', CTX, 'linux').join(' ').indexOf('R:1080:socks') >= 0, 'chisel on-host sets up the reverse SOCKS');
ok(PK.onHostLines('sshuttle', CTX, 'linux').length === 0, 'sshuttle has no on-host half (all local)');

if (fail) { console.error('pivotkit-smoke: ' + fail + ' FAIL'); process.exit(1); }
console.log('pivotkit-smoke: OK');
