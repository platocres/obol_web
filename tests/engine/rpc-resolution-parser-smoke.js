/* Raw rpcclient SID/name resolution + single-object detail parser (corpus-mined, output axis):
 *  an interactive "rpcclient $>" session (or a RID-cycling loop) resolves SIDs to names and dumps one
 *  account at a time with shapes enum4linux-ng/nxc never relabel to the (SidTypeUser) / user:[x] rid:[y]
 *  forms _rid_usernames already catches:
 *    lookupsids  -> "<SID> <DOMAIN>\<name> (<type>)"      type 1 = user, 2/4/5 = group
 *    lookupnames -> "<name> <SID> (<Label>: <type>)"      Label names the SID_NAME_USE class
 *    queryuser   -> "User Name : <name>"                  one resolved user
 *    querygroup  -> "Group Name : <name>"                 one resolved group
 *  The product's ingest prepends the REPL tool token to the sub-shell command ("rpcclient $> lookupsids"
 *  -> command string "rpcclient lookupsids ..."), which is what the dispatcher routes on, so these feed
 *  the existing ad.user_list (the sprayable/roastable pivot, 5 live consumers) and ad.group_list facts.
 *  *unknown* resolutions, non-user/-group SID classes, machine accounts, and NT_STATUS_NONE_MAPPED
 *  failures carry no sprayable name and must mint nothing. Shapes are hand-built, not copied. */
'use strict';
var path = require('path');
var R = path.join(__dirname, '..', '..');
function req(p) { return require(path.join(R, p)); }
req('assets/engine/facts.js'); req('assets/engine/phases.js'); req('assets/engine/pack.js');
req('assets/engine/profile.js'); req('assets/engine/command.js'); req('assets/engine/workspace.js');
var OBOL = globalThis.OBOL, PK = OBOL.pack;
var fs = require('fs'), pdir = path.join(R, 'data/packs'), bundle = {};
fs.readdirSync(pdir).filter(function (f) { return f.endsWith('.json'); }).forEach(function (f) { bundle[f.replace(/\.json$/, '')] = JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); });
var A = PK.loadPacks(Object.keys(bundle).map(function (k) { return bundle[k]; }));
req('assets/engine/parsers/common.js');
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'shape', 'pivot', 'dns', 'blockers', 'nxc-catalog'].forEach(function (m) { req('assets/engine/parsers/' + m + '.js'); });
req('assets/engine/parsers/index.js');

var BS = String.fromCharCode(92); // a single backslash, kept out of string literals to avoid escaping noise
var fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }
function facts(cmd, out) { var r = OBOL.parsers.parseActionOutput({ actionId: '', command: cmd, stdout: out, scope: 'host:10.10.10.10', domain: 'supportdesk.local' }); return (r.facts || []); }
function userList(cmd, out) { return facts(cmd, out).filter(function (f) { return f.kind === 'ad.user_list'; })[0] || null; }
function groupList(cmd, out) { return facts(cmd, out).filter(function (f) { return f.kind === 'ad.group_list'; })[0] || null; }
function has(arr, v) { return (arr || []).map(function (x) { return x.toLowerCase(); }).indexOf(v.toLowerCase()) >= 0; }

// --- lookupsids: a resolved SID block classified by the trailing SID_NAME_USE type. ---
var sidsOut =
  'S-1-5-21-4254423774-1266059056-3197185112-500 SUPPORTDESK' + BS + 'Administrator (1)\n' +
  'S-1-5-21-4254423774-1266059056-3197185112-1008 SUPPORTDESK' + BS + 'Hazard (1)\n' +
  'S-1-5-21-4254423774-1266059056-3197185112-512 SUPPORTDESK' + BS + 'Domain Admins (2)\n' +
  'S-1-5-21-4254423774-1266059056-3197185112-1101 SUPPORTDESK' + BS + 'WEB01$ (1)\n' +
  'S-1-5-21-4254423774-1266059056-3197185112-1111 *unknown*' + BS + '*unknown* (8)';
var slUsers = userList('rpcclient lookupsids S-1-5-21-4254423774-1266059056-3197185112', sidsOut);
var slGroups = groupList('rpcclient lookupsids S-1-5-21-4254423774-1266059056-3197185112', sidsOut);
ok(slUsers && has(slUsers.value.users, 'Hazard') && has(slUsers.value.users, 'Administrator'), 'lookupsids type-1 SIDs resolve into ad.user_list');
ok(slGroups && has(slGroups.value.groups, 'Domain Admins'), 'lookupsids type-2 SID resolves into ad.group_list');
ok(slUsers && !has(slUsers.value.users, 'WEB01$'), 'a machine account (trailing $) is not added to the user list');
ok(slUsers && !has(slUsers.value.users, '*unknown*') && (!slGroups || !has(slGroups.value.groups, '*unknown*')), 'an *unknown* / type-8 resolution mints no user and no group');

// --- lookupnames: the explicit Label names the class (User vs Domain Group/Alias). ---
var namesOut =
  'hazard S-1-5-21-4254423774-1266059056-3197185112-1008 (User: 1)\n' +
  'Domain Admins S-1-5-21-4254423774-1266059056-3197185112-512 (Domain Group: 2)\n' +
  'Backup Operators S-1-5-32-551 (Alias: 4)\n' +
  'notauser S-1-0-0 (Invalid: 7)';
var lnUsers = userList('rpcclient lookupnames hazard', namesOut);
var lnGroups = groupList('rpcclient lookupnames hazard', namesOut);
ok(lnUsers && has(lnUsers.value.users, 'hazard'), 'lookupnames "(User: 1)" resolves into ad.user_list');
ok(lnGroups && has(lnGroups.value.groups, 'Domain Admins') && has(lnGroups.value.groups, 'Backup Operators'), 'lookupnames Domain Group and Alias labels resolve into ad.group_list');
ok(lnUsers && !has(lnUsers.value.users, 'notauser'), 'a "(Invalid: 7)" resolution mints no user');

// --- queryuser / querygroup single-object detail dumps. ---
var quOut = '\tUser Name   :\tHazard\n\tFull Name   :\tDale Hazard\n\tHome Drive  :\n\tacct_flags  :\t0x00000210\n\tUser Name   :\tChase\n\tFull Name   :\tChase User';
var quUsers = userList('rpcclient queryuser 0x3f8', quOut);
ok(quUsers && has(quUsers.value.users, 'Hazard') && has(quUsers.value.users, 'Chase'), 'queryuser "User Name :" mints all queried users in a multi-query paste');
ok(quUsers && !has(quUsers.value.users, 'Dale'), 'queryuser does not mistake the "Full Name :" line for a username');
var qgOut = '\tGroup Name:\tDomain Admins\n\tDescription:\tDesignated administrators of the domain\n\tGroup Attribute:7\n\tNum Members:1';
var qgGroups = groupList('rpcclient querygroup 0x200', qgOut);
ok(qgGroups && has(qgGroups.value.groups, 'Domain Admins'), 'querygroup "Group Name :" mints the group');

// --- No false positives: a failed resolution carries no name. ---
ok(!userList('rpcclient lookupnames bogus', 'bogus S-1-0-0 (Invalid: 7)\nresult was NT_STATUS_NONE_MAPPED'), 'an all-failed lookupnames (NONE_MAPPED) mints no ad.user_list');

// --- No regression: the existing enumdomusers shape still mints, and resolution users MERGE with it. ---
var enumOut =
  'user:[Administrator] rid:[0x1f4]\n' +
  'user:[krbtgt] rid:[0x1f6]\n' +
  'user:[svc_backup] rid:[0x3e9]';
var enUsers = userList('rpcclient enumdomusers', enumOut);
ok(enUsers && has(enUsers.value.users, 'svc_backup') && has(enUsers.value.users, 'krbtgt'), 'the existing enumdomusers user:[x] rid:[y] path still mints ad.user_list');
var mixed = enumOut + '\n' + 'S-1-5-21-4254423774-1266059056-3197185112-1008 SUPPORTDESK' + BS + 'Hazard (1)';
var mixUsers = userList('rpcclient enumdomusers', mixed);
ok(mixUsers && has(mixUsers.value.users, 'svc_backup') && has(mixUsers.value.users, 'Hazard'), 'a paste holding both enumdomusers rows and a lookupsids resolution merges both into one user list');

// --- The minted fact has a live downstream consumer (the loop advances). ---
var consumers = A.filter(function (m) { return [].concat(m.requires_all || [], m.requires_any || []).indexOf('ad.user_list') >= 0; });
ok(consumers.length >= 1, 'ad.user_list drives at least one downstream move (' + consumers.length + ')');

console.log('\nRPC RESOLUTION PARSER SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
