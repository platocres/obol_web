/*!
 * obol engine — profile.js
 * Engagement profile: platform/exam awareness (HTB, OffSec/OSCP, PWK, THM, HTB-CPTS, CTF,
 * OSWP, custom) + machine types. Decides which flag names/formats the hunt looks for, the
 * submittable-proof requirement, the exam-floor posture, and the ranking focus nudge.
 * Faithful JS port of obol-local/obol/profile.py (browser subset — no shell command building
 * beyond the flag-hunt token helpers). Configuration, never a proof.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  var FORMAT_PATTERNS = {
    brace: /\b[A-Za-z0-9_]{2,20}\{[^}\r\n]{1,200}\}/,
    hex64: /\b[0-9a-fA-F]{64}\b/,
    hex32: /\b[0-9a-fA-F]{32}\b/,
    uuid: /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/,
    token: /^\S{1,64}$/,
  };
  var DEFAULT_FORMATS = ['brace', 'hex64', 'hex32', 'token'];
  var DEFAULT_FLAG_NAMES = ['user.txt', 'root.txt', 'local.txt', 'proof.txt', 'flag.txt', 'flag'];
  var DEFAULT_SLOTS = { 'user.txt': 'local', 'local.txt': 'local', 'root.txt': 'root', 'proof.txt': 'root' };

  var DEFAULT_PROOF = {
    required_slots: [],
    identity_linux: ['ip a', 'hostname', 'id'],
    identity_windows: ['ipconfig', 'hostname', 'whoami'],
    note: 'capture the flag and a host-identity command (ip a / hostname) in one screenshot',
    points: { local: 10, root: 10, flag: 10 },
    pass_threshold: 0,
    points_note: '',
  };

  var PRESETS = {
    htb: { name: 'Hack The Box', aliases: ['hackthebox', 'hack-the-box'],
      flag_names: ['user.txt', 'root.txt'], flag_formats: ['hex32', 'hex64', 'brace'],
      slots: { 'user.txt': 'local', 'root.txt': 'root' } },
    cpts: { name: 'HTB CPTS (exam)', aliases: ['htb-cpts', 'hackthebox-cpts', 'htb-exam'],
      flag_names: ['flag.txt', 'user.txt', 'root.txt'], flag_formats: ['hex32', 'hex64', 'brace', 'token'],
      slots: { 'user.txt': 'local', 'root.txt': 'root' },
      proof: { required_slots: [], note: 'CPTS is graded on the report: capture each finding with reproducible evidence (command + output), and screenshot each flag with a host-identity command in the same terminal.' } },
    oscp: { name: 'OffSec / OSCP', aliases: ['offsec', 'offensive-security', 'pen-200', 'pen200'],
      flag_names: ['local.txt', 'proof.txt'], flag_formats: ['hex32', 'hex64', 'token'],
      slots: { 'local.txt': 'local', 'proof.txt': 'root' },
      proof: { required_slots: ['local', 'root'],
        note: 'OffSec requires a screenshot of the flag with `ip a` (and hostname) visible in the same terminal, on the target host.',
        points: { local: 10, root: 10, flag: 10 }, pass_threshold: 70, ad_set_points: 40,
        points_note: 'OSCP: local.txt + proof.txt = 20 pts/standalone machine; 70 to pass. The AD set scores all-or-nothing (40).' } },
    pwk: { name: 'OffSec Labs / PWK (practice)', aliases: ['oscp-lab', 'oscp-labs', 'offsec-lab', 'offsec-labs', 'pen-200-labs', 'pen200-labs'],
      flag_names: ['local.txt', 'proof.txt'], flag_formats: ['hex32', 'hex64', 'token'],
      slots: { 'local.txt': 'local', 'proof.txt': 'root' } },
    thm: { name: 'TryHackMe', aliases: ['tryhackme', 'try-hack-me'],
      flag_names: ['user.txt', 'root.txt', 'flag.txt', 'flag1.txt', 'flag2.txt'], flag_formats: ['brace', 'hex32', 'token'],
      slots: { 'user.txt': 'local', 'root.txt': 'root' } },
    ctf: { name: 'Capture the Flag', aliases: ['capture-the-flag'],
      flag_names: ['flag.txt', 'flag', 'flag1.txt', 'proof.txt'], flag_formats: ['brace', 'uuid', 'hex32', 'hex64', 'token'], slots: {} },
    oswp: { name: 'OffSec / OSWP', aliases: ['offsec-wireless', 'wep-500', 'pen-210', 'pen210'],
      flag_names: DEFAULT_FLAG_NAMES.slice(), flag_formats: DEFAULT_FORMATS.slice(), slots: Object.assign({}, DEFAULT_SLOTS),
      proof: { required_slots: [], note: 'OSWP is graded on the report: for each authorized network, show the captured handshake/PMKID, the crack, and the recovered key with evidence.', wifi_screenshots: true } },
    custom: { name: 'Custom', aliases: ['default', 'generic', 'lab'],
      flag_names: DEFAULT_FLAG_NAMES.slice(), flag_formats: DEFAULT_FORMATS.slice(), slots: Object.assign({}, DEFAULT_SLOTS) },
  };
  var DEFAULT_PLATFORM = 'custom';
  var EXAM_PLATFORMS = { oscp: true, oswp: true, cpts: true };
  var OSID_PLATFORMS = { oscp: true, oswp: true };
  var EXAM_LAB_COUNTERPART = { oscp: 'pwk', pwk: 'oscp', cpts: 'htb', htb: 'cpts' };

  var MACHINE_TYPES = {
    standalone: { name: 'Standalone server', aliases: ['standalone', 'server', 'box'], focus: ['service.', 'web.', 'http.', 'ftp.', 'ssh.', 'exploit.'] },
    dc: { name: 'Active Directory DC', aliases: ['dc', 'domain-controller', 'ad-dc', 'domaincontroller'], focus: ['ad.', 'kerberos', 'hash.tgs', 'hash.asrep', 'ldap.', 'smb.', 'domain.'] },
    member: { name: 'AD member server', aliases: ['member', 'member-server', 'ad-member'], focus: ['ad.', 'smb.', 'credential.', 'kerberos', 'service.'] },
    workstation: { name: 'AD workstation', aliases: ['workstation', 'client', 'endpoint'], focus: ['credential.', 'loot.', 'privesc.', 'smb.'] },
    lab: { name: 'Generic lab box', aliases: ['lab', 'ctf', 'practice'], focus: ['service.', 'web.', 'exploit.'] },
    wireless: { name: 'Wireless / Wi-Fi target', aliases: ['wifi', 'wlan', 'wireless', 'oswp'], focus: ['wifi.', 'credential.'] },
  };

  function slug(s) { return String(s == null ? '' : s).trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, ''); }

  var ALIAS_TO_ID = {};
  Object.keys(PRESETS).forEach(function (pid) {
    ALIAS_TO_ID[pid] = pid;
    (PRESETS[pid].aliases || []).forEach(function (a) { ALIAS_TO_ID[a] = pid; ALIAS_TO_ID[slug(a)] = pid; });
  });
  var MACHINE_ALIAS = {};
  Object.keys(MACHINE_TYPES).forEach(function (mid) {
    MACHINE_ALIAS[mid] = mid;
    (MACHINE_TYPES[mid].aliases || []).forEach(function (a) { MACHINE_ALIAS[a] = mid; });
  });

  function normalizePlatform(v) { var k = slug(v); return ALIAS_TO_ID[k] || ALIAS_TO_ID[String(v || '').trim().toLowerCase()] || ''; }
  function normalizeMachineType(v) { return MACHINE_ALIAS[slug(v)] || ''; }
  function machineFocus(mt) { var m = MACHINE_TYPES[normalizeMachineType(mt)]; return m ? m.focus.slice() : []; }
  function isExamPlatform(p) { return !!EXAM_PLATFORMS[normalizePlatform(p)]; }
  function counterpartPlatform(p) {
    var pid = normalizePlatform(p) || DEFAULT_PLATFORM;
    if (EXAM_LAB_COUNTERPART[pid]) return EXAM_LAB_COUNTERPART[pid];
    return EXAM_PLATFORMS[pid] ? 'htb' : 'oscp';
  }
  function toggledPlatform(cur, wantExam) {
    var pid = normalizePlatform(cur) || DEFAULT_PLATFORM;
    return isExamPlatform(pid) === wantExam ? pid : counterpartPlatform(pid);
  }

  function cleanNames(names) {
    var seen = {}, out = [];
    (names || []).forEach(function (raw) { var n = String(raw || '').trim().toLowerCase(); if (n && !seen[n]) { seen[n] = 1; out.push(n); } });
    return out;
  }
  function cleanFormats(fs) { return (fs || []).map(function (f) { return String(f || '').trim().toLowerCase(); }).filter(function (f) { return FORMAT_PATTERNS[f]; }); }

  function listPresets() {
    return Object.keys(PRESETS).map(function (pid) {
      var p = PRESETS[pid];
      return { id: pid, name: p.name, flag_names: p.flag_names.slice(), flag_formats: p.flag_formats.slice(),
        exam: !!EXAM_PLATFORMS[pid], osid: !!OSID_PLATFORMS[pid], ad_set: !!((p.proof || {}).ad_set_points) };
    });
  }
  function listMachineTypes() { return Object.keys(MACHINE_TYPES).map(function (mid) { return { id: mid, name: MACHINE_TYPES[mid].name }; }); }

  function normalizeProfile(data) {
    data = data || {};
    var platform = normalizePlatform(data.platform) || DEFAULT_PLATFORM;
    var out = { platform: platform };
    var names = cleanNames(data.flag_names), formats = cleanFormats(data.flag_formats);
    if (names.length) out.flag_names = names;
    if (formats.length) out.flag_formats = formats;
    var mt = normalizeMachineType(data.machine_type);
    if (mt) out.machine_type = mt;
    ['candidate', 'osid'].forEach(function (k) { if (data[k] != null && data[k] !== '') out[k] = String(data[k]).trim(); });
    if (Array.isArray(data.ad_set)) out.ad_set = data.ad_set.map(function (h) { return String(h).trim(); }).filter(Boolean);
    if (Array.isArray(data.scope)) out.scope = data.scope.map(function (s) { return String(s).trim(); }).filter(Boolean);
    return out;
  }

  function resolveFlagConfig(profile) {
    var prof = normalizeProfile(profile);
    var preset = PRESETS[prof.platform] || PRESETS[DEFAULT_PLATFORM];
    var names = (prof.flag_names && prof.flag_names.length ? prof.flag_names : preset.flag_names) || DEFAULT_FLAG_NAMES;
    var formats = (prof.flag_formats && prof.flag_formats.length ? prof.flag_formats : preset.flag_formats) || DEFAULT_FORMATS;
    var slots = Object.assign({}, DEFAULT_SLOTS, preset.slots || {});
    return { platform: prof.platform, platform_name: preset.name, names: cleanNames(names), formats: cleanFormats(formats).length ? cleanFormats(formats) : DEFAULT_FORMATS.slice(), slots: slots };
  }

  function resolveProofConfig(profile) {
    var prof = normalizeProfile(profile);
    var preset = PRESETS[prof.platform] || PRESETS[DEFAULT_PLATFORM];
    var spec = Object.assign({}, DEFAULT_PROOF, preset.proof || {});
    var slots = (spec.required_slots || []).filter(function (s) { return ['local', 'root', 'flag'].indexOf(s) >= 0; });
    return {
      platform: prof.platform, platform_name: preset.name,
      required_slots: slots, required: !!slots.length,
      identity_linux: spec.identity_linux.slice(), identity_windows: spec.identity_windows.slice(),
      note: spec.note, points: Object.assign({}, spec.points),
      pass_threshold: parseInt(spec.pass_threshold || 0, 10), points_note: spec.points_note || '',
      ad_set: (prof.ad_set || []).slice(), ad_set_points: parseInt(prof.ad_set_points || spec.ad_set_points || 0, 10),
    };
  }

  function safeNames(names) {
    var s = cleanNames(names).filter(function (n) { return /^[a-z0-9._-]{1,64}$/.test(n); });
    return s.length ? s : DEFAULT_FLAG_NAMES.slice();
  }
  function linuxInameExpr(names) { return safeNames(names).map(function (n) { return '-iname ' + n; }).join(' -o '); }
  function windowsNameList(names) { return safeNames(names).join(','); }

  OBOL.profile = {
    PRESETS: PRESETS, DEFAULT_PLATFORM: DEFAULT_PLATFORM, MACHINE_TYPES: MACHINE_TYPES,
    FORMAT_PATTERNS: FORMAT_PATTERNS, DEFAULT_FLAG_NAMES: DEFAULT_FLAG_NAMES, DEFAULT_FORMATS: DEFAULT_FORMATS,
    normalizePlatform: normalizePlatform, normalizeMachineType: normalizeMachineType,
    machineFocus: machineFocus, isExamPlatform: isExamPlatform, counterpartPlatform: counterpartPlatform,
    toggledPlatform: toggledPlatform, listPresets: listPresets, listMachineTypes: listMachineTypes,
    normalizeProfile: normalizeProfile, resolveFlagConfig: resolveFlagConfig, resolveProofConfig: resolveProofConfig,
    linuxInameExpr: linuxInameExpr, windowsNameList: windowsNameList,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
