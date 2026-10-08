/*!
 * data/attack-move-map.js — fact-kind -> MITRE ATT&CK technique map. Powers two derivations in the
 * Frameworks view, so the ATT&CK matrix lights up from what you RAN and PROVED, not only from findings
 * that carry an explicit `attack` code:
 *   (1) the recorded-moves trail: each Run Log activity's produced fact kinds map to techniques;
 *   (2) finding gap-fill: a matched finding with no authored `attack` derives one from the fact that
 *       triggered it.
 * Conservative and standard (the fact that proves the step maps to the technique); omit where ambiguous.
 * Hand-authored; extend as parsers mint new kinds. ATT&CK (C) The MITRE Corporation.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  var BY_KIND = {
    // recon / discovery
    'host.up': 'T1046', 'ports.open': 'T1046', 'scan.nmap.quick': 'T1046', 'scan.nmap.version': 'T1046',
    'scan.masscan': 'T1046', 'snmp.community': 'T1046',
    'smb.null_session': 'T1135', 'smb.guest_session': 'T1135', 'smb.shares': 'T1135',
    'ad.user_list': 'T1087.002', 'ad.users': 'T1087.002', 'rid.users': 'T1087.002', 'ad.anonymous_bind': 'T1087.002',
    'web.source': 'T1592', 'web.dirs': 'T1595', 'web.vhosts': 'T1595',
    'host.processes': 'T1057', 'privesc.process_lead': 'T1057',
    // exploit / execution (public-facing app and injection classes)
    'web.sqli_confirmed': 'T1190', 'web.cmdi_confirmed': 'T1190', 'web.ssti_confirmed': 'T1190',
    'web.xxe_confirmed': 'T1190', 'web.nosqli_confirmed': 'T1190', 'web.deserial_confirmed': 'T1190',
    'web.lfi_confirmed': 'T1190', 'web.rce': 'T1190', 'web.authz_bypass': 'T1190', 'exploit.candidate': 'T1190',
    'access.shell': 'T1059', 'foothold.shell': 'T1059', 'web.shell': 'T1505.003',
    // credential access
    'hash.ntlm': 'T1003', 'credential.ntlm_hash': 'T1003', 'loot.sam': 'T1003',
    'loot.ntds': 'T1003.006', 'hash.krbtgt': 'T1003.006', 'ad.dcsync': 'T1003.006',
    'hash.asrep': 'T1558.004', 'hash.kerberoast': 'T1558.003', 'hash.tgs': 'T1558.003',
    'credential.weak_hash': 'T1110.002',
    'credential.plaintext': 'T1078', 'credential.available': 'T1078', 'credential.validated': 'T1078',
    'gpp.cpassword': 'T1552.006', 'loot.gpp': 'T1552.006', 'privesc.stored_credentials': 'T1552.001',
    'loot.ssh_key': 'T1552.004', 'loot.creds': 'T1552.001',
    // AD escalation
    'adcs.vulnerable': 'T1649', 'credential.certificate': 'T1649',
    'ad.control_paths': 'T1098', 'ad.attack_paths': 'T1098', 'ad.acl_lead': 'T1098', 'ad.gpo_control': 'T1098',
    'ad.zerologon': 'T1210', 'ad.coerced_auth': 'T1557.001',
    // privilege escalation
    'privesc.sudo_rights': 'T1548.003', 'privesc.sudo_binary': 'T1548.003',
    'privesc.suid_candidate': 'T1548.001', 'privesc.capability': 'T1548',
    'privesc.cron_writable': 'T1053.003',
    'privesc.kernel': 'T1068', 'privesc.patch_gap': 'T1068', 'privesc.service_bof_candidate': 'T1068',
    'privesc.nfs_no_root_squash': 'T1068',
    'privesc.dll_hijack_candidate': 'T1574.001', 'privesc.unquoted_service_path': 'T1574.009',
    'privesc.always_install_elevated': 'T1548.002',
    'privesc.docker_group': 'T1611', 'privesc.lxd_group': 'T1611',
    'privesc.windows_privilege': 'T1134.001',
    // lateral / relay
    'smb.signing_disabled': 'T1557.001', 'relay.target': 'T1557.001',
  };

  OBOL.ATTACK_MOVE = { byKind: BY_KIND };
  if (typeof module !== 'undefined' && module.exports) { module.exports = OBOL.ATTACK_MOVE; }
})(typeof globalThis !== 'undefined' ? globalThis : this);
