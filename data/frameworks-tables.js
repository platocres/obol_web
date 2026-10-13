/*!
 * data/frameworks-tables.js — small fixed framework reference tables for the Frameworks view.
 * Lockheed Martin Cyber Kill Chain, NIST CSF functions + 800-53 family names, CIS Controls v8,
 * PCI DSS v4 requirements, and the cross-maps obol uses (ATT&CK tactic -> kill-chain stage,
 * obol phase -> kill-chain stage, 800-53 family -> CSF function). Hand-authored, stable taxonomies.
 * Sources: lockheedmartin.com (Cyber Kill Chain), NIST CSF 2.0 + SP 800-53 Rev 5, CIS Controls v8,
 * PCI DSS v4.0. Titles paraphrased for display.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  // Lockheed Martin Cyber Kill Chain (7 stages, in order).
  var KILL_CHAIN = [
    { id: 'recon', name: 'Reconnaissance' },
    { id: 'weaponization', name: 'Weaponization' },
    { id: 'delivery', name: 'Delivery' },
    { id: 'exploitation', name: 'Exploitation' },
    { id: 'installation', name: 'Installation' },
    { id: 'c2', name: 'Command And Control' },
    { id: 'actions', name: 'Actions On Objectives' },
  ];

  // ATT&CK tactic (shortname) -> kill-chain stage. Enterprise tactics incl. v19 names.
  var ATTACK_TACTIC_TO_KC = {
    'reconnaissance': 'recon', 'resource-development': 'weaponization',
    'initial-access': 'delivery', 'execution': 'exploitation',
    'persistence': 'installation', 'privilege-escalation': 'exploitation',
    'defense-evasion': 'installation', 'stealth': 'installation', 'defense-impairment': 'installation',
    'credential-access': 'actions', 'discovery': 'actions', 'lateral-movement': 'actions',
    'collection': 'actions', 'command-and-control': 'c2', 'exfiltration': 'actions', 'impact': 'actions',
  };

  // obol engagement phase -> kill-chain stage (for the recorded-moves trail).
  var OBOL_PHASE_TO_KC = {
    recon: 'recon', enum: 'recon', creds: 'actions', access: 'delivery', escalate: 'exploitation', loot: 'actions',
  };

  // NIST CSF 2.0 functions.
  var NIST_CSF = [
    { id: 'GV', name: 'Govern' }, { id: 'ID', name: 'Identify' }, { id: 'PR', name: 'Protect' },
    { id: 'DE', name: 'Detect' }, { id: 'RS', name: 'Respond' }, { id: 'RC', name: 'Recover' },
  ];

  // NIST SP 800-53 Rev 5 control family prefix -> family name.
  var NIST_FAMILY = {
    AC: 'Access Control', AU: 'Audit and Accountability', AT: 'Awareness and Training',
    CM: 'Configuration Management', CP: 'Contingency Planning', IA: 'Identification and Authentication',
    IR: 'Incident Response', MA: 'Maintenance', MP: 'Media Protection', PS: 'Personnel Security',
    PE: 'Physical and Environmental Protection', PL: 'Planning', PM: 'Program Management',
    RA: 'Risk Assessment', CA: 'Assessment, Authorization, and Monitoring', SC: 'System and Communications Protection',
    SI: 'System and Information Integrity', SA: 'System and Services Acquisition', SR: 'Supply Chain Risk Management',
  };
  // 800-53 family -> primary CSF function (approximate, for the rollup).
  var NIST_FAMILY_TO_CSF = {
    AC: 'PR', IA: 'PR', SC: 'PR', CM: 'PR', MP: 'PR', PE: 'PR', AT: 'PR',
    SI: 'DE', AU: 'DE', CA: 'ID', RA: 'ID', PL: 'ID', SA: 'ID', PM: 'GV', PS: 'GV', SR: 'ID',
    IR: 'RS', MA: 'PR', CP: 'RC',
  };

  // CIS Critical Security Controls v8 (18 controls).
  var CIS_V8 = {
    '1': 'Inventory and Control of Enterprise Assets', '2': 'Inventory and Control of Software Assets',
    '3': 'Data Protection', '4': 'Secure Configuration of Enterprise Assets and Software',
    '5': 'Account Management', '6': 'Access Control Management', '7': 'Continuous Vulnerability Management',
    '8': 'Audit Log Management', '9': 'Email and Web Browser Protections', '10': 'Malware Defenses',
    '11': 'Data Recovery', '12': 'Network Infrastructure Management', '13': 'Network Monitoring and Defense',
    '14': 'Security Awareness and Skills Training', '15': 'Service Provider Management',
    '16': 'Application Software Security', '17': 'Incident Response Management', '18': 'Penetration Testing',
  };

  // PCI DSS v4.0 requirements (12).
  var PCI_V4 = {
    '1': 'Install and Maintain Network Security Controls', '2': 'Apply Secure Configurations',
    '3': 'Protect Stored Account Data', '4': 'Protect Cardholder Data With Strong Cryptography in Transit',
    '5': 'Protect All Systems and Networks From Malicious Software', '6': 'Develop and Maintain Secure Systems and Software',
    '7': 'Restrict Access by Business Need to Know', '8': 'Identify Users and Authenticate Access',
    '9': 'Restrict Physical Access to Cardholder Data', '10': 'Log and Monitor All Access',
    '11': 'Test Security of Systems and Networks Regularly', '12': 'Support Information Security With Policies',
  };

  // NIST SP 800-53 control -> CIS Controls v8 numbers and PCI DSS v4 requirement numbers (a pragmatic
  // crosswalk for the controls obol's findings actually use, so CIS/PCI fill in from an authored NIST
  // control without hand-editing every finding). Keyed by exact control, then by family as a fallback.
  var NIST_TO_CIS = {
    'AC-3': ['6'], 'AC-4': ['13'], 'AC-6': ['5', '6'], 'IA-2': ['6'], 'IA-5': ['5'],
    'CM-7': ['4'], 'CM-8': ['1', '2'], 'SC-7': ['12', '13'], 'SC-8': ['3'], 'SC-18': ['9'],
    'SC-23': ['3'], 'SC-30': ['10'], 'SI-2': ['7'], 'SI-7': ['3'], 'SI-10': ['16'], 'SI-16': ['10'],
    _family: { AC: ['6'], IA: ['5', '6'], SC: ['3'], CM: ['4'], SI: ['7'], AU: ['8'], RA: ['7'], CA: ['18'] },
  };
  var NIST_TO_PCI = {
    'AC-3': ['7'], 'AC-4': ['1'], 'AC-6': ['7'], 'IA-2': ['8'], 'IA-5': ['8'],
    'CM-7': ['2'], 'CM-8': ['2'], 'SC-7': ['1'], 'SC-8': ['4'], 'SC-18': ['5'],
    'SC-23': ['4'], 'SC-30': ['6'], 'SI-2': ['6'], 'SI-7': ['11'], 'SI-10': ['6'], 'SI-16': ['5'],
    _family: { AC: ['7'], IA: ['8'], SC: ['4'], CM: ['2'], SI: ['6'], AU: ['10'], RA: ['11'], CA: ['11'] },
  };

  OBOL.FRAMEWORK_TABLES = {
    KILL_CHAIN: KILL_CHAIN,
    NIST_TO_CIS: NIST_TO_CIS,
    NIST_TO_PCI: NIST_TO_PCI,
    ATTACK_TACTIC_TO_KC: ATTACK_TACTIC_TO_KC,
    OBOL_PHASE_TO_KC: OBOL_PHASE_TO_KC,
    NIST_CSF: NIST_CSF,
    NIST_FAMILY: NIST_FAMILY,
    NIST_FAMILY_TO_CSF: NIST_FAMILY_TO_CSF,
    CIS_V8: CIS_V8,
    PCI_V4: PCI_V4,
  };
  if (typeof module !== 'undefined' && module.exports) { module.exports = OBOL.FRAMEWORK_TABLES; }
})(typeof globalThis !== 'undefined' ? globalThis : this);
