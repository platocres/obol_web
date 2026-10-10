/*!
 * data/oscp-scope.js — OSCP exam scope for the Checklist "OSCP" view. The default checklist view ("All")
 * shows every command obol has inventoried; the "OSCP" view hides the moves below, which are out of the
 * PEN-200 exam's scope or banned in the exam. Everything NOT listed here stays visible, so the OSCP view
 * is the core exam methodology (recon, manual web exploitation, Linux/Windows privilege escalation, the
 * core AD attacks PEN-200 teaches: Kerberoasting, AS-REP, pass-the-hash/ticket, DCSync, ACL abuse,
 * delegation, silver/golden tickets, BloodHound) minus the enterprise/advanced and exam-illegal pieces.
 *
 * This is a deterministic, hand-authored list, easy to edit: add or remove an id to change the OSCP view.
 * OSCP (PEN-200) is Offensive Security's; obol is a study aid, not affiliated.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  // move id -> short reason it is hidden in the OSCP view.
  var EXCLUDE = {
    // Cloud: outside the PEN-200 exam environment.
    'aws-credential-abuse': 'cloud, out of OSCP scope',
    'azure-imds': 'cloud, out of OSCP scope',
    'gcp-metadata': 'cloud, out of OSCP scope',
    // Banned in the exam.
    'sqlmap-automation': 'sqlmap is banned in the OSCP exam',
    // ADCS / certificate attacks: not taught in PEN-200.
    'adcs-esc': 'ADCS abuse, beyond PEN-200',
    'certifried': 'ADCS CVE, beyond PEN-200',
    'cert-authenticate': 'certificate (PKINIT) auth, tied to ADCS',
    'shadow-credentials': 'msDS-KeyCredentialLink abuse, beyond PEN-200',
    // SCCM / WSUS / gMSA: enterprise, not in PEN-200.
    'sccm-enum': 'SCCM, enterprise, beyond PEN-200',
    'sccm-exploit': 'SCCM, enterprise, beyond PEN-200',
    'wsus-abuse': 'WSUS, enterprise, beyond PEN-200',
    'gmsa-read': 'gMSA, beyond PEN-200',
    // Coercion / IPv6 takeover: beyond PEN-200 core.
    'coerce-auth': 'authentication coercion, beyond PEN-200',
    'kerberos-relay': 'Kerberos relay, beyond PEN-200',
    'mitm6-ipv6-takeover': 'IPv6/DNS takeover, beyond PEN-200',
    // Cross-forest / trusts / niche roasting: beyond the single-domain OSCP set.
    'trust-enum': 'forest trusts, beyond PEN-200',
    'sid-history-abuse': 'cross-forest SID history, beyond PEN-200',
    'adidns-abuse': 'ADIDNS abuse, beyond PEN-200',
    'timeroasting': 'timeroasting, beyond PEN-200',
    'diamond-ticket': 'diamond ticket, beyond PEN-200',
    // Environment-specific AD CVEs (not core methodology).
    'zerologon-check': 'Zerologon CVE, environment-specific',
    'zerologon-exploit': 'Zerologon CVE, environment-specific',
    'nopac': 'noPac CVE, environment-specific',
    'ms14-068': 'MS14-068 CVE, environment-specific',
    // Advanced web classes rarely on OSCP.
    'http-request-smuggling': 'request smuggling, advanced web',
    'prototype-pollution': 'prototype pollution, advanced web',
    'mass-assignment': 'mass assignment, advanced web',
    'graphql-abuse': 'GraphQL abuse, advanced web',
    'java-rmi': 'Java RMI deserialization, advanced',
    // Enterprise app CVE RCEs unlikely on OSCP.
    'aerospike-udf': 'enterprise app CVE, unlikely on OSCP',
    'freeswitch-esl': 'enterprise app CVE, unlikely on OSCP',
    'ofbiz-deser': 'enterprise app CVE, unlikely on OSCP',
    'splunk-app-rce': 'enterprise app CVE, unlikely on OSCP',
    'zabbix-script-rce': 'enterprise app CVE, unlikely on OSCP',
    'wifi-mouse-rce': 'niche app CVE, unlikely on OSCP',
    'cacti-cmdinjection': 'enterprise app CVE, unlikely on OSCP',
    'text4shell': 'Text4Shell CVE, unlikely on OSCP',
    'check-log4shell': 'Log4Shell CVE, unlikely on OSCP',
    'check-struts2': 'Struts2 CVE, unlikely on OSCP',
  };

  OBOL.OSCP_SCOPE = { exclude: EXCLUDE, inScope: function (id) { return !EXCLUDE[id]; } };
  if (typeof module !== 'undefined' && module.exports) { module.exports = OBOL.OSCP_SCOPE; }
})(typeof globalThis !== 'undefined' ? globalThis : this);
