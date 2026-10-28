/*!
 * data/frameworks-tables.js - fixed framework reference tables & crosswalks for the Frameworks view.
 * Lockheed Martin Cyber Kill Chain, NIST CSF 2.0 functions + SP 800-53 Rev 5 control details,
 * CIS Controls v8, PCI DSS v4.0 requirements, MITRE CWE catalog, OWASP Top 10 (2021), and crosswalks
 * (ATT&CK -> NIST/CWE, NIST -> CIS/PCI, CWE -> OWASP). Hand-authored, stable taxonomies.
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

  // OBOL engagement phase -> kill-chain stage (for the recorded-moves trail).
  var OBOL_PHASE_TO_KC = {
    recon: 'recon', enum: 'recon', creds: 'actions', access: 'delivery', escalate: 'exploitation', loot: 'actions',
  };

  // NIST CSF 2.0 functions.
  var NIST_CSF = [
    { id: 'GV', name: 'Govern', summary: 'Organizational cybersecurity strategy, policy, roles, and risk oversight.' },
    { id: 'ID', name: 'Identify', summary: 'Asset inventory, attack-surface visibility, and vulnerability risk assessment.' },
    { id: 'PR', name: 'Protect', summary: 'Identity, access control, least privilege, configuration hardening, and data security.' },
    { id: 'DE', name: 'Detect', summary: 'Continuous security monitoring, anomaly correlation, and integrity verification.' },
    { id: 'RS', name: 'Respond', summary: 'Incident containment, credential rotation, and forensic triage.' },
    { id: 'RC', name: 'Recover', summary: 'Resilient backups, service restoration, and post-incident validation.' },
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

  // 800-53 family -> primary CSF function (for the rollup).
  var NIST_FAMILY_TO_CSF = {
    AC: 'PR', IA: 'PR', SC: 'PR', CM: 'PR', MP: 'PR', PE: 'PR', AT: 'PR',
    SI: 'DE', AU: 'DE', CA: 'ID', RA: 'ID', PL: 'ID', SA: 'ID', PM: 'GV', PS: 'GV', SR: 'ID',
    IR: 'RS', MA: 'PR', CP: 'RC',
  };

  function nistUrl(code) {
    return 'https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=' + encodeURIComponent(code);
  }

  // Specific NIST SP 800-53 Rev 5 control names + plain-English blue-team requirement summaries.
  var NIST_CONTROLS = {
    'AC-2': { name: 'Account Management', summary: 'Provision, review, disable, and remove local, domain, and service accounts according to least-privilege lifecycle rules.' },
    'AC-3': { name: 'Access Enforcement', summary: 'Enforce approved server-side authorization checks on every object, share, API endpoint, and directory operation.' },
    'AC-4': { name: 'Information Flow Enforcement', summary: 'Control data and protocol flows across security domains and VLANs using segmentation and egress/ingress filtering.' },
    'AC-6': { name: 'Least Privilege', summary: 'Grant users, services, binaries, and AD principals only the minimum privileges and ACL rights needed to operate.' },
    'AC-7': { name: 'Unsuccessful Logon Attempts', summary: 'Enforce progressive account lockout or rate-limiting thresholds against online password guessing and spraying.' },
    'AC-17': { name: 'Remote Access', summary: 'Authorize, encrypt, and restrict remote administration channels (RDP, SSH, WinRM, VPN) through MFA and jump hosts.' },
    'AU-2': { name: 'Event Logging', summary: 'Capture authentication, privilege escalation, process creation, and directory-change events across endpoints and servers.' },
    'AU-6': { name: 'Audit Record Review, Analysis, and Reporting', summary: 'Correlate security telemetry centrally in a SIEM to surface lateral movement, credential theft, and privilege abuse.' },
    'AU-12': { name: 'Audit Record Generation', summary: 'Generate detailed command-line, script-block, and object-access audit records tamper-protected off-host.' },
    'CA-8': { name: 'Penetration Testing', summary: 'Validate defensive controls and attack-path exposure through adversary-emulation exercises and remediate root causes.' },
    'CM-6': { name: 'Configuration Settings', summary: 'Apply hardened security baselines (CIS/DISA STIG) and remove insecure defaults before deploying systems.' },
    'CM-7': { name: 'Least Functionality', summary: 'Disable unused network ports, legacy protocols (SMBv1/LLMNR/NTLMv1), anonymous binds, debug consoles, and unneeded utilities.' },
    'CM-8': { name: 'System Component Inventory', summary: 'Maintain an accurate inventory of hosts, exposed services, frameworks, and software versions mapped to patch ownership.' },
    'IA-2': { name: 'Identification and Authentication (Organizational Users)', summary: 'Uniquely identify and strongly authenticate users (including phishing-resistant MFA) before granting system or network access.' },
    'IA-3': { name: 'Device Identification and Authentication', summary: 'Authenticate devices and enforce mutual channel binding / signing before establishing trusted network sessions.' },
    'IA-5': { name: 'Authenticator Management', summary: 'Protect passwords, hashes, tickets, keys, and certificates using strong passphrases/gMSA, modern KDFs, vault storage, and rotation.' },
    'RA-5': { name: 'Vulnerability Monitoring and Scanning', summary: 'Continuously scan infrastructure, web applications, and Active Directory attack paths and remediate verified exposures.' },
    'SA-11': { name: 'Developer Testing and Evaluation', summary: 'Perform SAST/DAST, code review, and security testing in CI/CD to eliminate injection, memory, and logic flaws pre-release.' },
    'SC-7': { name: 'Boundary Protection', summary: 'Monitor and restrict communications at external perimeters and internal network sub-boundaries (DMZ, workstation, Tier-0).' },
    'SC-8': { name: 'Transmission Confidentiality and Integrity', summary: 'Protect network traffic against eavesdropping, poisoning, and relay using TLS 1.2+, SMB signing, and LDAP signing + EPA.' },
    'SC-18': { name: 'Mobile Code', summary: 'Restrict untrusted client-side scripts, macros, and active web content from executing in user or browser contexts.' },
    'SC-23': { name: 'Session Authenticity', summary: 'Protect session tokens, cookies, and tickets against hijacking, fixation, and replay across authenticated channels.' },
    'SC-28': { name: 'Protection of Information at Rest', summary: 'Encrypt and ACL-protect stored credentials, backups, databases, and configuration secrets at rest.' },
    'SC-30': { name: 'Concealment and Misdirection', summary: 'Suppress unnecessary version/stack disclosure and reduce predictable metadata exposed to unauthenticated callers.' },
    'SI-2': { name: 'Flaw Remediation', summary: 'Identify, test, and install security patches for OS kernels, services, Domain Controllers, and third-party libraries promptly.' },
    'SI-4': { name: 'System Monitoring', summary: 'Monitor endpoints, web roots, and network traffic for unauthorized processes, web shells, reconnaissance bursts, and C2.' },
    'SI-7': { name: 'Software, Firmware, and Information Integrity', summary: 'Verify code signatures and file integrity on binaries, DLLs, service paths, and configuration artifacts.' },
    'SI-10': { name: 'Information Input Validation', summary: 'Validate, type-check, and parameterize all untrusted inputs to prevent SQLi, command injection, XXE, SSRF, LFI, and XSS.' },
    'SI-16': { name: 'Memory Protection', summary: 'Enforce hardware/OS memory protections (DEP/NX, ASLR, CFG, stack canaries) against buffer and heap exploitation.' },
  };

  // CIS Critical Security Controls v8 (18 controls) + summaries.
  var CIS_V8 = {
    '1': 'Inventory and Control of Enterprise Assets',
    '2': 'Inventory and Control of Software Assets',
    '3': 'Data Protection',
    '4': 'Secure Configuration of Enterprise Assets and Software',
    '5': 'Account Management',
    '6': 'Access Control Management',
    '7': 'Continuous Vulnerability Management',
    '8': 'Audit Log Management',
    '9': 'Email and Web Browser Protections',
    '10': 'Malware Defenses',
    '11': 'Data Recovery',
    '12': 'Network Infrastructure Management',
    '13': 'Network Monitoring and Defense',
    '14': 'Security Awareness and Skills Training',
    '15': 'Service Provider Management',
    '16': 'Application Software Security',
    '17': 'Incident Response Management',
    '18': 'Penetration Testing',
  };

  var CIS_DETAILS = {
    '1': 'Actively track all network-connected endpoints, servers, and Domain Controllers so rogue or unmanaged hosts cannot linger.',
    '2': 'Inventory installed packages/frameworks, remove unsupported legacy software, and enforce executable allowlisting.',
    '3': 'Classify, encrypt, and ACL-protect sensitive files, shares, repositories, and credential stores in transit and at rest.',
    '4': 'Establish hardened OS/service baselines: disable SMBv1, LLMNR, NBT-NS, anonymous binds, default accounts, and unquoted paths.',
    '5': 'Harden local, domain, and service accounts: eliminate shared/default creds, use gMSA + LAPS, and enforce strong passphrases.',
    '6': 'Enforce least-privilege RBAC, AD Tiering, phishing-resistant MFA, and clean AD/file/service ACLs.',
    '7': 'Run continuous authenticated vulnerability scans and prioritize patching CISA KEV and externally reachable CVEs.',
    '8': 'Collect and centralize command-line, PowerShell, Kerberos, directory, and authentication audit logs off-host.',
    '9': 'Harden browsers and email gateways against macro payloads, malicious archives, and unsafe content.',
    '10': 'Deploy real-time EDR/AV behavioral blocking, AMSI inspection, and credential-theft ASR protections.',
    '11': 'Maintain offline/immutable backups isolated from domain admin credentials.',
    '12': 'Harden network devices, segment Tier-0/DMZ/workstation zones, and restrict management plane protocols.',
    '13': 'Monitor East-West and egress network traffic for port scans, NTLM relays, DCSync, Kerberoasting, and C2 beacons.',
    '14': 'Train staff and engineers on credential hygiene, phishing resistance, and secret-free development workflows.',
    '15': 'Scope and audit third-party vendor and cloud integrations.',
    '16': 'Build secure software using parameterized queries, strict server-side authz, input validation, and dependency patching.',
    '17': 'Maintain playbooks for rapid credential rotation (krbtgt, service accounts, keys) and host isolation.',
    '18': 'Test defenses regularly through adversary emulation and verify remediation effectiveness.',
  };

  // PCI DSS v4.0 requirements (12) + summaries.
  var PCI_V4 = {
    '1': 'Install and Maintain Network Security Controls',
    '2': 'Apply Secure Configurations',
    '3': 'Protect Stored Account Data',
    '4': 'Protect Cardholder Data With Strong Cryptography in Transit',
    '5': 'Protect All Systems and Networks From Malicious Software',
    '6': 'Develop and Maintain Secure Systems and Software',
    '7': 'Restrict Access by Business Need to Know',
    '8': 'Identify Users and Authenticate Access',
    '9': 'Restrict Physical Access to Cardholder Data',
    '10': 'Log and Monitor All Access',
    '11': 'Test Security of Systems and Networks Regularly',
    '12': 'Support Information Security With Policies',
  };

  var PCI_DETAILS = {
    '1': 'Enforce stateful firewall and micro-segmentation rules restricting inbound/outbound and lateral traffic between zones.',
    '2': 'Remove vendor defaults, disable unnecessary services/protocols (anonymous FTP/SMB/LDAP, LLMNR), and harden system configs.',
    '3': 'Eliminate cleartext storage of sensitive account data, keys, and secrets on disks, shares, and repositories.',
    '4': 'Enforce strong cryptography (TLS 1.2+, signed SMB/LDAP, SSH) across all network transmissions; ban cleartext auth.',
    '5': 'Deploy anti-malware/EDR behavioral controls and protect endpoints against unauthorized payload execution.',
    '6': 'Eliminate injection, broken access control, path traversal, and deserialization flaws and apply security patches promptly.',
    '7': 'Enforce least-privilege role-based access control across OS services, shares, databases, and Active Directory ACLs.',
    '8': 'Assign unique IDs, enforce strong passphrases/lockout policies, eliminate cleartext/GPP passwords, and require MFA.',
    '9': 'Restrict physical access to infrastructure and media.',
    '10': 'Log and centrally monitor all administrative actions, authentication events, and access to critical assets.',
    '11': 'Perform regular vulnerability scans, file-integrity monitoring, IDS/IPS monitoring, and internal/external penetration tests.',
    '12': 'Maintain formal security policies, asset inventories, and incident response readiness.',
  };

  // NIST SP 800-53 control -> CIS Controls v8 numbers and PCI DSS v4 requirement numbers.
  var NIST_TO_CIS = {
    'AC-2': ['5', '6'], 'AC-3': ['6'], 'AC-4': ['12', '13'], 'AC-6': ['5', '6'], 'AC-7': ['5', '6'], 'AC-17': ['6', '12'],
    'AU-2': ['8'], 'AU-6': ['8', '13'], 'AU-12': ['8'], 'CA-8': ['18'],
    'CM-6': ['4'], 'CM-7': ['4'], 'CM-8': ['1', '2'],
    'IA-2': ['6'], 'IA-3': ['1', '12'], 'IA-5': ['5'],
    'RA-5': ['7'], 'SA-11': ['16'],
    'SC-7': ['12', '13'], 'SC-8': ['3', '12'], 'SC-18': ['9'], 'SC-23': ['16'], 'SC-28': ['3'], 'SC-30': ['4'],
    'SI-2': ['7'], 'SI-4': ['8', '13'], 'SI-7': ['2', '3'], 'SI-10': ['16'], 'SI-16': ['10', '16'],
    _family: { AC: ['6'], IA: ['5', '6'], SC: ['3'], CM: ['4'], SI: ['7'], AU: ['8'], RA: ['7'], CA: ['18'], SA: ['16'] },
  };

  var NIST_TO_PCI = {
    'AC-2': ['7', '8'], 'AC-3': ['7'], 'AC-4': ['1'], 'AC-6': ['7'], 'AC-7': ['8'], 'AC-17': ['1', '8'],
    'AU-2': ['10'], 'AU-6': ['10'], 'AU-12': ['10'], 'CA-8': ['11'],
    'CM-6': ['2'], 'CM-7': ['2'], 'CM-8': ['2', '12'],
    'IA-2': ['8'], 'IA-3': ['2', '8'], 'IA-5': ['8'],
    'RA-5': ['6', '11'], 'SA-11': ['6'],
    'SC-7': ['1'], 'SC-8': ['4'], 'SC-18': ['5', '6'], 'SC-23': ['6', '8'], 'SC-28': ['3'], 'SC-30': ['2'],
    'SI-2': ['6'], 'SI-4': ['10', '11'], 'SI-7': ['11'], 'SI-10': ['6'], 'SI-16': ['6'],
    _family: { AC: ['7'], IA: ['8'], SC: ['4'], CM: ['2'], SI: ['6'], AU: ['10'], RA: ['11'], CA: ['11'], SA: ['6'] },
  };

  // MITRE CWE catalog: exact names + plain-English weakness summaries for all OBOL-referenced CWEs.
  var CWE_CATALOG = {
    'CWE-20': { name: 'Improper Input Validation', summary: 'Application processes untrusted input without validating syntax, bounds, or expected type.' },
    'CWE-22': { name: 'Path Traversal (Improper Limitation of a Pathname)', summary: 'User-controlled relative path sequences (../) escape the intended directory to read or write arbitrary files.' },
    'CWE-73': { name: 'External Control of File Name or Path', summary: 'External input dictates filesystem paths used in read, write, or include operations.' },
    'CWE-78': { name: 'OS Command Injection', summary: 'Untrusted input is concatenated into a shell or OS command executed by the host.' },
    'CWE-79': { name: 'Cross-site Scripting (XSS)', summary: 'Unencoded input is rendered into HTML/DOM responses, executing attacker JavaScript in victim sessions.' },
    'CWE-89': { name: 'SQL Injection', summary: 'Untrusted input alters SQL query structure due to string concatenation instead of parameterized statements.' },
    'CWE-94': { name: 'Improper Control of Generation of Code (Code Injection)', summary: 'User input is evaluated directly by a dynamic language interpreter (eval, assert, script engine).' },
    'CWE-98': { name: 'PHP Remote/Local File Inclusion', summary: 'Untrusted filename passed to include/require executes attacker-controlled script code.' },
    'CWE-120': { name: 'Classic Buffer Overflow', summary: 'Buffer copy occurs without verifying input size, allowing memory corruption and control-flow hijack.' },
    'CWE-121': { name: 'Stack-based Buffer Overflow', summary: 'Writing past a stack buffer overwrites return addresses or local control data.' },
    'CWE-200': { name: 'Exposure of Sensitive Information to an Unauthorized Actor', summary: 'System leaks internal configuration, user lists, stack traces, or environment details to unauthorized callers.' },
    'CWE-214': { name: 'Invocation of Process Using Visible Sensitive Information', summary: 'Secrets or passwords are exposed in CLI arguments or environment variables visible to local users.' },
    'CWE-250': { name: 'Execution with Unnecessary Privileges', summary: 'Process, SUID binary, sudo rule, or container operates with root/SYSTEM privileges it does not need.' },
    'CWE-266': { name: 'Incorrect Privilege Assignment', summary: 'Dangerous permissions (DCSync, WriteDacl, AD CS enrollment, admin group membership) are granted to untrusted principals.' },
    'CWE-269': { name: 'Improper Privilege Management', summary: 'Privilege boundaries (SeImpersonate, service tokens, kernel transitions) are mishandled, enabling privilege escalation.' },
    'CWE-284': { name: 'Improper Access Control', summary: 'System fails to restrict access to protected resources or administrative actions.' },
    'CWE-287': { name: 'Improper Authentication', summary: 'Actor claims an identity without sufficient cryptographic verification of that identity.' },
    'CWE-290': { name: 'Authentication Bypass by Spoofing', summary: 'Name-resolution or source spoofing (LLMNR/NBT-NS/DNS/IP) tricks peers into authenticating to an adversary.' },
    'CWE-294': { name: 'Authentication Bypass by Capture-replay', summary: 'Captured hashes, NTLM challenges, or tickets can be relayed or replayed to authenticate elsewhere.' },
    'CWE-295': { name: 'Improper Certificate Validation', summary: 'TLS or PKI certificates are accepted without verifying chain of trust, hostname, or revocation.' },
    'CWE-300': { name: 'Channel Accessible by Non-Endpoint (Adversary-in-the-Middle)', summary: 'Lack of mutual signing/channel binding lets an on-path responder intercept or relay communications.' },
    'CWE-306': { name: 'Missing Authentication for Critical Function', summary: 'Sensitive service (anonymous SMB/LDAP/FTP, Redis, Jenkins, management API) allows unauthenticated access.' },
    'CWE-307': { name: 'Improper Restriction of Excessive Authentication Attempts', summary: 'Absence of rate limiting, lockout, or MFA permits brute-force guessing and password spraying.' },
    'CWE-312': { name: 'Cleartext Storage of Sensitive Information', summary: 'Passwords, keys, or tokens are stored unencrypted in files, databases, registries, or version history.' },
    'CWE-319': { name: 'Cleartext Transmission of Sensitive Information', summary: 'Credentials or session traffic cross the network unencrypted (HTTP, FTP, Telnet, unsigned LDAP/SMB).' },
    'CWE-326': { name: 'Inadequate Encryption Strength', summary: 'Weak or deprecated ciphers (RC4 Kerberos, DES, NTLMv1, short RSA keys, static GPP AES key) protect sensitive data.' },
    'CWE-327': { name: 'Use of a Broken or Risky Cryptographic Algorithm', summary: 'Protocol relies on broken cryptography that can be downgraded, forged, or cracked offline.' },
    'CWE-330': { name: 'Use of Insufficiently Random Values', summary: 'Predictable IVs, nonces, or tokens (such as Zerologon all-zero AES-CFB8 IV flaw) undermine cryptographic security.' },
    'CWE-347': { name: 'Improper Verification of Cryptographic Signature', summary: 'JWTs, updates, or tickets are accepted with missing, forged, or alg:none signatures.' },
    'CWE-350': { name: 'Reliance on Reverse DNS Resolution for a Security-Critical Action', summary: 'Access decisions trust spoofable PTR/hostname lookups.' },
    'CWE-352': { name: 'Cross-Site Request Forgery (CSRF)', summary: 'State-changing web requests lack anti-CSRF tokens or SameSite protections.' },
    'CWE-400': { name: 'Uncontrolled Resource Consumption', summary: 'Service lacks bounds on request rates, query complexity, or payload size.' },
    'CWE-427': { name: 'Uncontrolled Search Path Element', summary: 'Process resolves DLLs or binaries from user-writable PATH or working directories.' },
    'CWE-428': { name: 'Unquoted Search Path or Element', summary: 'Windows service ImagePath with spaces lacks quotes, allowing binary planting in parent path segments.' },
    'CWE-434': { name: 'Unrestricted Upload of File with Dangerous Type', summary: 'Application accepts executable scripts (.php, .aspx, .jsp, .war) into web-accessible storage.' },
    'CWE-477': { name: 'Use of Obsolete Function', summary: 'Software relies on deprecated, insecure APIs or legacy protocol features.' },
    'CWE-502': { name: 'Deserialization of Untrusted Data', summary: 'Deserializing untrusted objects triggers gadget chains resulting in remote code execution.' },
    'CWE-506': { name: 'Embedded Malicious Code', summary: 'Backdoored upstream package or unauthorized persistence implant resides inside deployed software.' },
    'CWE-521': { name: 'Weak Password Requirements', summary: 'Password policy allows short, dictionary, or default passwords trivial to crack or spray.' },
    'CWE-522': { name: 'Insufficiently Protected Credentials', summary: 'Credentials (GPP cpassword, roastable RC4 SPN hashes, AS-REP hashes, config secrets) are stored or transmitted in crackable/recoverable form.' },
    'CWE-538': { name: 'Insertion of Sensitive Information into Externally-Accessible File or Directory', summary: 'VCS folders (.git/.svn), backups, or .env files are served directly from public web directories.' },
    'CWE-601': { name: 'URL Redirection to Untrusted Site (Open Redirect)', summary: 'Unvalidated redirect parameter forwards users or OAuth tokens to attacker-controlled domains.' },
    'CWE-611': { name: 'Improper Restriction of XML External Entity Reference (XXE)', summary: 'XML parser resolves external DTD/SYSTEM entities, enabling local file disclosure and SSRF.' },
    'CWE-614': { name: 'Sensitive Cookie in HTTPS Session Without Secure Attribute', summary: 'Session cookies omit Secure/HttpOnly flags, exposing them over cleartext or DOM script access.' },
    'CWE-639': { name: 'Authorization Bypass Through User-Controlled Key (IDOR)', summary: 'Application trusts user-supplied object IDs without verifying ownership or tenant authorization.' },
    'CWE-650': { name: 'Trusting HTTP Permission Methods on the Server Side', summary: 'Access controls apply only to GET/POST while leaving HEAD, PUT, or custom HTTP verbs unrestricted.' },
    'CWE-668': { name: 'Exposure of Resource to Wrong Sphere', summary: 'Internal services, shares, or management interfaces are exposed beyond their intended trust boundary.' },
    'CWE-693': { name: 'Protection Mechanism Failure', summary: 'Security header, sandbox, or defensive boundary is missing, misconfigured, or bypassable.' },
    'CWE-732': { name: 'Incorrect Permission Assignment for Critical Resource', summary: 'Service binaries, cron scripts, shadow files, SSH keys, or shares carry overly permissive read/write ACLs.' },
    'CWE-787': { name: 'Out-of-bounds Write', summary: 'Software writes data past the end or before the start of an allocated memory buffer.' },
    'CWE-798': { name: 'Use of Hard-coded Credentials', summary: 'Static passwords, SNMP communities, or API keys are baked directly into scripts, configs, or binaries.' },
    'CWE-916': { name: 'Use of Password Hash With Insufficient Computational Effort', summary: 'Fast unsalted or weak hashes (NTLM/MD5/SHA1/RC4) allow high-speed offline GPU cracking.' },
    'CWE-918': { name: 'Server-Side Request Forgery (SSRF)', summary: 'Server fetches attacker-controlled URLs, reaching internal localhost services or cloud metadata endpoints.' },
    'CWE-942': { name: 'Permissive Cross-domain Policy with Untrusted Domains (CORS)', summary: 'Wildcard or reflected Access-Control-Allow-Origin with credentials exposes authenticated responses cross-origin.' },
    'CWE-943': { name: 'Improper Neutralization of Special Elements in Data Query Logic', summary: 'Untrusted operators ($ne, $gt, LDAP filters) manipulate NoSQL or directory query logic.' },
    'CWE-1021': { name: 'Improper Restriction of Rendered UI Layers (Clickjacking)', summary: 'Missing X-Frame-Options / frame-ancestors CSP allows framing sensitive UI actions.' },
    'CWE-1104': { name: 'Use of Unmaintained Third Party Components', summary: 'Deployment runs end-of-life OS or application versions no longer receiving security patches.' },
    'CWE-1321': { name: 'Improperly Controlled Modification of Object Prototype Attributes (Prototype Pollution)', summary: 'Untrusted properties merge into JavaScript Object.prototype, altering application logic or templates.' },
    'CWE-1333': { name: 'Inefficient Regular Expression Complexity (ReDoS)', summary: 'Catastrophic backtracking in regex evaluation exhausts CPU on crafted input.' },
    'CWE-1336': { name: 'Server-Side Template Injection (SSTI)', summary: 'User input is interpolated directly into a server template string and executed by the template engine.' },
    'CWE-1395': { name: 'Dependency on Vulnerable Third-Party Component', summary: 'Application ships third-party plugins, libraries, or services with known exploitable CVEs.' },
  };

  function cweUrl(code) {
    var m = /^CWE-(\d+)$/i.exec(String(code || '').trim());
    return m ? ('https://cwe.mitre.org/data/definitions/' + m[1] + '.html') : 'https://cwe.mitre.org/';
  }

  // OWASP Top 10 (2021) details + official URLs.
  var OWASP_TOP10 = {
    'A01': { name: 'Broken Access Control', url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/', summary: 'Missing or bypassable authorization checks (IDOR, path traversal, anonymous/unrestricted admin endpoints, CORS).' },
    'A02': { name: 'Cryptographic Failures', url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/', summary: 'Cleartext transmission/storage, static or weak encryption keys (GPP AES, RC4, NTLMv1), and TLS weaknesses.' },
    'A03': { name: 'Injection', url: 'https://owasp.org/Top10/A03_2021-Injection/', summary: 'Untrusted input interpreted as SQL, OS commands, LDAP/NoSQL filters, XSS scripts, or server-side templates.' },
    'A04': { name: 'Insecure Design', url: 'https://owasp.org/Top10/A04_2021-Insecure_Design/', summary: 'Architectural flaws lacking trust boundaries, rate limits, or abuse-case defenses.' },
    'A05': { name: 'Security Misconfiguration', url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/', summary: 'Insecure default configs, exposed .git/backups/shares, XXE enabled, verbose headers, or unnecessary features enabled.' },
    'A06': { name: 'Vulnerable and Outdated Components', url: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/', summary: 'Unpatched OS services, CMS plugins, or libraries with known public CVEs.' },
    'A07': { name: 'Identification and Authentication Failures', url: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/', summary: 'Weak/crackable passwords, missing MFA/lockout, roastable accounts, credential reuse, or weak session cookies.' },
    'A08': { name: 'Software and Data Integrity Failures', url: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/', summary: 'Unsafe deserialization, unsigned updates/DLLs, or writable CI/CD and deployment pipelines.' },
    'A09': { name: 'Security Logging and Monitoring Failures', url: 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/', summary: 'Missing audit telemetry or alerting for authentication failures, privilege changes, and lateral movement.' },
    'A10': { name: 'Server-Side Request Forgery (SSRF)', url: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/', summary: 'Server fetches unvalidated user-supplied URLs targeting internal services or cloud metadata.' },
  };

  // ATT&CK technique (exact or parent) -> primary { nist, cwe } fallback for activity-derived findings
  // that lack an explicit reportmeta/catalog compliance mapping.
  var TECHNIQUE_TO_COMPLIANCE = {
    'T1003': { nist: 'IA-5', cwe: 'CWE-522' },
    'T1003.001': { nist: 'SC-28', cwe: 'CWE-522' },
    'T1003.002': { nist: 'SC-28', cwe: 'CWE-522' },
    'T1003.003': { nist: 'AC-6', cwe: 'CWE-522' },
    'T1003.006': { nist: 'AC-6', cwe: 'CWE-266' },
    'T1003.008': { nist: 'AC-6', cwe: 'CWE-732' },
    'T1021': { nist: 'AC-17', cwe: 'CWE-284' },
    'T1039': { nist: 'AC-3', cwe: 'CWE-732' },
    'T1046': { nist: 'CM-7', cwe: 'CWE-200' },
    'T1053': { nist: 'AC-6', cwe: 'CWE-732' },
    'T1059': { nist: 'CM-7', cwe: 'CWE-78' },
    'T1068': { nist: 'SI-2', cwe: 'CWE-269' },
    'T1072': { nist: 'CM-6', cwe: 'CWE-269' },
    'T1078': { nist: 'IA-2', cwe: 'CWE-522' },
    'T1078.001': { nist: 'IA-5', cwe: 'CWE-798' },
    'T1087': { nist: 'AC-3', cwe: 'CWE-200' },
    'T1090': { nist: 'SC-7', cwe: 'CWE-668' },
    'T1098': { nist: 'AC-6', cwe: 'CWE-266' },
    'T1110': { nist: 'IA-5', cwe: 'CWE-307' },
    'T1110.002': { nist: 'IA-5', cwe: 'CWE-916' },
    'T1110.003': { nist: 'AC-7', cwe: 'CWE-307' },
    'T1134': { nist: 'AC-6', cwe: 'CWE-269' },
    'T1135': { nist: 'AC-3', cwe: 'CWE-306' },
    'T1136': { nist: 'AC-2', cwe: 'CWE-266' },
    'T1190': { nist: 'SI-10', cwe: 'CWE-20' },
    'T1210': { nist: 'SI-2', cwe: 'CWE-1395' },
    'T1213': { nist: 'AC-3', cwe: 'CWE-538' },
    'T1482': { nist: 'AC-4', cwe: 'CWE-668' },
    'T1484': { nist: 'AC-6', cwe: 'CWE-266' },
    'T1505': { nist: 'CM-7', cwe: 'CWE-434' },
    'T1505.001': { nist: 'CM-7', cwe: 'CWE-250' },
    'T1505.003': { nist: 'SI-10', cwe: 'CWE-434' },
    'T1543': { nist: 'AC-6', cwe: 'CWE-732' },
    'T1548': { nist: 'AC-6', cwe: 'CWE-250' },
    'T1550': { nist: 'IA-2', cwe: 'CWE-294' },
    'T1550.002': { nist: 'IA-5', cwe: 'CWE-294' },
    'T1550.003': { nist: 'IA-2', cwe: 'CWE-294' },
    'T1552': { nist: 'SC-28', cwe: 'CWE-522' },
    'T1552.001': { nist: 'SC-28', cwe: 'CWE-312' },
    'T1552.004': { nist: 'SC-28', cwe: 'CWE-732' },
    'T1552.005': { nist: 'SC-7', cwe: 'CWE-918' },
    'T1552.006': { nist: 'IA-5', cwe: 'CWE-522' },
    'T1555': { nist: 'SC-28', cwe: 'CWE-522' },
    'T1557': { nist: 'SC-8', cwe: 'CWE-300' },
    'T1557.001': { nist: 'SC-8', cwe: 'CWE-300' },
    'T1558': { nist: 'IA-5', cwe: 'CWE-522' },
    'T1558.001': { nist: 'IA-5', cwe: 'CWE-327' },
    'T1558.002': { nist: 'IA-5', cwe: 'CWE-327' },
    'T1558.003': { nist: 'IA-5', cwe: 'CWE-522' },
    'T1558.004': { nist: 'IA-5', cwe: 'CWE-287' },
    'T1574': { nist: 'SI-7', cwe: 'CWE-427' },
    'T1574.009': { nist: 'CM-6', cwe: 'CWE-428' },
    'T1574.010': { nist: 'AC-6', cwe: 'CWE-732' },
    'T1590': { nist: 'CM-7', cwe: 'CWE-200' },
    'T1595': { nist: 'RA-5', cwe: 'CWE-200' },
    'T1611': { nist: 'AC-6', cwe: 'CWE-250' },
    'T1649': { nist: 'AC-6', cwe: 'CWE-266' },
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
    NIST_CONTROLS: NIST_CONTROLS,
    nistUrl: nistUrl,
    CIS_V8: CIS_V8,
    CIS_DETAILS: CIS_DETAILS,
    PCI_V4: PCI_V4,
    PCI_DETAILS: PCI_DETAILS,
    CWE_CATALOG: CWE_CATALOG,
    cweUrl: cweUrl,
    OWASP_TOP10: OWASP_TOP10,
    TECHNIQUE_TO_COMPLIANCE: TECHNIQUE_TO_COMPLIANCE,
  };
  if (typeof module !== 'undefined' && module.exports) { module.exports = OBOL.FRAMEWORK_TABLES; }
})(typeof globalThis !== 'undefined' ? globalThis : this);
