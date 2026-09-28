;(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  OBOL.narratives = {
    // ---- Active Directory ----
    'adcs-template-abuse': {
      phase_label: 'Privilege Escalation — AD CS Certificate Template Abuse',
      explanation: 'A published Active Directory Certificate Services template was misconfigured (an ESC1-8 condition) so that a low-privileged enrollee could request a certificate specifying an arbitrary subject or using it for client authentication. This allowed a certificate to be minted that authenticates to the {{domain}} domain as a higher-privileged principal.',
      impact: 'Issuance of a certificate that authenticates as a privileged domain account, escalating access within the domain.'
    },
    'asrep-roasting': {
      phase_label: 'Initial Access — AS-REP Roasting',
      explanation: 'The account {{subject}} had Kerberos pre-authentication disabled (DONT_REQ_PREAUTH), so any unauthenticated actor could request an AS-REP for it and recover the account password hash for offline cracking. The recovered credential provided an authenticated foothold in the {{domain}} domain.',
      impact: 'Recovery of a valid domain credential and an authenticated foothold.'
    },
    'dangerous-ad-acl': {
      phase_label: 'Lateral Movement — Dangerous Active Directory ACLs',
      explanation: 'An overly permissive access-control entry (such as GenericAll, WriteDacl, WriteOwner, or ForceChangePassword) granted {{subject}} effective control over another privileged object. An already-authenticated principal could abuse this ACE to reset a password, add itself to a group, or otherwise seize the target object.',
      impact: 'Attacker-controlled takeover of a higher-privileged principal along an Active Directory attack path.'
    },
    'dcsync': {
      phase_label: 'Credential Access — DCSync Replication Abuse',
      explanation: 'The principal {{subject}} held the directory replication rights (Get-Changes and Get-Changes-All) on the domain object, allowing it to impersonate a domain controller and request the replication of account secrets. This exposed every credential in the directory, including the krbtgt key.',
      impact: 'Extraction of all domain password hashes, including krbtgt, amounting to full domain compromise.'
    },
    'golden-ticket': {
      phase_label: 'Persistence — Golden Ticket (krbtgt Forgery)',
      explanation: 'With the krbtgt account key recovered from the {{domain}} domain, arbitrary Kerberos ticket-granting tickets could be forged for any user with any group membership. Because the krbtgt key signs all TGTs, these forged tickets are accepted domain-wide until the key is rotated.',
      impact: 'Forgery of Kerberos tickets granting persistent, arbitrary access to any domain resource.'
    },
    'kerberoasting': {
      phase_label: 'Credential Access — Kerberoasting',
      explanation: 'The service account {{subject}} had a Service Principal Name registered, so any authenticated user could request a service ticket (TGS) encrypted with the account password-derived key. The ticket was recovered and cracked offline to reveal the service account plaintext password.',
      impact: 'Recovery of a service account credential for reuse and further access.'
    },
    'pass-the-hash': {
      phase_label: 'Lateral Movement — Pass-the-Hash',
      explanation: 'The NTLM hash of {{subject}} was reused directly against network services that accept NTLM authentication, so no plaintext password was required. NTLM authentication treats the hash as the shared secret, allowing an actor holding it to authenticate as the account.',
      impact: 'Authentication and code execution as the compromised account without cracking its password.'
    },
    'password-spraying': {
      phase_label: 'Initial Access — Password Spraying',
      explanation: 'A weak password policy and the absence of effective account lockout allowed a small set of common or predictable passwords to be tried against the enumerated {{domain}} account list without triggering defenses. At least one account used a guessable password.',
      impact: 'Recovery of valid domain credentials and an authenticated foothold.'
    },
    'zerologon': {
      phase_label: 'Privilege Escalation — Zerologon (CVE-2020-1472)',
      explanation: 'A cryptographic flaw in the Netlogon protocol on the domain controller {{target}} allowed an unauthenticated actor on the network to reset the domain controller machine-account password to an empty value. This bypasses authentication entirely and yields control of the domain controller.',
      impact: 'Unauthenticated reset of the domain controller account, leading to full domain compromise.'
    },

    // ---- Credential Access ----
    'credentials-in-files': {
      phase_label: 'Credential Access — Cleartext Credentials in Files',
      explanation: 'Reusable credentials belonging to {{subject}} were stored in cleartext in configuration files, scripts, shell histories, or backups readable from the compromised context. Because the credentials were valid elsewhere, they were harvested and reused to expand access.',
      impact: 'Recovery of reusable credentials enabling access to additional accounts or systems.'
    },
    'credentials-in-process-list': {
      phase_label: 'Credential Access — Credentials in Process Arguments',
      explanation: 'A secret was passed as a command-line argument, making it visible to any local user through the world-readable process table (ps and /proc). An unprivileged user on {{target}} could read the argument list and recover the credential.',
      impact: 'Disclosure of a credential to any local user, enabling reuse for further access.'
    },
    'weak-password-hashing': {
      phase_label: 'Credential Access — Weak Password Hashing',
      explanation: 'Recovered password hashes were stored with a fast or unsalted algorithm (such as MD5, SHA-1, or plain SHA-256) rather than a memory-hard KDF. This makes offline brute-force and dictionary cracking of the hashes practical at high speed.',
      impact: 'Rapid offline recovery of plaintext passwords from the captured hashes.'
    },

    // ---- Windows Local Privilege Escalation ----
    'dll-hijacking': {
      phase_label: 'Privilege Escalation — DLL Search-Order Hijacking',
      explanation: 'A privileged process on {{target}} loaded a library by name from a directory writable by a lower-privileged user, or from a location searched before the legitimate one. Placing a malicious DLL there causes the privileged process to execute attacker code when it next loads the library.',
      impact: 'Execution of arbitrary code in the security context of the privileged process.'
    },
    'custom-service-buffer-overflow': {
      phase_label: 'Privilege Escalation — Service Stack Buffer Overflow',
      explanation: 'A custom or legacy service running with elevated privileges on {{target}} handled attacker-supplied input without bounds checking, allowing a stack buffer to be overflowed and control of execution to be seized. The absence of modern mitigations (DEP, ASLR, stack canaries) made reliable exploitation possible.',
      impact: 'Arbitrary code execution in the privileged context of the vulnerable service.'
    },
    'stored-windows-credentials': {
      phase_label: 'Privilege Escalation — Stored Windows Credentials',
      explanation: 'Reusable Windows credentials were recoverable from the host in autologon registry values, Credential Manager / cmdkey entries, or unattend.xml and sysprep answer files. These stored secrets belonged to a more privileged account and were reused to escalate.',
      impact: 'Recovery of privileged credentials enabling escalation or lateral movement.'
    },
    'always-install-elevated': {
      phase_label: 'Privilege Escalation — AlwaysInstallElevated',
      explanation: 'The AlwaysInstallElevated policy was enabled in both the HKLM and HKCU registry hives, so any user can install a Windows Installer (MSI) package with SYSTEM privileges. A crafted MSI was therefore installed to run attacker code as SYSTEM.',
      impact: 'Escalation from a standard user to SYSTEM on the host.'
    },
    'missing-security-patches': {
      phase_label: 'Privilege Escalation — Missing Security Patches',
      explanation: 'The host {{target}} was missing an operating-system or kernel security update for which a public local privilege-escalation exploit exists. Running the matched exploit against the unpatched component provides a direct path to elevated privileges.',
      impact: 'Escalation to administrative or root privileges via a known unpatched vulnerability.'
    },
    'seimpersonate-potato': {
      phase_label: 'Privilege Escalation — SeImpersonatePrivilege Abuse (Potato)',
      explanation: 'The compromised service context on {{target}} held SeImpersonatePrivilege, which permits impersonating the security token of another authentication. A potato-style technique was used to coerce a SYSTEM authentication and impersonate its token.',
      impact: 'Escalation from a service account to SYSTEM on the host.'
    },
    'unquoted-service-path': {
      phase_label: 'Privilege Escalation — Unquoted Service Path',
      explanation: 'A Windows service on {{target}} had an unquoted ImagePath containing spaces, and an intermediate directory in that path was writable by a lower-privileged user. Windows will attempt to execute a planted executable earlier in the path, which then runs in the service account context.',
      impact: 'Execution of attacker code in the privileged context of the service.'
    },
    'weak-service-permissions': {
      phase_label: 'Privilege Escalation — Weak Windows Service Permissions',
      explanation: 'A Windows service on {{target}} was configured so that a non-administrative user could modify its configuration or overwrite its binary. Reconfiguring the service binary path or replacing the executable causes attacker code to run when the service starts, typically as SYSTEM.',
      impact: 'Escalation to the SYSTEM context in which the service runs.'
    },

    // ---- Linux Local Privilege Escalation ----
    'linux-capabilities': {
      phase_label: 'Privilege Escalation — Dangerous Linux Capability',
      explanation: 'A binary on {{target}} carried a file capability (such as cap_setuid, cap_dac_override, or cap_sys_admin) that is effectively root-equivalent. The capability was leveraged, per GTFOBins, to read protected files or execute code with elevated privileges.',
      impact: 'Escalation from the compromised user to root-equivalent control of the host.'
    },
    'writable-cron-job': {
      phase_label: 'Privilege Escalation — Writable Scheduled Task / Cron Job',
      explanation: 'A cron job executed by root ran a script, or referenced a directory, writable by a lower-privileged user. Modifying the scheduled script causes the injected commands to run with root privileges at the next execution.',
      impact: 'Escalation from the compromised user to root when the scheduled task runs.'
    },
    'docker-group-escape': {
      phase_label: 'Privilege Escalation — Docker/LXD Group Abuse',
      explanation: 'The compromised user {{subject}} belonged to the docker or lxd group, which is root-equivalent because it can start a container that mounts the host filesystem. Mounting the host root filesystem into a container grants full read/write access as root.',
      impact: 'Escalation from a group member to full root control of the host.'
    },
    'nfs-no-root-squash': {
      phase_label: 'Privilege Escalation — NFS no_root_squash',
      explanation: 'An NFS export on {{target}} was configured with no_root_squash, so a client mounting the share retains root identity for file operations. A setuid-root binary was written to the share from the attacker-controlled client and then executed on the target to gain root.',
      impact: 'Escalation to root on the host exporting the share.'
    },
    'sudo-misconfiguration': {
      phase_label: 'Privilege Escalation — Sudo Misconfiguration',
      explanation: 'The sudoers policy permitted {{subject}} to run a program as root that can be coerced into executing arbitrary commands (per GTFOBins), so the grant was leveraged to spawn a root shell.',
      impact: 'Escalation from the compromised user to full root control of the host.'
    },
    'suid-sgid-abuse': {
      phase_label: 'Privilege Escalation — Dangerous SUID/SGID Binary',
      explanation: 'A binary on {{target}} carried the setuid or setgid bit and could be coerced into running arbitrary commands as its owner (per GTFOBins). Because the owner was root, executing the binary in the documented manner yielded root privileges.',
      impact: 'Escalation from the compromised user to root on the host.'
    },
    'writable-etc-passwd': {
      phase_label: 'Privilege Escalation — World-Writable /etc/passwd',
      explanation: 'The /etc/passwd file (or another sensitive file) on {{target}} was writable by a lower-privileged user. A new entry with UID 0 and an attacker-known password hash was appended, creating a root-equivalent account.',
      impact: 'Escalation to a root-privileged account on the host.'
    },

    // ---- Web / Service Exploitation ----
    'tomcat-manager-weak-creds': {
      phase_label: 'Initial Access — Tomcat Manager Weak Credentials',
      explanation: 'The Apache Tomcat Manager application on {{target}} was reachable with default or weak credentials, which grant the ability to deploy web applications. A malicious WAR was deployed through the manager interface to obtain command execution on the server.',
      impact: 'Remote code execution on the host and an initial foothold.'
    },
    'unauthenticated-admin-interface': {
      phase_label: 'Initial Access — Unauthenticated Admin Interface',
      explanation: 'An administrative console on {{target}} (such as a Jenkins script console) was exposed without authentication and offered a code-execution or scripting facility. The interface was used directly to run arbitrary commands on the underlying host.',
      impact: 'Remote code execution on the host without authentication.'
    },
    'command-injection': {
      phase_label: 'Initial Access — OS Command Injection',
      explanation: 'The application on {{target}} passed unsanitized user input into an operating-system shell, so injected shell metacharacters were interpreted as additional commands. This allowed arbitrary commands to run in the context of the web-service account.',
      impact: 'Remote code execution on the host and an initial foothold.'
    },
    'insecure-deserialization': {
      phase_label: 'Initial Access — Insecure Deserialization',
      explanation: 'The application on {{target}} deserialized attacker-controlled data without integrity verification, allowing a crafted object graph to trigger a gadget chain during deserialization. This drove the application into executing attacker-chosen code.',
      impact: 'Remote code execution in the context of the vulnerable application.'
    },
    'nosql-injection': {
      phase_label: 'Initial Access — NoSQL Injection',
      explanation: 'The application on {{target}} incorporated untrusted input into a NoSQL query without type checking, allowing query operators to be injected where scalar values were expected. This subverted the intended query logic, for example to bypass authentication or extract data.',
      impact: 'Authentication bypass or unauthorized data access against the datastore.'
    },
    'server-side-template-injection': {
      phase_label: 'Initial Access — Server-Side Template Injection',
      explanation: 'User-controlled input on {{target}} was rendered as template source rather than passed as a bound variable, so the template engine evaluated attacker-supplied expressions. Depending on the engine, this evaluation was escalated to arbitrary code execution.',
      impact: 'Remote code execution in the context of the application server.'
    },
    'sql-injection': {
      phase_label: 'Initial Access — SQL Injection',
      explanation: 'The application on {{target}} concatenated untrusted input into SQL statements instead of using parameterized queries, allowing the query structure to be altered. This permitted extraction of data, authentication bypass, or, depending on privileges, command execution.',
      impact: 'Unauthorized database access and potential foothold on the host.'
    },
    'xml-external-entity': {
      phase_label: 'Initial Access — XML External Entity (XXE) Injection',
      explanation: 'An XML parser on {{target}} resolved external entities and processed DTDs from attacker-supplied documents. Defining an external entity allowed local files to be read and internal requests to be made from the server.',
      impact: 'Disclosure of server-side files and server-side request forgery from the host.'
    },
    'cross-site-scripting': {
      phase_label: 'Credential Access — Cross-Site Scripting (XSS)',
      explanation: 'The application on {{target}} reflected or stored user input into a page without context-aware output encoding, so attacker-supplied script executed in a victim browser. The injected script runs with the privileges of the victim session against the application.',
      impact: 'Theft of session material or actions performed as the victim user.'
    },
    'local-file-inclusion': {
      phase_label: 'Initial Access — Local File Inclusion / Path Traversal',
      explanation: 'The application on {{target}} incorporated a user-controlled value into a file path without validation, allowing traversal to files outside the intended directory. This exposed arbitrary readable files on the server and, via stream wrappers or log poisoning, a path to code execution.',
      impact: 'Disclosure of sensitive server-side files and a potential path to code execution.'
    },
    'server-side-request-forgery': {
      phase_label: 'Initial Access — Server-Side Request Forgery (SSRF)',
      explanation: 'The application on {{target}} fetched a URL supplied by the user without restricting the destination, so requests could be directed at internal services and link-local addresses. This reached resources not exposed externally, including the cloud metadata endpoint.',
      impact: 'Access to internal services and metadata reachable only from the host.'
    },
    'unrestricted-file-upload': {
      phase_label: 'Initial Access — Unrestricted File Upload',
      explanation: 'The application on {{target}} accepted an uploaded file without validating its extension or content and stored it within the web root where scripts execute. A server-side script (web shell) was uploaded and then requested to obtain command execution.',
      impact: 'Remote code execution on the host through an uploaded web shell.'
    },

    // ---- Fallback ----
    '_default': {
      phase_label: '',
      explanation: 'A weakness on {{target}} was leveraged to advance access, as evidenced by the commands below.',
      impact: ''
    }
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
