;(function(root){var OBOL=root.OBOL=root.OBOL||{};OBOL.findingsCatalog=[
  {
   "key": "insecure-direct-object-reference",
   "title": "Insecure Direct Object Reference (IDOR)",
   "category": "access",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Enforce object-level authorization server-side on every request; never rely on unguessable identifiers or client-supplied keys for access control.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/639.html",
    "https://attack.mitre.org/techniques/T1190/",
    "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
   ],
   "cwe": "CWE-639",
   "attack": "T1190",
   "nist": "AC-3",
   "match": {
    "facts_any": [
     "web.authz_bypass"
    ]
   }
  },
  {
   "key": "smb-null-session",
   "title": "SMB Null Session / Anonymous Enumeration",
   "category": "access",
   "severity": "medium",
   "confidence": "confirmed",
   "remediation": "Disable null sessions (RestrictAnonymous=2), require SMB signing, and remove unauthenticated open shares.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/306.html",
    "https://attack.mitre.org/techniques/T1135/",
    "https://learn.microsoft.com/en-us/troubleshoot/windows-server/security/restrict-anonymous-access"
   ],
   "cwe": "CWE-306",
   "attack": "T1135",
   "nist": "AC-3",
   "match": {
    "facts_any": [
     "smb.null_session"
    ]
   }
  },
  {
   "key": "tomcat-manager-weak-creds",
   "match": {"fact_value": {"kind": "web.cmdi_confirmed", "field": "method", "equals": "tomcat_war_deploy"}},
   "title": "Tomcat Manager Default / Weak Credentials",
   "category": "access",
   "severity": "critical",
   "confidence": "confirmed",
   "remediation": "Remove the manager application from production, set strong unique credentials, and restrict the manager interface to trusted management IPs.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/521.html",
    "https://attack.mitre.org/techniques/T1190/",
    "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"
   ],
   "cwe": "CWE-521",
   "attack": "T1190",
   "nist": "AC-3"
  },
  {
   "key": "unauthenticated-admin-interface",
   "match": {"fact_value": {"kind": "web.cmdi_confirmed", "field": "method", "equals": "jenkins_script_console"}},
   "title": "Unauthenticated Admin Interface (e.g. Jenkins)",
   "category": "access",
   "severity": "critical",
   "confidence": "confirmed",
   "remediation": "Require authentication on all management consoles, disable the script console for non-admins, patch to current, and isolate CI/CD from production networks.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/306.html",
    "https://attack.mitre.org/techniques/T1059/",
    "https://owasp.org/www-community/vulnerabilities/Missing_Function_Level_Access_Control"
   ],
   "cwe": "CWE-306",
   "attack": "T1059",
   "nist": "AC-3"
  },
  {
   "key": "unauthenticated-datastore",
   "match": {"fact_value": {"kind": "config.review", "field": "kind", "equals": "unauthenticated_redis"}},
   "title": "Unauthenticated Data Store (Redis/Elasticsearch/etc.)",
   "category": "access",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Require authentication (requirepass / X-Pack security), bind services to localhost or trusted networks, and never expose data-store ports publicly.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/306.html",
    "https://attack.mitre.org/techniques/T1190/",
    "https://cwe.mitre.org/data/definitions/306.html"
   ],
   "cwe": "CWE-306",
   "attack": "T1190",
   "nist": "AC-3"
  },
  {
   "key": "adcs-template-abuse",
   "title": "AD CS Certificate Template Abuse (ESC1-8)",
   "category": "ad",
   "severity": "critical",
   "confidence": "confirmed",
   "remediation": "Remediate vulnerable certificate templates, disable EDITF_ATTRIBUTESUBJECTALTNAME2, and restrict enrollment rights per Certipy/Certify audit guidance.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/266.html",
    "https://attack.mitre.org/techniques/T1649/",
    "https://attack.mitre.org/techniques/T1649/"
   ],
   "cwe": "CWE-266",
   "attack": "T1649",
   "nist": "AC-3",
   "match": {
    "facts_any": [
     "adcs.vulnerable"
    ]
   }
  },
  {
   "key": "asrep-roasting",
   "title": "AS-REP Roasting",
   "category": "ad",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Remove the DONT_REQ_PREAUTH flag from all accounts (require Kerberos pre-authentication) and audit for it regularly with BloodHound or PowerShell.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/522.html",
    "https://attack.mitre.org/techniques/T1558/004/",
    "https://attack.mitre.org/techniques/T1558/004/"
   ],
   "cwe": "CWE-522",
   "attack": "T1558.004",
   "nist": "IA-5",
   "match": {
    "facts_any": [
     "hash.asrep"
    ]
   }
  },
  {
   "key": "dangerous-ad-acl",
   "title": "Dangerous Active Directory ACLs",
   "category": "ad",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Audit and remove dangerous ACEs (GenericAll, WriteDacl, WriteOwner, ForceChangePassword) with BloodHound, and enable AdminSDHolder protection on privileged groups.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/266.html",
    "https://attack.mitre.org/techniques/T1098/",
    "https://attack.mitre.org/techniques/T1098/"
   ],
   "cwe": "CWE-266",
   "attack": "T1098",
   "nist": "AC-3",
   "match": {
    "facts_any": [
     "ad.control_paths",
     "ad.attack_paths"
    ]
   }
  },
  {
   "key": "dcsync",
   "title": "DCSync Replication Abuse",
   "category": "ad",
   "severity": "critical",
   "confidence": "confirmed",
   "remediation": "Audit GetChanges/GetChangesAll rights on the domain object, remove them from non-tier-0 principals, and alert on replication (event 4662) from non-DC hosts.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/266.html",
    "https://attack.mitre.org/techniques/T1003/006/",
    "https://attack.mitre.org/techniques/T1003/006/"
   ],
   "cwe": "CWE-266",
   "attack": "T1003.006",
   "nist": "AC-6",
   "match": {
    "facts_any": [
     "loot.ntds",
     "hash.krbtgt"
    ]
   }
  },
  {
   "key": "golden-ticket",
   "title": "Golden Ticket (krbtgt Forgery)",
   "category": "ad",
   "severity": "critical",
   "confidence": "confirmed",
   "remediation": "Rotate the krbtgt account password twice, protect domain controllers as tier-0 assets, and treat a confirmed golden ticket as grounds for forest-rebuild consideration.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/522.html",
    "https://attack.mitre.org/techniques/T1558/001/",
    "https://attack.mitre.org/techniques/T1558/001/"
   ],
   "cwe": "CWE-522",
   "attack": "T1558.001",
   "nist": "IA-5",
   "match": {
    "facts_any": [
     "hash.krbtgt"
    ]
   }
  },
  {
   "key": "kerberoasting",
   "title": "Kerberoasting",
   "category": "ad",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Use gMSA or 25+ character random passwords for service accounts, remove unnecessary SPNs, and enforce AES-only encryption for SPN accounts.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/522.html",
    "https://attack.mitre.org/techniques/T1558/003/",
    "https://attack.mitre.org/techniques/T1558/003/"
   ],
   "cwe": "CWE-522",
   "attack": "T1558.003",
   "nist": "IA-5",
   "match": {
    "facts_any": [
     "hash.tgs"
    ]
   }
  },
  {
   "key": "pass-the-hash",
   "title": "Pass-the-Hash / Overpass-the-Hash",
   "category": "ad",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Deploy Credential Guard, enforce a tiered-admin model, and use LAPS so local admin hashes are unique per host.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/522.html",
    "https://attack.mitre.org/techniques/T1550/002/",
    "https://attack.mitre.org/techniques/T1550/002/"
   ],
   "cwe": "CWE-522",
   "attack": "T1550.002",
   "nist": "AC-6",
   "match": {
    "facts_any": [
     "credential.ntlm_hash",
     "hash.ntlm"
    ]
   }
  },
  {
   "key": "outdated-vulnerable-software",
   "title": "Outdated / Vulnerable Third-Party Software",
   "category": "config",
   "severity": "high",
   "confidence": "candidate",
   "remediation": "Maintain a patch cadence prioritized by exploit availability (CISA KEV), remove default credentials, and track component versions against advisories.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/1395.html",
    "https://attack.mitre.org/techniques/T1190/",
    "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"
   ],
   "cwe": "CWE-1395",
   "attack": "T1190",
   "nist": "SI-2",
   "match": {
    "facts_any": [
     "exploit.candidate"
    ]
   }
  },
  {
   "key": "cookie-missing-flags",
   "title": "Cookie Missing Security Flags",
   "category": "cookies",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Set cookies with Secure; HttpOnly; SameSite attributes.",
   "refs": [
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies"
   ],
   "cwe": "CWE-614",
   "nist": "SC-23",
   "match": {
    "flag": "cookie_insecure"
   }
  },
  {
   "key": "cors-null-origin",
   "title": "CORS null Origin Allowed",
   "category": "cors",
   "severity": "medium",
   "confidence": "confirmed",
   "remediation": "Remove 'null' from the CORS allow-list.",
   "refs": [
    "https://portswigger.net/web-security/cors"
   ],
   "cwe": "CWE-942",
   "nist": "AC-4",
   "match": {
    "flag": "cors_null"
   }
  },
  {
   "key": "cors-origin-reflection",
   "title": "CORS Origin Reflection",
   "category": "cors",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Validate Origin against a strict allow-list before echoing it back.",
   "refs": [
    "https://portswigger.net/web-security/cors"
   ],
   "cwe": "CWE-942",
   "nist": "AC-4",
   "match": {
    "flag": "cors_origin_reflected"
   }
  },
  {
   "key": "cors-wildcard",
   "title": "CORS Wildcard Origin",
   "category": "cors",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Use an explicit allow-list of trusted origins instead of '*'.",
   "refs": [
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"
   ],
   "cwe": "CWE-942",
   "nist": "AC-4",
   "match": {
    "flag": "cors_wildcard"
   }
  },
  {
   "key": "credentials-in-files",
   "title": "Cleartext / Reusable Credentials in Files",
   "category": "credential",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Remove credentials from config files, scripts, histories, and backups; store secrets in a vault and rotate anything discovered.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/522.html",
    "https://attack.mitre.org/techniques/T1552/001/",
    "https://attack.mitre.org/techniques/T1552/001/"
   ],
   "cwe": "CWE-522",
   "attack": "T1552.001",
   "nist": "AC-6",
   "match": {
    "facts_any": [
     "credential.plaintext"
    ]
   }
  },
  {
   "key": "gpp-cpassword",
   "title": "Group Policy Preferences cpassword Exposure",
   "category": "credential",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Delete legacy cpassword XML from SYSVOL (KB2962486), never store credentials in GPP, and use LAPS for local-admin password management instead.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/522.html",
    "https://attack.mitre.org/techniques/T1552/006/",
    "https://attack.mitre.org/techniques/T1552/006/"
   ],
   "cwe": "CWE-522",
   "attack": "T1552.006",
   "nist": "IA-5"
  },
  {
   "key": "ipv6-dns-takeover",
   "title": "IPv6 DNS Takeover (mitm6)",
   "category": "credential",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Disable IPv6 if unused, block rogue DHCPv6 with RA Guard / DHCPv6 Guard, and disable WPAD.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/300.html",
    "https://attack.mitre.org/techniques/T1557/001/",
    "https://attack.mitre.org/techniques/T1557/001/"
   ],
   "cwe": "CWE-300",
   "attack": "T1557.001",
   "nist": "SC-7"
  },
  {
   "key": "llmnr-nbtns-poisoning",
   "title": "LLMNR / NBT-NS Poisoning",
   "category": "credential",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Disable LLMNR and NBT-NS via GPO, require SMB signing, and segment workstations to limit broadcast poisoning.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/300.html",
    "https://attack.mitre.org/techniques/T1557/001/",
    "https://attack.mitre.org/techniques/T1557/001/"
   ],
   "cwe": "CWE-300",
   "attack": "T1557.001",
   "nist": "SC-7"
  },
  {
   "key": "ntlm-relay",
   "title": "NTLM Relay (Missing SMB Signing)",
   "category": "credential",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Require SMB signing everywhere, enable Extended Protection for Authentication (EPA), disable NTLMv1, and disable the WebClient service.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/294.html",
    "https://attack.mitre.org/techniques/T1557/001/",
    "https://attack.mitre.org/techniques/T1557/001/"
   ],
   "cwe": "CWE-294",
   "attack": "T1557.001",
   "nist": "SC-8",
   "match": {
    "flag": "smb_signing_disabled"
   }
  },
  {
   "key": "password-spraying",
   "title": "Password Spraying / Weak Password Policy",
   "category": "credential",
   "severity": "high",
   "confidence": "candidate",
   "remediation": "Enforce account lockout and MFA, ban seasonal and company-derived passwords, and alert on one-password-against-many-accounts patterns.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/307.html",
    "https://attack.mitre.org/techniques/T1110/003/",
    "https://attack.mitre.org/techniques/T1110/003/"
   ],
   "cwe": "CWE-307",
   "attack": "T1110.003",
   "nist": "IA-5",
   "match": {
    "facts_any": [
     "ad.user_list"
    ]
   }
  },
  {
   "key": "weak-password-hashing",
   "title": "Weak / Fast Password Hashing",
   "category": "crypto",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Store credentials using a modern memory-hard KDF (Argon2, bcrypt, or yescrypt) and enforce long passphrases so recovered hashes are uncrackable in practice.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/916.html",
    "https://attack.mitre.org/techniques/T1110/002/",
    "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"
   ],
   "cwe": "CWE-916",
   "attack": "T1110.002",
   "nist": "IA-5"
  },
  {
   "key": "cve-angularjs-2019-10768",
   "title": "angularjs < 1.7.9 \u2014 Prototype pollution (CVE-2019-10768)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2019-10768",
   "tech": "angularjs",
   "fixed": "1.7.9",
   "remediation": "Upgrade angularjs to >= 1.7.9.",
   "refs": [
    "https://github.com/angular/angular.js/blob/master/CHANGELOG.md#179-pollution-eradication-2019-11-19",
    "https://github.com/angular/angular.js/commit/726f49dcf6c23106ddaf5cfd5e2e592841db743a"
   ],
   "match": {
    "tech": "angularjs",
    "version_lt": "1.7.9"
   },
   "cwe": "CWE-1321"
  },
  {
   "key": "cve-angularjs-2019-14863",
   "title": "angularjs < 1.5.0-beta.1 \u2014 XSS through xlink:href attributes (CVE-2019-14863)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2019-14863",
   "tech": "angularjs",
   "fixed": "1.5.0-beta.1",
   "remediation": "Upgrade angularjs to >= 1.5.0-beta.1.",
   "refs": [
    "https://github.com/advisories/GHSA-r5fx-8r73-v86c",
    "https://github.com/angular/angular.js/blob/master/CHANGELOG.md#150-beta1-dense-dispersion-2015-09-29"
   ],
   "match": {
    "tech": "angularjs",
    "version_lt": "1.5.0-beta.1"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-angularjs-2020-7676",
   "title": "angularjs < 1.8.0 \u2014 XSS may be triggered in AngularJS applications that sanitize user-controlled HTML snippets before passing them to JQLite",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-7676",
   "tech": "angularjs",
   "fixed": "1.8.0",
   "remediation": "Upgrade angularjs to >= 1.8.0.",
   "refs": [
    "https://github.com/advisories/GHSA-5cp4-xmrw-59wf",
    "https://nvd.nist.gov/vuln/detail/CVE-2020-7676"
   ],
   "match": {
    "tech": "angularjs",
    "version_lt": "1.8.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-angularjs-2022-25844",
   "title": "angularjs < 999.999.999 \u2014 angular vulnerable to regular expression denial of service (ReDoS) (CVE-2022-25844)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-25844",
   "tech": "angularjs",
   "fixed": "999.999.999",
   "remediation": "Upgrade angularjs to >= 999.999.999.",
   "refs": [
    "https://github.com/advisories/GHSA-m2h2-264f-f486"
   ],
   "match": {
    "tech": "angularjs",
    "version_lt": "999.999.999"
   },
   "cwe": "CWE-1333"
  },
  {
   "key": "cve-angularjs-2022-25869",
   "title": "angularjs < 1.8.4 \u2014 Angular (deprecated package) Cross-site Scripting (CVE-2022-25869)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-25869",
   "tech": "angularjs",
   "fixed": "1.8.4",
   "remediation": "Upgrade angularjs to >= 1.8.4.",
   "refs": [
    "https://github.com/advisories/GHSA-prc3-vjfx-vhm9"
   ],
   "match": {
    "tech": "angularjs",
    "version_lt": "1.8.4"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-angularjs-2023-26116",
   "title": "angularjs < 1.8.4 \u2014 angular vulnerable to regular expression denial of service via the angular.copy() utility (CVE-2023-26116)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2023-26116",
   "tech": "angularjs",
   "fixed": "1.8.4",
   "remediation": "Upgrade angularjs to >= 1.8.4.",
   "refs": [
    "https://github.com/advisories/GHSA-2vrf-hf26-jrp5"
   ],
   "match": {
    "tech": "angularjs",
    "version_lt": "1.8.4"
   },
   "cwe": "CWE-400"
  },
  {
   "key": "cve-angularjs-2023-26117",
   "title": "angularjs < 1.8.4 \u2014 angular vulnerable to regular expression denial of service via the $resource service (CVE-2023-26117)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2023-26117",
   "tech": "angularjs",
   "fixed": "1.8.4",
   "remediation": "Upgrade angularjs to >= 1.8.4.",
   "refs": [
    "https://github.com/advisories/GHSA-2qqx-w9hr-q5gx"
   ],
   "match": {
    "tech": "angularjs",
    "version_lt": "1.8.4"
   },
   "cwe": "CWE-400"
  },
  {
   "key": "cve-angularjs-2023-26118",
   "title": "angularjs < 1.8.4 \u2014 angular vulnerable to regular expression denial of service via the <input type=\"url\"> element (CVE-2023-26118)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2023-26118",
   "tech": "angularjs",
   "fixed": "1.8.4",
   "remediation": "Upgrade angularjs to >= 1.8.4.",
   "refs": [
    "https://github.com/advisories/GHSA-qwqh-hm9m-p5hr"
   ],
   "match": {
    "tech": "angularjs",
    "version_lt": "1.8.4"
   },
   "cwe": "CWE-400"
  },
  {
   "key": "cve-angularjs-2024-21490",
   "title": "angularjs < 1.8.4 \u2014 angular vulnerable to super-linear runtime due to backtracking (CVE-2024-21490)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2024-21490",
   "tech": "angularjs",
   "fixed": "1.8.4",
   "remediation": "Upgrade angularjs to >= 1.8.4.",
   "refs": [
    "https://github.com/advisories/GHSA-4w4v-5hc9-xrr2",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-21490",
    "https://github.com/angular/angular.js",
    "https://security.snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWER-6241746",
    "https://security.snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-6241747",
    "https://security.snyk.io/vuln/SNYK-JS-ANGULAR-6091113",
    "https://stackblitz.com/edit/angularjs-vulnerability-ng-srcset-redos"
   ],
   "match": {
    "tech": "angularjs",
    "version_lt": "1.8.4"
   }
  },
  {
   "key": "cve-angularjs-2024-8372",
   "title": "angularjs < 1.8.4 \u2014 AngularJS allows attackers to bypass common image source restrictions (CVE-2024-8372)",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2024-8372",
   "tech": "angularjs",
   "fixed": "1.8.4",
   "remediation": "Upgrade angularjs to >= 1.8.4.",
   "refs": [
    "https://github.com/advisories/GHSA-m9gf-397r-hwpg",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-8372",
    "https://codepen.io/herodevs/full/xxoQRNL/0072e627abe03e9cda373bc75b4c1017",
    "https://github.com/angular/angular.js",
    "https://www.herodevs.com/vulnerability-directory/cve-2024-8372"
   ],
   "match": {
    "tech": "angularjs",
    "version_lt": "1.8.4"
   },
   "cwe": "CWE-94"
  },
  {
   "key": "cve-angularjs-2024-8373",
   "title": "angularjs < 1.8.4 \u2014 AngularJS allows attackers to bypass common image source restrictions (CVE-2024-8373)",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2024-8373",
   "tech": "angularjs",
   "fixed": "1.8.4",
   "remediation": "Upgrade angularjs to >= 1.8.4.",
   "refs": [
    "https://github.com/advisories/GHSA-mqm9-c95h-x2p6",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-8373",
    "https://codepen.io/herodevs/full/bGPQgMp/8da9ce87e99403ee13a295c305ebfa0b",
    "https://github.com/angular/angular.js",
    "https://www.herodevs.com/vulnerability-directory/cve-2024-8373"
   ],
   "match": {
    "tech": "angularjs",
    "version_lt": "1.8.4"
   },
   "cwe": "CWE-94"
  },
  {
   "key": "cve-angularjs-2025-0716",
   "title": "angularjs < 1.8.4 \u2014 AngularJS improperly sanitizes SVG elements (CVE-2025-0716)",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2025-0716",
   "tech": "angularjs",
   "fixed": "1.8.4",
   "remediation": "Upgrade angularjs to >= 1.8.4.",
   "refs": [
    "https://github.com/advisories/GHSA-j58c-ww9w-pwp5",
    "https://nvd.nist.gov/vuln/detail/CVE-2025-0716",
    "https://codepen.io/herodevs/pen/qEWQmpd/a86a0d29310e12c7a3756768e6c7b915",
    "https://github.com/angular/angular.js",
    "https://www.herodevs.com/vulnerability-directory/cve-2025-0716"
   ],
   "match": {
    "tech": "angularjs",
    "version_lt": "1.8.4"
   }
  },
  {
   "key": "cve-angularjs-2025-2336",
   "title": "angularjs < 1.8.4 \u2014 AngularJS Incomplete Filtering of Special Elements vulnerability (CVE-2025-2336)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2025-2336",
   "tech": "angularjs",
   "fixed": "1.8.4",
   "remediation": "Upgrade angularjs to >= 1.8.4.",
   "refs": [
    "https://github.com/advisories/GHSA-4p4w-6hg8-63wx",
    "https://nvd.nist.gov/vuln/detail/CVE-2025-2336",
    "https://codepen.io/herodevs/pen/bNGYaXx/412a3a4218387479898912f60c269c6c",
    "https://github.com/angular/angular.js",
    "https://www.herodevs.com/vulnerability-directory/cve-2025-2336"
   ],
   "match": {
    "tech": "angularjs",
    "version_lt": "1.8.4"
   }
  },
  {
   "key": "cve-angularjs-2025-4690",
   "title": "angularjs < 1.9.9 \u2014 AngularJS Regular expression Denial of Service (ReDoS) (CVE-2025-4690)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2025-4690",
   "tech": "angularjs",
   "fixed": "1.9.9",
   "remediation": "Upgrade angularjs to >= 1.9.9.",
   "refs": [
    "https://github.com/advisories/GHSA-hfff-63hg-f47j",
    "https://nvd.nist.gov/vuln/detail/CVE-2025-4690",
    "https://codepen.io/herodevs/pen/RNNEPzP/751b91eab7730dff277523f3d50e4b77",
    "https://github.com/angular/angular.js",
    "https://www.herodevs.com/vulnerability-directory/cve-2025-4690"
   ],
   "match": {
    "tech": "angularjs",
    "version_lt": "1.9.9"
   },
   "cwe": "CWE-1333"
  },
  {
   "key": "cve-angularjs-2026-11998",
   "title": "angularjs < 1.8.4 \u2014 Angular's deprecated package has a Cross-Site Scripting issue (CVE-2026-11998)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2026-11998",
   "tech": "angularjs",
   "fixed": "1.8.4",
   "remediation": "Upgrade angularjs to >= 1.8.4.",
   "refs": [
    "https://access.redhat.com/security/cve/CVE-2026-11998",
    "https://bugzilla.redhat.com/show_bug.cgi?id=2492579",
    "https://codepen.io/herodevs/pen/JobQdmz/5b3896f56fab66f20cd25e698cf3faa8",
    "https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-11998.json",
    "https://www.herodevs.com/vulnerability-directory/cve-2026-11998",
    "https://www.herodevs.com/vulnerability-directory/cve-2026-11998?nes-for-angularjs"
   ],
   "match": {
    "tech": "angularjs",
    "version_lt": "1.8.4"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-apache-2019-0211",
   "title": "Apache HTTP 2.4.17-2.4.38 \u2014 Local root privesc via scoreboard (CVE-2019-0211)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "remediation": "Upgrade Apache HTTP Server to >= 2.4.39.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2019-0211"
   ],
   "cwe": "CWE-94",
   "cve": "CVE-2019-0211",
   "tech": "apache",
   "fixed": "2.4.39",
   "match": {
    "tech": "apache",
    "version_lt": "2.4.39"
   }
  },
  {
   "key": "cve-apache-2021-41773",
   "title": "Apache HTTP 2.4.49 \u2014 Path traversal + RCE via %2e encoding (CVE-2021-41773)",
   "category": "cve",
   "severity": "critical",
   "confidence": "candidate",
   "remediation": "Upgrade Apache HTTP Server to >= 2.4.51.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
   ],
   "cwe": "CWE-22",
   "cve": "CVE-2021-41773",
   "tech": "apache",
   "fixed": "2.4.51",
   "match": {
    "tech": "apache",
    "version_lt": "2.4.51"
   }
  },
  {
   "key": "cve-apache-2021-42013",
   "title": "Apache HTTP 2.4.49-2.4.50 \u2014 Path traversal + RCE via double encoding (CVE-2021-42013)",
   "category": "cve",
   "severity": "critical",
   "confidence": "candidate",
   "remediation": "Upgrade Apache HTTP Server to >= 2.4.51.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2021-42013"
   ],
   "cwe": "CWE-22",
   "cve": "CVE-2021-42013",
   "tech": "apache",
   "fixed": "2.4.51",
   "match": {
    "tech": "apache",
    "version_lt": "2.4.51"
   }
  },
  {
   "key": "cve-bootstrap-2016-10735",
   "title": "bootstrap < 3.4.0 \u2014 XSS is possible in the data-target attribute. (CVE-2016-10735)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2016-10735",
   "tech": "bootstrap",
   "fixed": "3.4.0",
   "remediation": "Upgrade bootstrap to >= 3.4.0.",
   "refs": [
    "https://github.com/advisories/GHSA-4p24-vmcr-4gqj"
   ],
   "match": {
    "tech": "bootstrap",
    "version_lt": "3.4.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-bootstrap-2018-14040",
   "title": "bootstrap < 3.4.0 \u2014 XSS in collapse data-parent attribute (CVE-2018-14040)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2018-14040",
   "tech": "bootstrap",
   "fixed": "3.4.0",
   "remediation": "Upgrade bootstrap to >= 3.4.0.",
   "refs": [
    "https://github.com/twbs/bootstrap/issues/20184"
   ],
   "match": {
    "tech": "bootstrap",
    "version_lt": "3.4.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-bootstrap-2018-14042",
   "title": "bootstrap < 3.4.0 \u2014 XSS in data-container property of tooltip (CVE-2018-14042)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2018-14042",
   "tech": "bootstrap",
   "fixed": "3.4.0",
   "remediation": "Upgrade bootstrap to >= 3.4.0.",
   "refs": [
    "https://github.com/twbs/bootstrap/issues/20184"
   ],
   "match": {
    "tech": "bootstrap",
    "version_lt": "3.4.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-bootstrap-2018-20676",
   "title": "bootstrap < 3.4.0 \u2014 In Bootstrap before 3.4.0, XSS is possible in the tooltip data-viewport attribute. (CVE-2018-20676)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2018-20676",
   "tech": "bootstrap",
   "fixed": "3.4.0",
   "remediation": "Upgrade bootstrap to >= 3.4.0.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2018-20676"
   ],
   "match": {
    "tech": "bootstrap",
    "version_lt": "3.4.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-bootstrap-2018-20677",
   "title": "bootstrap < 3.4.0 \u2014 In Bootstrap before 3.4.0, XSS is possible in the affix configuration target property. (CVE-2018-20677)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2018-20677",
   "tech": "bootstrap",
   "fixed": "3.4.0",
   "remediation": "Upgrade bootstrap to >= 3.4.0.",
   "refs": [
    "https://github.com/advisories/GHSA-ph58-4vrj-w6hr"
   ],
   "match": {
    "tech": "bootstrap",
    "version_lt": "3.4.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-bootstrap-2019-8331",
   "title": "bootstrap < 3.4.1 \u2014 XSS in data-template, data-content and data-title properties of tooltip/popover (CVE-2019-8331)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2019-8331",
   "tech": "bootstrap",
   "fixed": "3.4.1",
   "remediation": "Upgrade bootstrap to >= 3.4.1.",
   "refs": [
    "https://github.com/advisories/GHSA-9v3m-8fp8-mj99",
    "https://github.com/twbs/bootstrap/issues/28236"
   ],
   "match": {
    "tech": "bootstrap",
    "version_lt": "3.4.1"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-bootstrap-2024-6485",
   "title": "bootstrap < 3.4.2 \u2014 Bootstrap Cross-Site Scripting (XSS) vulnerability for data-* attributes (CVE-2024-6485)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2024-6485",
   "tech": "bootstrap",
   "fixed": "3.4.2",
   "remediation": "Upgrade bootstrap to >= 3.4.2.",
   "refs": [
    "https://github.com/advisories/GHSA-vxmc-5x29-h64v",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-6485",
    "https://github.com/twbs/bootstrap",
    "https://www.herodevs.com/vulnerability-directory/cve-2024-6485"
   ],
   "match": {
    "tech": "bootstrap",
    "version_lt": "3.4.2"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-bootstrap-2025-1647",
   "title": "bootstrap < 3.4.2 \u2014 Improper Neutralization of Input During Web Page Generation (XSS or 'Cross-site Scripting') vulnerability in Bootstrap a",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2025-1647",
   "tech": "bootstrap",
   "fixed": "3.4.2",
   "remediation": "Upgrade bootstrap to >= 3.4.2.",
   "refs": [
    "https://lists.debian.org/debian-lts-announce/2025/06/msg00001.html",
    "https://www.herodevs.com/vulnerability-directory/cve-2025-1647"
   ],
   "match": {
    "tech": "bootstrap",
    "version_lt": "3.4.2"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-ckeditor-2021-32808",
   "title": "ckeditor < 4.16.2 \u2014 XSS vulnerability in the Widget plugin (CVE-2021-32808)",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2021-32808",
   "tech": "ckeditor",
   "fixed": "4.16.2",
   "remediation": "Upgrade ckeditor to >= 4.16.2.",
   "refs": [
    "https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-6226-h7ff-ch6c"
   ],
   "match": {
    "tech": "ckeditor",
    "version_lt": "4.16.2"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-ckeditor-2021-32809",
   "title": "ckeditor < 4.16.2 \u2014 XSS vulnerability in the Clipboard plugin (CVE-2021-32809)",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2021-32809",
   "tech": "ckeditor",
   "fixed": "4.16.2",
   "remediation": "Upgrade ckeditor to >= 4.16.2.",
   "refs": [
    "https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-7889-rm5j-hpgg"
   ],
   "match": {
    "tech": "ckeditor",
    "version_lt": "4.16.2"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-ckeditor-2021-37695",
   "title": "ckeditor < 4.16.2 \u2014 XSS vulnerability in the Fake Objects plugin (CVE-2021-37695)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2021-37695",
   "tech": "ckeditor",
   "fixed": "4.16.2",
   "remediation": "Upgrade ckeditor to >= 4.16.2.",
   "refs": [
    "https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-m94c-37g6-cjhc"
   ],
   "match": {
    "tech": "ckeditor",
    "version_lt": "4.16.2"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-ckeditor-2021-41164",
   "title": "ckeditor < 4.17.0 \u2014 XSS vulnerabilities in the core module (CVE-2021-41164)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2021-41164",
   "tech": "ckeditor",
   "fixed": "4.17.0",
   "remediation": "Upgrade ckeditor to >= 4.17.0.",
   "refs": [
    "https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-7h26-63m7-qhf2",
    "https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-pvmx-g8h5-cprj"
   ],
   "match": {
    "tech": "ckeditor",
    "version_lt": "4.17.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-ckeditor-2023-28439",
   "title": "ckeditor < 4.21.0 \u2014 cross-site scripting vulnerability has been discovered affecting Iframe Dialog and Media Embed packages. The vulnerabili",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2023-28439",
   "tech": "ckeditor",
   "fixed": "4.21.0",
   "remediation": "Upgrade ckeditor to >= 4.21.0.",
   "refs": [
    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-28439",
    "https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-vh5c-xwqv-cv9g",
    "https://nvd.nist.gov/vuln/detail/CVE-2023-28439"
   ],
   "match": {
    "tech": "ckeditor",
    "version_lt": "4.21.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-dojo-2008-6681",
   "title": "dojo < 1.1.0 \u2014 Affected versions of dojo are susceptible to a cross-site scripting vulnerability in the dijit.Editor and textarea components",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2008-6681",
   "tech": "dojo",
   "fixed": "1.1.0",
   "remediation": "Upgrade dojo to >= 1.1.0.",
   "refs": [
    "http://www.cvedetails.com/cve/CVE-2008-6681/"
   ],
   "match": {
    "tech": "dojo",
    "version_lt": "1.1.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-dojo-2010-2273",
   "title": "dojo < 1.10.10 \u2014 Versions of dojo prior to 1.4.2 are vulnerable to DOM-based Cross-Site Scripting (XSS). The package does not sanitize URL p",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2010-2273",
   "tech": "dojo",
   "fixed": "1.10.10",
   "remediation": "Upgrade dojo to >= 1.10.10.",
   "refs": [
    "http://dojotoolkit.org/blog/dojo-security-advisory",
    "http://www.cvedetails.com/cve/CVE-2010-2272/",
    "http://www.cvedetails.com/cve/CVE-2010-2273/",
    "http://www.cvedetails.com/cve/CVE-2010-2274/",
    "http://www.cvedetails.com/cve/CVE-2010-2276/",
    "https://dojotoolkit.org/blog/dojo-1-14-released",
    "https://github.com/advisories/GHSA-536q-8gxx-m782",
    "https://github.com/dojo/dojo/pull/307"
   ],
   "match": {
    "tech": "dojo",
    "version_lt": "1.10.10"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-dojo-2010-2275",
   "title": "dojo < 1.4.2 \u2014 Cross-site scripting (XSS) vulnerability in dijit/tests/_testCommon.js in Dojo Toolkit SDK before 1.4.2 allows remote attacke",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2010-2275",
   "tech": "dojo",
   "fixed": "1.4.2",
   "remediation": "Upgrade dojo to >= 1.4.2.",
   "refs": [
    "http://www.cvedetails.com/cve/CVE-2010-2275/"
   ],
   "match": {
    "tech": "dojo",
    "version_lt": "1.4.2"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-dojo-2015-5654",
   "title": "dojo < 1.2.0 \u2014 Versions of dojo prior to 1.2.0 are vulnerable to Cross-Site Scripting (XSS). The package fails to sanitize HTML code in user",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2015-5654",
   "tech": "dojo",
   "fixed": "1.2.0",
   "remediation": "Upgrade dojo to >= 1.2.0.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2015-5654"
   ],
   "match": {
    "tech": "dojo",
    "version_lt": "1.2.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-dojo-2018-15494",
   "title": "dojo < 1.14 \u2014 In Dojo Toolkit before 1.14.0, there is unescaped string injection in dojox/Grid/DataGrid. (CVE-2018-15494)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2018-15494",
   "tech": "dojo",
   "fixed": "1.14",
   "remediation": "Upgrade dojo to >= 1.14.",
   "refs": [
    "https://dojotoolkit.org/blog/dojo-1-14-released"
   ],
   "match": {
    "tech": "dojo",
    "version_lt": "1.14"
   }
  },
  {
   "key": "cve-dojo-2020-5258",
   "title": "dojo < 1.11.10 \u2014 Prototype pollution in dojo (CVE-2020-5258)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2020-5258",
   "tech": "dojo",
   "fixed": "1.11.10",
   "remediation": "Upgrade dojo to >= 1.11.10.",
   "refs": [
    "https://github.com/advisories/GHSA-jxfh-8wgv-vfr2",
    "https://github.com/dojo/dojo/security/advisories/GHSA-jxfh-8wgv-vfr2"
   ],
   "match": {
    "tech": "dojo",
    "version_lt": "1.11.10"
   },
   "cwe": "CWE-1321"
  },
  {
   "key": "cve-dojo-2021-23450",
   "title": "dojo < 1.16.5 \u2014 Prototype pollution (CVE-2021-23450)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2021-23450",
   "tech": "dojo",
   "fixed": "1.16.5",
   "remediation": "Upgrade dojo to >= 1.16.5.",
   "refs": [
    "https://github.com/dojo/dojo/pull/418"
   ],
   "match": {
    "tech": "dojo",
    "version_lt": "1.16.5"
   },
   "cwe": "CWE-1321"
  },
  {
   "key": "cve-dompurify-2019-16728",
   "title": "DOMPurify < 2.0.3 \u2014 Fixed an mXSS-based bypass caused by nested forms inside MathML (CVE-2019-16728)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2019-16728",
   "tech": "dompurify",
   "fixed": "2.0.3",
   "remediation": "Upgrade DOMPurify to >= 2.0.3.",
   "refs": [
    "https://github.com/cure53/DOMPurify/releases"
   ],
   "match": {
    "tech": "dompurify",
    "version_lt": "2.0.3"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-dompurify-2019-25155",
   "title": "DOMPurify < 1.0.11 \u2014 DOMPurify Open Redirect vulnerability (CVE-2019-25155)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2019-25155",
   "tech": "dompurify",
   "fixed": "1.0.11",
   "remediation": "Upgrade DOMPurify to >= 1.0.11.",
   "refs": [
    "https://github.com/advisories/GHSA-8hgg-xxm5-3873",
    "https://nvd.nist.gov/vuln/detail/CVE-2019-25155",
    "https://github.com/cure53/DOMPurify/pull/337",
    "https://github.com/cure53/DOMPurify/commit/7601c33a57e029cce51d910eda5179a3f1b51c83",
    "https://github.com/cure53/DOMPurify",
    "https://github.com/cure53/DOMPurify/compare/1.0.10...1.0.11"
   ],
   "match": {
    "tech": "dompurify",
    "version_lt": "1.0.11"
   },
   "cwe": "CWE-601"
  },
  {
   "key": "cve-dompurify-2020-26870",
   "title": "DOMPurify < 2.0.17 \u2014 Fixed another bypass causing mXSS by using MathML (CVE-2020-26870)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-26870",
   "tech": "dompurify",
   "fixed": "2.0.17",
   "remediation": "Upgrade DOMPurify to >= 2.0.17.",
   "refs": [
    "https://github.com/cure53/DOMPurify/releases"
   ],
   "match": {
    "tech": "dompurify",
    "version_lt": "2.0.17"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-dompurify-2024-45801",
   "title": "DOMPurify < 2.5.4 \u2014 DOMPurify allows tampering by prototype pollution (CVE-2024-45801)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2024-45801",
   "tech": "dompurify",
   "fixed": "2.5.4",
   "remediation": "Upgrade DOMPurify to >= 2.5.4.",
   "refs": [
    "https://github.com/advisories/GHSA-mmhx-hmjr-r674",
    "https://github.com/cure53/DOMPurify/security/advisories/GHSA-mmhx-hmjr-r674",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-45801",
    "https://github.com/cure53/DOMPurify/commit/1e520262bf4c66b5efda49e2316d6d1246ca7b21",
    "https://github.com/cure53/DOMPurify/commit/26e1d69ca7f769f5c558619d644d90dd8bf26ebc",
    "https://github.com/cure53/DOMPurify"
   ],
   "match": {
    "tech": "dompurify",
    "version_lt": "2.5.4"
   },
   "cwe": "CWE-1321"
  },
  {
   "key": "cve-dompurify-2024-47875",
   "title": "DOMPurify < 2.5.0 \u2014 DOMpurify has a nesting-based mXSS (CVE-2024-47875)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2024-47875",
   "tech": "dompurify",
   "fixed": "2.5.0",
   "remediation": "Upgrade DOMPurify to >= 2.5.0.",
   "refs": [
    "https://github.com/advisories/GHSA-gx9m-whjm-85jf",
    "https://github.com/cure53/DOMPurify/security/advisories/GHSA-gx9m-whjm-85jf",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-47875",
    "https://github.com/cure53/DOMPurify/commit/0ef5e537a514f904b6aa1d7ad9e749e365d7185f",
    "https://github.com/cure53/DOMPurify/commit/6ea80cd8b47640c20f2f230c7920b1f4ce4fdf7a",
    "https://github.com/cure53/DOMPurify",
    "https://github.com/cure53/DOMPurify/blob/0ef5e537a514f904b6aa1d7ad9e749e365d7185f/test/test-suite.js#L2098"
   ],
   "match": {
    "tech": "dompurify",
    "version_lt": "2.5.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-dompurify-2024-48910",
   "title": "DOMPurify < 2.4.2 \u2014 DOMPurify vulnerable to tampering by prototype polution (CVE-2024-48910)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2024-48910",
   "tech": "dompurify",
   "fixed": "2.4.2",
   "remediation": "Upgrade DOMPurify to >= 2.4.2.",
   "refs": [
    "https://github.com/advisories/GHSA-p3vf-v8qc-cwcr",
    "https://github.com/cure53/DOMPurify/security/advisories/GHSA-p3vf-v8qc-cwcr",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-48910",
    "https://github.com/cure53/DOMPurify/commit/d1dd0374caef2b4c56c3bd09fe1988c3479166dc",
    "https://github.com/cure53/DOMPurify"
   ],
   "match": {
    "tech": "dompurify",
    "version_lt": "2.4.2"
   }
  },
  {
   "key": "cve-dompurify-2025-15599",
   "title": "DOMPurify < 2.5.9 \u2014 DOMPurify 3.1.3 through 3.2.6 and 2.5.3 through 2.5.8 contain a cross-site scripting vulnerability that allows attackers",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2025-15599",
   "tech": "dompurify",
   "fixed": "2.5.9",
   "remediation": "Upgrade DOMPurify to >= 2.5.9.",
   "refs": [
    "https://github.com/cure53/DOMPurify/commit/c861f5a83fb8d90800f1680f855fee551161ac2b",
    "https://www.vulncheck.com/advisories/dompurify-xss-via-textarea-rawtext-bypass-in-safe-for-xml",
    "https://www.vulncheck.com/advisories/dompurify-xss-via-textarea-rawtext-bypass-in-safeforxml"
   ],
   "match": {
    "tech": "dompurify",
    "version_lt": "2.5.9"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-dompurify-2025-26791",
   "title": "DOMPurify < 3.2.4 \u2014 DOMPurify allows Cross-site Scripting (XSS) (CVE-2025-26791)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2025-26791",
   "tech": "dompurify",
   "fixed": "3.2.4",
   "remediation": "Upgrade DOMPurify to >= 3.2.4.",
   "refs": [
    "https://github.com/advisories/GHSA-vhxf-7vqr-mrjg",
    "https://nvd.nist.gov/vuln/detail/CVE-2025-26791",
    "https://github.com/cure53/DOMPurify/commit/d18ffcb554e0001748865da03ac75dd7829f0f02",
    "https://ensy.zip/posts/dompurify-323-bypass",
    "https://github.com/cure53/DOMPurify",
    "https://github.com/cure53/DOMPurify/releases/tag/3.2.4",
    "https://nsysean.github.io/posts/dompurify-323-bypass"
   ],
   "match": {
    "tech": "dompurify",
    "version_lt": "3.2.4"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-dompurify-2026-0540",
   "title": "DOMPurify < 2.5.9 \u2014 DOMPurify 3.1.3-3.3.1 and 2.5.3-2.5.8 contain a cross-site scripting vulnerability allowing bypass of attribute sanitiza",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-0540",
   "tech": "dompurify",
   "fixed": "2.5.9",
   "remediation": "Upgrade DOMPurify to >= 2.5.9.",
   "refs": [
    "https://github.com/cure53/DOMPurify/commit/fca0a938b4261ddc9c0293a289935a9029c049f5",
    "https://www.vulncheck.com/advisories/dompurify-xss-via-missing-rawtext-elements-in-safe-for-xml",
    "https://www.vulncheck.com/advisories/dompurify-xss-via-missing-rawtext-elements-in-safeforxml"
   ],
   "match": {
    "tech": "dompurify",
    "version_lt": "2.5.9"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-dompurify-2026-41238",
   "title": "DOMPurify < 3.4.0 \u2014 DOMPurify versions 3.0.1 through 3.3.3 are vulnerable to an XSS bypass via prototype pollution. When no CUSTOM_ELEMENT_H",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-41238",
   "tech": "dompurify",
   "fixed": "3.4.0",
   "remediation": "Upgrade DOMPurify to >= 3.4.0.",
   "refs": [
    "https://github.com/cure53/DOMPurify/security/advisories/GHSA-v9jr-rg53-9pgp",
    "https://github.com/cure53/DOMPurify/releases/tag/3.4.0"
   ],
   "match": {
    "tech": "dompurify",
    "version_lt": "3.4.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-dompurify-2026-41239",
   "title": "DOMPurify < 3.4.0 \u2014 DOMPurify's SAFE_FOR_TEMPLATES feature fails to strip Mustache/template expressions when RETURN_DOM or RETURN_DOM_FRAGME",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-41239",
   "tech": "dompurify",
   "fixed": "3.4.0",
   "remediation": "Upgrade DOMPurify to >= 3.4.0.",
   "refs": [
    "https://github.com/cure53/DOMPurify/security/advisories/GHSA-crv5-9vww-q3g8",
    "https://github.com/cure53/DOMPurify/releases/tag/3.4.0"
   ],
   "match": {
    "tech": "dompurify",
    "version_lt": "3.4.0"
   }
  },
  {
   "key": "cve-dompurify-2026-41240",
   "title": "DOMPurify < 3.4.0 \u2014 DOMPurify has an asymmetric security inconsistency where FORBID_TAGS does not win over a function-based ADD_TAGS predica",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-41240",
   "tech": "dompurify",
   "fixed": "3.4.0",
   "remediation": "Upgrade DOMPurify to >= 3.4.0.",
   "refs": [
    "https://github.com/cure53/DOMPurify/security/advisories/GHSA-h7mw-gpvr-xq4m",
    "https://github.com/cure53/DOMPurify/releases/tag/3.4.0"
   ],
   "match": {
    "tech": "dompurify",
    "version_lt": "3.4.0"
   }
  },
  {
   "key": "cve-dompurify-2026-47423",
   "title": "DOMPurify < 3.4.5 \u2014 DOMPurify XSS via selectedcontent re-clone (CVE-2026-47423)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2026-47423",
   "tech": "dompurify",
   "fixed": "3.4.5",
   "remediation": "Upgrade DOMPurify to >= 3.4.5.",
   "refs": [
    "https://github.com/cure53/DOMPurify/security/advisories/GHSA-87xg-pxx2-7hvx"
   ],
   "match": {
    "tech": "dompurify",
    "version_lt": "3.4.5"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-dompurify-2026-49458",
   "title": "DOMPurify < 3.4.6 \u2014 DOMPurify: Cross-realm IN_PLACE sanitization leaves executable markup intact via realm-bound `instanceof` checks (CVE-20",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-49458",
   "tech": "dompurify",
   "fixed": "3.4.6",
   "remediation": "Upgrade DOMPurify to >= 3.4.6.",
   "refs": [
    "https://github.com/cure53/DOMPurify/security/advisories/GHSA-hpcv-96wg-7vj8"
   ],
   "match": {
    "tech": "dompurify",
    "version_lt": "3.4.6"
   }
  },
  {
   "key": "cve-dompurify-2026-49459",
   "title": "DOMPurify < 3.4.6 \u2014 DOMPurify: IN_PLACE mode preserves attributes of a clobbered root element, allowing XSS via attacker-controlled root DOM",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-49459",
   "tech": "dompurify",
   "fixed": "3.4.6",
   "remediation": "Upgrade DOMPurify to >= 3.4.6.",
   "refs": [
    "https://github.com/cure53/DOMPurify/security/advisories/GHSA-r47g-fvhr-h676"
   ],
   "match": {
    "tech": "dompurify",
    "version_lt": "3.4.6"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-dompurify-2026-49978",
   "title": "DOMPurify < 3.4.7 \u2014 DOMPurify IN_PLACE Sanitization Bypass via Attached Shadow Root Inside <template>.content (CVE-2026-49978)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-49978",
   "tech": "dompurify",
   "fixed": "3.4.7",
   "remediation": "Upgrade DOMPurify to >= 3.4.7.",
   "refs": [
    "https://github.com/cure53/DOMPurify/security/advisories/GHSA-rp9w-3fw7-7cwq"
   ],
   "match": {
    "tech": "dompurify",
    "version_lt": "3.4.7"
   }
  },
  {
   "key": "cve-dompurify-2026-65898",
   "title": "DOMPurify < 3.4.11 \u2014 DOMPurify: Permanent `ALLOWED_ATTR` pollution via `setConfig()` bypassing the hook clone-guard (incomplete fix of the 3",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-65898",
   "tech": "dompurify",
   "fixed": "3.4.11",
   "remediation": "Upgrade DOMPurify to >= 3.4.11.",
   "refs": [
    "https://github.com/cure53/DOMPurify/security/advisories/GHSA-cmwh-pvxp-8882"
   ],
   "match": {
    "tech": "dompurify",
    "version_lt": "3.4.11"
   }
  },
  {
   "key": "cve-dompurify-2026-65899",
   "title": "DOMPurify < 3.4.9 \u2014 DOMPurify: Trusted Types policy survives `clearConfig()` and can poison later `RETURN_TRUSTED_TYPE` output (CVE-2026-658",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2026-65899",
   "tech": "dompurify",
   "fixed": "3.4.9",
   "remediation": "Upgrade DOMPurify to >= 3.4.9.",
   "refs": [
    "https://github.com/cure53/DOMPurify/security/advisories/GHSA-vxr8-fq34-vvx9"
   ],
   "match": {
    "tech": "dompurify",
    "version_lt": "3.4.9"
   }
  },
  {
   "key": "cve-dompurify-2026-65900",
   "title": "DOMPurify < 3.4.8 \u2014 DOMPurify: SAFE_FOR_TEMPLATES bypass - template expressions survive sanitization inside <template> content when using DO",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2026-65900",
   "tech": "dompurify",
   "fixed": "3.4.8",
   "remediation": "Upgrade DOMPurify to >= 3.4.8.",
   "refs": [
    "https://github.com/cure53/DOMPurify/security/advisories/GHSA-gvmj-g25r-r7wr"
   ],
   "match": {
    "tech": "dompurify",
    "version_lt": "3.4.8"
   }
  },
  {
   "key": "cve-dompurify-2026-65901",
   "title": "DOMPurify < 3.4.7 \u2014 DOMPurify: `IN_PLACE` mode trusts attacker-controlled `nodeName` on live non-form nodes, allowing script retention and X",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2026-65901",
   "tech": "dompurify",
   "fixed": "3.4.7",
   "remediation": "Upgrade DOMPurify to >= 3.4.7.",
   "refs": [
    "https://github.com/cure53/DOMPurify/security/advisories/GHSA-x4vx-rjvf-j5p4"
   ],
   "match": {
    "tech": "dompurify",
    "version_lt": "3.4.7"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-dompurify-2026-65902",
   "title": "DOMPurify < 3.4.7 \u2014 DOMPurify: Hook mutation of `data.allowedTags` / `data.allowedAttributes` permanently pollutes `DEFAULT_ALLOWED_TAGS` / ",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-65902",
   "tech": "dompurify",
   "fixed": "3.4.7",
   "remediation": "Upgrade DOMPurify to >= 3.4.7.",
   "refs": [
    "https://github.com/cure53/DOMPurify/security/advisories/GHSA-76mc-f452-cxcm"
   ],
   "match": {
    "tech": "dompurify",
    "version_lt": "3.4.7"
   }
  },
  {
   "key": "cve-dompurify-2026-65903",
   "title": "DOMPurify < 3.4.0 \u2014 DOMPurify has a logic inconsistency where FORBID_TAGS is not checked when a function-based ADD_TAGS (tagCheck) returns t",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-65903",
   "tech": "dompurify",
   "fixed": "3.4.0",
   "remediation": "Upgrade DOMPurify to >= 3.4.0.",
   "refs": [
    "https://github.com/cure53/DOMPurify/security/advisories/GHSA-39q2-94rc-95cp"
   ],
   "match": {
    "tech": "dompurify",
    "version_lt": "3.4.0"
   }
  },
  {
   "key": "cve-dompurify-2026-65912",
   "title": "DOMPurify < 3.3.2 \u2014 DOMPurify's ADD_ATTR predicate function mechanism (via EXTRA_ELEMENT_HANDLING.attributeCheck) short-circuits URI validat",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-65912",
   "tech": "dompurify",
   "fixed": "3.3.2",
   "remediation": "Upgrade DOMPurify to >= 3.3.2.",
   "refs": [
    "https://github.com/cure53/DOMPurify/security/advisories/GHSA-cjmm-f4jc-qw8r",
    "https://github.com/cure53/DOMPurify/releases/tag/3.3.2"
   ],
   "match": {
    "tech": "dompurify",
    "version_lt": "3.3.2"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-dompurify-2026-65913",
   "title": "DOMPurify < 3.3.2 \u2014 When USE_PROFILES is enabled, DOMPurify rebuilds ALLOWED_ATTR as a plain array whose properties are looked up by name, m",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-65913",
   "tech": "dompurify",
   "fixed": "3.3.2",
   "remediation": "Upgrade DOMPurify to >= 3.3.2.",
   "refs": [
    "https://github.com/cure53/DOMPurify/security/advisories/GHSA-cj63-jhhr-wcxv",
    "https://github.com/cure53/DOMPurify/releases/tag/3.3.2"
   ],
   "match": {
    "tech": "dompurify",
    "version_lt": "3.3.2"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-dompurify-2026-65914",
   "title": "DOMPurify < 3.3.2 \u2014 DOMPurify is vulnerable to mutation-XSS (mXSS) when sanitized HTML is embedded into special raw-text wrapper elements su",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-65914",
   "tech": "dompurify",
   "fixed": "3.3.2",
   "remediation": "Upgrade DOMPurify to >= 3.3.2.",
   "refs": [
    "https://github.com/cure53/DOMPurify/security/advisories/GHSA-h8r8-wccr-v5f2",
    "https://github.com/cure53/DOMPurify/releases/tag/3.3.2"
   ],
   "match": {
    "tech": "dompurify",
    "version_lt": "3.3.2"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-dompurify-2026-66010",
   "title": "DOMPurify < 3.4.12 \u2014 DOMPurify: `CUSTOM_ELEMENT_HANDLING` bypasses `afterSanitizeElements` for allowed custom elements. (CVE-2026-66010)",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2026-66010",
   "tech": "dompurify",
   "fixed": "3.4.12",
   "remediation": "Upgrade DOMPurify to >= 3.4.12.",
   "refs": [
    "https://github.com/cure53/DOMPurify/security/advisories/GHSA-c2j3-45gr-mqc4",
    "https://github.com/cure53/DOMPurify/pull/1537",
    "https://github.com/cure53/DOMPurify/commit/a9ca1e537422319a557a9a2aa61f003b23b4a197",
    "https://github.com/cure53/DOMPurify/releases/tag/3.4.12"
   ],
   "match": {
    "tech": "dompurify",
    "version_lt": "3.4.12"
   }
  },
  {
   "key": "cve-dompurify-2026-75838",
   "title": "DOMPurify < 3.4.13 \u2014 DOMPurify: IN_PLACE hook removal leaves a detached subtree executable, causing XSS (CVE-2026-75838)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-75838",
   "tech": "dompurify",
   "fixed": "3.4.13",
   "remediation": "Upgrade DOMPurify to >= 3.4.13.",
   "refs": [
    "https://github.com/cure53/DOMPurify/security/advisories/GHSA-55q2-fjhq-7xh7",
    "https://github.com/cure53/DOMPurify/pull/1557",
    "https://github.com/cure53/DOMPurify/commit/3067f7746769",
    "https://github.com/cure53/DOMPurify/releases/tag/3.4.13"
   ],
   "match": {
    "tech": "dompurify",
    "version_lt": "3.4.13"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-drupal-2011-2687",
   "title": "drupal < 7.3 \u2014 Drupal Access Control Bypass (CVE-2011-2687)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2011-2687",
   "tech": "drupal",
   "fixed": "7.3",
   "remediation": "Upgrade drupal to >= 7.3.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2011-2687",
    "https://bugzilla.redhat.com/show_bug.cgi?id=717874",
    "https://web.archive.org/web/20110710024036/http://www.securityfocus.com/bid/48505"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "7.3"
   }
  },
  {
   "key": "cve-drupal-2016-3162",
   "title": "drupal < 7.43 \u2014 Drupal File upload access bypass and denial of service (CVE-2016-3162)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2016-3162",
   "tech": "drupal",
   "fixed": "7.43",
   "remediation": "Upgrade drupal to >= 7.43.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2016-3162",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2016-3162.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2016-3162.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "7.43"
   },
   "cwe": "CWE-400"
  },
  {
   "key": "cve-drupal-2016-3163",
   "title": "drupal < 6.38 \u2014 Drupal Brute force amplification attacks via XML-RPC (CVE-2016-3163)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2016-3163",
   "tech": "drupal",
   "fixed": "6.38",
   "remediation": "Upgrade drupal to >= 6.38.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2016-3163",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2016-3163.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2016-3163.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "6.38"
   },
   "cwe": "CWE-94"
  },
  {
   "key": "cve-drupal-2016-3164",
   "title": "drupal < 6.38 \u2014 Drupal Open Redirect (CVE-2016-3164)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2016-3164",
   "tech": "drupal",
   "fixed": "6.38",
   "remediation": "Upgrade drupal to >= 6.38.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2016-3164",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2016-3164.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2016-3164.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "6.38"
   },
   "cwe": "CWE-601"
  },
  {
   "key": "cve-drupal-2016-3165",
   "title": "drupal < 6.38 \u2014 Drupal Form API ignores access restrictions on submit buttons (CVE-2016-3165)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2016-3165",
   "tech": "drupal",
   "fixed": "6.38",
   "remediation": "Upgrade drupal to >= 6.38.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2016-3165",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2016-3165.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2016-3165.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "6.38"
   }
  },
  {
   "key": "cve-drupal-2016-3166",
   "title": "drupal < 6.38 \u2014 Drupal CRLF injection vulnerability in the drupal_set_header function (CVE-2016-3166)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2016-3166",
   "tech": "drupal",
   "fixed": "6.38",
   "remediation": "Upgrade drupal to >= 6.38.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2016-3166",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2016-3166.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2016-3166.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "6.38"
   }
  },
  {
   "key": "cve-drupal-2016-3167",
   "title": "drupal < 6.38 \u2014 Drupal Open redirect vulnerability in the drupal_goto function (CVE-2016-3167)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2016-3167",
   "tech": "drupal",
   "fixed": "6.38",
   "remediation": "Upgrade drupal to >= 6.38.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2016-3167",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2016-3167.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2016-3167.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "6.38"
   },
   "cwe": "CWE-601"
  },
  {
   "key": "cve-drupal-2016-3168",
   "title": "drupal < 6.38 \u2014 Drupal Reflected file download vulnerability (CVE-2016-3168)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2016-3168",
   "tech": "drupal",
   "fixed": "6.38",
   "remediation": "Upgrade drupal to >= 6.38.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2016-3168",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2016-3168.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2016-3168.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "6.38"
   }
  },
  {
   "key": "cve-drupal-2016-3169",
   "title": "drupal < 6.38 \u2014 Drupal saving user accounts can sometimes grant the user all roles (CVE-2016-3169)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2016-3169",
   "tech": "drupal",
   "fixed": "6.38",
   "remediation": "Upgrade drupal to >= 6.38.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2016-3169",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2016-3169.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2016-3169.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "6.38"
   }
  },
  {
   "key": "cve-drupal-2016-3170",
   "title": "drupal < 7.43 \u2014 Drupal sensitive information disclosure (CVE-2016-3170)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2016-3170",
   "tech": "drupal",
   "fixed": "7.43",
   "remediation": "Upgrade drupal to >= 7.43.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2016-3170",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2016-3170.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2016-3170.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "7.43"
   }
  },
  {
   "key": "cve-drupal-2016-3171",
   "title": "drupal < 6.38 \u2014 Drupal arbitrary code execution (CVE-2016-3171)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2016-3171",
   "tech": "drupal",
   "fixed": "6.38",
   "remediation": "Upgrade drupal to >= 6.38.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2016-3171",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2016-3171.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2016-3171.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "6.38"
   }
  },
  {
   "key": "cve-drupal-2016-5385",
   "title": "drupal < 1.1.2 \u2014 HTTP Proxy header vulnerability (CVE-2016-5385)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2016-5385",
   "tech": "drupal",
   "fixed": "1.1.2",
   "remediation": "Upgrade drupal to >= 1.1.2.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2016-5385",
    "https://github.com/bugsnag/bugsnag-laravel/pull/143",
    "https://github.com/bugsnag/bugsnag-laravel/pull/145"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "1.1.2"
   }
  },
  {
   "key": "cve-drupal-2016-6211",
   "title": "drupal < 7.44 \u2014 Drupal Saving user accounts can sometimes grant the user all roles (CVE-2016-6211)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2016-6211",
   "tech": "drupal",
   "fixed": "7.44",
   "remediation": "Upgrade drupal to >= 7.44.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2016-6211",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2016-6211.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2016-6211.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "7.44"
   }
  },
  {
   "key": "cve-drupal-2016-6212",
   "title": "drupal < 8.1.3 \u2014 Drupal Views can allow unauthorized users to see Statistics information (CVE-2016-6212)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2016-6212",
   "tech": "drupal",
   "fixed": "8.1.3",
   "remediation": "Upgrade drupal to >= 8.1.3.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2016-6212",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2016-6212.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2016-6212.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.1.3"
   }
  },
  {
   "key": "cve-drupal-2016-7570",
   "title": "drupal < 8.1.10 \u2014 Drupal Users without \"Administer comments\" can set comment visibility on nodes they can edit (CVE-2016-7570)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2016-7570",
   "tech": "drupal",
   "fixed": "8.1.10",
   "remediation": "Upgrade drupal to >= 8.1.10.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2016-7570",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2016-7570.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2016-7570.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.1.10"
   }
  },
  {
   "key": "cve-drupal-2016-7571",
   "title": "drupal < 8.1.10 \u2014 Drupal Cross-site scripting (XSS) vulnerability (CVE-2016-7571)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2016-7571",
   "tech": "drupal",
   "fixed": "8.1.10",
   "remediation": "Upgrade drupal to >= 8.1.10.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2016-7571",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2016-7571.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2016-7571.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.1.10"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-drupal-2016-7572",
   "title": "drupal < 8.1.10 \u2014 Drupal Unprivileged access to config export (CVE-2016-7572)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2016-7572",
   "tech": "drupal",
   "fixed": "8.1.10",
   "remediation": "Upgrade drupal to >= 8.1.10.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2016-7572",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2016-7572.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2016-7572.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.1.10"
   }
  },
  {
   "key": "cve-drupal-2016-9449",
   "title": "drupal < 7.52 \u2014 Drupal sensitive information disclosure (CVE-2016-9449)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2016-9449",
   "tech": "drupal",
   "fixed": "7.52",
   "remediation": "Upgrade drupal to >= 7.52.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2016-9449",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2016-9449.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2016-9449.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "7.52"
   }
  },
  {
   "key": "cve-drupal-2016-9450",
   "title": "drupal < 8.2.3 \u2014 Drupal Incorrect cache context on password reset page (CVE-2016-9450)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2016-9450",
   "tech": "drupal",
   "fixed": "8.2.3",
   "remediation": "Upgrade drupal to >= 8.2.3.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2016-9450",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2016-9450.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2016-9450.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.2.3"
   }
  },
  {
   "key": "cve-drupal-2016-9451",
   "title": "drupal < 8.2.3 \u2014 Drupal Open Redirect (CVE-2016-9451)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2016-9451",
   "tech": "drupal",
   "fixed": "8.2.3",
   "remediation": "Upgrade drupal to >= 8.2.3.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2016-9451",
    "https://github.com/drupal/core",
    "https://www.drupal.org/SA-CORE-2016-005"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.2.3"
   },
   "cwe": "CWE-601"
  },
  {
   "key": "cve-drupal-2016-9452",
   "title": "drupal < 8.2.3 \u2014 Drupal Denial of service via transliterate mechanism (CVE-2016-9452)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2016-9452",
   "tech": "drupal",
   "fixed": "8.2.3",
   "remediation": "Upgrade drupal to >= 8.2.3.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2016-9452",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2016-9452.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2016-9452.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.2.3"
   },
   "cwe": "CWE-400"
  },
  {
   "key": "cve-drupal-2017-6377",
   "title": "drupal < 8.2.7 \u2014 Drupal editor module incorrectly checks access to inline private files (CVE-2017-6377)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2017-6377",
   "tech": "drupal",
   "fixed": "8.2.7",
   "remediation": "Upgrade drupal to >= 8.2.7.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-6377",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2017-6377.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2017-6377.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.2.7"
   }
  },
  {
   "key": "cve-drupal-2017-6379",
   "title": "drupal < 8.2.7 \u2014 Drupal Cross-Site Request Forgery (CSRF) (CVE-2017-6379)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2017-6379",
   "tech": "drupal",
   "fixed": "8.2.7",
   "remediation": "Upgrade drupal to >= 8.2.7.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-6379",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2017-6379.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2017-6379.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.2.7"
   },
   "cwe": "CWE-352"
  },
  {
   "key": "cve-drupal-2017-6381",
   "title": "drupal < 8.2.7 \u2014 Drupal Remote code execution (CVE-2017-6381)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2017-6381",
   "tech": "drupal",
   "fixed": "8.2.7",
   "remediation": "Upgrade drupal to >= 8.2.7.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-6381",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2017-6381.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2017-6381.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.2.7"
   },
   "cwe": "CWE-94"
  },
  {
   "key": "cve-drupal-2017-6919",
   "title": "drupal < 8.3.1 \u2014 Drupal access control bypass vulnerability (CVE-2017-6919)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2017-6919",
   "tech": "drupal",
   "fixed": "8.3.1",
   "remediation": "Upgrade drupal to >= 8.3.1.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-6919",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2017-6919.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2017-6919.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.3.1"
   }
  },
  {
   "key": "cve-drupal-2017-6920",
   "title": "drupal < 8.3.4 \u2014 Drupal PECL YAML parser unsafe object handling (CVE-2017-6920)",
   "category": "cve",
   "severity": "critical",
   "confidence": "candidate",
   "cve": "CVE-2017-6920",
   "tech": "drupal",
   "fixed": "8.3.4",
   "remediation": "Upgrade drupal to >= 8.3.4.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-6920",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2017-6920.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2017-6920.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.3.4"
   }
  },
  {
   "key": "cve-drupal-2017-6921",
   "title": "drupal < 8.3.4 \u2014 Drupal file REST resource does not properly validate (CVE-2017-6921)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2017-6921",
   "tech": "drupal",
   "fixed": "8.3.4",
   "remediation": "Upgrade drupal to >= 8.3.4.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-6921",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2017-6921.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2017-6921.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.3.4"
   },
   "cwe": "CWE-94"
  },
  {
   "key": "cve-drupal-2017-6922",
   "title": "drupal < 7.56 \u2014 Drupal core access bypass vulnerability (CVE-2017-6922)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2017-6922",
   "tech": "drupal",
   "fixed": "7.56",
   "remediation": "Upgrade drupal to >= 7.56.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-6922",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2017-6922.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2017-6922.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "7.56"
   }
  },
  {
   "key": "cve-drupal-2017-6923",
   "title": "drupal < 8.3.7 \u2014 Missing Authorization in Drupal (CVE-2017-6923)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2017-6923",
   "tech": "drupal",
   "fixed": "8.3.7",
   "remediation": "Upgrade drupal to >= 8.3.7.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-6923",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2017-6923.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2017-6923.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.3.7"
   }
  },
  {
   "key": "cve-drupal-2017-6924",
   "title": "drupal < 8.3.7 \u2014 Drupal REST API can bypass comment approval (CVE-2017-6924)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2017-6924",
   "tech": "drupal",
   "fixed": "8.3.7",
   "remediation": "Upgrade drupal to >= 8.3.7.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-6924",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2017-6924.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2017-6924.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.3.7"
   }
  },
  {
   "key": "cve-drupal-2017-6925",
   "title": "drupal < 8.3.7 \u2014 Drupal Entity access bypass for entities that do not have UUIDs or have protected revisions (CVE-2017-6925)",
   "category": "cve",
   "severity": "critical",
   "confidence": "candidate",
   "cve": "CVE-2017-6925",
   "tech": "drupal",
   "fixed": "8.3.7",
   "remediation": "Upgrade drupal to >= 8.3.7.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-6925",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2017-6925.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2017-6925.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.3.7"
   }
  },
  {
   "key": "cve-drupal-2017-6926",
   "title": "drupal < 7.57 \u2014 Drupal Comment reply form allows access to restricted content (CVE-2017-6926)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2017-6926",
   "tech": "drupal",
   "fixed": "7.57",
   "remediation": "Upgrade drupal to >= 7.57.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-6926",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2017-6926.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2017-6926.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "7.57"
   }
  },
  {
   "key": "cve-drupal-2017-6927",
   "title": "drupal < 7.57 \u2014 Drupal cross-site scripting vulnerability (CVE-2017-6927)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2017-6927",
   "tech": "drupal",
   "fixed": "7.57",
   "remediation": "Upgrade drupal to >= 7.57.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-6927",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2017-6927.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2017-6927.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "7.57"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-drupal-2017-6928",
   "title": "drupal < 7.57 \u2014 Drupal access bypass vulnerability (CVE-2017-6928)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2017-6928",
   "tech": "drupal",
   "fixed": "7.57",
   "remediation": "Upgrade drupal to >= 7.57.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-6928",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2017-6928.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2017-6928.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "7.57"
   }
  },
  {
   "key": "cve-drupal-2017-6929",
   "title": "drupal < 7.57 \u2014 Drupal cross site scripting vulnerability (CVE-2017-6929)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2017-6929",
   "tech": "drupal",
   "fixed": "7.57",
   "remediation": "Upgrade drupal to >= 7.57.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-6929",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2017-6929.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2017-6929.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "7.57"
   }
  },
  {
   "key": "cve-drupal-2017-6930",
   "title": "drupal < 8.4.5 \u2014 Drupal access bypass vulnerability (CVE-2017-6930)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2017-6930",
   "tech": "drupal",
   "fixed": "8.4.5",
   "remediation": "Upgrade drupal to >= 8.4.5.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-6930",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2017-6930.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2017-6930.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.4.5"
   }
  },
  {
   "key": "cve-drupal-2017-6931",
   "title": "drupal < 8.4.5 \u2014 Drupal Settings Tray access bypass (CVE-2017-6931)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2017-6931",
   "tech": "drupal",
   "fixed": "8.4.5",
   "remediation": "Upgrade drupal to >= 8.4.5.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-6931",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2017-6931.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2017-6931.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.4.5"
   }
  },
  {
   "key": "cve-drupal-2017-6932",
   "title": "drupal < 7.57 \u2014 Drupal external link injection vulnerability (CVE-2017-6932)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2017-6932",
   "tech": "drupal",
   "fixed": "7.57",
   "remediation": "Upgrade drupal to >= 7.57.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-6932",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2017-6932.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2017-6932.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "7.57"
   }
  },
  {
   "key": "cve-drupal-2018-7600",
   "title": "drupal < 8.5.1 \u2014 drupal vulnerability (CVE-2018-7600)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2018-7600",
   "tech": "drupal",
   "fixed": "8.5.1",
   "remediation": "Upgrade drupal to >= 8.5.1.",
   "refs": [
    "https://www.drupal.org/sa-core-2018-002"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.5.1"
   }
  },
  {
   "key": "cve-drupal-2018-7602",
   "title": "drupal < 8.5.3 \u2014 drupal vulnerability (CVE-2018-7602)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2018-7602",
   "tech": "drupal",
   "fixed": "8.5.3",
   "remediation": "Upgrade drupal to >= 8.5.3.",
   "refs": [
    "https://www.drupal.org/sa-core-2018-004"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.5.3"
   }
  },
  {
   "key": "cve-drupal-2018-9861",
   "title": "drupal < 8.5.2 \u2014 drupal vulnerability (CVE-2018-9861)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2018-9861",
   "tech": "drupal",
   "fixed": "8.5.2",
   "remediation": "Upgrade drupal to >= 8.5.2.",
   "refs": [
    "https://www.drupal.org/sa-core-2018-003"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.5.2"
   }
  },
  {
   "key": "cve-drupal-2019-11358",
   "title": "drupal < 8.6.15 \u2014 drupal vulnerability (CVE-2019-11358)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2019-11358",
   "tech": "drupal",
   "fixed": "8.6.15",
   "remediation": "Upgrade drupal to >= 8.6.15.",
   "refs": [
    "https://www.drupal.org/sa-core-2019-006"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.6.15"
   }
  },
  {
   "key": "cve-drupal-2019-11831",
   "title": "drupal < 8.7.1 \u2014 drupal vulnerability (CVE-2019-11831)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2019-11831",
   "tech": "drupal",
   "fixed": "8.7.1",
   "remediation": "Upgrade drupal to >= 8.7.1.",
   "refs": [
    "https://www.drupal.org/sa-core-2019-007"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.7.1"
   }
  },
  {
   "key": "cve-drupal-2019-6338",
   "title": "drupal < 8.6.6 \u2014 drupal vulnerability (CVE-2019-6338)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2019-6338",
   "tech": "drupal",
   "fixed": "8.6.6",
   "remediation": "Upgrade drupal to >= 8.6.6.",
   "refs": [
    "https://www.drupal.org/sa-core-2019-001"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.6.6"
   }
  },
  {
   "key": "cve-drupal-2019-6339",
   "title": "drupal < 8.6.6 \u2014 drupal vulnerability (CVE-2019-6339)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2019-6339",
   "tech": "drupal",
   "fixed": "8.6.6",
   "remediation": "Upgrade drupal to >= 8.6.6.",
   "refs": [
    "https://www.drupal.org/sa-core-2019-002"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.6.6"
   }
  },
  {
   "key": "cve-drupal-2019-6340",
   "title": "drupal < 8.6.10 \u2014 drupal vulnerability (CVE-2019-6340)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2019-6340",
   "tech": "drupal",
   "fixed": "8.6.10",
   "remediation": "Upgrade drupal to >= 8.6.10.",
   "refs": [
    "https://www.drupal.org/sa-core-2019-003"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.6.10"
   }
  },
  {
   "key": "cve-drupal-2019-6341",
   "title": "drupal < 8.6.13 \u2014 drupal vulnerability (CVE-2019-6341)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2019-6341",
   "tech": "drupal",
   "fixed": "8.6.13",
   "remediation": "Upgrade drupal to >= 8.6.13.",
   "refs": [
    "https://www.drupal.org/sa-core-2019-004"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.6.13"
   }
  },
  {
   "key": "cve-drupal-2019-6342",
   "title": "drupal < 8.7.5 \u2014 drupal vulnerability (CVE-2019-6342)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2019-6342",
   "tech": "drupal",
   "fixed": "8.7.5",
   "remediation": "Upgrade drupal to >= 8.7.5.",
   "refs": [
    "https://www.drupal.org/sa-core-2019-008"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "8.7.5"
   }
  },
  {
   "key": "cve-drupal-2020-13662",
   "title": "drupal < 7.70 \u2014 Drupal Core Open Redirect vulnerability (CVE-2020-13662)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-13662",
   "tech": "drupal",
   "fixed": "7.70",
   "remediation": "Upgrade drupal to >= 7.70.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2020-13662",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2020-13662.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2020-13662.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "7.70"
   },
   "cwe": "CWE-601"
  },
  {
   "key": "cve-drupal-2020-13663",
   "title": "drupal < 9.0.1 \u2014 drupal vulnerability (CVE-2020-13663)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-13663",
   "tech": "drupal",
   "fixed": "9.0.1",
   "remediation": "Upgrade drupal to >= 9.0.1.",
   "refs": [
    "https://www.drupal.org/sa-core-2020-004"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.0.1"
   }
  },
  {
   "key": "cve-drupal-2020-13664",
   "title": "drupal < 9.0.1 \u2014 drupal vulnerability (CVE-2020-13664)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-13664",
   "tech": "drupal",
   "fixed": "9.0.1",
   "remediation": "Upgrade drupal to >= 9.0.1.",
   "refs": [
    "https://www.drupal.org/sa-core-2020-005"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.0.1"
   }
  },
  {
   "key": "cve-drupal-2020-13665",
   "title": "drupal < 9.0.1 \u2014 Drupal Core Access bypass vulnerability (CVE-2020-13665)",
   "category": "cve",
   "severity": "critical",
   "confidence": "candidate",
   "cve": "CVE-2020-13665",
   "tech": "drupal",
   "fixed": "9.0.1",
   "remediation": "Upgrade drupal to >= 9.0.1.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2020-13665",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2020-13665.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/drupal/CVE-2020-13665.yaml"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.0.1"
   }
  },
  {
   "key": "cve-drupal-2020-13665 ",
   "title": "drupal < 9.0.1 \u2014 drupal vulnerability (CVE-2020-13665 )",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-13665 ",
   "tech": "drupal",
   "fixed": "9.0.1",
   "remediation": "Upgrade drupal to >= 9.0.1.",
   "refs": [
    "https://www.drupal.org/sa-core-2020-006"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.0.1"
   }
  },
  {
   "key": "cve-drupal-2020-13666",
   "title": "drupal < 9.0.6 \u2014 drupal vulnerability (CVE-2020-13666)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-13666",
   "tech": "drupal",
   "fixed": "9.0.6",
   "remediation": "Upgrade drupal to >= 9.0.6.",
   "refs": [
    "https://www.drupal.org/sa-core-2020-007"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.0.6"
   }
  },
  {
   "key": "cve-drupal-2020-13667",
   "title": "drupal < 9.0.6 \u2014 drupal vulnerability (CVE-2020-13667)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-13667",
   "tech": "drupal",
   "fixed": "9.0.6",
   "remediation": "Upgrade drupal to >= 9.0.6.",
   "refs": [
    "https://www.drupal.org/sa-core-2020-008"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.0.6"
   }
  },
  {
   "key": "cve-drupal-2020-13668",
   "title": "drupal < 9.0.6 \u2014 Cross-site Scripting in Drupal Core (CVE-2020-13668)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-13668",
   "tech": "drupal",
   "fixed": "9.0.6",
   "remediation": "Upgrade drupal to >= 9.0.6.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2020-13668",
    "https://github.com/drupal/core/commit/3184fa4b2f3b65b44884b5e858cdc7794d34b4c8",
    "https://github.com/drupal/core/commit/58330ba58d1ac6f1a0a549e8dbde8a3e094bf4fb"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.0.6"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-drupal-2020-13669",
   "title": "drupal < 9.0.6 \u2014 drupal vulnerability (CVE-2020-13669)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-13669",
   "tech": "drupal",
   "fixed": "9.0.6",
   "remediation": "Upgrade drupal to >= 9.0.6.",
   "refs": [
    "https://www.drupal.org/sa-core-2020-010"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.0.6"
   }
  },
  {
   "key": "cve-drupal-2020-13670",
   "title": "drupal < 9.0.6 \u2014 drupal vulnerability (CVE-2020-13670)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-13670",
   "tech": "drupal",
   "fixed": "9.0.6",
   "remediation": "Upgrade drupal to >= 9.0.6.",
   "refs": [
    "https://www.drupal.org/sa-core-2020-011"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.0.6"
   }
  },
  {
   "key": "cve-drupal-2020-13671",
   "title": "drupal < 9.0.8 \u2014 drupal vulnerability (CVE-2020-13671)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-13671",
   "tech": "drupal",
   "fixed": "9.0.8",
   "remediation": "Upgrade drupal to >= 9.0.8.",
   "refs": [
    "https://www.drupal.org/sa-core-2020-012"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.0.8"
   }
  },
  {
   "key": "cve-drupal-2020-13672",
   "title": "drupal < 9.1.7 \u2014 drupal vulnerability (CVE-2020-13672)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-13672",
   "tech": "drupal",
   "fixed": "9.1.7",
   "remediation": "Upgrade drupal to >= 9.1.7.",
   "refs": [
    "https://www.drupal.org/sa-core-2021-002"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.1.7"
   }
  },
  {
   "key": "cve-drupal-2020-13673",
   "title": "drupal < 9.2.6 \u2014 drupal vulnerability (CVE-2020-13673)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-13673",
   "tech": "drupal",
   "fixed": "9.2.6",
   "remediation": "Upgrade drupal to >= 9.2.6.",
   "refs": [
    "https://www.drupal.org/sa-core-2021-006"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.2.6"
   }
  },
  {
   "key": "cve-drupal-2020-13674",
   "title": "drupal < 9.2.6 \u2014 drupal vulnerability (CVE-2020-13674)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-13674",
   "tech": "drupal",
   "fixed": "9.2.6",
   "remediation": "Upgrade drupal to >= 9.2.6.",
   "refs": [
    "https://www.drupal.org/sa-core-2021-007"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.2.6"
   }
  },
  {
   "key": "cve-drupal-2020-13675",
   "title": "drupal < 9.2.6 \u2014 drupal vulnerability (CVE-2020-13675)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-13675",
   "tech": "drupal",
   "fixed": "9.2.6",
   "remediation": "Upgrade drupal to >= 9.2.6.",
   "refs": [
    "https://www.drupal.org/sa-core-2021-008"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.2.6"
   }
  },
  {
   "key": "cve-drupal-2020-13676",
   "title": "drupal < 9.2.6 \u2014 drupal vulnerability (CVE-2020-13676)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-13676",
   "tech": "drupal",
   "fixed": "9.2.6",
   "remediation": "Upgrade drupal to >= 9.2.6.",
   "refs": [
    "https://www.drupal.org/sa-core-2021-009"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.2.6"
   }
  },
  {
   "key": "cve-drupal-2020-13677",
   "title": "drupal < 9.2.6 \u2014 drupal vulnerability (CVE-2020-13677)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-13677",
   "tech": "drupal",
   "fixed": "9.2.6",
   "remediation": "Upgrade drupal to >= 9.2.6.",
   "refs": [
    "https://www.drupal.org/sa-core-2021-010"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.2.6"
   }
  },
  {
   "key": "cve-drupal-2020-13688",
   "title": "drupal < 9.0.6 \u2014 drupal vulnerability (CVE-2020-13688)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-13688",
   "tech": "drupal",
   "fixed": "9.0.6",
   "remediation": "Upgrade drupal to >= 9.0.6.",
   "refs": [
    "https://www.drupal.org/sa-core-2020-009"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.0.6"
   }
  },
  {
   "key": "cve-drupal-2020-28948",
   "title": "drupal < 9.0.9 \u2014 drupal vulnerability (CVE-2020-28948)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-28948",
   "tech": "drupal",
   "fixed": "9.0.9",
   "remediation": "Upgrade drupal to >= 9.0.9.",
   "refs": [
    "https://www.drupal.org/sa-core-2020-013"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.0.9"
   }
  },
  {
   "key": "cve-drupal-2021-32610",
   "title": "drupal < 9.2.2 \u2014 drupal vulnerability (CVE-2021-32610)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2021-32610",
   "tech": "drupal",
   "fixed": "9.2.2",
   "remediation": "Upgrade drupal to >= 9.2.2.",
   "refs": [
    "https://www.drupal.org/sa-core-2021-004"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.2.2"
   }
  },
  {
   "key": "cve-drupal-2021-33829",
   "title": "drupal < 9.1.9 \u2014 drupal vulnerability (CVE-2021-33829)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2021-33829",
   "tech": "drupal",
   "fixed": "9.1.9",
   "remediation": "Upgrade drupal to >= 9.1.9.",
   "refs": [
    "https://www.drupal.org/sa-core-2021-003"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.1.9"
   }
  },
  {
   "key": "cve-drupal-2022-24728",
   "title": "drupal < 9.3.8 \u2014 drupal vulnerability (CVE-2022-24728)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-24728",
   "tech": "drupal",
   "fixed": "9.3.8",
   "remediation": "Upgrade drupal to >= 9.3.8.",
   "refs": [
    "https://www.drupal.org/sa-core-2022-005"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.3.8"
   }
  },
  {
   "key": "cve-drupal-2022-24775",
   "title": "drupal < 9.3.9 \u2014 drupal vulnerability (CVE-2022-24775)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-24775",
   "tech": "drupal",
   "fixed": "9.3.9",
   "remediation": "Upgrade drupal to >= 9.3.9.",
   "refs": [
    "https://www.drupal.org/sa-core-2022-006"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.3.9"
   }
  },
  {
   "key": "cve-drupal-2022-25270",
   "title": "drupal < 9.3.6 \u2014 drupal vulnerability (CVE-2022-25270)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-25270",
   "tech": "drupal",
   "fixed": "9.3.6",
   "remediation": "Upgrade drupal to >= 9.3.6.",
   "refs": [
    "https://www.drupal.org/sa-core-2022-004"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.3.6"
   }
  },
  {
   "key": "cve-drupal-2022-25271",
   "title": "drupal < 9.3.6 \u2014 drupal vulnerability (CVE-2022-25271)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-25271",
   "tech": "drupal",
   "fixed": "9.3.6",
   "remediation": "Upgrade drupal to >= 9.3.6.",
   "refs": [
    "https://www.drupal.org/sa-core-2022-003"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.3.6"
   }
  },
  {
   "key": "cve-drupal-2022-25273",
   "title": "drupal < 9.3.12 \u2014 drupal vulnerability (CVE-2022-25273)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-25273",
   "tech": "drupal",
   "fixed": "9.3.12",
   "remediation": "Upgrade drupal to >= 9.3.12.",
   "refs": [
    "https://www.drupal.org/sa-core-2022-008"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.3.12"
   }
  },
  {
   "key": "cve-drupal-2022-25274",
   "title": "drupal < 9.3.12 \u2014 drupal vulnerability (CVE-2022-25274)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-25274",
   "tech": "drupal",
   "fixed": "9.3.12",
   "remediation": "Upgrade drupal to >= 9.3.12.",
   "refs": [
    "https://www.drupal.org/sa-core-2022-009"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.3.12"
   }
  },
  {
   "key": "cve-drupal-2022-25275",
   "title": "drupal < 9.4.3 \u2014 drupal vulnerability (CVE-2022-25275)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-25275",
   "tech": "drupal",
   "fixed": "9.4.3",
   "remediation": "Upgrade drupal to >= 9.4.3.",
   "refs": [
    "https://www.drupal.org/sa-core-2022-012"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.4.3"
   }
  },
  {
   "key": "cve-drupal-2022-25276",
   "title": "drupal < 9.4.3 \u2014 drupal vulnerability (CVE-2022-25276)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-25276",
   "tech": "drupal",
   "fixed": "9.4.3",
   "remediation": "Upgrade drupal to >= 9.4.3.",
   "refs": [
    "https://www.drupal.org/sa-core-2022-015"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.4.3"
   }
  },
  {
   "key": "cve-drupal-2022-25277",
   "title": "drupal < 9.4.3 \u2014 drupal vulnerability (CVE-2022-25277)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-25277",
   "tech": "drupal",
   "fixed": "9.4.3",
   "remediation": "Upgrade drupal to >= 9.4.3.",
   "refs": [
    "https://www.drupal.org/sa-core-2022-014"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.4.3"
   }
  },
  {
   "key": "cve-drupal-2022-25278",
   "title": "drupal < 9.4.3 \u2014 drupal vulnerability (CVE-2022-25278)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-25278",
   "tech": "drupal",
   "fixed": "9.4.3",
   "remediation": "Upgrade drupal to >= 9.4.3.",
   "refs": [
    "https://www.drupal.org/sa-core-2022-013"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.4.3"
   }
  },
  {
   "key": "cve-drupal-2022-29248",
   "title": "drupal < 9.3.14 \u2014 drupal vulnerability (CVE-2022-29248)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-29248",
   "tech": "drupal",
   "fixed": "9.3.14",
   "remediation": "Upgrade drupal to >= 9.3.14.",
   "refs": [
    "https://www.drupal.org/sa-core-2022-010"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.3.14"
   }
  },
  {
   "key": "cve-drupal-2022-31042",
   "title": "drupal < 9.3.16 \u2014 drupal vulnerability (CVE-2022-31042)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-31042",
   "tech": "drupal",
   "fixed": "9.3.16",
   "remediation": "Upgrade drupal to >= 9.3.16.",
   "refs": [
    "https://www.drupal.org/sa-core-2022-011"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.3.16"
   }
  },
  {
   "key": "cve-drupal-2022-39261",
   "title": "drupal < 9.4.7 \u2014 drupal vulnerability (CVE-2022-39261)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-39261",
   "tech": "drupal",
   "fixed": "9.4.7",
   "remediation": "Upgrade drupal to >= 9.4.7.",
   "refs": [
    "https://www.drupal.org/sa-core-2022-016"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "9.4.7"
   }
  },
  {
   "key": "cve-drupal-2023-31250",
   "title": "drupal < 10.0.8 \u2014 drupal vulnerability (CVE-2023-31250)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2023-31250",
   "tech": "drupal",
   "fixed": "10.0.8",
   "remediation": "Upgrade drupal to >= 10.0.8.",
   "refs": [
    "https://www.drupal.org/sa-core-2023-005"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "10.0.8"
   }
  },
  {
   "key": "cve-drupal-2023-5256",
   "title": "drupal < 10.1.4 \u2014 drupal vulnerability (CVE-2023-5256)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2023-5256",
   "tech": "drupal",
   "fixed": "10.1.4",
   "remediation": "Upgrade drupal to >= 10.1.4.",
   "refs": [
    "https://www.drupal.org/sa-core-2023-006"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "10.1.4"
   }
  },
  {
   "key": "cve-drupal-2024-11941",
   "title": "drupal < 10.2.2 \u2014 drupal vulnerability (CVE-2024-11941)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2024-11941",
   "tech": "drupal",
   "fixed": "10.2.2",
   "remediation": "Upgrade drupal to >= 10.2.2.",
   "refs": [
    "https://www.drupal.org/sa-core-2024-001"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "10.2.2"
   }
  },
  {
   "key": "cve-drupal-2024-11942",
   "title": "drupal < 10.2.10 \u2014 drupal vulnerability (CVE-2024-11942)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2024-11942",
   "tech": "drupal",
   "fixed": "10.2.10",
   "remediation": "Upgrade drupal to >= 10.2.10.",
   "refs": [
    "https://www.drupal.org/sa-core-2024-002"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "10.2.10"
   }
  },
  {
   "key": "cve-drupal-2024-12393",
   "title": "drupal < 11.0.8 \u2014 drupal vulnerability (CVE-2024-12393)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2024-12393",
   "tech": "drupal",
   "fixed": "11.0.8",
   "remediation": "Upgrade drupal to >= 11.0.8.",
   "refs": [
    "https://www.drupal.org/sa-core-2024-003"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "11.0.8"
   }
  },
  {
   "key": "cve-drupal-2024-45440",
   "title": "drupal < 10.2.9 \u2014 Drupal Full Path Disclosure (CVE-2024-45440)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2024-45440",
   "tech": "drupal",
   "fixed": "10.2.9",
   "remediation": "Upgrade drupal to >= 10.2.9.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2024-45440",
    "https://github.com/github/advisory-database/pull/4827",
    "https://github.com/drupal/drupal"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "10.2.9"
   }
  },
  {
   "key": "cve-drupal-2024-55634",
   "title": "drupal < 11.0.8 \u2014 drupal vulnerability (CVE-2024-55634)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2024-55634",
   "tech": "drupal",
   "fixed": "11.0.8",
   "remediation": "Upgrade drupal to >= 11.0.8.",
   "refs": [
    "https://www.drupal.org/sa-core-2024-004"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "11.0.8"
   }
  },
  {
   "key": "cve-drupal-2024-55636",
   "title": "drupal < 11.0.8 \u2014 drupal vulnerability (CVE-2024-55636)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2024-55636",
   "tech": "drupal",
   "fixed": "11.0.8",
   "remediation": "Upgrade drupal to >= 11.0.8.",
   "refs": [
    "https://www.drupal.org/sa-core-2024-006"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "11.0.8"
   }
  },
  {
   "key": "cve-drupal-2024-55637",
   "title": "drupal < 11.0.8 \u2014 drupal vulnerability (CVE-2024-55637)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2024-55637",
   "tech": "drupal",
   "fixed": "11.0.8",
   "remediation": "Upgrade drupal to >= 11.0.8.",
   "refs": [
    "https://www.drupal.org/sa-core-2024-007"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "11.0.8"
   }
  },
  {
   "key": "cve-drupal-2024-55638",
   "title": "drupal < 10.3.9 \u2014 drupal vulnerability (CVE-2024-55638)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2024-55638",
   "tech": "drupal",
   "fixed": "10.3.9",
   "remediation": "Upgrade drupal to >= 10.3.9.",
   "refs": [
    "https://www.drupal.org/sa-core-2024-008"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "10.3.9"
   }
  },
  {
   "key": "cve-drupal-2025-13080",
   "title": "drupal < 11.2.8 \u2014 drupal vulnerability (CVE-2025-13080)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2025-13080",
   "tech": "drupal",
   "fixed": "11.2.8",
   "remediation": "Upgrade drupal to >= 11.2.8.",
   "refs": [
    "https://www.drupal.org/sa-core-2025-005"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "11.2.8"
   }
  },
  {
   "key": "cve-drupal-2025-13081",
   "title": "drupal < 11.2.8 \u2014 drupal vulnerability (CVE-2025-13081)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2025-13081",
   "tech": "drupal",
   "fixed": "11.2.8",
   "remediation": "Upgrade drupal to >= 11.2.8.",
   "refs": [
    "https://www.drupal.org/sa-core-2025-006"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "11.2.8"
   }
  },
  {
   "key": "cve-drupal-2025-13082",
   "title": "drupal < 11.2.8 \u2014 drupal vulnerability (CVE-2025-13082)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2025-13082",
   "tech": "drupal",
   "fixed": "11.2.8",
   "remediation": "Upgrade drupal to >= 11.2.8.",
   "refs": [
    "https://www.drupal.org/sa-core-2025-007"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "11.2.8"
   }
  },
  {
   "key": "cve-drupal-2025-13083",
   "title": "drupal < 11.2.8 \u2014 drupal vulnerability (CVE-2025-13083)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2025-13083",
   "tech": "drupal",
   "fixed": "11.2.8",
   "remediation": "Upgrade drupal to >= 11.2.8.",
   "refs": [
    "https://www.drupal.org/sa-core-2025-008"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "11.2.8"
   }
  },
  {
   "key": "cve-drupal-2025-3057",
   "title": "drupal < 11.1.3 \u2014 drupal vulnerability (CVE-2025-3057)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2025-3057",
   "tech": "drupal",
   "fixed": "11.1.3",
   "remediation": "Upgrade drupal to >= 11.1.3.",
   "refs": [
    "https://www.drupal.org/sa-core-2025-001"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "11.1.3"
   }
  },
  {
   "key": "cve-drupal-2025-31673",
   "title": "drupal < 11.1.3 \u2014 drupal vulnerability (CVE-2025-31673)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2025-31673",
   "tech": "drupal",
   "fixed": "11.1.3",
   "remediation": "Upgrade drupal to >= 11.1.3.",
   "refs": [
    "https://www.drupal.org/sa-core-2025-002"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "11.1.3"
   }
  },
  {
   "key": "cve-drupal-2025-31674",
   "title": "drupal < 11.1.3 \u2014 drupal vulnerability (CVE-2025-31674)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2025-31674",
   "tech": "drupal",
   "fixed": "11.1.3",
   "remediation": "Upgrade drupal to >= 11.1.3.",
   "refs": [
    "https://www.drupal.org/sa-core-2025-003"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "11.1.3"
   }
  },
  {
   "key": "cve-drupal-2025-31675",
   "title": "drupal < 11.1.5 \u2014 drupal vulnerability (CVE-2025-31675)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2025-31675",
   "tech": "drupal",
   "fixed": "11.1.5",
   "remediation": "Upgrade drupal to >= 11.1.5.",
   "refs": [
    "https://www.drupal.org/sa-core-2025-004"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "11.1.5"
   }
  },
  {
   "key": "cve-drupal-2026-15916",
   "title": "drupal < 11.3.0 \u2014 drupal vulnerability (CVE-2026-15916)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-15916",
   "tech": "drupal",
   "fixed": "11.3.0",
   "remediation": "Upgrade drupal to >= 11.3.0.",
   "refs": [
    "https://www.drupal.org/sa-core-2026-010"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "11.3.0"
   }
  },
  {
   "key": "cve-drupal-2026-15917",
   "title": "drupal < 11.3.0 \u2014 drupal vulnerability (CVE-2026-15917)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-15917",
   "tech": "drupal",
   "fixed": "11.3.0",
   "remediation": "Upgrade drupal to >= 11.3.0.",
   "refs": [
    "https://www.drupal.org/sa-core-2026-011"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "11.3.0"
   }
  },
  {
   "key": "cve-drupal-2026-55803",
   "title": "drupal < 11.2.0 \u2014 drupal vulnerability (CVE-2026-55803)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-55803",
   "tech": "drupal",
   "fixed": "11.2.0",
   "remediation": "Upgrade drupal to >= 11.2.0.",
   "refs": [
    "https://www.drupal.org/sa-core-2026-005"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "11.2.0"
   }
  },
  {
   "key": "cve-drupal-2026-55804",
   "title": "drupal < 11.2.0 \u2014 drupal vulnerability (CVE-2026-55804)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-55804",
   "tech": "drupal",
   "fixed": "11.2.0",
   "remediation": "Upgrade drupal to >= 11.2.0.",
   "refs": [
    "https://www.drupal.org/sa-core-2026-006"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "11.2.0"
   }
  },
  {
   "key": "cve-drupal-2026-55805",
   "title": "drupal < 11.3.0 \u2014 drupal vulnerability (CVE-2026-55805)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-55805",
   "tech": "drupal",
   "fixed": "11.3.0",
   "remediation": "Upgrade drupal to >= 11.3.0.",
   "refs": [
    "https://www.drupal.org/sa-core-2026-012"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "11.3.0"
   }
  },
  {
   "key": "cve-drupal-2026-55806",
   "title": "drupal < 11.2.0 \u2014 drupal vulnerability (CVE-2026-55806)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-55806",
   "tech": "drupal",
   "fixed": "11.2.0",
   "remediation": "Upgrade drupal to >= 11.2.0.",
   "refs": [
    "https://www.drupal.org/sa-core-2026-007"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "11.2.0"
   }
  },
  {
   "key": "cve-drupal-2026-55807",
   "title": "drupal < 11.2.0 \u2014 drupal vulnerability (CVE-2026-55807)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-55807",
   "tech": "drupal",
   "fixed": "11.2.0",
   "remediation": "Upgrade drupal to >= 11.2.0.",
   "refs": [
    "https://www.drupal.org/sa-core-2026-008"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "11.2.0"
   }
  },
  {
   "key": "cve-drupal-2026-55808",
   "title": "drupal < 11.2.0 \u2014 drupal vulnerability (CVE-2026-55808)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-55808",
   "tech": "drupal",
   "fixed": "11.2.0",
   "remediation": "Upgrade drupal to >= 11.2.0.",
   "refs": [
    "https://www.drupal.org/sa-core-2026-009"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "11.2.0"
   }
  },
  {
   "key": "cve-drupal-2026-6365",
   "title": "drupal < 11.3.7 \u2014 drupal vulnerability (CVE-2026-6365)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-6365",
   "tech": "drupal",
   "fixed": "11.3.7",
   "remediation": "Upgrade drupal to >= 11.3.7.",
   "refs": [
    "https://www.drupal.org/sa-core-2026-001"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "11.3.7"
   }
  },
  {
   "key": "cve-drupal-2026-6366",
   "title": "drupal < 11.3.7 \u2014 drupal vulnerability (CVE-2026-6366)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-6366",
   "tech": "drupal",
   "fixed": "11.3.7",
   "remediation": "Upgrade drupal to >= 11.3.7.",
   "refs": [
    "https://www.drupal.org/sa-core-2026-002"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "11.3.7"
   }
  },
  {
   "key": "cve-drupal-2026-6367",
   "title": "drupal < 11.3.7 \u2014 drupal vulnerability (CVE-2026-6367)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-6367",
   "tech": "drupal",
   "fixed": "11.3.7",
   "remediation": "Upgrade drupal to >= 11.3.7.",
   "refs": [
    "https://www.drupal.org/sa-core-2026-003"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "11.3.7"
   }
  },
  {
   "key": "cve-drupal-2026-9082",
   "title": "drupal < 11.3.10 \u2014 drupal vulnerability (CVE-2026-9082)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-9082",
   "tech": "drupal",
   "fixed": "11.3.10",
   "remediation": "Upgrade drupal to >= 11.3.10.",
   "refs": [
    "https://www.drupal.org/sa-core-2026-004"
   ],
   "match": {
    "tech": "drupal",
    "version_lt": "11.3.10"
   }
  },
  {
   "key": "cve-ember-2013-4170",
   "title": "ember < 1.0.0-rc.1.1 \u2014 ember vulnerability (CVE-2013-4170)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2013-4170",
   "tech": "ember",
   "fixed": "1.0.0-rc.1.1",
   "remediation": "Upgrade ember to >= 1.0.0-rc.1.1.",
   "refs": [
    "https://groups.google.com/forum/#!topic/ember-security/dokLVwwxAdM"
   ],
   "match": {
    "tech": "ember",
    "version_lt": "1.0.0-rc.1.1"
   }
  },
  {
   "key": "cve-ember-2014-0013",
   "title": "ember < 1.0.1 \u2014 ember vulnerability (CVE-2014-0013)",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2014-0013",
   "tech": "ember",
   "fixed": "1.0.1",
   "remediation": "Upgrade ember to >= 1.0.1.",
   "refs": [
    "https://groups.google.com/forum/#!topic/ember-security/2kpXXCxISS4",
    "https://groups.google.com/forum/#!topic/ember-security/PSE4RzTi6l4"
   ],
   "match": {
    "tech": "ember",
    "version_lt": "1.0.1"
   }
  },
  {
   "key": "cve-ember-2014-0046",
   "title": "ember < 1.2.2 \u2014 ember-routing-auto-location can be forced to redirect to another domain (CVE-2014-0046)",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2014-0046",
   "tech": "ember",
   "fixed": "1.2.2",
   "remediation": "Upgrade ember to >= 1.2.2.",
   "refs": [
    "https://github.com/emberjs/ember.js/blob/v1.5.0/CHANGELOG.md",
    "https://groups.google.com/forum/#!topic/ember-security/1h6FRgr8lXQ"
   ],
   "match": {
    "tech": "ember",
    "version_lt": "1.2.2"
   },
   "cwe": "CWE-94"
  },
  {
   "key": "cve-ember-2015-7565",
   "title": "ember < 1.11.4 \u2014 ember vulnerability (CVE-2015-7565)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2015-7565",
   "tech": "ember",
   "fixed": "1.11.4",
   "remediation": "Upgrade ember to >= 1.11.4.",
   "refs": [
    "https://groups.google.com/forum/#!topic/ember-security/OfyQkoSuppY"
   ],
   "match": {
    "tech": "ember",
    "version_lt": "1.11.4"
   }
  },
  {
   "key": "cve-handlebars-2015-8861",
   "title": "handlebars < 4.0.0 \u2014 Quoteless attributes in templates can lead to XSS (CVE-2015-8861)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2015-8861",
   "tech": "handlebars",
   "fixed": "4.0.0",
   "remediation": "Upgrade handlebars to >= 4.0.0.",
   "refs": [
    "https://github.com/wycats/handlebars.js/pull/1083"
   ],
   "match": {
    "tech": "handlebars",
    "version_lt": "4.0.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-handlebars-2019-19919",
   "title": "handlebars < 3.0.8 \u2014 Disallow calling helperMissing and blockHelperMissing directly (CVE-2019-19919)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2019-19919",
   "tech": "handlebars",
   "fixed": "3.0.8",
   "remediation": "Upgrade handlebars to >= 3.0.8.",
   "refs": [
    "https://github.com/wycats/handlebars.js/blob/master/release-notes.md#v430---september-24th-2019"
   ],
   "match": {
    "tech": "handlebars",
    "version_lt": "3.0.8"
   }
  },
  {
   "key": "cve-handlebars-2019-20920",
   "title": "handlebars < 3.0.8 \u2014 Handlebars before 3.0.8 and 4.x before 4.5.3 is vulnerable to Arbitrary Code Execution. The lookup helper fails to prop",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2019-20920",
   "tech": "handlebars",
   "fixed": "3.0.8",
   "remediation": "Upgrade handlebars to >= 3.0.8.",
   "refs": [
    "https://github.com/advisories/GHSA-3cqr-58rm-57f8",
    "https://nvd.nist.gov/vuln/detail/CVE-2019-20920"
   ],
   "match": {
    "tech": "handlebars",
    "version_lt": "3.0.8"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-handlebars-2019-20922",
   "title": "handlebars < 4.4.5 \u2014 Regular Expression Denial of Service in Handlebars (CVE-2019-20922)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2019-20922",
   "tech": "handlebars",
   "fixed": "4.4.5",
   "remediation": "Upgrade handlebars to >= 4.4.5.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2019-20922"
   ],
   "match": {
    "tech": "handlebars",
    "version_lt": "4.4.5"
   },
   "cwe": "CWE-400"
  },
  {
   "key": "cve-handlebars-2021-23369",
   "title": "handlebars < 4.7.7 \u2014 Remote code execution in handlebars when compiling templates (CVE-2021-23369)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2021-23369",
   "tech": "handlebars",
   "fixed": "4.7.7",
   "remediation": "Upgrade handlebars to >= 4.7.7.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2021-23369"
   ],
   "match": {
    "tech": "handlebars",
    "version_lt": "4.7.7"
   },
   "cwe": "CWE-94"
  },
  {
   "key": "cve-handlebars-2021-23383",
   "title": "handlebars < 4.7.7 \u2014 Prototype Pollution in handlebars (CVE-2021-23383)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2021-23383",
   "tech": "handlebars",
   "fixed": "4.7.7",
   "remediation": "Upgrade handlebars to >= 4.7.7.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2021-23383"
   ],
   "match": {
    "tech": "handlebars",
    "version_lt": "4.7.7"
   },
   "cwe": "CWE-1321"
  },
  {
   "key": "cve-handlebars-2026-33916",
   "title": "handlebars < 4.7.9 \u2014 Handlebars is vulnerable to XSS via prototype pollution: the resolvePartial() function looks up partial names with an u",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-33916",
   "tech": "handlebars",
   "fixed": "4.7.9",
   "remediation": "Upgrade handlebars to >= 4.7.9.",
   "refs": [
    "https://github.com/handlebars-lang/handlebars.js/security/advisories/GHSA-2qvq-rjwj-gvw9",
    "https://github.com/handlebars-lang/handlebars.js/commit/68d8df5a88e0a26fe9e6084c5c6aaebe67b07da2",
    "https://github.com/handlebars-lang/handlebars.js/releases/tag/v4.7.9"
   ],
   "match": {
    "tech": "handlebars",
    "version_lt": "4.7.9"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-handlebars-2026-33937",
   "title": "handlebars < 4.7.9 \u2014 Handlebars is vulnerable to Remote Code Execution when Handlebars.compile() is passed an attacker-controlled pre-parsed",
   "category": "cve",
   "severity": "critical",
   "confidence": "candidate",
   "cve": "CVE-2026-33937",
   "tech": "handlebars",
   "fixed": "4.7.9",
   "remediation": "Upgrade handlebars to >= 4.7.9.",
   "refs": [
    "https://github.com/handlebars-lang/handlebars.js/security/advisories/GHSA-2w6w-674q-4c4q",
    "https://github.com/handlebars-lang/handlebars.js/commit/68d8df5a88e0a26fe9e6084c5c6aaebe67b07da2",
    "https://github.com/handlebars-lang/handlebars.js/releases/tag/v4.7.9"
   ],
   "match": {
    "tech": "handlebars",
    "version_lt": "4.7.9"
   },
   "cwe": "CWE-94"
  },
  {
   "key": "cve-handlebars-2026-33938",
   "title": "handlebars < 4.7.9 \u2014 Handlebars is vulnerable to Remote Code Execution via the @partial-block mechanism. When a helper with write access to ",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2026-33938",
   "tech": "handlebars",
   "fixed": "4.7.9",
   "remediation": "Upgrade handlebars to >= 4.7.9.",
   "refs": [
    "https://github.com/handlebars-lang/handlebars.js/security/advisories/GHSA-3mfm-83xf-c92r",
    "https://github.com/handlebars-lang/handlebars.js/commit/68d8df5a88e0a26fe9e6084c5c6aaebe67b07da2",
    "https://github.com/handlebars-lang/handlebars.js/releases/tag/v4.7.9"
   ],
   "match": {
    "tech": "handlebars",
    "version_lt": "4.7.9"
   },
   "cwe": "CWE-94"
  },
  {
   "key": "cve-handlebars-2026-33939",
   "title": "handlebars < 4.7.9 \u2014 Handlebars is vulnerable to Denial of Service via unregistered decorator syntax. When a template contains a decorator r",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2026-33939",
   "tech": "handlebars",
   "fixed": "4.7.9",
   "remediation": "Upgrade handlebars to >= 4.7.9.",
   "refs": [
    "https://github.com/handlebars-lang/handlebars.js/security/advisories/GHSA-9cx6-37pm-9jff",
    "https://github.com/handlebars-lang/handlebars.js/commit/68d8df5a88e0a26fe9e6084c5c6aaebe67b07da2",
    "https://github.com/handlebars-lang/handlebars.js/releases/tag/v4.7.9"
   ],
   "match": {
    "tech": "handlebars",
    "version_lt": "4.7.9"
   },
   "cwe": "CWE-400"
  },
  {
   "key": "cve-handlebars-2026-33940",
   "title": "handlebars < 4.7.9 \u2014 Handlebars is vulnerable to Remote Code Execution through dynamic partial lookups. A crafted object with call: true pla",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2026-33940",
   "tech": "handlebars",
   "fixed": "4.7.9",
   "remediation": "Upgrade handlebars to >= 4.7.9.",
   "refs": [
    "https://github.com/handlebars-lang/handlebars.js/security/advisories/GHSA-xhpv-hc6g-r9c6",
    "https://github.com/handlebars-lang/handlebars.js/commit/68d8df5a88e0a26fe9e6084c5c6aaebe67b07da2",
    "https://github.com/handlebars-lang/handlebars.js/releases/tag/v4.7.9"
   ],
   "match": {
    "tech": "handlebars",
    "version_lt": "4.7.9"
   },
   "cwe": "CWE-94"
  },
  {
   "key": "cve-handlebars-2026-33941",
   "title": "handlebars < 4.7.9 \u2014 The Handlebars CLI precompiler is vulnerable to code injection through multiple unsanitized inputs: template file names",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2026-33941",
   "tech": "handlebars",
   "fixed": "4.7.9",
   "remediation": "Upgrade handlebars to >= 4.7.9.",
   "refs": [
    "https://github.com/handlebars-lang/handlebars.js/security/advisories/GHSA-xjpj-3mr7-gcpf",
    "https://github.com/handlebars-lang/handlebars.js/commit/68d8df5a88e0a26fe9e6084c5c6aaebe67b07da2",
    "https://github.com/handlebars-lang/handlebars.js/releases/tag/v4.7.9"
   ],
   "match": {
    "tech": "handlebars",
    "version_lt": "4.7.9"
   }
  },
  {
   "key": "cve-iis-2015-1635",
   "title": "IIS < 8.5 \u2014 HTTP.sys RCE via crafted Range header (MS15-034, CVE-2015-1635)",
   "category": "cve",
   "severity": "critical",
   "confidence": "candidate",
   "remediation": "Apply MS15-034 / upgrade so HTTP.sys is patched (>= 8.5).",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2015-1635"
   ],
   "cwe": "CWE-94",
   "cve": "CVE-2015-1635",
   "tech": "iis",
   "fixed": "8.5",
   "match": {
    "tech": "iis",
    "version_lt": "8.5"
   }
  },
  {
   "key": "cve-iis-2017-7269",
   "title": "IIS 6.0 \u2014 WebDAV ScStoragePathFromUrl buffer overflow RCE (CVE-2017-7269)",
   "category": "cve",
   "severity": "critical",
   "confidence": "candidate",
   "remediation": "Upgrade off IIS 6.0 (>= 7.0) or disable WebDAV.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-7269"
   ],
   "cwe": "CWE-94",
   "cve": "CVE-2017-7269",
   "tech": "iis",
   "fixed": "7.0",
   "match": {
    "tech": "iis",
    "version_lt": "7.0"
   }
  },
  {
   "key": "cve-joomla-2010-1649",
   "title": "joomla < 1.5.18 \u2014 Joomla! vulnerable to Cross-site Scripting (CVE-2010-1649)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2010-1649",
   "tech": "joomla",
   "fixed": "1.5.18",
   "remediation": "Upgrade joomla to >= 1.5.18.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2010-1649",
    "https://web.archive.org/web/20200228225430/https://www.securityfocus.com/bid/40444",
    "http://developer.joomla.org/security/news/314-20100501-core-xss-vulnerabilities-in-back-end.html?utm_source=feedburner&utm_medium=email&utm_campaign=Feed%3A+JoomlaSecurityNews+%28Joomla!+Security+News%29"
   ],
   "match": {
    "tech": "joomla",
    "version_lt": "1.5.18"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-joomla-2011-2509",
   "title": "joomla < 1.6.4 \u2014 Joomla! vulnerable to Cross-site Scripting (CVE-2011-2509)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2011-2509",
   "tech": "joomla",
   "fixed": "1.6.4",
   "remediation": "Upgrade joomla to >= 1.6.4.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2011-2509",
    "http://developer.joomla.org/security/news/352-20110604-xss-vulnerability.html",
    "http://www.openwall.com/lists/oss-security/2011/06/28/4"
   ],
   "match": {
    "tech": "joomla",
    "version_lt": "1.6.4"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-joomla-2011-4332",
   "title": "joomla < 1.6.4 \u2014 Joomla! vulnerable to Cross-site Scripting (CVE-2011-4332)",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2011-4332",
   "tech": "joomla",
   "fixed": "1.6.4",
   "remediation": "Upgrade joomla to >= 1.6.4.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2011-4332",
    "https://web.archive.org/web/20111115073609/http://www.mavitunasecurity.com/xss-vulnerability-in-joomla-163",
    "http://developer.joomla.org/security/news/349-20110601-xss-vulnerabilities.html"
   ],
   "match": {
    "tech": "joomla",
    "version_lt": "1.6.4"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-joomla-2013-5583",
   "title": "joomla < 3.1.6 \u2014 Joomla! Cross-site Scripting vulnerability (CVE-2013-5583)",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2013-5583",
   "tech": "joomla",
   "fixed": "3.1.6",
   "remediation": "Upgrade joomla to >= 3.1.6.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2013-5583",
    "https://github.com/joomla/joomla-cms/commit/c00c033d33d901e1ca6be9061a44e55acd041b1f",
    "https://github.com/joomla/joomla-cms"
   ],
   "match": {
    "tech": "joomla",
    "version_lt": "3.1.6"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-joomla-2015-8562",
   "title": "Joomla < 3.4.6 \u2014 PHP object injection RCE via User-Agent (CVE-2015-8562)",
   "category": "cve",
   "severity": "critical",
   "confidence": "candidate",
   "remediation": "Upgrade Joomla to >= 3.4.6.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2015-8562"
   ],
   "cwe": "CWE-94",
   "cve": "CVE-2015-8562",
   "tech": "joomla",
   "fixed": "3.4.6",
   "match": {
    "tech": "joomla",
    "version_lt": "3.4.6"
   }
  },
  {
   "key": "cve-joomla-2018-11326",
   "title": "joomla < 3.8.8 \u2014 Joomla! XSS Vulnerability (CVE-2018-11326)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2018-11326",
   "tech": "joomla",
   "fixed": "3.8.8",
   "remediation": "Upgrade joomla to >= 3.8.8.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2018-11326",
    "https://developer.joomla.org/security-centre/733-20180505-core-xss-vulnerabilities-additional-hadering.html",
    "https://github.com/joomla/joomla-cms"
   ],
   "match": {
    "tech": "joomla",
    "version_lt": "3.8.8"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-joomla-2019-16725",
   "title": "joomla < 3.9.12 \u2014 Joomla! XSS in Default Templates (CVE-2019-16725)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2019-16725",
   "tech": "joomla",
   "fixed": "3.9.12",
   "remediation": "Upgrade joomla to >= 3.9.12.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2019-16725",
    "https://developer.joomla.org/security-centre/791-20190901-core-xss-in-logo-parameter-of-default-templates.html",
    "https://github.com/joomla/joomla-cms"
   ],
   "match": {
    "tech": "joomla",
    "version_lt": "3.9.12"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-joomla-2019-7743",
   "title": "joomla < 3.9.3 \u2014 Joomla! Object Injection Vulnerability (CVE-2019-7743)",
   "category": "cve",
   "severity": "critical",
   "confidence": "candidate",
   "cve": "CVE-2019-7743",
   "tech": "joomla",
   "fixed": "3.9.3",
   "remediation": "Upgrade joomla to >= 3.9.3.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2019-7743",
    "https://github.com/joomla/joomla-cms/issues/23907",
    "https://developer.joomla.org/security-centre/770-20190206-core-implement-the-typo3-phar-stream-wrapper"
   ],
   "match": {
    "tech": "joomla",
    "version_lt": "3.9.3"
   }
  },
  {
   "key": "cve-joomla-2023-23752",
   "title": "Joomla < 4.2.8 \u2014 Improper access check exposes web-service endpoints (CVE-2023-23752)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "remediation": "Upgrade Joomla to >= 4.2.8.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2023-23752"
   ],
   "cve": "CVE-2023-23752",
   "tech": "joomla",
   "fixed": "4.2.8",
   "match": {
    "tech": "joomla",
    "version_lt": "4.2.8"
   }
  },
  {
   "key": "cve-joomla-2025-25227",
   "title": "joomla < 4.4.13 \u2014 Joomla CMS Multi-Factor Authentication Bypass (CVE-2025-25227)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2025-25227",
   "tech": "joomla",
   "fixed": "4.4.13",
   "remediation": "Upgrade joomla to >= 4.4.13.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2025-25227",
    "https://developer.joomla.org/security-centre/964-20250402-core-mfa-authentication-bypass.html",
    "https://github.com/joomla/joomla-cms"
   ],
   "match": {
    "tech": "joomla",
    "version_lt": "4.4.13"
   }
  },
  {
   "key": "cve-jquery-2011-4969",
   "title": "jquery < 1.6.3 \u2014 XSS with location.hash (CVE-2011-4969)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2011-4969",
   "tech": "jquery",
   "fixed": "1.6.3",
   "remediation": "Upgrade jquery to >= 1.6.3.",
   "refs": [
    "http://research.insecurelabs.org/jquery/test/",
    "https://bugs.jquery.com/ticket/9521",
    "https://nvd.nist.gov/vuln/detail/CVE-2011-4969"
   ],
   "match": {
    "tech": "jquery",
    "version_lt": "1.6.3"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-jquery-2012-6708",
   "title": "jquery < 1.9.0b1 \u2014 Selector interpreted as HTML (CVE-2012-6708)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2012-6708",
   "tech": "jquery",
   "fixed": "1.9.0b1",
   "remediation": "Upgrade jquery to >= 1.9.0b1.",
   "refs": [
    "http://bugs.jquery.com/ticket/11290",
    "http://research.insecurelabs.org/jquery/test/",
    "https://nvd.nist.gov/vuln/detail/CVE-2012-6708"
   ],
   "match": {
    "tech": "jquery",
    "version_lt": "1.9.0b1"
   }
  },
  {
   "key": "cve-jquery-2015-9251",
   "title": "jquery < 1.12.0 \u2014 3rd party CORS request may execute (CVE-2015-9251)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2015-9251",
   "tech": "jquery",
   "fixed": "1.12.0",
   "remediation": "Upgrade jquery to >= 1.12.0.",
   "refs": [
    "http://blog.jquery.com/2016/01/08/jquery-2-2-and-1-12-released/",
    "http://research.insecurelabs.org/jquery/test/",
    "https://github.com/advisories/GHSA-rmxg-73gg-4p98",
    "https://github.com/jquery/jquery/issues/2432",
    "https://nvd.nist.gov/vuln/detail/CVE-2015-9251"
   ],
   "match": {
    "tech": "jquery",
    "version_lt": "1.12.0"
   }
  },
  {
   "key": "cve-jquery-2016-10707",
   "title": "jquery < 3.0.0 \u2014 Denial of Service in jquery (CVE-2016-10707)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2016-10707",
   "tech": "jquery",
   "fixed": "3.0.0",
   "remediation": "Upgrade jquery to >= 3.0.0.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2016-10707"
   ],
   "match": {
    "tech": "jquery",
    "version_lt": "3.0.0"
   },
   "cwe": "CWE-400"
  },
  {
   "key": "cve-jquery-2020-11022",
   "title": "jquery < 3.5.0 \u2014 Regex in its jQuery.htmlPrefilter sometimes may introduce XSS (CVE-2020-11022)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-11022",
   "tech": "jquery",
   "fixed": "3.5.0",
   "remediation": "Upgrade jquery to >= 3.5.0.",
   "refs": [
    "https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/"
   ],
   "match": {
    "tech": "jquery",
    "version_lt": "3.5.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-jquery-2020-11023",
   "title": "jquery < 3.5.0 \u2014 passing HTML containing <option> elements from untrusted sources - even after sanitizing it - to one of jQuery's DOM manipu",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-11023",
   "tech": "jquery",
   "fixed": "3.5.0",
   "remediation": "Upgrade jquery to >= 3.5.0.",
   "refs": [
    "https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/"
   ],
   "match": {
    "tech": "jquery",
    "version_lt": "3.5.0"
   },
   "cwe": "CWE-94"
  },
  {
   "key": "cve-jquery-2020-7656",
   "title": "jquery < 1.9.0 \u2014 Versions of jQuery prior to 1.9.0 are vulnerable to Cross-Site Scripting (XSS). The load method fails to recognize and stri",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-7656",
   "tech": "jquery",
   "fixed": "1.9.0",
   "remediation": "Upgrade jquery to >= 1.9.0.",
   "refs": [
    "https://github.com/advisories/GHSA-q4m3-2j7h-f7xw",
    "https://nvd.nist.gov/vuln/detail/CVE-2020-7656",
    "https://research.insecurelabs.org/jquery/test/"
   ],
   "match": {
    "tech": "jquery",
    "version_lt": "1.9.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-jquery-ui-2021-41182",
   "title": "jquery-ui < 1.13.0 \u2014 XSS in the `altField` option of the Datepicker widget (CVE-2021-41182)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2021-41182",
   "tech": "jquery-ui",
   "fixed": "1.13.0",
   "remediation": "Upgrade jquery-ui to >= 1.13.0.",
   "refs": [
    "https://github.com/jquery/jquery-ui/security/advisories/GHSA-9gj3-hwp5-pmwc",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-41182"
   ],
   "match": {
    "tech": "jquery-ui",
    "version_lt": "1.13.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-jquery-ui-2021-41183",
   "title": "jquery-ui < 1.13.0 \u2014 XSS Vulnerability on text options of jQuery UI datepicker (CVE-2021-41183)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2021-41183",
   "tech": "jquery-ui",
   "fixed": "1.13.0",
   "remediation": "Upgrade jquery-ui to >= 1.13.0.",
   "refs": [
    "https://bugs.jqueryui.com/ticket/15284",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-41183"
   ],
   "match": {
    "tech": "jquery-ui",
    "version_lt": "1.13.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-jquery-ui-2021-41184",
   "title": "jquery-ui < 1.13.0 \u2014 XSS in the `of` option of the `.position()` util (CVE-2021-41184)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2021-41184",
   "tech": "jquery-ui",
   "fixed": "1.13.0",
   "remediation": "Upgrade jquery-ui to >= 1.13.0.",
   "refs": [
    "https://github.com/jquery/jquery-ui/security/advisories/GHSA-gpqq-952q-5327",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-41184"
   ],
   "match": {
    "tech": "jquery-ui",
    "version_lt": "1.13.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-jquery-ui-2022-31160",
   "title": "jquery-ui < 1.13.2 \u2014 XSS when refreshing a checkboxradio with an HTML-like initial text label  (CVE-2022-31160)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-31160",
   "tech": "jquery-ui",
   "fixed": "1.13.2",
   "remediation": "Upgrade jquery-ui to >= 1.13.2.",
   "refs": [
    "https://github.com/advisories/GHSA-h6gj-6jjq-h8g9",
    "https://github.com/jquery/jquery-ui/commit/8cc5bae1caa1fcf96bf5862c5646c787020ba3f9",
    "https://github.com/jquery/jquery-ui/issues/2101",
    "https://nvd.nist.gov/vuln/detail/CVE-2022-31160"
   ],
   "match": {
    "tech": "jquery-ui",
    "version_lt": "1.13.2"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-knockout-2019-14862",
   "title": "knockout < 3.5.0 \u2014 XSS injection point in attr name binding for browser IE7 and older (CVE-2019-14862)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2019-14862",
   "tech": "knockout",
   "fixed": "3.5.0",
   "remediation": "Upgrade knockout to >= 3.5.0.",
   "refs": [
    "https://github.com/knockout/knockout/issues/1244"
   ],
   "match": {
    "tech": "knockout",
    "version_lt": "3.5.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-laravel-2017-14775",
   "title": "laravel < 5.5.10 \u2014 Laravel Sensitive Data Exposure (CVE-2017-14775)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2017-14775",
   "tech": "laravel",
   "fixed": "5.5.10",
   "remediation": "Upgrade laravel to >= 5.5.10.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-14775",
    "https://github.com/laravel/framework/pull/21320",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/illuminate/auth/CVE-2017-14775.yaml"
   ],
   "match": {
    "tech": "laravel",
    "version_lt": "5.5.10"
   }
  },
  {
   "key": "cve-laravel-2017-9303",
   "title": "laravel < 5.4.22 \u2014 Laravel does not properly constrain the host portion of a password-reset URL (CVE-2017-9303)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2017-9303",
   "tech": "laravel",
   "fixed": "5.4.22",
   "remediation": "Upgrade laravel to >= 5.4.22.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-9303",
    "https://github.com/laravel/framework/commit/cef10551820530632a86fa6f1306fee95c5cac43",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/illuminate/auth/CVE-2017-9303.yaml"
   ],
   "match": {
    "tech": "laravel",
    "version_lt": "5.4.22"
   }
  },
  {
   "key": "cve-laravel-2018-15133",
   "title": "laravel < 5.6.30 \u2014 Laravel Framework RCE Vulnerability (CVE-2018-15133)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2018-15133",
   "tech": "laravel",
   "fixed": "5.6.30",
   "remediation": "Upgrade laravel to >= 5.6.30.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2018-15133",
    "https://github.com/laravel/framework/commit/d84cf988ed5d4661a4bf1fdcb08f5073835083a0",
    "https://github.com/kozmic/laravel-poc-CVE-2018-15133"
   ],
   "match": {
    "tech": "laravel",
    "version_lt": "5.6.30"
   },
   "cwe": "CWE-94"
  },
  {
   "key": "cve-laravel-2019-9081",
   "title": "laravel < 6.20.44 \u2014 Laravel Framework Deserialization Vulnerability (CVE-2019-9081)",
   "category": "cve",
   "severity": "critical",
   "confidence": "candidate",
   "cve": "CVE-2019-9081",
   "tech": "laravel",
   "fixed": "6.20.44",
   "remediation": "Upgrade laravel to >= 6.20.44.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2019-9081",
    "https://github.com/Laworigin/Laworigin.github.io/blob/master/2019/02/21/laravelv5-7%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96rce/index.html",
    "https://github.com/laravel/framework"
   ],
   "match": {
    "tech": "laravel",
    "version_lt": "6.20.44"
   },
   "cwe": "CWE-502"
  },
  {
   "key": "cve-laravel-2020-19316",
   "title": "laravel < 5.8.17 \u2014 OS Command Injection in Laravel Framework (CVE-2020-19316)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2020-19316",
   "tech": "laravel",
   "fixed": "5.8.17",
   "remediation": "Upgrade laravel to >= 5.8.17.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2020-19316",
    "https://github.com/laravel/framework/commit/44c3feb604944599ad1c782a9942981c3991fa31",
    "https://github.com/laravel/framework"
   ],
   "match": {
    "tech": "laravel",
    "version_lt": "5.8.17"
   }
  },
  {
   "key": "cve-laravel-2020-24941",
   "title": "laravel < 7.24.0 \u2014 Improper Input Validation in Laravel (CVE-2020-24941)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2020-24941",
   "tech": "laravel",
   "fixed": "7.24.0",
   "remediation": "Upgrade laravel to >= 7.24.0.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2020-24941",
    "https://github.com/laravel/framework/commit/897d107775737a958dbd0b2f3ea37877c7526371",
    "https://blog.laravel.com/security-release-laravel-61835-7240"
   ],
   "match": {
    "tech": "laravel",
    "version_lt": "7.24.0"
   }
  },
  {
   "key": "cve-laravel-2021-21263",
   "title": "laravel < 7.30.2 \u2014 Query Binding Exploitation (CVE-2021-21263)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2021-21263",
   "tech": "laravel",
   "fixed": "7.30.2",
   "remediation": "Upgrade laravel to >= 7.30.2.",
   "refs": [
    "https://github.com/laravel/framework/security/advisories/GHSA-3p32-j457-pg5x",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-21263",
    "https://github.com/laravel/framework/pull/35865"
   ],
   "match": {
    "tech": "laravel",
    "version_lt": "7.30.2"
   }
  },
  {
   "key": "cve-laravel-2021-3129",
   "title": "Laravel < 8.4.3 \u2014 Ignition debug-mode RCE via phar deserialization (CVE-2021-3129)",
   "category": "cve",
   "severity": "critical",
   "confidence": "candidate",
   "remediation": "Upgrade laravel to >= 8.4.3 and disable APP_DEBUG in production.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2021-3129"
   ],
   "cwe": "CWE-94",
   "cve": "CVE-2021-3129",
   "tech": "laravel",
   "fixed": "8.4.3",
   "match": {
    "tech": "laravel",
    "version_lt": "8.4.3"
   }
  },
  {
   "key": "cve-laravel-2021-43808",
   "title": "laravel < 8.75.0 \u2014 Laravel Framework XSS in Blade templating engine (CVE-2021-43808)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2021-43808",
   "tech": "laravel",
   "fixed": "8.75.0",
   "remediation": "Upgrade laravel to >= 8.75.0.",
   "refs": [
    "https://github.com/laravel/framework/security/advisories/GHSA-66hf-2p6w-jqfw",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-43808",
    "https://github.com/laravel/framework/pull/39906"
   ],
   "match": {
    "tech": "laravel",
    "version_lt": "8.75.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-laravel-2024-13918",
   "title": "laravel < 11.36.0 \u2014 Laravel framework susceptible to reflected cross-site scripting (CVE-2024-13918)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2024-13918",
   "tech": "laravel",
   "fixed": "11.36.0",
   "remediation": "Upgrade laravel to >= 11.36.0.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2024-13918",
    "https://github.com/laravel/framework/pull/53869",
    "https://github.com/laravel/framework/commit/45287fb2a91c69bb1c110539b9b7341faf5aee33"
   ],
   "match": {
    "tech": "laravel",
    "version_lt": "11.36.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-laravel-2024-13919",
   "title": "laravel < 11.36.0 \u2014 Laravel framework susceptible to reflected cross-site scripting (CVE-2024-13919)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2024-13919",
   "tech": "laravel",
   "fixed": "11.36.0",
   "remediation": "Upgrade laravel to >= 11.36.0.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2024-13919",
    "https://github.com/laravel/framework/pull/53869",
    "https://github.com/laravel/framework/commit/45287fb2a91c69bb1c110539b9b7341faf5aee33"
   ],
   "match": {
    "tech": "laravel",
    "version_lt": "11.36.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-laravel-2024-52301",
   "title": "laravel < 11.31.0 \u2014 Laravel environment manipulation via query string (CVE-2024-52301)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2024-52301",
   "tech": "laravel",
   "fixed": "11.31.0",
   "remediation": "Upgrade laravel to >= 11.31.0.",
   "refs": [
    "https://github.com/laravel/framework/security/advisories/GHSA-gv7v-rgg6-548h",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-52301",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/laravel/framework/CVE-2024-52301.yaml"
   ],
   "match": {
    "tech": "laravel",
    "version_lt": "11.31.0"
   }
  },
  {
   "key": "cve-laravel-2025-27515",
   "title": "laravel < 10.48.29 \u2014 Laravel has a File Validation Bypass (CVE-2025-27515)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2025-27515",
   "tech": "laravel",
   "fixed": "10.48.29",
   "remediation": "Upgrade laravel to >= 10.48.29.",
   "refs": [
    "https://github.com/laravel/framework/security/advisories/GHSA-78fx-h6xr-vch4",
    "https://nvd.nist.gov/vuln/detail/CVE-2025-27515",
    "https://github.com/laravel/framework/commit/2d133034fefddfb047838f4caca3687a3ba811a5"
   ],
   "match": {
    "tech": "laravel",
    "version_lt": "10.48.29"
   }
  },
  {
   "key": "cve-laravel-2026-48019",
   "title": "laravel < 12.60.0 \u2014 Laravel Framework: CRLF injection in default email rule  (CVE-2026-48019)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2026-48019",
   "tech": "laravel",
   "fixed": "12.60.0",
   "remediation": "Upgrade laravel to >= 12.60.0.",
   "refs": [
    "https://github.com/laravel/framework/security/advisories/GHSA-5vg9-5847-vvmq",
    "https://github.com/laravel/framework"
   ],
   "match": {
    "tech": "laravel",
    "version_lt": "12.60.0"
   }
  },
  {
   "key": "cve-lodash-2018-16487",
   "title": "lodash < 4.17.11 \u2014 Prototype Pollution in lodash (CVE-2018-16487)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2018-16487",
   "tech": "lodash",
   "fixed": "4.17.11",
   "remediation": "Upgrade lodash to >= 4.17.11.",
   "refs": [
    "https://github.com/advisories/GHSA-4xc9-xhrj-v574",
    "https://nvd.nist.gov/vuln/detail/CVE-2018-16487",
    "https://github.com/lodash/lodash/commit/90e6199a161b6445b01454517b40ef65ebecd2ad",
    "https://hackerone.com/reports/380873",
    "https://github.com/advisories/GHSA-4xc9-xhrj-v574",
    "https://security.netapp.com/advisory/ntap-20190919-0004/",
    "https://www.npmjs.com/advisories/782"
   ],
   "match": {
    "tech": "lodash",
    "version_lt": "4.17.11"
   },
   "cwe": "CWE-1321"
  },
  {
   "key": "cve-lodash-2018-3721",
   "title": "lodash < 4.17.5 \u2014 Prototype Pollution in lodash (CVE-2018-3721)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2018-3721",
   "tech": "lodash",
   "fixed": "4.17.5",
   "remediation": "Upgrade lodash to >= 4.17.5.",
   "refs": [
    "https://github.com/advisories/GHSA-fvqr-27wr-82fm",
    "https://nvd.nist.gov/vuln/detail/CVE-2018-3721",
    "https://github.com/lodash/lodash/commit/d8e069cc3410082e44eb18fcf8e7f3d08ebe1d4a",
    "https://hackerone.com/reports/310443",
    "https://github.com/advisories/GHSA-fvqr-27wr-82fm",
    "https://security.netapp.com/advisory/ntap-20190919-0004/",
    "https://www.npmjs.com/advisories/577"
   ],
   "match": {
    "tech": "lodash",
    "version_lt": "4.17.5"
   },
   "cwe": "CWE-1321"
  },
  {
   "key": "cve-lodash-2019-1010266",
   "title": "lodash < 4.17.11 \u2014 Regular Expression Denial of Service (ReDoS) in lodash (CVE-2019-1010266)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2019-1010266",
   "tech": "lodash",
   "fixed": "4.17.11",
   "remediation": "Upgrade lodash to >= 4.17.11.",
   "refs": [
    "https://github.com/advisories/GHSA-x5rq-j2xg-h7qm",
    "https://nvd.nist.gov/vuln/detail/CVE-2019-1010266",
    "https://github.com/lodash/lodash/issues/3359",
    "https://github.com/lodash/lodash/commit/5c08f18d365b64063bfbfa686cbb97cdd6267347",
    "https://github.com/lodash/lodash/wiki/Changelog",
    "https://security.netapp.com/advisory/ntap-20190919-0004/",
    "https://snyk.io/vuln/SNYK-JS-LODASH-73639"
   ],
   "match": {
    "tech": "lodash",
    "version_lt": "4.17.11"
   },
   "cwe": "CWE-1333"
  },
  {
   "key": "cve-lodash-2019-10744",
   "title": "lodash < 4.17.12 \u2014 Prototype Pollution in lodash (CVE-2019-10744)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2019-10744",
   "tech": "lodash",
   "fixed": "4.17.12",
   "remediation": "Upgrade lodash to >= 4.17.12.",
   "refs": [
    "https://github.com/advisories/GHSA-jf85-cpcp-j695",
    "https://nvd.nist.gov/vuln/detail/CVE-2019-10744",
    "https://github.com/lodash/lodash/pull/4336",
    "https://access.redhat.com/errata/RHSA-2019:3024",
    "https://security.netapp.com/advisory/ntap-20191004-0005/",
    "https://snyk.io/vuln/SNYK-JS-LODASH-450202",
    "https://support.f5.com/csp/article/K47105354?utm_source=f5support&amp;utm_medium=RSS",
    "https://www.npmjs.com/advisories/1065",
    "https://www.oracle.com/security-alerts/cpujan2021.html",
    "https://www.oracle.com/security-alerts/cpuoct2020.html"
   ],
   "match": {
    "tech": "lodash",
    "version_lt": "4.17.12"
   },
   "cwe": "CWE-1321"
  },
  {
   "key": "cve-lodash-2020-28500",
   "title": "lodash < 4.17.21 \u2014 Regular Expression Denial of Service (ReDoS) in lodash (CVE-2020-28500)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-28500",
   "tech": "lodash",
   "fixed": "4.17.21",
   "remediation": "Upgrade lodash to >= 4.17.21.",
   "refs": [
    "https://github.com/advisories/GHSA-29mw-wpgm-hmr9",
    "https://nvd.nist.gov/vuln/detail/CVE-2020-28500",
    "https://github.com/lodash/lodash/pull/5065",
    "https://github.com/lodash/lodash/pull/5065/commits/02906b8191d3c100c193fe6f7b27d1c40f200bb7",
    "https://github.com/lodash/lodash/commit/c4847ebe7d14540bb28a8b932a9ce1b9ecbfee1a",
    "https://cert-portal.siemens.com/productcert/pdf/ssa-637483.pdf",
    "https://github.com/lodash/lodash",
    "https://github.com/lodash/lodash/blob/npm/trimEnd.js%23L8",
    "https://security.netapp.com/advisory/ntap-20210312-0006/",
    "https://snyk.io/vuln/SNYK-JAVA-ORGFUJIONWEBJARS-1074896",
    "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARS-1074894",
    "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWER-1074892",
    "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWERGITHUBLODASH-1074895",
    "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-1074893",
    "https://snyk.io/vuln/SNYK-JS-LODASH-1018905",
    "https://www.oracle.com//security-alerts/cpujul2021.html",
    "https://www.oracle.com/security-alerts/cpujan2022.html",
    "https://www.oracle.com/security-alerts/cpujul2022.html",
    "https://www.oracle.com/security-alerts/cpuoct2021.html"
   ],
   "match": {
    "tech": "lodash",
    "version_lt": "4.17.21"
   },
   "cwe": "CWE-1333"
  },
  {
   "key": "cve-lodash-2020-8203",
   "title": "lodash < 4.17.19 \u2014 Prototype Pollution in lodash (CVE-2020-8203)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2020-8203",
   "tech": "lodash",
   "fixed": "4.17.19",
   "remediation": "Upgrade lodash to >= 4.17.19.",
   "refs": [
    "https://github.com/advisories/GHSA-p6mc-m468-83gw",
    "https://nvd.nist.gov/vuln/detail/CVE-2020-8203",
    "https://github.com/lodash/lodash/issues/4744",
    "https://github.com/lodash/lodash/issues/4874",
    "https://github.com/github/advisory-database/pull/2884",
    "https://github.com/lodash/lodash/commit/c84fe82760fb2d3e03a63379b297a1cc1a2fce12",
    "https://hackerone.com/reports/712065",
    "https://hackerone.com/reports/864701",
    "https://github.com/lodash/lodash",
    "https://github.com/lodash/lodash/wiki/Changelog#v41719",
    "https://web.archive.org/web/20210914001339/https://github.com/lodash/lodash/issues/4744"
   ],
   "match": {
    "tech": "lodash",
    "version_lt": "4.17.19"
   },
   "cwe": "CWE-1321"
  },
  {
   "key": "cve-lodash-2021-23337",
   "title": "lodash < 4.17.21 \u2014 Command Injection in lodash (CVE-2021-23337)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2021-23337",
   "tech": "lodash",
   "fixed": "4.17.21",
   "remediation": "Upgrade lodash to >= 4.17.21.",
   "refs": [
    "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
    "https://github.com/lodash/lodash/commit/3469357cff396a26c363f8c1b5a91dde28ba4b1c",
    "https://cert-portal.siemens.com/productcert/pdf/ssa-637483.pdf",
    "https://github.com/lodash/lodash",
    "https://github.com/lodash/lodash/blob/ddfd9b11a0126db2302cb70ec9973b66baec0975/lodash.js#L14851",
    "https://github.com/lodash/lodash/blob/ddfd9b11a0126db2302cb70ec9973b66baec0975/lodash.js%23L14851",
    "https://security.netapp.com/advisory/ntap-20210312-0006/",
    "https://snyk.io/vuln/SNYK-JAVA-ORGFUJIONWEBJARS-1074932",
    "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARS-1074930",
    "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWER-1074928",
    "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWERGITHUBLODASH-1074931",
    "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-1074929",
    "https://snyk.io/vuln/SNYK-JS-LODASH-1040724",
    "https://www.oracle.com//security-alerts/cpujul2021.html",
    "https://www.oracle.com/security-alerts/cpujan2022.html",
    "https://www.oracle.com/security-alerts/cpujul2022.html",
    "https://www.oracle.com/security-alerts/cpuoct2021.html"
   ],
   "match": {
    "tech": "lodash",
    "version_lt": "4.17.21"
   }
  },
  {
   "key": "cve-lodash-2025-13465",
   "title": "lodash < 4.17.23 \u2014 Lodash versions 4.0.0 through 4.17.22 are vulnerable to prototype pollution via the _.unset and _.omit functions. An atta",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2025-13465",
   "tech": "lodash",
   "fixed": "4.17.23",
   "remediation": "Upgrade lodash to >= 4.17.23.",
   "refs": [
    "https://github.com/lodash/lodash/security/advisories/GHSA-xxjr-mmjv-4gpg",
    "https://github.com/lodash/lodash/commit/edadd452146f7e4bad4ea684e955708931d84d81"
   ],
   "match": {
    "tech": "lodash",
    "version_lt": "4.17.23"
   },
   "cwe": "CWE-1321"
  },
  {
   "key": "cve-log4j-2021-44228",
   "title": "Apache Log4j2 2.0-2.14.1 \u2014 Log4Shell JNDI RCE (CVE-2021-44228)",
   "category": "cve",
   "severity": "critical",
   "confidence": "candidate",
   "remediation": "Upgrade Log4j2 to >= 2.17.1 (or 2.3.1/2.12.3 on legacy JVMs).",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
   ],
   "cwe": "CWE-94",
   "cve": "CVE-2021-44228",
   "tech": "log4j",
   "fixed": "2.3.1",
   "match": {
    "tech": "log4j",
    "version_lt": "2.3.1"
   }
  },
  {
   "key": "cve-mootools-2021-23432",
   "title": "mootools < 1.5.3 \u2014 This affects all versions of package mootools. This is due to the ability to pass untrusted input to Object.merge() (CVE-",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2021-23432",
   "tech": "mootools",
   "fixed": "1.5.3",
   "remediation": "Upgrade mootools to >= 1.5.3.",
   "refs": [
    "https://snyk.io/vuln/SNYK-JS-MOOTOOLS-1325536"
   ],
   "match": {
    "tech": "mootools",
    "version_lt": "1.5.3"
   }
  },
  {
   "key": "cve-mootools-2021-32821",
   "title": "mootools < 1.5.3 \u2014 MooTools is a collection of JavaScript utilities for JavaScript developers. All known versions include a CSS selector par",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2021-32821",
   "tech": "mootools",
   "fixed": "1.5.3",
   "remediation": "Upgrade mootools to >= 1.5.3.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2021-32821"
   ],
   "match": {
    "tech": "mootools",
    "version_lt": "1.5.3"
   },
   "cwe": "CWE-1333"
  },
  {
   "key": "cve-nginx-2013-2028",
   "title": "nginx 1.3.9-1.4.0 \u2014 Stack overflow RCE via chunked Transfer-Encoding (CVE-2013-2028)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "remediation": "Upgrade nginx to >= 1.4.1.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2013-2028"
   ],
   "cwe": "CWE-94",
   "cve": "CVE-2013-2028",
   "tech": "nginx",
   "fixed": "1.4.1",
   "match": {
    "tech": "nginx",
    "version_lt": "1.4.1"
   }
  },
  {
   "key": "cve-nginx-2017-7529",
   "title": "nginx < 1.13.3 \u2014 Integer overflow / info disclosure in range filter (CVE-2017-7529)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "remediation": "Upgrade nginx to >= 1.13.3.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-7529"
   ],
   "cve": "CVE-2017-7529",
   "tech": "nginx",
   "fixed": "1.13.3",
   "match": {
    "tech": "nginx",
    "version_lt": "1.13.3"
   }
  },
  {
   "key": "cve-nginx-2019-20372",
   "title": "nginx < 1.17.7 \u2014 HTTP request smuggling via error_page (CVE-2019-20372)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "remediation": "Upgrade nginx to >= 1.17.7.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2019-20372"
   ],
   "cve": "CVE-2019-20372",
   "tech": "nginx",
   "fixed": "1.17.7",
   "match": {
    "tech": "nginx",
    "version_lt": "1.17.7"
   }
  },
  {
   "key": "cve-php-2024-4577",
   "title": "PHP-CGI < 8.3.8 \u2014 CGI argument injection RCE on Windows (CVE-2024-4577)",
   "category": "cve",
   "severity": "critical",
   "confidence": "candidate",
   "remediation": "Upgrade PHP to >= 8.1.29 / 8.2.20 / 8.3.8, or stop running PHP-CGI on Windows.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2024-4577"
   ],
   "cwe": "CWE-94",
   "cve": "CVE-2024-4577",
   "tech": "php",
   "fixed": "8.3.8",
   "match": {
    "tech": "php",
    "version_lt": "8.3.8"
   }
  },
  {
   "key": "cve-prototypejs-2008-7220",
   "title": "prototypejs < 1.5.1.2 \u2014 prototypejs vulnerability (CVE-2008-7220)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2008-7220",
   "tech": "prototypejs",
   "fixed": "1.5.1.2",
   "remediation": "Upgrade prototypejs to >= 1.5.1.2.",
   "refs": [
    "http://prototypejs.org/2008/01/25/prototype-1-6-0-2-bug-fixes-performance-improvements-and-security/",
    "http://www.cvedetails.com/cve/CVE-2008-7220/"
   ],
   "match": {
    "tech": "prototypejs",
    "version_lt": "1.5.1.2"
   }
  },
  {
   "key": "cve-prototypejs-2020-27511",
   "title": "prototypejs < 1.7.4 \u2014 An issue was discovered in the stripTags and unescapeHTML components in Prototype 1.7.3 where an attacker can cause a ",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2020-27511",
   "tech": "prototypejs",
   "fixed": "1.7.4",
   "remediation": "Upgrade prototypejs to >= 1.7.4.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2020-27511",
    "https://github.com/prototypejs/prototype/issues/355"
   ],
   "match": {
    "tech": "prototypejs",
    "version_lt": "1.7.4"
   },
   "cwe": "CWE-1333"
  },
  {
   "key": "cve-react-2013-7035",
   "title": "react < 0.4.2 \u2014 potential XSS vulnerability can arise when using user data as a key (CVE-2013-7035)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2013-7035",
   "tech": "react",
   "fixed": "0.4.2",
   "remediation": "Upgrade react to >= 0.4.2.",
   "refs": [
    "https://facebook.github.io/react/blog/2013/12/18/react-v0.5.2-v0.4.2.html",
    "https://github.com/advisories/GHSA-g53w-52xc-2j85"
   ],
   "match": {
    "tech": "react",
    "version_lt": "0.4.2"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-react-2018-6341",
   "title": "react < 16.0.1 \u2014 potential XSS vulnerability when the attacker controls an attribute name (CVE-2018-6341)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2018-6341",
   "tech": "react",
   "fixed": "16.0.1",
   "remediation": "Upgrade react to >= 16.0.1.",
   "refs": [
    "https://github.com/facebook/react/blob/master/CHANGELOG.md",
    "https://reactjs.org/blog/2018/08/01/react-v-16-4-2.html"
   ],
   "match": {
    "tech": "react",
    "version_lt": "16.0.1"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-struts-2017-5638",
   "title": "Apache Struts 2 < 2.3.32 / < 2.5.10.1 \u2014 Jakarta Multipart RCE (CVE-2017-5638)",
   "category": "cve",
   "severity": "critical",
   "confidence": "candidate",
   "remediation": "Upgrade Struts to >= 2.3.32 / 2.5.10.1.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-5638"
   ],
   "cwe": "CWE-94",
   "cve": "CVE-2017-5638",
   "tech": "struts",
   "fixed": "2.3.32",
   "match": {
    "tech": "struts",
    "version_lt": "2.3.32"
   }
  },
  {
   "key": "cve-symfony-2012-6431",
   "title": "symfony < 2.0.19 \u2014 Symfony Allows URI Restrictions Bypass Via Double-Encoded String (CVE-2012-6431)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2012-6431",
   "tech": "symfony",
   "fixed": "2.0.19",
   "remediation": "Upgrade symfony to >= 2.0.19.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2012-6431",
    "https://github.com/symfony/symfony/commit/55014a6841bec50046e8329a4835c160ac31a496",
    "https://github.com/symfony/symfony/commit/8b2c17f80377582287a78e0b521497e039dd6b0d"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "2.0.19"
   }
  },
  {
   "key": "cve-symfony-2012-6432",
   "title": "symfony < 2.1.5 \u2014 Symfony Access Control Vulnerability (CVE-2012-6432)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2012-6432",
   "tech": "symfony",
   "fixed": "2.1.5",
   "remediation": "Upgrade symfony to >= 2.1.5.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2012-6432",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/symfony/CVE-2012-6432.yaml",
    "https://github.com/symfony/symfony"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "2.1.5"
   }
  },
  {
   "key": "cve-symfony-2013-1348",
   "title": "symfony < 2.0.22 \u2014 Symphony Vulnerable to PHP Code Injection via YAML Parsing (CVE-2013-1348)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2013-1348",
   "tech": "symfony",
   "fixed": "2.0.22",
   "remediation": "Upgrade symfony to >= 2.0.22.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2013-1348",
    "https://github.com/symfony/symfony/commit/ac756bf39e646b4e130fad058d10a0228dbd9779",
    "https://exchange.xforce.ibmcloud.com/vulnerabilities/81550"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "2.0.22"
   }
  },
  {
   "key": "cve-symfony-2013-1397",
   "title": "symfony < 2.2.0-BETA2 \u2014 Symfony Arbitrary PHP code Execution (CVE-2013-1397)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2013-1397",
   "tech": "symfony",
   "fixed": "2.2.0-BETA2",
   "remediation": "Upgrade symfony to >= 2.2.0-BETA2.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2013-1397",
    "https://github.com/symfony/symfony/commit/ba6e3159c0eeb3b6e21db32fce8fa2535cb3aa77",
    "https://exchange.xforce.ibmcloud.com/vulnerabilities/81551"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "2.2.0-BETA2"
   }
  },
  {
   "key": "cve-symfony-2013-4751",
   "title": "symfony < 2.3.3 \u2014 Symfony collectionCascaded and collectionCascadedDeeply fields security bypass (CVE-2013-4751)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2013-4751",
   "tech": "symfony",
   "fixed": "2.3.3",
   "remediation": "Upgrade symfony to >= 2.3.3.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2013-4751",
    "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2013-4751",
    "https://exchange.xforce.ibmcloud.com/vulnerabilities/86364"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "2.3.3"
   }
  },
  {
   "key": "cve-symfony-2013-4752",
   "title": "symfony < 2.3.3 \u2014 Symfony Host Header Injection vulnerability in the HttpFoundation component (CVE-2013-4752)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2013-4752",
   "tech": "symfony",
   "fixed": "2.3.3",
   "remediation": "Upgrade symfony to >= 2.3.3.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2013-4752",
    "https://web.archive.org/web/20130901060826/http://www.securityfocus.com/bid/61715",
    "https://symfony.com/blog/security-releases-symfony-2-0-24-2-1-12-2-2-5-and-2-3-3-released"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "2.3.3"
   }
  },
  {
   "key": "cve-symfony-2013-5958",
   "title": "symfony < 2.3.6 \u2014 Symfony Denial of Service Via Long Password Hashing (CVE-2013-5958)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2013-5958",
   "tech": "symfony",
   "fixed": "2.3.6",
   "remediation": "Upgrade symfony to >= 2.3.6.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2013-5958",
    "https://github.com/symfony/symfony/issues/11522",
    "https://github.com/symfony/polyfill/pull/155"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "2.3.6"
   },
   "cwe": "CWE-400"
  },
  {
   "key": "cve-symfony-2014-4931",
   "title": "symfony < 2.5.4 \u2014 Code injection in the way Symfony implements translation caching in FrameworkBundle (CVE-2014-4931)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2014-4931",
   "tech": "symfony",
   "fixed": "2.5.4",
   "remediation": "Upgrade symfony to >= 2.5.4.",
   "refs": [
    "https://github.com/symfony/symfony/commit/06a80fbdbe744ad6f3010479ba64ef5cf35dd9af.patch",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/framework-bundle/CVE-2014-4931.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/symfony/CVE-2014-4931.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "2.5.4"
   }
  },
  {
   "key": "cve-symfony-2014-5244",
   "title": "symfony < 2.5.4 \u2014 Symfony vulnerable to denial of service via a malicious HTTP Host header (CVE-2014-5244)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2014-5244",
   "tech": "symfony",
   "fixed": "2.5.4",
   "remediation": "Upgrade symfony to >= 2.5.4.",
   "refs": [
    "https://github.com/symfony/symfony/pull/11828",
    "https://github.com/symfony/symfony/commit/1ee96a8b1b0987ffe2a62dca7ad268bf9edfa9b8",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/http-foundation/CVE-2014-5244.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "2.5.4"
   },
   "cwe": "CWE-400"
  },
  {
   "key": "cve-symfony-2014-5245",
   "title": "symfony < 2.5.4 \u2014 Symfony allows direct access of ESI URLs behind a trusted proxy (CVE-2014-5245)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2014-5245",
   "tech": "symfony",
   "fixed": "2.5.4",
   "remediation": "Upgrade symfony to >= 2.5.4.",
   "refs": [
    "https://github.com/symfony/symfony/pull/11831",
    "https://github.com/symfony/symfony/commit/654b1f281e09dd96ffbbd3da815411700423ecf5",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/http-kernel/CVE-2014-5245.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "2.5.4"
   }
  },
  {
   "key": "cve-symfony-2014-6061",
   "title": "symfony < 2.5.4 \u2014 Symfony has a security issue when parsing the Authorization header (CVE-2014-6061)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2014-6061",
   "tech": "symfony",
   "fixed": "2.5.4",
   "remediation": "Upgrade symfony to >= 2.5.4.",
   "refs": [
    "https://github.com/symfony/symfony/pull/11829",
    "https://github.com/symfony/symfony/commit/3b4046e89467dc1fb5e079e377c2cfd4c239f904",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/http-foundation/CVE-2014-6061.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "2.5.4"
   }
  },
  {
   "key": "cve-symfony-2014-6072",
   "title": "symfony < 2.5.4 \u2014 Symfony Cross-Site Request Forgery vulnerability in the Web Profiler (CVE-2014-6072)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2014-6072",
   "tech": "symfony",
   "fixed": "2.5.4",
   "remediation": "Upgrade symfony to >= 2.5.4.",
   "refs": [
    "https://github.com/symfony/symfony/pull/11832",
    "https://github.com/symfony/symfony/commit/f38536ab79058f6a934426c41170256ba9623a02",
    "https://github.com/symfony/web-profiler-bundle/commit/5b589ba83faf7eb20cec50725cd657075aebdd36"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "2.5.4"
   }
  },
  {
   "key": "cve-symfony-2015-2308",
   "title": "symfony < 2.6.6 \u2014 Symfony Vulnerable to PHP Eval Injection (CVE-2015-2308)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2015-2308",
   "tech": "symfony",
   "fixed": "2.6.6",
   "remediation": "Upgrade symfony to >= 2.6.6.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2015-2308",
    "https://github.com/symfony/symfony/pull/14167/commits/195c57e1f50765aff33137689b16e126a689056a",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/http-kernel/CVE-2015-2308.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "2.6.6"
   }
  },
  {
   "key": "cve-symfony-2015-2309",
   "title": "symfony < 2.6.6 \u2014 Symfony has unsafe methods in the Request class (CVE-2015-2309)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2015-2309",
   "tech": "symfony",
   "fixed": "2.6.6",
   "remediation": "Upgrade symfony to >= 2.6.6.",
   "refs": [
    "https://github.com/symfony/symfony/pull/14166",
    "https://github.com/symfony/symfony/commit/6c73f0ce9302a0091bbfbb96f317e400ce16ef84",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/http-foundation/CVE-2015-2309.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "2.6.6"
   }
  },
  {
   "key": "cve-symfony-2015-4050",
   "title": "symfony < 2.6.8 \u2014 Symfony Incorrect Access Control (CVE-2015-4050)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2015-4050",
   "tech": "symfony",
   "fixed": "2.6.8",
   "remediation": "Upgrade symfony to >= 2.6.8.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2015-4050",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/http-kernel/CVE-2015-4050.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/symfony/CVE-2015-4050.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "2.6.8"
   }
  },
  {
   "key": "cve-symfony-2015-8124",
   "title": "symfony < 2.7.7 \u2014 Symfony Session Fixation Vulnerability (CVE-2015-8124)",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2015-8124",
   "tech": "symfony",
   "fixed": "2.7.7",
   "remediation": "Upgrade symfony to >= 2.7.7.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2015-8124",
    "https://github.com/symfony/symfony/pull/16631",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/security-http/CVE-2015-8124.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "2.7.7"
   }
  },
  {
   "key": "cve-symfony-2015-8125",
   "title": "symfony < 2.6.12 \u2014 Symfony Vulnerable to Timing Attack (CVE-2015-8125)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2015-8125",
   "tech": "symfony",
   "fixed": "2.6.12",
   "remediation": "Upgrade symfony to >= 2.6.12.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2015-8125",
    "https://github.com/symfony/symfony/pull/16630",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/form/CVE-2015-8125.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "2.6.12"
   }
  },
  {
   "key": "cve-symfony-2016-1902",
   "title": "symfony < 2.7.9 \u2014 Symfony Cryptographic Vulnerability (CVE-2016-1902)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2016-1902",
   "tech": "symfony",
   "fixed": "2.7.9",
   "remediation": "Upgrade symfony to >= 2.7.9.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2016-1902",
    "https://github.com/symfony/symfony/pull/17359",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/security-core/CVE-2016-1902.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "2.7.9"
   }
  },
  {
   "key": "cve-symfony-2016-2403",
   "title": "symfony < 3.0.6 \u2014 Symfony Authentication Bypass (CVE-2016-2403)",
   "category": "cve",
   "severity": "critical",
   "confidence": "candidate",
   "cve": "CVE-2016-2403",
   "tech": "symfony",
   "fixed": "3.0.6",
   "remediation": "Upgrade symfony to >= 3.0.6.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2016-2403",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/security-core/CVE-2016-2403.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/security/CVE-2016-2403.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "3.0.6"
   }
  },
  {
   "key": "cve-symfony-2016-4423",
   "title": "symfony < 3.0.6 \u2014 Symphony Denial of Service Via Overlong Usernames (CVE-2016-4423)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2016-4423",
   "tech": "symfony",
   "fixed": "3.0.6",
   "remediation": "Upgrade symfony to >= 3.0.6.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2016-4423",
    "https://github.com/symfony/symfony/pull/18733",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/security-http/CVE-2016-4423.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "3.0.6"
   },
   "cwe": "CWE-400"
  },
  {
   "key": "cve-symfony-2017-11365",
   "title": "symfony < 3.3.5 \u2014 Symfony Incorrect Access Control (CVE-2017-11365)",
   "category": "cve",
   "severity": "critical",
   "confidence": "candidate",
   "cve": "CVE-2017-11365",
   "tech": "symfony",
   "fixed": "3.3.5",
   "remediation": "Upgrade symfony to >= 3.3.5.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-11365",
    "https://github.com/symfony/symfony/pull/23507",
    "https://github.com/symfony/symfony/commit/878198cefae028386c6dc800ccbf18f2b9cbff3f"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "3.3.5"
   }
  },
  {
   "key": "cve-symfony-2017-16652",
   "title": "symfony < 3.3.13 \u2014 Symfony Open Redirect (CVE-2017-16652)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2017-16652",
   "tech": "symfony",
   "fixed": "3.3.13",
   "remediation": "Upgrade symfony to >= 3.3.13.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-16652",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/security-http/CVE-2017-16652.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/security/CVE-2017-16652.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "3.3.13"
   },
   "cwe": "CWE-601"
  },
  {
   "key": "cve-symfony-2017-16653",
   "title": "symfony < 3.3.13 \u2014 Symfony CSRF Vulnerability (CVE-2017-16653)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2017-16653",
   "tech": "symfony",
   "fixed": "3.3.13",
   "remediation": "Upgrade symfony to >= 3.3.13.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-16653",
    "https://github.com/symfony/symfony/pull/24992",
    "https://github.com/symfony/symfony/commit/b4dbdd7cd8732483d585eacff3428c16b07ad15e"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "3.3.13"
   },
   "cwe": "CWE-352"
  },
  {
   "key": "cve-symfony-2017-16654",
   "title": "symfony < 3.3.13 \u2014 Symfony Directory Traversal (CVE-2017-16654)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2017-16654",
   "tech": "symfony",
   "fixed": "3.3.13",
   "remediation": "Upgrade symfony to >= 3.3.13.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-16654",
    "https://github.com/symfony/symfony/pull/24994",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/intl/CVE-2017-16654.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "3.3.13"
   }
  },
  {
   "key": "cve-symfony-2017-16790",
   "title": "symfony < 3.3.13 \u2014 Symfony SSRF Vulnerability via Form Component (CVE-2017-16790)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2017-16790",
   "tech": "symfony",
   "fixed": "3.3.13",
   "remediation": "Upgrade symfony to >= 3.3.13.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-16790",
    "https://github.com/symfony/symfony/pull/24993",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/form/CVE-2017-16790.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "3.3.13"
   }
  },
  {
   "key": "cve-symfony-2018-11385",
   "title": "symfony < 4.0.11 \u2014 Symfony Session Fixation Vulnerability (CVE-2018-11385)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2018-11385",
   "tech": "symfony",
   "fixed": "4.0.11",
   "remediation": "Upgrade symfony to >= 4.0.11.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2018-11385",
    "https://github.com/symfony/symfony/commit/194caff28b56707ea98e746c6582c06acbb9bc3f",
    "https://github.com/symfony/symfony/commit/fa5bf4b17d45ee32f41bd1a9abc3fb6c134ec89b"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "4.0.11"
   }
  },
  {
   "key": "cve-symfony-2018-11386",
   "title": "symfony < 4.0.11 \u2014 Symfony DoS (CVE-2018-11386)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2018-11386",
   "tech": "symfony",
   "fixed": "4.0.11",
   "remediation": "Upgrade symfony to >= 4.0.11.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2018-11386",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/http-foundation/CVE-2018-11386.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/symfony/CVE-2018-11386.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "4.0.11"
   }
  },
  {
   "key": "cve-symfony-2018-11406",
   "title": "symfony < 4.0.11 \u2014 Symfony CSRF Token Fixation (CVE-2018-11406)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2018-11406",
   "tech": "symfony",
   "fixed": "4.0.11",
   "remediation": "Upgrade symfony to >= 4.0.11.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2018-11406",
    "https://github.com/symfony/symfony/commit/319e1bdd43979d9c1559497de8d69adea28ab8d1",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/security-bundle/CVE-2018-11406.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "4.0.11"
   },
   "cwe": "CWE-352"
  },
  {
   "key": "cve-symfony-2018-11407",
   "title": "symfony < 4.0.7 \u2014 Symfony Authentication Bypass (CVE-2018-11407)",
   "category": "cve",
   "severity": "critical",
   "confidence": "candidate",
   "cve": "CVE-2018-11407",
   "tech": "symfony",
   "fixed": "4.0.7",
   "remediation": "Upgrade symfony to >= 4.0.7.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2018-11407",
    "https://github.com/symfony/symfony/pull/27377",
    "https://github.com/symfony/symfony/commit/b46fc93785d37ffa5d706a82cd175b33ce8f2934"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "4.0.7"
   }
  },
  {
   "key": "cve-symfony-2018-11408",
   "title": "symfony < 4.0.11 \u2014 Symfony Open Redirect (CVE-2018-11408)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2018-11408",
   "tech": "symfony",
   "fixed": "4.0.11",
   "remediation": "Upgrade symfony to >= 4.0.11.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2018-11408",
    "https://github.com/symfony/symfony/commit/b20e83562e32c56f8d9b8296ab07b0e4c0a54db8",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/security-bundle/CVE-2018-11408.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "4.0.11"
   },
   "cwe": "CWE-601"
  },
  {
   "key": "cve-symfony-2018-14773",
   "title": "symfony < 4.1.3 \u2014 Symfony HTTP Foundation web cache poisoning (CVE-2018-14773)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2018-14773",
   "tech": "symfony",
   "fixed": "4.1.3",
   "remediation": "Upgrade symfony to >= 4.1.3.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2018-14773",
    "https://github.com/symfony/symfony/commit/e447e8b92148ddb3d1956b96638600ec95e08f6b",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/http-foundation/CVE-2018-14773.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "4.1.3"
   }
  },
  {
   "key": "cve-symfony-2018-14774",
   "title": "symfony < 4.1.3 \u2014 Symfony Host Header Injection (CVE-2018-14774)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2018-14774",
   "tech": "symfony",
   "fixed": "4.1.3",
   "remediation": "Upgrade symfony to >= 4.1.3.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2018-14774",
    "https://github.com/symfony/symfony/commit/725dee4cd8b4ccd52e335ae4b4522242cea9bd4a",
    "https://github.com/symfony/symfony/commit/7f912bbb78377c2ea331b3da28363435fbd91337"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "4.1.3"
   }
  },
  {
   "key": "cve-symfony-2018-19789",
   "title": "symfony < 4.2.1 \u2014 Symfony Path Disclosure (CVE-2018-19789)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2018-19789",
   "tech": "symfony",
   "fixed": "4.2.1",
   "remediation": "Upgrade symfony to >= 4.2.1.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2018-19789",
    "https://github.com/symfony/symfony/commit/b65e6f1a47b68f2713b60cdac9cc3a4af62a2d1c",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/form/CVE-2018-19789.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "4.2.1"
   }
  },
  {
   "key": "cve-symfony-2018-19790",
   "title": "symfony < 4.1.9 \u2014 Symfony Open Redirect (CVE-2018-19790)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2018-19790",
   "tech": "symfony",
   "fixed": "4.1.9",
   "remediation": "Upgrade symfony to >= 4.1.9.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2018-19790",
    "https://github.com/symfony/symfony/commit/99a0cec0a6be39ce5ef38386e57339603b33ee5b",
    "https://www.debian.org/security/2019/dsa-4441"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "4.1.9"
   },
   "cwe": "CWE-601"
  },
  {
   "key": "cve-symfony-2019-10909",
   "title": "symfony < 8.6.15 \u2014 Symfony Cross-site Scripting (XSS) vulnerability (CVE-2019-10909)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2019-10909",
   "tech": "symfony",
   "fixed": "8.6.15",
   "remediation": "Upgrade symfony to >= 8.6.15.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2019-10909",
    "https://github.com/symfony/symfony/commit/ab4d05358c3d0dd1a36fc8c306829f68e3dd84e2",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/drupal/core/CVE-2019-10909.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.6.15"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-symfony-2019-10910",
   "title": "symfony < 4.2.7 \u2014 Symfony Service IDs Allow Injection (CVE-2019-10910)",
   "category": "cve",
   "severity": "critical",
   "confidence": "candidate",
   "cve": "CVE-2019-10910",
   "tech": "symfony",
   "fixed": "4.2.7",
   "remediation": "Upgrade symfony to >= 4.2.7.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2019-10910",
    "https://github.com/symfony/symfony/commit/3876c75f858d5d82e2c309698d21af2f1d721afb",
    "https://github.com/symfony/symfony/commit/4c80c3444854ef384df94deb4acbcef4b5e5243b"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "4.2.7"
   }
  },
  {
   "key": "cve-symfony-2019-10911",
   "title": "symfony < 4.2.7 \u2014 Improper authentication in Symfony (CVE-2019-10911)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2019-10911",
   "tech": "symfony",
   "fixed": "4.2.7",
   "remediation": "Upgrade symfony to >= 4.2.7.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2019-10911",
    "https://github.com/symfony/symfony/commit/a29ce2817cf43bb1850cf6af114004ac26c7a081",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/security-http/CVE-2019-10911.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "4.2.7"
   }
  },
  {
   "key": "cve-symfony-2019-10913",
   "title": "symfony < 4.2.7 \u2014 Invalid HTTP method overrides allow possible XSS or other attacks in Symfony (CVE-2019-10913)",
   "category": "cve",
   "severity": "critical",
   "confidence": "candidate",
   "cve": "CVE-2019-10913",
   "tech": "symfony",
   "fixed": "4.2.7",
   "remediation": "Upgrade symfony to >= 4.2.7.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2019-10913",
    "https://github.com/symfony/symfony/commit/944e60f083c3bffbc6a0b5112db127a10a66a8ec",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/http-foundation/CVE-2019-10913.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "4.2.7"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-symfony-2019-11325",
   "title": "symfony < 4.3.8 \u2014 Improper Input Validation in Symfony (CVE-2019-11325)",
   "category": "cve",
   "severity": "critical",
   "confidence": "candidate",
   "cve": "CVE-2019-11325",
   "tech": "symfony",
   "fixed": "4.3.8",
   "remediation": "Upgrade symfony to >= 4.3.8.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2019-11325",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/symfony/CVE-2019-11325.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/var-exporter/CVE-2019-11325.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "4.3.8"
   }
  },
  {
   "key": "cve-symfony-2019-18886",
   "title": "symfony < 4.3.8 \u2014 User enumeration leak using switch user functionality in Symfony (CVE-2019-18886)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2019-18886",
   "tech": "symfony",
   "fixed": "4.3.8",
   "remediation": "Upgrade symfony to >= 4.3.8.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2019-18886",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/security-http/CVE-2019-18886.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/symfony/CVE-2019-18886.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "4.3.8"
   }
  },
  {
   "key": "cve-symfony-2019-18887",
   "title": "symfony < 4.3.8 \u2014 Symfony Http-Kernel has non-constant time comparison in UriSigner (CVE-2019-18887)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2019-18887",
   "tech": "symfony",
   "fixed": "4.3.8",
   "remediation": "Upgrade symfony to >= 4.3.8.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2019-18887",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/http-kernel/CVE-2019-18887.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/symfony/CVE-2019-18887.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "4.3.8"
   }
  },
  {
   "key": "cve-symfony-2019-18888",
   "title": "symfony < 4.3.8 \u2014 Argument injection in a MimeTypeGuesser in Symfony (CVE-2019-18888)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2019-18888",
   "tech": "symfony",
   "fixed": "4.3.8",
   "remediation": "Upgrade symfony to >= 4.3.8.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2019-18888",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/http-foundation/CVE-2019-18888.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/mime/CVE-2019-18888.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "4.3.8"
   }
  },
  {
   "key": "cve-symfony-2019-18889",
   "title": "symfony < 4.3.8 \u2014 Symfony Unsafe Cache Serialization Could Enable RCE (CVE-2019-18889)",
   "category": "cve",
   "severity": "critical",
   "confidence": "candidate",
   "cve": "CVE-2019-18889",
   "tech": "symfony",
   "fixed": "4.3.8",
   "remediation": "Upgrade symfony to >= 4.3.8.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2019-18889",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/cache/CVE-2019-18889.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/symfony/CVE-2019-18889.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "4.3.8"
   },
   "cwe": "CWE-94"
  },
  {
   "key": "cve-symfony-2020-15094",
   "title": "symfony < 5.1.5 \u2014 RCE in Symfony (CVE-2020-15094)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2020-15094",
   "tech": "symfony",
   "fixed": "5.1.5",
   "remediation": "Upgrade symfony to >= 5.1.5.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-754h-5r27-7x3r",
    "https://nvd.nist.gov/vuln/detail/CVE-2020-15094",
    "https://github.com/symfony/symfony/commit/d9910e0b33a2e0f993abff41c6fbc86951b66d78"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "5.1.5"
   },
   "cwe": "CWE-94"
  },
  {
   "key": "cve-symfony-2020-5255",
   "title": "symfony < 5.0.7 \u2014 Prevent cache poisoning via a Response Content-Type header in Symfony (CVE-2020-5255)",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2020-5255",
   "tech": "symfony",
   "fixed": "5.0.7",
   "remediation": "Upgrade symfony to >= 5.0.7.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-mcx4-f5f5-4859",
    "https://nvd.nist.gov/vuln/detail/CVE-2020-5255",
    "https://github.com/symfony/symfony/commit/dca343442e6a954f96a2609e7b4e9c21ed6d74e6"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "5.0.7"
   }
  },
  {
   "key": "cve-symfony-2020-5274",
   "title": "symfony < 5.0.4 \u2014 Exceptions displayed in non-debug configurations in Symfony (CVE-2020-5274)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-5274",
   "tech": "symfony",
   "fixed": "5.0.4",
   "remediation": "Upgrade symfony to >= 5.0.4.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-m884-279h-32v2",
    "https://nvd.nist.gov/vuln/detail/CVE-2020-5274",
    "https://github.com/symfony/symfony/commit/629d21b800a15dc649fb0ae9ed7cd9211e7e45db"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "5.0.4"
   }
  },
  {
   "key": "cve-symfony-2020-5275",
   "title": "symfony < 5.0.7 \u2014 Firewall configured with unanimous strategy was not actually unanimous in Symfony (CVE-2020-5275)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2020-5275",
   "tech": "symfony",
   "fixed": "5.0.7",
   "remediation": "Upgrade symfony to >= 5.0.7.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-g4m9-5hpf-hx72",
    "https://nvd.nist.gov/vuln/detail/CVE-2020-5275",
    "https://github.com/symfony/symfony/commit/c935e4a3fba6cc2ab463a6ca382858068d63cebf"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "5.0.7"
   }
  },
  {
   "key": "cve-symfony-2021-21424",
   "title": "symfony < 5.2.9 \u2014 Prevent user enumeration using Guard or the new Authenticator-based Security (CVE-2021-21424)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2021-21424",
   "tech": "symfony",
   "fixed": "5.2.9",
   "remediation": "Upgrade symfony to >= 5.2.9.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-5pv8-ppvj-4h68",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-21424",
    "https://github.com/symfony/symfony/commit/2a581d22cc621b33d5464ed65c4bc2057f72f011"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "5.2.9"
   }
  },
  {
   "key": "cve-symfony-2021-32693",
   "title": "symfony < 5.3.2 \u2014 Authentication granted to all firewalls instead of just one (CVE-2021-32693)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2021-32693",
   "tech": "symfony",
   "fixed": "5.3.2",
   "remediation": "Upgrade symfony to >= 5.3.2.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-rfcf-m67m-jcrq",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-32693",
    "https://github.com/symfony/security-http/commit/6bf4c31219773a558b019ee12e54572174ff8129"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "5.3.2"
   }
  },
  {
   "key": "cve-symfony-2021-41267",
   "title": "symfony < 5.3.12 \u2014 Webcache Poisoning in symfony/http-kernel (CVE-2021-41267)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2021-41267",
   "tech": "symfony",
   "fixed": "5.3.12",
   "remediation": "Upgrade symfony to >= 5.3.12.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-q3j3-w37x-hq2q",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-41267",
    "https://github.com/symfony/symfony/pull/44243"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "5.3.12"
   }
  },
  {
   "key": "cve-symfony-2021-41268",
   "title": "symfony < 5.3.12 \u2014 Cookie persistence after password changes in symfony/security-bundle (CVE-2021-41268)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2021-41268",
   "tech": "symfony",
   "fixed": "5.3.12",
   "remediation": "Upgrade symfony to >= 5.3.12.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-qw36-p97w-vcqr",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-41268",
    "https://github.com/symfony/symfony/pull/44243"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "5.3.12"
   }
  },
  {
   "key": "cve-symfony-2021-41270",
   "title": "symfony < 5.3.12 \u2014 CSV Injection in symfony/serializer (CVE-2021-41270)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2021-41270",
   "tech": "symfony",
   "fixed": "5.3.12",
   "remediation": "Upgrade symfony to >= 5.3.12.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-2xhg-w2g5-w95x",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-41270",
    "https://github.com/symfony/symfony/pull/44243"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "5.3.12"
   }
  },
  {
   "key": "cve-symfony-2022-24894",
   "title": "symfony < 6.2.6 \u2014 Symfony storing cookie headers in HttpCache (CVE-2022-24894)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-24894",
   "tech": "symfony",
   "fixed": "6.2.6",
   "remediation": "Upgrade symfony to >= 6.2.6.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-h7vf-5wrv-9fhv",
    "https://nvd.nist.gov/vuln/detail/CVE-2022-24894",
    "https://github.com/symfony/symfony/commit/d2f6322af9444ac5cd1ef3ac6f280dbef7f9d1fb"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "6.2.6"
   }
  },
  {
   "key": "cve-symfony-2022-24895",
   "title": "symfony < 6.2.6 \u2014 Symfony vulnerable to Session Fixation of CSRF tokens (CVE-2022-24895)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-24895",
   "tech": "symfony",
   "fixed": "6.2.6",
   "remediation": "Upgrade symfony to >= 6.2.6.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-3gv2-29qc-v67m",
    "https://nvd.nist.gov/vuln/detail/CVE-2022-24895",
    "https://github.com/symfony/security-bundle/commit/076fd2088ada33d760758d98ff07ddedbf567946"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "6.2.6"
   },
   "cwe": "CWE-352"
  },
  {
   "key": "cve-symfony-2023-46733",
   "title": "symfony < 6.3.8 \u2014 Symfony possible session fixation vulnerability (CVE-2023-46733)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2023-46733",
   "tech": "symfony",
   "fixed": "6.3.8",
   "remediation": "Upgrade symfony to >= 6.3.8.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-m2wj-r6g3-fxfx",
    "https://nvd.nist.gov/vuln/detail/CVE-2023-46733",
    "https://github.com/symfony/symfony/commit/7467bd7e3f888b333102bc664b5e02ef1e7f88b9"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "6.3.8"
   }
  },
  {
   "key": "cve-symfony-2023-46734",
   "title": "symfony < 6.3.8 \u2014 Symfony potential Cross-site Scripting vulnerabilities in CodeExtension filters (CVE-2023-46734)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2023-46734",
   "tech": "symfony",
   "fixed": "6.3.8",
   "remediation": "Upgrade symfony to >= 6.3.8.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-q847-2q57-wmr3",
    "https://nvd.nist.gov/vuln/detail/CVE-2023-46734",
    "https://github.com/symfony/symfony/commit/5d095d5feb1322b16450284a04d6bb48d1198f54"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "6.3.8"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-symfony-2023-46735",
   "title": "symfony < 6.3.8 \u2014 Symfony potential Cross-site Scripting in WebhookController (CVE-2023-46735)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2023-46735",
   "tech": "symfony",
   "fixed": "6.3.8",
   "remediation": "Upgrade symfony to >= 6.3.8.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-72x2-5c85-6wmr",
    "https://nvd.nist.gov/vuln/detail/CVE-2023-46735",
    "https://github.com/symfony/symfony/commit/8128c302430394f639e818a7103b3f6815d8d962"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "6.3.8"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-symfony-2024-50340",
   "title": "symfony < 7.1.7 \u2014 Symfony allows changing the environment through a query (CVE-2024-50340)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2024-50340",
   "tech": "symfony",
   "fixed": "7.1.7",
   "remediation": "Upgrade symfony to >= 7.1.7.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-x8vp-gf4q-mw5j",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-50340",
    "https://github.com/symfony/symfony/commit/a77b308c3f179ed7c8a8bc295f82b2d6ee3493fa"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "7.1.7"
   }
  },
  {
   "key": "cve-symfony-2024-50341",
   "title": "symfony < 7.1.3 \u2014 Symfony's `Security::login` does not take into account custom `user_checker` (CVE-2024-50341)",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2024-50341",
   "tech": "symfony",
   "fixed": "7.1.3",
   "remediation": "Upgrade symfony to >= 7.1.3.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-jxgr-3v7q-3w9v",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-50341",
    "https://github.com/symfony/symfony/commit/22a0789a0085c3ee96f4ef715ecad8255cf0e105"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "7.1.3"
   }
  },
  {
   "key": "cve-symfony-2024-50342",
   "title": "symfony < 7.1.8 \u2014 Symfony allows internal address and port enumeration by NoPrivateNetworkHttpClient (CVE-2024-50342)",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2024-50342",
   "tech": "symfony",
   "fixed": "7.1.8",
   "remediation": "Upgrade symfony to >= 7.1.8.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-9c3x-r3wp-mgxm",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-50342",
    "https://github.com/symfony/symfony/commit/296d4b34a33b1a6ca5475c6040b3203622520f5b"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "7.1.8"
   }
  },
  {
   "key": "cve-symfony-2024-50343",
   "title": "symfony < 7.1.4 \u2014 Symfony has an incorrect response from Validator when input ends with `\\n` (CVE-2024-50343)",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2024-50343",
   "tech": "symfony",
   "fixed": "7.1.4",
   "remediation": "Upgrade symfony to >= 7.1.4.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-g3rh-rrhp-jhh9",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-50343",
    "https://github.com/symfony/symfony/commit/7d1032bbead9a4229b32fa6ebca32681c80cb76f"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "7.1.4"
   }
  },
  {
   "key": "cve-symfony-2024-51736",
   "title": "symfony < 7.1.7 \u2014 Symfony vulnerable to command execution hijack on Windows with Process class (CVE-2024-51736)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2024-51736",
   "tech": "symfony",
   "fixed": "7.1.7",
   "remediation": "Upgrade symfony to >= 7.1.7.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-qq5c-677p-737q",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-51736",
    "https://github.com/symfony/symfony/commit/18ecd03eda3917fdf901a48e72518f911c64a1c9"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "7.1.7"
   }
  },
  {
   "key": "cve-symfony-2025-64500",
   "title": "symfony < 7.3.7 \u2014 Symfony's incorrect parsing of PATH_INFO can lead to limited authorization bypass (CVE-2025-64500)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2025-64500",
   "tech": "symfony",
   "fixed": "7.3.7",
   "remediation": "Upgrade symfony to >= 7.3.7.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-3rg7-wf37-54rm",
    "https://nvd.nist.gov/vuln/detail/CVE-2025-64500",
    "https://github.com/symfony/symfony/commit/9962b91b12bb791322fa73836b350836b6db7cac"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "7.3.7"
   }
  },
  {
   "key": "cve-symfony-2026-24739",
   "title": "symfony < 8.0.5 \u2014 Symfony's incorrect argument escaping under MSYS2/Git Bash can lead to destructive file operations on Windows (CVE-2026-24",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-24739",
   "tech": "symfony",
   "fixed": "8.0.5",
   "remediation": "Upgrade symfony to >= 8.0.5.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-r39x-jcww-82v6",
    "https://nvd.nist.gov/vuln/detail/CVE-2026-24739",
    "https://github.com/symfony/symfony/issues/62921"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.5"
   }
  },
  {
   "key": "cve-symfony-2026-45063",
   "title": "symfony < 8.0.12 \u2014 Symfony Vulnerable to Identity Spoofing via Unanchored DN Regex in X509Authenticator (CVE-2026-45063)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2026-45063",
   "tech": "symfony",
   "fixed": "8.0.12",
   "remediation": "Upgrade symfony to >= 8.0.12.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-ph86-p8f6-f9r2",
    "https://github.com/symfony/symfony/commit/ccb3f724c7ff55670a6fe3521c7bf1514cceb478",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/security-http/CVE-2026-45063.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.12"
   }
  },
  {
   "key": "cve-symfony-2026-45064",
   "title": "symfony < 8.0.12 \u2014 Symfony's HtmlSanitizer URL Attributes Pass Through BiDi Override Characters \u2192 Visual href Spoofing (CVE-2026-45064)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-45064",
   "tech": "symfony",
   "fixed": "8.0.12",
   "remediation": "Upgrade symfony to >= 8.0.12.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-h5vq-qfcg-4m6p",
    "https://github.com/symfony/symfony/commit/743a435e948b897ef2b5564ac438d4beb95d2526",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/html-sanitizer/CVE-2026-45064.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.12"
   }
  },
  {
   "key": "cve-symfony-2026-45065",
   "title": "symfony < 8.0.12 \u2014 Symfony has a UrlGenerator Route-Requirement Bypass via Unanchored Regex Alternation \u2192 Off-Site //host URL Injection (CVE",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-45065",
   "tech": "symfony",
   "fixed": "8.0.12",
   "remediation": "Upgrade symfony to >= 8.0.12.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-72xp-p242-47p9",
    "https://github.com/symfony/symfony/commit/bcf487c22f3240ba994124e0e0fe8616f3cfc47a",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/routing/CVE-2026-45065.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.12"
   }
  },
  {
   "key": "cve-symfony-2026-45066",
   "title": "symfony < 8.0.12 \u2014 Symfony has an HtmlSanitizer allowLinkHosts() / allowMediaHosts() Bypass via URL-Parser Differentials and <area> Misclass",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-45066",
   "tech": "symfony",
   "fixed": "8.0.12",
   "remediation": "Upgrade symfony to >= 8.0.12.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-qc95-4862-92fh",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/html-sanitizer/CVE-2026-45066.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/symfony/CVE-2026-45066.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.12"
   }
  },
  {
   "key": "cve-symfony-2026-45067",
   "title": "symfony < 8.0.12 \u2014 Symfony has Email Header / SMTP Command Injection via CRLF in Symfony\\Component\\Mime\\Address (CVE-2026-45067)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2026-45067",
   "tech": "symfony",
   "fixed": "8.0.12",
   "remediation": "Upgrade symfony to >= 8.0.12.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-qpmx-3rfj-7rhv",
    "https://github.com/symfony/symfony/commit/dc2dbd29211eb4ddc451373fa1374fb926e94604",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/mime/CVE-2026-45067.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.12"
   }
  },
  {
   "key": "cve-symfony-2026-45068",
   "title": "symfony < 8.0.12 \u2014 Symfony has an Argument Injection in SendmailTransport via Dash-Prefixed Recipient Address (CVE-2026-45068)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-45068",
   "tech": "symfony",
   "fixed": "8.0.12",
   "remediation": "Upgrade symfony to >= 8.0.12.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-xx3c-qf5g-hc39",
    "https://github.com/symfony/symfony/commit/c45144862dc289d03952f41f6078174089a3afc6",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/mailer/CVE-2026-45068.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.12"
   }
  },
  {
   "key": "cve-symfony-2026-45069",
   "title": "symfony < 8.0.12 \u2014 Symfony's OidcTokenHandler Accepts JWTs Missing aud/iss/exp Claims (CVE-2026-45069)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-45069",
   "tech": "symfony",
   "fixed": "8.0.12",
   "remediation": "Upgrade symfony to >= 8.0.12.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-29fc-p6c4-24cg",
    "https://github.com/symfony/symfony/commit/6b717aaac21b7e96798448d14c4355ea87690b3d",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/security-http/CVE-2026-45069.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.12"
   }
  },
  {
   "key": "cve-symfony-2026-45070",
   "title": "symfony < 8.0.12 \u2014 Symfony has Email Header Injection via Non-Token Characters in Mime Parameter Names (CVE-2026-45070)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-45070",
   "tech": "symfony",
   "fixed": "8.0.12",
   "remediation": "Upgrade symfony to >= 8.0.12.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-vqc8-7275-q272",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/mime/CVE-2026-45070.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/symfony/CVE-2026-45070.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.12"
   }
  },
  {
   "key": "cve-symfony-2026-45071",
   "title": "symfony < 8.0.12 \u2014 Symfony has XXE (Local File Disclosure) in DomCrawler::addXmlContent() via validateOnParse = true (CVE-2026-45071)",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2026-45071",
   "tech": "symfony",
   "fixed": "8.0.12",
   "remediation": "Upgrade symfony to >= 8.0.12.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-x6g4-fwcc-jj8w",
    "https://github.com/symfony/symfony/commit/eea5fd7488cbdc241da4ce242344b7d9a3ecdf3d",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/dom-crawler/CVE-2026-45071.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.12"
   }
  },
  {
   "key": "cve-symfony-2026-45072",
   "title": "symfony < 8.0.12 \u2014 Symfony Vulnerable to stored XSS in WebProfiler CodeExtension::fileExcerpt() \u2014 Unescaped Non-PHP File Rendering (CVE-2026",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2026-45072",
   "tech": "symfony",
   "fixed": "8.0.12",
   "remediation": "Upgrade symfony to >= 8.0.12.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-hmr5-2xcr-v8pp",
    "https://github.com/symfony/symfony/commit/863aa81c61166f1aa74b7732df316f76113acbdb",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/symfony/CVE-2026-45072.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.12"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-symfony-2026-45073",
   "title": "symfony < 8.0.12 \u2014 Symfony Vulnerable to SQL Injection in PdoAdapter::doClear() via Unsanitized $prefix (CVE-2026-45073)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-45073",
   "tech": "symfony",
   "fixed": "8.0.12",
   "remediation": "Upgrade symfony to >= 8.0.12.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-6qh9-h6wf-jgqc",
    "https://github.com/symfony/symfony/commit/ec50b799d79ebe24561f29351c1efcb6da95c9b",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/cache/CVE-2026-45073.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.12"
   },
   "cwe": "CWE-89"
  },
  {
   "key": "cve-symfony-2026-45074",
   "title": "symfony < 8.0.12 \u2014 Symfony's Cas2Handler Derives CAS service URL from Client Host Header \u2192 Cross-Service Ticket Replay (CVE-2026-45074)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-45074",
   "tech": "symfony",
   "fixed": "8.0.12",
   "remediation": "Upgrade symfony to >= 8.0.12.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-j8gj-9rm5-4xhx",
    "https://github.com/symfony/symfony/commit/5ba145dba702404801bdf9e7e8d6df170060d541",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/security-http/CVE-2026-45074.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.12"
   }
  },
  {
   "key": "cve-symfony-2026-45075",
   "title": "symfony < 8.0.12 \u2014 Symfony's HEAD Request Bypasses methods: ['GET'] Filter in #[IsGranted] / #[IsSignatureValid] / #[IsCsrfTokenValid] (CVE-",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2026-45075",
   "tech": "symfony",
   "fixed": "8.0.12",
   "remediation": "Upgrade symfony to >= 8.0.12.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-6439-2f28-8p8q",
    "https://github.com/symfony/symfony/commit/fa8d5c67aa4b22c9656e3fd7d5c3aa59865bf838",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/http-kernel/CVE-2026-45075.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.12"
   },
   "cwe": "CWE-352"
  },
  {
   "key": "cve-symfony-2026-45077",
   "title": "symfony < 8.0.12 \u2014 Symfony has Unauthenticated PHP Object Deserialization in MonologBridge server:log Listener (CVE-2026-45077)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2026-45077",
   "tech": "symfony",
   "fixed": "8.0.12",
   "remediation": "Upgrade symfony to >= 8.0.12.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-m7v2-7gxm-vc2v",
    "https://github.com/symfony/symfony/commit/0891b2f293896c488e26943dc034334364b77fc4",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/monolog-bridge/CVE-2026-45077.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.12"
   },
   "cwe": "CWE-502"
  },
  {
   "key": "cve-symfony-2026-45133",
   "title": "symfony < 8.0.12 \u2014 Symfony hardened the parser when handling untrusted input (CVE-2026-45133)",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2026-45133",
   "tech": "symfony",
   "fixed": "8.0.12",
   "remediation": "Upgrade symfony to >= 8.0.12.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-c2p3-7m5p-cv8x",
    "https://github.com/symfony/symfony/commit/914f427ed9630ddb3904dafba763e53d9f133fe3",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/symfony/CVE-2026-45133.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.12"
   }
  },
  {
   "key": "cve-symfony-2026-45304",
   "title": "symfony < 8.0.12 \u2014 Symfony's YAML Parser Vulnerable to Exponential Memory Allocation via Recursive Collection-Alias Expansion (\"Billion Laug",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2026-45304",
   "tech": "symfony",
   "fixed": "8.0.12",
   "remediation": "Upgrade symfony to >= 8.0.12.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-4qpc-3hr4-r2p4",
    "https://github.com/symfony/symfony/commit/e77391b2e4f18821198f010d573674c8ed4a970a",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/symfony/CVE-2026-45304.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.12"
   }
  },
  {
   "key": "cve-symfony-2026-45305",
   "title": "symfony < 8.0.12 \u2014 Symfony's YAML Parser has a ReDoS via Catastrophic Backtracking in Parser::cleanup() Regex (CVE-2026-45305)",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2026-45305",
   "tech": "symfony",
   "fixed": "8.0.12",
   "remediation": "Upgrade symfony to >= 8.0.12.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-9frc-8383-795m",
    "https://github.com/symfony/symfony/commit/9749cd43c5e09b3735093623670b21b9d8a056cb",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/symfony/CVE-2026-45305.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.12"
   },
   "cwe": "CWE-1333"
  },
  {
   "key": "cve-symfony-2026-45753",
   "title": "symfony < 8.0.12 \u2014 Symfony's HtmlSanitizer UrlAttributeSanitizer Omits action/formaction/poster/cite \u2014 `javascript`: URI Survives Sanitizati",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2026-45753",
   "tech": "symfony",
   "fixed": "8.0.12",
   "remediation": "Upgrade symfony to >= 8.0.12.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-hhg7-c65m-h7ff",
    "https://github.com/symfony/symfony/commit/26a598fcfc4f903cc55ff202f642ee621839825e",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/html-sanitizer/CVE-2026-45753.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.12"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-symfony-2026-45754",
   "title": "symfony < 8.0.12 \u2014 Symfony's Mailjet Mailer Webhook Parser Never Verifies the Configured Secret \u2014 Unauthenticated Webhook Event Injection (C",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-45754",
   "tech": "symfony",
   "fixed": "8.0.12",
   "remediation": "Upgrade symfony to >= 8.0.12.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-64hg-93w9-fc35",
    "https://github.com/symfony/symfony/commit/4aaa45dd054f73445f1ab254968b7e60b546cc77",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/lox24-notifier/CVE-2026-45754.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.12"
   }
  },
  {
   "key": "cve-symfony-2026-45755",
   "title": "symfony < 8.0.12 \u2014 Symfony's Mailtrap Mailer Webhook Parser Never Verifies the X-Mt-Signature HMAC \u2014 Unauthenticated Webhook Event Injection",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-45755",
   "tech": "symfony",
   "fixed": "8.0.12",
   "remediation": "Upgrade symfony to >= 8.0.12.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-59f3-vp2f-mp9w",
    "https://github.com/symfony/symfony/commit/4e0467e4e182cf2e704a3d9e1bc1a6be65d52ab8",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/mailtrap-mailer/CVE-2026-45755.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.12"
   }
  },
  {
   "key": "cve-symfony-2026-45756",
   "title": "symfony < 8.0.12 \u2014 Symfony's JsonPath Evaluates Attacker-Controlled Regular Expressions in match()/search() Without Limits \u2014 ReDoS (CVE-2026",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2026-45756",
   "tech": "symfony",
   "fixed": "8.0.12",
   "remediation": "Upgrade symfony to >= 8.0.12.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-8v8v-g73j-492j",
    "https://github.com/symfony/symfony/commit/1ac2d47418ec23066112db1e6ca35be6fe123d14",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/json-path/CVE-2026-45756.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.12"
   },
   "cwe": "CWE-1333"
  },
  {
   "key": "cve-symfony-2026-47212",
   "title": "symfony < 8.0.12 \u2014 Symfony: Twilio SMS Notifier allows unauthenticated webhook injection due to missing X-Twilio-Signature verification (CVE",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-47212",
   "tech": "symfony",
   "fixed": "8.0.12",
   "remediation": "Upgrade symfony to >= 8.0.12.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-55rj-x2vc-4whq",
    "https://github.com/symfony/symfony/commit/8545fb2af6c07dfb5ef0fc8d9bccf86db2c94356",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/symfony/CVE-2026-47212.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.12"
   }
  },
  {
   "key": "cve-symfony-2026-47767",
   "title": "symfony < 8.0.12 \u2014 SymfonyRuntime CVE-2024-50340 Patch Bypass: Web Requests Can Still Set APP_ENV/APP_DEBUG via parse_str/SAPI Argv Mismatch",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-47767",
   "tech": "symfony",
   "fixed": "8.0.12",
   "remediation": "Upgrade symfony to >= 8.0.12.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-fqc7-9xjw-jrh3",
    "https://github.com/symfony/symfony"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.12"
   }
  },
  {
   "key": "cve-symfony-2026-48489",
   "title": "symfony < 8.0.13 \u2014 Symfony: Security Firewall Bypass via failure_forward Subrequest: Unauthenticated Access to access_control-Protected GET ",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2026-48489",
   "tech": "symfony",
   "fixed": "8.0.13",
   "remediation": "Upgrade symfony to >= 8.0.13.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-6h46-9jf5-q59x",
    "https://github.com/symfony/symfony/commit/c48a4276309e11aedeeb0ce3a89dfbf0b4fe04ff",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/security-http/CVE-2026-48489.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.13"
   }
  },
  {
   "key": "cve-symfony-2026-48736",
   "title": "symfony < 8.0.13 \u2014 Symfony: IpUtils::PRIVATE_SUBNETS Omits IPv6 Transition Forms (6to4, NAT64, Teredo, IPv4-compatible): SSRF Bypass in NoPr",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-48736",
   "tech": "symfony",
   "fixed": "8.0.13",
   "remediation": "Upgrade symfony to >= 8.0.13.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-38cx-cq6f-5755",
    "https://github.com/symfony/symfony/commit/82765368cf74177c36613575182f168a2eb765b2",
    "https://github.com/symfony/symfony/commit/85b831555be8ea1f43bf01078afe87bc4c92f65e"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.13"
   }
  },
  {
   "key": "cve-symfony-2026-48747",
   "title": "symfony < 8.0.13 \u2014 Symfony: Mailomat Mailer Webhook Parser Reads the HMAC Algorithm from the Request: Signature Algorithm Downgrade (CVE-202",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-48747",
   "tech": "symfony",
   "fixed": "8.0.13",
   "remediation": "Upgrade symfony to >= 8.0.13.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-rrj9-5q2j-4gvr",
    "https://github.com/symfony/symfony/commit/bdfe9fe0d94d33dfaca0bc2fe0b00b54767b0c88",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/mailomat-mailer/CVE-2026-48747.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.13"
   }
  },
  {
   "key": "cve-symfony-2026-48760",
   "title": "symfony < 8.0.13 \u2014 Symfony: HtmlSanitizer URL Parser Deny Gates Underinclusive: Percent-Encoded BiDi Marks and Unicode Whitespace Bypass Vis",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-48760",
   "tech": "symfony",
   "fixed": "8.0.13",
   "remediation": "Upgrade symfony to >= 8.0.13.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-v3wm-qf9p-c549",
    "https://github.com/symfony/symfony/commit/b21a626fd90f5c12d2db432c629eed3e780ba2f8",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/html-sanitizer/CVE-2026-48760.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.13"
   },
   "cwe": "CWE-94"
  },
  {
   "key": "cve-symfony-2026-48761",
   "title": "symfony < 8.0.13 \u2014 Symfony: HtmlSanitizer UrlAttributeSanitizer Misses URL Attributes (CVE-2026-48761)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-48761",
   "tech": "symfony",
   "fixed": "8.0.13",
   "remediation": "Upgrade symfony to >= 8.0.13.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-x5qj-865h-mgvm",
    "https://github.com/symfony/symfony/commit/069a70f9f26e61e9de3b7f9a864a86ed24b36bd0",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/html-sanitizer/CVE-2026-48761.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.13"
   }
  },
  {
   "key": "cve-symfony-2026-48784",
   "title": "symfony < 8.0.13 \u2014 Symfony: UrlGenerator Dot-Segment Encoding Skips Every Other Chained `../` or `./` \u2192 Generated URL Collapses Off-Route Un",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-48784",
   "tech": "symfony",
   "fixed": "8.0.13",
   "remediation": "Upgrade symfony to >= 8.0.13.",
   "refs": [
    "https://github.com/symfony/symfony/security/advisories/GHSA-h5x3-xfc9-m39h",
    "https://github.com/symfony/symfony/commit/4b63c3a3f7af04ecd79c89a594b0b02a01990b1d",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/symfony/routing/CVE-2026-48784.yaml"
   ],
   "match": {
    "tech": "symfony",
    "version_lt": "8.0.13"
   }
  },
  {
   "key": "cve-tinymce-2011-4825",
   "title": "tinyMCE < 1.4.2 \u2014 Static code injection vulnerability in inc/function.base.php (CVE-2011-4825)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2011-4825",
   "tech": "tinymce",
   "fixed": "1.4.2",
   "remediation": "Upgrade tinyMCE to >= 1.4.2.",
   "refs": [
    "http://www.cvedetails.com/cve/CVE-2011-4825/"
   ],
   "match": {
    "tech": "tinymce",
    "version_lt": "1.4.2"
   }
  },
  {
   "key": "cve-tinymce-2019-1010091",
   "title": "tinyMCE < 4.9.10 \u2014 cross-site scripting (XSS) vulnerability was discovered in: the core parser and `media` plugin.  (CVE-2019-1010091)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2019-1010091",
   "tech": "tinymce",
   "fixed": "4.9.10",
   "remediation": "Upgrade tinyMCE to >= 4.9.10.",
   "refs": [
    "https://github.com/advisories/GHSA-c78w-2gw7-gjv3",
    "https://github.com/tinymce/tinymce/security/advisories/GHSA-vrv8-v4w8-f95h"
   ],
   "match": {
    "tech": "tinymce",
    "version_lt": "4.9.10"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-tinymce-2020-12648",
   "title": "tinyMCE < 4.9.11 \u2014 Cross-site scripting vulnerability in TinyMCE (CVE-2020-12648)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-12648",
   "tech": "tinymce",
   "fixed": "4.9.11",
   "remediation": "Upgrade tinyMCE to >= 4.9.11.",
   "refs": [
    "https://github.com/advisories/GHSA-vrv8-v4w8-f95h",
    "https://github.com/tinymce/tinymce/security/advisories/GHSA-vrv8-v4w8-f95h"
   ],
   "match": {
    "tech": "tinymce",
    "version_lt": "4.9.11"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-tinymce-2020-17480",
   "title": "tinyMCE < 4.9.7 \u2014 The vulnerability allowed arbitrary JavaScript execution when inserting a specially crafted piece of content into the edit",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2020-17480",
   "tech": "tinymce",
   "fixed": "4.9.7",
   "remediation": "Upgrade tinyMCE to >= 4.9.7.",
   "refs": [
    "https://github.com/advisories/GHSA-27gm-ghr9-4v95",
    "https://github.com/tinymce/tinymce/security/advisories/GHSA-27gm-ghr9-4v95"
   ],
   "match": {
    "tech": "tinymce",
    "version_lt": "4.9.7"
   }
  },
  {
   "key": "cve-tinymce-2022-23494",
   "title": "tinyMCE < 5.10.7 \u2014 A cross-site scripting (XSS) vulnerability in TinyMCE alerts which allowed arbitrary JavaScript execution was found and f",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-23494",
   "tech": "tinymce",
   "fixed": "5.10.7",
   "remediation": "Upgrade tinyMCE to >= 5.10.7.",
   "refs": [
    "https://github.com/advisories/GHSA-gg8r-xjwq-4w92",
    "https://www.cve.org/CVERecord?id=CVE-2022-23494",
    "https://www.tiny.cloud/docs/changelog/#5107-2022-12-06"
   ],
   "match": {
    "tech": "tinymce",
    "version_lt": "5.10.7"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-tinymce-2023-45818",
   "title": "tinyMCE < 5.10.8 \u2014 TinyMCE mXSS vulnerability in undo/redo, getContent API, resetContent API, and Autosave plugin (CVE-2023-45818)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2023-45818",
   "tech": "tinymce",
   "fixed": "5.10.8",
   "remediation": "Upgrade tinyMCE to >= 5.10.8.",
   "refs": [
    "https://github.com/advisories/GHSA-v65r-p3vv-jjfv"
   ],
   "match": {
    "tech": "tinymce",
    "version_lt": "5.10.8"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-tinymce-2023-45819",
   "title": "tinyMCE < 5.10.8 \u2014 TinyMCE XSS vulnerability in notificationManager.open API (CVE-2023-45819)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2023-45819",
   "tech": "tinymce",
   "fixed": "5.10.8",
   "remediation": "Upgrade tinyMCE to >= 5.10.8.",
   "refs": [
    "https://github.com/advisories/GHSA-hgqx-r2hp-jr38",
    "https://www.cve.org/CVERecord?id=CVE-2022-23494",
    "https://www.tiny.cloud/docs/changelog/#5107-2022-12-06"
   ],
   "match": {
    "tech": "tinymce",
    "version_lt": "5.10.8"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-tinymce-2023-48219",
   "title": "tinyMCE < 5.10.9 \u2014 TinyMCE vulnerable to mutation Cross-site Scripting via special characters in unescaped text nodes (CVE-2023-48219)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2023-48219",
   "tech": "tinymce",
   "fixed": "5.10.9",
   "remediation": "Upgrade tinyMCE to >= 5.10.9.",
   "refs": [
    "https://github.com/advisories/GHSA-v626-r774-j7f8",
    "https://github.com/tinymce/tinymce/security/advisories/GHSA-v626-r774-j7f8",
    "https://nvd.nist.gov/vuln/detail/CVE-2023-48219",
    "https://github.com/tinymce/tinymce",
    "https://github.com/tinymce/tinymce/releases/tag/5.10.9",
    "https://github.com/tinymce/tinymce/releases/tag/6.7.3",
    "https://tiny.cloud/docs/release-notes/release-notes5109/",
    "https://tiny.cloud/docs/tinymce/6/6.7.3-release-notes/"
   ],
   "match": {
    "tech": "tinymce",
    "version_lt": "5.10.9"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-tinymce-2024-21908",
   "title": "tinyMCE < 5.9.0 \u2014 Inserting certain HTML content into the editor could result in invalid HTML once parsed. This caused a medium severity Cro",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2024-21908",
   "tech": "tinymce",
   "fixed": "5.9.0",
   "remediation": "Upgrade tinyMCE to >= 5.9.0.",
   "refs": [
    "https://www.tiny.cloud/docs/release-notes/release-notes59/#securityfixes"
   ],
   "match": {
    "tech": "tinymce",
    "version_lt": "5.9.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-tinymce-2024-21910",
   "title": "tinyMCE < 5.10.0 \u2014 URLs not cleaned correctly in some cases in the link and image plugins (CVE-2024-21910)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2024-21910",
   "tech": "tinymce",
   "fixed": "5.10.0",
   "remediation": "Upgrade tinyMCE to >= 5.10.0.",
   "refs": [
    "https://www.tiny.cloud/docs/release-notes/release-notes510/#securityfixes"
   ],
   "match": {
    "tech": "tinymce",
    "version_lt": "5.10.0"
   }
  },
  {
   "key": "cve-tinymce-2024-21911",
   "title": "tinyMCE < 5.6.0 \u2014 security issue where URLs in attributes weren\u2019t correctly sanitized. security issue in the codesample plugin (CVE-2024-219",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2024-21911",
   "tech": "tinymce",
   "fixed": "5.6.0",
   "remediation": "Upgrade tinyMCE to >= 5.6.0.",
   "refs": [
    "https://www.tiny.cloud/docs/release-notes/release-notes56/#securityfixes"
   ],
   "match": {
    "tech": "tinymce",
    "version_lt": "5.6.0"
   }
  },
  {
   "key": "cve-tinymce-2024-29203",
   "title": "tinyMCE < 6.8.1 \u2014 TinyMCE Cross-Site Scripting (XSS) vulnerability in handling iframes (CVE-2024-29203)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2024-29203",
   "tech": "tinymce",
   "fixed": "6.8.1",
   "remediation": "Upgrade tinyMCE to >= 6.8.1.",
   "refs": [
    "https://github.com/advisories/GHSA-438c-3975-5x3f",
    "https://github.com/tinymce/tinymce/security/advisories/GHSA-438c-3975-5x3f",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-29203",
    "https://github.com/tinymce/tinymce/commit/bcdea2ad14e3c2cea40743fb48c63bba067ae6d1",
    "https://github.com/tinymce/tinymce",
    "https://www.tiny.cloud/docs/tinymce/6/6.8.1-release-notes/#new-convert_unsafe_embeds-option-that-controls-whether-object-and-embed-elements-will-be-converted-to-more-restrictive-alternatives-namely-img-for-image-mime-types-video-for-video-mime-types-audio-audio-mime-types-or-iframe-for-other-or-unspecified-mime-types",
    "https://www.tiny.cloud/docs/tinymce/7/7.0-release-notes/#sandbox_iframes-editor-option-is-now-defaulted-to-true"
   ],
   "match": {
    "tech": "tinymce",
    "version_lt": "6.8.1"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-tinymce-2024-29881",
   "title": "tinyMCE < 7.0.0 \u2014 TinyMCE Cross-Site Scripting (XSS) vulnerability in handling external SVG files through Object or Embed elements (CVE-2024",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2024-29881",
   "tech": "tinymce",
   "fixed": "7.0.0",
   "remediation": "Upgrade tinyMCE to >= 7.0.0.",
   "refs": [
    "https://github.com/advisories/GHSA-5359-pvf2-pw78",
    "https://github.com/tinymce/tinymce/security/advisories/GHSA-5359-pvf2-pw78",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-29881",
    "https://github.com/tinymce/tinymce/commit/bcdea2ad14e3c2cea40743fb48c63bba067ae6d1",
    "https://github.com/tinymce/tinymce",
    "https://www.tiny.cloud/docs/tinymce/6/6.8.1-release-notes/#new-convert_unsafe_embeds-option-that-controls-whether-object-and-embed-elements-will-be-converted-to-more-restrictive-alternatives-namely-img-for-image-mime-types-video-for-video-mime-types-audio-audio-mime-types-or-iframe-for-other-or-unspecified-mime-types",
    "https://www.tiny.cloud/docs/tinymce/7/7.0-release-notes/#convert_unsafe_embeds-editor-option-is-now-defaulted-to-true"
   ],
   "match": {
    "tech": "tinymce",
    "version_lt": "7.0.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-tinymce-2024-38356",
   "title": "tinyMCE < 5.11.0 \u2014 TinyMCE Cross-Site Scripting (XSS) vulnerability using noneditable_regexp option (CVE-2024-38356)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2024-38356",
   "tech": "tinymce",
   "fixed": "5.11.0",
   "remediation": "Upgrade tinyMCE to >= 5.11.0.",
   "refs": [
    "https://github.com/advisories/GHSA-9hcv-j9pv-qmph",
    "https://github.com/tinymce/tinymce/security/advisories/GHSA-9hcv-j9pv-qmph",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-38356",
    "https://github.com/tinymce/tinymce/commit/5acb741665a98e83d62b91713c800abbff43b00d",
    "https://github.com/tinymce/tinymce/commit/a9fb858509f86dacfa8b01cfd34653b408983ac0",
    "https://github.com/tinymce/tinymce",
    "https://owasp.org/www-community/attacks/xss",
    "https://www.tiny.cloud/docs/tinymce/6/6.8.4-release-notes/#overview",
    "https://www.tiny.cloud/docs/tinymce/7/7.2-release-notes/#overview",
    "https://www.tiny.cloud/docs/tinymce/latest/7.2-release-notes/#overview"
   ],
   "match": {
    "tech": "tinymce",
    "version_lt": "5.11.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-tinymce-2024-38357",
   "title": "tinyMCE < 5.11.0 \u2014 TinyMCE Cross-Site Scripting (XSS) vulnerability using noscript elements (CVE-2024-38357)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2024-38357",
   "tech": "tinymce",
   "fixed": "5.11.0",
   "remediation": "Upgrade tinyMCE to >= 5.11.0.",
   "refs": [
    "https://github.com/advisories/GHSA-w9jx-4g6g-rp7x",
    "https://github.com/tinymce/tinymce/security/advisories/GHSA-w9jx-4g6g-rp7x",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-38357",
    "https://github.com/tinymce/tinymce/commit/5acb741665a98e83d62b91713c800abbff43b00d",
    "https://github.com/tinymce/tinymce/commit/a9fb858509f86dacfa8b01cfd34653b408983ac0",
    "https://github.com/tinymce/tinymce",
    "https://owasp.org/www-community/attacks/xss",
    "https://www.tiny.cloud/docs/tinymce/6/6.8.4-release-notes/#overview",
    "https://www.tiny.cloud/docs/tinymce/7/7.2-release-notes/#overview"
   ],
   "match": {
    "tech": "tinymce",
    "version_lt": "5.11.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-tinymce-2026-47759",
   "title": "tinyMCE < 5.10.10 \u2014 TinyMCE Cross-Site Scripting (XSS) vulnerability using through data-mce- prefixed src, href, style attributes (CVE-2026-",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2026-47759",
   "tech": "tinymce",
   "fixed": "5.10.10",
   "remediation": "Upgrade tinyMCE to >= 5.10.10.",
   "refs": [
    "https://github.com/tinymce/tinymce/security/advisories/GHSA-q742-qvgc-gc2f",
    "https://www.tiny.cloud/docs/tinymce/7/7.9.3-release-notes/#overview",
    "https://www.tiny.cloud/docs/tinymce/8/8.5.1-release-notes/#overview"
   ],
   "match": {
    "tech": "tinymce",
    "version_lt": "5.10.10"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-tinymce-2026-47760",
   "title": "tinyMCE < 7.1.0 \u2014 TinyMCE Cross-Site Scripting (XSS) vulnerability using sanitization bypass through nested SVGs (CVE-2026-47760)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2026-47760",
   "tech": "tinymce",
   "fixed": "7.1.0",
   "remediation": "Upgrade tinyMCE to >= 7.1.0.",
   "refs": [
    "https://github.com/tinymce/tinymce/security/advisories/GHSA-mh5m-5hw4-5c69"
   ],
   "match": {
    "tech": "tinymce",
    "version_lt": "7.1.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-tinymce-2026-47761",
   "title": "tinyMCE < 5.10.10 \u2014 TinyMCE Cross-Site Scripting (XSS) vulnerability using media plugin `data-mce-object` injection (CVE-2026-47761)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2026-47761",
   "tech": "tinymce",
   "fixed": "5.10.10",
   "remediation": "Upgrade tinyMCE to >= 5.10.10.",
   "refs": [
    "https://github.com/tinymce/tinymce/security/advisories/GHSA-vg35-5wq7-3x7w",
    "https://www.tiny.cloud/docs/tinymce/7/7.9.3-release-notes/#overview",
    "https://www.tiny.cloud/docs/tinymce/8/8.5.1-release-notes/#overview"
   ],
   "match": {
    "tech": "tinymce",
    "version_lt": "5.10.10"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-tinymce-2026-47762",
   "title": "tinyMCE < 5.10.10 \u2014 TinyMCE Cross-Site Scripting (XSS) vulnerability through `mce:protected` comments (CVE-2026-47762)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2026-47762",
   "tech": "tinymce",
   "fixed": "5.10.10",
   "remediation": "Upgrade tinyMCE to >= 5.10.10.",
   "refs": [
    "https://github.com/tinymce/tinymce/security/advisories/GHSA-v98h-vmpc-fpqv",
    "https://www.tiny.cloud/docs/tinymce/7/7.9.3-release-notes/#overview",
    "https://www.tiny.cloud/docs/tinymce/8/8.5.1-release-notes/#overview"
   ],
   "match": {
    "tech": "tinymce",
    "version_lt": "5.10.10"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-typo3-2008-2717",
   "title": "typo3 < 4.2.1 \u2014 TYPO3 Unrestricted File Upload vulnerability (CVE-2008-2717)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2008-2717",
   "tech": "typo3",
   "fixed": "4.2.1",
   "remediation": "Upgrade typo3 to >= 4.2.1.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2008-2717",
    "https://exchange.xforce.ibmcloud.com/vulnerabilities/42988",
    "https://github.com/TYPO3-CMS/core"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "4.2.1"
   }
  },
  {
   "key": "cve-typo3-2009-3633",
   "title": "typo3 < 4.3beta2 \u2014 TYPO3 API function vulnerable to Cross-site Scripting (CVE-2009-3633)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2009-3633",
   "tech": "typo3",
   "fixed": "4.3beta2",
   "remediation": "Upgrade typo3 to >= 4.3beta2.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2009-3633",
    "https://github.com/TYPO3/typo3/commit/51f3dd9804cae04575323b92a9136e5a511fe810",
    "https://github.com/TYPO3/typo3/commit/5d4218fad3aeda46236754004232d7e635205e7a"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "4.3beta2"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-typo3-2010-3673",
   "title": "typo3 < 4.4.1 \u2014 TYPO3 is vulnerable to Information Disclosure in the HTML mailing API (CVE-2010-3673)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2010-3673",
   "tech": "typo3",
   "fixed": "4.4.1",
   "remediation": "Upgrade typo3 to >= 4.4.1.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2010-3673",
    "https://github.com/TYPO3/typo3/commit/3e24a0fff04897826a12e5cac16b5b0a3848cf2d",
    "https://github.com/TYPO3/typo3/commit/46693d4930d0bce64c5bdd4274224724041cef2f"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "4.4.1"
   }
  },
  {
   "key": "cve-typo3-2010-5104",
   "title": "typo3 < 4.4.5 \u2014 TYPO3 Sensitive Information Disclosure via escapeStrForLike method (CVE-2010-5104)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2010-5104",
   "tech": "typo3",
   "fixed": "4.4.5",
   "remediation": "Upgrade typo3 to >= 4.4.5.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2010-5104",
    "https://github.com/TYPO3/typo3/commit/9eb4be4ccf10e6959699b9cce375d48697f06cba",
    "https://github.com/TYPO3/typo3/commit/e8c32474a5571336681243465f42090cf056054f"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "4.4.5"
   }
  },
  {
   "key": "cve-typo3-2013-1842",
   "title": "typo3 < 6.0.3 \u2014 TYPO3 SQL injection vulnerability in the Extbase Framework (CVE-2013-1842)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2013-1842",
   "tech": "typo3",
   "fixed": "6.0.3",
   "remediation": "Upgrade typo3 to >= 6.0.3.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2013-1842",
    "https://github.com/TYPO3-CMS/core",
    "http://lists.opensuse.org/opensuse-updates/2013-03/msg00079.html"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "6.0.3"
   },
   "cwe": "CWE-89"
  },
  {
   "key": "cve-typo3-2013-1843",
   "title": "typo3 < 6.0.3 \u2014 TYPO3 Open redirect vulnerability in the Access tracking mechanism  (CVE-2013-1843)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2013-1843",
   "tech": "typo3",
   "fixed": "6.0.3",
   "remediation": "Upgrade typo3 to >= 6.0.3.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2013-1843",
    "https://github.com/TYPO3-CMS/core",
    "http://lists.opensuse.org/opensuse-updates/2013-03/msg00079.html"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "6.0.3"
   },
   "cwe": "CWE-601"
  },
  {
   "key": "cve-typo3-2013-4320",
   "title": "typo3 < 6.1.4 \u2014 TYPO3 Improper Access Management in the File Abstraction Layer (CVE-2013-4320)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2013-4320",
   "tech": "typo3",
   "fixed": "6.1.4",
   "remediation": "Upgrade typo3 to >= 6.1.4.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2013-4320",
    "https://github.com/TYPO3-CMS/core",
    "https://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2013-003"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "6.1.4"
   }
  },
  {
   "key": "cve-typo3-2013-7077",
   "title": "typo3 < 6.1.7 \u2014 TYPO3 Cross-site scripting (XSS) vulnerability in the Backend User Administration Module  (CVE-2013-7077)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2013-7077",
   "tech": "typo3",
   "fixed": "6.1.7",
   "remediation": "Upgrade typo3 to >= 6.1.7.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2013-7077",
    "https://exchange.xforce.ibmcloud.com/vulnerabilities/89626",
    "https://github.com/TYPO3-CMS/core"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "6.1.7"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-typo3-2013-7078",
   "title": "typo3 < 6.0.11 \u2014 TYPO3 Cross-site scripting (XSS) vulnerability in the Extbase Framework (CVE-2013-7078)",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2013-7078",
   "tech": "typo3",
   "fixed": "6.0.11",
   "remediation": "Upgrade typo3 to >= 6.0.11.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2013-7078",
    "https://exchange.xforce.ibmcloud.com/vulnerabilities/89629",
    "https://github.com/TYPO3-CMS/core"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "6.0.11"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-typo3-2013-7080",
   "title": "typo3 < 6.0.11 \u2014 TYPO3 is vulnerable to Mass Assignment in the Extension table administration library (CVE-2013-7080)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2013-7080",
   "tech": "typo3",
   "fixed": "6.0.11",
   "remediation": "Upgrade typo3 to >= 6.0.11.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2013-7080",
    "https://github.com/TYPO3-CMS/core",
    "http://seclists.org/oss-sec/2013/q4/473"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "6.0.11"
   }
  },
  {
   "key": "cve-typo3-2013-7081",
   "title": "typo3 < 6.1.6 \u2014 TYPO3 Improper Access Control vulnerability (CVE-2013-7081)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2013-7081",
   "tech": "typo3",
   "fixed": "6.1.6",
   "remediation": "Upgrade typo3 to >= 6.1.6.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2013-7081",
    "https://github.com/TYPO3-CMS/core",
    "http://seclists.org/oss-sec/2013/q4/473"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "6.1.6"
   }
  },
  {
   "key": "cve-typo3-2018-14041",
   "title": "typo3 < 4.1.2 \u2014 Bootstrap Cross-site Scripting vulnerability (CVE-2018-14041)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2018-14041",
   "tech": "typo3",
   "fixed": "4.1.2",
   "remediation": "Upgrade typo3 to >= 4.1.2.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2018-14041",
    "https://github.com/twbs/bootstrap/issues/26423",
    "https://github.com/twbs/bootstrap/issues/26627"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "4.1.2"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-typo3-2018-17960",
   "title": "typo3 < 9.5.2 \u2014 Ckeditor XSS Vulnerability (CVE-2018-17960)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2018-17960",
   "tech": "typo3",
   "fixed": "9.5.2",
   "remediation": "Upgrade typo3 to >= 9.5.2.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2018-17960",
    "https://ckeditor.com/blog/CKEditor-4.11-with-emoji-dropdown-and-auto-link-on-typing-released",
    "https://ckeditor.com/cke4/release/CKEditor-4.11.0"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "9.5.2"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-typo3-2019-10912",
   "title": "typo3 < 9.5.8 \u2014 Deserialization of untrusted data in Symfony (CVE-2019-10912)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2019-10912",
   "tech": "typo3",
   "fixed": "9.5.8",
   "remediation": "Upgrade typo3 to >= 9.5.8.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2019-10912",
    "https://github.com/symfony/symfony/commit/4fb975281634b8d49ebf013af9e502e67c28816b",
    "https://www.debian.org/security/2019/dsa-4441"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "9.5.8"
   },
   "cwe": "CWE-502"
  },
  {
   "key": "cve-typo3-2019-11832",
   "title": "typo3 < 9.5.6 \u2014 TYPO3 Image Processing susceptible to Code Execution (CVE-2019-11832)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2019-11832",
   "tech": "typo3",
   "fixed": "9.5.6",
   "remediation": "Upgrade typo3 to >= 9.5.6.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2019-11832",
    "https://github.com/github/advisory-database/pull/3530",
    "https://github.com/TYPO3/typo3/commit/2c04eeac44733fda491f92c697f88c1337d19c79"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "9.5.6"
   }
  },
  {
   "key": "cve-typo3-2019-12747",
   "title": "typo3 < 9.5.8 \u2014 TYPO3 Vulnerable to Insecure Deserialization (CVE-2019-12747)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2019-12747",
   "tech": "typo3",
   "fixed": "9.5.8",
   "remediation": "Upgrade typo3 to >= 9.5.8.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2019-12747",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/typo3/cms-core/CVE-2019-12747.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/typo3/cms/CVE-2019-12747.yaml"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "9.5.8"
   },
   "cwe": "CWE-502"
  },
  {
   "key": "cve-typo3-2019-12748",
   "title": "typo3 < 9.5.8 \u2014 Typo3 Cross-Site Scripting in Link Handling (CVE-2019-12748)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2019-12748",
   "tech": "typo3",
   "fixed": "9.5.8",
   "remediation": "Upgrade typo3 to >= 9.5.8.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2019-12748",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/typo3/cms-core/CVE-2019-12748.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/typo3/cms/CVE-2019-12748.yaml"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "9.5.8"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-typo3-2019-19848",
   "title": "typo3 < 9.5.12 \u2014 TYPO3 Directory Traversal on ZIP extraction (CVE-2019-19848)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2019-19848",
   "tech": "typo3",
   "fixed": "9.5.12",
   "remediation": "Upgrade typo3 to >= 9.5.12.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2019-19848",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/typo3/cms-core/CVE-2019-19848.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/typo3/cms/CVE-2019-19848.yaml"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "9.5.12"
   }
  },
  {
   "key": "cve-typo3-2019-19849",
   "title": "typo3 < 9.5.12 \u2014 TYPO3 Insecure Deserialization in Query Generator & Query View (CVE-2019-19849)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2019-19849",
   "tech": "typo3",
   "fixed": "9.5.12",
   "remediation": "Upgrade typo3 to >= 9.5.12.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2019-19849",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/typo3/cms-core/CVE-2019-19849.yaml",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/typo3/cms/CVE-2019-19849.yaml"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "9.5.12"
   },
   "cwe": "CWE-502"
  },
  {
   "key": "cve-typo3-2019-19850",
   "title": "typo3 < 10.2.2 \u2014 TYPO3  SQL Injection in low-level Query Generator (CVE-2019-19850)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2019-19850",
   "tech": "typo3",
   "fixed": "10.2.2",
   "remediation": "Upgrade typo3 to >= 10.2.2.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2019-19850",
    "https://github.com/TYPO3/typo3",
    "https://review.typo3.org/q/%2522Resolves:+%252389452%2522+topic:security"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "10.2.2"
   },
   "cwe": "CWE-89"
  },
  {
   "key": "cve-typo3-2020-11063",
   "title": "typo3 < 10.4.2 \u2014 Information Disclosure in Password Reset (CVE-2020-11063)",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2020-11063",
   "tech": "typo3",
   "fixed": "10.4.2",
   "remediation": "Upgrade typo3 to >= 10.4.2.",
   "refs": [
    "https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-347x-877p-hcwx",
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-347x-877p-hcwx",
    "https://nvd.nist.gov/vuln/detail/CVE-2020-11063"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "10.4.2"
   }
  },
  {
   "key": "cve-typo3-2020-11064",
   "title": "typo3 < 9.5.17 \u2014 Cross-Site Scripting in TYPO3 CMS Form Engine (CVE-2020-11064)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-11064",
   "tech": "typo3",
   "fixed": "9.5.17",
   "remediation": "Upgrade typo3 to >= 9.5.17.",
   "refs": [
    "https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-43gj-mj2w-wh46",
    "https://nvd.nist.gov/vuln/detail/CVE-2020-11064",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/typo3/cms-core/CVE-2020-11064.yaml"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "9.5.17"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-typo3-2020-11065",
   "title": "typo3 < 9.5.17 \u2014 Cross-Site Scripting in TYPO3 CMS Link Handling (CVE-2020-11065)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-11065",
   "tech": "typo3",
   "fixed": "9.5.17",
   "remediation": "Upgrade typo3 to >= 9.5.17.",
   "refs": [
    "https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-4j77-gg36-9864",
    "https://nvd.nist.gov/vuln/detail/CVE-2020-11065",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/typo3/cms-core/CVE-2020-11065.yaml"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "9.5.17"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-typo3-2020-11066",
   "title": "typo3 < 9.5.17 \u2014 Class destructors causing side-effects when being unserialized in TYPO3 CMS (CVE-2020-11066)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2020-11066",
   "tech": "typo3",
   "fixed": "9.5.17",
   "remediation": "Upgrade typo3 to >= 9.5.17.",
   "refs": [
    "https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-2rxh-h6h9-qrqc",
    "https://nvd.nist.gov/vuln/detail/CVE-2020-11066",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/typo3/cms-core/CVE-2020-11066.yaml"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "9.5.17"
   }
  },
  {
   "key": "cve-typo3-2020-11067",
   "title": "typo3 < 9.5.17 \u2014 Insecure Deserialization in Backend User Settings in TYPO3 CMS (CVE-2020-11067)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2020-11067",
   "tech": "typo3",
   "fixed": "9.5.17",
   "remediation": "Upgrade typo3 to >= 9.5.17.",
   "refs": [
    "https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-2wj9-434x-9hvp",
    "https://nvd.nist.gov/vuln/detail/CVE-2020-11067",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/typo3/cms-core/CVE-2020-11067.yaml"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "9.5.17"
   },
   "cwe": "CWE-502"
  },
  {
   "key": "cve-typo3-2020-11069",
   "title": "typo3 < 9.5.17 \u2014 Backend Same-Site Request Forgery in TYPO3 CMS (CVE-2020-11069)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2020-11069",
   "tech": "typo3",
   "fixed": "9.5.17",
   "remediation": "Upgrade typo3 to >= 9.5.17.",
   "refs": [
    "https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-pqg8-crx9-g8m4",
    "https://nvd.nist.gov/vuln/detail/CVE-2020-11069",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/typo3/cms-core/CVE-2020-11069.yaml"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "9.5.17"
   }
  },
  {
   "key": "cve-typo3-2020-15098",
   "title": "typo3 < 9.5.20 \u2014 Missing Required Cryptographic Step Leading to Sensitive Information Disclosure in TYPO3 CMS (CVE-2020-15098)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2020-15098",
   "tech": "typo3",
   "fixed": "9.5.20",
   "remediation": "Upgrade typo3 to >= 9.5.20.",
   "refs": [
    "https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-m5vr-3m74-jwxp",
    "https://nvd.nist.gov/vuln/detail/CVE-2016-5091",
    "https://nvd.nist.gov/vuln/detail/CVE-2020-15098"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "9.5.20"
   }
  },
  {
   "key": "cve-typo3-2020-15099",
   "title": "typo3 < 9.5.20 \u2014 Exposure of Sensitive Information to an Unauthorized Actor in TYPO3 CMS (CVE-2020-15099)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2020-15099",
   "tech": "typo3",
   "fixed": "9.5.20",
   "remediation": "Upgrade typo3 to >= 9.5.20.",
   "refs": [
    "https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-3x94-fv5h-5q2c",
    "https://nvd.nist.gov/vuln/detail/CVE-2020-15099",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/typo3/cms-core/CVE-2020-15099.yaml"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "9.5.20"
   }
  },
  {
   "key": "cve-typo3-2020-15241",
   "title": "typo3 < 9.5.6 \u2014 Cross-Site Scripting in ternary conditional operator (CVE-2020-15241)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-15241",
   "tech": "typo3",
   "fixed": "9.5.6",
   "remediation": "Upgrade typo3 to >= 9.5.6.",
   "refs": [
    "https://github.com/TYPO3/Fluid/security/advisories/GHSA-7733-hjv6-4h47",
    "https://nvd.nist.gov/vuln/detail/CVE-2020-15241",
    "https://github.com/TYPO3/Fluid/commit/9ef6a8ffff2e812025fc0701b4ce72eea6911a3d"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "9.5.6"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-typo3-2020-26227",
   "title": "typo3 < 8.7.38 \u2014 Cross-Site Scripting in Fluid view helpers (CVE-2020-26227)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2020-26227",
   "tech": "typo3",
   "fixed": "8.7.38",
   "remediation": "Upgrade typo3 to >= 8.7.38.",
   "refs": [
    "https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-vqqx-jw6p-q3rf",
    "https://nvd.nist.gov/vuln/detail/CVE-2020-26227",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/typo3/cms-core/CVE-2020-26227.yaml"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "8.7.38"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-typo3-2020-26228",
   "title": "typo3 < 8.7.38 \u2014 Cleartext storage of session identifier (CVE-2020-26228)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2020-26228",
   "tech": "typo3",
   "fixed": "8.7.38",
   "remediation": "Upgrade typo3 to >= 8.7.38.",
   "refs": [
    "https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-954j-f27r-cj52",
    "https://nvd.nist.gov/vuln/detail/CVE-2020-26228",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/typo3/cms-core/CVE-2020-26228.yaml"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "8.7.38"
   }
  },
  {
   "key": "cve-typo3-2020-26229",
   "title": "typo3 < 10.4.10 \u2014 XML External Entity in Dashboard Widget (CVE-2020-26229)",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2020-26229",
   "tech": "typo3",
   "fixed": "10.4.10",
   "remediation": "Upgrade typo3 to >= 10.4.10.",
   "refs": [
    "https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-q9cp-mc96-m4w2",
    "https://nvd.nist.gov/vuln/detail/CVE-2020-26229",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/typo3/cms-core/CVE-2020-26229.yaml"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "10.4.10"
   }
  },
  {
   "key": "cve-typo3-2021-21338",
   "title": "typo3 < 9.5.25 \u2014 Open Redirection in Login Handling (CVE-2021-21338)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2021-21338",
   "tech": "typo3",
   "fixed": "9.5.25",
   "remediation": "Upgrade typo3 to >= 9.5.25.",
   "refs": [
    "https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-4jhw-2p6j-5wmp",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-21338",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/typo3/cms-core/CVE-2021-21338.yaml"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "9.5.25"
   },
   "cwe": "CWE-601"
  },
  {
   "key": "cve-typo3-2021-21339",
   "title": "typo3 < 9.5.25 \u2014 Cleartext storage of session identifier (CVE-2021-21339)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2021-21339",
   "tech": "typo3",
   "fixed": "9.5.25",
   "remediation": "Upgrade typo3 to >= 9.5.25.",
   "refs": [
    "https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-qx3w-4864-94ch",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-21339",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/typo3/cms-core/CVE-2021-21339.yaml"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "9.5.25"
   }
  },
  {
   "key": "cve-typo3-2021-21340",
   "title": "typo3 < 11.1.1 \u2014 Cross-Site Scripting in Content Preview (CVE-2021-21340)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2021-21340",
   "tech": "typo3",
   "fixed": "11.1.1",
   "remediation": "Upgrade typo3 to >= 11.1.1.",
   "refs": [
    "https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-fjh3-g8gq-9q92",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-21340",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/typo3/cms-core/CVE-2021-21340.yaml"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "11.1.1"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-typo3-2021-21355",
   "title": "typo3 < 9.5.25 \u2014 Unrestricted File Upload in Form Framework (CVE-2021-21355)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2021-21355",
   "tech": "typo3",
   "fixed": "9.5.25",
   "remediation": "Upgrade typo3 to >= 9.5.25.",
   "refs": [
    "https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-2r6j-862c-m2v2",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-21355",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/typo3/cms-core/CVE-2021-21355.yaml"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "9.5.25"
   }
  },
  {
   "key": "cve-typo3-2021-21357",
   "title": "typo3 < 9.5.25 \u2014 Broken Access Control in Form Framework (CVE-2021-21357)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2021-21357",
   "tech": "typo3",
   "fixed": "9.5.25",
   "remediation": "Upgrade typo3 to >= 9.5.25.",
   "refs": [
    "https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-3vg7-jw9m-pc3f",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-21357",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/typo3/cms-core/CVE-2021-21357.yaml"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "9.5.25"
   }
  },
  {
   "key": "cve-typo3-2021-21358",
   "title": "typo3 < 11.1.1 \u2014 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in typo3/cms-form (CVE-2021-21358)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2021-21358",
   "tech": "typo3",
   "fixed": "11.1.1",
   "remediation": "Upgrade typo3 to >= 11.1.1.",
   "refs": [
    "https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-x79j-wgqv-g8h2",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-21358",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/typo3/cms-core/CVE-2021-21358.yaml"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "11.1.1"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-typo3-2021-21359",
   "title": "typo3 < 9.5.25 \u2014 Denial of Service in Page Error Handling (CVE-2021-21359)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2021-21359",
   "tech": "typo3",
   "fixed": "9.5.25",
   "remediation": "Upgrade typo3 to >= 9.5.25.",
   "refs": [
    "https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-4p9g-qgx9-397p",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-21359",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/typo3/cms-core/CVE-2021-21359.yaml"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "9.5.25"
   },
   "cwe": "CWE-400"
  },
  {
   "key": "cve-typo3-2021-21370",
   "title": "typo3 < 9.5.25 \u2014 Cross-Site Scripting in Content Preview (CType menu) (CVE-2021-21370)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2021-21370",
   "tech": "typo3",
   "fixed": "9.5.25",
   "remediation": "Upgrade typo3 to >= 9.5.25.",
   "refs": [
    "https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-x7hc-x7fm-f7qh",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-21370",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/typo3/cms-core/CVE-2021-21370.yaml"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "9.5.25"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-typo3-2021-32667",
   "title": "typo3 < 9.5.28 \u2014 Cross-Site Scripting in Page Preview (CVE-2021-32667)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2021-32667",
   "tech": "typo3",
   "fixed": "9.5.28",
   "remediation": "Upgrade typo3 to >= 9.5.28.",
   "refs": [
    "https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-8mq9-fqv8-59wf",
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-8mq9-fqv8-59wf",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-32667"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "9.5.28"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-typo3-2021-32668",
   "title": "typo3 < 9.5.28 \u2014 Cross-Site Scripting in Query Generator & Query View (CVE-2021-32668)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2021-32668",
   "tech": "typo3",
   "fixed": "9.5.28",
   "remediation": "Upgrade typo3 to >= 9.5.28.",
   "refs": [
    "https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-6mh3-j5r5-2379",
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-6mh3-j5r5-2379",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-32668"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "9.5.28"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-typo3-2021-32669",
   "title": "typo3 < 9.5.28 \u2014 Cross-Site Scripting in Backend Grid View (CVE-2021-32669)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2021-32669",
   "tech": "typo3",
   "fixed": "9.5.28",
   "remediation": "Upgrade typo3 to >= 9.5.28.",
   "refs": [
    "https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-rgcg-28xm-8mmw",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-32669",
    "https://github.com/FriendsOfPHP/security-advisories/blob/master/typo3/cms-core/CVE-2021-32669.yaml"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "9.5.28"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-typo3-2021-32767",
   "title": "typo3 < 9.5.28 \u2014 Information Disclosure in User Authentication (CVE-2021-32767)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2021-32767",
   "tech": "typo3",
   "fixed": "9.5.28",
   "remediation": "Upgrade typo3 to >= 9.5.28.",
   "refs": [
    "https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-34fr-fhqr-7235",
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-34fr-fhqr-7235",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-32767"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "9.5.28"
   }
  },
  {
   "key": "cve-typo3-2021-32768",
   "title": "typo3 < 7.6.53 \u2014 Cross-Site Scripting via Rich-Text Content (CVE-2021-32768)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2021-32768",
   "tech": "typo3",
   "fixed": "7.6.53",
   "remediation": "Upgrade typo3 to >= 7.6.53.",
   "refs": [
    "https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-c5c9-8c6m-727v",
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-c5c9-8c6m-727v",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-32768"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "7.6.53"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-typo3-2021-41113",
   "title": "typo3 < 11.5.0 \u2014 Cross-Site-Request-Forgery in Backend (CVE-2021-41113)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2021-41113",
   "tech": "typo3",
   "fixed": "11.5.0",
   "remediation": "Upgrade typo3 to >= 11.5.0.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-657m-v5vm-f6rw",
    "https://nvd.nist.gov/vuln/detail/CVE-2020-11069",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-41113"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "11.5.0"
   }
  },
  {
   "key": "cve-typo3-2021-41114",
   "title": "typo3 < 11.5.0 \u2014 HTTP Host Header Injection (CVE-2021-41114)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2021-41114",
   "tech": "typo3",
   "fixed": "11.5.0",
   "remediation": "Upgrade typo3 to >= 11.5.0.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-m2jh-fxw4-gphm",
    "https://nvd.nist.gov/vuln/detail/CVE-2014-3941",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-41114"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "11.5.0"
   }
  },
  {
   "key": "cve-typo3-2022-23500",
   "title": "typo3 < 11.5.20 \u2014 TYPO3 CMS vulnerable to Denial of Service in Page Error Handling (CVE-2022-23500)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-23500",
   "tech": "typo3",
   "fixed": "11.5.20",
   "remediation": "Upgrade typo3 to >= 11.5.20.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-8c28-5mp7-v24h",
    "https://nvd.nist.gov/vuln/detail/CVE-2022-23500",
    "https://github.com/TYPO3/typo3/commit/1e5f44417f031c9c5a9f9d09a6a841cf89aa7b7a"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "11.5.20"
   },
   "cwe": "CWE-400"
  },
  {
   "key": "cve-typo3-2022-23501",
   "title": "typo3 < 12.1.1 \u2014 TYPO3 CMS vulnerable to Weak Authentication in Frontend Login (CVE-2022-23501)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-23501",
   "tech": "typo3",
   "fixed": "12.1.1",
   "remediation": "Upgrade typo3 to >= 12.1.1.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-jfp7-79g7-89rf",
    "https://nvd.nist.gov/vuln/detail/CVE-2022-23501",
    "https://github.com/TYPO3/typo3/commit/28be9cdb3fed02ce4cfc6fa2d39f7d8e2266eced"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "12.1.1"
   }
  },
  {
   "key": "cve-typo3-2022-23502",
   "title": "typo3 < 12.1.1 \u2014 TYPO3 CMS vulnerable to Insufficient Session Expiration after Password Reset (CVE-2022-23502)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-23502",
   "tech": "typo3",
   "fixed": "12.1.1",
   "remediation": "Upgrade typo3 to >= 12.1.1.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-mgj2-q8wp-29rr",
    "https://nvd.nist.gov/vuln/detail/CVE-2022-23502",
    "https://github.com/TYPO3/typo3/commit/d9ffbf24fcc62068033ebb3912538347bd380a6c"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "12.1.1"
   }
  },
  {
   "key": "cve-typo3-2022-23503",
   "title": "typo3 < 12.1.1 \u2014 TYPO3 CMS vulnerable to Arbitrary Code Execution via Form Framework (CVE-2022-23503)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2022-23503",
   "tech": "typo3",
   "fixed": "12.1.1",
   "remediation": "Upgrade typo3 to >= 12.1.1.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-c5wx-6c2c-f7rm",
    "https://nvd.nist.gov/vuln/detail/CVE-2022-23503",
    "https://github.com/TYPO3/typo3/commit/1302e88565821f2159e08b5d818d28de17ecc830"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "12.1.1"
   }
  },
  {
   "key": "cve-typo3-2022-23504",
   "title": "typo3 < 12.1.1 \u2014 TYPO3 CMS vulnerable to Sensitive Information Disclosure via YAML Placeholder Expressions in Site Configuration (CVE-2022-2",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-23504",
   "tech": "typo3",
   "fixed": "12.1.1",
   "remediation": "Upgrade typo3 to >= 12.1.1.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-8w3p-qh3x-6gjr",
    "https://nvd.nist.gov/vuln/detail/CVE-2022-23504",
    "https://github.com/TYPO3/typo3/commit/d1e627ff7eef07bd94c53db861e85977b203900a"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "12.1.1"
   }
  },
  {
   "key": "cve-typo3-2022-31046",
   "title": "typo3 < 11.5.11 \u2014 Information Disclosure via Export Module (CVE-2022-31046)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-31046",
   "tech": "typo3",
   "fixed": "11.5.11",
   "remediation": "Upgrade typo3 to >= 11.5.11.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-8gmv-9hwg-w89g",
    "https://nvd.nist.gov/vuln/detail/CVE-2022-31046",
    "https://github.com/TYPO3/typo3/commit/7447a3d1283017d2ee08737a7972c720001a93e9"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "11.5.11"
   }
  },
  {
   "key": "cve-typo3-2022-31047",
   "title": "typo3 < 11.5.11 \u2014 Insertion of Sensitive Information into Log File in typo3/cms-core (CVE-2022-31047)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-31047",
   "tech": "typo3",
   "fixed": "11.5.11",
   "remediation": "Upgrade typo3 to >= 11.5.11.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-fh99-4pgr-8j99",
    "https://nvd.nist.gov/vuln/detail/CVE-2022-31047",
    "https://github.com/TYPO3/typo3/commit/c93ea692e7dfef03b7c50fe5437487545bee4d6a"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "11.5.11"
   }
  },
  {
   "key": "cve-typo3-2022-31048",
   "title": "typo3 < 11.5.11 \u2014 Cross-Site Scripting in TYPO3's Form Framework (CVE-2022-31048)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-31048",
   "tech": "typo3",
   "fixed": "11.5.11",
   "remediation": "Upgrade typo3 to >= 11.5.11.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-3r95-23jp-mhvg",
    "https://nvd.nist.gov/vuln/detail/CVE-2022-31048",
    "https://github.com/TYPO3/typo3/commit/6f2554dc4ea0b670fd5599c54fd788d4db96c4a0"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "11.5.11"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-typo3-2022-31049",
   "title": "typo3 < 11.5.11 \u2014 Cross-Site Scripting in TYPO3's Frontend Login Mailer (CVE-2022-31049)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-31049",
   "tech": "typo3",
   "fixed": "11.5.11",
   "remediation": "Upgrade typo3 to >= 11.5.11.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-h4mx-xv96-2jgm",
    "https://nvd.nist.gov/vuln/detail/CVE-2022-31049",
    "https://github.com/TYPO3/typo3/commit/da611775f92102d7602713003f4c79606c8a445d"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "11.5.11"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-typo3-2022-31050",
   "title": "typo3 < 11.5.11 \u2014 Insufficient Session Expiration in TYPO3's Admin Tool (CVE-2022-31050)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-31050",
   "tech": "typo3",
   "fixed": "11.5.11",
   "remediation": "Upgrade typo3 to >= 11.5.11.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-wwjw-r3gj-39fq",
    "https://nvd.nist.gov/vuln/detail/CVE-2022-31050",
    "https://github.com/TYPO3/typo3/commit/592387972912290c135ebecc91768a67f83a3a4d"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "11.5.11"
   }
  },
  {
   "key": "cve-typo3-2022-36020",
   "title": "typo3 < 11.5.16 \u2014 TYPO3 HTML Sanitizer Bypasses Cross-Site Scripting Protection (CVE-2022-36020)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-36020",
   "tech": "typo3",
   "fixed": "11.5.16",
   "remediation": "Upgrade typo3 to >= 11.5.16.",
   "refs": [
    "https://github.com/TYPO3/html-sanitizer/security/advisories/GHSA-47m6-46mj-p235",
    "https://nvd.nist.gov/vuln/detail/CVE-2022-36020",
    "https://github.com/TYPO3/html-sanitizer/commit/60bfdc7f9b394d0236e16ee4cea8372a7defa493"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "11.5.16"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-typo3-2022-36104",
   "title": "typo3 < 11.5.16 \u2014 TYPO3 CMS vulnerable to Denial of Service in Page Error Handling (CVE-2022-36104)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-36104",
   "tech": "typo3",
   "fixed": "11.5.16",
   "remediation": "Upgrade typo3 to >= 11.5.16.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-fffr-7x4x-f98q",
    "https://nvd.nist.gov/vuln/detail/CVE-2022-36104",
    "https://github.com/TYPO3/typo3/commit/179dd7cd78947081d573fee2050e197faa556f13"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "11.5.16"
   },
   "cwe": "CWE-400"
  },
  {
   "key": "cve-typo3-2022-36105",
   "title": "typo3 < 11.5.16 \u2014 TYPO3 CMS vulnerable to User Enumeration via Response Timing (CVE-2022-36105)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-36105",
   "tech": "typo3",
   "fixed": "11.5.16",
   "remediation": "Upgrade typo3 to >= 11.5.16.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-m392-235j-9r7r",
    "https://nvd.nist.gov/vuln/detail/CVE-2022-36105",
    "https://github.com/TYPO3/typo3/commit/f0fc9c4cd7c38207c30dd158de53ee5d9d6f41a2"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "11.5.16"
   }
  },
  {
   "key": "cve-typo3-2022-36106",
   "title": "typo3 < 11.5.16 \u2014 TYPO3 CMS missing check for expiration time of password reset token for backend users (CVE-2022-36106)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-36106",
   "tech": "typo3",
   "fixed": "11.5.16",
   "remediation": "Upgrade typo3 to >= 11.5.16.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-5959-4x58-r8c2",
    "https://nvd.nist.gov/vuln/detail/CVE-2022-36106",
    "https://github.com/TYPO3/typo3/commit/00b52a443b21baaaab35f8606dbb0ce427261bb5"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "11.5.16"
   }
  },
  {
   "key": "cve-typo3-2022-36107",
   "title": "typo3 < 11.5.16 \u2014 TYPO3 CMS Stored Cross-Site Scripting via FileDumpController (CVE-2022-36107)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-36107",
   "tech": "typo3",
   "fixed": "11.5.16",
   "remediation": "Upgrade typo3 to >= 11.5.16.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-9c6w-55cp-5w25",
    "https://nvd.nist.gov/vuln/detail/CVE-2022-36107",
    "https://github.com/TYPO3/typo3/commit/546208428c861a09d62b86cde141eb19a81fae66"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "11.5.16"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-typo3-2022-36108",
   "title": "typo3 < 11.5.16 \u2014 TYPO3 CMS vulnerable to Cross-Site Scripting in <f:asset.css> view helper (CVE-2022-36108)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2022-36108",
   "tech": "typo3",
   "fixed": "11.5.16",
   "remediation": "Upgrade typo3 to >= 11.5.16.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-fv2m-9249-qx85",
    "https://nvd.nist.gov/vuln/detail/CVE-2022-36108",
    "https://github.com/TYPO3/typo3/commit/6863f73818c36b0b88c677ba533765c8074907b4"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "11.5.16"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-typo3-2023-24814",
   "title": "typo3 < 12.2.0 \u2014 TYPO3 is vulnerable to Cross-Site Scripting via frontend rendering (CVE-2023-24814)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2023-24814",
   "tech": "typo3",
   "fixed": "12.2.0",
   "remediation": "Upgrade typo3 to >= 12.2.0.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-r4f8-f93x-5qh3",
    "https://nvd.nist.gov/vuln/detail/CVE-2023-24814",
    "https://github.com/TYPO3/typo3/commit/0005a6fd86ab97eff8bf2e3a5828bf0e7cb6263a"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "12.2.0"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-typo3-2023-30451",
   "title": "typo3 < 13.0.1 \u2014 Path Traversal in TYPO3 File Abstraction Layer Storages (CVE-2023-30451)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2023-30451",
   "tech": "typo3",
   "fixed": "13.0.1",
   "remediation": "Upgrade typo3 to >= 13.0.1.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-w6x2-jg8h-p6mp",
    "https://nvd.nist.gov/vuln/detail/CVE-2023-30451",
    "https://github.com/TYPO3/typo3/commit/205115cca3d67594a12d0195c937da0e51eb494a"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "13.0.1"
   },
   "cwe": "CWE-22"
  },
  {
   "key": "cve-typo3-2023-38499",
   "title": "typo3 < 12.4.4 \u2014 Information Disclosure due to Out-of-scope Site Resolution (CVE-2023-38499)",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2023-38499",
   "tech": "typo3",
   "fixed": "12.4.4",
   "remediation": "Upgrade typo3 to >= 12.4.4.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-jq6g-4v5m-wm9r",
    "https://nvd.nist.gov/vuln/detail/CVE-2023-38499",
    "https://github.com/TYPO3/typo3/commit/702e2debd4b28f9cdb540544565fe6a8627ccb6a"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "12.4.4"
   }
  },
  {
   "key": "cve-typo3-2023-47127",
   "title": "typo3 < 12.4.8 \u2014 TYPO3 vulnerable to Weak Authentication in Session Handling (CVE-2023-47127)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2023-47127",
   "tech": "typo3",
   "fixed": "12.4.8",
   "remediation": "Upgrade typo3 to >= 12.4.8.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-3vmm-7h4j-69rm",
    "https://nvd.nist.gov/vuln/detail/CVE-2023-47127",
    "https://github.com/TYPO3/typo3/commit/535dfbdc54fd5362e0bc08d911db44eac7f64019"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "12.4.8"
   }
  },
  {
   "key": "cve-typo3-2024-22188",
   "title": "typo3 < 13.0.1 \u2014 TYPO3 Install Tool vulnerable to Code Execution (CVE-2024-22188)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2024-22188",
   "tech": "typo3",
   "fixed": "13.0.1",
   "remediation": "Upgrade typo3 to >= 13.0.1.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-5w2h-59j3-8x5w",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-22188",
    "https://github.com/TYPO3/typo3/commit/47e897f8c7668ef299ecc9ce93f52cafbb3497ed"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "13.0.1"
   }
  },
  {
   "key": "cve-typo3-2024-25118",
   "title": "typo3 < 13.0.1 \u2014 TYPO3 Backend Forms vulnerable to Information Disclosure of Hashed Passwords (CVE-2024-25118)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2024-25118",
   "tech": "typo3",
   "fixed": "13.0.1",
   "remediation": "Upgrade typo3 to >= 13.0.1.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-38r2-5695-334w",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-25118",
    "https://github.com/TYPO3/typo3/commit/1186b2fec8a665a8f228ed66e6d60abf8407c17b"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "13.0.1"
   }
  },
  {
   "key": "cve-typo3-2024-25119",
   "title": "typo3 < 13.0.1 \u2014 TYPO3 Install Tool vulnerable to Information Disclosure of Encryption Key (CVE-2024-25119)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2024-25119",
   "tech": "typo3",
   "fixed": "13.0.1",
   "remediation": "Upgrade typo3 to >= 13.0.1.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-h47m-3f78-qp9g",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-25119",
    "https://github.com/TYPO3/typo3/commit/14d101359c71ee963cf51ad0c8ae777b7b9ec9a1"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "13.0.1"
   }
  },
  {
   "key": "cve-typo3-2024-25120",
   "title": "typo3 < 13.0.1 \u2014 TYPO3 vulnerable to Improper Access Control of Resources Referenced by t3:// URI Scheme (CVE-2024-25120)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2024-25120",
   "tech": "typo3",
   "fixed": "13.0.1",
   "remediation": "Upgrade typo3 to >= 13.0.1.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-wf85-8hx9-gj7c",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-25120",
    "https://github.com/TYPO3/typo3/commit/2de87ff113ba24333ab7cbb8078588743f8958d6"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "13.0.1"
   },
   "cwe": "CWE-94"
  },
  {
   "key": "cve-typo3-2024-25121",
   "title": "typo3 < 13.0.1 \u2014 TYPO3 vulnerable to Improper Access Control Persisting File Abstraction Layer Entities via Data Handler (CVE-2024-25121)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2024-25121",
   "tech": "typo3",
   "fixed": "13.0.1",
   "remediation": "Upgrade typo3 to >= 13.0.1.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-rj3x-wvc6-5j66",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-25121",
    "https://github.com/TYPO3/typo3/commit/38f0bf9a61e10365be26eb75bc23a81184dbed07"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "13.0.1"
   }
  },
  {
   "key": "cve-typo3-2024-34355",
   "title": "typo3 < 13.1.1 \u2014 TYPO3 vulnerable to an HTML Injection in the History Module (CVE-2024-34355)",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2024-34355",
   "tech": "typo3",
   "fixed": "13.1.1",
   "remediation": "Upgrade typo3 to >= 13.1.1.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-xjwx-78x7-q6jc",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-34355",
    "https://github.com/TYPO3/typo3/commit/56afa304ba8b5ad302e15df5def71bcc8d820375"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "13.1.1"
   }
  },
  {
   "key": "cve-typo3-2024-34356",
   "title": "typo3 < 13.1.1 \u2014 TYPO3 vulnerable to Cross-Site Scripting in the Form Manager Module (CVE-2024-34356)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2024-34356",
   "tech": "typo3",
   "fixed": "13.1.1",
   "remediation": "Upgrade typo3 to >= 13.1.1.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-v6mw-h7w6-59w3",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-34356",
    "https://github.com/TYPO3/typo3/commit/2832e2f51f929aeddb5de7d667538a33ceda8156"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "13.1.1"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-typo3-2024-34357",
   "title": "typo3 < 13.1.1 \u2014 TYPO3 vulnerable to Cross-Site Scripting in the ShowImageController (CVE-2024-34357)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2024-34357",
   "tech": "typo3",
   "fixed": "13.1.1",
   "remediation": "Upgrade typo3 to >= 13.1.1.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-hw6c-6gwq-3m3m",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-34357",
    "https://github.com/TYPO3/typo3/commit/376474904f6b9a54dc1b785a2e45277cbd13b0d7"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "13.1.1"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-typo3-2024-34358",
   "title": "typo3 < 13.1.1 \u2014 TYPO3 vulnerable to an Uncontrolled Resource Consumption in the ShowImageController (CVE-2024-34358)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2024-34358",
   "tech": "typo3",
   "fixed": "13.1.1",
   "remediation": "Upgrade typo3 to >= 13.1.1.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-36g8-62qv-5957",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-34358",
    "https://github.com/TYPO3/typo3/commit/05c95fed869a1a6dcca06c7077b83b6ea866ff14"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "13.1.1"
   },
   "cwe": "CWE-94"
  },
  {
   "key": "cve-typo3-2024-55892",
   "title": "typo3 < 13.4.3 \u2014 TYPO3 Potential Open Redirect via Parsing Differences (CVE-2024-55892)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2024-55892",
   "tech": "typo3",
   "fixed": "13.4.3",
   "remediation": "Upgrade typo3 to >= 13.4.3.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-2fx5-pggv-6jjr",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-55892",
    "https://github.com/TYPO3/typo3/commit/a4abf48d254685f43383e6e7f80d48aebaea56af"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "13.4.3"
   },
   "cwe": "CWE-601"
  },
  {
   "key": "cve-typo3-2025-47937",
   "title": "typo3 < 13.4.12 \u2014 TYPO3 Allows Information Disclosure via DBAL Restriction Handling (CVE-2025-47937)",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2025-47937",
   "tech": "typo3",
   "fixed": "13.4.12",
   "remediation": "Upgrade typo3 to >= 13.4.12.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-x8pv-fgxp-8v3x",
    "https://nvd.nist.gov/vuln/detail/CVE-2025-47937",
    "https://github.com/TYPO3-CMS/core"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "13.4.12"
   }
  },
  {
   "key": "cve-typo3-2025-47938",
   "title": "typo3 < 13.4.12 \u2014 TYPO3 Unverified Password Change for Backend Users (CVE-2025-47938)",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2025-47938",
   "tech": "typo3",
   "fixed": "13.4.12",
   "remediation": "Upgrade typo3 to >= 13.4.12.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-3jrg-97f3-rqh9",
    "https://nvd.nist.gov/vuln/detail/CVE-2025-47938",
    "https://github.com/TYPO3-CMS/core/commit/b9a8bcb614ecdd42aa27e1c430c6213d6b6b20b3"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "13.4.12"
   }
  },
  {
   "key": "cve-typo3-2025-47939",
   "title": "typo3 < 13.4.12 \u2014 TYPO3 Allows Unrestricted File Upload in File Abstraction Layer (CVE-2025-47939)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2025-47939",
   "tech": "typo3",
   "fixed": "13.4.12",
   "remediation": "Upgrade typo3 to >= 13.4.12.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-9hq9-cr36-4wpj",
    "https://nvd.nist.gov/vuln/detail/CVE-2025-47939",
    "https://github.com/TYPO3-CMS/core/commit/c265beed6e2c01817c534a226e80e593400f8255"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "13.4.12"
   }
  },
  {
   "key": "cve-typo3-2025-47940",
   "title": "typo3 < 13.4.12 \u2014 TYPO3 Allows Privilege Escalation to System Maintainer (CVE-2025-47940)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2025-47940",
   "tech": "typo3",
   "fixed": "13.4.12",
   "remediation": "Upgrade typo3 to >= 13.4.12.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-6frx-j292-c844",
    "https://nvd.nist.gov/vuln/detail/CVE-2025-47940",
    "https://github.com/TYPO3-CMS/core/commit/a659cc8c0ae05c44dd7f01d13629cdd2d0b7219b"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "13.4.12"
   }
  },
  {
   "key": "cve-typo3-2025-59013",
   "title": "typo3 < 13.4.18 \u2014 TYPO3 CMS has an open\u2011redirect vulnerability (CVE-2025-59013)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2025-59013",
   "tech": "typo3",
   "fixed": "13.4.18",
   "remediation": "Upgrade typo3 to >= 13.4.18.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2025-59013",
    "https://github.com/TYPO3-CMS/core/commit/862b9da870815132c31119cd85bc454a5010793c",
    "https://github.com/TYPO3-CMS/core"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "13.4.18"
   }
  },
  {
   "key": "cve-typo3-2025-59015",
   "title": "typo3 < 13.4.18 \u2014 TYPO3 CMS uses insufficient entropy when generating passwords (CVE-2025-59015)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2025-59015",
   "tech": "typo3",
   "fixed": "13.4.18",
   "remediation": "Upgrade typo3 to >= 13.4.18.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2025-59015",
    "https://github.com/TYPO3-CMS/core/commit/d2057cc7b2c2db417a2af38c30cb9da42302ab70",
    "https://github.com/TYPO3-CMS/core"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "13.4.18"
   }
  },
  {
   "key": "cve-typo3-2025-59016",
   "title": "typo3 < 13.4.18 \u2014 TYPO3 CMS exposes sensitive information in an error message (CVE-2025-59016)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2025-59016",
   "tech": "typo3",
   "fixed": "13.4.18",
   "remediation": "Upgrade typo3 to >= 13.4.18.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2025-59016",
    "https://github.com/TYPO3-CMS/core/commit/e1e4380a2d8e72228c597403f0463c21d6e1b8d9",
    "https://github.com/TYPO3-CMS/core"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "13.4.18"
   }
  },
  {
   "key": "cve-typo3-2026-0859",
   "title": "typo3 < 10.4.55 \u2014 TYPO3 CMS Allows Insecure Deserialization via Mailer File Spool (CVE-2026-0859)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-0859",
   "tech": "typo3",
   "fixed": "10.4.55",
   "remediation": "Upgrade typo3 to >= 10.4.55.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-7vp9-x248-9vr9",
    "https://nvd.nist.gov/vuln/detail/CVE-2026-0859",
    "https://github.com/TYPO3/typo3/commit/3225d705080a1bde57a66689621c947da5a4782f"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "10.4.55"
   },
   "cwe": "CWE-502"
  },
  {
   "key": "cve-typo3-2026-11607",
   "title": "typo3 < 14.3.3 \u2014 TYPO3 CMS has Broken Access Control in its Form Framework (CVE-2026-11607)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2026-11607",
   "tech": "typo3",
   "fixed": "14.3.3",
   "remediation": "Upgrade typo3 to >= 14.3.3.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-pjpj-v387-x4vq",
    "https://nvd.nist.gov/vuln/detail/CVE-2026-11607",
    "https://github.com/TYPO3/typo3/commit/040d50d082a01f9e8bd113effd91290a9bb3b69e"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "14.3.3"
   }
  },
  {
   "key": "cve-typo3-2026-19418",
   "title": "typo3 < 14.3.6 \u2014 TYPO3 CMS - Broken Access Control in Backend and Install Tool (CVE-2026-19418)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2026-19418",
   "tech": "typo3",
   "fixed": "14.3.6",
   "remediation": "Upgrade typo3 to >= 14.3.6.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-68jx-f42c-7599",
    "https://nvd.nist.gov/vuln/detail/CVE-2026-19418",
    "https://github.com/TYPO3/typo3/commit/4a75e862c589c85d795d7c65dcdc835f8f413efc"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "14.3.6"
   }
  },
  {
   "key": "cve-typo3-2026-47343",
   "title": "typo3 < 14.3.3 \u2014 TYPO3 CMS: Destructive Actions on File Mount Folders (CVE-2026-47343)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2026-47343",
   "tech": "typo3",
   "fixed": "14.3.3",
   "remediation": "Upgrade typo3 to >= 14.3.3.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-3v8v-4wg6-r7qh",
    "https://nvd.nist.gov/vuln/detail/CVE-2026-47343",
    "https://github.com/TYPO3/typo3/commit/504e72470ff72aaf5d2256878bf473747f389798"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "14.3.3"
   }
  },
  {
   "key": "cve-typo3-2026-47346",
   "title": "typo3 < 14.3.3 \u2014 TYPO3 CMS has Broken Access Control in its Form Framework (CVE-2026-47346)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2026-47346",
   "tech": "typo3",
   "fixed": "14.3.3",
   "remediation": "Upgrade typo3 to >= 14.3.3.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-hwvq-2w67-rvxp",
    "https://nvd.nist.gov/vuln/detail/CVE-2026-47346",
    "https://github.com/TYPO3/typo3/commit/2030617e6f273cee7b756c695f0a48a45a31eb47"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "14.3.3"
   }
  },
  {
   "key": "cve-typo3-2026-47347",
   "title": "typo3 < 14.3.3 \u2014 TYPO3 CMS has an Open Redirect Vulnerability via Core Utilities (CVE-2026-47347)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-47347",
   "tech": "typo3",
   "fixed": "14.3.3",
   "remediation": "Upgrade typo3 to >= 14.3.3.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-3p42-w5ch-gg42",
    "https://nvd.nist.gov/vuln/detail/CVE-2026-47347",
    "https://github.com/TYPO3/typo3/commit/22c2dd5398ebc4cb7aa4aa37e02cb39181dee0cd"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "14.3.3"
   },
   "cwe": "CWE-601"
  },
  {
   "key": "cve-typo3-2026-47348",
   "title": "typo3 < 14.3.3 \u2014 TYPO3 CMS has Cross-Site Scripting in Indexed Search (CVE-2026-47348)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-47348",
   "tech": "typo3",
   "fixed": "14.3.3",
   "remediation": "Upgrade typo3 to >= 14.3.3.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-cg75-qfg2-w9hj",
    "https://nvd.nist.gov/vuln/detail/CVE-2026-47348",
    "https://github.com/TYPO3/typo3/commit/2e96dd0e9fab7ad877b741fb9f6fc645b4270a3e"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "14.3.3"
   },
   "cwe": "CWE-79"
  },
  {
   "key": "cve-typo3-2026-47349",
   "title": "typo3 < 14.3.3 \u2014 TYPO3 CMS has Broken Access Control in the Recycler Module (CVE-2026-47349)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-47349",
   "tech": "typo3",
   "fixed": "14.3.3",
   "remediation": "Upgrade typo3 to >= 14.3.3.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-f34x-rx2w-7pm3",
    "https://nvd.nist.gov/vuln/detail/CVE-2026-47349",
    "https://github.com/TYPO3/typo3/commit/92f08d8944f1aeccf506fcd323c260448c64d7c8"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "14.3.3"
   }
  },
  {
   "key": "cve-typo3-2026-47350",
   "title": "typo3 < 14.3.3 \u2014 TYPO3 CMS has Broken Access Control in its DataHandler (CVE-2026-47350)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-47350",
   "tech": "typo3",
   "fixed": "14.3.3",
   "remediation": "Upgrade typo3 to >= 14.3.3.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-qcmw-6rm2-5x78",
    "https://nvd.nist.gov/vuln/detail/CVE-2026-47350",
    "https://github.com/TYPO3/typo3/commit/195356996a60e40aeb2cd3e45a5f5c8940d5e116"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "14.3.3"
   }
  },
  {
   "key": "cve-typo3-2026-47351",
   "title": "typo3 < 14.3.3 \u2014 TYPO3 CMS: Broken Access Control in Media Module (CVE-2026-47351)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-47351",
   "tech": "typo3",
   "fixed": "14.3.3",
   "remediation": "Upgrade typo3 to >= 14.3.3.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-q93m-25xv-94hh",
    "https://nvd.nist.gov/vuln/detail/CVE-2026-47351",
    "https://github.com/TYPO3/typo3/commit/2740707563343d78184c0b7c6303a7484553d7f3"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "14.3.3"
   }
  },
  {
   "key": "cve-typo3-2026-47352",
   "title": "typo3 < 14.3.3 \u2014 TYPO3 CMS has Broken Access Control in Backend API (CVE-2026-47352)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-47352",
   "tech": "typo3",
   "fixed": "14.3.3",
   "remediation": "Upgrade typo3 to >= 14.3.3.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-2j54-93q2-3hjq",
    "https://nvd.nist.gov/vuln/detail/CVE-2026-47352",
    "https://github.com/TYPO3/typo3/commit/17a3b7830d5931725db5fdab0cfc76d479884c96"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "14.3.3"
   }
  },
  {
   "key": "cve-typo3-2026-49738",
   "title": "typo3 < 14.3.3 \u2014 TYPO3 CMS has Broken Access Control in its File Abstraction Layer (CVE-2026-49738)",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2026-49738",
   "tech": "typo3",
   "fixed": "14.3.3",
   "remediation": "Upgrade typo3 to >= 14.3.3.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-jf56-v8jc-jcc5",
    "https://nvd.nist.gov/vuln/detail/CVE-2026-49738",
    "https://github.com/TYPO3/typo3/commit/150a983a5d687cedcfc33bbe9c335d9a13fd05e5"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "14.3.3"
   }
  },
  {
   "key": "cve-typo3-2026-49740",
   "title": "typo3 < 14.3.3 \u2014 TYPO3 CMS has Insecure Deserialization via Core API (CVE-2026-49740)",
   "category": "cve",
   "severity": "medium",
   "confidence": "candidate",
   "cve": "CVE-2026-49740",
   "tech": "typo3",
   "fixed": "14.3.3",
   "remediation": "Upgrade typo3 to >= 14.3.3.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-c78m-c52x-jgwp",
    "https://nvd.nist.gov/vuln/detail/CVE-2026-49740",
    "https://github.com/TYPO3/typo3/commit/48bcf24f31f52cc0b43d3bea4984634bd2cf85c7"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "14.3.3"
   },
   "cwe": "CWE-502"
  },
  {
   "key": "cve-typo3-2026-49741",
   "title": "typo3 < 14.3.3 \u2014 TYPO3 CMS has Privilege Escalation & SQL Injection in its Form Framework (CVE-2026-49741)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2026-49741",
   "tech": "typo3",
   "fixed": "14.3.3",
   "remediation": "Upgrade typo3 to >= 14.3.3.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-jh32-v29g-68pq",
    "https://nvd.nist.gov/vuln/detail/CVE-2026-49741",
    "https://github.com/TYPO3/typo3/commit/c90493c13b633f328cf2c066182c90a1655ff0fc"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "14.3.3"
   },
   "cwe": "CWE-89"
  },
  {
   "key": "cve-typo3-2026-49742",
   "title": "typo3 < 14.3.3 \u2014 TYPO3 CMS has Broken Access Control in its Media Module (CVE-2026-49742)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "cve": "CVE-2026-49742",
   "tech": "typo3",
   "fixed": "14.3.3",
   "remediation": "Upgrade typo3 to >= 14.3.3.",
   "refs": [
    "https://github.com/TYPO3/typo3/security/advisories/GHSA-chm7-4vch-h8vr",
    "https://nvd.nist.gov/vuln/detail/CVE-2026-49742",
    "https://github.com/TYPO3/typo3/commit/ad636b6183843b57c758a1e12174a75093ac93c3"
   ],
   "match": {
    "tech": "typo3",
    "version_lt": "14.3.3"
   }
  },
  {
   "key": "cve-vue-2024-9506",
   "title": "vue < 3.0.0-alpha.0 \u2014 ReDoS vulnerability in vue package that is exploitable through inefficient regex evaluation in the parseHTML function ",
   "category": "cve",
   "severity": "low",
   "confidence": "candidate",
   "cve": "CVE-2024-9506",
   "tech": "vue",
   "fixed": "3.0.0-alpha.0",
   "remediation": "Upgrade vue to >= 3.0.0-alpha.0.",
   "refs": [
    "https://github.com/advisories/GHSA-5j4c-8p2g-v4jx",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-9506",
    "https://github.com/vuejs/core",
    "https://www.herodevs.com/vulnerability-directory/cve-2024-9506"
   ],
   "match": {
    "tech": "vue",
    "version_lt": "3.0.0-alpha.0"
   },
   "cwe": "CWE-1333"
  },
  {
   "key": "cve-wordpress-2022-21661",
   "title": "WordPress < 5.8.3 \u2014 SQL injection via WP_Query (CVE-2022-21661)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "remediation": "Upgrade WordPress to >= 5.8.3.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2022-21661"
   ],
   "cwe": "CWE-89",
   "cve": "CVE-2022-21661",
   "tech": "wordpress",
   "fixed": "5.8.3",
   "match": {
    "tech": "wordpress",
    "version_lt": "5.8.3"
   }
  },
  {
   "key": "cve-wordpress-2022-21663",
   "title": "WordPress < 5.8.3 \u2014 Object injection via multisite (CVE-2022-21663)",
   "category": "cve",
   "severity": "high",
   "confidence": "candidate",
   "remediation": "Upgrade WordPress to >= 5.8.3.",
   "refs": [
    "https://nvd.nist.gov/vuln/detail/CVE-2022-21663"
   ],
   "cve": "CVE-2022-21663",
   "tech": "wordpress",
   "fixed": "5.8.3",
   "match": {
    "tech": "wordpress",
    "version_lt": "5.8.3"
   }
  },
  {
   "key": "default-snmp-community",
   "title": "Default SNMP Community Strings",
   "category": "disclosure",
   "severity": "medium",
   "confidence": "confirmed",
   "remediation": "Disable SNMPv1/v2c and default 'public'/'private' communities; require SNMPv3 with authentication and privacy.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/798.html",
    "https://attack.mitre.org/techniques/T1046/",
    "https://cwe.mitre.org/data/definitions/798.html"
   ],
   "cwe": "CWE-798",
   "attack": "T1046",
   "nist": "IA-5",
   "match": {
    "facts_any": [
     "snmp.community"
    ]
   }
  },
  {
   "key": "exposed-sensitive-file",
   "title": "Exposed Sensitive File / Path",
   "category": "disclosure",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Restrict or remove the exposed path from public access (deny in web-server config).",
   "refs": [
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Review_Webpage_Content_for_Information_Leakage"
   ],
   "cwe": "CWE-538",
   "nist": "AC-3",
   "match": {
    "flag": "exposed_file"
   }
  },
  {
   "key": "exposed-vcs-metadata",
   "title": "Exposed Version-Control Metadata (.git/.svn)",
   "category": "disclosure",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Block access to .git and .svn directories at the web server, deploy from a clean export rather than a working copy, and rotate any credentials found in history.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/538.html",
    "https://attack.mitre.org/techniques/T1552/001/",
    "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url"
   ],
   "cwe": "CWE-538",
   "attack": "T1552.001",
   "nist": "CM-7",
   "match": {
    "facts_any": [
     "web.source"
    ]
   }
  },
  {
   "key": "server-version-disclosed",
   "title": "Server Version Disclosed",
   "category": "disclosure",
   "severity": "low",
   "confidence": "confirmed",
   "remediation": "Strip version numbers from the Server header (e.g. ServerTokens Prod in Apache).",
   "refs": [
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"
   ],
   "cwe": "CWE-200",
   "nist": "SC-30",
   "match": {
    "flag": "server_version_disclosed"
   }
  },
  {
   "key": "tech-stack-disclosed",
   "title": "Technology Stack Disclosed (X-Powered-By)",
   "category": "disclosure",
   "severity": "low",
   "confidence": "confirmed",
   "remediation": "Remove or obscure X-Powered-By in server/app config.",
   "refs": [
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Powered-By"
   ],
   "cwe": "CWE-200",
   "nist": "SC-30",
   "match": {
    "flag": "tech_disclosed"
   }
  },
  {
   "key": "dmarc-policy-none",
   "title": "DMARC Policy: none (monitoring only)",
   "category": "dns",
   "severity": "low",
   "confidence": "confirmed",
   "remediation": "Upgrade to p=quarantine then p=reject once confident in mail flows.",
   "refs": [
    "https://dmarc.org/"
   ],
   "cwe": "CWE-290",
   "nist": "SC-8",
   "match": {
    "flag": "dns_weak_dmarc"
   }
  },
  {
   "key": "missing-dmarc",
   "title": "Missing DMARC Record",
   "category": "dns",
   "severity": "medium",
   "confidence": "confirmed",
   "remediation": "Add: _dmarc TXT \"v=DMARC1; p=reject; rua=mailto:dmarc@<domain>\"",
   "refs": [
    "https://dmarc.org/"
   ],
   "cwe": "CWE-290",
   "nist": "SC-8",
   "match": {
    "flag": "dns_no_dmarc"
   }
  },
  {
   "key": "missing-spf",
   "title": "Missing SPF Record",
   "category": "dns",
   "severity": "medium",
   "confidence": "confirmed",
   "remediation": "Add: TXT \"v=spf1 include:<mail-provider> -all\"",
   "refs": [
    "https://datatracker.ietf.org/doc/rfc7208/"
   ],
   "cwe": "CWE-290",
   "nist": "SC-8",
   "match": {
    "flag": "dns_no_spf"
   }
  },
  {
   "key": "spf-permissive-plus-all",
   "title": "SPF Permissive (+all)",
   "category": "dns",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Replace +all with -all.",
   "refs": [
    "https://datatracker.ietf.org/doc/rfc7208/"
   ],
   "cwe": "CWE-290",
   "nist": "SC-8",
   "match": {
    "flag": "dns_weak_spf"
   }
  },
  {
   "key": "subdomain-takeover",
   "title": "Potential Subdomain Takeover",
   "category": "dns",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Claim the resource on the target service or remove the dangling CNAME.",
   "refs": [
    "https://github.com/EdOverflow/can-i-take-over-xyz"
   ],
   "cwe": "CWE-350",
   "nist": "CM-8",
   "match": {
    "flag": "subdomain_takeover"
   }
  },
  {
   "key": "weak-spf-policy",
   "title": "Weak SPF Policy (?all / no all)",
   "category": "dns",
   "severity": "medium",
   "confidence": "confirmed",
   "remediation": "Tighten SPF to -all (hard-fail) or ~all (soft-fail) at minimum.",
   "refs": [
    "https://datatracker.ietf.org/doc/rfc7208/"
   ],
   "cwe": "CWE-290",
   "nist": "SC-8",
   "match": {
    "flag": "dns_weak_spf"
   }
  },
  {
   "key": "stack-buffer-overflow",
   "title": "Stack Buffer Overflow in Custom/Legacy Service",
   "category": "exploit",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Patch or isolate the vulnerable application and rebuild it with modern exploit mitigations (DEP, ASLR, stack canaries).",
   "refs": [
    "https://cwe.mitre.org/data/definitions/120.html",
    "https://attack.mitre.org/techniques/T1068/",
    "https://cwe.mitre.org/data/definitions/120.html"
   ],
   "cwe": "CWE-120",
   "attack": "T1068",
   "nist": "SI-2"
  },
  {
   "key": "zerologon",
   "match": {"facts_any": ["ad.zerologon"]},
   "title": "Zerologon (CVE-2020-1472)",
   "category": "exploit",
   "severity": "critical",
   "confidence": "confirmed",
   "remediation": "Apply the August 2020+ Netlogon patches to all domain controllers, enable enforcement mode, and monitor events 5827-5829.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/330.html",
    "https://attack.mitre.org/techniques/T1068/",
    "https://nvd.nist.gov/vuln/detail/CVE-2020-1472"
   ],
   "cwe": "CWE-330",
   "attack": "T1068",
   "nist": "SI-2"
  },
  {
   "key": "missing-csp",
   "title": "Missing Content-Security-Policy",
   "category": "headers",
   "severity": "medium",
   "confidence": "confirmed",
   "remediation": "Add a CSP appropriate to your application (start with: default-src 'self').",
   "refs": [
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
   ],
   "cwe": "CWE-1021",
   "nist": "SC-18",
   "match": {
    "header_absent": "content-security-policy"
   }
  },
  {
   "key": "missing-hsts",
   "title": "Missing HSTS Header",
   "category": "headers",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
   "refs": [
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
   ],
   "cwe": "CWE-319",
   "nist": "SC-8",
   "match": {
    "header_absent": "strict-transport-security"
   }
  },
  {
   "key": "missing-permissions-policy",
   "title": "Missing Permissions-Policy",
   "category": "headers",
   "severity": "info",
   "confidence": "confirmed",
   "remediation": "Add a Permissions-Policy to restrict camera, microphone, geolocation, etc.",
   "refs": [
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"
   ],
   "cwe": "CWE-693",
   "nist": "SC-18",
   "match": {
    "header_absent": "permissions-policy"
   }
  },
  {
   "key": "missing-referrer-policy",
   "title": "Missing Referrer-Policy",
   "category": "headers",
   "severity": "low",
   "confidence": "confirmed",
   "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
   "refs": [
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
   ],
   "cwe": "CWE-200",
   "nist": "SC-18",
   "match": {
    "header_absent": "referrer-policy"
   }
  },
  {
   "key": "missing-x-content-type-options",
   "title": "Missing X-Content-Type-Options",
   "category": "headers",
   "severity": "low",
   "confidence": "confirmed",
   "remediation": "Add: X-Content-Type-Options: nosniff",
   "refs": [
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
   ],
   "cwe": "CWE-693",
   "nist": "SC-18",
   "match": {
    "header_absent": "x-content-type-options"
   }
  },
  {
   "key": "missing-x-frame-options",
   "title": "Missing X-Frame-Options / frame-ancestors",
   "category": "headers",
   "severity": "medium",
   "confidence": "confirmed",
   "remediation": "Add: X-Frame-Options: DENY  (or CSP frame-ancestors 'none').",
   "refs": [
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
   ],
   "cwe": "CWE-1021",
   "nist": "SC-18",
   "match": {
    "header_absent": "x-frame-options"
   }
  },
  {
   "key": "weak-csp",
   "title": "Weak CSP (unsafe-inline / unsafe-eval)",
   "category": "headers",
   "severity": "low",
   "confidence": "confirmed",
   "remediation": "Refactor to use nonces or hashes instead of unsafe-* directives.",
   "refs": [
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
   ],
   "cwe": "CWE-1021",
   "nist": "SC-18",
   "match": {
    "flag": "csp_weak"
   }
  },
  {
   "key": "weak-hsts-max-age",
   "title": "Weak HSTS max-age",
   "category": "headers",
   "severity": "medium",
   "confidence": "confirmed",
   "remediation": "Set max-age to at least 31536000 (1 year).",
   "refs": [
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
   ],
   "cwe": "CWE-319",
   "nist": "SC-8",
   "match": {
    "flag": "hsts_weak"
   }
  },
  {
   "key": "mixed-content",
   "title": "Mixed Content",
   "category": "html",
   "severity": "medium",
   "confidence": "confirmed",
   "remediation": "Use HTTPS (or protocol-relative) URLs for all page resources.",
   "refs": [
    "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"
   ],
   "cwe": "CWE-319",
   "nist": "SC-8",
   "match": {
    "flag": "mixed_content"
   }
  },
  {
   "key": "password-field-autocomplete",
   "title": "Password Field Autocomplete Enabled",
   "category": "html",
   "severity": "info",
   "confidence": "confirmed",
   "remediation": "Use autocomplete=\"new-password\" or \"current-password\" on password inputs.",
   "refs": [
    "https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/Turning_off_form_autocompletion"
   ],
   "cwe": "CWE-200",
   "nist": "IA-5",
   "match": {
    "flag": "password_autocomplete"
   }
  },
  {
   "key": "post-form-missing-csrf",
   "title": "POST Forms Lack CSRF Token (heuristic)",
   "category": "html",
   "severity": "low",
   "confidence": "confirmed",
   "remediation": "Verify CSRF protection (synchronizer token) is in place for all state-changing forms.",
   "refs": [
    "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
   ],
   "cwe": "CWE-352",
   "nist": "SC-8",
   "match": {
    "flag": "csrf_missing"
   }
  },
  {
   "key": "command-injection",
   "title": "OS Command Injection",
   "category": "injection",
   "severity": "critical",
   "confidence": "confirmed",
   "remediation": "Never pass user input to a shell; call library APIs directly and apply strict input validation with an allowlist.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/78.html",
    "https://attack.mitre.org/techniques/T1059/",
    "https://owasp.org/www-community/attacks/Command_Injection"
   ],
   "cwe": "CWE-78",
   "attack": "T1059",
   "nist": "SI-10",
   "match": {
    "facts_any": [
     "web.cmdi_confirmed"
    ]
   }
  },
  {
   "key": "insecure-deserialization",
   "title": "Insecure Deserialization of Untrusted Data",
   "category": "injection",
   "severity": "critical",
   "confidence": "confirmed",
   "remediation": "Never deserialize untrusted data; if unavoidable, sign and verify serialized blobs and keep gadget-chain libraries patched.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/502.html",
    "https://attack.mitre.org/techniques/T1190/",
    "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"
   ],
   "cwe": "CWE-502",
   "attack": "T1190",
   "nist": "SI-10",
   "match": {
    "facts_any": [
     "web.deserial_confirmed"
    ]
   }
  },
  {
   "key": "nosql-injection",
   "title": "NoSQL Injection",
   "category": "injection",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Type-check and sanitize query operators, reject object-typed inputs where scalars are expected, and enforce schema validation at the ODM layer.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/943.html",
    "https://attack.mitre.org/techniques/T1190/",
    "https://owasp.org/www-community/Injection_Flaws"
   ],
   "cwe": "CWE-943",
   "attack": "T1190",
   "nist": "SI-10",
   "match": {
    "facts_any": [
     "web.nosqli_confirmed"
    ]
   }
  },
  {
   "key": "server-side-template-injection",
   "title": "Server-Side Template Injection (SSTI)",
   "category": "injection",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Never render user-controlled input as template source; pass user data only as bound variables and sandbox the template engine.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/1336.html",
    "https://attack.mitre.org/techniques/T1190/",
    "https://portswigger.net/web-security/server-side-template-injection"
   ],
   "cwe": "CWE-1336",
   "attack": "T1190",
   "nist": "SI-10",
   "match": {
    "facts_any": [
     "web.ssti_confirmed"
    ]
   }
  },
  {
   "key": "sql-injection",
   "title": "SQL Injection",
   "category": "injection",
   "severity": "critical",
   "confidence": "confirmed",
   "remediation": "Use parameterized queries / prepared statements everywhere; run the database with a least-privilege account; deploy a WAF only as a compensating control, not the fix.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/89.html",
    "https://attack.mitre.org/techniques/T1190/",
    "https://owasp.org/Top10/A03_2021-Injection/"
   ],
   "cwe": "CWE-89",
   "attack": "T1190",
   "nist": "SI-10",
   "match": {
    "facts_any": [
     "web.sqli_confirmed"
    ]
   }
  },
  {
   "key": "xml-external-entity",
   "title": "XML External Entity (XXE) Injection",
   "category": "injection",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Disable DTD processing and external entity resolution in every XML parser; prefer less complex data formats such as JSON where possible.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/611.html",
    "https://attack.mitre.org/techniques/T1190/",
    "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"
   ],
   "cwe": "CWE-611",
   "attack": "T1190",
   "nist": "SI-10",
   "match": {
    "facts_any": [
     "web.xxe_confirmed"
    ]
   }
  },
  {
   "key": "risky-http-methods",
   "title": "Risky HTTP Methods Enabled",
   "category": "methods",
   "severity": "medium",
   "confidence": "confirmed",
   "remediation": "Disable TRACE, PUT, DELETE, CONNECT at the web-server/app level unless required.",
   "refs": [
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"
   ],
   "cwe": "CWE-650",
   "nist": "AC-3",
   "match": {
    "flag": "http_methods_risky"
   }
  },
  {
   "key": "dll-hijacking",
   "title": "DLL Search-Order Hijacking",
   "category": "privesc",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Remove writable directories from PATH and application folders, enable SafeDllSearchMode, and sign and audit DLL loads.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/427.html",
    "https://attack.mitre.org/techniques/T1574/001/",
    "https://attack.mitre.org/techniques/T1574/001/"
   ],
   "cwe": "CWE-427",
   "attack": "T1574.001",
   "nist": "SI-7",
   "match": {
    "facts_any": [
     "privesc.dll_hijack_candidate"
    ]
   }
  },
  {
   "key": "custom-service-buffer-overflow",
   "title": "Custom Service Stack Buffer Overflow",
   "category": "privesc",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Rebuild the service with stack canaries, ASLR/DEP, and safe string handling (bounds-checked copies); treat all network input as untrusted and fuzz it.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/121.html",
    "https://attack.mitre.org/techniques/T1203/",
    "https://owasp.org/www-community/vulnerabilities/Buffer_Overflow"
   ],
   "cwe": "CWE-121",
   "attack": "T1203",
   "nist": "SI-16",
   "match": {
    "facts_any": [
     "privesc.service_bof_candidate"
    ]
   }
  },
  {
   "key": "weak-password-hashing",
   "title": "Weak / Unsalted Password Hashing",
   "category": "crypto",
   "severity": "medium",
   "confidence": "confirmed",
   "remediation": "Store passwords with a slow, salted algorithm (bcrypt, scrypt, or Argon2id) with a per-user salt; never MD5/SHA1/plain SHA-256 or an unsalted digest.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/916.html",
    "https://cwe.mitre.org/data/definitions/759.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"
   ],
   "cwe": "CWE-916",
   "attack": "T1552",
   "nist": "IA-5",
   "match": {
    "facts_any": [
     "credential.weak_hash"
    ]
   }
  },
  {
   "key": "linux-capabilities",
   "title": "Dangerous Linux Capability",
   "category": "privesc",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Remove unneeded file capabilities (setcap -r); never grant cap_setuid/cap_dac_override/cap_sys_admin to general-purpose binaries — they are root-equivalent.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/250.html",
    "https://attack.mitre.org/techniques/T1548/",
    "https://gtfobins.github.io/#+capabilities"
   ],
   "cwe": "CWE-250",
   "attack": "T1548",
   "nist": "AC-6",
   "match": {
    "facts_any": [
     "privesc.capability"
    ]
   }
  },
  {
   "key": "writable-cron-job",
   "title": "Writable Scheduled Task / Cron Job",
   "category": "privesc",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Make cron scripts and their directories writable only by root; run scheduled tasks as least-privilege service accounts and audit their paths.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/732.html",
    "https://attack.mitre.org/techniques/T1053/003/",
    "https://cwe.mitre.org/data/definitions/276.html"
   ],
   "cwe": "CWE-732",
   "attack": "T1053.003",
   "nist": "AC-6",
   "match": {
    "facts_any": [
     "privesc.cron_writable"
    ]
   }
  },
  {
   "key": "credentials-in-process-list",
   "title": "Credentials Exposed in Process Arguments",
   "category": "privesc",
   "severity": "medium",
   "confidence": "confirmed",
   "remediation": "Never pass secrets on the command line (they are world-readable in /proc and ps); use environment files with restricted perms, stdin, or a secrets manager.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/214.html",
    "https://attack.mitre.org/techniques/T1057/",
    "https://cwe.mitre.org/data/definitions/522.html"
   ],
   "cwe": "CWE-214",
   "attack": "T1057",
   "nist": "IA-5",
   "match": {
    "facts_any": [
     "privesc.process_lead"
    ]
   }
  },
  {
   "key": "stored-windows-credentials",
   "title": "Stored Windows Credentials",
   "category": "privesc",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Remove autologon/DefaultPassword registry values, clear cmdkey/Credential Manager entries, and scrub unattend.xml/sysprep answer files of plaintext or reversible passwords.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/522.html",
    "https://attack.mitre.org/techniques/T1555/",
    "https://attack.mitre.org/techniques/T1552/001/"
   ],
   "cwe": "CWE-522",
   "attack": "T1555",
   "nist": "IA-5",
   "match": {
    "facts_any": [
     "privesc.stored_credentials"
    ]
   }
  },
  {
   "key": "always-install-elevated",
   "title": "AlwaysInstallElevated Enabled",
   "category": "privesc",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Disable the AlwaysInstallElevated policy in both HKLM and HKCU; it lets any user install an MSI as SYSTEM.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/269.html",
    "https://attack.mitre.org/techniques/T1548/002/",
    "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/always-install-with-elevated-privileges"
   ],
   "cwe": "CWE-269",
   "attack": "T1548.002",
   "nist": "AC-6",
   "match": {
    "facts_any": [
     "privesc.always_install_elevated"
    ]
   }
  },
  {
   "key": "missing-security-patches",
   "title": "Missing Security Patches (Privilege Escalation)",
   "category": "privesc",
   "severity": "high",
   "confidence": "candidate",
   "remediation": "Apply the outstanding OS security updates; a missing kernel/OS patch matched to a public local exploit is a direct privilege-escalation path.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/1104.html",
    "https://attack.mitre.org/techniques/T1068/",
    "https://cwe.mitre.org/data/definitions/1352.html"
   ],
   "cwe": "CWE-1104",
   "attack": "T1068",
   "nist": "SI-2",
   "match": {
    "facts_any": [
     "privesc.patch_gap"
    ]
   }
  },
  {
   "key": "docker-group-escape",
   "title": "Docker/LXD Group Root-Equivalence",
   "category": "privesc",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Remove users from the docker and lxd groups (they are root-equivalent), use rootless Docker, and never mount the host root filesystem into containers.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/250.html",
    "https://attack.mitre.org/techniques/T1611/",
    "https://attack.mitre.org/techniques/T1611/"
   ],
   "cwe": "CWE-250",
   "attack": "T1611",
   "nist": "AC-6",
   "match": {
    "facts_any": [
     "privesc.docker_group",
     "privesc.lxd_group"
    ]
   }
  },
  {
   "key": "nfs-no-root-squash",
   "title": "NFS Export with no_root_squash",
   "category": "privesc",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Enable root_squash (the default), restrict exports by IP, and require authentication via NFSv4 with Kerberos.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/732.html",
    "https://attack.mitre.org/techniques/T1548/",
    "https://cwe.mitre.org/data/definitions/732.html"
   ],
   "cwe": "CWE-732",
   "attack": "T1548",
   "nist": "AC-6",
   "match": {
    "facts_any": [
     "privesc.nfs_no_root_squash"
    ]
   }
  },
  {
   "key": "seimpersonate-potato",
   "title": "SeImpersonatePrivilege Abuse (Potato attacks)",
   "category": "privesc",
   "severity": "high",
   "confidence": "candidate",
   "remediation": "Remove SeImpersonatePrivilege from service accounts where possible, apply DCOM/RPC hardening patches, and disable the Print Spooler on servers that do not print.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/269.html",
    "https://attack.mitre.org/techniques/T1134/001/",
    "https://attack.mitre.org/techniques/T1134/001/"
   ],
   "cwe": "CWE-269",
   "attack": "T1134.001",
   "nist": "AC-6",
   "match": {
    "facts_any": [
     "privesc.windows_privilege"
    ]
   }
  },
  {
   "key": "sudo-misconfiguration",
   "title": "Sudo Misconfiguration",
   "category": "privesc",
   "severity": "high",
   "confidence": "candidate",
   "remediation": "Apply least-privilege sudoers rules, avoid NOPASSWD, and never grant sudo on GTFOBins-exploitable binaries.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/250.html",
    "https://attack.mitre.org/techniques/T1548/003/",
    "https://attack.mitre.org/techniques/T1548/003/"
   ],
   "cwe": "CWE-250",
   "attack": "T1548.003",
   "nist": "AC-6",
   "match": {
    "facts_any": [
     "privesc.sudo_rights",
     "privesc.sudo_binary"
    ]
   }
  },
  {
   "key": "suid-sgid-abuse",
   "title": "Dangerous SUID/SGID Binaries",
   "category": "privesc",
   "severity": "high",
   "confidence": "candidate",
   "remediation": "Remove unnecessary SUID/SGID bits and audit remaining setuid binaries against the GTFOBins list.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/250.html",
    "https://attack.mitre.org/techniques/T1548/001/",
    "https://attack.mitre.org/techniques/T1548/001/"
   ],
   "cwe": "CWE-250",
   "attack": "T1548.001",
   "nist": "AC-6",
   "match": {
    "facts_any": [
     "privesc.suid_candidate"
    ]
   }
  },
  {
   "key": "unquoted-service-path",
   "title": "Unquoted Service Path",
   "category": "privesc",
   "severity": "medium",
   "confidence": "candidate",
   "remediation": "Quote all service ImagePath values and audit for writable directories along service executable paths.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/428.html",
    "https://attack.mitre.org/techniques/T1574/009/",
    "https://attack.mitre.org/techniques/T1574/009/"
   ],
   "cwe": "CWE-428",
   "attack": "T1574.009",
   "nist": "AC-6",
   "match": {
    "facts_any": [
     "privesc.unquoted_service_path"
    ]
   }
  },
  {
   "key": "weak-service-permissions",
   "title": "Weak Windows Service Permissions",
   "category": "privesc",
   "severity": "high",
   "confidence": "candidate",
   "remediation": "Restrict service binaries and configuration so they are writable only by SYSTEM/Administrators, and audit with accesschk.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/732.html",
    "https://attack.mitre.org/techniques/T1574/010/",
    "https://attack.mitre.org/techniques/T1574/010/"
   ],
   "cwe": "CWE-732",
   "attack": "T1574.010",
   "nist": "AC-6",
   "match": {
    "facts_any": [
     "privesc.weak_service_permission"
    ]
   }
  },
  {
   "key": "writable-etc-passwd",
   "title": "World-Writable /etc/passwd or Sensitive File",
   "category": "privesc",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Restore /etc/passwd to root:root 0644, investigate how it became writable (usually a deeper misconfiguration), and audit permissions on other sensitive files.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/732.html",
    "https://attack.mitre.org/techniques/T1098/",
    "https://cwe.mitre.org/data/definitions/732.html"
   ],
   "cwe": "CWE-732",
   "attack": "T1098",
   "nist": "AC-6",
   "match": {
    "facts_any": [
     "privesc.passwd_writable"
    ]
   }
  },
  {
   "key": "http-redirect-not-https",
   "title": "HTTP Redirect Not to HTTPS",
   "category": "tls",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Redirect all HTTP traffic to the https:// counterpart.",
   "refs": [
    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"
   ],
   "cwe": "CWE-319",
   "nist": "SC-8",
   "match": {
    "flag": "http_no_redirect"
   }
  },
  {
   "key": "http-serves-content",
   "title": "HTTP Listener Serves Content",
   "category": "tls",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Force-redirect all HTTP requests to HTTPS, or disable port 80.",
   "refs": [
    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"
   ],
   "cwe": "CWE-319",
   "nist": "SC-8",
   "match": {
    "flag": "http_serves_content"
   }
  },
  {
   "key": "tls-cert-expired",
   "title": "TLS Certificate Expired",
   "category": "tls",
   "severity": "critical",
   "confidence": "confirmed",
   "remediation": "Renew the TLS certificate immediately.",
   "refs": [
    "https://letsencrypt.org/"
   ],
   "cwe": "CWE-295",
   "nist": "SC-8",
   "match": {
    "flag": "tls_expired"
   }
  },
  {
   "key": "tls-cert-expiring-soon",
   "title": "TLS Certificate Expiring Soon",
   "category": "tls",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Renew the TLS certificate before it expires; automate renewal (e.g. certbot).",
   "refs": [
    "https://letsencrypt.org/"
   ],
   "cwe": "CWE-295",
   "nist": "SC-8",
   "match": {
    "flag": "tls_expiring"
   }
  },
  {
   "key": "tls-cert-validation-failed",
   "title": "TLS Certificate Validation Failed",
   "category": "tls",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Ensure the certificate chain is complete and the hostname matches the SAN/CN.",
   "refs": [
    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"
   ],
   "cwe": "CWE-295",
   "nist": "SC-8",
   "match": {
    "flag": "tls_validation_failed"
   }
  },
  {
   "key": "tls-outdated-protocol",
   "title": "Outdated TLS Protocol",
   "category": "tls",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Disable TLS 1.0/1.1 and SSLv2/v3. Require TLS 1.2+ (preferably 1.3).",
   "refs": [
    "https://datatracker.ietf.org/doc/rfc8996/"
   ],
   "cwe": "CWE-326",
   "nist": "SC-8",
   "match": {
    "flag": "tls_outdated"
   }
  },
  {
   "key": "tls-self-signed",
   "title": "Self-Signed Certificate",
   "category": "tls",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Use a certificate signed by a trusted CA (e.g. Let's Encrypt).",
   "refs": [
    "https://letsencrypt.org/docs/"
   ],
   "cwe": "CWE-295",
   "nist": "SC-8",
   "match": {
    "flag": "tls_self_signed"
   }
  },
  {
   "key": "cross-site-scripting",
   "title": "Cross-Site Scripting (XSS)",
   "category": "web",
   "severity": "medium",
   "confidence": "confirmed",
   "remediation": "Apply context-aware output encoding, deploy a strict Content Security Policy, and set HttpOnly and Secure flags on session cookies.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/79.html",
    "https://attack.mitre.org/techniques/T1190/",
    "https://owasp.org/www-community/attacks/xss/"
   ],
   "cwe": "CWE-79",
   "attack": "T1190",
   "nist": "SI-10",
   "match": {
    "facts_any": [
     "web.xss_confirmed"
    ]
   }
  },
  {
   "key": "jwt-signature-bypass",
   "title": "JWT Signature / Algorithm Confusion Abuse",
   "category": "web",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Pin the expected signing algorithm and reject alg:none, use a strong secret or asymmetric key, and validate exp/aud/iss on every token.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/347.html",
    "https://attack.mitre.org/techniques/T1190/",
    "https://portswigger.net/web-security/jwt"
   ],
   "cwe": "CWE-347",
   "attack": "T1190",
   "nist": "IA-2",
   "match": {
    "facts_any": [
     "web.jwt_secret",
     "web.authz_bypass"
    ]
   }
  },
  {
   "key": "lfi-to-rce",
   "title": "Local File Inclusion Escalated to RCE",
   "category": "web",
   "severity": "critical",
   "confidence": "confirmed",
   "remediation": "Fix the underlying LFI, disable dangerous PHP wrappers (php://, data://, expect://), and keep logs and the web root unwritable by the application user.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/98.html",
    "https://attack.mitre.org/techniques/T1190/",
    "https://owasp.org/www-community/attacks/Path_Traversal"
   ],
   "cwe": "CWE-98",
   "attack": "T1190",
   "nist": "SI-10"
  },
  {
   "key": "local-file-inclusion",
   "title": "Local File Inclusion / Path Traversal",
   "category": "web",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Never include user-controlled paths; use an allowlist of permitted files and disable dangerous stream wrappers.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/22.html",
    "https://attack.mitre.org/techniques/T1190/",
    "https://owasp.org/www-community/attacks/Path_Traversal"
   ],
   "cwe": "CWE-22",
   "attack": "T1190",
   "nist": "SI-10",
   "match": {
    "facts_any": [
     "web.lfi_confirmed"
    ]
   }
  },
  {
   "key": "server-side-request-forgery",
   "title": "Server-Side Request Forgery (SSRF)",
   "category": "web",
   "severity": "high",
   "confidence": "confirmed",
   "remediation": "Allowlist permitted outbound destinations, block link-local and cloud-metadata IP ranges (169.254.169.254), and require authentication on internal services.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/918.html",
    "https://attack.mitre.org/techniques/T1190/",
    "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"
   ],
   "cwe": "CWE-918",
   "attack": "T1190",
   "nist": "SC-7",
   "match": {
    "facts_any": [
     "web.ssrf_confirmed"
    ]
   }
  },
  {
   "key": "unrestricted-file-upload",
   "title": "Unrestricted File Upload",
   "category": "web",
   "severity": "critical",
   "confidence": "confirmed",
   "remediation": "Allowlist extensions and validate MIME/content, store uploads outside the web root, and disable script execution in upload directories.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/434.html",
    "https://attack.mitre.org/techniques/T1505/003/",
    "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"
   ],
   "cwe": "CWE-434",
   "attack": "T1505.003",
   "nist": "SI-10",
   "match": {
    "facts_any": [
     "web.upload_confirmed"
    ]
   }
  },
  {
   "key": "anonymous-ldap-bind",
   "title": "Anonymous LDAP Bind / Domain Enumeration",
   "category": "access",
   "severity": "medium",
   "confidence": "confirmed",
   "remediation": "Disable anonymous LDAP binds on the domain controllers and require authenticated, least-privilege access for directory queries; monitor for anonymous enumeration.",
   "refs": [
    "https://cwe.mitre.org/data/definitions/306.html",
    "https://attack.mitre.org/techniques/T1087/002/",
    "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/anonymous-ldap-operations-active-directory-disabled"
   ],
   "cwe": "CWE-306",
   "attack": "T1087.002",
   "nist": "AC-3",
   "match": {
    "facts_any": [
     "ad.anonymous_bind"
    ]
   }
  },
  {
   "key": "smbv1-enabled",
   "title": "Legacy SMBv1 Protocol Enabled",
   "category": "config",
   "severity": "medium",
   "confidence": "confirmed",
   "remediation": "Disable the SMBv1 protocol on all hosts and require SMBv2/3 with signing; SMBv1 is deprecated and exposes the host to well-known remote code-execution families (e.g. EternalBlue).",
   "refs": [
    "https://cwe.mitre.org/data/definitions/477.html",
    "https://attack.mitre.org/techniques/T1210/",
    "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"
   ],
   "cwe": "CWE-477",
   "attack": "T1210",
   "nist": "CM-7",
   "match": {
    "fact_value": {
     "kind": "smb.smbv1",
     "field": "enabled",
     "equals": true
    }
   }
  }
 ];})(typeof globalThis!=='undefined'?globalThis:this);
