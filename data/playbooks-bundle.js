/*! obol data :: playbooks-bundle.js :: GENERATED. */
(function (root) {
  "use strict";
  var OBOL = root.OBOL = root.OBOL || {};
  OBOL.playbookData = {"ad-recon":{"name":"ad-recon","title":"AD Initial Recon","description":"The opening evidence sweep for a domain-joined target: nmap discovery through anonymous AD enumeration. Each step runs through the same scope-enforced runner and parser as `obol run`.","steps":[{"label":"Fast TCP open-port discovery","action_id":"nmap-fast-open-ports","note":"All TCP ports at a high rate; establishes the live host and open ports."},{"label":"Targeted service and default-script scan","action_id":"nmap-version-scripts","note":"Fingerprints the discovered ports so AD service moves unlock. Runs after step 1 fills the port list."},{"label":"Identify the domain controller and domain","action_id":"ad-dc-identify","note":"NetExec LDAP smoke test: DC candidate, domain name, and base DN."},{"label":"Anonymous LDAP enumeration","action_id":"ad-anon-ldap-enum","note":"Unauthenticated bind for the domain user list."},{"label":"SMB / RID user enumeration","action_id":"ad-user-enum","require_approval":true,"note":"Guest RID brute-force, the noisiest recon step; use when anonymous LDAP is thin."}],"phase":"recon"},"bloodhound-expressway":{"name":"bloodhound-expressway","title":"BloodHound & AD Control Paths","description":"Automated domain graph ingestion, shortest-path calculation to Domain Admins, and ACL modification to compromise domain security.","steps":[{"label":"Ingest Domain Graph with BloodHound","action_id":"bloodhound-collect","note":"Collect domain objects, memberships, sessions, and ACLs via bloodhound-python or SharpHound."},{"label":"Inspect Abusable Control Paths & ACLs","action_id":"bloodyad-acl","note":"Inspect permissions on target objects (GenericAll, WriteDacl, AddMember) identified by graph analysis."},{"label":"Execute DACL Abuse / Group Escalation","action_id":"ad-acl-abuse","require_approval":true,"note":"Add user to privileged group or grant DS-Replication-Get-Changes-All rights to current account."},{"label":"Dump NTDS Credential Database via DCSync","action_id":"dcsync","require_approval":true,"note":"Pull administrator hashes from the DC over DRSUAPI."}],"phase":"escalate"},"domain-persistence":{"name":"domain-persistence","title":"Establish Domain Persistence (defense-in-depth)","description":"Once you own the domain (a krbtgt hash, a replicated NTDS dump, or Domain-Admin rights), lay down SEVERAL INDEPENDENT persistence mechanisms so cleaning up any one does not evict you. Each step is a separate fact-gated pack action producing its own persistence.domain fact and runs through the same scope-enforced runner as `obol run`; unmet steps (e.g. no krbtgt hash yet) are skipped, and every step is approval-gated because it modifies domain infrastructure, obol crafts and runs on approval, never silently. Post-exploitation / OSEP-tier: opt in deliberately (never needed to pass an OSCP exam).","steps":[{"label":"Golden ticket (forge a TGT from the krbtgt key)","action_id":"golden-ticket","require_approval":true,"note":"The krbtgt-key forgery, any user, any group, offline. The broadest persistence; survives every password reset except krbtgt (twice)."},{"label":"Diamond ticket (re-sign a real DC-issued TGT)","action_id":"diamond-ticket","require_approval":true,"note":"Stealthier than golden, modifies a legitimately-issued ticket rather than forging one, so it blends with real Kerberos traffic. Independent of the golden path above."},{"label":"WSUS abuse (push a signed update as SYSTEM)","action_id":"wsus-abuse","require_approval":true,"note":"A patch-infrastructure foothold, independent of Kerberos entirely, so it survives a krbtgt double-reset that kills the ticket mechanisms."},{"label":"DnsAdmins ServerLevelPluginDll (DC SYSTEM via a DLL)","action_id":"dnsadmins-abuse","require_approval":true,"note":"Load a plugin DLL into the DNS service running as SYSTEM on the DC, a separate write-privesc persistence lever, gated on a control path over the DC/DnsAdmins."},{"label":"SID-history injection (cross-forest / hidden DA membership)","action_id":"sid-history-abuse","require_approval":true,"note":"Inject a high-privilege SID into an account you control, persistence that does not depend on holding krbtgt, and reaches across a trust when one exists."}],"phase":"loot"},"kerberos-chain":{"name":"kerberos-chain","title":"Kerberos & Active Directory Attack Chain (GPP to Domain Admin)","description":"The complete Active Directory attack sequence: share exploration, GPP password hunting, Kerberoasting, offline hash cracking, interactive host access, and domain domination.","steps":[{"label":"Identify DC and Domain Architecture","action_id":"ad-dc-identify","note":"NetExec LDAP & SMB discovery: confirm DC candidate, FQDN, and base DN."},{"label":"Browse & Download Accessible SMB Shares","action_id":"smb-share-browse-download","note":"Connect anonymously with smbclient to browse and dump readable shares (Replication, SYSVOL, Backups)."},{"label":"GPP Password Hunting & Decryption","action_id":"gpp-passwords","note":"Grep for cpassword in Groups.xml and decrypt AES ciphertext with gpp-decrypt to recover domain credentials."},{"label":"Capture User Flag via SMB","action_id":"flag-hunt-windows","note":"Directly pull user.txt from Users share using recovered low-priv domain credentials."},{"label":"Kerberoasting (Service Principal Names)","action_id":"kerberoast","note":"Request TGS tickets for accounts with SPNs (using impacket-GetUserSPNs or NetExec); yields $krb5tgs$ hashes."},{"label":"Crack Kerberoast TGS Hashes Offline","action_id":"crack-tgs","note":"Crack TGS tickets using Hashcat mode 13100 (not 18200) or John the Ripper to recover Administrator password."},{"label":"Obtain Interactive Shell on the Target","action_id":"win-interactive-shell","note":"Establish interactive command prompt via impacket-wmiexec (port 135/445) or impacket-psexec (SYSTEM shell)."},{"label":"Capture Root Flag on Host","action_id":"flag-hunt-root-windows","note":"Read proof / root.txt from Administrator's Desktop inside interactive shell session."},{"label":"DCSync Domain Credential Replication","action_id":"dcsync","require_approval":true,"note":"Replicate NTDS hashes using DCSync rights (DS-Replication-Get-Changes-All)."}],"phase":"creds"},"linux-privesc-path":{"name":"linux-privesc-path","title":"Linux Local Privilege Escalation","description":"Identify and exploit Sudo rules, SUID binaries, Linux capabilities, or cron jobs to achieve root access.","steps":[{"label":"Audit Linux Privileges and Environment","action_id":"linux-enum","note":"Inspect id, sudo -l, environment variables, PATH, and local network listeners."},{"label":"Exploit Sudo Privileges via GTFOBins","action_id":"sudo-abuse","note":"Leverage permissible sudo binaries (e.g. vim, less, awk, find) to execute root shell."},{"label":"Exploit SUID Binaries via GTFOBins","action_id":"suid-gtfobins","note":"Locate non-standard SUID executables and execute file-read or root-spawn escapes."},{"label":"Abuse Linux Capabilities","action_id":"capabilities","note":"Inspect getcap -r / for cap_setuid, cap_dac_override, or python/perl capabilities."},{"label":"Capture Root Flag","action_id":"flag-hunt-root-linux","note":"Read /root/root.txt with id (uid=0) and ip addr in the same terminal frame."}],"phase":"escalate"},"prepare-reverse-shell":{"name":"prepare-reverse-shell","title":"Prepare a Reverse Shell","description":"Stand up everything needed to catch a shell: a listener, a Linux and a Windows payload crafted for it, and the PTY-upgrade recipe for once it lands. obol never fires the payload, it crafts and stages; you trigger it. Each step runs through the same scope-enforced runner as `obol run`.","steps":[{"label":"Start a reverse-shell listener","action_id":"shell-listener","note":"Opens the catcher on an operator/callback port; the crafted payloads point back at it."},{"label":"Craft a Linux reverse-shell payload","action_id":"shell-revshell-linux","note":"Renders the one-liner (bash/nc/etc.) targeting the listener, copy it to run on the box; never auto-fired."},{"label":"Craft a Windows reverse-shell payload","action_id":"shell-revshell-windows","note":"The Windows equivalent (PowerShell/nc.exe). Skip the OS you don't need, per-step, operator's choice."},{"label":"Upgrade a dumb shell to a full PTY","action_id":"shell-pty-upgrade","note":"The recipe to turn the caught shell into an interactive TTY (job control, vim, sudo), for after it lands."}],"phase":"access"},"tunnel-and-sweep":{"name":"tunnel-and-sweep","title":"Tunnel and Sweep a New Segment","description":"Stand up a pivot from a proven foothold and enumerate the segment it exposes. Pick ONE tunnel method (the applicable one is ready; the rest skip or wait for approval), then scan an internal host through the proxy. A proven tunnel auto-extends scope to the exposed subnet, the hard gate stays enforced, never bypassed. Each step runs through the one scope-enforced runner.","steps":[{"label":"Pivot: SSH dynamic port-forward (SOCKS)","action_id":"pivot-ssh-dynamic","require_approval":true,"note":"The simplest pivot when you have SSH creds on the foothold, a SOCKS proxy over the SSH session."},{"label":"Pivot: sshuttle transparent tunnel (alternative)","action_id":"pivot-sshuttle","require_approval":true,"note":"A transparent, route-based alternative over SSH, no per-tool proxychains needed."},{"label":"Pivot: Chisel reverse SOCKS (no-SSH alternative)","action_id":"pivot-chisel-socks","require_approval":true,"note":"When there's no SSH: stage chisel and open a reverse SOCKS tunnel back through the listener."},{"label":"Scan an internal host through the proxy","action_id":"pivot-scan-through","note":"Once a tunnel is up (scope auto-extended to the exposed subnet), enumerate a host on the far side."}],"phase":"access"},"web-recon":{"name":"web-recon","title":"Web Initial Recon","description":"The opening evidence sweep for an HTTP target: content discovery, nikto, and virtual-host fuzzing. Unlocks once nmap has proven an HTTP port. Each step runs through the same scope-enforced runner and parser as `obol run`.","steps":[{"label":"Content discovery","action_id":"content-discovery","note":"Fuzz paths for the unlinked surface (admin panels.git, backups, /api), maps discovered content."},{"label":"Nikto scan","action_id":"nikto-scan","note":"Baseline server/app misconfiguration and interesting-file leads (candidates to verify, not confirmed vulns)."},{"label":"Virtual-host discovery","action_id":"vhost-discovery","require_approval":true,"note":"Subdomain/vhost fuzzing, noisier, and needs a known domain (set one with --set domain=example.com if nmap did not reveal it)."}],"phase":"recon"},"web-to-foothold":{"name":"web-to-foothold","title":"Web Application to Initial Foothold","description":"Progress from unauthenticated web service discovery to command execution, reverse shell catch, and interactive PTY stabilization.","steps":[{"label":"Web Surface & Directory Discovery","action_id":"content-discovery","note":"Fuzz web paths and endpoints for unlinked functionality and vulnerable parameters."},{"label":"Probe Local File Inclusion / Traversal","action_id":"lfi-probe","note":"Test path traversal vectors to read sensitive configs or prepare log poisoning."},{"label":"Test File Upload Restrictions","action_id":"file-upload","note":"Bypass extension and MIME filters to upload executable server payloads."},{"label":"Start Reverse Shell Listener","action_id":"shell-listener","note":"Set up netcat or socat listener on Kali machine to catch callback."},{"label":"Upgrade Dumb Shell to Interactive PTY","action_id":"shell-pty-upgrade","note":"Stabilize reverse shell with Python pty, stty raw -echo, and environment variables."},{"label":"Locate and Read User Flag","action_id":"flag-hunt-linux","note":"Prove initial foothold identity and capture user proof flag."}],"phase":"access"},"windows-privesc-path":{"name":"windows-privesc-path","title":"Windows Local Privilege Escalation","description":"Systematic evaluation of Windows local configuration to escalate from unprivileged access to NT AUTHORITY\\SYSTEM.","steps":[{"label":"Audit Host Environment & Privileges","action_id":"windows-enum","note":"Inspect systeminfo, privileges (whoami /priv), installed applications, and patches."},{"label":"Inspect SeImpersonatePrivilege Capability","action_id":"seimpersonate","note":"Verify token impersonation rights and evaluate matching Potato binary variants."},{"label":"Select Compatible Potato Exploit","action_id":"potato-select","note":"Deploy GodPotato or PrintSpoofer based on operating system build version."},{"label":"Inspect Unquoted Service Paths & Weak Service DACLs","action_id":"unquoted-service-path","note":"Identify service executables vulnerable to path hijacking or binary replacement."},{"label":"Capture Root / SYSTEM Flag","action_id":"flag-hunt-root-windows","note":"Capture proof.txt flag in C:\\Users\\Administrator\\Desktop with SYSTEM identity proved in frame."}],"phase":"escalate"}};
  OBOL.PLAYBOOK_NAMES = ["ad-recon","bloodhound-expressway","domain-persistence","kerberos-chain","linux-privesc-path","prepare-reverse-shell","tunnel-and-sweep","web-recon","web-to-foothold","windows-privesc-path"];
  OBOL.CAMPAIGN_TRACKS = {
  "ad-chain": {
    "id": "ad-chain",
    "name": "Active Directory Attack Path",
    "badge": "AD / Kerberos",
    "description": "From unauthenticated domain discovery through Kerberoasting, BloodHound graph analysis, and DCSync Domain Admin compromise.",
    "playbook": "kerberos-chain",
    "phases": [
      {
        "id": "recon",
        "name": "Domain Recon",
        "actions": [
          "ad-dc-identify",
          "ad-anon-ldap-enum",
          "ad-user-enum",
          "powerview-enum",
          "smb-share-browse-download"
        ]
      },
      {
        "id": "harvest",
        "name": "Credential Harvesting",
        "actions": [
          "gpp-passwords",
          "asrep-roast",
          "crack-asrep",
          "kerberoast",
          "crack-tgs",
          "password-spray",
          "flag-hunt-windows"
        ]
      },
      {
        "id": "graph",
        "name": "Graph & ACL Abuse",
        "actions": [
          "bloodhound-collect",
          "ad-path-manual",
          "bloodyad-acl",
          "ad-acl-abuse"
        ]
      },
      {
        "id": "escalate",
        "name": "Domain Escalation (DA)",
        "actions": [
          "win-interactive-shell",
          "dump-secrets",
          "dcsync",
          "own-domain-pth",
          "golden-ticket",
          "flag-hunt-root-windows"
        ]
      }
    ]
  },
  "web-foothold": {
    "id": "web-foothold",
    "name": "Web to Initial Foothold",
    "badge": "Web App",
    "description": "Uncover web attack surfaces, exploit injection or upload flaws, and catch an interactive shell foothold.",
    "playbook": "web-to-foothold",
    "phases": [
      {
        "id": "recon",
        "name": "Surface Mapping",
        "actions": [
          "web-recon",
          "vhost-discovery",
          "content-discovery",
          "nikto-scan",
          "param-discovery"
        ]
      },
      {
        "id": "exploit",
        "name": "Vulnerability Exploitation",
        "actions": [
          "lfi-probe",
          "sqli-basics",
          "file-upload",
          "command-injection",
          "http-put-webshell"
        ]
      },
      {
        "id": "catch",
        "name": "Catcher & Payloads",
        "actions": [
          "shell-listener",
          "shell-revshell-linux",
          "shell-revshell-windows"
        ]
      },
      {
        "id": "stabilize",
        "name": "Shell Stabilization & Flags",
        "actions": [
          "shell-pty-upgrade",
          "flag-hunt-linux",
          "flag-hunt-windows"
        ]
      }
    ]
  },
  "win-privesc": {
    "id": "win-privesc",
    "name": "Windows Privilege Escalation",
    "badge": "Win Local",
    "description": "Progress from low-privileged user to NT AUTHORITY\\SYSTEM via service misconfigurations, tokens, or Potato exploits.",
    "playbook": "windows-privesc-path",
    "phases": [
      {
        "id": "audit",
        "name": "Host Audit & Privs",
        "actions": [
          "windows-enum",
          "stored-credentials",
          "dpapi-secrets"
        ]
      },
      {
        "id": "vectors",
        "name": "Vector Selection",
        "actions": [
          "seimpersonate",
          "potato-select",
          "unquoted-service-path",
          "weak-service-permissions",
          "alwaysinstallelevated"
        ]
      },
      {
        "id": "elevate",
        "name": "System Elevation",
        "actions": [
          "lsass-dump-onbox",
          "windows-patch-exploit",
          "com-hijack"
        ]
      },
      {
        "id": "loot",
        "name": "Root Flag & Proof",
        "actions": [
          "flag-hunt-root-windows"
        ]
      }
    ]
  },
  "linux-privesc": {
    "id": "linux-privesc",
    "name": "Linux Privilege Escalation",
    "badge": "Linux Local",
    "description": "System audit to root compromise using Sudo permissions, SUID binaries, cron jobs, and kernel exploits.",
    "playbook": "linux-privesc-path",
    "phases": [
      {
        "id": "audit",
        "name": "System Enumeration",
        "actions": [
          "linux-enum",
          "pspy-monitor",
          "linux-loot-hunt"
        ]
      },
      {
        "id": "vectors",
        "name": "Privilege Vectors",
        "actions": [
          "sudo-abuse",
          "suid-gtfobins",
          "capabilities",
          "cron-abuse",
          "writable-passwd",
          "wildcard-injection"
        ]
      },
      {
        "id": "elevate",
        "name": "Root Escalation",
        "actions": [
          "linux-path-hijack",
          "linux-ld-preload",
          "polkit-abuse",
          "dirtypipe"
        ]
      },
      {
        "id": "loot",
        "name": "Root Proof Flag",
        "actions": [
          "flag-hunt-root-linux"
        ]
      }
    ]
  },
  "lateral-pivot": {
    "id": "lateral-pivot",
    "name": "Lateral Movement & Pivoting",
    "badge": "Network Pivot",
    "description": "Tunnel through compromised hosts and move laterally across internal segments.",
    "playbook": "tunnel-and-sweep",
    "phases": [
      {
        "id": "tunnel",
        "name": "Tunnel Establishment",
        "actions": [
          "pivot-ssh-dynamic",
          "pivot-sshuttle",
          "pivot-chisel-socks"
        ]
      },
      {
        "id": "discover",
        "name": "Internal Host Discovery",
        "actions": [
          "pivot-scan-through",
          "pivot-enumerate-neighbors",
          "local-linux-routes",
          "local-windows-routes"
        ]
      },
      {
        "id": "move",
        "name": "Lateral Execution",
        "actions": [
          "own-domain-pth",
          "lateral-exec",
          "remote-app-creds",
          "cred-reuse-sweep"
        ]
      }
    ]
  }
};
})(typeof globalThis !== "undefined" ? globalThis : this);
