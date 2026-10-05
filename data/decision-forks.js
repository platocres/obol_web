/*!
 * obol data — decision-forks.js — OBOL.DECISION_FORKS
 *
 * The one-line fork CONDITION per move, for the decision map (see docs/DECISION-MAP.md). The map derives
 * the tree STRUCTURE and the ranked spine from the engine; this file adds only the short, authored
 * sentence that labels the branch point — the observable question whose answer decides where you go:
 *   { '<moveId>': { cond: 'the yes/no the result turns on', onFail: 'what to do if it does not pan out' } }
 * `cond` renders on the node as "does X? → branch"; `onFail` is the authored hint for the "it didn't work"
 * edge (the map already derives the alternatives from alternativesFor, so onFail is just the human nudge).
 * Keep both to one plain sentence. A move with no entry still renders (structure + alternatives are
 * derived) — the lint simply reports it as a fork-condition gap, so coverage is visible and fillable.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  OBOL.DECISION_FORKS = {
    // ---- recon / services ----
    'recon-ftp': { cond: 'Does anonymous login succeed, and is anything readable?', onFail: 'No anonymous access → brute a known user, or move on.' },
    'ftp-upload-webshell': { cond: 'Is the writable FTP directory also the web root (marker round-trips over HTTP)?', onFail: 'No overlap → the write is just loot, not a shell.' },
    'online-brute-ftp': { cond: 'Does any credential pair log in?', onFail: 'No hit → the account/wordlist is wrong; find usernames first.' },
    'recon-telnet': { cond: 'Does the banner name a device, and does a default/reused password log in?', onFail: 'No default works → brute a small list, or treat it as recon only.' },
    'recon-rservices': { cond: 'Does the host trust you for a password-free rlogin/rsh?', onFail: 'No trust → there is nothing to brute; move on.' },
    'recon-rsync': { cond: 'Are any modules listable, and is one writable?', onFail: 'Auth required → try a known credential, else move on.' },
    'recon-tftp': { cond: 'Does a guessed device-config filename come back?', onFail: 'Wrong names → try device-specific paths, or move on.' },
    'recon-x11': { cond: 'Is access control off (any client accepted)?', onFail: 'Cookie required → you cannot drive the display.' },
    'recon-smtp': { cond: 'Does the server confirm usernames (VRFY/EXPN/RCPT)?', onFail: 'Verbs disabled → enumerate users another way.' },
    'recon-mail': { cond: 'Do you hold a mailbox credential to read the inbox?', onFail: 'No credential yet → recover one first.' },
    'recon-dns': { cond: 'Does a zone transfer (AXFR) succeed?', onFail: 'Refused → fall back to record/subdomain enumeration.' },
    'recon-snmp': { cond: 'Does a default community string ("public") read the MIB?', onFail: 'No default → brute community strings, or move on.' },
    'recon-finger': { cond: 'Does the service disclose usernames?', onFail: 'Empty → no spray material here.' },
    'recon-vnc': { cond: 'Is the security type "None" (unauthenticated)?', onFail: 'Password required → crack the short VNC password.' },
    'rdp-enum': { cond: 'Does a held credential actually log in (Pwn3d!)?', onFail: 'No credential logs in → recover or crack one first.' },
    'nfs-enum': { cond: 'Is an export readable, and is no_root_squash set?', onFail: 'Nothing exported to you → move on.' },
    'recon-web-triage': { cond: 'What stack/app is this (so your attacks and wordlists match)?', onFail: 'Boring default page → fuzz for virtual hosts and hidden content.' },
    'oracle-tns': { cond: 'Do you have a SID and a working account?', onFail: 'No SID or no default account → brute harder, or move on.' },
    'elasticsearch-enum': { cond: 'Is the API unauthenticated (indices list)?', onFail: 'Auth required → find a credential; note the version for RCE.' },
    'memcached-enum': { cond: 'Are there cached items worth reading?', onFail: 'Empty cache → nothing to take here.' },
    'ajp-ghostcat': { cond: 'Is the Tomcat version pre-patch, and can you reach a file to include?', onFail: 'Patched → file read only, or nothing.' },
    'java-rmi': { cond: 'Does the registry deserialize attacker objects (rmg: Vulnerable)?', onFail: 'Not vulnerable → enumerate bound methods for another way.' },

    // ---- web ----
    'vhost-discovery': { cond: 'Does a Host value return a differently-sized, real site?', onFail: 'Only the default size → no hidden vhosts; work the main site.' },
    'content-discovery': { cond: 'Did discovery turn up an admin panel, upload, backup, or source?', onFail: 'Nothing interesting → add extensions and a bigger wordlist.' },
    'param-discovery': { cond: 'Is there a hidden parameter that feeds the page?', onFail: 'No parameters → look for a different injectable surface.' },
    'sqli-basics': { cond: 'Does a single quote change the response (error/boolean/timing)?', onFail: 'No reaction → the parameter is not injectable here.' },
    'manual-sqli-exploitation': { cond: 'Can you read data (UNION reflects, or blind oracle responds)?', onFail: 'Locked down → try a different injection type or parameter.' },
    'file-upload': { cond: 'Does a filter bypass land a file that executes?', onFail: 'Every trick rejected → the upload may still feed LFI/XXE instead.' },
    'lfi-probe': { cond: 'Does a traversal payload read a known file?', onFail: 'No traversal → test wrappers, or a different parameter.' },
    'command-injection': { cond: 'Does an injected command run (echo / sleep / callback)?', onFail: 'No execution → the input is sanitised; try another sink.' },
    'ssti': { cond: 'Does a template expression evaluate (e.g. {{7*7}}=49)?', onFail: 'Rendered literally → not template injection.' },
    'web-shells': { cond: 'Does the planted shell return command output?', onFail: 'No execution → the drop point is not served as code.' },
    'tomcat-deploy': { cond: 'Do the manager credentials deploy a WAR?', onFail: 'No manager access → try Ghostcat on 8009, or default creds.' },
    'jenkins-access': { cond: 'Can you reach the script console or a build step?', onFail: 'Locked down → check for the unauth CLI file-read.' },

    // ---- AD / domain ----
    'ad-dc-identify': { cond: 'Is this a DC, and what is the domain name?', onFail: 'Not a DC → treat it as a normal host.' },
    'ad-anon-ldap-enum': { cond: 'Does an anonymous bind list the directory?', onFail: 'Bind refused → you need a credential first.' },
    'ad-user-enum': { cond: 'Can you build a real user list (RID-brute / --users)?', onFail: 'No list → try anonymous SMB/LDAP, or kerbrute.' },
    'asrep-roast': { cond: 'Does any account have pre-auth disabled (roastable)?', onFail: 'None roastable → spray a seasonal password instead.' },
    'kerberoast': { cond: 'Are there service accounts with SPNs to roast?', onFail: 'No SPNs / no creds → get a credential first.' },
    'password-spray': { cond: 'Does one password hit any account (watch lockout)?', onFail: 'No hit → refine the policy-aware password set.' },
    'bloodhound-collect': { cond: 'Did collection return a graph with attack paths?', onFail: 'Collection failed → check creds/DNS and retry a method.' },
    'ad-acl-abuse': { cond: 'Do you hold an ACL edge (GenericAll/WriteDacl) to abuse?', onFail: 'No edge → map more of the graph first.' },
    'adcs-esc': { cond: 'Is a certificate template vulnerable (ESC1-8)?', onFail: 'No vulnerable template → another path to privilege.' },
    'dcsync': { cond: 'Do you hold replication rights (DS-Replication-Get-Changes)?', onFail: 'Not yet → walk an ACL/delegation path to earn them.' },
    'eternalblue': { cond: 'Is the host confirmed MS17-010 vulnerable?', onFail: 'Patched / not vulnerable → do not fire; find another way.' },

    // ---- databases ----
    'mysql-login': { cond: 'Does a credential (or blank root) open a session?', onFail: 'No login → brute, or recover a credential elsewhere.' },
    'mysql-loot': { cond: 'Do the tables hold crackable hashes or reused secrets?', onFail: 'Nothing useful → the DB was a dead end.' },
    'mssql-login': { cond: 'Does sa / a domain account log in?', onFail: 'No login → recover a credential first.' },
    'mssql-xp-cmdshell': { cond: 'Does the account have sysadmin to enable xp_cmdshell?', onFail: 'Not sysadmin → impersonate or chain a linked server.' },
    'postgres-login': { cond: 'Does a default/reused role log in?', onFail: 'No login → brute, or move on.' },
    'redis-enum': { cond: 'Is Redis unauthenticated, and is it writable?', onFail: 'AUTH set → find the password, else read-only at best.' },
    'mongo-enum': { cond: 'Can you list and read databases without auth?', onFail: 'Auth required → recover a credential first.' },

    // ---- creds / cracking ----
    'crack-identify': { cond: 'What hash type is this (so you pick the right mode)?', onFail: 'Unknown format → inspect length/prefix by hand.' },
    'crack-ntlm': { cond: 'Does the NT hash crack to a password in time?', onFail: 'Uncracked → pass the hash instead of cracking it.' },
    'crack-asrep': { cond: 'Does the AS-REP hash crack offline?', onFail: 'Uncracked → spray or roast another account.' },
    'online-brute-ssh': { cond: 'Does any credential pair log in over SSH?', onFail: 'No hit → wrong account; find usernames first.' },
    'online-brute-rdp': { cond: 'Does any credential pair open an RDP session?', onFail: 'No hit → watch for lockout; narrow the list.' },

    // ---- shells / foothold ----
    'shell-listener': { cond: 'Is your listener up and reachable from the target?', onFail: 'No callback → check firewall/port and the reverse-shell one-liner.' },
    'shell-revshell-linux': { cond: 'Did the reverse shell connect back?', onFail: 'No connection → try another shell payload or transport.' },
    'shell-pty-upgrade': { cond: 'Is the shell now a full interactive TTY?', onFail: 'Still raw → try the python/script upgrade, then stty.' },
    'ssh-key-login': { cond: 'Does the recovered private key log in?', onFail: 'Rejected → wrong user, or the key needs a passphrase.' },

    // ---- privesc ----
    'linux-enum': { cond: 'What is the strongest escalation lead (sudo / SUID / cron / caps)?', onFail: 'Nothing obvious → run pspy and hunt writable files.' },
    'windows-enum': { cond: 'What is the strongest lead (token / service / stored cred)?', onFail: 'Nothing obvious → check patch level and AlwaysInstallElevated.' },
    'sudo-abuse': { cond: 'Is there a NOPASSWD / GTFOBins-abusable sudo entry?', onFail: 'No usable sudo → pivot to SUID or cron.' },
    'suid-gtfobins': { cond: 'Is a SUID binary abusable per GTFOBins?', onFail: 'None abusable → watch for a root cron job.' },
    'seimpersonate': { cond: 'Is SeImpersonate/SeAssignPrimaryToken enabled?', onFail: 'Not held → try a service or stored-credential path.' },
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
