# Per-move gate audit (bidirectional)

Every move in `data/packs/*.json` reviewed by hand for **gate correctness in both directions**:

- **→ over-surface** (shows when it shouldn't): is the gate loose enough that the move can headline with no
  real reason to run it?
- **← under-surface** (fails to show when it should): is the gate so tight or mis-named that the move stays
  hidden in a state where the operator genuinely needs it?

For each move the reviewer read its `hypothesis`, `requires_all`, `requires_any`, `produces`, `locus`, and
leading command, then judged the gate against the real-world trigger the technique has. Verdict legend:

- `OK` — gate matches the trigger in both directions.
- `OK*` — defensible, with a noted nuance (usually an intentionally-capped speculative move).
- `FIX` — a real gate fault; the fix (and its commit) is noted inline.

The mechanical backstops (`tools/gate-audit.js`, `tools/move-lint.js`, `tools/gap-report.js`, the corpus)
enforce the structural half; this document is the human judgment half. Re-run the wiring with
`node tools/gate-audit.js`.

---
## recon (30)

Entry-point service probes. Gate pattern: `port:<svc>` / `<svc>.reachable` → the probe for that service.
Reviewed each for a looser-than-warranted gate (none: a service probe keyed to its own port is correct) and
for a too-tight gate (none: each lists every relevant port plus the `*.reachable` alias).

| move | should trigger on | gate | verdict |
|---|---|---|---|
| recon-smb-anon | SMB open | smb.reachable/445/139 | OK |
| recon-web-triage | HTTP open | http.reachable/80/443/8080/8000/8443 | OK |
| recon-dns | DNS open | dns.reachable/53 | OK |
| recon-snmp | SNMP/UDP open | snmp.reachable/161/scan.nmap.udp | OK |
| recon-ike-vpn | IKE/500 | port:500 | OK |
| recon-finger | finger/79 | port:79 | OK |
| recon-vnc | VNC/590x | port:5900/5901/5800 | OK* produces nothing (leaf auth-mode check; a no-auth VNC is pursued by hand — no graph hand-off, not a gate fault) |
| recon-smtp | SMTP/25/587/465 | those ports | OK |
| recon-ftp | FTP open | ftp.reachable/21 | OK |
| recon-mail | POP3/IMAP | 110/143/993/995 | OK* leaf check, no hand-off |
| rdp-enum | RDP/3389 | rdp.reachable/3389 | OK* validation/leaf; creds flow to lateral-exec, not an RDP-specific foothold |
| nfs-enum | NFS/2049 | port:2049 | OK* leaf; nfs-squash reaches privesc straight off port:2049 |
| recon-telnet | telnet/23 | port:23 | OK* leaf |
| recon-rservices | r-services 512-514 | those ports | OK* leaf |
| recon-rsync | rsync/873 | port:873 | OK (SEQ) |
| recon-tftp | TFTP/69 | port:69 | OK (SEQ) |
| recon-x11 | X11/6000 | port:6000 | OK |
| ftp-upload-webshell | writable FTP == webroot | port:21 | OK* pure speculation (no writable-ftp fact to gate on); capped by ranker |
| ssh-user-enum | SSH <7.7 | port:22/ssh.reachable | OK (SEQ) |
| smtp-open-relay | SMTP | 25/587/465 | OK (SEQ) |
| ftp-bounce | FTP PORT | port:21/ftp.reachable | OK (SEQ) |
| vsftpd-backdoor | vsftpd 2.3.4 | port:21 OR vuln.vsftpd_234 | OK* intended offer-at-port/promote-on-fingerprint |
| proftpd-modcopy | ProFTPD 1.3.5 | port:21 OR vuln.proftpd_modcopy | OK* same |
| samba-usermap | Samba 3.0.20-25 | 445/139 OR vuln.samba_usermap | OK* same |
| smbghost | SMBv3.1.1 Win10 1903/09 | port:445 OR vuln.smbghost | OK* same |
| bluekeep | RDP Win7/2008R2 | port:3389 OR vuln.bluekeep | OK* same |
| freeswitch-esl | FreeSWITCH 8021 | port:8021 OR vuln.freeswitch | OK* same |
| jdwp-debug | JDWP | 8000/8787/5005 OR vuln.jdwp | OK* same |
| aerospike-udf | Aerospike <=5.1 | port:3000 OR vuln.aerospike | OK* same |
| wifi-mouse-rce | WiFi Mouse 1978 | port:1978 OR vuln.wifi_mouse | OK* same |

**recon: 30/30 gates correct.** No additions needed — the `vuln.*` fingerprints are minted by the vulnmatch
parser from each exploit move's own version-check (cmd0), so the promote path is wired.

## database (12)

| move | should trigger on | gate | verdict |
|---|---|---|---|
| mysql-login | MySQL open | service.mysql/3306 | OK |
| mysql-loot | a DB session | db.session | OK* title says MySQL but dumping tables is generic; left engine-agnostic |
| mssql-login | MSSQL open | service.ms-sql-s/1433 | OK |
| mssql-xp-cmdshell | MSSQL session w/ sysadmin | db.session **+ (ms-sql-s/1433)** | **FIX** was db.session only → would surface on a Postgres/Oracle session; scoped to MSSQL |
| postgres-login | Postgres open | service.postgresql/5432 | OK |
| redis-enum | Redis | 6379/service.redis | OK |
| mongo-enum | Mongo | 27017/service.mongodb | OK |
| oracle-tns | Oracle TNS | 1521/service.oracle-tns | OK |
| elasticsearch-enum | ES | 9200/service.elasticsearch | OK |
| memcached-enum | memcached | 11211/service.memcached | OK |
| mssql-linked-server | MSSQL session | db.session **+ (ms-sql-s/1433)** | **FIX** was any:[db.session] → wrong-engine surface; scoped to MSSQL |
| mysql-outfile-rce | MySQL session w/ FILE | db.session **+ (mysql/3306)** | **FIX** was any:[db.session] → wrong-engine surface; scoped to MySQL |

Root cause: `db.session` carries its engine in the fact *value*, which gates match on *kind* only — so every
post-session exploit fired on any engine's session. Scoped the three engine-specific exec moves by AND-ing
the originating service/port. (committed)

## credential_access (3)

| move | should trigger on | gate | verdict |
|---|---|---|---|
| responder-poison | on an AD/Win broadcast net | smb.reachable/ad.domain_known/host.domain | OK* passive poisoning, offered on any AD-ish net; capped |
| ntlm-relay-attack | SMB signing not required | smb.signing/smb.reachable | OK* smb.signing is the real lead; smb.reachable keeps it offered speculatively, capped |
| mitm6-ipv6-takeover | AD present | ad.domain_known | OK |

## cracking (11)

| move | should trigger on | gate | verdict |
|---|---|---|---|
| crack-identify | hash-bearing loot in hand | loot.material/credential.candidate/db.tables | OK (dead hash.type option removed earlier) |
| crack-kerberoast | a TGS hash | hash.tgs | OK |
| crack-asrep-offline | an AS-REP hash | hash.asrep | OK |
| crack-ntlm | an NT hash / NTDS | hash.ntlm/loot.ntds | OK |
| crack-netntlmv2 | a NetNTLMv2 capture | credential.netntlm/loot.material | OK |
| crack-shadow | a readable shadow entry | loot.shadow/loot.material | OK |
| crack-archive | a protected archive in loot | loot.material | OK |
| online-brute-ssh | SSH, no cred yet | ssh.reachable | OK* produces none; a recovered login is minted by the hydra parser |
| online-brute-ftp | FTP, no cred yet | ftp.reachable | OK* same |
| online-brute-rdp | RDP, no cred yet | rdp.reachable | OK* same |
| crack-mscache2 | a DCC2 hash | hash.mscache | OK |

## shells (6)

| move | should trigger on | gate | verdict |
|---|---|---|---|
| shell-listener | an exec primitive in hand | web.cmdi_confirmed/foothold.*/exploit.candidate | OK |
| shell-revshell-linux | listener + Linux exec | listener.open/web.cmdi_confirmed | OK |
| shell-revshell-windows | listener + Win exec | listener.open/web.cmdi_confirmed/foothold.windows | OK |
| shell-pty-upgrade | a raw shell | access.shell | OK |
| ssh-key-login | a PEM key + SSH | ssh.reachable + credential.certificate | **FIX** produced nothing → Linux privesc never surfaced after a key login; now produces foothold.linux+access.shell |
| linux-remote-exec | Linux cred + SSH | ssh.reachable + credential.available/certificate/foothold.linux | OK |

**Batch: 4 FIXES** (3 DB engine-scoping over-surface, 1 ssh-key-login under-surface). 50/50 remaining gates OK.

## web (35)

Gate pattern: discovery moves on `http.reachable`/ports; exploit-class moves on a lead
(`web.parameterized`, `web.content_map`, `web.*_confirmed`, `web.upload_form`) or capped-speculative on bare
`http.reachable`. Reviewed each; the speculative web menu is intentional (offered, ranked below evidenced
moves). One effect-honesty fault:

| move | gate | verdict |
|---|---|---|
| vhost-discovery, content-discovery, param-discovery | http/ports/leads | OK |
| lfi-probe, sqli-basics, idor | web.parameterized/web.content_map | OK (lead-gated) |
| manual-sqli-exploitation, sqlmap-automation | web.sqli_confirmed | OK |
| file-upload | web.upload_form/http.reachable | OK* (lead + speculative) |
| git-exposed, svn-exposed, ssrf, ssti, xxe, jwt-attacks, xss-basics, wordpress, nikto-scan, verb-tampering, deserialization, tomcat-deploy | http.reachable (+ web.server/tech) | OK* intentional capped-speculative web menu |
| command-injection | web.parameterized/http.reachable | OK* |
| web-shells | web.upload_confirmed/foothold.webshell/web.lfi_confirmed | OK |
| nosql-injection | http.reachable/vuln.nosqli | **FIX** produced access.admin (a win GOAL) + validated creds from a web auth bypass; its own does_not_prove said "application only". Now produces web.authz_bypass + credential.candidate |
| ajp-ghostcat, java-rmi | service/port | OK* (service-gated) |
| lfi-secret-harvest | web.lfi_confirmed | OK |
| aws-credential-abuse | cloud.credential | OK |
| graphql-abuse, http-request-smuggling, prototype-pollution, mass-assignment | web.content_map/http.reachable | OK* |
| azure-imds, gcp-metadata | web.ssrf_confirmed/cloud.credential | OK (SSRF-gated) |

## web_exploit_checks (13)

All are the intended offer-at-web / promote-on-`vuln.<product>` pattern (SEQ; cmd0 fingerprints the version
→ vulnmatch mints the vuln → the exploit promotes). check-log4shell / check-struts2 are canary checks.
**13/13 OK** (capped-speculative until the fingerprint lands).

## findings_checks (11)

Report/finding checks keyed to the right surface: web checks on http/web indicators, check-subdomain-takeover
on a hostname (host.fqdn/domain/hostname), check-dns-email on a known domain. check-web-components /
check-cms-version carry the documented advisory SELF-SATISFIED nuance (report-only, benign). **11/11 OK.**

**Web batch: 1 FIX (nosql-injection effect honesty). 58/59 gates OK as-authored.**

