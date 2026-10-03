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

  OBOL.ARSENAL = A;
})(typeof globalThis !== 'undefined' ? globalThis : this);
