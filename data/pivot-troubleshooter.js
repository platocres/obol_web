/*!
 * obol data — pivot-troubleshooter.js — OBOL.PIVOT_SYMPTOMS + OBOL.PIVOT_CHECKLIST
 *
 * The symptom set for the pivot troubleshooter (the calm guided diagnostic that lives off the
 * connectivity panel). Pivoting is where learners lose whole evenings, so this is the README's
 * "calm voice next to you" pointed at a broken tunnel instead of an attack path.
 *
 * It is symptom-first and ND-friendly: you pick what you SEE in plain language ("the agent won't
 * call back"), not the cause. Each symptom hands you a couple of machine-labelled probe commands;
 * you paste the result; OBOL.pivotDoctor (assets/engine/pivotdoctor.js) runs the recognizers below
 * and returns a verdict with the problem line highlighted and a suggested fix.
 *
 * Conservative, like every other parser in obol: a recognizer only fires on output that actually
 * supports the diagnosis (anchored on real tool tokens), and when nothing matches the doctor says so
 * and hands over the general checklist rather than guessing. These are DIAGNOSTIC findings for the
 * UI, never minted attack facts, so the proof ledger is untouched.
 *
 * Shape:
 *   { key, symptom, hint, probes:[{where,label,cmd,why}],
 *     diagnoses:[{id, re, notRe?, healthy?, verdict, fix?}] }   // first match (re and NOT notRe) wins;
 *                                                                // {{tokens}} fill at render time
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  OBOL.PIVOT_SYMPTOMS = [
    { key: 'agent-no-callback',
      symptom: "The agent won't call back",
      hint: 'You ran the agent (ligolo) or client (chisel) on the target, but your proxy/server never says it joined.',
      probes: [
        { where: 'host', label: 'Can the target reach your listener port?', cmd: 'nc -vz {{lhost}} 11601',
          why: 'This is the real question. "refused" or "timed out" means the traffic never arrives, so the agent command itself is not the problem.' },
        { where: 'local', label: 'Is your proxy actually listening?', cmd: 'sudo ss -tlnp | grep 11601',
          why: 'If nothing is bound to 11601, the agent has nothing to call back to.' },
      ],
      diagnoses: [
        { id: 'refused', re: 'refused', verdict: 'The target reached your box, but the port is closed: your proxy is not running, or it bound a different port than the agent dials.', fix: 'sudo ./proxy -selfcert   # start it on 11601, then re-run the agent' },
        { id: 'timeout', re: 'timed out|timeout|100% packet loss|No route to host', verdict: 'The target cannot reach your box at all: a firewall or routing is dropping traffic to your listener. The tunnel tool is fine; the path to you is blocked.', fix: '# confirm {{lhost}} is the address the TARGET can reach, and that nothing firewalls 11601 inbound' },
        { id: 'cert', re: 'certificate|x509|tls handshake|bad certificate', verdict: 'The connection reaches the proxy but the self-signed TLS cert is being rejected.', fix: './agent -connect {{lhost}}:11601 -ignore-cert' },
        { id: 'open', re: 'succeeded|Connected to|Agent joined|open$|open\\b', healthy: true, verdict: 'This looks healthy: the connection succeeded. If the session is still unusable, select it in the proxy console.', fix: 'session' },
        { id: 'listening', re: 'LISTEN[^\\n]*11601|0\\.0\\.0\\.0:11601|:::11601', healthy: true, verdict: 'Your proxy IS listening on 11601, so the gap is on the target side: re-check the agent command points at THIS box and this port.', fix: './agent -connect {{lhost}}:11601 -ignore-cert' },
      ] },

    { key: 'no-subnet',
      symptom: "I can't reach the internal subnet",
      hint: 'The tunnel is up (ligolo/sshuttle), but traffic to the hidden network goes nowhere.',
      probes: [
        { where: 'local', label: 'Does a route to the subnet exist, via the tunnel?', cmd: 'ip route get <internal-ip>',
          why: 'Shows which interface Kali will use. It must say "dev ligolo" (or the tun/sshuttle device), not your normal NIC.' },
        { where: 'local', label: 'List the routes pointed at the tunnel', cmd: 'ip route | grep ligolo',
          why: 'Confirms the subnet is actually pointed at the ligolo interface.' },
      ],
      diagnoses: [
        { id: 'via-tun', re: 'dev ligolo|dev tun|dev sshuttle|dev ligolo0', healthy: true, verdict: 'The route is correct: traffic to that host goes through the tunnel. If it still fails, the issue is further in, try the "connection refused" or "everything filtered" symptoms.', fix: 'nmap -sT -Pn <internal-ip>' },
        { id: 'unreachable', re: 'unreachable|Network is unreachable|RTNETLINK', verdict: 'There is no route to that subnet at all. Add one pointing at the tunnel interface.', fix: 'sudo ip route add <internal-cidr> dev ligolo' },
        { id: 'via-nic', re: 'dev (eth|ens|enp|wlan|wlp)', verdict: 'The route goes out your normal interface, not the tunnel: Kali does not know to send this subnet through ligolo yet.', fix: 'sudo ip route add <internal-cidr> dev ligolo' },
      ] },

    { key: 'proxychains-hangs',
      symptom: 'proxychains just hangs',
      hint: 'Every command you wrap in proxychains stalls or times out.',
      probes: [
        { where: 'local', label: 'Which SOCKS proxy is proxychains aimed at?', cmd: 'tail -n3 /etc/proxychains4.conf',
          why: 'The last line is the proxy it uses. A fresh Kali ships it pointing at 9050 (Tor); your chisel/ssh -D tunnel is on 1080.' },
        { where: 'local', label: 'Is anything actually listening on 1080?', cmd: 'ss -tlnp | grep 1080',
          why: 'If nothing is bound, proxychains dials a dead port and waits forever.' },
      ],
      diagnoses: [
        { id: 'tor-default', re: 'socks[45]\\s+127\\.0\\.0\\.1\\s+9050', verdict: 'proxychains is still pointed at 9050, the Tor default it ships with, not your tunnel on 1080. That mismatch is the classic hang.', fix: "echo 'socks5 127.0.0.1 1080' | sudo tee -a /etc/proxychains4.conf" },
        { id: 'listener-up', re: 'LISTEN[^\\n]*1080|127\\.0\\.0\\.1:1080', healthy: true, verdict: 'The SOCKS proxy IS up on 1080. If the config also points at 1080, a remaining hang is usually a SYN scan over SOCKS, see "everything shows filtered".', fix: 'proxychains -q nmap -sT -Pn <internal-ip>' },
        { id: 'conf-1080', re: 'socks[45]\\s+127\\.0\\.0\\.1\\s+1080', verdict: 'The config points at 1080 correctly, so the proxy itself is likely not up: your chisel client or ssh -D session is not running. Re-open the tunnel.', fix: 'ssh -D 1080 -N {{user}}@{{target}}' },
      ] },

    { key: 'all-filtered',
      symptom: 'Everything through the tunnel shows filtered',
      hint: 'Scans run but every port comes back filtered, or the scan never finishes.',
      probes: [
        { where: 'local', label: 'Show the exact scan you ran', cmd: 'history | grep nmap | tail -n1',
          why: 'A SOCKS proxy cannot carry nmap\'s raw-packet SYN scan or its ICMP host-discovery ping. The flags are almost always the cause.' },
      ],
      diagnoses: [
        { id: 'syn', re: '-sS', verdict: 'You are running a SYN scan (-sS, the default as root) through a SOCKS proxy, which cannot carry raw packets, so every port reads filtered. Use a TCP-connect scan.', fix: 'proxychains -q nmap -sT -Pn <internal-ip>' },
        { id: 'no-st', re: 'nmap', notRe: '-sT', verdict: 'This scan is not a TCP-connect scan (-sT). Over a SOCKS proxy only -sT works, because the proxy relays full TCP connections, not raw probes.', fix: 'proxychains -q nmap -sT -Pn <internal-ip>' },
        { id: 'no-pn', re: 'nmap', notRe: '-Pn', verdict: 'Without -Pn, nmap first pings the host; ICMP will not traverse the proxy, so nmap decides the host is down and skips it.', fix: 'proxychains -q nmap -sT -Pn <internal-ip>' },
        { id: 'tcp-ok', re: '-sT', healthy: true, verdict: 'Your flags are right for a SOCKS pivot (-sT -Pn). If ports still read filtered, they are genuinely filtered or the service is down, not a tunnel issue.', fix: 'proxychains -q nmap -sT -Pn -p <ports> <internal-ip>' },
      ] },

    { key: 'refused-through-tunnel',
      symptom: 'Connection refused through the tunnel',
      hint: 'The tunnel reaches the subnet, but a specific service connection is refused or resets.',
      probes: [
        { where: 'local', label: 'Probe just that one service through the tunnel', cmd: 'proxychains -q nc -vz <internal-ip> <port>',
          why: 'Tests one port cleanly. "refused" means you reached the host but that service is not listening; "open" means it works and the fault is in the tool you used.' },
      ],
      diagnoses: [
        { id: 'refused', re: 'refused', verdict: 'You reached the internal host, but that service is not listening on that port. The pivot works; re-check the port (or the host) you are targeting.', fix: 'proxychains -q nmap -sT -Pn <internal-ip>   # re-enumerate the open ports' },
        { id: 'timeout', re: 'timed out|timeout', verdict: 'The probe timed out, so traffic is not actually reaching the host. Re-check the route and SOCKS symptoms before blaming the service.', fix: 'ip route get <internal-ip>' },
        { id: 'open', re: 'succeeded|open$|open\\b', healthy: true, verdict: 'The service is reachable through the tunnel. The refusal was in the specific tool, not the pivot; remember -sT for nmap and that UDP will not traverse SOCKS.', fix: 'proxychains -q nmap -sT -Pn -p <port> <internal-ip>' },
      ] },

    { key: 'tunnel-died',
      symptom: 'It worked, then the tunnel died',
      hint: 'You had reach, then everything started failing again.',
      probes: [
        { where: 'local', label: 'Is the proxy/SOCKS still up?', cmd: 'sudo ss -tlnp | grep -E "11601|1080"',
          why: 'If the listener is gone, the proxy or ssh session dropped and took the tunnel with it.' },
        { where: 'host', label: 'Is the agent still running on the target?', cmd: 'ps aux | grep -E "agent|chisel" | grep -v grep',
          why: 'A killed shell often kills the agent. If it is gone, re-launch it detached so it survives.' },
      ],
      diagnoses: [
        { id: 'alive', re: 'LISTEN|agent -connect|chisel client|\\bagent\\b', healthy: true, verdict: 'The tunnel process still looks alive. A transient drop is often the lab resetting; re-run your last command and it should flow again.', fix: 'proxychains -q nmap -sT -Pn <internal-ip>' },
        { id: 'reset', re: 'reset by peer|broken pipe|Connection closed|session closed', verdict: 'The session that carried the tunnel was reset. Restart the proxy and reconnect the agent, and launch the agent detached so a dropped shell does not take it down.', fix: 'setsid ./agent -connect {{lhost}}:11601 -ignore-cert &' },
      ] },
  ];

  // When no recognizer matches, the doctor stands down to this plain checklist rather than guessing.
  OBOL.PIVOT_CHECKLIST = [
    'On the target: can it reach your box at all? (ping {{lhost}}, or nc -vz {{lhost}} <port>)',
    'On Kali: is your proxy/SOCKS actually listening? (sudo ss -tlnp)',
    'Is {{lhost}} the address the TARGET can reach you on, not a second interface?',
    'For a route tool (ligolo/sshuttle): does "ip route get <internal-ip>" go via the tunnel device?',
    'For a SOCKS tool (chisel/ssh -D): does proxychains point at the right port, and are you using nmap -sT -Pn?',
    'Did the session that holds the tunnel stay alive?',
  ];
})(typeof globalThis !== 'undefined' ? globalThis : this);
