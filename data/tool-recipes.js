/*!
 * obol data — tool-recipes.js — named field PRESETS for the Tool Builders (the funnel's hero tiles).
 *
 * OBOL.TOOL_RECIPES maps a builder id to a small set of recipes. A recipe is a human-named bundle of
 * field values that pre-fills the builder form for a common job (the "directory brute", the "AS-REP
 * crack"), so a student gets the right command in one tap, then can tune or edit it. Recipes set the
 * METHOD knobs only (wordlist, mode, codes); the shared engagement-binding component supplies the
 * target, URL, and identity, so a recipe stays reusable across engagements.
 *
 * Bidirectional (Option B): picking a recipe writes its values into the form; editing a field after
 * just makes the command "custom". Every `values` key must be a real field id of the builder, and
 * every recipe must compile, both asserted by tests/engine/tool-recipes-smoke.js. Recipes mirror the
 * canonical pack commands (the source of truth); `phase` tags them for the right funnel lane. House
 * style: no em or en dashes.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var WC = '/usr/share/seclists/Discovery/Web-Content/';
  var DNS = '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt';

  OBOL.TOOL_RECIPES = {
    'tb-nmap': [
      { id: 'discover', label: 'Host Discovery', phase: 'recon', hint: 'Ping sweep a range to find live hosts before you touch any ports.',
        values: { profile: 'discover' } },
      { id: 'quick', label: 'Quick Top 1000', phase: 'recon', hint: 'The fast first look: the 1000 most common TCP ports, open ones only.',
        values: { profile: 'quick', portScope: 'top1000', timing: 'T4' } },
      { id: 'allports', label: 'All TCP Ports', phase: 'recon', hint: 'Every one of the 65535 TCP ports at a high rate. Nothing hides.',
        values: { profile: 'full', portScope: 'all', timing: 'T4', minRate: '5000' } },
      { id: 'service', label: 'Service + Scripts', phase: 'recon', hint: 'Version banners and the default NSE scripts on the ports you already found.',
        values: { profile: 'service', version: true, scripts: true } },
      { id: 'udp', label: 'Top UDP', phase: 'recon', hint: 'The common UDP services (DNS, SNMP, TFTP) that a TCP scan never sees.',
        values: { profile: 'udp', portScope: 'top100udp' } },
    ],
    'tb-ffuf': [
      { id: 'dir-common', label: 'Directory Brute', phase: 'enum', hint: 'The default first sweep: common web paths, keep the interesting status codes, auto-calibrated.',
        values: { action: 'content', wordlist: WC + 'common.txt', matchCodes: '200,204,301,302,307,401,403', autoCalibration: true } },
      { id: 'dir-ext', label: 'Files + Extensions', phase: 'enum', hint: 'A deeper directory list that also tries php, txt, html, and bak on every word.',
        values: { action: 'content', wordlist: WC + 'raft-medium-directories.txt', extensions: '.php,.txt,.html,.bak', autoCalibration: true } },
      { id: 'vhost', label: 'Virtual Host Sweep', phase: 'enum', hint: 'Same IP, different site: fuzz the Host header to find hidden vhosts. Set the domain first.',
        values: { action: 'vhost', wordlist: DNS, filterSize: '0' } },
      { id: 'api', label: 'API Endpoints', phase: 'enum', hint: 'Hunt REST and API routes specifically.',
        values: { action: 'content', wordlist: WC + 'api/api-endpoints.txt', matchCodes: '200,201,401,403,405', autoCalibration: true } },
    ],
    'tb-gobuster-ferox': [
      { id: 'gobuster-dir', label: 'Gobuster Directories', phase: 'enum', hint: 'Classic directory and file discovery with common extensions.',
        values: { engine: 'gobuster', gobusterMode: 'dir', wordlist: WC + 'raft-medium-directories.txt', extensions: 'php,txt,html,bak' } },
      { id: 'ferox-recurse', label: 'Feroxbuster (recursive)', phase: 'enum', hint: 'Feroxbuster dives into each folder it finds automatically. Great for deep trees.',
        values: { engine: 'feroxbuster', wordlist: WC + 'raft-medium-directories.txt', extensions: 'php,txt,html', recursion: true, depth: '2' } },
      { id: 'gobuster-vhost', label: 'Gobuster VHosts', phase: 'enum', hint: 'Virtual-host discovery: same IP, different Host header.',
        values: { engine: 'gobuster', gobusterMode: 'vhost', wordlist: DNS } },
      { id: 'gobuster-dns', label: 'Gobuster Subdomains', phase: 'recon', hint: 'DNS subdomain discovery. No web server needed, just a domain.',
        values: { engine: 'gobuster', gobusterMode: 'dns', wordlist: DNS } },
    ],
    'tb-wfuzz': [
      { id: 'path', label: 'Path Discovery', phase: 'enum', hint: 'Fuzz the URL path, hide the 404 background.',
        values: { action: 'path', mode: 'path', wordlist: '/usr/share/wordlists/dirb/common.txt', hideCodes: '404' } },
      { id: 'vhost', label: 'Virtual Host Sweep', phase: 'enum', hint: 'Fuzz the Host header; hide the baseline response size so only real vhosts show.',
        values: { action: 'custom', mode: 'custom', header: 'Host: FUZZ.target.local', hideChars: '0' } },
    ],
    'tb-hashcat': [
      { id: 'ntlm', label: 'NTLM', phase: 'cracking', hint: 'Plain Windows NT hashes (mode 1000) against rockyou.',
        values: { mode: '1000', attack: 'straight', wordlist: '/usr/share/wordlists/rockyou.txt' } },
      { id: 'ntlm-rules', label: 'NTLM + Rules', phase: 'cracking', hint: 'NTLM with best64 mangling rules when a plain wordlist stalls.',
        values: { mode: '1000', attack: 'straight', wordlist: '/usr/share/wordlists/rockyou.txt', rule: '/usr/share/hashcat/rules/best64.rule' } },
      { id: 'asrep', label: 'AS-REP Roast', phase: 'cracking', hint: 'Kerberos AS-REP hashes from pre-auth-disabled accounts (mode 18200).',
        values: { mode: '18200', attack: 'straight', wordlist: '/usr/share/wordlists/rockyou.txt' } },
      { id: 'kerberoast', label: 'Kerberoast', phase: 'cracking', hint: 'Kerberos TGS service-ticket hashes (mode 13100).',
        values: { mode: '13100', attack: 'straight', wordlist: '/usr/share/wordlists/rockyou.txt' } },
      { id: 'netntlmv2', label: 'NetNTLMv2', phase: 'cracking', hint: 'Captured responder / relay hashes (mode 5600).',
        values: { mode: '5600', attack: 'straight', wordlist: '/usr/share/wordlists/rockyou.txt' } },
    ],
    'tb-john': [
      { id: 'asrep', label: 'AS-REP Roast', phase: 'cracking', hint: 'Crack AS-REP hashes with john when you have no GPU.',
        values: { format: 'krb5asrep', mode: 'wordlist', wordlist: '/usr/share/wordlists/rockyou.txt' } },
      { id: 'kerberoast', label: 'Kerberoast', phase: 'cracking', hint: 'Crack TGS service tickets with john.',
        values: { format: 'krb5tgs', mode: 'wordlist', wordlist: '/usr/share/wordlists/rockyou.txt' } },
      { id: 'shadow', label: 'Linux Shadow', phase: 'cracking', hint: 'sha512crypt hashes from a Linux /etc/shadow (unshadow first).',
        values: { format: 'sha512crypt', mode: 'wordlist', wordlist: '/usr/share/wordlists/rockyou.txt' } },
      { id: 'ntlm', label: 'NTLM', phase: 'cracking', hint: 'Windows NT hashes with john instead of hashcat.',
        values: { format: 'NT', mode: 'wordlist', wordlist: '/usr/share/wordlists/rockyou.txt' } },
    ],
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
