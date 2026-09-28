/*!
 * obol ui — util.js — tiny DOM/util helpers (no framework).
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function attr(s) { return esc(s); }

  // First sentence of a longer string (for one-line "why").
  function firstSentence(s) {
    s = String(s || '').trim();
    var m = s.match(/^(.*?[.!?])(\s|$)/);
    return m ? m[1] : s;
  }

  function copy(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).then(function () { return true; }, function () { return fallbackCopy(text); });
    }
    return Promise.resolve(fallbackCopy(text));
  }
  function fallbackCopy(text) {
    try {
      var ta = document.createElement('textarea');
      ta.value = text; ta.setAttribute('readonly', ''); ta.style.position = 'absolute'; ta.style.left = '-9999px';
      document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
      return true;
    } catch (e) { return false; }
  }

  var _toastEl = null;
  function toast(msg, kind) {
    try {
      if (!_toastEl) {
        _toastEl = document.createElement('div');
        _toastEl.className = 'obol-toast';
        _toastEl.setAttribute('role', 'status');
        _toastEl.setAttribute('aria-live', 'polite');
        document.body.appendChild(_toastEl);
      }
      _toastEl.textContent = msg;
      _toastEl.className = 'obol-toast show' + (kind ? (' ' + kind) : '');
      clearTimeout(_toastEl._t);
      _toastEl._t = setTimeout(function () { _toastEl.className = 'obol-toast'; }, 2200);
    } catch (e) {}
  }

  // Title Case for display labels: capitalizes the first letter of each word (split on space and
  // hyphen) while leaving intact (a) tokens already starting with a capital — acronyms/proper
  // casing like AS-REP, WinRM, NTDS, GTFOBins, BloodHound — and (b) literal tokens that carry a
  // path/command/config shape (a '/', '_' or '.'), so "/etc/passwd", "xp_cmdshell" and
  // "no_root_squash" survive verbatim. Apostrophe-s is not capitalized ("host's" → "Host's").
  // Security/AD acronyms and proper spellings kept in their canonical case (SMB, LDAP, DCSync, WinRM…),
  // so a lowercased fact label ("smb authenticated") title-cases to "SMB Authenticated", not "Smb …".
  var TC_WORDS = {
    smb: 'SMB', smbv1: 'SMBv1', smbv2: 'SMBv2', smbv3: 'SMBv3', ldap: 'LDAP', ldaps: 'LDAPS', ad: 'AD', dc: 'DC',
    dns: 'DNS', rdp: 'RDP', ntds: 'NTDS', ntlm: 'NTLM', uac: 'UAC', rid: 'RID', sid: 'SID', acl: 'ACL', acls: 'ACLs',
    spn: 'SPN', spns: 'SPNs', tgs: 'TGS', tgt: 'TGT', gpo: 'GPO', gpp: 'GPP', adcs: 'ADCS', krbtgt: 'krbtgt',
    kdc: 'KDC', ca: 'CA', ip: 'IP', tcp: 'TCP', udp: 'UDP', http: 'HTTP', https: 'HTTPS', ftp: 'FTP', ssh: 'SSH',
    winrm: 'WinRM', os: 'OS', cve: 'CVE', poc: 'PoC', url: 'URL', api: 'API', sql: 'SQL', sqli: 'SQLi', xss: 'XSS',
    ssrf: 'SSRF', xxe: 'XXE', lfi: 'LFI', rfi: 'RFI', ssti: 'SSTI', jwt: 'JWT', cors: 'CORS', smtp: 'SMTP',
    snmp: 'SNMP', vnc: 'VNC', wmi: 'WMI', dcom: 'DCOM', sccm: 'SCCM', gmsa: 'gMSA', laps: 'LAPS', sam: 'SAM',
    dcsync: 'DCSync', bloodhound: 'BloodHound', netexec: 'NetExec', 'as-rep': 'AS-REP', asrep: 'AS-REP',
    pth: 'PtH', nfs: 'NFS', suid: 'SUID', sgid: 'SGID', gtfobins: 'GTFOBins', lxd: 'LXD', mssql: 'MSSQL',
    tls: 'TLS', ssl: 'SSL', vpn: 'VPN', dacl: 'DACL', mfa: 'MFA', rce: 'RCE', idor: 'IDOR',
  };
  var TC_SMALL = { of: 1, the: 1, a: 1, an: 1, to: 1, in: 1, on: 1, for: 1, and: 1, or: 1, with: 1, via: 1, per: 1 };
  function titleCase(s) {
    var seen = 0;
    function word(w, isPathPart, isFirst) {
      if (!/[A-Za-z]/.test(w)) return w;
      var lw = w.toLowerCase();
      if (TC_WORDS[lw]) return TC_WORDS[lw];
      if (!isPathPart && !isFirst && TC_SMALL[lw]) return lw;      // connector word (not first) → lowercase
      if (/^[^A-Za-z]*[A-Z]/.test(w)) return w;                    // already starts capitalized (proper/acronym)
      return w.replace(/^([^A-Za-z]*)([a-z])/, function (_, pre, c) { return pre + c.toUpperCase(); });
    }
    return String(s == null ? '' : s).split(/(\s+|-)/).map(function (w) {
      if (/^\s+$/.test(w) || w === '-') return w;
      if (/^\//.test(w) || /[_.]/.test(w)) return w;               // absolute path / command / config key → literal
      var isFirst = seen === 0; seen++;
      if (w.indexOf('/') !== -1) return w.split(/(\/)/).map(function (p, i) { return p === '/' ? p : word(p, true, isFirst && i === 0); }).join('');
      return word(w, false, isFirst);
    }).join('');
  }

  // Delegated click helper: on(container, selector, handler).
  function on(container, evt, selector, handler) {
    container.addEventListener(evt, function (e) {
      var t = e.target.closest(selector);
      if (t && container.contains(t)) handler(e, t);
    });
  }

  OBOL.util = { esc: esc, attr: attr, firstSentence: firstSentence, copy: copy, toast: toast, on: on, titleCase: titleCase };
})(typeof globalThis !== 'undefined' ? globalThis : this);
