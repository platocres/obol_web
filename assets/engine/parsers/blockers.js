/*!
 * obol engine — parsers/blockers.js — the "cryptic wall" detectors.
 *
 * Classic OSCP/HTB traps are rarely a real defence — they are an error message a learner has not seen
 * before, and the fix is one command. Each recognizer below reads a pasted failure and mints a
 * blocker.* fact so the matching fix/guidance move surfaces with the exact remedy. Everything here is
 * content-gated and additive: a benign paste mints nothing, and a blocker only appears once the user's
 * own output shows the wall, so Next Steps is never cluttered by advice for a wall they have not hit.
 *
 * These are DIAGNOSTIC facts, not attack evidence: they say "here is why your command failed and how to
 * get past it", which is a different muscle from the attack-fact parsers, hence their own small module.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var C = OBOL._parserCommon; if (!C) return;
  var mkFact = C.mkFact, _add = C._add, S = C.ProofState.SUPPORTED;

  // kind -> the signature that proves the wall. Ordered; several may fire from one paste.
  var WALLS = [
    // recon: nmap says the host is down because ICMP is filtered — the #1 beginner trap. Fix: -Pn.
    { kind: 'blocker.host_down', re: /Note:\s*Host seems down|0 hosts up|host (?:seems|appears) to be down|increase .*--host-timeout/i },
    // name resolution: a box addressed by a hostname (box.htb) that is not in /etc/hosts.
    { kind: 'blocker.name_resolution', re: /Could not resolve host(?:name)?|Name or service not known|Temporary failure in name resolution|Name does not resolve|getaddrinfo .*Name or service/i },
    // a uploaded script with Windows CRLF line endings: "/bin/bash^M: bad interpreter".
    { kind: 'blocker.crlf', re: /bad interpreter:\s*No such file or directory|[\^]M: bad interpreter|\r': bad interpreter|cannot execute:\s*required file not found/i },
    // a command that needs a real terminal (sudo, su, ssh interactive) from a dumb shell.
    { kind: 'blocker.no_tty', re: /sudo:\s*(?:no tty present|a (?:terminal|password) is required)|must be run from a terminal|no tty present and no askpass|the input device is not a TTY/i },
    // Windows Defender / AMSI eating a payload.
    { kind: 'blocker.amsi', re: /This script contains malicious content and has been blocked|contains a virus or potentially unwanted software|Operation did not complete successfully because the file contains a virus|AMSI_RESULT_DETECTED|failed with error code 0x80508023/i },
    // SeImpersonate potato that picked the wrong technique for the Windows build.
    { kind: 'blocker.potato', re: /CoGetInstanceFromIStorage|RpcServerRegisterIf.*failed|the handle is invalid|CreateProcessAsUser.*(?:failed|1314)|BITS.*(?:not|disabled)|potato.*fail/i },
    // web fuzzing throttled by a WAF / rate limiter.
    { kind: 'blocker.rate_limited', re: /\b429\b\s*(?:Too Many Requests)?|Too Many Requests|rate.?limit(?:ed|ing)?|temporarily blocked|request(?:s)? (?:have been )?throttled/i },
    // http vs https mismatch: curl/tooling hitting the wrong scheme.
    { kind: 'blocker.tls_scheme', re: /SSL.*WRONG_VERSION_NUMBER|wrong version number|record layer failure|sslv3 alert handshake failure|routines::?(?:unexpected eof|wrong version)/i },
    // hashcat/john refusing the hash: wrong mode, a username: prefix left on, or CRLF in the hash file.
    { kind: 'blocker.hash_format', re: /Token length exception|No hashes loaded|No password hashes loaded(?: with these settings)?|Separator unmatched|Signature unmatched|Line-length exception|Hashfile '[^']*' on line \d+/i },
    // a reverse shell that never calls back — the payload ran but egress is filtered.
    { kind: 'blocker.egress_blocked', re: /nc:.*(?:Connection refused|No route to host|Network is unreachable)|Ncat: (?:Connection refused|TIMEOUT|No route to host)|socat.*(?:Connection refused|refused)|curl:\s*\(7\)\s*Failed to connect/i },
  ];

  function _parse_op_blockers(text, ws, command, source, facts) {
    var t = String(text || ''); if (!t) return;
    var h = 'host:' + ws.target;
    for (var i = 0; i < WALLS.length; i++) {
      if (WALLS[i].re.test(t)) _add(facts, mkFact(WALLS[i].kind, h, { tool: C._exec_tool ? C._exec_tool(command || '') : '', via: 'blocker-detect' }, S, source));
    }
  }
  C._parse_op_blockers = _parse_op_blockers;
})(typeof globalThis !== 'undefined' ? globalThis : this);
