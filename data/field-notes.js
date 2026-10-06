/*!
 * obol data — field-notes.js — OBOL.FIELD_NOTES, OBOL.FIELD_DOCTORS, OBOL.fieldNote()
 *
 * Execution help for the Next Steps canvas, scoped to a (move, command) — NOT the Learn tab's teaching
 * prose. It answers the one question a learner has with a command in front of them: "how do I make THIS
 * run work?" Each authored entry is { land:[...], mistakes:[...], win:'...', doctor?:{title,body,code?} }:
 *   land     — 1-3 plain steps to land the command (voice: the tunnel wizard's "you'll know it worked").
 *   mistakes — the usual ways it goes wrong (always-on, distinct from the reactive doctor).
 *   win      — the single observable that tells you it worked.
 *   doctor   — an optional authored "if it fails like X" note tied to THIS command.
 * FIELD_NOTES is keyed by moveId -> array indexed by command position. It does NOT need to cover every
 * move: OBOL.fieldNote() falls back to the move's own command note + hypothesis, which the pack authors
 * already write richly, so an un-authored command still shows useful, non-empty help. Seed the high-traffic
 * spine here; coverage widens over time. No em dashes, Title Case headings handled by the renderer.
 *
 * FIELD_DOCTORS is keyed by a live blocker.* fact kind: when the operator has pasted an error that minted
 * that blocker, the canvas surfaces this fix reactively (amber), independent of which command is selected.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  OBOL.FIELD_NOTES = {
    // ---- the flag-capture spine (highest traffic, and where the Remote/On-Host distinction matters most) ----
    'flag-hunt-linux': [
      { land: ['You already have a shell, so just read the flag. No credential needed.',
               'Print your identity (id) and the target IP next to the flag so one screenshot proves all three.'],
        mistakes: ['Capturing only the flag value, with no id or IP in the same frame.'],
        win: 'The flag value prints under your id and the interface IP.' },
      { land: ['Only for when you hold SSH creds but have no shell yet. This runs from Kali, so it only LOCATES the flag.',
               'Note the path it prints, then get a shell and read it on the host.'],
        mistakes: ['Treating this remote read as the capture. A flag read from Kali scores zero on the exam.'],
        win: 'A path like /home/user/user.txt prints. Now capture it in a shell on the box.' },
      { land: ['Run this INSIDE your shell on the target, not from Kali.',
               'id + ip addr + the flag, together, is the report screenshot.'],
        mistakes: ['Running it over a one-shot remote exec instead of in your session.'],
        win: 'The flag prints beneath uid= and the target IP in your own session.' } ],
    'flag-hunt-root-linux': [
      { land: ['You are root now, so read the proof flag in /root before you do anything else.',
               'id must show uid=0 in the same screenshot as the flag.'],
        mistakes: ['Forgetting to prove uid=0 alongside the flag.'],
        win: 'The root flag prints beneath uid=0(root).' },
      { land: ['If the exact path was not located yet, sweep for it now that /root is readable.'],
        mistakes: [], win: 'The sweep turns up the proof file and prints it.' } ],
    'flag-hunt-windows': [
      { land: ['You already have a shell, so read the user flag. No credential needed.',
               'hostname + ipconfig next to the flag is the report screenshot.'],
        mistakes: ['Capturing the value without hostname/ipconfig in the same frame.'],
        win: 'The flag prints under your hostname and the target IP.' },
      { land: ['Only for when you hold a hash/credential but have no shell yet. This runs from Kali, so it only LOCATES the flag file.',
               'Note the path, then get on the host to read it.'],
        mistakes: ['Treating the spider output as the capture. A remote read scores zero.'],
        win: 'A path like Users\\svc\\Desktop\\user.txt prints. Switch to On-Host to grab it.' },
      { land: ['Use the NT hash you dumped (-H, not -p). This drops you into a real session ON the box.',
               'That session is the point: the exam only counts a flag you read from a shell on the target.'],
        mistakes: ['Pasting the whole LM:NT hash. evil-winrm wants only the NT half.'],
        win: 'You land at an *Evil-WinRM* PS prompt on the target.',
        doctor: { title: 'If The Login Is Refused', body: 'WinRM access denied usually means the user is not in Remote Management Users. Confirm the hash validates over SMB first:', code: 'nxc smb <target> -u <user> -H <hash>' } },
      { land: ['Run this inside the evil-winrm session, not from Kali.',
               'hostname + ipconfig + the flag, together, is the capture.'],
        mistakes: ['Reading it over a remote exec rather than in your session.'],
        win: 'The flag prints under your hostname and the target IP, in your session.' } ],
    'flag-hunt-root-windows': [
      { land: ['You are SYSTEM/Administrator now, so grab the proof flag first.',
               'whoami + hostname + ipconfig + the flag, together, is the report screenshot.'],
        mistakes: ['Not proving the elevated identity (whoami) alongside the flag.'],
        win: 'The proof flag prints beneath whoami showing SYSTEM or Administrator.' },
      { land: ['If the path was not located yet, sweep the Administrator Desktop now that it is readable.'],
        mistakes: [], win: 'The sweep finds proof.txt / root.txt and prints it.' } ],
  };

  // Reactive doctors — surfaced in the canvas when a pasted error has minted the matching blocker.* fact,
  // regardless of which command is selected. Concise fixes; the full fix move still exists in the engine.
  OBOL.FIELD_DOCTORS = {
    'blocker.clock_skew': { title: 'Kerberos Clock Skew', body: 'KRB_AP_ERR_SKEW means your clock is more than 5 minutes off the DC. Sync to the DC, then retry. Your credential is fine.', code: 'sudo ntpdate <dc-ip>   # or: sudo rdate -n <dc-ip>' },
    'blocker.name_resolution': { title: 'Name Resolution', body: 'A tool was handed a hostname with no DNS. Map it in /etc/hosts and retry.', code: 'echo "<target-ip> <host.domain>" | sudo tee -a /etc/hosts' },
    'blocker.no_tty': { title: 'No TTY For Sudo', body: 'sudo wants a real terminal. Upgrade your shell to a PTY first.', code: 'python3 -c \'import pty;pty.spawn("/bin/bash")\'' },
    'blocker.crlf': { title: 'Bad Interpreter (CRLF)', body: 'A script you uploaded has Windows line endings. Strip the \\r and run it again.', code: 'sed -i \'s/\\r$//\' <script>' },
    'ssh.key_rejected': { title: 'SSH Key Refused', body: 'A found or planted private key must be mode 600 and owned by you, or SSH ignores it. Fix permissions, then connect.', code: 'chmod 600 id_rsa && ssh -i id_rsa <user>@<target>' },
    'blocker.potato': { title: 'Potato Failed', body: 'A SeImpersonate potato that errors is usually the wrong one for this Windows build. Check the build and pick the match.', code: 'systeminfo | findstr /B /C:"OS Version"' },
    'blocker.hash_format': { title: 'No Hashes Loaded', body: 'The cracker rejected the file. It is almost always the wrong mode for the hash type, not a tough hash. Identify the type and set the matching mode.', code: 'hashid <hashfile>   # then pick the matching -m / --format' },
    'blocker.egress_blocked': { title: 'Egress Blocked', body: 'Your payload ran but nothing hit your listener. The box cannot reach you on that port. Try a common outbound port (443/53) or a different channel.', code: null },
    'blocker.amsi': { title: 'AMSI Block', body: 'AMSI flagged your script in memory. Load it in a fresh session with an AMSI bypass, or run the tool from disk as a trusted binary.', code: null },
    'blocker.rate_limited': { title: 'Rate Limited', body: 'A 429 or WAF throttle is slowing your fuzzing. Back off the thread count and add a delay before retrying.', code: null },
    'blocker.smb_signing': { title: 'SMB Signing Required', body: 'This relay target enforces SMB signing, so it cannot be a relay destination. Find a host with signing off (nxc smb <range> --gen-relay-list).', code: null },
    'blocker.ntlm_disabled': { title: 'NTLM Disabled', body: 'The DC refused NTLM (STATUS_NOT_SUPPORTED). Authenticate with Kerberos instead: get a TGT, then use -k.', code: 'kinit <user>   # then add -k to your nxc/impacket command' },
    'blocker.lockout': { title: 'Account Lockout', body: 'A spray tripped the lockout policy. Stop spraying, wait out the window, and lower your attempts per account next time.', code: null },
    'blocker.password_change': { title: 'Password Change Required', body: 'The credential is valid but the account must set a new password. Change it, then use the new one.', code: 'smbpasswd -r <target> -U <user>' },
  };

  // Resolve a (move, command index) to a canvas note, with a graceful fallback to the pack's own command
  // note + move hypothesis so an un-authored command is never empty.
  OBOL.fieldNote = function (move, idx) {
    if (!move) return null;
    var authored = (OBOL.FIELD_NOTES[move.id] || [])[idx] || {};
    var cmd = (move.commands || [])[idx] || {};
    var firstSentence = function (s) { s = String(s || '').trim(); var m = s.match(/^.*?[.!?](\s|$)/); return m ? m[0].trim() : s; };
    var land = authored.land && authored.land.length ? authored.land
      : (cmd.note ? [String(cmd.note)] : (move.hypothesis ? [firstSentence(move.hypothesis)] : []));
    var win = authored.win || '';
    var locus = (OBOL.pack && OBOL.pack.commandLocus) ? OBOL.pack.commandLocus(cmd) : 'remote';
    return {
      land: land,
      mistakes: authored.mistakes || [],
      win: win,
      doctor: authored.doctor || null,
      locus: locus,
      authored: !!(OBOL.FIELD_NOTES[move.id] || [])[idx],
    };
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
