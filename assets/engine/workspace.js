/*!
 * obol engine — workspace.js
 * Models the on-disk working directory the operator runs commands from (their Kali box), so obol
 * web can fill concrete output paths into suggested commands and tell the user exactly where a
 * file landed and how to attach it. obol web never touches the filesystem — this only *generates*
 * paths and a one-time scaffold command; the operator runs it and attaches the results.
 *
 * The attacker box is Kali/Linux, so paths are POSIX. The layout mirrors obol-local's `scans/`
 * convention (tool output → scans/). Default root is box-centric on labs, engagement-centric on
 * exams. Pure + self-contained (window / worker / node).
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  var LAYOUT = { scans: 'scans', loot: 'loot', exploit: 'exploit', www: 'www', proof: 'proof' };
  var DEFAULT_BASE = '~/engagements';

  function slugify(s) {
    return String(s || '').trim().toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 64) || 'run';
  }
  // Sanitize a working-directory path the operator typed/pasted. obol drops the path into generated
  // commands UNQUOTED (e.g. `-oN <root>/scans/…`), so a stray shell metacharacter — a `]`, or worse a
  // `;`/backtick/`$(…)` — would leak into a command they paste into their own terminal. Strip shell-
  // special characters and whitespace; keep ordinary POSIX path characters (~ / . _ - and word chars).
  function sanitizeRoot(s) {
    return String(s == null ? '' : s).trim()
      .replace(/[;&|`$(){}\[\]<>*?!'"\\\s]+/g, '')
      .replace(/\/{2,}/g, '/').replace(/\/+$/, '');
  }
  // Join POSIX path parts, collapsing duplicate slashes (a leading ~ or / is preserved).
  function join() {
    var parts = [].slice.call(arguments).filter(function (p) { return p !== undefined && p !== null && p !== ''; });
    return parts.join('/').replace(/([^:])\/{2,}/g, '$1/').replace(/\/+$/, '') || '/';
  }
  // Lab runs are box-centric (a dir per box); exams are engagement-centric (one dir for the exam).
  // Default leaf folder for an engagement: the engagement's own name — neutral and stable, never the
  // target IP (a box-centric folder was surprising when the operator had named the run).
  function slugFor(eng) {
    return eng ? slugify(eng.name) : 'run'; // slugify falls back to 'run' for an empty name
  }
  function defaultRoot(base, eng) { return join(base || DEFAULT_BASE, slugFor(eng)); }
  function rootFor(eng) { return (eng && eng.workspace && eng.workspace.root) ? sanitizeRoot(eng.workspace.root) : ''; }
  function isConfigured(eng) { return !!rootFor(eng); }

  // Concrete output directories as {{token}} values. With no workspace set they fall back to
  // relative dirs (scans/, loot/…) so commands still form — just not absolute.
  function dirs(eng) {
    var r = rootFor(eng);
    function d(k) { return r ? join(r, LAYOUT[k]) : LAYOUT[k]; }
    return { root: r || '.', scandir: d('scans'), lootdir: d('loot'), exploitdir: d('exploit'), wwwdir: d('www'), proofdir: d('proof') };
  }
  var tokens = dirs;

  // The one-time "set up your workspace" command — create the tree and cd into it.
  function scaffold(eng) {
    var r = rootFor(eng);
    var subs = Object.keys(LAYOUT).map(function (k) { return LAYOUT[k]; }).join(',');
    return r ? ('mkdir -p ' + r + '/{' + subs + '} && cd ' + r) : ('mkdir -p {' + subs + '}');
  }

  // A NON-DESTRUCTIVE zsh tweak: print a dim line with the UTC time + VPN address before every prompt,
  // WITHOUT replacing the operator's own PROMPT (precmd_functions+=() appends a hook, so it composes with
  // oh-my-zsh / powerlevel10k / a plain prompt alike). Two payoffs feed the whole-session import:
  //   • every command gets a timestamp, so obol can stitch captures from several tabs into one timeline;
  //   • the tun/tap/wg address is surfaced, so obol reads the operator's {{lhost}} straight from a paste.
  // The device name is auto-detected (tun0/tap0/wg0…) and printed verbatim, matching ingest.detectLhost.
  var PROMPT_STAMP_ZSH = [
    '# obol: stamp each prompt with the UTC time + VPN IP (keeps your existing prompt).',
    'obol_stamp() {',
    '  local dev ip',
    '  read -r dev ip <<< "$(ip -4 -o addr show 2>/dev/null | awk \'$2 ~ /^(tun|tap|wg)/ {split($4,a,\"/\"); print $2, a[1]; exit}\')"',
    '  print -P "%F{244}[$(date -u \'+%Y-%m-%d %H:%M:%S UTC\')]${ip:+ [$dev:$ip]}%f"',
    '}',
    'precmd_functions+=(obol_stamp)',
  ].join('\n');
  // Pin the stamp to a specific interface when the operator has told obol which one their VM uses (from the
  // engagement setup). It reads that adapter's address directly and labels the stamp with its name — which
  // ingest.detectLhost keys on. Falls back to the auto-detecting default when no interface is configured.
  function promptStamp(iface) {
    if (!iface || !/^[a-z][a-z0-9.:_-]{0,14}$/i.test(iface)) return PROMPT_STAMP_ZSH;
    return [
      '# obol: stamp each prompt with the UTC time + ' + iface + ' IP (keeps your existing prompt).',
      'obol_stamp() {',
      '  local ip',
      '  ip=$(ip -4 -o addr show ' + iface + ' 2>/dev/null | awk \'{split($4,a,"/"); print a[1]; exit}\')',
      '  print -P "%F{244}[$(date -u \'+%Y-%m-%d %H:%M:%S UTC\')]${ip:+ [' + iface + ':$ip]}%f"',
      '}',
      'precmd_functions+=(obol_stamp)',
    ].join('\n');
  }
  // Append it to ~/.zshrc and reload — idempotent (the guard skips a second append).
  function promptStampInstall(iface) {
    return "grep -q obol_stamp ~/.zshrc || cat >> ~/.zshrc <<'OBOL_ZSH'\n" + promptStamp(iface) + "\nOBOL_ZSH\nsource ~/.zshrc";
  }
  var PROMPT_STAMP_INSTALL = promptStampInstall('');
  // Capture a whole session to a file to import in one go (portable: works without the prompt tweak, but
  // timestamps come out best WITH it). `script` records everything you run + its output, timing included.
  function captureCmd(eng) {
    var d = dirs(eng);
    return 'script -q -f ' + join(d.loot || 'loot', 'session-$(date -u +%Y%m%d-%H%M%S).log');
  }
  // A one-shot snapshot of the working directory: list every file (path + size + mtime), wrapped in
  // markers so obol can find the block in a larger paste. The operator runs it and pastes the output
  // back to fully synchronize the virtual workspace — obol confirms the files it predicted and adopts
  // any it didn't know about. GNU find (Kali); hidden files skipped so ~/.zshrc etc. stay out.
  function snapshotCmd(eng) {
    var r = rootFor(eng) || '.';
    return 'cd ' + r + " 2>/dev/null && { echo '### OBOL-WS-SNAPSHOT'; find . -type f -not -path '*/.*' -printf '%P\\t%s\\t%TY-%Tm-%TdT%TH:%TM\\n' 2>/dev/null | sort; echo '### END'; }";
  }

  OBOL.workspace = {
    LAYOUT: LAYOUT, DEFAULT_BASE: DEFAULT_BASE,
    PROMPT_STAMP_ZSH: PROMPT_STAMP_ZSH, PROMPT_STAMP_INSTALL: PROMPT_STAMP_INSTALL,
    promptStamp: promptStamp, promptStampInstall: promptStampInstall,
    slugify: slugify, sanitizeRoot: sanitizeRoot, join: join, slugFor: slugFor, defaultRoot: defaultRoot,
    rootFor: rootFor, isConfigured: isConfigured, dirs: dirs, tokens: tokens, scaffold: scaffold,
    captureCmd: captureCmd, snapshotCmd: snapshotCmd,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
