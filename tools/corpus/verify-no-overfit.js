#!/usr/bin/env node
/*
 * tools/corpus/verify-no-overfit.js - Automated Anti-Overfitting & House-Style Red-Team
 * Scanner (qa-only; never ships to prod, never runs at runtime).
 *
 * Dynamically loads corpus identities (box/lab slugs, machine names, Challenge Lab
 * hostnames, walkthrough-specific IPs, author repository handles, and walkthrough prose)
 * from local corpus manifests without hardcoding distinctive box lists in source code:
 *   - ../corpus/pg-practice-2026-10-29/corpus-manifest.json
 *   - ../0xdf-offsec-complete-2026-08-20/ranked-walkthroughs.json
 *   - ../0xdf-offsec-complete-2026-08-20/corpus-manifest.json (if present)
 *   - ../corpus/pg-challenge-labs-2026-10-29/corpus-manifest.json (if present)
 *   - any additional ../corpus/<name>/corpus-manifest.json discovered on disk
 *
 * Enforces four non-negotiable gates across git diff (default), --files, or --all:
 *   1. HARDCODED_BOX_IDENTITY: Zero distinctive box/lab slugs, Challenge Lab hostnames,
 *      manifest IPs, or author handles in qa/assets/, qa/data/, or qa/tests/.
 *      Includes a principled standard English / computing / protocol allowlist so genuine
 *      dictionary and protocol terms (access, internal, vault, squid, administrator, etc.)
 *      do not false-positive when used normally.
 *   2. SUSPICIOUS_BOX_LOOKUP_TABLE: Blocks explicit box qualifiers ("HTB: <Name>",
 *      "PG Practice: <Name>", "<slug>.htb") and multi-slug lookup arrays/tables (>= 4
 *      manifest slugs in one expression) even when individual words are English.
 *   3. VERBATIM_WALKTHROUGH_PROSE: Zero >= 48-char verbatim walkthrough prose substrings
 *      leaked into qa/tests/ (exact Pigeonhole-aligned 24-char anchor index).
 *   4. HOUSE_STYLE_VIOLATION: Zero em dashes (\u2014), zero en dashes (\u2013), and zero
 *      decorative emoji across scanned files.
 *
 * Usage:
 *   node tools/corpus/verify-no-overfit.js [--all] [--files f1,f2] [--base HEAD] [--json]
 *
 * Exits 0 when clean, 1 on any violation.
 * House style: no em dashes, no en dashes, no emoji.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const QA_ROOT = path.resolve(__dirname, '..', '..');
const SITE_ROOT = path.resolve(QA_ROOT, '..');

// Standard English dictionary words, OS/programming keywords, and real-world protocols or
// open-source software products that happen to share names with CTF/lab titles.
const COMMON_ENGLISH_AND_TECH_ALLOWLIST = new Set((
  'a about absolute access account active acute admin administrator analysis apache api app ' +
  'apex apt archive art artifact assignment atom authority auth autumn av backdoor backup ' +
  'bank bar base bastion batch beep binary bingo bit black blue board book boolean box ' +
  'branch bridge broker browser browsed bucket buffer build builder bus bypass cache call ' +
  'canary capture card cascade case cast cat catch cave center cerberus cert certified ' +
  'chain challenge change channel check cheese chefchemistry chronic cipher circle claim ' +
  'class clean clear client clock cloud clue cluster cmd coach code cockpit coffee cold ' +
  'collection color command comment common compact compare compile config connect console ' +
  'contact container content context control cookie copy core corner corp count craft ' +
  'crash create cred credit cron cross crypto cube cup curl current custom cut cyber ' +
  'cycle daily dark data database date dawn dead deal debug deck decode deep default ' +
  'delay delete delivery delta demo dense deploy depth desk desktop dev devel device ' +
  'dialog dictionary diff dig digital dir direct directory dirty disable discovery disk ' +
  'dispatch display dns doctor dog domain done door double down download draft driver ' +
  'drop dry dual dump dynamic early earth easy echo edge edit editor editorial educated ' +
  'eight eighteen electric element email emit empty enable encode end engine enterprise ' +
  'entry enum env epoch equal error escape event evil exact exam example exchange exec ' +
  'execute exfiltrated exit expand expect exploit export express extend external extra ' +
  'eye fact factor fail fall false family farm fast fault feature feed fetch field file ' +
  'fill filter final find finger fingerprint finish fire fired firewall firm first fish ' +
  'fix flag flash flat flight float floor flow fluid flush focus folder follow font food ' +
  'foot foothold force forest forge form format forward found frame free fresh friend ' +
  'front full fun function fuse future fuzz game gap garden gate gateway gear general ' +
  'get ghost gift git glass global glpi go gold good graph green grid group guard guest ' +
  'guide gui gun hack hall hand handle hard hash head header health heap heavy help ' +
  'helpdesk hero hidden high hint history hit hold home hook hop horizon host hospital ' +
  'hot hotel hour house html http hub human hunt hybrid hyper icon id ideal identity ' +
  'idle image impact import in inbox include index info infra init inject inline input ' +
  'insert inside inspect install instance int integer intelligence intent interface ' +
  'internal internet into invalid inventory io ip iron island issue item jack jar java ' +
  'jenkins jet job join journal json judge jump junior jury just keen keep kernel key ' +
  'kick kid kill kind king kit kitchen knife knock know lab label lack ladder lake ' +
  'lambda lamp land lane language large laser last late lateral launch law layer lazy ' +
  'lead leaf leak lean learn lease leave ledger left legacy legal lens less level ' +
  'library license life lift light lightweight limit line link linux list listen live ' +
  'load local lock log logic login long look loop loose lost lot loud love low lucky ' +
  'machine macro magic mail mailing main major make manager mango manual map mark ' +
  'market marketing mask mass master match matrix max maybe mean measure media medical ' +
  'medium meet member memory mental mentor menu merge mesh message meta metal method ' +
  'metric micro mid middle might mile milk mill mind mine mini minor mint mirror miss ' +
  'mix mobile mode model modern modify module moment money monitor monitored monitors ' +
  'month moon more morning mount mouse move movie multi music mutual mysql name narrow ' +
  'native natural near neat neck need needle negative neighbor nest net network ' +
  'networked neutral never new news next nice night nine ninja node noise none normal ' +
  'north note nothing notice novel now null number nurse object observe ocean october ' +
  'odd off office official offline offset oil ok old olive omega on once one online ' +
  'only open opera operator opinion optimal optimum option oracle orange order organic ' +
  'origin other out outbound outcome outdated outer output over owner pack package ' +
  'packet pad page pain paint pair palace palm panel panic paper parallel param ' +
  'parent park part partial partner party pass passage password paste patch path ' +
  'patient pattern pause pay pc peace peak pearl peer pen penalty pending people ' +
  'pepper perfect perform period perm permission person pet phase phone photo physical ' +
  'piano pick picture piece pilot pin ping pipe pitch pivot pixel place plain plan ' +
  'plane planet plant plate platform play player please plot plug plus pocket point ' +
  'poison polar police policy poll pool poor pop popular port portal position positive ' +
  'post postman pot potato power practice prefix premium prep prepare present press ' +
  'pretty prev prevent preview price pride primary prime print prior priority private ' +
  'privilege prize pro probe problem process produce product profile profit program ' +
  'progress project promise promote prompt proof proper property protect protocol ' +
  'proud prove provide proxy public publish pull pulse pump punch pure push put ' +
  'python quad quality quantum quarter query queries quest queue quick quiet quit ' +
  'quote rabbit race radar radio rail rain raise rally ram random range rank rapid ' +
  'rare rate ratio raw reach react read reader ready real realm reason rebel receipt ' +
  'receive recent record recover red redirect reduce ref reference reflect refresh ' +
  'region register registry regular reject relate relay release relevant relief ' +
  'reload remain remedy remember remind remote remove render renew rent repair repeat ' +
  'replace replay reply report repo request require rescue research reserve reset ' +
  'resident resolve resource respect respond response rest restore result resume ' +
  'retail retain retire return reveal review reward rhythm rich ride ridge rifle ' +
  'right rigid ring riot rise risk ritual river road roast robot rock rocket role ' +
  'roll roof room root rope rose roster rotate rough round route router row royal ' +
  'ruby rule run runner rural rush rust safe safety sail salad salary sale salt ' +
  'same sample sandbox sand save scale scan scanner scene schedule schema school ' +
  'science scope score scout scrap screen script scroll sea seal search season seat ' +
  'second secret section sector secure security seed seek seem segment select self ' +
  'sell semi send senior sense sensor sentence separate sequence series serve server ' +
  'service session set settle setup seven shadow shake shallow shape share shared ' +
  'shark sharp shed sheet shelf shell shield shift shine ship shibboleth shock shoe ' +
  'shoot shop shore short shot should show shower shrink shut shy sick side sight ' +
  'sign signal signature signed silence silent silicon silk silver similar simple ' +
  'since sing single sink sir sister site six size skate sketch ski skill skin skip ' +
  'skirt skull sky slab slam sleep slice slide slight slim link slip slot slow ' +
  'small smart smash smell smile smoke smooth snack snake snap sniff sniper snow ' +
  'soap soccer social socket soda soft solar soldier solid solution solve some ' +
  'son song soon sorry sort soul sound soup source south space spare spark spatial ' +
  'spawn speak special specific speed spell spend sphere spice spider spike spin ' +
  'spirit split spoil sponsor spoon sport spot spray spread spring spy spx SQL ' +
  'square squid stack stacked staff stage stain stair stake stale stamp stand ' +
  'standard star start state static station status stay steady steam steel steep ' +
  'stem step stereo stick still sting stock stomach stone stool stop store storm ' +
  'story stove strategy street strike strong struct structure struggle student ' +
  'studio study stuff stumble style subject submit subnet subtle success such ' +
  'sudden sudo suffer sugar suggest suit summer sun sunny sunset super supply ' +
  'support sure surface surge surprise surround survey suspect sustain swallow ' +
  'swamp swap swarm swear sweat sweep sweet swell swift swim swing switch sword ' +
  'symbol symbolic symptom sync syntax system table tackle tag tail talent talk ' +
  'tank tap target task taste tattoo taxi teach team tear tech technical tedious ' +
  'tell temp template tenant tend tent term terminal test text thank that theme ' +
  'then theory there they thick thin thing think third this thought three thrive ' +
  'throw thumb thunder ticket tide tiger tilt timber time timer timing tiny tip ' +
  'tired tissue title toast tobacco today toe together toilet token toll tomato ' +
  'tomorrow tone tongue tonight tool tooth top topic topology topple torch ' +
  'tornado tortoise total tourist toward tower town toy track trade traffic ' +
  'tragic train transfer trap trash travel tray treat tree trend trial tribe ' +
  'trick trigger trim trip trophy trouble truck true truly trumpet trust truth ' +
  'try tube tuition tumble tuna tunnel turkey turn turtle twelve twenty twice ' +
  'twin twist two type typical ugly umbrella unable unattended unaware uncle uncover under ' +
  'undo unfair unfold unhappy uniform union unique unit universe unknown unlock ' +
  'until unusual unveil update upgrade uphold upon upper upset urban urge usage ' +
  'use used useful user useless usual utility vacant vacuum vague valid ' +
  'validation valley valve van vanish vapor various vast vault vector velvet ' +
  'vendor venture venue verb verify version very vessel veteran viable vibrant ' +
  'vicious victory video view village vintage violin virtual virus visa visit ' +
  'visual vital vivid vocal voice void voip volcano volume vote voyage wage ' +
  'wagon wait walk wall walnut want war warm warrior wash wasp waste water ' +
  'wave way wealth weapon wear weasel weather web wedding weekend weird welcome ' +
  'west wet whale what wheat wheel when where whip whisper wide width wife ' +
  'wild will win window windows wine wing wink winner winter wire wisdom wise ' +
  'wish witness wolf woman wonder wood wool word work worker world worry worth ' +
  'wrap wreck wrestle wrist write writer writeup wrong yard year yellow you ' +
  'young youth zebra zero zip zipper zone'
).toLowerCase().split(/\s+/).filter(Boolean));

// Standard Unicode decorative emoji detector (excludes ASCII, box-drawing, arrows, and CJK prompt sigils)
const EMOJI_RE = /\p{Extended_Pictographic}/u;
const COPYRIGHT_EXEMPT_RE = /^[\u00A9\u00AE\u2122]$/;

function discoverDefaultManifestPaths(siteRoot) {
  const root = siteRoot ? path.resolve(siteRoot) : SITE_ROOT;
  const candidates = [
    path.join(root, 'corpus', 'pg-practice-2026-10-29', 'corpus-manifest.json'),
    path.join(root, '0xdf-offsec-complete-2026-08-20', 'ranked-walkthroughs.json'),
    path.join(root, '0xdf-offsec-complete-2026-08-20', 'corpus-manifest.json'),
    path.join(root, 'corpus', 'pg-challenge-labs-2026-10-29', 'corpus-manifest.json'),
    path.join(root, 'pg-challenge-labs-2026-10-29', 'corpus-manifest.json')
  ];

  const corpusRoot = path.join(root, 'corpus');
  if (fs.existsSync(corpusRoot) && fs.statSync(corpusRoot).isDirectory()) {
    for (const d of fs.readdirSync(corpusRoot)) {
      if (d.startsWith('_')) continue;
      const mp = path.join(corpusRoot, d, 'corpus-manifest.json');
      if (candidates.indexOf(mp) < 0) candidates.push(mp);
    }
  }

  return candidates.filter(p => fs.existsSync(p));
}

function normalizeIdentityToken(s) {
  return String(s || '')
    .trim()
    .replace(/^(?:HTB|PG\s+Practice|PG\s+Play|OffSec|Challenge\s+Lab)\s*:\s*/i, '')
    .trim()
    .toLowerCase();
}

function stripCodeAndMarkupToProseParagraphs(md) {
  let s = String(md || '').replace(/\r\n/g, '\n');
  // Remove YAML frontmatter
  if (s.startsWith('---\n')) {
    const endFm = s.indexOf('\n---\n', 4);
    if (endFm > 0) s = s.slice(endFm + 5);
  }
  // Remove 0xdf HTML code div wrappers and CommonMark fenced blocks
  s = s.replace(/<div class="language-[^"]*">[\s\S]*?```[\s\S]*?```(?:\s*<\/div>)*/g, '\n\n');
  s = s.replace(/^[ \t]{0,3}(`{3,}|~{3,})[^\n]*\n[\s\S]*?\n[ \t]{0,3}\1[ \t]*$/gm, '\n\n');
  // Remove Markdown images and convert links to anchor text
  s = s.replace(/!\[[^\]]*\]\([^)]*\)/g, ' ');
  s = s.replace(/\[([^\]]+)\]\([^)]*\)/g, '$1');
  // Remove HTML tags
  s = s.replace(/<[^>]+>/g, ' ');

  const rawParas = s.split(/\n{2,}/);
  const paras = [];
  for (const raw of rawParas) {
    const lines = raw.split('\n')
      .map(l => l.trim())
      .filter(l => {
        if (!l) return false;
        if (/^#{1,6}\s+/.test(l)) return false;
        if (/^\|.*\|$/.test(l)) return false;
        if (/^(?:[-*+]\s+|\d+\.\s+)?`[^`]+`\s*$/.test(l)) return false;
        if (/^(?:PORT\s+STATE|Nmap scan report|\d+\/tcp\s+open|HTTP\/1\.\d\s+\d{3})/i.test(l)) return false;
        return true;
      });
    if (!lines.length) continue;
    const joined = lines.join(' ')
      .replace(/[`*_~>#]+/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
    if (joined.length < 48) continue;
    const alphaWords = joined.match(/[A-Za-z]{3,}/g) || [];
    if (alphaWords.length < 7) continue;
    paras.push(joined);
  }
  return paras;
}

function buildProseIndex(proseItems, minLen) {
  const threshold = Math.max(48, Number(minLen) || 48);
  const anchorLen = 24;
  const step = 24;
  const paragraphs = [];
  const anchors = new Map();

  for (const item of proseItems || []) {
    const sourceLabel = typeof item === 'string' ? 'synthetic' : (item.source || 'corpus');
    const paras = typeof item === 'string'
      ? stripCodeAndMarkupToProseParagraphs(item)
      : (Array.isArray(item.paragraphs) ? item.paragraphs : stripCodeAndMarkupToProseParagraphs(item.markdown || ''));

    for (const p of paras) {
      const norm = p.toLowerCase().replace(/\s+/g, ' ').trim();
      if (norm.length < threshold) continue;
      const pIdx = paragraphs.length;
      paragraphs.push({ text: norm, source: sourceLabel });

      for (let off = 0; off + anchorLen <= norm.length; off += step) {
        const key = norm.slice(off, off + anchorLen);
        let list = anchors.get(key);
        if (!list) {
          list = [];
          anchors.set(key, list);
        }
        if (list.length < 16) {
          list.push({ pIdx: pIdx, off: off });
        }
      }
    }
  }

  return {
    minLen: threshold,
    anchorLen: anchorLen,
    paragraphs: paragraphs,
    anchors: anchors
  };
}

function loadCorpusIdentities(opts) {
  opts = opts || {};
  const manifestPaths = Array.isArray(opts.manifestPaths)
    ? opts.manifestPaths
    : discoverDefaultManifestPaths(opts.siteRoot);

  const allManifestSlugs = new Set();
  const distinctiveIdentities = new Map(); // token -> { kind, source }
  const manifestIps = new Map(); // ip -> source
  const proseSources = [];

  function registerSlugOrName(raw, kind, source) {
    const tok = normalizeIdentityToken(raw);
    if (!tok || tok.length < 2) return;
    allManifestSlugs.add(tok);
    const compact = tok.replace(/[\s_-]+/g, '');
    if (compact.length >= 3) allManifestSlugs.add(compact);

    if (!COMMON_ENGLISH_AND_TECH_ALLOWLIST.has(tok) && tok.length >= 3) {
      if (!distinctiveIdentities.has(tok)) {
        distinctiveIdentities.set(tok, { kind: kind, source: source });
      }
    }
    if (compact !== tok && compact.length >= 4 && !COMMON_ENGLISH_AND_TECH_ALLOWLIST.has(compact)) {
      if (!distinctiveIdentities.has(compact)) {
        distinctiveIdentities.set(compact, { kind: kind, source: source });
      }
    }
  }

  function registerAuthorHandle(raw, source) {
    const handle = String(raw || '').trim().toLowerCase();
    if (!handle || handle.length < 4) return;
    if (COMMON_ENGLISH_AND_TECH_ALLOWLIST.has(handle)) return;
    if (!distinctiveIdentities.has(handle)) {
      distinctiveIdentities.set(handle, { kind: 'author_handle', source: source });
    }
  }

  function ingestManifestObject(doc, sourceLabel, manifestDir) {
    if (!doc) return;
    const list = Array.isArray(doc)
      ? doc
      : (Array.isArray(doc.walkthroughs) ? doc.walkthroughs
        : (Array.isArray(doc.labs) ? doc.labs
          : (Array.isArray(doc.boxes) ? doc.boxes : [])));

    if (!Array.isArray(doc) && Array.isArray(doc.upstream_repositories)) {
      for (const up of doc.upstream_repositories) {
        if (up && up.dir) {
          const base = path.basename(up.dir);
          const owner = base.split('-')[0];
          if (owner && owner.length >= 5) registerAuthorHandle(owner, sourceLabel);
        }
      }
    }

    for (const entry of list) {
      if (!entry || typeof entry !== 'object') continue;
      if (entry.slug) registerSlugOrName(entry.slug, 'box_slug', sourceLabel);
      if (entry.name) registerSlugOrName(entry.name, 'box_name', sourceLabel);
      if (entry.title) registerSlugOrName(entry.title, 'box_title', sourceLabel);
      if (entry.codename) registerSlugOrName(entry.codename, 'lab_codename', sourceLabel);
      if (Array.isArray(entry.hostnames)) {
        for (const hn of entry.hostnames) {
          registerSlugOrName(hn, 'lab_hostname', sourceLabel);
          const shortHn = String(hn || '').split('.')[0];
          if (shortHn) registerSlugOrName(shortHn, 'lab_hostname', sourceLabel);
        }
      }
      if (Array.isArray(entry.ips)) {
        for (const ip of entry.ips) {
          if (ip && !manifestIps.has(ip)) manifestIps.set(String(ip), sourceLabel);
        }
      } else if (entry.ip && !manifestIps.has(entry.ip)) {
        manifestIps.set(String(entry.ip), sourceLabel);
      }
      if (entry.winner_source && entry.winner_source.repo_id) {
        registerAuthorHandle(entry.winner_source.repo_id, sourceLabel);
      }
      if (Array.isArray(entry.all_sources_evaluated)) {
        for (const src of entry.all_sources_evaluated) {
          if (src && src.repo_id) registerAuthorHandle(src.repo_id, sourceLabel);
        }
      }
    }

    if (opts.loadProse !== false && manifestDir) {
      const wtDir = path.join(manifestDir, 'walkthroughs');
      if (fs.existsSync(wtDir) && fs.statSync(wtDir).isDirectory()) {
        for (const fn of fs.readdirSync(wtDir)) {
          if (!fn.endsWith('.md')) continue;
          const full = path.join(wtDir, fn);
          proseSources.push({
            source: sourceLabel + ':' + fn,
            markdown: fs.readFileSync(full, 'utf8')
          });
        }
      }
    }
  }

  for (const mp of manifestPaths) {
    try {
      const doc = JSON.parse(fs.readFileSync(mp, 'utf8'));
      ingestManifestObject(doc, path.basename(path.dirname(mp)), path.dirname(mp));
    } catch (_err) {
      // Ignore unreadable optional manifest
    }
  }

  if (Array.isArray(opts.manifests)) {
    opts.manifests.forEach((doc, idx) => {
      ingestManifestObject(doc, 'custom_manifest_' + idx, null);
    });
  }

  if (Array.isArray(opts.proseTexts)) {
    opts.proseTexts.forEach((txt, idx) => {
      proseSources.push(
        typeof txt === 'string'
          ? { source: 'custom_prose_' + idx, markdown: txt }
          : txt
      );
    });
  }

  const proseIndex = opts.loadProse === false
    ? buildProseIndex([], opts.minProseLen)
    : buildProseIndex(proseSources, opts.minProseLen);

  return {
    manifestPaths: manifestPaths,
    allManifestSlugs: allManifestSlugs,
    distinctiveIdentities: distinctiveIdentities,
    manifestIps: manifestIps,
    proseIndex: proseIndex
  };
}

function classifyRepoPath(relPath) {
  const norm = String(relPath || '').replace(/\\/g, '/').replace(/^\.\//, '');
  const checkIdentity = /^(?:assets|data|tests)\//.test(norm) && !/^tests\/corpus\//.test(norm);
  const checkProse = /^tests\//.test(norm) && !/^tests\/corpus\//.test(norm);
  const checkHouseStyle = /\.(?:js|json|md|html|css)$/i.test(norm)
    && !/^tests\/corpus\//.test(norm)
    && !/^tools\/corpus\/reports\//.test(norm);
  return {
    relPath: norm,
    checkIdentity: checkIdentity,
    checkProse: checkProse,
    checkHouseStyle: checkHouseStyle
  };
}

function scanHouseStyleLine(lineText, lineNum, relPath) {
  const violations = [];
  if (lineText.indexOf('\u2014') >= 0) {
    violations.push({
      rule: 'HOUSE_STYLE_VIOLATION',
      subtype: 'em_dash',
      file: relPath,
      line: lineNum,
      message: 'Em dash (\\u2014) is forbidden by house style'
    });
  }
  if (lineText.indexOf('\u2013') >= 0) {
    violations.push({
      rule: 'HOUSE_STYLE_VIOLATION',
      subtype: 'en_dash',
      file: relPath,
      line: lineNum,
      message: 'En dash (\\u2013) is forbidden by house style'
    });
  }
  if (EMOJI_RE.test(lineText)) {
    for (const ch of Array.from(lineText)) {
      if (EMOJI_RE.test(ch) && !COPYRIGHT_EXEMPT_RE.test(ch)) {
        violations.push({
          rule: 'HOUSE_STYLE_VIOLATION',
          subtype: 'decorative_emoji',
          file: relPath,
          line: lineNum,
          message: 'Decorative emoji (' + JSON.stringify(ch) + ') is forbidden by house style'
        });
        break;
      }
    }
  }
  return violations;
}

function findVerbatimProseLeak(text, proseIndex) {
  if (!proseIndex || !proseIndex.anchors || proseIndex.anchors.size === 0) return null;
  const norm = String(text || '').toLowerCase().replace(/\s+/g, ' ').trim();
  const minLen = proseIndex.minLen || 48;
  const anchorLen = proseIndex.anchorLen || 24;
  if (norm.length < minLen) return null;

  for (let i = 0; i + anchorLen <= norm.length; i++) {
    const key = norm.slice(i, i + anchorLen);
    const hits = proseIndex.anchors.get(key);
    if (!hits) continue;

    for (let h = 0; h < hits.length; h++) {
      const ref = hits[h];
      const para = proseIndex.paragraphs[ref.pIdx].text;
      let left = 0;
      while (i - left - 1 >= 0 && ref.off - left - 1 >= 0 && norm.charCodeAt(i - left - 1) === para.charCodeAt(ref.off - left - 1)) {
        left++;
      }
      let right = anchorLen;
      while (i + right < norm.length && ref.off + right < para.length && norm.charCodeAt(i + right) === para.charCodeAt(ref.off + right)) {
        right++;
      }
      const matchLen = left + right;
      if (matchLen >= minLen) {
        return {
          length: matchLen,
          source: proseIndex.paragraphs[ref.pIdx].source,
          snippet: norm.slice(i - left, i - left + Math.min(matchLen, 80))
        };
      }
    }
  }
  return null;
}

const EXPLICIT_BOX_PREFIX_RE = /\b(?:HTB|PG\s+Practice|PG\s+Play|Challenge\s+Lab)\s*:\s*([A-Za-z0-9_.-]{2,40})\b/gi;
const BOX_TLD_RE = /\b([A-Za-z0-9_-]{2,40})\.(?:htb|offsec|pg)\b/gi;
const QUOTED_LITERAL_RE = /['"`]([A-Za-z0-9_-]{2,40})['"`]/g;
const WORD_TOKEN_RE = /[A-Za-z0-9_-]{3,48}/g;
const IPV4_TOKEN_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

function scanTextForOverfit(content, opts) {
  opts = opts || {};
  const relPath = opts.relPath || 'inline.js';
  const scope = classifyRepoPath(relPath);
  const identities = opts.identities || {
    allManifestSlugs: new Set(),
    distinctiveIdentities: new Map(),
    manifestIps: new Map(),
    proseIndex: null
  };

  const lines = Array.isArray(content)
    ? content
    : String(content || '').split(/\r?\n/).map((text, idx) => ({ line: idx + 1, text: text }));

  const violations = [];

  for (const item of lines) {
    const ln = item.line;
    const txt = String(item.text || '');

    if (scope.checkHouseStyle) {
      violations.push(...scanHouseStyleLine(txt, ln, scope.relPath));
    }

    if (scope.checkIdentity) {
      // 1. Check explicit box qualifiers ("HTB: Access", "PG Practice: Vault", "access.htb")
      EXPLICIT_BOX_PREFIX_RE.lastIndex = 0;
      let pm;
      while ((pm = EXPLICIT_BOX_PREFIX_RE.exec(txt)) !== null) {
        const cand = pm[1].toLowerCase();
        if (identities.allManifestSlugs.has(cand) || identities.distinctiveIdentities.has(cand)) {
          violations.push({
            rule: 'SUSPICIOUS_BOX_LOOKUP_TABLE',
            subtype: 'explicit_box_qualifier',
            file: scope.relPath,
            line: ln,
            token: pm[0],
            message: 'Explicit walkthrough/box title reference (' + pm[0] + ') is forbidden'
          });
        }
      }

      BOX_TLD_RE.lastIndex = 0;
      let tm;
      while ((tm = BOX_TLD_RE.exec(txt)) !== null) {
        const hostLabel = tm[1].toLowerCase();
        if (identities.allManifestSlugs.has(hostLabel) || identities.distinctiveIdentities.has(hostLabel)) {
          violations.push({
            rule: 'HARDCODED_BOX_IDENTITY',
            subtype: 'corpus_box_domain',
            file: scope.relPath,
            line: ln,
            token: tm[0],
            message: 'Corpus box hostname (' + tm[0] + ') is forbidden in ' + scope.relPath
          });
        }
      }

      // 2. Check multi-slug lookup arrays/tables (>= 4 manifest slugs quoted on one line)
      const quotedSlugs = [];
      QUOTED_LITERAL_RE.lastIndex = 0;
      let qm;
      while ((qm = QUOTED_LITERAL_RE.exec(txt)) !== null) {
        const qLow = qm[1].toLowerCase();
        if (identities.allManifestSlugs.has(qLow) && quotedSlugs.indexOf(qLow) < 0) {
          quotedSlugs.push(qLow);
        }
      }
      if (quotedSlugs.length >= 4) {
        violations.push({
          rule: 'SUSPICIOUS_BOX_LOOKUP_TABLE',
          subtype: 'multi_slug_lookup_list',
          file: scope.relPath,
          line: ln,
          token: quotedSlugs.slice(0, 5).join(', '),
          message: 'Line contains ' + quotedSlugs.length + ' quoted corpus box slugs (' + quotedSlugs.slice(0, 5).join(', ') + ')'
        });
      }

      // 3. Check distinctive non-English box slugs, Challenge Lab codenames, and author handles
      WORD_TOKEN_RE.lastIndex = 0;
      let wm;
      while ((wm = WORD_TOKEN_RE.exec(txt)) !== null) {
        const rawTok = wm[0];
        const lowTok = rawTok.toLowerCase();
        const hit = identities.distinctiveIdentities.get(lowTok);
        if (hit) {
          violations.push({
            rule: 'HARDCODED_BOX_IDENTITY',
            subtype: hit.kind,
            file: scope.relPath,
            line: ln,
            token: rawTok,
            message: 'Distinctive corpus ' + hit.kind + ' (' + rawTok + ' from ' + hit.source + ') is forbidden in ' + scope.relPath
          });
        }
      }

      // 4. Check manifest-specific walkthrough IPs
      if (identities.manifestIps && identities.manifestIps.size > 0) {
        IPV4_TOKEN_RE.lastIndex = 0;
        let im;
        while ((im = IPV4_TOKEN_RE.exec(txt)) !== null) {
          const ipSrc = identities.manifestIps.get(im[0]);
          if (ipSrc) {
            violations.push({
              rule: 'HARDCODED_BOX_IDENTITY',
              subtype: 'walkthrough_ip',
              file: scope.relPath,
              line: ln,
              token: im[0],
              message: 'Manifest walkthrough IP (' + im[0] + ' from ' + ipSrc + ') is forbidden in ' + scope.relPath
            });
          }
        }
      }
    }

    if (scope.checkProse && txt.trim().length >= 48) {
      const leak = findVerbatimProseLeak(txt, identities.proseIndex);
      if (leak) {
        violations.push({
          rule: 'VERBATIM_WALKTHROUGH_PROSE',
          subtype: 'prose_substring',
          file: scope.relPath,
          line: ln,
          token: leak.snippet,
          message: 'Verbatim walkthrough prose substring (' + leak.length + ' chars from ' + leak.source + ') leaked into ' + scope.relPath
        });
      }
    }
  }

  // Also check multi-line prose leaks across adjacent lines in qa/tests/
  if (scope.checkProse && lines.length > 1) {
    const alreadyFlaggedProse = violations.some(v => v.rule === 'VERBATIM_WALKTHROUGH_PROSE');
    if (!alreadyFlaggedProse) {
      const combined = lines.map(l => l.text).join(' ');
      const leak = findVerbatimProseLeak(combined, identities.proseIndex);
      if (leak) {
        violations.push({
          rule: 'VERBATIM_WALKTHROUGH_PROSE',
          subtype: 'multiline_prose_substring',
          file: scope.relPath,
          line: lines[0].line,
          token: leak.snippet,
          message: 'Multi-line verbatim walkthrough prose substring (' + leak.length + ' chars from ' + leak.source + ') leaked into ' + scope.relPath
        });
      }
    }
  }

  return violations;
}

function parseUnifiedDiffAddedLines(diffText) {
  const byFile = new Map();
  let curFile = '';
  let curNewLine = 0;

  const lines = String(diffText || '').split(/\r?\n/);
  for (const ln of lines) {
    if (ln.startsWith('+++ b/')) {
      curFile = ln.slice(6).trim();
      if (!byFile.has(curFile)) byFile.set(curFile, []);
      continue;
    }
    if (ln.startsWith('+++ /dev/null')) {
      curFile = '';
      continue;
    }
    const hm = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(ln);
    if (hm) {
      curNewLine = parseInt(hm[1], 10);
      continue;
    }
    if (!curFile) continue;
    if (ln.startsWith('+') && !ln.startsWith('+++')) {
      byFile.get(curFile).push({
        line: curNewLine,
        text: ln.slice(1)
      });
      curNewLine++;
    } else if (!ln.startsWith('-') && !ln.startsWith('\\')) {
      curNewLine++;
    }
  }
  return byFile;
}

// Generated single-line bundle build artifacts compiled from data/packs/*.json and data/playbooks/*.json.
// Skipped in git-diff mode ONLY because re-serializing a 1-line bundle marks all pre-existing untouched
// packs as a single added line while their authored JSON sources are already scanned line-by-line in the
// same git diff. (--files and --all still scan them when explicitly requested.)
const GENERATED_SINGLE_LINE_BUNDLES = new Set([
  'data/packs-bundle.js',
  'data/flag-reach.js',
  'data/playbooks-bundle.js'
]);

function collectGitDiffTargets(qaRoot, baseRef) {
  const targets = new Map();
  const ref = baseRef || 'HEAD';
  const diffOut = execFileSync('git', ['diff', '--unified=0', ref], {
    cwd: qaRoot,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'ignore']
  });
  const parsed = parseUnifiedDiffAddedLines(diffOut);
  for (const [rel, addedLines] of parsed.entries()) {
    const normRel = rel.replace(/\\/g, '/').replace(/^\.\//, '');
    if (GENERATED_SINGLE_LINE_BUNDLES.has(normRel)) continue;
    if (addedLines.length > 0) targets.set(normRel, addedLines);
  }

  const untrackedOut = execFileSync('git', ['ls-files', '--others', '--exclude-standard'], {
    cwd: qaRoot,
    encoding: 'utf8'
  });
  for (const rel of untrackedOut.split(/\r?\n/).map(s => s.trim()).filter(Boolean)) {
    const normRel = rel.replace(/\\/g, '/').replace(/^\.\//, '');
    if (GENERATED_SINGLE_LINE_BUNDLES.has(normRel)) continue;
    const abs = path.join(qaRoot, rel);
    if (!fs.existsSync(abs) || fs.statSync(abs).isDirectory()) continue;
    if (!/\.(?:js|json|md|html|css)$/i.test(rel)) continue;
    const content = fs.readFileSync(abs, 'utf8');
    const allLines = content.split(/\r?\n/).map((text, idx) => ({ line: idx + 1, text: text }));
    targets.set(normRel, allLines);
  }

  return targets;
}

function walkRepoFiles(qaRoot, subdirs) {
  const out = [];
  for (const sub of subdirs) {
    const start = path.join(qaRoot, sub);
    if (!fs.existsSync(start)) continue;
    const stack = [start];
    while (stack.length) {
      const cur = stack.pop();
      const stat = fs.statSync(cur);
      if (stat.isDirectory()) {
        if (path.basename(cur) === 'corpus' || path.basename(cur) === 'node_modules') continue;
        for (const child of fs.readdirSync(cur)) {
          stack.push(path.join(cur, child));
        }
      } else if (/\.(?:js|json|md|html|css)$/i.test(cur)) {
        out.push(path.relative(qaRoot, cur).replace(/\\/g, '/'));
      }
    }
  }
  return out.sort();
}

function runVerifyNoOverfit(opts) {
  opts = opts || {};
  const qaRoot = opts.qaRoot ? path.resolve(opts.qaRoot) : QA_ROOT;
  const identities = opts.identities || loadCorpusIdentities({
    siteRoot: opts.siteRoot,
    manifestPaths: opts.manifestPaths,
    manifests: opts.manifests,
    proseTexts: opts.proseTexts,
    minProseLen: opts.minProseLen
  });

  const violations = [];
  let scannedFiles = 0;
  let scannedLines = 0;

  if (Array.isArray(opts.files) && opts.files.length > 0) {
    for (const f of opts.files) {
      const abs = path.isAbsolute(f) ? f : path.join(qaRoot, f);
      if (!fs.existsSync(abs) || fs.statSync(abs).isDirectory()) continue;
      const rel = path.relative(qaRoot, abs).replace(/\\/g, '/');
      const content = fs.readFileSync(abs, 'utf8');
      const lineObjs = content.split(/\r?\n/).map((text, idx) => ({ line: idx + 1, text: text }));
      scannedFiles++;
      scannedLines += lineObjs.length;
      violations.push(...scanTextForOverfit(lineObjs, { relPath: rel, identities: identities }));
    }
  } else if (opts.all) {
    const relFiles = walkRepoFiles(qaRoot, ['assets', 'data', 'tests']);
    for (const rel of relFiles) {
      const abs = path.join(qaRoot, rel);
      const content = fs.readFileSync(abs, 'utf8');
      const lineObjs = content.split(/\r?\n/).map((text, idx) => ({ line: idx + 1, text: text }));
      scannedFiles++;
      scannedLines += lineObjs.length;
      violations.push(...scanTextForOverfit(lineObjs, { relPath: rel, identities: identities }));
    }
  } else {
    const diffTargets = collectGitDiffTargets(qaRoot, opts.baseRef || 'HEAD');
    for (const [rel, lineObjs] of diffTargets.entries()) {
      scannedFiles++;
      scannedLines += lineObjs.length;
      violations.push(...scanTextForOverfit(lineObjs, { relPath: rel, identities: identities }));
    }
  }

  return {
    ok: violations.length === 0,
    manifests_loaded: identities.manifestPaths.length,
    distinctive_identities_loaded: identities.distinctiveIdentities.size,
    manifest_slugs_loaded: identities.allManifestSlugs.size,
    prose_paragraphs_indexed: identities.proseIndex ? identities.proseIndex.paragraphs.length : 0,
    scanned_files: scannedFiles,
    scanned_lines: scannedLines,
    violation_count: violations.length,
    violations: violations
  };
}

function parseCliArgs(argv) {
  const opts = {
    all: false,
    files: [],
    baseRef: 'HEAD',
    minProseLen: 48,
    json: false
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--all') opts.all = true;
    else if (a === '--json') opts.json = true;
    else if (a === '--base' && argv[i + 1]) opts.baseRef = argv[++i];
    else if (a === '--min-prose' && argv[i + 1]) opts.minProseLen = parseInt(argv[++i], 10) || 48;
    else if (a === '--files' && argv[i + 1]) {
      opts.files = argv[++i].split(',').map(s => s.trim()).filter(Boolean);
    }
  }
  return opts;
}

function main() {
  const opts = parseCliArgs(process.argv.slice(2));
  const result = runVerifyNoOverfit(opts);

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(
      'verify-no-overfit: manifests=' + result.manifests_loaded +
      ', distinctive_identities=' + result.distinctive_identities_loaded +
      ', prose_paragraphs=' + result.prose_paragraphs_indexed +
      ', scanned_files=' + result.scanned_files +
      ', scanned_lines=' + result.scanned_lines
    );
    if (result.ok) {
      console.log('verify-no-overfit: CLEAN (0 violations)');
    } else {
      console.error('verify-no-overfit: FAILED (' + result.violation_count + ' violation(s)):');
      for (const v of result.violations.slice(0, 50)) {
        console.error('  [' + v.rule + '] ' + v.file + ':' + v.line + ' - ' + v.message);
      }
    }
  }

  process.exit(result.ok ? 0 : 1);
}

if (require.main === module) {
  main();
}

module.exports = {
  COMMON_ENGLISH_AND_TECH_ALLOWLIST: COMMON_ENGLISH_AND_TECH_ALLOWLIST,
  stripCodeAndMarkupToProseParagraphs: stripCodeAndMarkupToProseParagraphs,
  buildProseIndex: buildProseIndex,
  loadCorpusIdentities: loadCorpusIdentities,
  scanHouseStyleLine: scanHouseStyleLine,
  findVerbatimProseLeak: findVerbatimProseLeak,
  scanTextForOverfit: scanTextForOverfit,
  runVerifyNoOverfit: runVerifyNoOverfit
};
