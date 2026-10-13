/*!
 * obol engine — parsers/findings.js  (findings-lens checks)
 *
 * The "checks" lane and a few recon observations produce report-grade facts that no other parser
 * minted, so the decision map's parser-cover lens flagged them as parse gaps. These recognizers read
 * the posture out of standard tool output (curl -I, OPTIONS, dig, ffuf vhost) and mint one conservative
 * finding fact each. They are content-gated: an unrelated paste mints nothing. See docs/DECISION-MAP.md.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var C = OBOL._parserCommon;
  var mkFact = C.mkFact, _add = C._add, S = C.ProofState.SUPPORTED;
  var reSearch = C.reSearch, reAll = C.reAll;
  function h(ws) { return 'host:' + ws.target; }

  // check-web-headers: a curl -I / header scan. Record which security headers are present vs missing.
  function _parse_http_headers(text, ws, source, facts) {
    if (!/HTTP\/\d/i.test(text)) return;
    var want = { 'strict-transport-security': 'HSTS', 'content-security-policy': 'CSP', 'x-frame-options': 'X-Frame-Options', 'x-content-type-options': 'X-Content-Type-Options', 'referrer-policy': 'Referrer-Policy' };
    var low = text.toLowerCase(), missing = [], present = [];
    Object.keys(want).forEach(function (k) { (low.indexOf(k + ':') >= 0 ? present : missing).push(want[k]); });
    var srv = reSearch(/^server:\s*(.+)$/im, text);
    _add(facts, mkFact('http.headers', h(ws), { missing: missing, present: present, server: srv ? srv[1].trim() : '' }, S, source));
  }
  C._parse_http_headers = _parse_http_headers;

  // check-http-methods: the OPTIONS Allow / Public header. Flag the state-changing verbs.
  function _parse_http_methods(text, ws, source, facts) {
    var m = reSearch(/^\s*allow:\s*(.+)$/im, text) || reSearch(/^\s*public:\s*(.+)$/im, text);
    if (!m) return;
    var methods = m[1].split(',').map(function (x) { return x.trim().toUpperCase(); }).filter(Boolean);
    var risky = methods.filter(function (x) { return ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH'].indexOf(x) >= 0; });
    _add(facts, mkFact('http.methods', h(ws), { methods: methods, risky: risky }, S, source));
  }
  C._parse_http_methods = _parse_http_methods;

  // check-cors: Access-Control-Allow-Origin, misconfigured when it reflects a supplied origin, is null,
  // or is * together with Allow-Credentials.
  function _parse_http_cors(text, ws, source, facts) {
    var acao = reSearch(/access-control-allow-origin:\s*(.+)/i, text);
    if (!acao) return;
    var origin = acao[1].trim(), creds = /access-control-allow-credentials:\s*true/i.test(text);
    var bad = /evil\.example|^null$/i.test(origin) || (origin === '*' && creds);
    _add(facts, mkFact('http.cors', h(ws), { origin: origin, credentials: creds, misconfigured: !!bad }, S, source));
  }
  C._parse_http_cors = _parse_http_cors;

  // check-web-body: a comment or inline token in the page body that leaks a secret or a lead.
  var _BODY_LEAK = /<!--[^>]*(?:password|passwd|todo|fixme|api[_-]?key|secret|backup|debug|credential)[^>]*-->|(?:api[_-]?key|secret|password)\s*[:=]\s*['"][^'"]{4,}['"]/i;
  function _parse_http_body(text, ws, source, facts) {
    var m = reSearch(_BODY_LEAK, text);
    if (!m) return;
    _add(facts, mkFact('http.body', h(ws), { lead: m[0].slice(0, 160) }, S, source));
  }
  C._parse_http_body = _parse_http_body;

  // check-exposed-files: a readable sensitive artifact (a git repo, an env file, an IIS config, a key).
  function _parse_http_exposed(text, ws, source, facts) {
    var hits = [];
    if (/ref:\s*refs\/heads\//i.test(text) || /\[core\][\s\S]{0,60}repositoryformatversion/i.test(text)) hits.push('.git');
    if (/^[A-Z][A-Z0-9_]*=\S/m.test(text) && /(DB_|APP_|SECRET|PASSWORD|API_|AWS_)/i.test(text)) hits.push('.env');
    if (/<configuration>[\s\S]*<\/configuration>|connectionString\s*=/i.test(text)) hits.push('web.config');
    if (/-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----/.test(text)) hits.push('private-key');
    if (hits.length) _add(facts, mkFact('http.exposed', h(ws), { files: hits.filter(function (v, i, a) { return a.indexOf(v) === i; }) }, S, source));
  }
  C._parse_http_exposed = _parse_http_exposed;

  // recon-dns: a successful zone transfer (AXFR) returns the records, so mint the hosts it leaks.
  function _parse_dns_zone(text, ws, source, facts) {
    if (/transfer failed|connection timed out|communications error|XFR size: 0|; Transfer failed/i.test(text)) return;
    var recs = reAll(/^(\S+?)\.?\s+\d+\s+IN\s+(A|AAAA|NS|MX|CNAME|TXT|SRV|PTR)\s+/gim, text);
    if (/\bIN\s+SOA\b/i.test(text) && recs.length >= 2) {
      var hosts = {};
      recs.forEach(function (m) { if (['A', 'AAAA', 'CNAME'].indexOf(m[2]) >= 0) hosts[m[1].toLowerCase()] = 1; });
      _add(facts, mkFact('dns.zone', C._scope_for_domain(ws), { records: recs.length, hosts: Object.keys(hosts).slice(0, 40) }, S, source));
    }
  }
  C._parse_dns_zone = _parse_dns_zone;

  // check-dns-email: SPF / DMARC posture, weak when the policy does not actually enforce.
  function _parse_dns_email(text, ws, source, facts) {
    var spf = /v=spf1/i.test(text), dmarc = /v=DMARC1/i.test(text);
    if (!spf && !dmarc) return;
    var weak = (spf && /[?~]all/i.test(text) && !/-all/i.test(text)) || (dmarc && /p=none/i.test(text));
    _add(facts, mkFact('dns.email', C._scope_for_domain(ws), { spf: spf, dmarc: dmarc, weak: weak }, S, source));
  }
  C._parse_dns_email = _parse_dns_email;

  // check-subdomain-takeover: a dangling CNAME plus a takeover fingerprint from the target service.
  var _TAKEOVER = /NoSuchBucket|There isn't a GitHub Pages site here|No such app|herokucdn\.com\/error|Fastly error: unknown domain|The specified bucket does not exist|Domain uses DO name servers with no records|Repository not found|NXDOMAIN/i;
  function _parse_dns_takeover(text, ws, source, facts) {
    var fp = reSearch(_TAKEOVER, text);
    if (!fp) return;
    var c = reSearch(/CNAME\s+(\S+)/i, text) || reSearch(/(\S+\.(?:s3\.amazonaws\.com|github\.io|herokuapp\.com|azurewebsites\.net|cloudfront\.net|fastly\.net))/i, text);
    _add(facts, mkFact('dns.takeover', C._scope_for_domain(ws), { target: c ? c[1].replace(/\.$/, '') : '', fingerprint: fp[0] }, S, source));
  }
  C._parse_dns_takeover = _parse_dns_takeover;

  // vhost-discovery: a discovered virtual host (ffuf / gobuster vhost) that returns a real page.
  function _parse_vhost(text, ws, source, facts) {
    var hosts = {};
    reAll(/Found:\s+(\S+?)\s/gi, text).forEach(function (m) { hosts[m[1].toLowerCase()] = 1; });
    reAll(/^\s*(\S+?)\s+\[Status:\s*(?:200|301|302|401|403)/gim, text).forEach(function (m) { hosts[m[1].toLowerCase()] = 1; });
    var list = Object.keys(hosts).filter(function (x) { return x && x.toUpperCase() !== 'FUZZ'; });
    if (list.length) _add(facts, mkFact('web.vhost', h(ws), { vhosts: list.slice(0, 20) }, S, source));
  }
  C._parse_vhost = _parse_vhost;

  // check-tls-config: sslscan / testssl / nmap ssl-enum-ciphers. Record the weak protocols, weak
  // ciphers, and certificate problems that make a reportable finding.
  function _parse_tls_info(text, ws, source, facts) {
    if (!/ssl|tls|cipher|certificat|heartbleed/i.test(text)) return;
    var weakProto = [];
    ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLS 1.0', 'TLSv1.1', 'TLS 1.1'].forEach(function (p) {
      var re = new RegExp(p.replace('.', '\\.') + '[^\\n]*\\b(enabled|offered|supported)\\b', 'i');
      if (re.test(text) || new RegExp('(enabled|offered|accepted)[^\\n]*' + p.replace('.', '\\.'), 'i').test(text)) weakProto.push(p);
    });
    var heartbleed = /heartbleed|CVE-2014-0160/i.test(text) && !/not vulnerable/i.test(text);
    var weakCipher = /\b(RC4|DES|3DES|EXPORT|NULL|MD5|anon)\b[^\n]*\b(accepted|enabled|offered|preferred)\b/i.test(text) || /Weak cipher|CBC/i.test(text) && /SSLv3|TLSv1\.0/i.test(text);
    var certBad = /self.signed|certificate has expired|not valid after|expired!|NotAfter.*20(1[0-9]|2[0-3])/i.test(text);
    if (weakProto.length || heartbleed || weakCipher || certBad) {
      _add(facts, mkFact('tls.info', h(ws), { weak_protocols: weakProto, heartbleed: !!heartbleed, weak_ciphers: !!weakCipher, cert_issue: !!certBad }, S, source));
    }
  }
  C._parse_tls_info = _parse_tls_info;

  // NOTE: SSRF to a cloud metadata endpoint is deliberately NOT minted as cloud.aws_access. The parser
  // corpus forbids it (web_ssrf_imds_cloud_credentials anti-overclaim): a key printed in IMDS output is
  // not proof of usable cloud access under obol's proof discipline, so cloud.aws_access is not a fact
  // obol recognizes, and it is not in any move's produces.

})(typeof globalThis !== 'undefined' ? globalThis : this);
