/* HTTP reachability from a returned response body (facts axis). A curl/wget fetch, a proxychains
 * tunneled fetch, or a PowerShell Invoke-WebRequest wrapper can prove a host answered over HTTP even
 * when the pasted output carries no status line and no Server header: the body itself (an HTML
 * document, or an "HTTP Error <code>" wrapper line) is the evidence. services.js _parse_http_metadata
 * now mints http.reachable for that shape, guarded so a name resolution or connection failure (which
 * returns no body) stays unreachable. This test is corpus-independent (hand-built shapes, no verbatim
 * corpus output) so it holds the parser logic where the 0xdf snapshot is absent. House style: no em or
 * en dashes. qa-only; nothing here ships. */
'use strict';
var path = require('path');
var R = path.join(__dirname, '..', '..');
function req(p) { return require(path.join(R, p)); }
req('assets/engine/facts.js'); req('assets/engine/phases.js'); req('assets/engine/pack.js');
req('assets/engine/profile.js'); req('assets/engine/command.js'); req('assets/engine/workspace.js');
var OBOL = globalThis.OBOL;
req('assets/engine/parsers/common.js');
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'shape', 'pivot', 'dns', 'blockers', 'nxc-catalog'].forEach(function (m) { req('assets/engine/parsers/' + m + '.js'); });
req('assets/engine/parsers/index.js');

var fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }
function kinds(cmd, out) {
  var r = OBOL.parsers.parseActionOutput({ actionId: '', command: cmd, stdout: out, scope: 'host:172.20.144.1', domain: '' });
  return (r.facts || []).map(function (f) { return f.kind; });
}
function reachable(cmd, out) { return kinds(cmd, out).indexOf('http.reachable') >= 0; }

// ---- true positives: a body came back, so the host answered over HTTP ----
var iwr404 = 'curl : The remote server returned an error: (404) Not Found.\n' +
  'At line:1 char:1\n' +
  '+ curl 172.20.144.1\n' +
  'FullyQualifiedErrorId : WebCmdletWebResponseException\n' +
  '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN">\n' +
  '<HTML><HEAD><TITLE>Not Found</TITLE></HEAD>\n' +
  '<BODY><p>HTTP Error 404. The requested resource is not found.</p></BODY></HTML>';
ok(reachable('curl 172.20.144.1', iwr404),
  'a PowerShell Invoke-WebRequest 404 wrapper (HTML body + "HTTP Error 404") mints http.reachable');

var proxied200 = 'ProxyChains-3.1 (http://proxychains.sf.net)\n' +
  '|S-chain|-<>-127.0.0.1:1080-<><>-172.20.144.1:80-<><>-OK\n' +
  '<!DOCTYPE html>\n<html lang="en"><head><title>Software Portal</title></head>\n' +
  '<body><h1>Welcome</h1></body></html>';
ok(reachable('proxychains curl softwareportal.windcorp.htb', proxied200),
  'a proxychains tunneled curl returning an HTML page mints http.reachable');

var cleanHtml = 'curl http://172.20.144.1/\n<!DOCTYPE html>\n<html><head><title>Index</title></head><body>ok</body></html>';
ok(reachable('curl http://172.20.144.1/', cleanHtml),
  'a plain curl that returns an HTML document mints http.reachable even with no status line');

// ---- unchanged paths still work (a real status line / Server header) ----
ok(reachable('curl -i http://172.20.144.1/', 'HTTP/1.1 200 OK\nServer: nginx/1.18.0\nContent-Type: text/html\n\n<html></html>'),
  'a real HTTP status line still mints http.reachable (existing path intact)');

// ---- false positives: a transport failure returns no body, so NOT reachable ----
var dnsFail = 'curl : The remote name could not be resolved: \'softwareportal.windcorp.htb\'\n' +
  'At line:1 char:1\n+ curl softwareportal.windcorp.htb\nFullyQualifiedErrorId : WebCmdletWebResponseException';
ok(!reachable('curl softwareportal.windcorp.htb', dnsFail),
  'a name resolution failure (no body) does NOT mint http.reachable');

ok(!reachable('curl http://172.20.144.1/', 'curl: (7) Failed to connect to 172.20.144.1 port 80: Connection refused'),
  'a connection refused (no body) does NOT mint http.reachable');

ok(!reachable('curl http://172.20.144.1/', 'curl: (28) Connection timed out after 5001 milliseconds'),
  'a connection timeout (no body) does NOT mint http.reachable');

console.log('\nHTTP-REACHABLE-BODY SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
