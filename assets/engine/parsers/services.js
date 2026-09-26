/*!
 * obol engine — parsers/services.js
 * Faithful JS port of obol-local/obol/parsers/services.py.
 * Generic service metadata: HTTP, SSH, FTP, SNMP — reachability/fingerprints only.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var C = OBOL._parserCommon;
  var mkFact = C.mkFact, _add = C._add, S = C.ProofState.SUPPORTED;
  var reAll = C.reAll, reSearch = C.reSearch;

  function _parse_http_metadata(text, ws, source, facts) {
    var h = 'host:' + ws.target;
    C._add_os_from_text(text, ws, source, facts, 'http', 'medium', false);
    var statusValues = [];
    reAll(C._HTTP_STATUS_RE, text).forEach(function (m) {
      var value = { status: parseInt(m.groups.status, 10) };
      var reason = (m.groups.reason || '').trim();
      if (reason) value.reason = reason;
      statusValues.push(value);
    });
    if (statusValues.length) {
      _add(facts, mkFact('http.reachable', h, { tool: 'http-client' }, S, source));
      _add(facts, mkFact('http.response', h, { responses: statusValues.slice(0, 10) }, S, source));
    }
    var servers = {}, redirects = {}, contentTypes = {}, tech = [];
    reAll(C._HTTP_HEADER_RE, text).forEach(function (m) {
      var key = m.groups.key.toLowerCase(), value = m.groups.value.trim();
      if (!value) return;
      if (key === 'server') servers[value] = true;
      else if (key === 'x-powered-by') tech.push({ name: 'x-powered-by', value: value });
      else if (key === 'location') redirects[value] = true;
      else if (key === 'content-type') contentTypes[value] = true;
    });
    reAll(C._WHATWEB_PLUGIN_RE, text).forEach(function (m) {
      var name = m.groups.name.trim(), value = m.groups.value.trim();
      var nl = name.toLowerCase();
      if (['title', 'ip', 'country', 'email', 'summary'].indexOf(nl) >= 0) return;
      if (nl === 'httpserver' || nl === 'server') servers[value] = true;
      else tech.push({ name: name, value: value });
    });
    var titleMatch = /\bTitle\[(?<title>[^\]\r\n]+)\]/.exec(text);
    if (titleMatch && titleMatch.groups.title.trim()) _add(facts, mkFact('web.title', h, { titles: [titleMatch.groups.title.trim()] }, S, source));
    if (Object.keys(servers).length) _add(facts, mkFact('web.server', h, { headers: C.uniqueSortedCI(Object.keys(servers)).slice(0, 10) }, S, source));
    if (Object.keys(redirects).length) _add(facts, mkFact('http.redirect', h, { locations: C.uniqueSortedCI(Object.keys(redirects)).slice(0, 10) }, S, source));
    if (Object.keys(contentTypes).length) C.uniqueSortedCI(Object.keys(contentTypes)).forEach(function (item) { tech.push({ name: 'content-type', value: item }); });
    if (tech.length) {
      var dedup = [], seen = {};
      tech.forEach(function (item) {
        var key = item.name.toLowerCase() + '|' + item.value.toLowerCase();
        if (seen[key]) return;
        seen[key] = true;
        dedup.push(item);
      });
      _add(facts, mkFact('web.tech', h, { items: dedup.slice(0, 20) }, S, source));
    }
  }
  C._parse_http_metadata = _parse_http_metadata;

  function _parse_ssh_banner(text, ws, source, facts) {
    var banners = C.uniqueSortedCI(reAll(C._SSH_BANNER_RE, text).map(function (m) { return m[0].trim(); }));
    if (!banners.length) return;
    C._add_os_from_text(banners.join('\n'), ws, source, facts, 'ssh', 'medium', false);
    _add(facts, mkFact('ssh.reachable', 'host:' + ws.target, { tool: 'banner' }, S, source));
    _add(facts, mkFact('ssh.banner', 'host:' + ws.target, { banners: banners.slice(0, 10) }, S, source));
  }
  C._parse_ssh_banner = _parse_ssh_banner;

  function _parse_ftp_output(text, ws, command, source, facts) {
    var banners = [], loginSuccess = false;
    reAll(C._FTP_BANNER_RE, text).forEach(function (m) {
      var banner = (m.groups.banner || m.groups.login || '').trim();
      if (banner) banners.push(banner);
      if (m.groups.login) loginSuccess = true;
    });
    if (!banners.length && !loginSuccess) return;
    var h = 'host:' + ws.target;
    _add(facts, mkFact('ftp.reachable', h, { tool: 'ftp-client' }, S, source));
    if (banners.length) _add(facts, mkFact('ftp.banner', h, { banners: C.uniqueSortedCI(banners).slice(0, 10) }, S, source));
    if (loginSuccess && /\banonymous\b/i.test(command)) _add(facts, mkFact('ftp.anonymous_login', h, { tool: 'ftp-client' }, S, source));
  }
  C._parse_ftp_output = _parse_ftp_output;

  function _parse_snmp_output(text, ws, command, source, facts) {
    var lowered = text.toLowerCase();
    if (['timeout', 'no response from', 'authorizationerror', 'authentication failure'].some(function (m) { return lowered.indexOf(m) >= 0; })) return;
    if (lowered.indexOf('snmpv2-mib::') < 0 && !/\[[^\]]+\]\s+\S/.test(text)) return;
    var h = 'host:' + ws.target, value = {};
    [['description', C._SNMP_SYSDESCR_RE], ['name', C._SNMP_SYSNAME_RE], ['location', C._SNMP_SYSLOCATION_RE], ['contact', C._SNMP_SYSCONTACT_RE]].forEach(function (pair) {
      var m = reSearch(pair[1], text);
      if (m) value[pair[0]] = C.stripChars(m.groups.value.trim(), '"');
    });
    var community = C._command_arg(command, ['-c', '--community']);
    if (!community) {
      var one = /\[(?<community>[^\]]+)\]\s+(?<description>.+)/.exec(text);
      if (one) {
        community = one.groups.community.trim();
        if (value.description === undefined) value.description = one.groups.description.trim();
      }
    }
    if (community) _add(facts, mkFact('snmp.community', h, { community: community }, S, source));
    _add(facts, mkFact('snmp.reachable', h, { tool: 'snmp' }, S, source));
    if (Object.keys(value).length) {
      _add(facts, mkFact('snmp.info', h, value, S, source));
      C._add_os_from_text(Object.keys(value).map(function (k) { return String(value[k]); }).join('\n'), ws, source, facts, 'snmp', 'high', true);
      if (value.name) _add(facts, mkFact('host.hostname', h, { name: value.name }, S, source));
    }
  }
  C._parse_snmp_output = _parse_snmp_output;

})(typeof globalThis !== 'undefined' ? globalThis : this);
