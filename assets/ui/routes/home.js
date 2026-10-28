/*!
 * obol ui - routes/home.js - THE ENGAGEMENT HUB (command center & launchpad).
 * Two distinct lifecycle modes:
 *   1. Pre-Engagement (!configured) -> Clean single-screen Launchpad (Platform, Scope, Box Settings).
 *   2. Active Engagement (configured) -> Unified Mission Header + 2-Column Operations Grid:
 *        - Left Column: Collapsible Target Rows & Attack Paths (capped at 10, with inline Bulk Nmap/IP Import)
 *        - Right Column: Clear-Interior Workspace + Pivot Connectivity + Recent Activity
 *      Engagement Library, In-Place Run Editor, and New Engagement Setup live in top command bar drawers.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }

  var _tunnelSel = 'ligolo';
  var _ptrSym = null;
  var _showNewSetup = false;
  var _showEditRun = false;
  var _showBulkTarget = false;
  var _targetFilter = 'all';
  var _lastEngId = null;

  function troubleKey() { var e = OBOL.store.active() || {}; return 'obol.pivotTrouble:' + (e.id || 'x'); }
  function troubleOn() { try { return localStorage.getItem(troubleKey()) === '1'; } catch (e) { return false; } }
  function setTrouble(on) { try { if (on) localStorage.setItem(troubleKey(), '1'); else localStorage.removeItem(troubleKey()); } catch (e) {} }

  // Extract IPs and CIDRs from arbitrary pasted text.
  var IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\b/g;
  function isValidIp(v) {
    var parts = String(v || '').split('/');
    if (parts.length > 2) return false;
    var base = parts[0];
    var octs = base.split('.');
    if (octs.length !== 4) return false;
    if (!octs.every(function (o) { return /^\d+$/.test(o) && +o >= 0 && +o <= 255; })) return false;
    if (parts.length === 2) {
      if (!/^\d{1,2}$/.test(parts[1])) return false;
      var mask = +parts[1];
      if (mask < 0 || mask > 32) return false;
    }
    return true;
  }
  function isIgnoredSelfOrBroadcast(ip, lhost) {
    var base = String(ip || '').split('/')[0];
    if (!base) return true;
    var octs = base.split('.').map(Number);
    if (base === '0.0.0.0' || base === '255.255.255.255' || octs[0] === 127 || octs[0] === 255 || octs[0] === 0) return true;
    if (octs[0] === 169 && octs[1] === 254) return true;
    if (lhost && base === lhost) return true;
    return false;
  }
  function extractScope(text, lhost) {
    text = String(text || '').replace(/\bhttps?:\/\/([^\s\/:]+)(?::\d+)?(?:\/[^\s]*)?/gi, '$1').replace(/\b((?:\d{1,3}\.){3}\d{1,3}):\d+(?:\/[^\s]*)?/g, '$1');
    var out = [], m, seen = {};
    IP_RE.lastIndex = 0;
    while ((m = IP_RE.exec(text || '')) !== null) {
      var v = m[0];
      // Ignore SNMP OIDs and 5+ segment dotted numbers like 1.3.6.1.2.1
      var before = m.index > 0 ? text.charAt(m.index - 1) : '';
      var after = text.charAt(m.index + v.length) || '';
      if (before === '.' || after === '.' || /[\/A-Za-z_-]/.test(before)) continue;
      if (isValidIp(v) && !isIgnoredSelfOrBroadcast(v, lhost) && !seen[v]) {
        seen[v] = 1;
        out.push(v);
      }
    }
    return out;
  }
  function isCidr(s) { return s.indexOf('/') >= 0; }

  function expandSmallCidr(cidr, lhost) {
    var parts = String(cidr || '').split('/');
    if (parts.length !== 2) return [];
    var mask = parseInt(parts[1], 10);
    if (isNaN(mask) || mask < 28 || mask > 32) return [];
    var octs = parts[0].split('.').map(Number);
    var baseInt = ((octs[0] << 24) | (octs[1] << 16) | (octs[2] << 8) | octs[3]) >>> 0;
    if (mask === 32) return isIgnoredSelfOrBroadcast(parts[0], lhost) ? [] : [parts[0]];
    var count = 1 << (32 - mask);
    var netInt = (baseInt & (~(count - 1) >>> 0)) >>> 0;
    var out = [];
    for (var i = 1; i < count - 1; i++) {
      var n = (netInt + i) >>> 0;
      var ip = [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
      if (!isIgnoredSelfOrBroadcast(ip, lhost)) out.push(ip);
    }
    return out;
  }

  // Smart Bulk Target / Nmap / /etc/hosts / CIDR parser shared by the Hub and the Targets tab.
  var NOISE_HOST_WORDS = {
    junk: 1, open: 1, closed: 1, filtered: 1, tcp: 1, udp: 1, host: 1, is: 1, up: 1, down: 1,
    status: 1, ports: 1, ignored: 1, states: 1, nmap: 1, scan: 1, report: 1, for: 1, latency: 1,
    seconds: 1, raw: 1, packets: 1, syn: 1, stealth: 1, service: 1, version: 1, starting: 1,
  };
  function cleanHostToken(tok) {
    tok = String(tok || '').trim().replace(/^[(\["']+|[)\]"',;:]+$/g, '');
    tok = tok.replace(/^https?:\/\//i, '').replace(/(?::\d+)?(?:\/.*)?$/, '');
    if (!tok || tok.length < 2 || tok.length > 90) return '';
    if (/^\d+$/.test(tok) || isValidIp(tok) || /[\/\\:]/.test(tok)) return '';
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]$/.test(tok)) return '';
    if (NOISE_HOST_WORDS[tok.toLowerCase()]) return '';
    return tok;
  }
  function parseBulkInput(text, lhost) {
    text = String(text || '');
    var isNmapScan = /Nmap scan report for|<nmaprun\b|^\s*\d+\/(?:tcp|udp)\s+open\b|\bPorts:\s+\d+\/open\//im.test(text);
    var isOtherToolScan = /^\s*(?:SMB|WINRM|SSH|LDAP|WMI|MSSQL|RDP|FTP)\s+(?:\d{1,3}\.){3}\d{1,3}\s+\d+\b|={3,}\s*OBOL STEP\s+\d+:|\benum4linux\b|Discovered open port\s+\d+\/|(?:\d{1,3}\.){3}\d{1,3}\s+is alive/im.test(text)
      || !!(OBOL.ingest && typeof OBOL.ingest.recognizesTool === 'function' && OBOL.ingest.recognizesTool('', text));
    var hasScanOutput = isNmapScan || isOtherToolScan;
    var hostMap = {};
    var scanIps = [], scanIpSeen = {};
    function pushScanIp(ip, hn) {
      if (!isValidIp(ip) || isCidr(ip) || isIgnoredSelfOrBroadcast(ip, lhost)) return;
      if (!scanIpSeen[ip]) { scanIpSeen[ip] = 1; scanIps.push(ip); }
      if (hn && !hostMap[ip]) hostMap[ip] = hn;
    }

    var lines = text.split(/\r?\n/);
    lines.forEach(function (line) {
      if (/\[host down\]|Status:\s*Down/i.test(line)) return;
      var mNmapParen = /Nmap scan report for\s+([^\s()]+)\s+\(((?:\d{1,3}\.){3}\d{1,3})\)/i.exec(line);
      if (mNmapParen) {
        pushScanIp(mNmapParen[2], cleanHostToken(mNmapParen[1]));
        return;
      }
      var mNmapBare = /Nmap scan report for\s+((?:\d{1,3}\.){3}\d{1,3})\b/i.exec(line);
      if (mNmapBare) {
        pushScanIp(mNmapBare[1], '');
        return;
      }
      var mGrep = /Host:\s+((?:\d{1,3}\.){3}\d{1,3})\s+\(([^)]*)\)/i.exec(line);
      if (mGrep) {
        pushScanIp(mGrep[1], cleanHostToken(mGrep[2]));
        return;
      }
      var mNxc = /^\s*(?:SMB|WINRM|SSH|LDAP|WMI|MSSQL|RDP|FTP)\s+((?:\d{1,3}\.){3}\d{1,3})\s+\d+\s+([^\s\[*+-]+)/i.exec(line);
      if (mNxc) {
        var nxcHn = cleanHostToken(mNxc[2]);
        var mDom = /\(domain:([^)\s]+)\)/i.exec(line);
        if (nxcHn && mDom && nxcHn.indexOf('.') < 0 && mDom[1].indexOf('.') > 0) nxcHn = nxcHn + '.' + mDom[1];
        pushScanIp(mNxc[1], nxcHn);
        return;
      }
      // /etc/hosts or "<ip> <hostname>" or "<hostname> <ip>" on a simple non-scan line
      if (/^\s*#/.test(line) || /Nmap|PORT\s+STATE|Host is up|^\s*\d+\/(?:tcp|udp)\b|^\s*\|/i.test(line)) return;
      var tokens = line.trim().split(/[\s,]+/).filter(Boolean);
      if (tokens.length >= 2 && tokens.length <= 6) {
        var ipTok = '';
        for (var i = 0; i < tokens.length; i++) {
          if (isValidIp(tokens[i]) && !isCidr(tokens[i]) && !isIgnoredSelfOrBroadcast(tokens[i], lhost)) {
            ipTok = tokens[i];
            break;
          }
        }
        if (ipTok && !hostMap[ipTok]) {
          for (var j = 0; j < tokens.length; j++) {
            if (tokens[j] === ipTok) continue;
            var cand = cleanHostToken(tokens[j]);
            if (cand && (cand.indexOf('.') > 0 || tokens.length <= 3)) {
              hostMap[ipTok] = cand;
              break;
            }
          }
        }
      }
    });

    // XML <host> support
    if (/<nmaprun\b/i.test(text)) {
      var hostBlocks = text.split(/<\/host>/i);
      hostBlocks.forEach(function (hb) {
        if (/<status[^>]*state=["']down["']/i.test(hb)) return;
        var mAddr = /<address[^>]*addr=["']((?:\d{1,3}\.){3}\d{1,3})["'][^>]*addrtype=["']ipv4["']/i.exec(hb)
          || /<address[^>]*addrtype=["']ipv4["'][^>]*addr=["']((?:\d{1,3}\.){3}\d{1,3})["']/i.exec(hb);
        if (mAddr) {
          var mHn = /<hostname[^>]*name=["']([^"']+)["']/i.exec(hb);
          pushScanIp(mAddr[1], mHn ? cleanHostToken(mHn[1]) : '');
        }
      });
    }

    var allExtracted = extractScope(text, lhost);
    var cidrs = allExtracted.filter(isCidr);
    var hostIps = (hasScanOutput && scanIps.length)
      ? scanIps
      : allExtracted.filter(function (s) { return !isCidr(s); });

    // If user pasted small CIDRs (/28-/32) and no individual IPs, expand them into host IPs
    if (!hostIps.length && cidrs.length) {
      cidrs.forEach(function (c) {
        expandSmallCidr(c, lhost).forEach(function (ip) {
          if (hostIps.indexOf(ip) === -1) hostIps.push(ip);
        });
      });
    }

    var hosts = hostIps.map(function (ip) {
      var hn = hostMap[ip] || '';
      var dom = '';
      if (hn && hn.indexOf('.') > 0) {
        dom = hn.split('.').slice(1).join('.');
      }
      return { ip: ip, hostname: hn, domain: dom };
    });

    // If user pasted a larger subnet CIDR (e.g. 10.10.10.0/24) with no individual host IPs, keep the CIDR as a target scope entry
    if (!hosts.length && cidrs.length) {
      cidrs.forEach(function (c) {
        hosts.push({ ip: c, hostname: '', domain: '' });
      });
    }

    // If user entered standalone hostname(s) (e.g. dc01.corp.local or box.htb) with no IPs/CIDRs
    if (!hosts.length && !cidrs.length && !hasScanOutput) {
      var seenHn = {};
      lines.forEach(function (line) {
        if (/^\s*#/.test(line)) return;
        line.trim().split(/[\s,]+/).forEach(function (tok) {
          var hn = cleanHostToken(tok);
          if (hn && (hn.indexOf('.') > 0 || lines.length === 1) && !seenHn[hn.toLowerCase()]) {
            seenHn[hn.toLowerCase()] = 1;
            var dom = hn.indexOf('.') > 0 ? hn.split('.').slice(1).join('.') : '';
            hosts.push({ ip: hn, hostname: hn, domain: dom });
          }
        });
      });
    }

    var scope = hostIps.concat(cidrs);
    if (!scope.length && hosts.length) {
      scope = hosts.map(function (h) { return h.ip; });
    }
    return { scope: scope, hosts: hosts, cidrs: cidrs, hasScanOutput: hasScanOutput };
  }

  function ingestScanBlocks(text, defaultIp, doneCb) {
    if (!(OBOL.ingest && OBOL.ingest.ensureParsers)) { if (doneCb) doneCb(0); return; }
    OBOL.ingest.ensureParsers().then(function (okp) {
      if (!okp || !OBOL.ingest.run) { if (doneCb) doneCb(0); return; }
      var totalAdded = 0;
      var raw = String(text || '');
      var isPureNmap = /Nmap scan report for|<nmaprun\b|^\s*\d+\/(?:tcp|udp)\s+open\b|\bPorts:\s+\d+\/open\//im.test(raw)
        && !/={3,}\s*OBOL STEP\s+\d+:/i.test(raw);
      if (!isPureNmap && OBOL.ingest.importSession) {
        var sRes = OBOL.ingest.importSession(raw, { target: defaultIp || 'auto' });
        if (doneCb) doneCb((sRes && sRes.added) || 0, sRes);
        return;
      }
      var reportChunks = raw.split(/(?=^Nmap scan report for\b)/im);
      var hostBlocks = [];
      if (reportChunks.length > 1) {
        var preamble = '';
        reportChunks.forEach(function (chunk) {
          if (!/^Nmap scan report for\b/i.test(chunk.trim())) {
            preamble += chunk;
            return;
          }
          if (/^Nmap scan report for[^\r\n]*\[host down\]/i.test(chunk.trim())) return;
          var mIp = /Nmap scan report for\s+(?:[^\s()]+\s+\()?((?:\d{1,3}\.){3}\d{1,3})\)?/i.exec(chunk);
          var bip = mIp ? mIp[1] : defaultIp;
          hostBlocks.push({ ip: bip, text: (preamble ? (preamble + '\n' + chunk) : chunk) });
          preamble = '';
        });
      }
      if (!hostBlocks.length) {
        hostBlocks.push({ ip: defaultIp, text: raw });
      }
      hostBlocks.forEach(function (b) {
        var r = OBOL.ingest.run({
          text: b.text,
          command: 'nmap',
          scope: b.ip ? ('host:' + b.ip) : undefined,
          source: 'paste',
          quiet: true,
        });
        totalAdded += (r && r.added) || 0;
      });
      if (doneCb) doneCb(totalAdded);
    }).catch(function () { if (doneCb) doneCb(0); });
  }

  function importBulkTargets(text, doneCb) {
    if (/OBOL-ARSENAL|OBOL-WS-SNAPSHOT/i.test(String(text || '')) && OBOL.ingest && OBOL.ingest.ensureParsers) {
      OBOL.ingest.ensureParsers().then(function (okp) {
        var sRes = (okp && OBOL.ingest.importSession) ? OBOL.ingest.importSession(text, { target: 'auto' }) : OBOL.ingest.run({ text: text });
        if (sRes && sRes.ok && ((sRes.arsenal && sRes.arsenal.ok) || (sRes.workspaceSync && sRes.workspaceSync.ok) || sRes.added > 0)) {
          if (doneCb) doneCb({ ok: true, added: (sRes.hosts || []).length, updated: 0, cidrs: 0, scanFacts: sRes.added || 0, arsenal: sRes.arsenal, workspaceSync: sRes.workspaceSync });
          return;
        }
        if (doneCb) doneCb({ ok: false, added: 0, updated: 0 });
      });
      return;
    }
    var eng = OBOL.store.active() || {};
    var lhost = (eng.params && eng.params.lhost) || '';
    var parsed = parseBulkInput(text, lhost);
    if (!parsed.hosts.length && !parsed.cidrs.length) {
      if (OBOL.ingest && OBOL.ingest.ensureParsers) {
        OBOL.ingest.ensureParsers().then(function (okp) {
          var sRes = (okp && OBOL.ingest.importSession) ? OBOL.ingest.importSession(text, { target: 'auto' }) : null;
          if (sRes && sRes.ok && (sRes.added > 0 || (sRes.arsenal && sRes.arsenal.ok) || (sRes.workspaceSync && sRes.workspaceSync.ok))) {
            if (doneCb) doneCb({ ok: true, added: (sRes.hosts || []).length, updated: 0, cidrs: 0, scanFacts: sRes.added || 0, arsenal: sRes.arsenal, workspaceSync: sRes.workspaceSync });
            return;
          }
          if (doneCb) doneCb({ ok: false, added: 0, updated: 0 });
        });
        return;
      }
      if (doneCb) doneCb({ ok: false, added: 0, updated: 0 });
      return;
    }
    var added = 0, updated = 0;
    var factsToAdd = [];
    var SUP = (OBOL.facts && OBOL.facts.ProofState && OBOL.facts.ProofState.SUPPORTED) || 'supported';
    OBOL.store.update(function (e) {
      e.targets = e.targets || [];
      e.params = e.params || {};
      if (parsed.scope.length) e.params.scope_defined = true;
      parsed.hosts.forEach(function (h, idx) {
        var existing = e.targets.find(function (t) { return (t.ip || t.id) === h.ip; });
        if (existing) {
          if (h.hostname && !existing.hostname) { existing.hostname = h.hostname; updated++; }
        } else {
          e.targets.push({ id: 't-' + Date.now().toString(36) + '-' + idx, ip: h.ip, hostname: h.hostname || '', os: '' });
          added++;
        }
        if (!e.params.target) {
          e.params.target = h.ip;
          e.activeTarget = h.ip;
        }
        var sc = 'host:' + h.ip;
        factsToAdd.push(OBOL.facts.makeFact({ kind: 'target.configured', scope: sc, source: 'targets' }));
        if (h.hostname) {
          factsToAdd.push(OBOL.facts.makeFact({ kind: 'host.hostname', scope: sc, value: { name: h.hostname.split('.')[0], fqdn: h.hostname }, state: SUP, source: 'targets' }));
        }
        if (h.domain) {
          factsToAdd.push(OBOL.facts.makeFact({ kind: 'host.domain', scope: sc, value: { domain: h.domain }, state: SUP, source: 'targets' }));
        }
      });
    }, 'targets');
    if (factsToAdd.length) OBOL.store.addFacts(factsToAdd, 'facts');

    var finish = function (scanFactsAdded) {
      if (OBOL.app && OBOL.app.renderSidebar) OBOL.app.renderSidebar();
      if (doneCb) doneCb({ ok: true, added: added, updated: updated, cidrs: parsed.cidrs.length, scanFacts: scanFactsAdded || 0 });
    };

    if (parsed.hasScanOutput) {
      var defIp = (parsed.hosts[0] && parsed.hosts[0].ip) || ((OBOL.store.active().params || {}).target) || '';
      ingestScanBlocks(text, defIp, finish);
    } else {
      finish(0);
    }
  }

  function platformCards(selected) {
    return OBOL.profile.listPresets().map(function (p) {
      var badgeCls = p.exam ? 'exam' : (p.id === 'client' ? 'client' : 'lab');
      var badgeTxt = p.exam ? 'exam' : (p.id === 'client' ? 'client' : 'lab');
      var objText = p.objective_label || (p.flag_names && p.flag_names.length ? p.flag_names.join(', ') : 'Full Compromise');
      return '<label class="pf-card' + (p.id === selected ? ' sel' : '') + '">'
        + '<input type="radio" name="pf-platform" value="' + esc(p.id) + '"' + (p.id === selected ? ' checked' : '') + '>'
        + '<span class="pf-name">' + esc(p.name) + '</span>'
        + '<span class="pf-badge ' + badgeCls + '">' + badgeTxt + '</span>'
        + '<span class="pf-flags">' + esc(objText) + '</span>'
        + '</label>';
    }).join('');
  }

  function workdirHint() {
    var sel = ((OBOL.store.active() || {}).profile || {}).platform || 'custom';
    return OBOL.workspace.join(OBOL.workspace.DEFAULT_BASE, OBOL.profile.isExamPlatform(sel) ? 'exam' : 'box');
  }

  function machineOptions(selected) {
    return '<option value="">Machine Type (Auto / Optional)</option>' + OBOL.profile.listMachineTypes().map(function (m) {
      return '<option value="' + esc(m.id) + '"' + (m.id === selected ? ' selected' : '') + '>' + esc(OBOL.store.runLabel(m)) + '</option>';
    }).join('');
  }

  function workflowOptions(selected) {
    var sel = (OBOL.profile.normalizeWorkflow && OBOL.profile.normalizeWorkflow(selected)) || OBOL.profile.DEFAULT_WORKFLOW;
    return (OBOL.profile.listWorkflows ? OBOL.profile.listWorkflows() : []).map(function (w) {
      return '<option value="' + esc(w.id) + '"' + (w.id === sel ? ' selected' : '') + '>' + esc(w.name) + '</option>';
    }).join('');
  }

  function isConfigured(eng) {
    if (OBOL.store && typeof OBOL.store.isConfigured === 'function') return OBOL.store.isConfigured(eng);
    if (!eng) return false;
    var n = eng.name != null ? String(eng.name).trim() : '';
    return !!n && !/^(untitled run|new engagement|no run yet|set up engagement\.{0,3})$/i.test(n);
  }

  function ago(at) {
    if (!at) return '';
    var s = Math.max(0, Math.floor((Date.now() - at) / 1000));
    if (s < 60) return 'Just Now';
    var m = Math.floor(s / 60); if (m < 60) return m + 'm ago';
    var h = Math.floor(m / 60); if (h < 24) return h + 'h ago';
    return Math.floor(h / 24) + 'd ago';
  }

  // Compact Loadout readiness pill for the Hub command bar
  function loadoutStatusPill() {
    var p; try { p = JSON.parse(localStorage.getItem('obol.arsenal-profile') || 'null'); } catch (e) { p = null; }
    var A = OBOL.ARSENAL || {}, seen = {}, total = 0, ready = 0;
    Object.keys(A).forEach(function (k) {
      var e = A[k]; if (!e || seen[e.key]) return; seen[e.key] = 1;
      total++;
      var pres = e.class === 'builtin' || (p && ((p.tools && p.tools[e.key] && p.tools[e.key].present)
        || (p.staged || []).indexOf(e.dest || '') >= 0 || (p.digests && p.digests[e.key])));
      if (pres) ready++;
    });
    if (p) {
      return '<a class="hb-lo-pill is-ok" href="#/loadout" title="Attack box Loadout synced - click to inspect">'
        + '<span class="hb-lo-dot">●</span> Loadout Stocked (' + ready + '/' + total + ')</a>';
    }
    return '<a class="hb-lo-pill is-warn" href="#/loadout" title="Stock or sync your Kali attack box">'
      + '<span class="hb-lo-dot">●</span> Step 0: Sync Loadout &rarr;</a>';
  }

  // Top Command Bar: houses the Engagement Library drawer, In-Place Run Editor toggle, New Run toggle, and Manage/Reset disclosure.
  function topCommandBar(configured) {
    var engs = (OBOL.store.listEngagements && OBOL.store.listEngagements()) || [];
    return '<div class="eng-library hb-cmdbar">'
      + '<div class="hb-cmdbar-left">'
      + '  <h1 class="route-h1 hb-route-h1">' + (configured ? 'Engagement Hub' : 'Launch Engagement') + '</h1>'
      + loadoutStatusPill()
      + '</div>'
      + '<div class="hb-cmdbar-right">'
      + '  <details class="eng-lib-drawer">'
      + '    <summary class="cr-btn-glass small hb-cmd-sum">&#8644; Switch / Library <span class="hb-cmd-count">' + engs.length + '</span></summary>'
      + '    <div class="eng-lib-popover">'
      + '      <div class="eng-lib-pop-h"><strong>Saved Engagements</strong><span class="muted small">Stored locally in this browser</span></div>'
      +        libraryList()
      + '    </div>'
      + '  </details>'
      + (configured
          ? '<button type="button" class="cr-btn-glass small' + (_showEditRun ? ' is-open' : '') + '" id="hb-toggle-edit">&#9881; Edit Run / LHOST</button>'
            + '<button type="button" class="cr-btn-neon neon-emerald small" id="hb-toggle-new">' + (_showNewSetup ? 'Close Setup ✕' : '+ New Engagement') + '</button>'
          : '')
      + '  <details class="eng-danger-toggle">'
      + '    <summary class="cr-btn-glass small hb-cmd-sum hb-danger-sum">Manage / Reset</summary>'
      + '    <div class="eng-danger">'
      + '      <div class="eng-danger-item"><div class="eng-danger-txt"><strong>Delete All Engagements</strong>'
      + '      <span>Remove every saved run and its evidence. Keeps your skin &amp; appearance settings.</span></div>'
      + '      <button class="btn-danger" id="eng-clear">Delete All Engagements</button></div>'
      + '      <div class="eng-danger-item"><div class="eng-danger-txt"><strong>Full Reset</strong>'
      + '      <span>Erase <em>everything</em> OBOL saved in this browser (engagements, screenshots, and settings) and start completely fresh. A hard refresh (Ctrl+F5) does not do this.</span></div>'
      + '      <button class="btn-danger btn-danger-strong" id="eng-reset">Full Reset, Erase All Data</button></div>'
      + '    </div>'
      + '  </details>'
      + '</div>'
      + '</div>';
  }

  // In-Place Run Editor Drawer (edit active engagement name, working dir, LHOST, interface, workflow without creating a new run)
  function editRunDrawer(eng) {
    if (!eng) return '';
    var prof = eng.profile || {};
    var params = eng.params || {};
    var root = (eng.workspace && eng.workspace.root) || '';
    var iface = params.lhost_iface || 'tun0';
    return '<div id="hb-edit-drawer" class="hb-drawer station-card neon-lane-cyan"' + (_showEditRun ? '' : ' hidden') + '>'
      + '<div class="hb-drawer-head">'
      + '  <div><span class="hb-drawer-kicker">ACTIVE RUN CONFIGURATION</span><h3 class="hb-drawer-title">Edit Engagement Settings In Place</h3></div>'
      + '  <button type="button" class="cr-btn-glass small" id="hb-edit-close">Close ✕</button>'
      + '</div>'
      + '<div class="hb-edit-grid">'
      + '  <label class="eng-field"><span>Engagement Name</span><input id="hb-edit-name" value="' + U.attr(eng.name || '') + '" autocomplete="off"></label>'
      + '  <label class="eng-field"><span>Working Directory (Kali)</span><input id="hb-edit-workdir" value="' + U.attr(root) + '" placeholder="~/engagements/box" autocomplete="off" spellcheck="false"></label>'
      + '  <label class="eng-field"><span>Your VPN IP (LHOST)</span><input id="hb-edit-lhost" value="' + U.attr(params.lhost || '') + '" placeholder="e.g. 10.10.14.9" autocomplete="off" spellcheck="false"></label>'
      + '  <label class="eng-field"><span>Interface</span><select id="hb-edit-iface">'
      +    ['tun0', 'tun1', 'tap0', 'eth0', 'wlan0', 'vpn0', 'wg0'].map(function (i) { return '<option value="' + i + '"' + (i === iface ? ' selected' : '') + '>' + i + '</option>'; }).join('')
      + '  <option value="">other / none</option></select></label>'
      + '  <label class="eng-field"><span>Attack Workflow Nudge</span><select id="hb-edit-wf">' + workflowOptions(prof.workflow || '') + '</select></label>'
      + '</div>'
      + '<div class="hb-drawer-foot">'
      + '  <button type="button" class="cr-btn-neon neon-emerald small" id="hb-edit-save">Save Run Settings</button>'
      + '</div>'
      + '</div>';
  }

  // Unified Mission Header: Active Run Identity + Phase Spine + 4 Neon Vitals + Integrated Next-Move Terminal Bar
  function activePanel() {
    var eng = OBOL.store.active();
    if (!eng) return '';
    var prof = eng.profile || {};
    var preset = (OBOL.profile.PRESETS[prof.platform] || OBOL.profile.PRESETS.custom);
    var exam = OBOL.profile.isExamPlatform(prof.platform);
    var flagsOn = OBOL.profile.hasFlags ? OBOL.profile.hasFlags(prof) : true;
    var facts = OBOL.store.factSet();
    var started = Object.keys(facts.kinds()).length > 0;
    var reached = started ? OBOL.phases.phaseIndex(OBOL.phases.targetPhase(facts)) : -1;
    var frontier = started ? OBOL.phases.frontierIndex(facts) : 0;
    var spine = OBOL.phases.PHASES.map(function (p, i) {
      return '<span class="spine-node ph-' + p + (i <= reached ? ' reached' : '') + (i === frontier ? ' frontier' : '') + '">' + U.titleCase(p) + '</span>';
    }).join('<span class="spine-sep">›</span>');
    var mt = prof.machine_type ? (OBOL.profile.MACHINE_TYPES[prof.machine_type] || {}).name : '';
    var nf = Object.keys(facts.kinds()).length;
    var isCustom = !prof.platform || prof.platform === 'custom';
    var infos = targetInfos(eng);
    var owned = infos.filter(function (i) { return i.lvl === 'privileged'; }).length;
    var totFlags = infos.reduce(function (a, i) { return a + i.flags; }, 0);
    var creds = (OBOL.creds && OBOL.creds.gather()) || [];

    function stat(href, cls, val, label, sub) {
      var inner = '<span class="eng-stat-v ' + cls + '">' + val + '</span>'
        + '<span class="eng-stat-k">' + esc(label) + (sub ? '<span class="eng-stat-sub">' + esc(sub) + '</span>' : '') + '</span>';
      return href ? '<a class="eng-stat" href="' + href + '">' + inner + '</a>' : '<span class="eng-stat">' + inner + '</span>';
    }
    var secondStat = flagsOn
      ? stat('#/scoreboard', 'es-flags', totFlags, totFlags === 1 ? 'Flag' : 'Flags', '')
      : stat('#/scoreboard', 'es-flags', owned, owned === 1 ? 'Host Owned' : 'Hosts Owned', '');
    var stats = '<div class="eng-stats">'
      + stat('#/targets', 'es-targets', infos.length, infos.length === 1 ? 'Target' : 'Targets', owned ? (owned + ' Owned') : '')
      + secondStat
      + stat('#/creds', 'es-creds', creds.length, creds.length === 1 ? 'Credential' : 'Credentials', '')
      + stat('#/findings', 'es-facts', nf, nf === 1 ? 'Fact' : 'Facts', '')
      + '</div>';

    // Integrated Next Move Strip
    var pack = OBOL.packs.actions();
    var focus = (OBOL.profile && eng.profile) ? OBOL.profile.profileFocus(eng.profile) : [];
    var allDone = infos.length > 0 && owned === infos.length && (!flagsOn || infos.every(function (i) { return i.flags >= 2; }));
    var nm = allDone ? null : ((OBOL.coach && OBOL.coach.topMove) ? OBOL.coach.topMove()
      : OBOL.pack.rankActions(facts, pack, { focusPrefixes: focus, noFlags: !flagsOn })[0]);
    var activeTgt = (eng.params && eng.params.target) || (infos[0] && infos[0].ip) || '';
    var nmHtml;
    if (allDone) {
      nmHtml = '<div class="hb-anchor">'
        + '<div class="hb-anchor-main">'
        + '  <span class="hb-anchor-l">Objectives Complete' + (activeTgt ? ' &middot; ' + esc(activeTgt) : '') + '</span>'
        + '  <span class="hb-anchor-t">All targets compromised' + (flagsOn ? ' and all flags secured' : '') + '</span>'
        + '  <span class="hb-anchor-body">Review your attack path, verify proof screenshots, and export your engagement report.</span>'
        + '</div>'
        + '<div class="hb-anchor-actions">'
        + '  <a class="cr-btn-neon neon-emerald small" href="#/report">Open Report &amp; Export &rarr;</a>'
        + '  <a class="cr-btn-neon neon-cyan small" href="#/evidence">Verify Proof &rarr;</a>'
        + '</div>'
        + '</div>';
    } else if (nm) {
      var fillOpts = { params: eng.params || {}, profile: eng.profile };
      var variants = (OBOL.command && OBOL.command.fillAll) ? OBOL.command.fillAll(nm, facts, fillOpts) : [];
      var v = variants.filter(function (x) { return !x.gated; })[0] || variants[0]
        || OBOL.command.fillCommand(nm, facts, fillOpts, 0);
      nmHtml = '<div class="hb-anchor">'
        + '<div class="hb-anchor-main">'
        + '  <span class="hb-anchor-l">Next Move' + (activeTgt ? ' &middot; ' + esc(activeTgt) : '') + '</span>'
        + '  <span class="hb-anchor-t">' + esc(nm.title) + '</span>'
        + '  <code class="hb-anchor-cmd">' + esc(v.filled) + '</code>'
        + '</div>'
        + '<div class="hb-anchor-actions">'
        + '  <button type="button" class="cr-btn-neon neon-cyan small btn-copy hb-copy" data-copy="' + U.attr(v.filled) + '">Copy Cmd</button>'
        + '  <a class="cr-btn-neon neon-emerald small" href="#/path">Open Cockpit &rarr;</a>'
        + '  <a class="cr-btn-neon neon-amber small" href="#/cruise">Cruise &rarr;</a>'
        + '</div>'
        + '</div>';
    } else {
      nmHtml = '<div class="hb-anchor hb-anchor-empty">'
        + '<div class="hb-anchor-main">'
        + '  <span class="hb-anchor-l">Next Move</span>'
        + '  <span class="hb-anchor-body">Add a target or paste scan evidence to rank your next command here.</span>'
        + '</div>'
        + '<div class="hb-anchor-actions">'
        + '  <a class="cr-btn-neon neon-emerald small" href="#/evidence">Paste Evidence &rarr;</a>'
        + '  <a class="cr-btn-neon neon-amber small" href="#/cruise">Open Cruise &rarr;</a>'
        + '</div>'
        + '</div>';
    }

    var lhostBadge = (eng.params && eng.params.lhost)
      ? '<span class="pill hb-lhost-pill">' + esc((eng.params.lhost_iface || 'tun0') + ': ' + eng.params.lhost) + '</span>'
      : '';

    return '<div class="eng-active station-card neon-lane-emerald">'
      + '<div class="eng-active-top">'
      + '  <div class="eng-active-id">'
      + '    <div class="eng-active-title-row">'
      + '      <span class="eng-active-name">' + esc(OBOL.store.runLabel(eng)) + '</span>'
      + '      <div class="eng-badges">'
      +          (isCustom ? '' : '<span class="pf-badge ' + (exam ? 'exam' : 'lab') + '">' + esc(preset.name) + (exam ? ' · exam' : '') + '</span>')
      +          (mt ? '<span class="pill">' + esc(mt) + '</span>' : '')
      +          (prof.osid ? '<span class="pill">OSID ' + esc(prof.osid) + '</span>' : '')
      +          (prof.client ? '<span class="pill">' + esc(prof.client) + '</span>' : '')
      +          lhostBadge
      + '      </div>'
      + '    </div>'
      + '    <div class="home-spine">' + spine + '</div>'
      + '  </div>'
      +    stats
      + '</div>'
      + nmHtml
      + '</div>';
  }

  // ── Virtual Workspace: clear dark interior, 1-click Kali init & serve bar, collapsed empty folders ──
  function factLine(kinds) {
    if (!kinds || !kinds.length) return '';
    var names = kinds.slice(0, 6).map(function (k) { return esc(U.titleCase(OBOL.pack.friendly(k))); });
    return '<div class="ws-file-facts"><span class="mini-label">Proved</span>' + names.join(', ')
      + (kinds.length > 6 ? ' +' + (kinds.length - 6) : '') + '</div>';
  }
  function fsize(n) { n = +n || 0; if (n <= 0) return ''; if (n < 1024) return n + ' B'; if (n < 1048576) return (n / 1024).toFixed(1) + ' kB'; return (n / 1048576).toFixed(1) + ' MB'; }
  function captureHref(f) { return f.actionId ? ('#/evidence/' + encodeURIComponent(f.actionId)) : '#/evidence'; }

  function fileRow(f, root) {
    var rel = OBOL.vfs.relOf(f.path, root);
    var badge = f.facts.length ? ('<span class="ws-badge">' + f.facts.length + ' Fact' + (f.facts.length === 1 ? '' : 's') + '</span>') : '';
    var suggested = f.status === 'expected' && f.origin === 'suggested';
    var credsLink = (f.facts || []).some(function (k) { return /^(credential\.|hash\.)/.test(k); })
      ? '<a class="ws-file-link" href="#/creds">Use these in Creds &rarr;</a>' : '';
    var tag = f.status === 'captured' ? '' : suggested ? '<span class="ws-tag ws-tag-sugg">Suggested</span>'
      : f.unknown ? '<span class="ws-tag ws-tag-unk">On Disk</span>'
      : f.manual ? '<span class="ws-tag ws-tag-man">Added</span>'
      : f.confirmed ? '<span class="ws-tag ws-tag-conf">On Disk</span>' : '<span class="ws-tag ws-tag-exp">Expected</span>';
    var cmdBlock = f.command ? '<div class="ws-file-cmd"><span class="mini-label">Command</span><code>' + esc(f.command) + '</code></div>' : '';
    var body;
    if (f.image) {
      body = '<img class="ws-shot" src="' + esc(f.image) + '" alt="proof screenshot">';
    } else if (f.status === 'captured') {
      var out = String(f.output || '').replace(/\s+$/, '');
      var capped = out.length > 4000 ? out.slice(0, 4000) + '\n... (truncated, full output in the Run Log)' : out;
      body = cmdBlock
        + (capped ? '<pre class="ws-mini-term">' + esc(capped) + '</pre>' : '<div class="ws-file-note">Captured, no text body.</div>')
        + factLine(f.facts)
        + '<div class="ws-file-links"><a class="ws-file-link" href="#/history">Review in the Run Log &rarr;</a>' + credsLink + '</div>';
    } else if (suggested) {
      body = '<div class="ws-file-note">The Cockpit is suggesting a move that creates this file'
        + (f.title ? ' (<strong>' + esc(f.title) + '</strong>)' : '') + '. Pencilled in, run it, then paste the output to capture it.</div>'
        + cmdBlock
        + '<div class="ws-file-links"><a class="ws-file-link" href="#/path">Open the move in Cockpit &rarr;</a>'
        + '<a class="ws-file-link" href="' + captureHref(f) + '">Capture its output &rarr;</a></div>';
    } else if (f.unknown) {
      body = '<div class="ws-file-note">Found on your disk by a workspace sync. OBOL doesn\'t know this one yet'
        + (f.size ? ' (' + esc(fsize(f.size)) + ')' : '') + '. Paste its contents and the parsers will read whatever they recognize.</div>'
        + '<a class="ws-file-link" href="#/evidence">Paste its contents on Evidence &rarr;</a>';
    } else if (f.manual) {
      body = '<div class="ws-file-note">You added this file by hand. Paste its contents on Evidence to mint any facts it proves.</div>'
        + '<a class="ws-file-link" href="#/evidence">Capture it on Evidence &rarr;</a>';
    } else if (f.confirmed) {
      body = '<div class="ws-file-note">This file is on your disk, but OBOL hasn\'t received its output. Paste it on Evidence to capture what it proves.</div>'
        + cmdBlock
        + '<a class="ws-file-link" href="' + captureHref(f) + '">Capture it on Evidence &rarr;</a>';
    } else {
      body = '<div class="ws-file-note">OBOL handed you a command that writes this file, but hasn\'t received its output yet.</div>'
        + cmdBlock
        + '<a class="ws-file-link" href="' + captureHref(f) + '">Paste its output on Evidence to capture it &rarr;</a>';
    }
    var desc = OBOL.vfs.describe ? ('<div class="ws-file-desc">' + esc(OBOL.vfs.describe(f)) + '</div>') : '';
    var cls = 'ws-file ws-' + f.status + (suggested ? ' ws-suggested' : '') + (f.confirmed ? ' ws-confirmed' : '')
      + (f.unknown ? ' ws-unknown' : '') + (f.manual ? ' ws-manual' : '') + (f.flag ? ' ws-flag' : '');
    var fromTag = (suggested && f.title) ? '<span class="ws-from" title="' + U.attr('Created by: ' + f.title) + '">&#8618; ' + esc(f.title) + '</span>' : '';
    var copyPath = '<button type="button" class="ws-copy-path" data-copy="' + U.attr(f.path || rel) + '" title="Copy path">&#10697;</button>';
    return '<details class="' + cls + '" data-rel="' + U.attr(rel) + '">'
      + '<summary><span class="ws-dot"></span><span class="ws-file-name">' + esc(f.name) + '</span>' + tag + badge + fromTag
      + (f.at ? '<span class="ws-when">' + esc(ago(f.at)) + '</span>' : '')
      + copyPath
      + '<button type="button" class="ws-rm" data-rel="' + U.attr(rel) + '" title="Remove from workspace" aria-label="Remove ' + U.attr(f.name) + '">×</button>'
      + '</summary>'
      + '<div class="ws-file-body">' + desc + body + '</div></details>';
  }

  function syncBlock(eng) {
    var cmd = (OBOL.workspace && OBOL.workspace.snapshotCmd) ? OBOL.workspace.snapshotCmd(eng) : '';
    if (!cmd) return '';
    return '<details class="ws-sync"><summary>Sync From Your Disk <span class="ws-sync-tag">Bulk-Match Working Folder</span></summary>'
      + '<p class="ws-sync-hint">Run this in your working directory and paste the output back. OBOL confirms the files it predicted and adopts any it didn\'t know about.</p>'
      + '<div class="ws-sync-cmd"><code id="ws-snap-code">' + esc(cmd) + '</code>'
      + '<button type="button" class="btn-copy ws-snap-copy" data-copy="ws-snap-code">copy</button></div>'
      + '<textarea id="ws-sync-paste" class="ws-sync-paste" rows="3" placeholder="Paste the file list here..." spellcheck="false"></textarea>'
      + '<button type="button" class="cr-btn-neon neon-cyan small ws-sync-run">Sync Workspace</button>'
      + '</details>';
  }

  function workspacePanel() {
    var eng = OBOL.store.active();
    if (!eng || !OBOL.vfs) return '';
    var ov = (eng.workspace && eng.workspace.overrides) || {};
    var started = (eng.activities || []).length > 0 || (eng.screenshots || []).length > 0 || ((ov.added || []).length > 0);
    var vfs = OBOL.vfs.build(eng, started ? {} : { suggested: [] });
    var hidden = Object.keys(ov.removed || {}).length;
    var rootStr = (vfs.root && vfs.root !== '.') ? vfs.root : ((OBOL.workspace && OBOL.workspace.defaultRoot) ? OBOL.workspace.defaultRoot(OBOL.workspace.DEFAULT_BASE, eng) : '~/engagements/run');
    var syncedStamp = ov.syncedAt ? '<span class="ws-synced-at">Synced ' + esc(ago(ov.syncedAt)) + '</span>' : '';

    var head = '<div class="ws-panel-head">'
      + '<div><h2 class="coach-sec-h">Workspace</h2><div class="ws-root"><code>' + esc(rootStr) + '</code>' + syncedStamp + '</div></div>'
      + '<div class="ws-counts">'
      + '  <span class="ws-c-cap">' + vfs.captured + ' Captured</span>'
      + (vfs.expected ? ' <span class="ws-c-exp">' + vfs.expected + ' Pending</span>' : '')
      + '</div>'
      + '</div>';

    // 1-Click Kali Workspace Init & Serve Payloads Bar
    var scaffoldCmd = (OBOL.workspace && OBOL.workspace.scaffold) ? OBOL.workspace.scaffold(eng) : ('mkdir -p ' + rootStr + '/{scans,loot,exploit,www,proof} && cd ' + rootStr);
    var serveCmd = 'python3 -m http.server 80 --directory ~/.obol/arsenal/www';
    var quickBar = '<div class="ws-quick-cmds ws-clear-box">'
      + '<div class="ws-qcmd-row">'
      + '  <span class="ws-qcmd-lbl">1. Init Kali Dir</span>'
      + '  <code class="ws-qcmd-code" title="' + U.attr(scaffoldCmd) + '">' + esc(scaffoldCmd) + '</code>'
      + '  <button type="button" class="ws-copyval cr-btn-glass tiny" data-copy="' + U.attr(scaffoldCmd) + '">Copy</button>'
      + '</div>'
      + '<div class="ws-qcmd-row">'
      + '  <span class="ws-qcmd-lbl">2. Serve Payloads</span>'
      + '  <code class="ws-qcmd-code" title="' + U.attr(serveCmd) + '">' + esc(serveCmd) + '</code>'
      + '  <button type="button" class="ws-copyval cr-btn-glass tiny" data-copy="' + U.attr(serveCmd) + '">Copy</button>'
      + '</div>'
      + '</div>';

    // Separate populated folders from empty folders so empty folders don't bloat the height!
    var populatedFolders = vfs.folders.filter(function (fo) { return fo.files && fo.files.length > 0; });
    var emptyFolders = vfs.folders.filter(function (fo) { return !fo.files || fo.files.length === 0; });

    var populatedHtml = populatedFolders.map(function (fo) {
      var files = fo.files.map(function (f) { return fileRow(f, vfs.root); }).join('');
      return '<div class="ws-folder">'
        + '<div class="ws-folder-h"><span class="ws-folder-name">' + esc(fo.label) + '</span>'
        + '<span class="ws-folder-count">' + fo.files.length + '</span>'
        + '<button type="button" class="ws-add" data-folder="' + U.attr(fo.key) + '" title="Add a file to ' + esc(fo.label) + '" aria-label="Add a file to ' + esc(fo.label) + '">+</button></div>'
        + files + '</div>';
    }).join('');

    var emptyNotice = !populatedFolders.length
      ? '<div class="ws-zero-note">No files captured yet. Run your first move in Cockpit or Cruise and paste output back to populate <code>scans/</code>, <code>loot/</code>, and <code>proof/</code> automatically.</div>'
      : '';

    var emptyStrip = emptyFolders.length
      ? '<div class="ws-empty-strip"><span class="ws-empty-lbl">Empty folders (click to add file):</span>'
        + emptyFolders.map(function (fo) {
            return '<button type="button" class="ws-empty-chip ws-add" data-folder="' + U.attr(fo.key) + '" title="Add a file to ' + esc(fo.label) + '">+ ' + esc(fo.label) + '</button>';
          }).join('')
        + '</div>'
      : '';

    var loInsight = loadoutInsight();
    var footer = hidden ? ('<div class="ws-foot"><button type="button" class="ws-restore" data-x>' + hidden + ' Hidden · Restore</button></div>') : '';

    return '<aside class="ws-panel station-card neon-lane-violet">'
      + head
      + quickBar
      + '<div class="ws-tree ws-clear-box">'
      + populatedHtml
      + emptyNotice
      + emptyStrip
      + '</div>'
      + loInsight
      + footer
      + syncBlock(eng)
      + '</aside>';
  }

  function loadoutInsight() {
    var p; try { p = JSON.parse(localStorage.getItem('obol.arsenal-profile') || 'null'); } catch (e) { p = null; }
    if (!p) return '';
    var staged = (p.staged || []).slice(0, 8), wl = Object.keys(p.wordlists || {});
    if (!staged.length && !wl.length) return '';
    var chips = staged.map(function (f) { return '<span class="ws-lo-chip">' + esc(f) + '</span>'; }).join('');
    return '<details class="ws-lo"><summary class="ws-lo-sum"><span>Staged in Loadout (' + (p.staged || []).length + ' payloads, ' + wl.length + ' wordlists)</span><a class="ws-lo-h" href="#/loadout">Loadout &nearr;</a></summary>'
      + '<div class="ws-lo-body">'
      + (staged.length ? '<div class="ws-lo-grp"><span class="ws-lo-lbl">Ready in ~/.obol/arsenal/www</span>' + chips + '</div>' : '')
      + (wl.length ? '<div class="ws-lo-grp"><span class="ws-lo-lbl">Wordlists</span>' + wl.map(function (w) { return '<span class="ws-lo-chip">' + esc(w) + '</span>'; }).join('') + '</div>' : '')
      + '</div></details>';
  }

  function loadoutSetupCard() {
    var p; try { p = JSON.parse(localStorage.getItem('obol.arsenal-profile') || 'null'); } catch (e) { p = null; }
    var A = OBOL.ARSENAL || {}, seen = {}, total = 0, ready = 0;
    Object.keys(A).forEach(function (k) {
      var e = A[k]; if (!e || seen[e.key]) return; seen[e.key] = 1;
      total++;
      var pres = e.class === 'builtin' || (p && ((p.tools && p.tools[e.key] && p.tools[e.key].present)
        || (p.staged || []).indexOf(e.dest || '') >= 0 || (p.digests && p.digests[e.key])));
      if (pres) ready++;
    });
    if (p) {
      var stagedN = (p.staged || []).length;
      var wlN = Object.keys(p.wordlists || {}).length;
      var vpnStr = p.lhost ? (' · VPN ' + (p.lhost_iface || 'tun0') + ': ' + p.lhost) : '';
      var syncStr = p.savedAt ? (' · Synced ' + ago(p.savedAt)) : '';
      return '<div class="lo-strip lo-strip-ok eng-lo-strip">'
        + '<span class="lo-strip-ico">✓</span>'
        + '<span class="lo-strip-txt"><strong>Attack Box Loadout Stocked</strong> · ' + ready + '/' + total + ' tools ready'
        + (stagedN ? (', ' + stagedN + ' payloads staged') : '')
        + (wlN ? (', ' + wlN + ' wordlists') : '')
        + esc(vpnStr + syncStr) + '</span>'
        + '<a class="lo-strip-go" href="#/loadout">Manage Loadout &rarr;</a>'
        + '</div>';
    }
    var runCmd = 'cd ~/Downloads && chmod +x download-loadout.sh && ./download-loadout.sh';
    return '<div class="eng-lo-card">'
      + '<div class="eng-lo-head">'
      + '<div><span class="eng-lo-kicker">Step 0 · Fresh Or Existing Kali</span><h3 class="eng-lo-title">Stock Or Sync Your Attack Box Loadout</h3></div>'
      + '<a class="eng-lo-full" href="#/loadout">Open Full Loadout &amp; Arsenal (' + total + ' tools) &rarr;</a>'
      + '</div>'
      + '<p class="eng-lo-sub">Works on a brand-new Kali VM or a customized box. It leaves your existing tools, git repos, and wordlists where they are, copies or fetches missing payloads into <code>~/.obol/arsenal/www</code>, and prints an inventory block so OBOL adapts commands to your exact paths (or pass <code>--check-only</code> for zero downloads).</p>'
      + '<div class="eng-lo-grid">'
      + '<div class="eng-lo-step"><span class="eng-lo-n">1</span><div class="eng-lo-step-b"><strong>Download Setup Script</strong><p>Non-destructive; keeps existing tools in place and only fetches what is missing.</p>'
      + '<button type="button" class="cr-btn-neon neon-amber small eng-lo-dl">Download download-loadout.sh</button></div></div>'
      + '<div class="eng-lo-step"><span class="eng-lo-n">2</span><div class="eng-lo-step-b"><strong>Run On Your Kali Box</strong><p>Or append <code>--check-only</code> to map your box with zero installs:</p>'
      + '<div class="eng-lo-cmd"><code>' + esc(runCmd) + '</code><button type="button" class="btn-copy" data-copy="' + U.attr(runCmd) + '">Copy</button></div></div></div>'
      + '<div class="eng-lo-step"><span class="eng-lo-n">3</span><div class="eng-lo-step-b"><strong>Paste The OBOL-ARSENAL Block Back</strong>'
      + '<div class="eng-lo-paste-row"><textarea class="eng-lo-paste" rows="2" placeholder="Paste the OBOL-ARSENAL block printed at the end of the script..." spellcheck="false"></textarea>'
      + '<button type="button" class="cr-btn-neon neon-emerald small eng-lo-ingest">Stock Loadout</button></div>'
      + '<span class="eng-lo-msg" role="status"></span></div></div>'
      + '</div></div>';
  }

  function lastActivityAt(ip, acts) {
    var t = 0;
    (acts || []).forEach(function (a) {
      if (a && a.at && a.at > t && (a.target === ip || a.scope === 'host:' + ip)) t = a.at;
    });
    return t;
  }

  // Collapsible Target Board & Attack Paths on the Hub (Capped at 10 targets, with Bulk Nmap/IP Import & Filter Pills)
  var HUB_TARGET_CAP = 10;
  function engagementPath() {
    var eng = OBOL.store.active(); if (!eng) return '';
    var allInfos = targetInfos(eng);
    var acts = eng.activities || [];
    var engId = OBOL.store.activeId();
    var activeTarget = (eng.params && eng.params.target) || (allInfos[0] && allInfos[0].ip) || '';

    // Sort so the active target is first, then Foothold -> Creds -> Enum -> Scan -> Owned
    var PRIORITY = { foothold: 5, credentialed: 4, enumerated: 3, discovered: 2, privileged: 1 };
    var sortedInfos = allInfos.slice().sort(function (a, b) {
      var aAct = a.ip === activeTarget ? 1 : 0;
      var bAct = b.ip === activeTarget ? 1 : 0;
      if (aAct !== bAct) return bAct - aAct;
      if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
      return (PRIORITY[b.lvl] || 0) - (PRIORITY[a.lvl] || 0);
    });

    var counts = {
      all: sortedInfos.length,
      foothold: sortedInfos.filter(function (i) { return i.lvl === 'foothold' || i.lvl === 'credentialed'; }).length,
      privileged: sortedInfos.filter(function (i) { return i.lvl === 'privileged'; }).length,
      recon: sortedInfos.filter(function (i) { return i.lvl === 'discovered' || i.lvl === 'enumerated'; }).length,
    };

    var filteredInfos = sortedInfos.filter(function (i) {
      if (_targetFilter === 'foothold') return i.lvl === 'foothold' || i.lvl === 'credentialed';
      if (_targetFilter === 'privileged') return i.lvl === 'privileged';
      if (_targetFilter === 'recon') return i.lvl === 'discovered' || i.lvl === 'enumerated';
      return true;
    });

    var shownInfos = filteredInfos.slice(0, HUB_TARGET_CAP);
    var single = allInfos.length === 1;

    function filterPill(key, label, n) {
      var on = _targetFilter === key;
      return '<button type="button" class="hb-tf-pill' + (on ? ' on' : '') + '" data-tf="' + key + '">'
        + esc(label) + ' <span class="hb-tf-n">' + n + '</span></button>';
    }

    var filterBar = allInfos.length > 0
      ? '<div class="hb-tf-bar">'
        + filterPill('all', 'All', counts.all)
        + (counts.foothold ? filterPill('foothold', 'Foothold / Creds', counts.foothold) : '')
        + (counts.privileged ? filterPill('privileged', 'Owned', counts.privileged) : '')
        + (counts.recon ? filterPill('recon', 'Recon / Enum', counts.recon) : '')
        + '</div>'
      : '';

    var showBulk = _showBulkTarget || allInfos.length === 0;
    var bulkBox = '<div id="hb-bulk-target-box" class="hb-bulk-box ws-clear-box"' + (showBulk ? '' : ' hidden') + '>'
      + '<div class="hb-bulk-head">'
      + '  <span class="hb-bulk-title">Add Single Target or Bulk-Paste Scope / Nmap / /etc/hosts</span>'
      + '  <span class="muted small">Extracts IPs, hostnames, CIDRs &amp; Nmap ports automatically</span>'
      + '</div>'
      + '<textarea id="hb-bulk-input" class="hb-bulk-ta" rows="3" placeholder="Examples:&#10;10.10.10.20 sql01.corp.local&#10;10.10.10.30 dc01.corp.local&#10;Or paste raw `nmap -sn` / grepable output / /etc/hosts..." spellcheck="false"></textarea>'
      + '<div class="hb-bulk-foot">'
      + (allInfos.length ? '<button type="button" class="cr-btn-glass small" id="hb-bulk-cancel">Close</button>' : '')
      + '  <button type="button" class="cr-btn-neon neon-emerald small" id="hb-bulk-go">Import &amp; Seed Recon Moves</button>'
      + '</div>'
      + '</div>';

    var rows = shownInfos.map(function (info) {
      var ip = info.ip, b = info.badge;
      var isFocused = ip === activeTarget;
      var idn = OBOL.store.targetIdentity ? OBOL.store.targetIdentity(ip) : { ip: ip, hostname: info.host, domain: info.domain };
      var host = idn.hostname || info.host || '';
      var dom = idn.domain || info.domain || '';
      var acc = '<span class="hb-acc ' + b.cls + '">' + b.label + '</span>';

      // Compact at-a-glance summary line (keeps collapsed rows clean and scannable)
      var sumLeft = '<span class="apath-row-id">'
        + acc
        + '<span class="apath-ip">' + esc(ip) + '</span>'
        + (host ? '<span class="apath-host-lbl">' + esc(host) + '</span>' : '')
        + (info.os ? '<span class="apath-os-pill">' + esc(info.os) + '</span>' : '')
        + (info.ports.length ? '<span class="apath-port-pill">' + info.ports.length + ' port' + (info.ports.length === 1 ? '' : 's') + '</span>' : '')
        + '</span>';

      var showFlags = !OBOL.profile || !OBOL.profile.hasFlags || OBOL.profile.hasFlags((eng || {}).profile) || info.flags > 0;
      var flags = showFlags ? ('<span class="apath-row-flags' + (info.flags ? '' : ' none') + '">' + OBOL.ic('flag') + ' ' + (info.flags || 0) + '</span>') : '';
      var next = (!isFocused && info.next) ? '<span class="apath-row-next" title="' + U.attr(info.next) + '">&rarr; ' + esc(info.next) + '</span>'
        : (info.lvl === 'privileged' ? '<span class="apath-row-next done">Owned</span>' : '');
      var focusCtrl = isFocused
        ? '<span class="hb-focus-chip is-on" title="Active target for Cockpit &amp; Cruise">● Active</span>'
        : '<button type="button" class="hb-focus-btn" data-focus-ip="' + U.attr(ip) + '" title="Set ' + U.attr(ip) + ' as active target">Focus</button>';
      var dossierLink = '<a class="hb-dossier-btn" href="#/target/' + U.attr(ip) + '" title="Open full Target Dossier for ' + U.attr(ip) + '">Target Dossier &rarr;</a>';

      var sumRight = '<span class="apath-row-meta">' + flags + next + focusCtrl + dossierLink + '</span>';

      // Expanded details: full identity pairs, all open port badges, service chips, and Attack Path ribbon
      function idPair(k, v) { return '<span class="apath-id-pair"><span class="apath-id-k">' + k + '</span><span class="apath-id-v">' + esc(v) + '</span></span>'; }
      var portsHtml = info.ports.length
        ? '<span class="apath-id-pair apath-ports"><span class="apath-id-k">Open Ports</span>'
            + info.ports.map(function (p) { return '<span class="apath-port">' + esc(p) + '</span>'; }).join('') + '</span>'
        : '<span class="apath-id-pair"><span class="apath-id-k">Open Ports</span><span class="muted small">None recorded yet</span></span>';
      var la = lastActivityAt(ip, acts);
      var prevIps = (info.t && Array.isArray(info.t.previousIps) && info.t.previousIps.length) ? info.t.previousIps : [];
      var detailStrip = '<div class="apath-detail-strip">'
        + (host ? idPair('Hostname', host) : '')
        + idPair('IP', ip)
        + (prevIps.length ? idPair('Was', prevIps[prevIps.length - 1]) : '')
        + (dom ? idPair('Domain', dom) : '')
        + (info.os ? idPair('OS', info.os) : '')
        + portsHtml
        + (la ? idPair('Last Activity', ago(la)) : '')
        + '<button type="button" class="cr-btn-glass small apath-edit-btn" data-edit-target="' + U.attr(ip) + '" title="Edit target identity or Re-IP after a lab respawn">&#9998; Edit / Re-IP</button>'
        + '</div>';

      var editDrawer = (OBOL.targets && OBOL.targets.renderEditDrawer) ? OBOL.targets.renderEditDrawer(ip) : '';
      var flow = OBOL.chainview ? OBOL.chainview.hostFlow(ip, acts) : '';
      var body = detailStrip
        + editDrawer
        + (flow
            ? '<h3 class="apath-body-h">Attack Path: What Led to What</h3>' + flow
            : '<div class="apath-empty">No moves recorded on this box yet. Run a move from Cockpit or Cruise and paste output back to build its Attack Path.</div>')
        + '<div class="apath-body-foot">'
        + (!isFocused ? '<button type="button" class="cr-btn-glass small" data-focus-ip="' + U.attr(ip) + '">Set As Active Target</button>' : '')
        + '  <button type="button" class="cr-btn-glass small" data-edit-target="' + U.attr(ip) + '">&#9998; Edit / Re-IP Target</button>'
        + '  <a class="cr-btn-neon neon-cyan small" href="#/target/' + U.attr(ip) + '">Open Target Dossier &amp; Path Graph &rarr;</a>'
        + '</div>';

      var key = 'obol.apath:' + engId + ':' + ip;
      var remembered = null; try { remembered = localStorage.getItem(key); } catch (e) {}
      // Open by default only for a single-target run or the currently focused target
      var open = remembered == null ? (single || isFocused) : remembered === '1';
      return '<details class="apath-host apath-row hb-lvl-' + info.lvl + (isFocused ? ' is-focused' : '') + '"' + (open ? ' open' : '') + ' data-apath-key="' + U.attr(key) + '">'
        + '<summary class="apath-row-sum">' + sumLeft + sumRight + '</summary>'
        + '<div class="apath-row-body">' + body + '</div></details>';
    }).join('');

    var capFooter = '';
    if (filteredInfos.length > HUB_TARGET_CAP) {
      capFooter = '<div class="hb-target-cap-bar">'
        + '<span>Showing top <strong>' + HUB_TARGET_CAP + '</strong> of <strong>' + filteredInfos.length + '</strong> targets on Hub.</span>'
        + '<a class="cr-btn-neon neon-cyan small" href="#/targets">View All ' + allInfos.length + ' Targets on Targets Tab &rarr;</a>'
        + '</div>';
    } else if (allInfos.length > 0) {
      capFooter = '<div class="hb-target-foot-link">'
        + '<span class="muted small">Click any row to expand its Attack Path, or open its Target Dossier for scoped moves &amp; graph.</span>'
        + '<a class="hb-sec-more" href="#/targets">All Targets Tab (' + allInfos.length + ') &rarr;</a>'
        + '</div>';
    }

    return '<div class="eng-apath station-card neon-lane-cyan">'
      + '<div class="hb-board-head">'
      + '  <div class="hb-board-title-wrap"><h2 class="coach-sec-h">Targets &amp; Attack Paths</h2></div>'
      + '  <button type="button" class="cr-btn-neon neon-cyan small" id="hb-toggle-bulk">' + (showBulk && allInfos.length ? 'Hide Target Import' : '+ Add / Paste Targets') + '</button>'
      + '</div>'
      + (filterBar ? '<div class="hb-board-filter-row">' + filterBar + '</div>' : '')
      + bulkBox
      + (rows ? '<div class="apath-rows ws-clear-box">' + rows + '</div>' : '')
      + capFooter
      + '</div>';
  }

  function libraryList() {
    var rows = OBOL.store.listEngagements().map(function (e) {
      var prof = e.profile || {};
      var preset = (OBOL.profile.PRESETS[prof.platform] || OBOL.profile.PRESETS.custom);
      var active = e.id === OBOL.store.activeId();
      return '<li class="lib-row' + (active ? ' active' : '') + '">'
        + '<button class="lib-open" data-eng="' + esc(e.id) + '"><span class="lib-name">' + esc(OBOL.store.runLabel(e)) + '</span>'
        + '<span class="pill">' + esc(preset.name) + '</span>'
        + '<span class="lib-meta">' + (e.targets || []).length + ' Targets · ' + (e.facts || []).length + ' Facts</span></button>'
        + '<button class="lib-del" data-eng="' + esc(e.id) + '" title="Delete">×</button></li>';
    }).join('');
    return '<ul class="lib-list">' + rows + '</ul>';
  }

  var ACC_BADGE = {
    privileged: { label: 'OWNED', cls: 'hb-acc-root', rank: 4 },
    foothold: { label: 'FOOTHOLD', cls: 'hb-acc-foot', rank: 3 },
    credentialed: { label: 'CREDS', cls: 'hb-acc-cred', rank: 2 },
    enumerated: { label: 'ENUM', cls: 'hb-acc-enum', rank: 1 },
    discovered: { label: 'SCAN', cls: 'hb-acc-disc', rank: 0 },
  };
  function hostLevel(f) {
    if (f.has('access.system') || f.has('access.admin') || f.has('access.root')) return 'privileged';
    if (f.has('foothold.windows') || f.has('foothold.linux') || f.has('access.shell') || f.has('winrm.authenticated') || f.has('foothold.webshell')) return 'foothold';
    if (f.has('credential.available') || f.has('credential.candidate')) return 'credentialed';
    if (f.facts.some(function (x) { return x.state === 'supported' && x.kind.indexOf('target.') !== 0 && x.kind.indexOf('host.') !== 0; })) return 'enumerated';
    return 'discovered';
  }
  function hostPorts(f) {
    var seen = {}, out = [];
    f.facts.forEach(function (x) { if (x.state !== 'supported') return; var p = (x.value || {}).port; if (p != null && !seen[p]) { seen[p] = 1; out.push(+p); } });
    return out.sort(function (a, b) { return a - b; });
  }
  function hostFlags(f) {
    var seen = {}, n = 0;
    ['objective.root_flag', 'objective.local_flag', 'objective.flag'].forEach(function (k) {
      (f.values(k) || []).forEach(function (v, idx) {
        var key = k + '|' + ((v && v.flag) ? String(v.flag).trim().toLowerCase() : idx);
        if (!seen[key]) { seen[key] = 1; n++; }
      });
    });
    return n;
  }
  function fval(f, k) { try { return (f.values(k) || [])[0] || null; } catch (e) { return null; } }
  function cleanOsDisplay(str) {
    if (!str) return '';
    str = String(str).trim();
    var cpeM = str.match(/cpe:\/o:([a-z0-9_-]+):([a-z0-9_.:-]+)/i);
    if (cpeM) {
      var prodParts = cpeM[2].split(':');
      var decoded = prodParts.join(' ')
        .replace(/_/g, ' ')
        .replace(/\bwindows\b/gi, 'Windows')
        .replace(/\bserver\b/gi, 'Server')
        .replace(/\br2\b/gi, 'R2')
        .replace(/\bsp(\d+)\b/gi, 'SP$1')
        .replace(/\bsp\b/gi, 'SP')
        .replace(/\s{2,}/g, ' ')
        .trim();
      if (/windows/i.test(decoded)) return decoded.indexOf('Windows') === 0 ? decoded : ('Windows ' + decoded);
      if (/ubuntu/i.test(decoded)) return decoded.indexOf('Ubuntu') === 0 ? decoded : ('Ubuntu ' + decoded);
      if (/debian/i.test(decoded)) return decoded.indexOf('Debian') === 0 ? decoded : ('Debian ' + decoded);
    }
    return str.replace(/;\s*CPE:.*$/i, '').trim();
  }
  function hostOs(f, t) {
    if (t && t.os) return cleanOsDisplay(t.os);
    var specific = '', fam = '';
    ['host.os_hint', 'host.os', 'host.os_family'].forEach(function (k) {
      (f.values(k) || []).forEach(function (v) {
        v = v || {};
        var os = cleanOsDisplay(v.os || '').trim();
        if (!specific && os && /[\s\d]/.test(os)) specific = os;
        if (!fam) fam = (v.family || v.name || (/^(windows|linux)$/i.test(os) ? os : '')).trim();
      });
    });
    if (specific) return specific;
    return fam ? fam.charAt(0).toUpperCase() + fam.slice(1) : '';
  }
  function hostDomain(f) {
    var v = fval(f, 'ad.domain_known') || fval(f, 'host.domain') || fval(f, 'ad.dc_candidate') || {};
    return (v && (v.domain || v.name || v.fqdn || v.dns_domain)) || '';
  }
  function hostServices(f) {
    var out = [], seen = {};
    (f.facts || []).forEach(function (x) {
      if (x.state !== 'supported') return;
      var m = /^([a-z0-9]+)\.reachable$/.exec(x.kind);
      if (m) { var s = m[1].toUpperCase(); if (!seen[s]) { seen[s] = 1; out.push(s); } }
    });
    return out;
  }
  function pinnedSet(eng) { return ((eng.ui || {}).pinnedTargets) || []; }

  var _targetInfosCache = { key: '', list: [] };

  function targetInfos(eng) {
    if (!eng) return [];
    var pack = OBOL.packs.actions();
    var pins = pinnedSet(eng);
    var tSig = (eng.targets || []).map(function (t) { return (t.ip || t.id || '') + ':' + (t.hostname || '') + ':' + (t.domain || '') + ':' + (t.os || '') + ':' + ((t.previousIps || []).join(',')); }).join('|');
    var supCount = 0;
    (eng.facts || []).forEach(function (f) { if (f && f.state === 'supported') supCount++; });
    var cacheKey = [
      eng.id || '',
      eng._rev || 0,
      eng.updatedAt || 0,
      (eng.facts || []).length,
      supCount,
      (eng.targets || []).length,
      pack.length,
      (eng.profile && eng.profile.platform) || '',
      (eng.profile && eng.profile.workflow) || '',
      pins.join(','),
      tSig,
    ].join('::');
    if (_targetInfosCache.key === cacheKey) {
      return _targetInfosCache.list;
    }
    var focus = (OBOL.profile && eng.profile) ? OBOL.profile.profileFocus(eng.profile) : [];
    var flagsOn = (!OBOL.profile || !OBOL.profile.hasFlags || !eng) ? true : OBOL.profile.hasFlags(eng.profile);
    var list = (eng.targets || []).map(function (t) {
      var ip = t.ip || t.id;
      var f = OBOL.store.factSetForTarget(ip);
      var lvl = hostLevel(f);
      var targetOwnedAndDone = lvl === 'privileged' && (!flagsOn || (f.has('objective.local_flag') && f.has('objective.root_flag')));
      var moves = targetOwnedAndDone ? [] : OBOL.pack.rankActions(f, pack, { focusPrefixes: focus, noFlags: !flagsOn })
        .filter(function (a) { return !(OBOL.pack.isReportOnly && OBOL.pack.isReportOnly(a, pack)); });
      var nextMove = targetOwnedAndDone ? null : (moves.filter(function (a) { return OBOL.phases.prematurity(a, f) === 0; })[0] || moves[0]);
      return {
        t: t, ip: ip, host: t.hostname || '', os: hostOs(f, t),
        lvl: lvl, badge: ACC_BADGE[lvl], ports: hostPorts(f), flags: hostFlags(f),
        domain: hostDomain(f), svcs: hostServices(f),
        next: nextMove ? nextMove.title : '', pinned: pins.indexOf(t.id) >= 0,
      };
    });
    _targetInfosCache = { key: cacheKey, list: list };
    return list;
  }
  function hostsFixCmd(oldIp, newIp, host, dom) {
    if (!oldIp || !newIp || oldIp === newIp) return '';
    return "sudo sed -i 's/" + oldIp.replace(/\./g, '\\.') + "/" + newIp + "/g' /etc/hosts";
  }

  function renderEditDrawer(ip) {
    var eng = (OBOL.store && OBOL.store.active && OBOL.store.active()) || {};
    var t = ((eng.targets || []).find(function (x) { return x && (x.ip === ip || x.id === ip); })) || {};
    var idn = (OBOL.store && OBOL.store.targetIdentity) ? OBOL.store.targetIdentity(ip) : { ip: ip, hostname: t.hostname || '', domain: t.domain || '', os: t.os || '' };
    var curLhost = (eng.params && eng.params.lhost) || '';
    var prevIps = Array.isArray(t.previousIps) ? t.previousIps : [];
    var lastOldIp = prevIps.length ? prevIps[prevIps.length - 1] : '';
    var sedCmd = lastOldIp ? hostsFixCmd(lastOldIp, idn.ip || ip, idn.hostname, idn.domain) : '';

    return '<div class="tgt-edit-drawer ws-clear-box" data-te-drawer="' + U.attr(ip) + '" hidden>'
      + '<div class="tgt-edit-head">'
      + '  <div>'
      + '    <span class="tgt-edit-kicker">TARGET IDENTITY &amp; RESPAWN RE-IP</span>'
      + '    <div class="tgt-edit-title">Edit Target or Migrate to Respawned Lab IP</div>'
      + '  </div>'
      + '  <button type="button" class="cr-btn-glass small" data-te-cancel="' + U.attr(ip) + '">Close ✕</button>'
      + '</div>'
      + '<p class="tgt-edit-sub">Lab timed out and assigned a new IP? Enter the new IP below. OBOL migrates all proven facts, credentials, checklist states, and rewrites your Run Log commands to the new address so you can pick right back up.</p>'
      + '<div class="tgt-edit-grid">'
      + '  <label class="tgt-edit-field"><span>Target IP Address</span><input type="text" class="ev-cmd" data-te-field="ip" value="' + U.attr(idn.ip || ip) + '" placeholder="e.g. 10.129.204.88" autocomplete="off" spellcheck="false" inputmode="decimal"></label>'
      + '  <label class="tgt-edit-field"><span>Hostname <span class="targets-add-opt">(Optional)</span></span><input type="text" class="ev-cmd" data-te-field="hostname" value="' + U.attr(idn.hostname || '') + '" placeholder="e.g. dc01 or forest" autocomplete="off" spellcheck="false"></label>'
      + '  <label class="tgt-edit-field"><span>Domain <span class="targets-add-opt">(Optional)</span></span><input type="text" class="ev-cmd" data-te-field="domain" value="' + U.attr(idn.domain || '') + '" placeholder="e.g. htb.local" autocomplete="off" spellcheck="false"></label>'
      + '  <label class="tgt-edit-field"><span>OS <span class="targets-add-opt">(Optional)</span></span><input type="text" class="ev-cmd" data-te-field="os" value="' + U.attr(idn.os || '') + '" placeholder="e.g. Windows Server 2019 or Ubuntu 22.04" autocomplete="off" spellcheck="false"></label>'
      + '  <label class="tgt-edit-field"><span>Your VPN IP / LHOST <span class="targets-add-opt">(If VPN Changed)</span></span><input type="text" class="ev-cmd" data-te-field="lhost" value="' + U.attr(curLhost) + '" placeholder="e.g. 10.10.14.9" autocomplete="off" spellcheck="false" inputmode="decimal"></label>'
      + '</div>'
      + (sedCmd
          ? '<div class="tgt-edit-hosts-tip">'
            + '<span class="tgt-edit-hosts-l">Previous IP: <code>' + esc(lastOldIp) + '</code> &rarr; <code>' + esc(idn.ip || ip) + '</code> · Update <code>/etc/hosts</code> on Kali:</span>'
            + '<div class="tgt-edit-hosts-cmd"><code>' + esc(sedCmd) + '</code><button type="button" class="btn-copy small" data-copy="' + U.attr(sedCmd) + '">Copy</button></div>'
            + '</div>'
          : '')
      + '<div class="tgt-edit-foot">'
      + '  <button type="button" class="cr-btn-glass small" data-te-cancel="' + U.attr(ip) + '">Cancel</button>'
      + '  <button type="button" class="cr-btn-neon neon-cyan small" data-te-save="' + U.attr(ip) + '" data-te-mode="stay">Save Target</button>'
      + '  <button type="button" class="cr-btn-neon neon-emerald small" data-te-save="' + U.attr(ip) + '" data-te-mode="replay">Save &amp; Replay in Run Log &rarr;</button>'
      + '</div>'
      + '</div>';
  }

  function bindEditDrawer(mount, opts) {
    if (!mount || mount._obolTargetEditBound) return;
    mount._obolTargetEditBound = true;
    opts = opts || {};

    U.on(mount, 'click', '[data-edit-target]', function (e, btn) {
      e.preventDefault();
      e.stopPropagation();
      var ip = btn.getAttribute('data-edit-target');
      if (!ip) return;
      var detailsParent = btn.closest('details.apath-row');
      if (detailsParent && !detailsParent.open) detailsParent.open = true;
      var drawer = mount.querySelector('[data-te-drawer="' + CSS.escape(ip) + '"]')
        || Array.prototype.find.call(mount.querySelectorAll('[data-te-drawer]'), function (el) { return el.getAttribute('data-te-drawer') === ip; });
      if (!drawer) return;
      var isHidden = drawer.hasAttribute('hidden');
      if (isHidden) {
        drawer.removeAttribute('hidden');
        var ipInput = drawer.querySelector('[data-te-field="ip"]');
        if (ipInput) {
          setTimeout(function () {
            try { ipInput.focus(); ipInput.select(); } catch (err) {}
          }, 20);
        }
      } else {
        drawer.setAttribute('hidden', '');
      }
    });

    U.on(mount, 'click', '[data-te-cancel]', function (e, btn) {
      e.preventDefault();
      e.stopPropagation();
      var drawer = btn.closest('[data-te-drawer]');
      if (drawer) drawer.setAttribute('hidden', '');
    });

    U.on(mount, 'click', '[data-te-save]', function (e, btn) {
      e.preventDefault();
      e.stopPropagation();
      var oldIp = btn.getAttribute('data-te-save');
      var mode = btn.getAttribute('data-te-mode') || 'stay';
      var drawer = btn.closest('[data-te-drawer]');
      if (!drawer || !oldIp || !OBOL.store || !OBOL.store.editTarget) return;

      function val(name) {
        var el = drawer.querySelector('[data-te-field="' + name + '"]');
        return el ? String(el.value || '').trim() : '';
      }
      var newIp = val('ip');
      if (!newIp) {
        U.toast('Target IP cannot be empty', 'err');
        return;
      }
      var res = OBOL.store.editTarget(oldIp, {
        ip: newIp,
        hostname: val('hostname'),
        domain: val('domain'),
        os: val('os'),
        lhost: val('lhost'),
      });
      if (!res || !res.ok) {
        U.toast((res && res.error) || 'Failed to update target', 'err');
        return;
      }
      if (OBOL.app && OBOL.app.renderSidebar) OBOL.app.renderSidebar();
      if (OBOL.ctxbar && OBOL.ctxbar.render) OBOL.ctxbar.render();

      var msgParts = [];
      if (res.reIp) {
        msgParts.push('Re-IP ' + res.oldIp + ' -> ' + res.newIp);
        if (res.rewrittenCommands) msgParts.push(res.rewrittenCommands + ' Run Log cmd' + (res.rewrittenCommands === 1 ? '' : 's') + ' updated');
      } else {
        msgParts.push('Target ' + res.newIp + ' updated');
      }
      if (res.lhostChanged) {
        msgParts.push('LHOST -> ' + res.newLhost);
      }
      U.toast(msgParts.join(' · '));

      if (mode === 'replay') {
        try {
          sessionStorage.setItem('obol.history.mode', 'replay');
          sessionStorage.setItem('obol.history.target', res.newIp);
        } catch (err) {}
        location.hash = '#/history';
        return;
      }
      if (typeof opts.onSaved === 'function') {
        opts.onSaved(res);
        return;
      }
      OBOL.router.render();
    });
  }

  OBOL.targets = OBOL.targets || {};
  OBOL.targets.all = function (eng) { return targetInfos(eng || OBOL.store.active() || { targets: [] }); };
  OBOL.targets.hostOs = hostOs;
  OBOL.targets.cleanOs = cleanOsDisplay;
  OBOL.targets.ACC_BADGE = ACC_BADGE;
  OBOL.targets.parseBulkInput = parseBulkInput;
  OBOL.targets.importBulk = importBulkTargets;
  OBOL.targets.renderEditDrawer = renderEditDrawer;
  OBOL.targets.bindEditDrawer = bindEditDrawer;
  OBOL.targets.hostsFixCmd = hostsFixCmd;

  // ── Connectivity: pivots + tunnel-setup chooser + symptom-first troubleshooter ──
  function connData(eng) {
    var fs = OBOL.store.factSet();
    var SUP = OBOL.facts.ProofState.SUPPORTED;
    var names = {};
    (eng.targets || []).forEach(function (t) { names[t.ip || t.id] = t.hostname || ''; });
    var byHost = {};
    function host(ip) { return byHost[ip] || (byHost[ip] = { ip: ip, hostname: names[ip] || '', subnets: {}, multihomed: false, tunnels: [] }); }
    (fs.facts || []).forEach(function (f) {
      if (f.state !== SUP) return;
      var ip = (f.scope || '').indexOf('host:') === 0 ? f.scope.slice(5) : '';
      if (!ip) return;
      if (f.kind === 'scan.local.interfaces' || f.kind === 'scan.local.routes') {
        var h = host(ip); (f.value.subnets || []).forEach(function (s) { h.subnets[s] = 1; });
      } else if (f.kind === 'host.multihomed') {
        host(ip).multihomed = true;
      } else if (f.kind === 'tunnel.socks' || f.kind === 'tunnel.route' || f.kind === 'tunnel.dns') {
        host(ip).tunnels.push({ kind: f.kind.split('.')[1], via: f.value.via || '' });
      }
    });
    return Object.keys(byHost).map(function (ip) {
      var h = byHost[ip]; h.subnetList = Object.keys(h.subnets); return h;
    }).filter(function (h) { return h.subnetList.length || h.tunnels.length || h.multihomed; });
  }

  function tunnelChooser(params) {
    var tools = OBOL.TUNNELS || [];
    if (!tools.length || !OBOL.renderTunnelSteps) return '';
    var sel = tools.filter(function (t) { return t.key === _tunnelSel; })[0] || tools[0];
    var tabs = tools.map(function (t) {
      var on = t.key === sel.key;
      return '<button type="button" class="conn-tool' + (on ? ' on' : '') + '" data-tunnel-sel="' + esc(t.key) + '" aria-pressed="' + (on ? 'true' : 'false') + '">'
        + '<span class="conn-tool-n">' + esc(t.name) + '</span>'
        + (t.rec ? '<span class="conn-rec">Recommended</span>' : '')
        + '</button>';
    }).join('');
    return '<div class="conn-chooser">'
      + '<div class="conn-tool-row" role="group" aria-label="Choose a tunnel tool">' + tabs + '</div>'
      + '<div class="conn-sel"><p class="conn-sel-when">' + esc(sel.when || sel.summary) + '</p>'
      + (sel.prereq ? '<p class="stage-prereq"><span class="stage-prereq-l">Before You Start:</span> ' + esc(sel.prereq) + '</p>' : '')
      + '<details class="conn-steps"><summary><span class="stage-sum-l">Setup Steps</span>'
      + '<span class="stage-sum-d">step by step, on your box and the host</span></summary>'
      + OBOL.renderTunnelSteps(sel, params) + '</details>'
      + '</div></div>';
  }

  function connMap(pivots, params) {
    var lhost = (params && params.lhost) || 'your box';
    return '<div class="conn-map" role="group" aria-label="Pivot connectivity map">' + pivots.map(function (h) {
      var label = h.hostname || h.ip;
      var subs = h.subnetList.length ? h.subnetList.join(', ') : 'Subnet Unknown';
      var via = h.tunnels.length ? ('Via ' + h.tunnels.map(function (t) { return t.via || t.kind; }).join(', ')) : '';
      var live = h.tunnels.length;
      return '<div class="conn-row">'
        + '<span class="conn-node conn-you">' + OBOL.ic('box') + '<span class="conn-node-l">You</span><span class="conn-node-s">' + esc(lhost) + '</span></span>'
        + '<span class="conn-edge' + (live ? ' conn-edge-live' : '') + '"><span class="conn-edge-line" aria-hidden="true"></span>'
        + '<span class="conn-edge-tag' + (live ? '' : ' conn-edge-off') + '">' + esc(via || 'No Tunnel Yet') + '</span>'
        + '<span class="conn-edge-warntag" aria-hidden="true">Needs Attention</span></span>'
        + '<span class="conn-node conn-pivot">' + OBOL.ic('host') + '<span class="conn-node-l">' + esc(label) + '</span>'
        + (h.hostname ? '<span class="conn-node-s">' + esc(h.ip) + '</span>' : '') + (h.multihomed ? '<span class="conn-tag-mh">Multihomed</span>' : '') + '</span>'
        + '<span class="conn-edge"><span class="conn-edge-line" aria-hidden="true"></span></span>'
        + '<span class="conn-node conn-net">' + OBOL.ic('disk') + '<span class="conn-node-l">' + esc(subs) + '</span><span class="conn-node-s">Reachable Subnet</span></span>'
        + '</div>';
    }).join('') + '</div>';
  }

  function troubleProbe(p, params) {
    var cmd = OBOL.pivotDoctor.fill(p.cmd, params);
    var whereLbl = p.where === 'host' ? 'On The Target Host' : 'On Your Kali Box';
    return '<li class="stage-step stage-' + (p.where === 'host' ? 'host' : 'local') + '">'
      + '<div class="stage-body" style="margin-left:0"><div class="stage-wl">'
      + '<span class="stage-where stage-where-' + (p.where === 'host' ? 'host' : 'local') + '">' + esc(whereLbl) + '</span>'
      + '<span class="stage-title">' + esc(p.label) + '</span></div>'
      + '<div class="stage-why">' + esc(p.why) + '</div>'
      + '<div class="stage-cmd"><code>' + esc(cmd) + '</code><button class="btn-copy stage-copy" data-copy="' + U.attr(cmd) + '" title="Copy command">copy</button></div>'
      + '</div></li>';
  }
  function troublePanel(params) {
    if (!OBOL.pivotDoctor) return '';
    var syms = OBOL.pivotDoctor.symptoms();
    var chips = syms.map(function (s) {
      var on = s.key === _ptrSym;
      return '<button type="button" class="ptr-sym' + (on ? ' on' : '') + '" data-ptr-sym="' + esc(s.key) + '" aria-pressed="' + (on ? 'true' : 'false') + '">' + esc(s.symptom) + '</button>';
    }).join('');
    var body = '';
    var sel = _ptrSym ? OBOL.pivotDoctor.get(_ptrSym) : null;
    if (sel) {
      var probes = '<ol class="stage-steps ptr-probes">' + sel.probes.map(function (p) { return troubleProbe(p, params); }).join('') + '</ol>';
      body = '<div class="ptr-body">'
        + '<p class="ptr-hint">' + esc(sel.hint) + '</p>'
        + '<div class="ptr-probe-h">Run one of these, then paste what it prints:</div>'
        + probes
        + '<textarea class="ptr-paste" data-ptr-paste placeholder="Paste the probe output here. OBOL reads it and tells you what is wrong and how to fix it." spellcheck="false"></textarea>'
        + '<div class="ptr-row"><button type="button" class="btn-primary ptr-go" data-ptr-go="' + esc(sel.key) + '">Diagnose</button>'
        + '<button type="button" class="btn-ghost ptr-clear" data-ptr-clear>Clear</button></div>'
        + '<div class="ptr-verdict" role="status" aria-live="polite"></div>'
        + '</div>';
    }
    return '<details class="conn-trouble"' + (_ptrSym ? ' open' : '') + '><summary><span class="ct-sum-l">Pivot Not Working?</span>'
      + '<span class="ct-sum-d">Describe what you see - OBOL diagnoses it.</span></summary>'
      + '<p class="ptr-lead">Pick what you are seeing. You do not need to know the cause.</p>'
      + '<div class="ptr-syms" role="group" aria-label="What are you seeing?">' + chips + '</div>'
      + body + '</details>';
  }

  function verdictHtml(res) {
    if (!res) return '';
    if (res.empty) return '<div class="ptr-v ptr-v-note">' + esc(res.verdict) + '</div>';
    if (!res.matched) {
      var items = (res.checklist || []).map(function (c) { return '<li>' + esc(c) + '</li>'; }).join('');
      return '<div class="ptr-v ptr-v-note"><p class="ptr-v-say">' + esc(res.verdict) + '</p>'
        + (items ? '<ul class="ptr-checklist">' + items + '</ul>' : '') + '</div>';
    }
    var cls = res.healthy ? 'ptr-v-ok' : 'ptr-v-bad';
    var lbl = res.healthy ? 'Looks healthy' : 'Likely cause';
    var line = res.line ? '<div class="ptr-line"><span class="ptr-line-l">From Your Output</span> <code>' + esc(res.line) + '</code></div>' : '';
    var fix = res.fix ? '<div class="ptr-fix"><span class="ptr-fix-l">' + (res.healthy ? 'Next' : 'Try This Fix') + '</span>'
      + '<div class="stage-cmd"><code>' + esc(res.fix) + '</code><button class="btn-copy stage-copy" data-copy="' + U.attr(res.fix) + '" title="Copy command">copy</button></div></div>' : '';
    return '<div class="ptr-v ' + cls + '"><div class="ptr-v-h">' + esc(lbl) + '</div>'
      + '<p class="ptr-v-say">' + esc(res.verdict) + '</p>' + line + fix + '</div>';
  }
  function setConnWarn(mount, on) { var hb = mount.querySelector('.hb-conn'); if (hb) hb.classList.toggle('hb-conn--warn', on); }

  function connPanel() {
    var eng = OBOL.store.active();
    var params = eng.params || {};
    var pivots = connData(eng);
    if (!pivots.length) {
      return '<div class="hb-conn station-card neon-lane-amber"><div class="hb-sec-h"><h2>Connectivity &amp; Pivots</h2></div>'
        + '<div class="conn-empty ws-clear-box">No Pivots Charted Yet. Paste <code>ip a</code> or <code>ip route</code> from a foothold and OBOL maps the subnets it can reach - a tunnel chooser appears here once there is a pivot to set up.</div></div>';
    }
    return '<div class="hb-conn station-card neon-lane-amber' + (troubleOn() ? ' hb-conn--warn' : '') + '"><div class="hb-sec-h"><h2>Connectivity &amp; Pivots</h2>'
      + '<span class="hb-sec-n">' + pivots.length + ' pivot' + (pivots.length > 1 ? 's' : '') + '</span>'
      + '<span class="conn-warnchip">' + OBOL.ic('bolt') + 'Needs Attention</span>'
      + '</div>' + connMap(pivots, params)
      + '<div class="conn-chooser-h"><h3>Set Up A Tunnel</h3><span class="conn-chooser-sub">Pick a tool, then follow the steps on each machine.</span></div>'
      + tunnelChooser(params)
      + troublePanel(params)
      + '</div>';
  }

  // New Engagement / Pre-Engagement Launchpad Form
  function setupDrawerHtml(configured, sel, prof) {
    var hiddenAttr = (configured && !_showNewSetup) ? ' hidden' : '';
    var active = OBOL.store.active() || {};
    var actP = active.params || {};
    var preOsid = !configured ? (prof.osid || '') : '';
    var preCand = !configured ? (prof.candidate || '') : '';
    var preClient = !configured ? (prof.client || '') : '';
    var preWorkdir = !configured ? ((active.workspace && active.workspace.root) || '') : '';
    var preScopeLines = [];
    if (!configured) {
      var seenScope = {};
      (active.targets || []).forEach(function (t) {
        var ip = (t && (t.ip || t.id)) || '';
        if (!ip || seenScope[ip]) return;
        seenScope[ip] = 1;
        preScopeLines.push(t.hostname && t.hostname !== ip ? (ip + ' ' + t.hostname) : ip);
      });
      if (actP.target && !seenScope[actP.target]) {
        seenScope[actP.target] = 1;
        preScopeLines.push(actP.target + (actP.domain && actP.target.indexOf(actP.domain) < 0 ? (' ' + actP.domain) : ''));
      }
      ((prof && prof.scope) || []).forEach(function (s) {
        if (s && !seenScope[s]) { seenScope[s] = 1; preScopeLines.push(s); }
      });
    }
    var preScope = preScopeLines.join('\n');
    var stagedFactCount = !configured ? Object.keys(OBOL.store.factSet().kinds()).length : 0;
    var stagedBanner = (!configured && (preScopeLines.length > 0 || stagedFactCount > 0))
      ? '<div class="eng-staged-notice ws-clear-box"><strong>Staged data ready:</strong> '
        + (preScopeLines.length ? (preScopeLines.length + ' target' + (preScopeLines.length === 1 ? '' : 's')) : '')
        + (preScopeLines.length && stagedFactCount ? ' and ' : '')
        + (stagedFactCount ? (stagedFactCount + ' fact' + (stagedFactCount === 1 ? '' : 's')) : '')
        + ' pre-filled below. Choose your Platform Profile and click <em>Create &amp; Launch Engagement</em> to begin.</div>'
      : '';

    var welcomeBanner = !configured
      ? '<div class="eng-welcome">'
        + '<div class="eng-welcome-main">'
        + '  <span class="hb-drawer-kicker">PRE-ENGAGEMENT LAUNCHPAD</span>'
        + '  <div class="eng-welcome-h">Set Up Your Engagement</div>'
        + '  <p class="eng-welcome-sub">Pick a platform profile, paste your target IPs or Nmap scan, and launch. OBOL configures your working folder, seeds recon moves, and tracks every host from scan to report.</p>'
        +    stagedBanner
        + '</div>'
        + '</div>'
      : '<div class="hb-drawer-head">'
        + '  <div><span class="hb-drawer-kicker">NEW RUN</span><h2 class="coach-sec-h">Create New Engagement</h2></div>'
        + '  <button type="button" class="cr-btn-glass small" id="hb-setup-close">Close ✕</button>'
        + '</div>';

    return '<div id="eng-setup-drawer" class="eng-setup-drawer"' + hiddenAttr + '>'
      + '<div class="eng-create station-card neon-lane-cyan" id="eng-setup">'
      + welcomeBanner
      + loadoutSetupCard()
      + '<div class="eng-row2">'
      + '  <label class="eng-field"><span>1. Engagement Name</span><input id="eng-name" placeholder="e.g. OSCP Prep Set A or Lab Run 01" autocomplete="off"></label>'
      + '  <label class="eng-field"><span>Machine Focus <span class="eng-field-opt">(Optional)</span></span><select id="eng-mt">' + machineOptions(prof.machine_type || '') + '</select></label>'
      + '</div>'
      + '<div class="eng-field"><span>2. Platform Profile <span class="eng-field-opt">(decides flag objectives, exam constraints &amp; report template)</span></span><div class="pf-grid" id="pf-grid">' + platformCards(sel) + '</div></div>'
      + '<div class="eng-row2">'
      + '  <label class="eng-field pf-osid" id="pf-osid-wrap" style="display:none"><span>OSID (OffSec Exam)</span><input id="eng-osid" value="' + U.attr(preOsid) + '" placeholder="OS-XXXXX"></label>'
      + '  <label class="eng-field pf-osid" id="pf-cand-wrap" style="display:none"><span>Candidate / Assessor</span><input id="eng-cand" value="' + U.attr(preCand) + '" placeholder="Your name"></label>'
      + '  <label class="eng-field pf-osid" id="pf-client-wrap" style="display:none"><span>Client / Organization</span><input id="eng-client" value="' + U.attr(preClient) + '" placeholder="e.g. Acme Corp"></label>'
      + '</div>'
      + '<label class="eng-field"><span>3. Scope / Targets <span class="eng-field-opt">(paste IPs, CIDRs, /etc/hosts, or raw Nmap output - junk is filtered)</span></span>'
      + '<textarea id="eng-scope" class="ev-textarea ws-clear-box" style="min-height:84px" placeholder="10.10.10.10 dc01.corp.local&#10;10.10.10.20 sql01.corp.local&#10;10.10.10.0/24">' + esc(preScope) + '</textarea></label>'
      + '<div class="eng-box-settings ws-clear-box">'
      + '  <div class="eng-box-settings-h"><span>4. Box &amp; Workspace Context</span><span class="muted small">Optional - defaults to ~/engagements/&lt;name&gt; and auto-learns tun0 from prompts</span></div>'
      + (function () {
          var arP = null; try { arP = JSON.parse(localStorage.getItem('obol.arsenal-profile') || 'null'); } catch (e) {}
          var defLh = actP.lhost || (arP && arP.lhost) || '';
          var defIf = actP.lhost_iface || (arP && arP.lhost_iface) || 'tun0';
          return '  <div class="eng-row3">'
            + '    <label class="eng-field"><span>Working Directory (Kali)</span><input id="eng-workdir" value="' + U.attr(preWorkdir) + '" autocomplete="off" spellcheck="false" placeholder="' + esc(workdirHint()) + '"></label>'
            + '    <label class="eng-field"><span>Your VM IP (LHOST)</span><input id="eng-lhost" value="' + U.attr(defLh) + '" autocomplete="off" spellcheck="false" inputmode="decimal" placeholder="e.g. 10.10.14.9"></label>'
            + '    <label class="eng-field"><span>Interface</span><select id="eng-iface">'
            +      ['tun0', 'tun1', 'tap0', 'eth0', 'wlan0', 'vpn0', 'wg0'].map(function (i) { return '<option value="' + i + '"' + (i === defIf ? ' selected' : '') + '>' + i + '</option>'; }).join('')
            + '    <option value="">other / none</option></select></label>';
        })()
      + '    <label class="eng-field"><span>Attack Workflow</span><select id="eng-wf">' + workflowOptions(prof.workflow || '') + '</select></label>'
      + '  </div>'
      + '</div>'
      + '<div class="eng-launch-row">'
      + '  <button id="eng-launch" class="cr-btn-neon neon-emerald">Create &amp; Launch Engagement &rarr;</button>'
      + '</div>'
      + '</div>'
      + '</div>';
  }

  function hubDashboard() {
    var eng = OBOL.store.active();
    var acts = (eng.activities || []).slice(-5).reverse().map(function (a) {
      return '<li><span class="hb-log-t">' + esc(ago(a.at) || '') + '</span><span class="hb-log-c">' + esc(a.title || a.summary || a.command || a.cmd || 'activity') + '</span></li>';
    }).join('');

    return '<section class="hub" aria-label="Engagement hub">'
      + activePanel()
      + '<div class="hb-grid">'
      + '  <section class="hb-col-main" aria-label="Targets and attack paths">'
      +      engagementPath()
      + '  </section>'
      + '  <aside class="hb-col-rail" aria-label="Workspace and connectivity">'
      +      workspacePanel()
      +      connPanel()
      + '    <div class="hb-recent station-card neon-lane-emerald">'
      + '      <div class="hb-sec-h"><h2>Recent Activity</h2><a class="hb-sec-more" href="#/history">Full Run Log &rarr;</a></div>'
      +        (acts ? '<ul class="hb-log ws-clear-box">' + acts + '</ul>' : '<div class="hb-log-empty ws-clear-box">Nothing logged yet. Your commands and proofs will appear here.</div>')
      + '    </div>'
      + '  </aside>'
      + '</div>'
      + '</section>';
  }

  function render() {
    var active = OBOL.store.active();
    if (active && active.id !== _lastEngId) {
      if (_lastEngId !== null) {
        _showNewSetup = false;
        _showEditRun = false;
        _showBulkTarget = false;
        _targetFilter = 'all';
      }
      _lastEngId = active.id;
    }
    var prof = (active || {}).profile || {};
    var sel = prof.platform || 'custom';
    var factCount = Object.keys(OBOL.store.factSet().kinds()).length;
    var configured = isConfigured(active, factCount);
    return '<section class="engscreen">'
      + topCommandBar(configured)
      + (configured ? editRunDrawer(active) : '')
      + setupDrawerHtml(configured, sel, prof)
      + (configured ? hubDashboard() : '')
      + '</section>';
  }

  function syncOsidVisibility() {
    var sel = (document.querySelector('input[name="pf-platform"]:checked') || {}).value || 'custom';
    var preset = OBOL.profile.listPresets().find(function (p) { return p.id === sel; }) || {};
    var o = document.getElementById('pf-osid-wrap'), c = document.getElementById('pf-cand-wrap'), cl = document.getElementById('pf-client-wrap');
    var oVal = ((document.getElementById('eng-osid') || {}).value || '').trim();
    var cVal = ((document.getElementById('eng-cand') || {}).value || '').trim();
    var clVal = ((document.getElementById('eng-client') || {}).value || '').trim();
    var showOsid = (preset.osid || oVal) ? '' : 'none';
    var showCand = (preset.osid || preset.client_field || sel === 'cpts' || sel === 'pnpt' || cVal) ? '' : 'none';
    var showClient = (preset.client_field || sel === 'pnpt' || clVal) ? '' : 'none';
    if (o) o.style.display = showOsid;
    if (c) c.style.display = showCand;
    if (cl) cl.style.display = showClient;
  }

  function ensureArsenal() {
    if (OBOL.arsenal && OBOL.arsenal.buildScript && OBOL.arsenal.ingestInventory) return Promise.resolve(true);
    if (OBOL.lazy && OBOL.lazy.loadGroup) return OBOL.lazy.loadGroup('loadout');
    return Promise.resolve(false);
  }

  function mounted(ctx) {
    var mount = ctx.mount;

    // Platform card selection styling + OSID reveal
    U.on(mount, 'change', 'input[name="pf-platform"]', function (e, t) {
      mount.querySelectorAll('.pf-card').forEach(function (el) { el.classList.remove('sel'); });
      var card = t.closest('.pf-card'); if (card) card.classList.add('sel');
      syncOsidVisibility();
    });
    syncOsidVisibility();

    // Toggle New Engagement setup drawer on an active engagement
    U.on(mount, 'click', '#hb-toggle-new, #hb-setup-close', function (e, t) {
      _showNewSetup = (t.id === 'hb-setup-close') ? false : !_showNewSetup;
      if (_showNewSetup) _showEditRun = false;
      OBOL.router.render();
      if (_showNewSetup) {
        setTimeout(function () {
          var nm = document.getElementById('eng-name');
          if (nm) { try { nm.focus(); } catch (err) {} }
        }, 50);
      }
    });

    // Toggle In-Place Edit Run drawer
    U.on(mount, 'click', '#hb-toggle-edit, #hb-edit-close', function (e, t) {
      _showEditRun = (t.id === 'hb-edit-close') ? false : !_showEditRun;
      if (_showEditRun) _showNewSetup = false;
      OBOL.router.render();
    });

    // Sanitize LHOST (strip CIDR suffix) and Scope (strip URL scheme/port/path) on change
    U.on(mount, 'change', '#hb-edit-lhost, #eng-lhost', function (e, t) {
      var v = String(t.value || '').trim().replace(/\/\d{1,2}$/, '').trim();
      if (v !== t.value) t.value = v;
    });
    U.on(mount, 'change', '#eng-scope, #hb-bulk-input', function (e, t) {
      var v = String(t.value || '');
      var cleaned = v.replace(/\bhttps?:\/\/([^\s\/:]+)(?::\d+)?(?:\/[^\s]*)?/gi, '$1').replace(/\b((?:\d{1,3}\.){3}\d{1,3}):\d+(?:\/[^\s]*)?/g, '$1');
      if (cleaned !== v) t.value = cleaned;
    });

    // Save In-Place Edit Run changes
    U.on(mount, 'click', '#hb-edit-save', function () {
      var name = ((document.getElementById('hb-edit-name') || {}).value || '').trim();
      var wd = OBOL.workspace.sanitizeRoot(((document.getElementById('hb-edit-workdir') || {}).value || '').trim());
      var lhostEl = document.getElementById('hb-edit-lhost');
      var lhostRaw = ((lhostEl || {}).value || '').trim().replace(/\/\d{1,2}$/, '').trim();
      if (lhostEl && lhostRaw) lhostEl.value = lhostRaw;
      var lhost = /^(\d{1,3}\.){3}\d{1,3}$/.test(lhostRaw) ? lhostRaw : '';
      var iface = ((document.getElementById('hb-edit-iface') || {}).value || '').trim();
      var wf = ((document.getElementById('hb-edit-wf') || {}).value || '').trim();
      if (lhostRaw && !lhost) {
        U.toast('That VM IP does not look like a valid IPv4 address', 'err');
        return;
      }
      OBOL.store.update(function (e) {
        if (name) e.name = name;
        e.workspace = e.workspace || {};
        if (wd) e.workspace.root = wd;
        e.params = e.params || {};
        e.params.lhost = lhost;
        e.params.lhost_iface = iface;
        e.profile = e.profile || {};
        e.profile.workflow = wf;
      }, 'edit-run');
      _showEditRun = false;
      if (OBOL.app && OBOL.app.renderSidebar) OBOL.app.renderSidebar();
      U.toast('Engagement settings updated');
      OBOL.router.render();
    });

    // Target Board: toggle Bulk Target Import box
    U.on(mount, 'click', '#hb-toggle-bulk, #hb-bulk-cancel', function (e, t) {
      _showBulkTarget = (t.id === 'hb-bulk-cancel') ? false : !_showBulkTarget;
      OBOL.router.render();
      if (_showBulkTarget) {
        setTimeout(function () {
          var ta = document.getElementById('hb-bulk-input');
          if (ta) { try { ta.focus(); } catch (err) {} }
        }, 40);
      }
    });

    // Target Board: run Bulk Target Import
    U.on(mount, 'click', '#hb-bulk-go', function () {
      var ta = document.getElementById('hb-bulk-input');
      var text = (ta && ta.value) || '';
      if (!text.trim()) { U.toast('Paste one or more IPs, hostnames, or Nmap output first', 'err'); return; }
      importBulkTargets(text, function (res) {
        if (!res.ok) {
          U.toast('No valid target IPs or CIDRs found in that paste', 'err');
          return;
        }
        _showBulkTarget = false;
        var parts = [];
        if (res.arsenal && res.arsenal.ok) parts.push('Loadout stocked (' + res.arsenal.present + ' tools)');
        if (res.workspaceSync && res.workspaceSync.ok) parts.push('Workspace synced (' + res.workspaceSync.confirmed + ' confirmed)');
        if (res.added) parts.push(res.added + ' target' + (res.added === 1 ? '' : 's') + ' added');
        if (res.updated) parts.push(res.updated + ' updated');
        if (res.scanFacts) parts.push(res.scanFacts + ' scan fact' + (res.scanFacts === 1 ? '' : 's') + ' minted');
        U.toast(parts.join(', ') || 'Scope updated');
        OBOL.router.render();
      });
    });

    // Target Board: filter pills
    U.on(mount, 'click', '[data-tf]', function (e, t) {
      _targetFilter = t.getAttribute('data-tf') || 'all';
      OBOL.router.render();
    });

    // Target Board: Focus button (sets active target without toggling parent <details>)
    U.on(mount, 'click', '[data-focus-ip]', function (e, t) {
      if (e && e.preventDefault) e.preventDefault();
      if (e && e.stopPropagation) e.stopPropagation();
      var ip = t.getAttribute('data-focus-ip');
      if (!ip) return;
      if (OBOL.store.setActiveTarget) OBOL.store.setActiveTarget(ip);
      else OBOL.store.update(function (eng) {
        eng.params = eng.params || {};
        eng.params.target = ip;
        eng.activeTarget = ip;
      }, 'params');
      if (OBOL.app && OBOL.app.renderSidebar) OBOL.app.renderSidebar();
      U.toast('Active target set to ' + ip);
      OBOL.router.render();
    });

    // Target Dossier link inside <summary>: prevent toggling <details> when clicking the link
    U.on(mount, 'click', '.hb-dossier-btn', function (e) {
      if (e && e.stopPropagation) e.stopPropagation();
    });

    // Step 0 Loadout setup card inside Engagement setup: download script & ingest inventory
    U.on(mount, 'click', '.eng-lo-dl', function () {
      ensureArsenal().then(function () {
        if (!OBOL.arsenal || !OBOL.arsenal.buildScript) { U.toast('Arsenal module still loading, try again', 'err'); return; }
        var promptStamp = true;
        try {
          var v = localStorage.getItem('obol.arsenal-promptstamp');
          if (v === null) v = localStorage.getItem('obol.arsenal-stamp');
          if (v !== null) promptStamp = v === '1';
        } catch (e) {}
        var blob = new Blob([OBOL.arsenal.buildScript({ promptStamp: promptStamp })], { type: 'text/x-shellscript' });
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob); a.download = 'download-loadout.sh';
        document.body.appendChild(a); a.click();
        setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 0);
        U.toast('download-loadout.sh downloaded');
      });
    });

    U.on(mount, 'click', '.eng-lo-ingest', function () {
      var box = mount.querySelector('.eng-lo-paste'), msg = mount.querySelector('.eng-lo-msg');
      var text = (box && box.value) || '';
      if (!text.trim()) { if (msg) { msg.textContent = 'Paste the script output first.'; msg.className = 'lo-paste-msg eng-lo-msg err'; } return; }
      ensureArsenal().then(function () {
        if (!OBOL.arsenal || !OBOL.arsenal.ingestInventory) { U.toast('Arsenal module still loading, try again', 'err'); return; }
        var r = OBOL.arsenal.ingestInventory(text);
        if (r.ok) {
          if (OBOL.ingest && OBOL.ingest.ensureParsers && (/={3,}\s*OBOL STEP\s+\d+:/i.test(text) || (OBOL.ingest.splitSession && OBOL.ingest.splitSession(text).some(function (s) { return s && s.command && !/download-loadout|setup-kali/i.test(s.command); })))) {
            OBOL.ingest.ensureParsers().then(function (okp) {
              var sRes = okp ? OBOL.ingest.importSession(text, { target: 'auto' }) : null;
              var extra = (sRes && sRes.added) ? (' + ' + sRes.added + ' fact' + (sRes.added === 1 ? '' : 's') + ' minted') : '';
              U.toast('Loadout stocked ' + r.present + ' tools, ' + r.staged + ' staged' + extra);
              OBOL.router.render();
            });
            return;
          }
          U.toast('Loadout stocked ' + r.present + ' tools, ' + r.staged + ' staged');
          OBOL.router.render();
          return;
        }
        if (OBOL.ingest && OBOL.ingest.ensureParsers) {
          OBOL.ingest.ensureParsers().then(function (okp) {
            var sRes = okp ? OBOL.ingest.importSession(text, { target: 'auto' }) : null;
            if (sRes && sRes.ok && (sRes.added > 0 || (sRes.workspaceSync && sRes.workspaceSync.ok) || (sRes.targetsImported && sRes.targetsImported.ok))) {
              if (sRes.workspaceSync && sRes.workspaceSync.ok && !sRes.added) U.toast('Workspace synced: ' + sRes.workspaceSync.confirmed + ' confirmed');
              else if (sRes.targetsImported && sRes.targetsImported.ok) U.toast((sRes.targetsImported.added || 0) + ' target(s) imported');
              else U.toast('Minted ' + sRes.added + ' fact' + (sRes.added === 1 ? '' : 's') + ' from paste');
              OBOL.router.render();
              return;
            }
            if (msg) { msg.textContent = r.reason; msg.className = 'lo-paste-msg eng-lo-msg err'; }
          });
          return;
        }
        if (msg) { msg.textContent = r.reason; msg.className = 'lo-paste-msg eng-lo-msg err'; }
      });
    });

    // Copy buttons
    U.on(mount, 'click', '.btn-copy', function (e, b) {
      U.copy(b.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Command copied' : 'Copy failed', ok ? '' : 'err'); });
    });

    if (OBOL.targets && OBOL.targets.bindEditDrawer) {
      OBOL.targets.bindEditDrawer(mount);
    }

    // Remember each per-target Attack Path row's open/closed state per browser
    Array.prototype.forEach.call(mount.querySelectorAll('details[data-apath-key]'), function (d) {
      if (d._apathBound) return; d._apathBound = true;
      d.addEventListener('toggle', function () {
        try { localStorage.setItem(d.getAttribute('data-apath-key'), d.open ? '1' : '0'); } catch (e) {}
      });
    });

    // Connectivity handlers (bound once on persistent #view)
    if (!mount._obolConnBound) {
      mount._obolConnBound = true;
      U.on(mount, 'click', '[data-tunnel-sel]', function (e, t) {
        _tunnelSel = t.getAttribute('data-tunnel-sel');
        OBOL.router.render();
      });
      U.on(mount, 'click', '[data-stage]', function (e, t) {
        var id = t.getAttribute('data-stage'), i = t.getAttribute('data-stage-i'), key = 'obol.stage:' + id + ':' + i;
        var was; try { was = localStorage.getItem(key) === '1'; localStorage.setItem(key, was ? '0' : '1'); } catch (x) { was = false; }
        var on = !was;
        t.setAttribute('aria-checked', on ? 'true' : 'false');
        t.innerHTML = on ? '✓' : '';
        var li = t.closest('.stage-step'); if (li) li.classList.toggle('done', on);
      });
      U.on(mount, 'click', '[data-ptr-sym]', function (e, t) {
        var k = t.getAttribute('data-ptr-sym');
        _ptrSym = (_ptrSym === k) ? null : k;
        OBOL.router.render();
      });
      U.on(mount, 'click', '[data-ptr-go]', function (e, t) {
        var key = t.getAttribute('data-ptr-go');
        var body = t.closest('.ptr-body'); if (!body) return;
        var ta = body.querySelector('[data-ptr-paste]'), out = body.querySelector('.ptr-verdict');
        var res = OBOL.pivotDoctor.diagnose(key, ta ? ta.value : '', (OBOL.store.active() || {}).params || {});
        if (out) out.innerHTML = verdictHtml(res);
        if (res && res.matched && !res.healthy) { setTrouble(true); setConnWarn(mount, true); }
        else if (res && res.matched && res.healthy) { setTrouble(false); setConnWarn(mount, false); }
      });
      U.on(mount, 'click', '[data-ptr-clear]', function () {
        setTrouble(false);
        OBOL.router.render();
      });
    }

    // Library: open / delete
    U.on(mount, 'click', '.lib-open', function (e, t) {
      var drawer = t.closest('details.eng-lib-drawer');
      if (drawer) drawer.open = false;
      OBOL.store.setActive(t.getAttribute('data-eng')).then(function () { OBOL.app.renderSidebar(); OBOL.router.render(); });
    });
    U.on(mount, 'click', '.lib-del', function (e, t) {
      if (!confirm('Delete this engagement? This cannot be undone.')) return;
      OBOL.store.deleteEngagement(t.getAttribute('data-eng')).then(function () { OBOL.app.renderSidebar(); OBOL.router.render(); });
    });

    // Danger zone: delete all engagements / full reset
    U.on(mount, 'click', '#eng-clear', function () {
      if (!confirm('Delete ALL engagements and their evidence?\n\nThis cannot be undone. Your appearance settings are kept.')) return;
      OBOL.store.clearEngagements().then(function () { try { U.toast('All engagements deleted, reloading'); } catch (e) {} setTimeout(function () { location.reload(); }, 150); });
    });
    U.on(mount, 'click', '#eng-reset', function () {
      if (!confirm('FULL RESET\n\nErase everything OBOL saved in this browser (every engagement, screenshot, and setting) and start completely fresh.\n\nThis cannot be undone. Continue?')) return;
      OBOL.store.resetAll().then(function () { try { U.toast('All data cleared, reloading fresh'); } catch (e) {} setTimeout(function () { location.reload(); }, 200); });
    });

    // Virtual workspace handlers
    function updateOverrides(fn, label) {
      OBOL.store.update(function (e) {
        e.workspace = e.workspace || {};
        var ov = e.workspace.overrides = e.workspace.overrides || {};
        ov.added = ov.added || []; ov.removed = ov.removed || {}; ov.onDisk = ov.onDisk || {};
        fn(ov, e);
      }, label || 'workspace');
      OBOL.router.render();
    }
    U.on(mount, 'click', '.ws-rm', function (e, t) {
      e.preventDefault(); e.stopPropagation();
      var rel = t.getAttribute('data-rel'); if (!rel) return;
      updateOverrides(function (ov) {
        ov.removed[rel] = true;
        ov.added = (ov.added || []).filter(function (a) { return OBOL.vfs.relOf((typeof a === 'string' ? a : a.path), (OBOL.store.active().workspace || {}).root) !== rel; });
      }, 'ws-remove');
    });
    U.on(mount, 'click', '.ws-add', function (e, t) {
      e.preventDefault();
      var folder = t.getAttribute('data-folder') || 'other';
      var raw = (window.prompt('Add a file to ' + folder + '/, name it exactly as it is on your disk:', '') || '').trim();
      if (!raw) return;
      var lay = (OBOL.workspace && OBOL.workspace.LAYOUT) || {};
      var name = raw.replace(/^\/+/, '');
      var rel = /[\/]/.test(name) ? name : ((lay[folder] || (folder !== 'other' ? folder : '')) ? ((lay[folder] || folder) + '/' + name) : name);
      updateOverrides(function (ov) {
        delete ov.removed[rel];
        if (!(ov.added || []).some(function (a) { return (typeof a === 'string' ? a : a.path) === rel; })) {
          ov.added.push({ path: rel, source: 'manual', at: Date.now() });
        }
      }, 'ws-add');
      U.toast('Added ' + rel + '. Paste its contents on Evidence to mint facts');
    });
    U.on(mount, 'click', '.ws-restore', function (e) {
      e.preventDefault();
      updateOverrides(function (ov) { ov.removed = {}; }, 'ws-restore');
    });
    U.on(mount, 'click', '.ws-copyval, .ws-copy-path', function (e, t) {
      if (e && e.preventDefault) e.preventDefault();
      if (e && e.stopPropagation) e.stopPropagation();
      U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Copied' : 'Copy failed', ok ? '' : 'err'); });
    });
    U.on(mount, 'click', '.ws-snap-copy', function (e, t) {
      var el = document.getElementById(t.getAttribute('data-copy'));
      if (el) U.copy(el.textContent).then(function (ok) { U.toast(ok ? 'Command copied' : 'Copy failed', ok ? '' : 'err'); });
    });

    // Hover preview card for Workspace files
    (function wireWorkspacePreview() {
      if (!OBOL.vfs || matchMedia('(hover: none)').matches) return;
      var byRel = {};
      try { var vt = OBOL.vfs.build(OBOL.store.active()); (vt.files || []).forEach(function (f) { byRel[OBOL.vfs.relOf(f.path, vt.root)] = f; }); } catch (e) { return; }
      var card = document.getElementById('ws-preview'), fresh = false;
      if (!card) { card = document.createElement('div'); card.id = 'ws-preview'; card.className = 'ws-preview'; card.hidden = true; document.body.appendChild(card); fresh = true; }
      function previewHtml(f) {
        var tag = f.status === 'captured' ? 'Captured' : f.origin === 'suggested' ? 'Suggested'
          : f.unknown ? 'On Disk' : f.manual ? 'Added' : f.confirmed ? 'On Disk' : 'Expected';
        var head = '<div class="ws-pv-head"><span class="ws-pv-name">' + esc(f.name) + '</span><span class="ws-pv-tag ws-pv-' + esc(tag.replace(/\s+/g, '').toLowerCase()) + '">' + esc(tag) + '</span></div>'
          + '<div class="ws-pv-desc">' + esc(OBOL.vfs.describe(f)) + '</div>';
        var cta = '<a class="ws-pv-cta" href="' + captureHref(f) + '">Paste Its Contents On Evidence &rarr;</a>';
        var body;
        if (f.image) body = '<img class="ws-pv-img" src="' + esc(f.image) + '" alt="">';
        else if (f.status === 'captured' && f.output) {
          var lines = String(f.output).replace(/\s+$/, '').split(/\n/);
          var shown = lines.slice(0, 16).join('\n') + (lines.length > 16 ? '\n... ' + (lines.length - 16) + ' more line' + (lines.length - 16 === 1 ? '' : 's') : '');
          body = '<pre class="ws-pv-term">' + esc(shown) + '</pre>';
        } else if (f.status === 'captured') {
          body = '<div class="ws-pv-note">Captured evidence file' + (f.size ? ' (' + esc(fsize(f.size)) + ')' : '') + (f.tool ? ' via ' + esc(f.tool) : '') + '. Saved to your Kali working directory.</div>';
        } else if (f.origin === 'suggested') body = '<div class="ws-pv-note">Pencilled in by the Cockpit, run the move, then paste its output to capture it.</div>' + (f.command ? '<code class="ws-pv-cmd">' + esc(f.command) + '</code>' : '') + cta;
        else if (f.unknown) body = '<div class="ws-pv-note">Found on your disk by a sync. OBOL knows it exists but not what\'s inside.</div>' + cta;
        else if (f.manual) body = '<div class="ws-pv-note">Added by hand. Syncing only confirms it exists, to mint facts, paste what\'s inside.</div>' + cta;
        else body = '<div class="ws-pv-note">OBOL expects this file but hasn\'t received its output yet.</div>' + (f.command ? '<code class="ws-pv-cmd">' + esc(f.command) + '</code>' : '') + cta;
        return head + body;
      }
      function place(row) {
        card.style.visibility = 'hidden'; card.hidden = false;
        var cw = card.offsetWidth, ch = card.offsetHeight;
        var r = row.getBoundingClientRect();
        var panel = row.closest('.ws-panel');
        var left, top;
        if (panel) {
          var pr = panel.getBoundingClientRect();
          left = pr.left - cw - 12;
          if (left < 8) left = pr.right - cw - 16;
          if (left < 8) left = 8;
          top = Math.min(Math.max(8, r.top - 2), window.innerHeight - ch - 8);
        } else {
          left = r.left - cw - 12;
          if (left < 8) left = Math.min(r.right + 12, window.innerWidth - cw - 8);
          top = Math.min(Math.max(8, r.top), window.innerHeight - ch - 8);
        }
        card.style.left = Math.max(8, left) + 'px'; card.style.top = top + 'px';
        card.style.visibility = '';
      }
      function show(row) {
        var rel = row.getAttribute('data-rel'); var f = byRel[rel];
        if (!f) return;
        clearTimeout(card._hideT);
        card.innerHTML = previewHtml(f);
        place(row);
      }
      U.on(mount, 'mouseover', '.ws-file > summary', function (e, t) { show(t.closest('.ws-file')); });
      U.on(mount, 'mouseout', '.ws-file > summary', function () { card._hideT = setTimeout(function () { card.hidden = true; }, 90); });
      if (fresh) {
        card.addEventListener('mouseenter', function () { clearTimeout(card._hideT); });
        card.addEventListener('mouseleave', function () { card.hidden = true; });
      }
    })();

    // Paste-back workspace snapshot sync
    U.on(mount, 'click', '.ws-sync-run', function () {
      var ta = document.getElementById('ws-sync-paste');
      var text = ta ? ta.value : '';
      var entries = OBOL.vfs.parseSnapshot(text);
      if (!entries.length) {
        if (OBOL.ingest && OBOL.ingest.ensureParsers && text.trim()) {
          OBOL.ingest.ensureParsers().then(function (okp) {
            var sRes = (okp && OBOL.ingest.importSession) ? OBOL.ingest.importSession(text, { target: 'auto' }) : null;
            if (sRes && sRes.ok && (sRes.added > 0 || (sRes.arsenal && sRes.arsenal.ok) || (sRes.targetsImported && sRes.targetsImported.ok))) {
              if (sRes.arsenal && sRes.arsenal.ok && !sRes.added) U.toast('Loadout stocked ' + sRes.arsenal.present + ' tools, ' + sRes.arsenal.staged + ' staged');
              else if (sRes.targetsImported && sRes.targetsImported.ok) U.toast((sRes.targetsImported.added || 0) + ' target(s) imported');
              else U.toast('Minted ' + sRes.added + ' fact' + (sRes.added === 1 ? '' : 's') + ' from paste');
              OBOL.router.render();
              return;
            }
            U.toast('No file list found in that paste', 'err');
          });
          return;
        }
        U.toast('No file list found in that paste', 'err');
        return;
      }
      var r = OBOL.vfs.reconcile(OBOL.store.active(), entries);
      OBOL.store.update(function (e) { e.workspace = e.workspace || {}; e.workspace.overrides = r.overrides; }, 'ws-sync');
      OBOL.router.render();
      U.toast(r.confirmed + ' confirmed · ' + r.adopted + ' new file' + (r.adopted === 1 ? '' : 's') + ' adopted');
    });

    // Create & Launch Engagement
    var launch = document.getElementById('eng-launch');
    if (launch) launch.addEventListener('click', function () {
      var name = (document.getElementById('eng-name').value || '').trim();
      var platform = (document.querySelector('input[name="pf-platform"]:checked') || {}).value || 'custom';
      var mt = (document.getElementById('eng-mt').value || '');
      var wf = ((document.getElementById('eng-wf') || {}).value || '');
      var osid = (document.getElementById('eng-osid') || {}).value || '';
      var cand = (document.getElementById('eng-cand') || {}).value || '';
      var client = (document.getElementById('eng-client') || {}).value || '';
      var scopeText = (document.getElementById('eng-scope').value || '');
      var lhostEl = document.getElementById('eng-lhost');
      var lhostRaw = ((lhostEl || {}).value || '').trim().replace(/\/\d{1,2}$/, '').trim();
      if (lhostEl && lhostRaw) lhostEl.value = lhostRaw;
      var lhost = /^(\d{1,3}\.){3}\d{1,3}$/.test(lhostRaw) ? lhostRaw : '';
      var iface = ((document.getElementById('eng-iface') || {}).value || '').trim();
      if (lhostRaw && !lhost) { U.toast('That VM IP doesn\'t look like an IPv4 address, ignoring it', 'err'); }
      if (!name) { name = (OBOL.profile.PRESETS[platform] || {}).name || 'Engagement'; }

      var parsedScope = parseBulkInput(scopeText, lhost);
      var scope = parsedScope.scope;

      var active = OBOL.store.active();
      var reuse = active && !isConfigured(active, Object.keys(OBOL.store.factSet().kinds()).length);

      var typed = OBOL.workspace.sanitizeRoot((document.getElementById('eng-workdir') || {}).value || '');
      if (!typed && scopeText) {
        var mScopeWd = /\[([~\/][^\[\]\r\n]+)\]/.exec(scopeText) || /^\s*(?:cd\s+)?((?:~\/|\/home\/|\/root\/)[A-Za-z0-9._\/-]+)\s*$/m.exec(scopeText);
        if (mScopeWd) typed = OBOL.workspace.sanitizeRoot(mScopeWd[1]);
      }
      var root = typed || OBOL.workspace.join(OBOL.workspace.DEFAULT_BASE, OBOL.workspace.slugify(name) || 'engagement');

      var seed = function () {
        var hosts = parsedScope.hosts;
        var facts = [];
        var SUP = (OBOL.facts && OBOL.facts.ProofState && OBOL.facts.ProofState.SUPPORTED) || 'supported';
        OBOL.store.update(function (e) {
          if (reuse) {
            e.name = name;
            e.profile = Object.assign(e.profile || {}, { platform: platform, machine_type: mt, workflow: wf, osid: osid.trim(), candidate: cand.trim(), client: client.trim(), scope: scope });
            e.params = e.params || {}; e.params.platform = platform;
          }
          if (!wf && OBOL.profile && OBOL.profile.defaultLens) {
            e.ui = e.ui || {};
            e.ui.pathLens = OBOL.profile.defaultLens(e.profile);
          }
          if (OBOL.profile && OBOL.profile.reportProfileFor) {
            e.ui = e.ui || {};
            e.ui.reportProfile = OBOL.profile.reportProfileFor(e.profile);
          }
          var prevTargetsByIp = {};
          if (reuse && Array.isArray(e.targets)) {
            e.targets.forEach(function (t) { if (t && t.ip) prevTargetsByIp[t.ip] = t; });
          }
          e.workspace = { root: root };
          e.targets = [];
          hosts.forEach(function (h, i) {
            var prev = prevTargetsByIp[h.ip] || {};
            e.targets.push({ id: prev.id || ('t' + i + '-' + Date.now().toString(36)), ip: h.ip, hostname: h.hostname || prev.hostname || '', os: prev.os || '' });
            var sc = 'host:' + h.ip;
            facts.push(OBOL.facts.makeFact({ kind: 'target.configured', scope: sc, source: 'engagement' }));
            if (h.hostname) {
              facts.push(OBOL.facts.makeFact({ kind: 'host.hostname', scope: sc, value: { name: h.hostname.split('.')[0], fqdn: h.hostname.indexOf('.') > 0 ? h.hostname : '' }, state: SUP, source: 'engagement' }));
            }
            if (h.domain) {
              facts.push(OBOL.facts.makeFact({ kind: 'host.domain', scope: sc, value: { domain: h.domain }, state: SUP, source: 'engagement' }));
            }
          });
          if (!e.params) e.params = {};
          e.activeTarget = hosts[0] ? hosts[0].ip : null;
          if (hosts[0]) e.params.target = hosts[0].ip;
          else delete e.params.target;
          if (scope.length) e.params.scope_defined = true;
          if (lhost) { e.params.lhost = lhost; if (iface) e.params.lhost_iface = iface; }
        }, 'launch');
        if (facts.length) OBOL.store.addFacts(facts, 'launch');
        _showNewSetup = false;
        var finishLaunch = function () {
          if (OBOL.app && OBOL.app.renderSidebar) OBOL.app.renderSidebar();
          if (OBOL.ctxbar && OBOL.ctxbar.render) OBOL.ctxbar.render();
          U.toast(hosts.length ? ('Launched ' + hosts.length + ' target(s) scoped') : 'Engagement created, add targets to begin');
          if (OBOL.router.current && OBOL.router.current().name === 'home') {
            OBOL.router.render();
            try { window.scrollTo({ top: 0, behavior: 'smooth' }); } catch (e) {}
          } else {
            OBOL.router.go('home');
          }
        };
        if (parsedScope.hasScanOutput && OBOL.ingest && OBOL.ingest.ensureParsers) {
          ingestScanBlocks(scopeText, hosts[0] && hosts[0].ip, finishLaunch);
        } else {
          finishLaunch();
        }
      };

      if (reuse) { seed(); }
      else { OBOL.store.createEngagement(name, { platform: platform, machine_type: mt, workflow: wf, osid: osid.trim(), candidate: cand.trim(), client: client.trim(), scope: scope }).then(seed); }
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.home = {
    render: render,
    mounted: mounted,
    openNewSetup: function () { _showNewSetup = true; _showEditRun = false; },
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
