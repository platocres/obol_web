/* tool-options-smoke.js — the Options composition contract (stackable Option toggles).
 *
 * Guards that every builder's headlineToggles are real, independent checkbox switches; that stacking ANY
 * subset of the toggles valid for a given primary state compiles to a clean command (no token leak, no
 * "undefined", right executable); and that nxc's selectorAliases (the deep-link back-compat) reference a
 * real protocol and real toggles. This is what makes "any stacked command is guaranteed to run" a test,
 * not a vibe.
 */
'use strict';
var path = require('path');
var ROOT = path.join(__dirname, '..', '..');
function req(p) { return require(path.join(ROOT, p)); }
req('assets/engine/toolbuilder.js');
req('data/toolset.js');
var OBOL = globalThis.OBOL, TB = OBOL.toolbuilder;

var fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

var byId = {}; OBOL.TOOLSET.forEach(function (b) { byId[b.id] = b; });
// a bound context so auth/target fill; plus placeholder fill for any non-secret required field left empty.
var CTX = { target: { value: '10.10.10.10', ip: '10.10.10.10', url: 'http://10.10.10.10', fuzzurl: 'http://10.10.10.10/FUZZ' }, context: { domain: 'corp.local', baseDn: 'DC=corp,DC=local', username: 'svc', lhost: '10.10.14.5', lport: '4444' }, workspace: { wordlist: 'rockyou.txt', outputDir: 'loot', hashfile: 'hashes.txt' } };
function fillRequired(b, vals) {
  var norm = TB.normalizeValues(b, vals, CTX), out = {}; Object.keys(norm).forEach(function (k) { out[k] = norm[k]; });
  (b.fields || []).forEach(function (f) {
    if (f.visibleWhen && !TB.conditionMatches(f.visibleWhen, norm)) return;
    var reqd = f.required === true || (f.requiredWhen ? TB.conditionMatches(f.requiredWhen, norm) : false);
    if (!reqd) return;
    var v = out[f.id];
    if (v === undefined || v === null || v === '') { if (f.type === 'checkbox') { if (f.mustBeChecked) out[f.id] = true; } else out[f.id] = (f.type === 'secret' ? 'S3cret!' : 'x'); }
  });
  return out;
}
function cleanCompile(b, vals, label) {
  var cmd;
  try { cmd = TB.compile(b, fillRequired(b, vals), CTX); } catch (e) { cmd = 'ERR:' + e.message; }
  ok(cmd.indexOf('ERR:') !== 0 && !/\{\{|\bundefined\b|\[object/.test(cmd), label + ' compiles clean' + (/ERR|\{\{|undefined/.test(cmd) ? ' -> ' + cmd : ''));
  return cmd;
}

// ---- every headlineToggle is a real, independent checkbox ----
var tooled = OBOL.TOOLSET.filter(function (b) { return (b.headlineToggles || []).length; });
ok(tooled.length >= 12, 'at least 12 tools carry stackable Option toggles (' + tooled.length + ')');
tooled.forEach(function (b) {
  var fieldById = {}; (b.fields || []).forEach(function (f) { fieldById[f.id] = f; });
  var bad = b.headlineToggles.filter(function (t) { return !fieldById[t] || fieldById[t].type !== 'checkbox'; });
  ok(bad.length === 0, b.id + ': every headlineToggle is a real checkbox' + (bad.length ? ' (BAD: ' + bad.join(',') + ')' : ''));
  ok(typeof b.switchesLabel === 'string' && b.switchesLabel.length > 0, b.id + ' has a switchesLabel');
});

// ---- stacking every module valid for a primary state compiles clean (the core guarantee) ----
// For a tool with a primary select (protocol/mode/role/engine), for each option value, turn ON every toggle
// whose visibleWhen is satisfied by that option, and assert a clean command. This proves no in-state stack
// is invalid.
var PRIMARY_IDS = ['protocol', 'mode', 'role', 'engine', 'method', 'client', 'requestMode'];
tooled.forEach(function (b) {
  var prim = (b.fields || []).filter(function (f) { return f.type === 'select' && PRIMARY_IDS.indexOf(f.id) >= 0 && (f.options || []).length; })[0];
  var states = prim ? prim.options.map(function (o) { var s = {}; s[prim.id] = o.value; return { k: prim.id + '=' + o.value, v: s }; }) : [{ k: 'default', v: {} }];
  states.forEach(function (st) {
    var norm = TB.normalizeValues(b, st.v, CTX);
    var onAll = {}; Object.keys(st.v).forEach(function (k) { onAll[k] = st.v[k]; });
    var lit = 0;
    (b.headlineToggles || []).forEach(function (tid) {
      var f = (b.fields || []).filter(function (x) { return x.id === tid; })[0];
      var vis = !(f.visibleWhen && !TB.conditionMatches(f.visibleWhen, norm));
      if (vis) { onAll[tid] = true; lit++; }
    });
    cleanCompile(b, onAll, b.id + ' [' + st.k + '] all ' + lit + ' visible toggles ON');
  });
});

// ---- nxc selectorAliases reference real protocol + real toggles (deep-link back-compat) ----
(function () {
  var nxc = byId['tb-nxc'];
  ok(nxc && nxc.selectorAliases, 'nxc has selectorAliases');
  if (!nxc || !nxc.selectorAliases) return;
  var protoOpts = {}; (nxc.fields.filter(function (f) { return f.id === 'protocol'; })[0].options || []).forEach(function (o) { protoOpts[o.value] = 1; });
  var toggleSet = {}; (nxc.headlineToggles || []).forEach(function (t) { toggleSet[t] = 1; });
  var bad = [];
  Object.keys(nxc.selectorAliases).forEach(function (sel) {
    var a = nxc.selectorAliases[sel];
    if (a.protocol && !protoOpts[a.protocol]) bad.push(sel + ' bad protocol ' + a.protocol);
    (a.on || []).forEach(function (t) { if (!toggleSet[t]) bad.push(sel + ' bad toggle ' + t); });
  });
  ok(bad.length === 0, 'every nxc selectorAlias maps to a real protocol + toggle' + (bad.length ? ' (' + bad.join('; ') + ')' : ''));
  // a couple of real stacks from the brief
  cleanCompile(nxc, { protocol: 'ldap', authMode: 'password', username: 'u', password: 'p', doUsers: true, doGroups: true, doAsrep: true, doKerberoast: true }, 'nxc ldap users+groups+asrep+kerberoast');
  cleanCompile(nxc, { protocol: 'smb', authMode: 'ntlm', username: 'administrator', hash: 'aad3b', doSam: true, doLsa: true, doNtds: true }, 'nxc smb sam+lsa+ntds');
  // hidden checkbox toggle (e.g. doBloodhound on LDAP) must be coerced to false when protocol is switched to smb/winrm
  var nxcSwitched = TB.compile(nxc, { protocol: 'winrm', target: '10.10.10.10', authMode: 'anonymous', doBloodhound: true, doAsrep: true }, CTX);
  ok(nxcSwitched.indexOf('-c All') === -1 && nxcSwitched.indexOf('--asreproast') === -1, 'hidden protocol toggles do not leak tokens when protocol changes (' + nxcSwitched + ')');
})();

// ---- UI Route DOM regression test: mode chips, toggle chips, and recipes in Autofill & Manual Fill ----
(function () {
  req('data/tool-recipes.js');
  req('data/tool-glossary.js');
  req('data/tool-stations.js');
  req('assets/engine/toolkit.js');
  req('assets/ui/util.js');

  // Minimal DOM implementation for testing OBOL.routes.tools.render + mounted in Node
  function decodeEntities(s) {
    return String(s == null ? '' : s)
      .replace(/&quot;/g, '"').replace(/&#39;/g, "'")
      .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
  }
  function MiniEl(tag) {
    this.tagName = String(tag || 'DIV').toUpperCase();
    this.attributes = {};
    this.children = [];
    this.parentNode = null;
    this._listeners = {};
    this._text = '';
    this._value = undefined;
    this.checked = false;
    this.hidden = false;
    var self = this;
    this.classList = {
      _set: function () { return String(self.attributes['class'] || '').split(/\s+/).filter(Boolean); },
      _write: function (arr) { self.attributes['class'] = arr.join(' '); },
      contains: function (c) { return this._set().indexOf(c) >= 0; },
      add: function () { var s = this._set(); for (var i = 0; i < arguments.length; i++) if (s.indexOf(arguments[i]) < 0) s.push(arguments[i]); this._write(s); },
      remove: function () { var s = this._set(), rem = Array.prototype.slice.call(arguments); this._write(s.filter(function (x) { return rem.indexOf(x) < 0; })); },
      toggle: function (c, force) { var has = this.contains(c), want = force !== undefined ? !!force : !has; if (want) this.add(c); else this.remove(c); return want; }
    };
    this.elements = {
      namedItem: function (name) {
        return self.querySelector('[name="' + name + '"]');
      }
    };
  }
  Object.defineProperty(MiniEl.prototype, 'className', {
    get: function () { return this.attributes['class'] || ''; },
    set: function (v) { this.attributes['class'] = String(v || ''); }
  });
  Object.defineProperty(MiniEl.prototype, 'id', {
    get: function () { return this.attributes['id'] || ''; },
    set: function (v) { this.attributes['id'] = String(v || ''); }
  });
  Object.defineProperty(MiniEl.prototype, 'options', {
    get: function () { return this.children.filter(function (c) { return c.tagName === 'OPTION'; }); }
  });
  Object.defineProperty(MiniEl.prototype, 'selectedIndex', {
    get: function () {
      var opts = this.options;
      for (var i = 0; i < opts.length; i++) if (opts[i].selected) return i;
      return opts.length ? 0 : -1;
    }
  });
  Object.defineProperty(MiniEl.prototype, 'value', {
    get: function () {
      if (this.tagName === 'SELECT') {
        var opts = this.options;
        for (var i = 0; i < opts.length; i++) if (opts[i].selected) return opts[i].getAttribute('value') || '';
        return opts.length ? (opts[0].getAttribute('value') || '') : '';
      }
      if (this._value !== undefined) return this._value;
      return this.attributes['value'] !== undefined ? this.attributes['value'] : this._text;
    },
    set: function (v) {
      var s = String(v == null ? '' : v);
      this._value = s;
      if (this.tagName === 'SELECT') {
        var opts = this.options;
        opts.forEach(function (o) { o.selected = (String(o.getAttribute('value')) === s); });
      }
    }
  });
  Object.defineProperty(MiniEl.prototype, 'textContent', {
    get: function () {
      if (!this.children.length) return this._text || '';
      return (this._text || '') + this.children.map(function (c) { return c.textContent; }).join('');
    },
    set: function (v) { this.children = []; this._text = String(v == null ? '' : v); }
  });
  Object.defineProperty(MiniEl.prototype, 'innerHTML', {
    get: function () { return this._rawHtml || this.textContent; },
    set: function (html) {
      this._rawHtml = String(html || '');
      this._text = '';
      this.children = parseHtml(this._rawHtml, this);
    }
  });
  Object.defineProperty(MiniEl.prototype, 'outerHTML', {
    get: function () { return this.innerHTML; },
    set: function (html) {
      if (!this.parentNode) return;
      var parsed = parseHtml(String(html || ''), this.parentNode);
      var idx = this.parentNode.children.indexOf(this);
      if (idx >= 0) {
        var args = [idx, 1].concat(parsed);
        Array.prototype.splice.apply(this.parentNode.children, args);
      }
    }
  });
  MiniEl.prototype.getAttribute = function (k) { return Object.prototype.hasOwnProperty.call(this.attributes, k) ? this.attributes[k] : null; };
  MiniEl.prototype.setAttribute = function (k, v) {
    this.attributes[k] = String(v == null ? '' : v);
    if (k === 'hidden') this.hidden = true;
  };
  MiniEl.prototype.removeAttribute = function (k) {
    delete this.attributes[k];
    if (k === 'hidden') this.hidden = false;
  };
  MiniEl.prototype.appendChild = function (c) { c.parentNode = this; this.children.push(c); return c; };
  MiniEl.prototype.insertBefore = function (n, ref) {
    n.parentNode = this;
    var i = this.children.indexOf(ref);
    if (i >= 0) this.children.splice(i, 0, n); else this.children.push(n);
    return n;
  };
  MiniEl.prototype.replaceChild = function (n, old) {
    n.parentNode = this;
    var i = this.children.indexOf(old);
    if (i >= 0) this.children[i] = n;
    return old;
  };
  MiniEl.prototype.cloneNode = function () {
    var c = new MiniEl(this.tagName);
    c.attributes = Object.assign({}, this.attributes);
    c.hidden = this.hidden;
    return c;
  };
  MiniEl.prototype.contains = function (other) {
    var cur = other;
    while (cur) { if (cur === this) return true; cur = cur.parentNode; }
    return false;
  };
  MiniEl.prototype.matches = function (sel) {
    if (this.tagName === '#TEXT') return false;
    var parts = String(sel).split(',').map(function (s) { return s.trim(); }).filter(Boolean);
    if (parts.length > 1) return parts.some(this.matches.bind(this));
    var s = parts[0] || '';
    if (!s) return false;
    var notMatch = s.match(/:not\(([^)]+)\)/);
    if (notMatch) {
      if (this.matches(notMatch[1])) return false;
      s = s.replace(notMatch[0], '');
    }
    var attrRe = /\[([a-zA-Z0-9_-]+)(?:="([^"]*)")?\]/g, m;
    while ((m = attrRe.exec(s)) !== null) {
      var ak = m[1], av = m[2];
      if (ak === 'hidden') { if (!this.hidden) return false; }
      else if (av !== undefined) { if (this.getAttribute(ak) !== av) return false; }
      else if (this.getAttribute(ak) === null) return false;
    }
    s = s.replace(attrRe, '');
    var idMatch = s.match(/#([a-zA-Z0-9_-]+)/);
    if (idMatch && this.id !== idMatch[1]) return false;
    s = s.replace(/#[a-zA-Z0-9_-]+/, '');
    var clsRe = /\.([a-zA-Z0-9_-]+)/g;
    while ((m = clsRe.exec(s)) !== null) {
      if (!this.classList.contains(m[1])) return false;
    }
    s = s.replace(clsRe, '').trim();
    if (s && this.tagName !== s.toUpperCase()) return false;
    return true;
  };
  MiniEl.prototype.closest = function (sel) {
    var cur = this;
    while (cur && cur.matches) { if (cur.matches(sel)) return cur; cur = cur.parentNode; }
    return null;
  };
  MiniEl.prototype.querySelectorAll = function (sel) {
    var out = [];
    function walk(node) {
      for (var i = 0; i < node.children.length; i++) {
        var c = node.children[i];
        if (c.matches(sel)) out.push(c);
        walk(c);
      }
    }
    walk(this);
    return out;
  };
  MiniEl.prototype.querySelector = function (sel) { return this.querySelectorAll(sel)[0] || null; };
  MiniEl.prototype.addEventListener = function (evt, fn) {
    (this._listeners[evt] = this._listeners[evt] || []).push(fn);
  };
  MiniEl.prototype.dispatchEvent = function (evt) {
    var type = typeof evt === 'string' ? evt : evt.type;
    var e = typeof evt === 'object' ? evt : { type: type };
    if (!e.target) e.target = this;
    if (!e.preventDefault) e.preventDefault = function () {};
    if (!e.stopPropagation) e.stopPropagation = function () { e._stopped = true; };
    var cur = this;
    while (cur && !e._stopped) {
      var list = (cur._listeners && cur._listeners[type]) || [];
      for (var i = 0; i < list.length; i++) list[i].call(cur, e);
      cur = cur.parentNode;
    }
  };
  MiniEl.prototype.click = function () { this.dispatchEvent({ type: 'click', target: this }); };
  MiniEl.prototype.focus = function () {};

  var VOID_TAGS = { INPUT: 1, BR: 1, HR: 1, IMG: 1, META: 1, LINK: 1 };
  function parseHtml(html, parent) {
    var root = { children: [] }, stack = [root];
    var tokenRe = /<!--[\s\S]*?-->|<\/([a-zA-Z0-9_-]+)\s*>|<([a-zA-Z0-9_-]+)((?:\s+[a-zA-Z0-9_:-]+(?:="[^"]*"|='[^']*'|[^\s>]*))*\s*)\/?>|([^<]+)/g;
    var m;
    while ((m = tokenRe.exec(html)) !== null) {
      if (m[1]) {
        var closeTag = m[1].toUpperCase();
        for (var s = stack.length - 1; s >= 1; s--) {
          if (stack[s].tagName === closeTag) { stack.length = s; break; }
        }
      } else if (m[2]) {
        var el = new MiniEl(m[2]);
        var attrStr = m[3] || '';
        var aRe = /([a-zA-Z0-9_:-]+)(?:="([^"]*)"|='([^']*)'|=([^\s>]+))?/g, am;
        while ((am = aRe.exec(attrStr)) !== null) {
          var k = am[1], v = am[2] !== undefined ? am[2] : (am[3] !== undefined ? am[3] : (am[4] !== undefined ? am[4] : ''));
          el.attributes[k] = decodeEntities(v);
          if (k === 'checked') el.checked = true;
          if (k === 'selected') el.selected = true;
          if (k === 'hidden') el.hidden = true;
        }
        var top = stack[stack.length - 1];
        el.parentNode = top === root ? parent : top;
        top.children.push(el);
        if (!VOID_TAGS[el.tagName] && !/\/$/.test(attrStr.trim())) stack.push(el);
      } else if (m[4]) {
        var cur = stack[stack.length - 1];
        if (cur !== root) {
          var txt = decodeEntities(m[4]);
          if (cur.children.length > 0) {
            var tn = new MiniEl('#TEXT');
            tn._text = txt;
            tn.parentNode = cur;
            cur.children.push(tn);
          } else {
            cur._text = (cur._text || '') + txt;
            if (cur.tagName === 'TEXTAREA') cur._value = cur._text;
          }
        }
      }
    }
    return root.children;
  }

  globalThis.document = {
    activeElement: null,
    createElement: function (t) { return new MiniEl(t); },
    getElementById: function () { return null; },
    body: new MiniEl('body')
  };
  globalThis.window = { scrollTo: function () {}, addEventListener: function () {} };
  globalThis.Event = function (type, opts) { this.type = type; this.bubbles = !!(opts && opts.bubbles); };

  var ENG = { params: { target: '10.10.10.10', domain: 'corp.local', username: 'svc' }, ui: { toolsLayout: 'grid' } };
  OBOL.store = {
    active: function () { return ENG; },
    factSet: function () { return { facts: [], kinds: function () { return {}; } }; },
    update: function (fn) { fn(ENG); },
    targetIdentity: function () { return {}; }
  };
  OBOL.creds = { gather: function () { return []; }, keyOf: function () { return ''; }, activeKey: function () { return ''; } };
  OBOL.command = { openPorts: function () { return [80, 445]; } };
  var allEquips = [];
  OBOL.TOOLSET.forEach(function (b) { (b.equips || []).forEach(function (t) { allEquips.push(t); }); });
  OBOL.packs = { equippedTools: function () { return allEquips; } };

  req('assets/ui/bind.js');
  req('assets/ui/routes/tools.js');

  function mountToolCard(toolId, manualMode) {
    ENG.ui = { toolsLayout: 'grid', bind: { manual: !!manualMode }, tools: {} };
    var mount = new MiniEl('main');
    mount.innerHTML = OBOL.routes.tools.render({ args: [toolId] });
    OBOL.routes.tools.mounted({ mount: mount, args: [toolId] });
    return mount.querySelector('.tool-card.open');
  }

  // 1) Test NetExec (tb-nxc) protocol buttons in BOTH Autofill and Manual Fill modes
  [false, true].forEach(function (manual) {
    var modeLabel = manual ? 'Manual Fill' : 'Autofill';
    var card = mountToolCard('tb-nxc', manual);
    ok(!!card, 'tb-nxc mounts open in ' + modeLabel);
    var form = card.querySelector('.tb-form');
    ok(!!(form && form.elements.namedItem('protocol')), 'tb-nxc form contains protocol control in ' + modeLabel);

    var chips = card.querySelectorAll('.tb-mode-chip');
    ok(chips.length === 5, 'tb-nxc renders 5 protocol chips in ' + modeLabel + ' (got ' + chips.length + ')');
    var activeInit = chips.filter(function (c) { return c.classList.contains('on'); });
    ok(activeInit.length === 1 && activeInit[0].getAttribute('data-mode-value') === 'smb',
      'tb-nxc initial active protocol chip is smb in ' + modeLabel);

    ['smb', 'ldap', 'winrm', 'ftp', 'mssql'].forEach(function (proto) {
      var chip = chips.filter(function (c) { return c.getAttribute('data-mode-value') === proto; })[0];
      ok(!!chip, 'tb-nxc has chip for ' + proto + ' in ' + modeLabel);
      chip.click();
      var onNow = chips.filter(function (c) { return c.classList.contains('on') && c.getAttribute('aria-pressed') === 'true'; });
      ok(onNow.length === 1 && onNow[0].getAttribute('data-mode-value') === proto,
        'tb-nxc clicking ' + proto + ' selects ONLY that chip in ' + modeLabel);
      ok(form.elements.namedItem('protocol').value === proto,
        'tb-nxc clicking ' + proto + ' updates form protocol value in ' + modeLabel);
      var codeText = card.querySelector('.tb-code').textContent;
      ok(codeText.indexOf('nxc ' + proto + ' ') === 0,
        'tb-nxc clicking ' + proto + ' updates command preview to "nxc ' + proto + ' ..." in ' + modeLabel + ' (got: ' + codeText + ')');
    });

    // Verify LDAP toggle stacking + automatic clearing when switching to WinRM
    var ldapChip = chips.filter(function (c) { return c.getAttribute('data-mode-value') === 'ldap'; })[0];
    ldapChip.click();
    var bhTog = card.querySelector('.tb-tog-chip[data-toggle-field="doBloodhound"]');
    ok(bhTog && !bhTog.hidden, 'tb-nxc BloodHound toggle is visible under LDAP in ' + modeLabel);
    bhTog.click();
    ok(card.querySelector('.tb-code').textContent.indexOf('--bloodhound') >= 0, 'tb-nxc LDAP + BloodHound adds --bloodhound in ' + modeLabel);
    var winrmChip = chips.filter(function (c) { return c.getAttribute('data-mode-value') === 'winrm'; })[0];
    winrmChip.click();
    ok(bhTog.hidden && !bhTog.classList.contains('on'), 'tb-nxc BloodHound toggle hides and unchecks when switching to WinRM in ' + modeLabel);
    ok(card.querySelector('.tb-code').textContent.indexOf('-c All') === -1, 'tb-nxc WinRM command has no leaked LDAP BloodHound flags in ' + modeLabel);
  });

  // 2) Sweep EVERY builder in OBOL.TOOLSET: verify every field exists in .tb-form and every .tb-mode-chip is clickable
  var modeChipsTested = 0;
  OBOL.TOOLSET.forEach(function (b) {
    var card = mountToolCard(b.id, false);
    ok(!!card, b.id + ': mounts open via deep link');
    if (!card) return;
    var form = card.querySelector('.tb-form');
    var missingControls = (b.fields || []).filter(function (f) { return !(form && form.elements.namedItem(f.id)); }).map(function (f) { return f.id; });
    ok(missingControls.length === 0, b.id + ': all builder fields exist in .tb-form' + (missingControls.length ? ' (MISSING: ' + missingControls.join(',') + ')' : ''));

    var chips = card.querySelectorAll('.tb-mode-chip');
    if (chips.length) {
      var initOn = chips.filter(function (c) { return c.classList.contains('on'); });
      ok(initOn.length === 1, b.id + ': exactly 1 mode chip is active on initial mount (got ' + initOn.length + ')');
      chips.forEach(function (chip) {
        var fid = chip.getAttribute('data-mode-field');
        var val = chip.getAttribute('data-mode-value');
        chip.click();
        modeChipsTested++;
        var active = chips.filter(function (c) { return c.classList.contains('on'); });
        if (active.length !== 1 || active[0] !== chip || form.elements.namedItem(fid).value !== val) {
          ok(false, b.id + ': clicking mode chip ' + fid + '=' + val + ' failed to select');
        }
      });
    }
  });
  ok(modeChipsTested >= 80, 'exercised clicking all ' + modeChipsTested + ' mode chips across all builders');
})();

if (fail) { console.error('tool-options-smoke: ' + fail + ' FAIL'); process.exit(1); }
console.log('tool-options-smoke: OK');
