/*!
 * obol engine — toolbuilder.js
 * The Tool Builder command COMPILER, ported and cleaned from the donor
 * data/tool-builder-current.js + data/tool-builder-schema.js. Pure and runtime-independent:
 * it validates a builder definition, resolves field values (defaults + dotted-key autofill),
 * and compiles the {executable, tokens[]} model into a single shell-safe command string.
 *
 * It NEVER executes anything — it only produces text. Builders that declare an execution hook
 * (execute/exec/spawn/runCommand/autoRun) are rejected by validate(). Attaches to `root` under
 * OBOL.toolbuilder using the same module pattern as the rest of the engine, so it runs in the
 * browser, a Web Worker, and Node (the smoke test loads it directly).
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  // ---------------------------------------------------------------- constants --
  var FIELD_TYPES = ['text', 'number', 'select', 'checkbox', 'secret', 'path', 'textarea'];
  var CREDENTIAL_KINDS = ['password', 'ntlm', 'netntlm', 'kerberos', 'certificate', 'ssh-key', 'cookie-token'];
  var EXECUTION_CONTEXTS = ['kali', 'linux', 'windows', 'remote-shell', 'any'];
  var TOKEN_KINDS = ['literal', 'field', 'toggle', 'choice', 'concat', 'repeat'];
  var FORBIDDEN = ['execute', 'exec', 'spawn', 'runCommand', 'autoRun'];

  function text(v) { return String(v == null ? '' : v); }
  function isArr(v) { return Array.isArray(v); }
  function arr(v) { return Array.isArray(v) ? v : []; }
  function unique(list) { var seen = {}, out = []; list.forEach(function (v) { if (!seen[v]) { seen[v] = 1; out.push(v); } }); return out; }

  // ---------------------------------------------------- POSIX single-quote quoting --
  // Same rule as OBOL.command.shellQuote: safe tokens pass through, everything else is
  // wrapped in single quotes with embedded quotes escaped. Secrets always flow through this.
  function shellQuote(s) {
    s = String(s == null ? '' : s);
    if (s === '') return "''";
    if (/^[A-Za-z0-9_@%+=:,.\/-]+$/.test(s)) return s;
    return "'" + s.replace(/'/g, "'\\''") + "'";
  }

  function truthy(v) { return v === true || v === 1 || v === '1' || v === 'true' || v === 'on' || v === 'yes'; }
  function same(a, b) { return String(a) === String(b); }

  // ------------------------------------------------------------- conditions (when) --
  function conditionMatches(condition, values) {
    if (condition == null) return true;
    if (isArr(condition)) return condition.every(function (c) { return conditionMatches(c, values); });
    var value = (values || {})[condition.field];
    if (Object.prototype.hasOwnProperty.call(condition, 'equals')) return same(value, condition.equals);
    if (Object.prototype.hasOwnProperty.call(condition, 'notEquals')) return !same(value, condition.notEquals);
    if (Object.prototype.hasOwnProperty.call(condition, 'in')) return (condition.in || []).some(function (e) { return same(value, e); });
    if (Object.prototype.hasOwnProperty.call(condition, 'notIn')) return !(condition.notIn || []).some(function (e) { return same(value, e); });
    if (Object.prototype.hasOwnProperty.call(condition, 'truthy')) return truthy(value) === condition.truthy;
    return false;
  }

  // ------------------------------------------------------------------- validation --
  function fail(errors, msg) { errors.push(msg); }

  function validateField(field, index) {
    var errors = [];
    if (!field || typeof field !== 'object') return ['field ' + index + ' must be an object'];
    if (!/^[a-z][a-z0-9_-]*$/i.test(text(field.id))) fail(errors, 'field ' + index + ' has invalid id');
    if (!text(field.label).trim()) fail(errors, 'field ' + text(field.id || index) + ' requires a label');
    if (FIELD_TYPES.indexOf(field.type) === -1) fail(errors, 'field ' + text(field.id || index) + ' has unsupported type ' + text(field.type));
    if (field.credentialKind && CREDENTIAL_KINDS.indexOf(field.credentialKind) === -1) fail(errors, 'field ' + text(field.id || index) + ' has unsupported credentialKind ' + text(field.credentialKind));
    if (field.type === 'select') {
      var opts = arr(field.options);
      if (!opts.length) fail(errors, 'select field ' + text(field.id || index) + ' requires options');
      opts.forEach(function (o) {
        if (!o || typeof o !== 'object' || !text(o.value).trim() && text(o.value) !== o.value || !text(o.label).trim()) {
          // value may be a bare number/boolean coerced to string; only require label + presence.
          if (!o || typeof o !== 'object' || !Object.prototype.hasOwnProperty.call(o, 'value') || !text(o.label).trim()) fail(errors, 'select field ' + text(field.id || index) + ' contains an invalid option');
        }
      });
    }
    if (field.presets !== undefined) {
      if (!isArr(field.presets)) fail(errors, 'field ' + text(field.id || index) + ' presets must be an array');
      else {
        if (field.type === 'checkbox') fail(errors, 'field ' + text(field.id || index) + ' checkbox fields cannot declare presets');
        field.presets.forEach(function (p, pi) {
          if (!p || typeof p !== 'object' || !Object.prototype.hasOwnProperty.call(p, 'value') || !text(p.label).trim()) fail(errors, 'field ' + text(field.id || index) + ' preset ' + pi + ' requires a label and value');
          else if (p.speed && ['fast', 'med', 'slow'].indexOf(p.speed) === -1) fail(errors, 'field ' + text(field.id || index) + ' preset ' + pi + ' has unsupported speed ' + text(p.speed));
        });
      }
    }
    if (field.snippets !== undefined) {
      if (field.type !== 'textarea') fail(errors, 'field ' + text(field.id || index) + ' snippets are only allowed on textarea fields');
      else if (!isArr(field.snippets)) fail(errors, 'field ' + text(field.id || index) + ' snippets must be an array');
      else field.snippets.forEach(function (s, si) { if (!s || typeof s !== 'object' || !text(s.label).trim() || !text(s.value).trim()) fail(errors, 'field ' + text(field.id || index) + ' snippet ' + si + ' requires a label and value'); });
    }
    return errors;
  }

  function validateCondition(condition, label, fieldIds) {
    var errors = [];
    if (condition == null) return errors;
    if (isArr(condition)) {
      if (!condition.length) fail(errors, label + ' contains an empty condition list');
      condition.forEach(function (entry, i) { validateCondition(entry, label + '[' + i + ']', fieldIds).forEach(function (e) { fail(errors, e); }); });
      return errors;
    }
    if (typeof condition !== 'object') return [label + ' must be an object or array'];
    if (!fieldIds[condition.field]) fail(errors, label + ' references unknown field ' + text(condition.field));
    var ops = ['equals', 'notEquals', 'in', 'notIn', 'truthy'].filter(function (k) { return Object.prototype.hasOwnProperty.call(condition, k); });
    if (ops.length !== 1) fail(errors, label + ' must declare exactly one condition operator');
    if (Object.prototype.hasOwnProperty.call(condition, 'in') && !isArr(condition.in)) fail(errors, label + ' in operator requires an array');
    if (Object.prototype.hasOwnProperty.call(condition, 'notIn') && !isArr(condition.notIn)) fail(errors, label + ' notIn operator requires an array');
    if (Object.prototype.hasOwnProperty.call(condition, 'truthy') && typeof condition.truthy !== 'boolean') fail(errors, label + ' truthy operator requires a boolean');
    return errors;
  }

  function validateToken(token, index, fieldIds) {
    var errors = [];
    if (!token || typeof token !== 'object') return ['command token ' + index + ' must be an object'];
    if (TOKEN_KINDS.indexOf(token.kind) === -1) fail(errors, 'command token ' + index + ' has unsupported kind ' + text(token.kind));
    if (token.when) validateCondition(token.when, 'command token ' + index + ' when', fieldIds).forEach(function (e) { fail(errors, e); });
    if (token.kind === 'literal' && !text(token.value).trim()) fail(errors, 'literal command token ' + index + ' requires value');
    if (['field', 'toggle', 'choice', 'repeat'].indexOf(token.kind) !== -1 && !fieldIds[token.field]) fail(errors, 'command token ' + index + ' references unknown field ' + text(token.field));
    if (token.kind === 'toggle' && !text(token.flag).trim()) fail(errors, 'toggle command token ' + index + ' requires flag');
    if (token.kind === 'choice' && !isArr(token.choices)) fail(errors, 'choice command token ' + index + ' requires choices');
    if (token.kind === 'choice') arr(token.choices).forEach(function (c) { if (!c || typeof c !== 'object' || !Object.prototype.hasOwnProperty.call(c, 'value') || !Object.prototype.hasOwnProperty.call(c, 'arg')) fail(errors, 'choice command token ' + index + ' contains an invalid choice'); });
    if (token.kind === 'concat') {
      if (!isArr(token.parts) || !token.parts.length) fail(errors, 'concat command token ' + index + ' requires parts');
      arr(token.parts).forEach(function (part) {
        if (!part || typeof part !== 'object') { fail(errors, 'concat command token ' + index + ' contains an invalid part'); return; }
        var hasField = Object.prototype.hasOwnProperty.call(part, 'field'), hasLiteral = Object.prototype.hasOwnProperty.call(part, 'literal');
        if (hasField === hasLiteral) fail(errors, 'concat command token ' + index + ' parts require exactly one field or literal');
        if (hasField && !fieldIds[part.field]) fail(errors, 'concat command token ' + index + ' references unknown field ' + text(part.field));
      });
    }
    if (token.kind === 'repeat' && token.split && ['lines', 'comma', 'space'].indexOf(token.split) === -1) fail(errors, 'repeat command token ' + index + ' has unsupported split ' + text(token.split));
    return errors;
  }

  function validateExecutable(executable, fieldIds) {
    var errors = [];
    if (typeof executable === 'string') {
      if (!text(executable).trim()) fail(errors, 'command executable must not be empty');
      return errors;
    }
    if (!executable || typeof executable !== 'object') return ['command executable must be a string or declared selector'];
    if (!fieldIds[executable.field]) fail(errors, 'command executable selector references unknown field ' + text(executable.field));
    if (!isArr(executable.choices) || !executable.choices.length) fail(errors, 'command executable selector requires choices');
    arr(executable.choices).forEach(function (choice) {
      if (!choice || typeof choice !== 'object' || !Object.prototype.hasOwnProperty.call(choice, 'value') || !text(choice.command).trim()) { fail(errors, 'command executable selector contains an invalid choice'); return; }
      if (!/^[A-Za-z0-9_./+-]+$/.test(text(choice.command))) fail(errors, 'command executable selector contains unsafe command literal ' + text(choice.command));
    });
    return errors;
  }

  // validate(builder) -> array of human-readable error strings ([] means valid). Structural,
  // safety, and reference checks; tolerant of extra descriptive keys (equips/category/defaults)
  // that the TOOLSET adds, but strict about the forbidden execution hooks.
  function validate(builder) {
    var errors = [];
    if (!builder || typeof builder !== 'object') return ['builder must be an object'];
    ['id', 'tool', 'title', 'summary'].forEach(function (k) { if (!text(builder[k]).trim()) fail(errors, 'builder requires ' + k); });
    if (!/^[a-z][a-z0-9_-]*$/i.test(text(builder.id))) fail(errors, 'builder id must be stable kebab/slug text');
    if (EXECUTION_CONTEXTS.indexOf(builder.executionContext || 'any') === -1) fail(errors, 'builder ' + text(builder.id) + ' has unsupported executionContext');
    var fields = arr(builder.fields);
    if (!fields.length) fail(errors, 'builder ' + text(builder.id) + ' requires at least one field');
    var ids = {};
    fields.forEach(function (field, index) {
      validateField(field, index).forEach(function (e) { fail(errors, e); });
      if (field && field.id) { if (ids[field.id]) fail(errors, 'duplicate field id ' + field.id); ids[field.id] = true; }
    });
    fields.forEach(function (field) {
      if (!field) return;
      if (field.requiredWhen) validateCondition(field.requiredWhen, 'field ' + field.id + ' requiredWhen', ids).forEach(function (e) { fail(errors, e); });
      if (field.visibleWhen) validateCondition(field.visibleWhen, 'field ' + field.id + ' visibleWhen', ids).forEach(function (e) { fail(errors, e); });
    });
    if (builder.fieldGroups !== undefined) {
      if (!isArr(builder.fieldGroups)) fail(errors, 'builder ' + text(builder.id) + ' fieldGroups must be an array');
      else {
        var grouped = {};
        builder.fieldGroups.forEach(function (group, gi) {
          if (!group || typeof group !== 'object') { fail(errors, 'builder ' + text(builder.id) + ' fieldGroup ' + gi + ' must be an object'); return; }
          if (!text(group.title).trim()) fail(errors, 'builder ' + text(builder.id) + ' fieldGroup ' + gi + ' requires a title');
          if (!text(group.description).trim()) fail(errors, 'builder ' + text(builder.id) + ' fieldGroup ' + gi + ' requires a plain-language description');
          if (!isArr(group.fields) || !group.fields.length) { fail(errors, 'builder ' + text(builder.id) + ' fieldGroup ' + gi + ' requires a non-empty fields list'); return; }
          group.fields.forEach(function (fid) {
            if (!ids[fid]) fail(errors, 'builder ' + text(builder.id) + ' fieldGroup ' + gi + ' references unknown field ' + text(fid));
            else if (grouped[fid]) fail(errors, 'builder ' + text(builder.id) + ' field ' + text(fid) + ' appears in more than one fieldGroup');
            else grouped[fid] = true;
          });
        });
      }
    }
    arr(builder.credentialModes).forEach(function (mode) { if (CREDENTIAL_KINDS.indexOf(mode) === -1) fail(errors, 'builder ' + text(builder.id) + ' has unsupported credential mode ' + text(mode)); });
    var command = builder.command;
    if (!command || typeof command !== 'object') fail(errors, 'builder ' + text(builder.id) + ' requires command model');
    else {
      validateExecutable(command.executable, ids).forEach(function (e) { fail(errors, e); });
      var tokens = arr(command.tokens);
      if (!tokens.length) fail(errors, 'builder ' + text(builder.id) + ' requires command tokens');
      tokens.forEach(function (token, index) { validateToken(token, index, ids).forEach(function (e) { fail(errors, e); }); });
    }
    var evidence = builder.evidence;
    if (!evidence || typeof evidence !== 'object' || !text(evidence.expectation).trim() || !text(evidence.proofBoundary).trim()) fail(errors, 'builder ' + text(builder.id) + ' requires Evidence expectation and proof boundary');
    var manual = builder.manualOutcome;
    if (!manual || manual.supported !== true || !text(manual.boundary).trim()) fail(errors, 'builder ' + text(builder.id) + ' requires manual outcome boundary');
    var report = builder.reportLineage;
    if (!report || report.activity !== true || report.evidenceRequiredForProof !== true) fail(errors, 'builder ' + text(builder.id) + ' must preserve report activity/proof lineage separation');
    FORBIDDEN.forEach(function (f) { if (Object.prototype.hasOwnProperty.call(builder, f)) fail(errors, 'builder ' + text(builder.id) + ' contains forbidden execution field ' + f); });
    return unique(errors);
  }

  // -------------------------------------------------------- value resolution / autofill --
  // Look up a dotted key (e.g. "target.value", "workspace.wordlist") in a nested context object.
  function contextValue(context, key) {
    var parts = text(key).split('.');
    var cur = context;
    for (var i = 0; i < parts.length; i++) { if (cur == null || typeof cur !== 'object') return ''; cur = cur[parts[i]]; }
    return cur == null ? '' : cur;
  }

  // Merge builder.defaults (static), then per-field default + autofill from context, over the
  // caller's values. Explicit values always win; autofill only fills blanks.
  function autofill(builder, context, values) {
    var out = {};
    var base = (builder && builder.defaults && typeof builder.defaults === 'object') ? builder.defaults : {};
    Object.keys(base).forEach(function (k) { out[k] = base[k]; });
    Object.keys(values || {}).forEach(function (k) { var v = values[k]; if (v !== undefined) out[k] = v; });
    arr(builder && builder.fields).forEach(function (field) {
      if ((out[field.id] === undefined || out[field.id] === '') && field.autofill) {
        var value = contextValue(context || {}, field.autofill);
        if (value !== '' && value != null) out[field.id] = value;
      }
      if (out[field.id] === undefined && field.default !== undefined) out[field.id] = field.default;
    });
    return out;
  }

  function normalizeValues(builder, values, context) { return autofill(builder, context, values || {}); }

  // The fully-resolved starting value set for a builder given a context (no caller overrides).
  function defaultsFor(builder, context) { return autofill(builder, context, {}); }

  // -------------------------------------------------------------- required-field check --
  function validateRequired(builder, values) {
    var missing = [];
    arr(builder.fields).forEach(function (field) {
      var required = field.required === true || (field.requiredWhen ? conditionMatches(field.requiredWhen, values) : false);
      if (!required) return;
      var v = values[field.id];
      if (v === undefined || v === null || v === '' || (field.type === 'checkbox' && field.mustBeChecked === true && !truthy(v))) missing.push(field.label || field.id);
    });
    return missing;
  }

  // ------------------------------------------------------------------ token compiler --
  function choiceArg(token, value) {
    var choice = arr(token.choices).filter(function (c) { return String(c.value) === String(value); })[0];
    return choice ? choice.arg : '';
  }
  function commandExecutable(builder, values) {
    var executable = builder && builder.command && builder.command.executable;
    if (typeof executable === 'string') return executable;
    if (executable && typeof executable === 'object') {
      var value = (values || {})[executable.field];
      var choice = arr(executable.choices).filter(function (e) { return String(e.value) === String(value); })[0];
      if (choice && choice.command) return String(choice.command);
      throw new Error('Select a valid command implementation');
    }
    throw new Error('Tool Builder command executable is invalid');
  }
  function valueWithAffixes(token, value) { return String(token.prefix || '') + String(value) + String(token.suffix || ''); }
  function splitRepeat(value, mode) {
    var raw = String(value == null ? '' : value);
    if (mode === 'comma') return raw.split(',').map(function (v) { return v.trim(); }).filter(Boolean);
    if (mode === 'space') return raw.split(/\s+/).map(function (v) { return v.trim(); }).filter(Boolean);
    return raw.split(/\r?\n/).map(function (v) { return v.trim(); }).filter(Boolean);
  }
  function concatValue(token, values) {
    var out = '';
    arr(token.parts).forEach(function (part) {
      if (Object.prototype.hasOwnProperty.call(part, 'literal')) { out += String(part.literal); return; }
      var value = values[part.field];
      if (value === undefined || value === null || value === '') return;
      out += String(part.prefix || '') + String(value) + String(part.suffix || '');
    });
    return out;
  }

  // compile(builder, values, context) -> a single shell-safe command string.
  // Throws when the builder is invalid or a required field is empty. Every non-raw value is
  // shell-quoted, so secrets and free text can never break out of their argument.
  function compile(builder, values, context) {
    var errors = validate(builder);
    if (errors.length) throw new Error(errors.join('; '));
    var resolved = normalizeValues(builder, values, context);
    var missing = validateRequired(builder, resolved);
    if (missing.length) throw new Error('Missing required fields: ' + missing.join(', '));
    var parts = [shellQuote(commandExecutable(builder, resolved))];
    arr(builder.command.tokens).forEach(function (token) {
      if (!conditionMatches(token.when, resolved)) return;
      if (token.kind === 'literal') { parts.push(String(token.value)); return; }
      var value = resolved[token.field];
      if (token.kind === 'toggle') { if (truthy(value)) parts.push(String(token.flag)); return; }
      if (token.kind === 'choice') { var a = choiceArg(token, value); if (a) parts.push(String(a)); return; }
      if (token.kind === 'concat') { var combined = concatValue(token, resolved); if (combined) parts.push(token.raw === true ? combined : shellQuote(combined)); return; }
      if (token.kind === 'repeat') {
        if (value === undefined || value === null || value === '') return;
        splitRepeat(value, token.split || 'lines').forEach(function (item) {
          if (token.flag) parts.push(String(token.flag));
          parts.push(token.raw === true ? item : shellQuote(valueWithAffixes(token, item)));
        });
        return;
      }
      if (token.kind === 'field') {
        if (value === undefined || value === null || value === '') return;
        if (token.flag) parts.push(String(token.flag));
        var rendered = valueWithAffixes(token, value);
        parts.push(token.raw === true ? rendered : shellQuote(rendered));
      }
    });
    return parts.filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
  }

  OBOL.toolbuilder = {
    FIELD_TYPES: FIELD_TYPES,
    CREDENTIAL_KINDS: CREDENTIAL_KINDS,
    EXECUTION_CONTEXTS: EXECUTION_CONTEXTS,
    shellQuote: shellQuote,
    truthy: truthy,
    conditionMatches: conditionMatches,
    validate: validate,
    autofill: autofill,
    normalizeValues: normalizeValues,
    defaultsFor: defaultsFor,
    validateRequired: validateRequired,
    commandExecutable: commandExecutable,
    compile: compile,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
