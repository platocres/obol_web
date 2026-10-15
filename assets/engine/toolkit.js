/*!
 * obol engine — toolkit.js — the glue the revamped Tools surface runs on (pure, Node-safe, tested).
 *
 * Three jobs, all presentation-only (they never execute, never touch the ranker or the move graph):
 *   1. RECIPES   — named field PRESETS per builder (OBOL.TOOL_RECIPES): list them, and apply one to a
 *                  builder's value set (recipe values over the builder's autofilled defaults).
 *   2. GLOSSARY  — turn any compiled or hand-edited command into a flag-by-flag teaching list
 *                  (OBOL.TOOL_GLOSSARY): tokenize, recognize flags/subcommands, return [{token,gloss}].
 *   3. STATIONS  — group substitute tools by the JOB they do (OBOL.STATIONS): resolve a station's
 *                  engines to live builders, and carry shared parameter values across an engine swap.
 *
 * Attaches to OBOL.toolkit with the usual module pattern so it runs in the browser, a Worker, and Node.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  function arr(v) { return Array.isArray(v) ? v : []; }
  function text(v) { return String(v == null ? '' : v); }

  // ---------------------------------------------------------------- recipes --
  function recipesFor(builderId) { return arr((OBOL.TOOL_RECIPES || {})[builderId]).slice(); }
  function recipeById(builderId, recipeId) {
    return recipesFor(builderId).filter(function (r) { return r.id === recipeId; })[0] || null;
  }
  // applyRecipe(builder, recipe, context) -> a fresh values object: the builder's autofilled defaults
  // with the recipe's values laid on top. Explicit recipe values win; everything else keeps its
  // autofill (so the engagement's target/url still flows in). The form adopts this wholesale (Option B).
  function applyRecipe(builder, recipe, context) {
    var TB = OBOL.toolbuilder;
    var base = TB ? TB.defaultsFor(builder, context || {}) : {};
    var out = {};
    Object.keys(base).forEach(function (k) { out[k] = base[k]; });
    var vals = (recipe && recipe.values) || {};
    Object.keys(vals).forEach(function (k) { out[k] = vals[k]; });
    return out;
  }
  // which recipe (if any) a value set currently matches, so the UI can highlight the active tile and
  // fall back to "Custom" once the operator edits a field a recipe pinned. When one recipe's values are
  // a subset of another's (ntlm vs ntlm+rules), the MOST SPECIFIC match wins (most pinned keys), so a
  // broader recipe never shadows the exact one the operator applied.
  function matchingRecipe(builder, values) {
    var recipes = recipesFor(builder && builder.id), best = null, bestKeys = -1;
    for (var i = 0; i < recipes.length; i++) {
      var vals = recipes[i].values || {}, ok = true, n = 0;
      for (var k in vals) { if (Object.prototype.hasOwnProperty.call(vals, k)) { n++; if (text(values[k]) !== text(vals[k])) { ok = false; break; } } }
      if (ok && n > bestKeys) { best = recipes[i].id; bestKeys = n; }
    }
    return best;
  }

  // ---------------------------------------------------------------- glossary --
  // The tool name to look glossary keys up under, given the command's first token and the builder.
  function glossToolName(firstToken, builder) {
    var G = OBOL.TOOL_GLOSSARY || {};
    var t = text(firstToken).split('/').pop().replace(/^\.\//, '').replace(/\.(exe|sh|py)$/i, '').toLowerCase();
    if (G[t]) return t;
    // builder.tool may be a slash list ("gobuster/feroxbuster"); try each.
    var fromBuilder = text(builder && builder.tool).toLowerCase().split('/');
    for (var i = 0; i < fromBuilder.length; i++) { if (G[fromBuilder[i]]) return fromBuilder[i]; }
    return t;
  }
  // Split a command string into tokens, honoring single/double quotes (so a quoted header stays one
  // token and its inner spaces do not masquerade as flags).
  function tokenize(cmd) {
    var out = [], re = /"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\S+/g, m;
    while ((m = re.exec(text(cmd)))) out.push(m[0]);
    return out;
  }
  // glossCommand(cmd, builder) -> [{token, flag, gloss}] for every token whose flag is in the tool's
  // glossary. Recognizes `-mc`, `--format=x` (keyed under `--format`), and a subcommand word (gobuster
  // `dir`, kerbrute `userenum`). De-duplicated by flag so a repeated -H is explained once.
  function glossCommand(cmd, builder) {
    var toks = tokenize(cmd);
    if (!toks.length) return [];
    var G = OBOL.TOOL_GLOSSARY || {};
    var dict = G[glossToolName(toks[0], builder)] || {};
    var out = [], seen = {};
    toks.forEach(function (tok, i) {
      if (i === 0) return; // the executable itself
      var key = tok;
      if (tok.indexOf('=') > 0 && /^--?/.test(tok)) key = tok.slice(0, tok.indexOf('=')); // --format=x
      var gloss = dict[key];
      if (gloss === undefined && !/^-/.test(tok)) gloss = dict[tok.toLowerCase()]; // bare subcommand
      if (gloss === undefined) return;
      if (seen[key]) return;
      seen[key] = 1;
      out.push({ token: tok, flag: key, gloss: gloss });
    });
    return out;
  }
  function hasGlossary(toolName) { return !!(OBOL.TOOL_GLOSSARY || {})[text(toolName).toLowerCase()]; }

  // ---------------------------------------------------------------- stations --
  function stations() { return arr(OBOL.STATIONS).slice(); }
  function stationById(id) { return stations().filter(function (s) { return s.id === id; })[0] || null; }
  // The builders a station's engines resolve to, in the station's declared order, filtered to those
  // that actually exist in the TOOLSET (so a not-yet-built engine is silently skipped until it lands).
  function stationBuilders(station) {
    var byId = {}; arr(OBOL.TOOLSET).forEach(function (b) { byId[b.id] = b; });
    return arr(station && station.engines).map(function (e) {
      return byId[e.builderId] ? { engine: e, builder: byId[e.builderId] } : null;
    }).filter(Boolean);
  }
  // Carry shared parameter VALUES across an engine swap: for each of the station's sharedParams, copy
  // the value out of the old engine's field (via its sharedMap) and into the new engine's field. Keeps
  // the url / wordlist / extensions the operator set when they switch ffuf -> gobuster.
  function carryShared(station, fromEngine, toEngine, fromValues) {
    var out = {};
    arr(station && station.sharedParams).forEach(function (param) {
      var fromField = (fromEngine && fromEngine.sharedMap && fromEngine.sharedMap[param]) || param;
      var toField = (toEngine && toEngine.sharedMap && toEngine.sharedMap[param]) || param;
      var v = (fromValues || {})[fromField];
      if (v !== undefined && v !== '') out[toField] = v;
    });
    return out;
  }
  // The engine a station should default to for the current facts: an engine whose `whenFact` kind is
  // present wins (stack-aware default), else the station's declared default, else the first engine.
  function defaultEngine(station, factKinds) {
    var kinds = {};
    if (Array.isArray(factKinds)) factKinds.forEach(function (k) { kinds[k] = 1; });
    else if (factKinds && typeof factKinds === 'object') kinds = factKinds; // FactSet.kinds() object-set

    var engines = arr(station && station.engines);
    for (var i = 0; i < engines.length; i++) { if (engines[i].whenFact && kinds[engines[i].whenFact]) return engines[i].builderId; }
    return (station && station.defaultEngine) || (engines[0] && engines[0].builderId) || null;
  }

  OBOL.toolkit = {
    recipesFor: recipesFor,
    recipeById: recipeById,
    applyRecipe: applyRecipe,
    matchingRecipe: matchingRecipe,
    glossCommand: glossCommand,
    glossToolName: glossToolName,
    tokenize: tokenize,
    hasGlossary: hasGlossary,
    stations: stations,
    stationById: stationById,
    stationBuilders: stationBuilders,
    carryShared: carryShared,
    defaultEngine: defaultEngine,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
