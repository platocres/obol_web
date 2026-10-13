const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
require(path.join(root, 'data/packs-bundle.js'));
const packData = globalThis.OBOL.packData;
const actionPacks = globalThis.OBOL.ACTION_PACKS;

console.log('=== OBOL MOVE LIBRARY GRAPH & PREREQUISITE AUDIT ===\n');

// 1. Gather all actions
const allActions = [];
const actionMap = new Map();
const packByAction = new Map();

actionPacks.forEach(pk => {
  const p = packData[pk];
  if (!p || !p.actions) return;
  p.actions.forEach(a => {
    allActions.push(a);
    actionMap.set(a.id, a);
    packByAction.set(a.id, pk);
  });
});

console.log(`Total Actions Loaded: ${allActions.length}`);

// 2. Gather all produced fact kinds across actions
const actionProducedKinds = new Set();
allActions.forEach(a => {
  (a.produces || []).forEach(k => actionProducedKinds.add(k));
});

// 3. Scan all engine and parser files for fact kinds
function getJsFiles(dir) {
  let res = [];
  fs.readdirSync(dir).forEach(f => {
    let p = path.join(dir, f);
    if (fs.statSync(p).isDirectory()) res = res.concat(getJsFiles(p));
    else if (p.endsWith('.js')) res.push(p);
  });
  return res;
}

const parserKinds = new Set();
// Scan the parser pipeline AND the UI layer: some facts are minted by the
// store/UI, not a parser (e.g. target.configured when a target is added or a
// paste is routed to a host), so a parser-only scan under-counts and cries wolf.
const engineFiles = getJsFiles(path.join(root, 'assets/engine'))
  .concat(getJsFiles(path.join(root, 'assets/ui')));

// Any quoted dotted kind literal ("privesc.suid_candidate", "blocker.potato",
// "smb.readable_share", ...). The three old narrow regexes missed how host.js
// and blockers.js actually mint, which is what produced the phantom
// "58 unminted requirements". A broad literal scan mirrors the real emit set.
const genericKindRegex = /['"`]([a-z][a-z0-9_]+(?:\.[a-z0-9_]+)+)['"`]/g;

engineFiles.forEach(f => {
  const filePath = f;
  if (!fs.existsSync(filePath)) return;
  const content = fs.readFileSync(filePath, 'utf8');
  let m;
  while ((m = genericKindRegex.exec(content)) !== null) parserKinds.add(m[1]);
});

// Also dynamically recognized patterns
// e.g., 'port:<num>', 'service.<name>'
function isDynamicallyMinted(k) {
  if (/^port:\d+$/.test(k)) return true;
  if (/^service\.[a-z0-9_-]+$/i.test(k)) return true;
  if (/^vuln\.[a-z0-9_-]+$/i.test(k)) return true;
  if (/^scan\.[a-z0-9_.-]+$/i.test(k)) return true;
  if (/^host\.[a-z0-9_-]+$/i.test(k)) return true;
  return false;
}

const allKnownKinds = new Set([...actionProducedKinds, ...parserKinds]);

// A requirement is satisfiable ("producible") if some action produces it, a
// parser/UI mints it, or it is a dynamically-resolved gate (port:/service./...).
function producible(k) {
  return allKnownKinds.has(k) || isDynamicallyMinted(k);
}

// A move is reachable if every requires_all entry is producible AND, when it
// has a requires_any, at least one branch is producible. A dead requires_any
// branch that has a live sibling does NOT make the move unreachable: it is a
// lost "precision hook" (the move still fires, just on a coarser gate).
function reachability(a) {
  const reqAll = a.requires_all || [];
  const reqAny = a.requires_any || [];
  const deadAll = reqAll.filter(k => !producible(k));
  const liveAny = reqAny.filter(producible);
  const deadAny = reqAny.filter(k => !producible(k));
  const unreachable = deadAll.length > 0 || (reqAny.length > 0 && liveAny.length === 0);
  return { unreachable, deadAll, deadAny, hasLiveAny: liveAny.length > 0 };
}

console.log(`Unique Fact Kinds Produced by Actions: ${actionProducedKinds.size}`);
console.log(`Unique Fact Kinds Minted by Parsers/UI: ${parserKinds.size}`);

// Audit Checks
const issues = {
  emptyProduces: [],
  emptyRequires: [],
  selfDependencies: [],
  redundantRequirements: [],
  unproducedRequires: [],
  unreachableMoves: [],
  deadBranches: [],
  duplicateProduces: [],
  badFactFormat: [],
  obsoleteInvalidKinds: [],
  deprioritizeInvalidKinds: []
};

allActions.forEach(a => {
  const pack = packByAction.get(a.id);
  const reqAll = a.requires_all || [];
  const reqAny = a.requires_any || [];
  const produces = a.produces || [];
  const obsoletedBy = a.obsoleted_by || [];
  const deprioritizeWhen = a.deprioritize_when || [];

  // Check 1: Empty produces
  if (!produces.length) {
    issues.emptyProduces.push({ id: a.id, pack });
  }

  // Check 2: Empty requires (ungated moves)
  if (!reqAll.length && !reqAny.length) {
    issues.emptyRequires.push({ id: a.id, pack, priority: a.priority, phase: a.phase, title: a.title });
  }

  // Check 3: Self-dependencies that are a genuine chicken-and-egg.
  // The fact ledger dedups on (kind, scope, value), so an action that consumes
  // one instance of a kind and produces a NEW instance (e.g. laps-read consumes
  // a domain credential.available and produces the recovered local-admin
  // credential.available) is legitimate, not a loop. Likewise a self-kind in
  // requires_any next to other live branches is benign re-entry. Only flag the
  // case where the self-produced kind is the SOLE way in: it sits in
  // requires_all (or is the only requires_any branch) with no other satisfiable
  // requirement, so the move could never fire the first time.
  const otherReqsLive =
    reqAll.some(k => !produces.includes(k) && producible(k)) ||
    reqAny.some(k => !produces.includes(k) && producible(k));
  [...reqAll.map(k => [k, 'requires_all']), ...reqAny.map(k => [k, 'requires_any'])].forEach(([k, where]) => {
    if (!produces.includes(k)) return;
    const soleGate = (where === 'requires_all') || (where === 'requires_any' && reqAny.length === 1);
    if (soleGate && !otherReqsLive) {
      issues.selfDependencies.push({ id: a.id, pack, kind: k, in: where });
    }
  });

  // Check 4: Redundant requirements
  const seenReqAll = new Set();
  reqAll.forEach(k => {
    if (seenReqAll.has(k)) {
      issues.redundantRequirements.push({ id: a.id, pack, kind: k, reason: 'Duplicate in requires_all' });
    }
    seenReqAll.add(k);
  });

  const seenReqAny = new Set();
  reqAny.forEach(k => {
    if (seenReqAny.has(k)) {
      issues.redundantRequirements.push({ id: a.id, pack, kind: k, reason: 'Duplicate in requires_any' });
    }
    seenReqAny.add(k);
    if (seenReqAll.has(k)) {
      issues.redundantRequirements.push({ id: a.id, pack, kind: k, reason: 'In requires_any but already in requires_all' });
    }
  });

  // Check 5: Reachability. The thing that actually matters is not "is this
  // kind minted somewhere" but "can this move ever become eligible". Split the
  // old raw unminted-kind list into (a) UNREACHABLE moves (a real defect: the
  // move can never fire) and (b) dead branches / precision hooks (the required
  // kind is never minted, but a live sibling keeps the move reachable, so it
  // just fires on a coarser gate than intended).
  const reach = reachability(a);
  if (reach.unreachable) {
    issues.unreachableMoves.push({ id: a.id, pack, deadRequiresAll: reach.deadAll, requiresAny: reqAny });
  } else {
    reach.deadAny.forEach(k => issues.deadBranches.push({ id: a.id, pack, kind: k, in: 'requires_any' }));
    reach.deadAll.forEach(k => issues.deadBranches.push({ id: a.id, pack, kind: k, in: 'requires_all' }));
  }

  // Check 6: Duplicate produces
  const seenProd = new Set();
  produces.forEach(k => {
    if (seenProd.has(k)) {
      issues.duplicateProduces.push({ id: a.id, pack, kind: k });
    }
    seenProd.add(k);
  });

  // Check 7: Bad format (spaces, uppercase, undefined, etc.)
  [...reqAll, ...reqAny].concat(produces).forEach(k => {
    if (!k || typeof k !== 'string' || /\s/.test(k)) {
      issues.badFactFormat.push({ id: a.id, pack, kind: k });
    }
  });

  // Check 8: obsoleted_by / deprioritize_when validity
  obsoletedBy.forEach(k => {
    if (!allKnownKinds.has(k) && !isDynamicallyMinted(k)) {
      issues.obsoleteInvalidKinds.push({ id: a.id, pack, kind: k });
    }
  });
  deprioritizeWhen.forEach(k => {
    if (!allKnownKinds.has(k) && !isDynamicallyMinted(k)) {
      issues.deprioritizeInvalidKinds.push({ id: a.id, pack, kind: k });
    }
  });
});

console.log('\n--- AUDIT FINDINGS ---');
console.log(`1. Empty produces (actions that can never settle): ${issues.emptyProduces.length}`);
if (issues.emptyProduces.length) console.log(issues.emptyProduces);

console.log(`\n2. Self-dependencies (action requires a fact it produces): ${issues.selfDependencies.length}`);
if (issues.selfDependencies.length) console.log(issues.selfDependencies);

console.log(`\n3. Redundant requirements (duplicates or any-in-all): ${issues.redundantRequirements.length}`);
if (issues.redundantRequirements.length) console.log(issues.redundantRequirements);

console.log(`\n4. UNREACHABLE moves (a required fact can never be satisfied, so the move can never fire): ${issues.unreachableMoves.length}`);
if (issues.unreachableMoves.length) console.log(issues.unreachableMoves);

console.log(`\n4b. Dead requirement branches (precision hooks: kind never minted, but a live sibling keeps the move reachable): ${issues.deadBranches.length}`);
if (issues.deadBranches.length) console.log(issues.deadBranches);

console.log(`\n5. Duplicate produces: ${issues.duplicateProduces.length}`);
if (issues.duplicateProduces.length) console.log(issues.duplicateProduces);

console.log(`\n6. Bad fact format: ${issues.badFactFormat.length}`);
if (issues.badFactFormat.length) console.log(issues.badFactFormat);

console.log(`\n7. Invalid obsoleted_by kinds: ${issues.obsoleteInvalidKinds.length}`);
if (issues.obsoleteInvalidKinds.length) console.log(issues.obsoleteInvalidKinds);

console.log(`\n8. Invalid deprioritize_when kinds: ${issues.deprioritizeInvalidKinds.length}`);
if (issues.deprioritizeInvalidKinds.length) console.log(issues.deprioritizeInvalidKinds);

console.log(`\n9. Actions with empty requires (ungated initial moves): ${issues.emptyRequires.length}`);
console.log(issues.emptyRequires.map(x => `${x.id} (${x.pack}) [priority: ${x.priority}, phase: ${x.phase}] - ${x.title}`));

// --- Regression gate (node tools/audit_graph.js --check) ---------------------
// Fails the build if graph hygiene regresses, so a new/edited move can't silently
// reintroduce a self-loop, an unreachable move, a dead precision-hook branch, an
// empty-produces move, or a malformed fact kind. Add this to the verify list.
// These five buckets are currently zero; keep them that way (mint the fact,
// point the requirement at a real kind, or drop the dead branch).
if (process.argv.indexOf('--check') >= 0) {
  const gate = [
    ['self-dependencies', issues.selfDependencies],
    ['unreachable moves', issues.unreachableMoves],
    ['dead requirement branches', issues.deadBranches],
    ['empty produces', issues.emptyProduces],
    ['bad fact format', issues.badFactFormat],
    ['invalid obsoleted_by kinds', issues.obsoleteInvalidKinds],
    ['invalid deprioritize_when kinds', issues.deprioritizeInvalidKinds],
  ];
  const failed = gate.filter(([, list]) => list.length);
  console.log('\n=== GRAPH HYGIENE GATE ===');
  if (failed.length) {
    failed.forEach(([name, list]) => console.log(`FAIL: ${list.length} ${name}`));
    console.log('GRAPH HYGIENE CHECK FAILED');
    process.exit(1);
  }
  console.log('PASS: graph hygiene clean (0 self-deps, 0 unreachable, 0 dead branches, 0 empty-produces, 0 malformed kinds)');
}
