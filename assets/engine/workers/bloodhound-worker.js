/*!
 * obol engine — workers/bloodhound-worker.js
 * Runs the BloodHound ingest + analysis OFF the main thread. SharpHound exports can be large
 * (tens of MB of JSON), and unzipping + the bounded owned→DA DFS would jank the UI on the main
 * thread; this Worker does the heavy lifting and posts the finished summary/view/facts back.
 *
 * DEGRADATION CONTRACT (important — the caller, not this file, handles the fallback):
 *   The page should FIRST try to construct this Worker. If Workers are unavailable — the classic
 *   case is opening the site from file:// where `new Worker(url)` throws a SecurityError, but also
 *   any environment that blocks Workers — the caller catches that and runs the SAME engine on the
 *   main thread directly:
 *
 *       // main thread fallback (no worker):
 *       //   OBOL.bloodhound.parse(files).then(function (summary) {
 *       //     var owned = OBOL.bloodhound.ownedPaths(summary, ownedPrincipals);
 *       //     var view  = OBOL.bloodhound.domainView(summary, ownedPrincipals);
 *       //     var facts = OBOL.bloodhound.toFacts(summary, owned, scope);
 *       //     var html  = OBOL.bloodhound.domainReportHtml(summary, view);
 *       //     OBOL.bloodhound.dropGraph(summary); // before persisting
 *       //   });
 *
 *   The results are identical either way — this Worker is a pure performance wrapper around
 *   OBOL.bloodhound, adding no behavior of its own.
 *
 * PROTOCOL:
 *   postMessage({ id, type:'ingest', files:[{name, arrayBuffer|text}], ownedPrincipals:[…], scope? })
 *   → posts back one of:
 *       { id, ok:true, summary, view, facts, reportHtml, ownedPaths }
 *       { id, ok:false, error:'…' }
 *   `files[].arrayBuffer` should be a transferable ArrayBuffer for a .zip (transfer it to avoid a
 *   copy); `files[].text` a string for a pre-extracted .json. The summary posted back has had its
 *   transient `_graph` dropped (it isn't structured-cloneable-cheap and isn't needed by the UI).
 *
 * This file loads its dependencies with importScripts. Paths are relative to THIS worker file
 * (assets/engine/workers/), so facts.js and bloodhound.js sit one level up and jszip two levels up.
 */
'use strict';

/* global importScripts, OBOL */
try {
  importScripts(
    '../facts.js',            // assets/engine/facts.js — OBOL.facts (must load first)
    '../../jszip.min.js',     // assets/jszip.min.js — the JSZip global, for .zip uploads
    '../bloodhound.js'        // assets/engine/bloodhound.js — OBOL.bloodhound
  );
} catch (e) {
  // If importScripts fails, every message will error out with this reason (surfaced to the caller,
  // which then falls back to the main-thread path described above).
  self.__obolImportError = String(e && e.message || e);
}

self.onmessage = function (ev) {
  var msg = ev.data || {};
  var id = msg.id;

  if (self.__obolImportError) {
    self.postMessage({ id: id, ok: false, error: 'worker failed to load engine: ' + self.__obolImportError });
    return;
  }
  if (typeof OBOL === 'undefined' || !OBOL.bloodhound) {
    self.postMessage({ id: id, ok: false, error: 'OBOL.bloodhound not available in worker' });
    return;
  }

  if (msg.type !== 'ingest') {
    self.postMessage({ id: id, ok: false, error: 'unknown message type: ' + msg.type });
    return;
  }

  var bh = OBOL.bloodhound;
  var ownedPrincipals = msg.ownedPrincipals || [];
  var scope = msg.scope || '';

  Promise.resolve()
    .then(function () { return bh.parse(msg.files || []); })
    .then(function (summary) {
      // ownedPaths + view read the transient _graph; compute everything BEFORE dropping it.
      var owned = bh.ownedPaths(summary, ownedPrincipals);
      var view = bh.domainView(summary, ownedPrincipals);
      var facts = bh.toFacts(summary, owned, scope || undefined);
      var reportHtml = bh.domainReportHtml(summary, view);
      bh.dropGraph(summary); // shed the large transient graph before posting back
      self.postMessage({
        id: id, ok: true,
        summary: summary, view: view, facts: facts,
        ownedPaths: owned, reportHtml: reportHtml,
      });
    })
    .catch(function (err) {
      self.postMessage({ id: id, ok: false, error: String(err && err.message || err) });
    });
};
