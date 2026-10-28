/*!
 * obol ui - settings.js - the bottom-right appearance control.
 * A single floating button + popover for the things worth letting anyone customise: skin, motion
 * (full/reduced/off), coin bursts, and block opacity (fade the surfaces so the motion background
 * shows through). Presentation-only. Skin persists via OBOL.store prefs (pre-painted in <head>);
 * motion/opacity/coins persist to their own tiny localStorage keys that backdrop.js + coin.js read.
 */
(function (root) {
  "use strict";
  var OBOL = root.OBOL = root.OBOL || {};
  var LS_MOTION = "obol.motion", LS_OPACITY = "obol.surface-alpha", LS_KALI_HINT = "obol.kali-motion-hint";
  function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }

  var SKINS = [
    { id: "obol", label: "OBOL" }, { id: "htb", label: "HTB" }, { id: "indigo", label: "Indigo" },
    { id: "ghostwire", label: "Ghostwire" }, { id: "amber", label: "Amber" },
    { id: "neon", label: "Neon" }, { id: "daylight", label: "Daylight" }
  ];
  var MOTION = ["full", "off"];
  var MOTION_LABEL = { full: "◉ Motion: on", off: "○ Motion: off" };

  function currentSkin() {
    try { return document.documentElement.getAttribute("data-skin") || (OBOL.store && OBOL.store.pref().skin) || "obol"; } catch (e) { return "obol"; }
  }
  function motionLevel() { return lsGet(LS_MOTION) === "off" ? "off" : "full"; }
  function osReducedMotion() {
    try { return !!(root.matchMedia && root.matchMedia("(prefers-reduced-motion: reduce)").matches); } catch (e) { return false; }
  }
  function isLinuxClient(nav) {
    if (root.__OBOL_FORCE_LINUX_HINT === true) return true;
    if (root.__OBOL_FORCE_LINUX_HINT === false) return false;
    try {
      var n = nav || root.navigator || {};
      var ua = String(n.userAgent || "");
      var plat = String(n.platform || "");
      var uaPlat = String((n.userAgentData && n.userAgentData.platform) || "");
      if (/\b(?:Android|CrOS)\b/i.test(ua)) return false;
      return /\b(?:Linux|Kali)\b/i.test(uaPlat) || /\b(?:Linux|Kali)\b/i.test(plat) || /\b(?:Linux|Kali)\b/i.test(ua);
    } catch (e) { return false; }
  }
  function surfaceAlpha() { var v = parseFloat(lsGet(LS_OPACITY)); return (v >= 0 && v <= 1) ? v : 0.5; }
  function applySurfaceAlpha(v) { try { document.documentElement.style.setProperty("--surface-alpha", String(v)); } catch (e) {} }
  function coinsOn() { return !OBOL.coins || OBOL.coins.enabled(); }
  function toast(m, k) { try { if (OBOL.util && OBOL.util.toast) OBOL.util.toast(m, k); } catch (e) {} }

  var panel = null, btn = null, hint = null, open = false, hintOpen = false, hintShownOnLanding = false;
  var skinBtns = [], motionBtn = null, coinBtn = null;

  function setMotionLevel(next) {
    var val = next === "off" ? "off" : "full";
    lsSet(LS_MOTION, val);
    try { document.documentElement.setAttribute("data-motion", (val === "off" || osReducedMotion()) ? "off" : "full"); } catch (e) {}
    if (OBOL.backdrop) OBOL.backdrop.update();
    if (motionBtn) syncMotion();
    if (OBOL.coins && OBOL.coins.updateMotion) OBOL.coins.updateMotion();
    if (OBOL.tips && OBOL.tips.refresh) OBOL.tips.refresh();
    if (val === "off") dismissHint(true);
  }

  function showHint() {
    if (!hint || !btn) return;
    hintShownOnLanding = true;
    if (hintOpen) return;
    hintOpen = true;
    hint.hidden = false;
    hint.classList.add("is-open");
    if (typeof hint.showPopover === "function" && hint.hasAttribute("popover")) {
      try { hint.showPopover(); } catch (e) {}
    }
    btn.classList.add("is-hinting");
    var active = document.activeElement;
    if (!active || active === document.body || active === document.documentElement) {
      var cta = hint.querySelector("[data-mh-off]");
      if (cta && cta.focus) {
        try { cta.focus({ preventScroll: true }); } catch (e2) { try { cta.focus(); } catch (e3) {} }
      }
    }
  }

  function hideHint() {
    if (!hint) return;
    hintOpen = false;
    hint.classList.remove("is-open");
    if (typeof hint.hidePopover === "function" && hint.hasAttribute("popover")) {
      try { hint.hidePopover(); } catch (e) {}
    }
    hint.hidden = true;
    if (btn) btn.classList.remove("is-hinting");
  }

  function dismissHint(persist) {
    if (persist !== false) lsSet(LS_KALI_HINT, "1");
    hideHint();
  }

  function hasBlockingOverlay() {
    try {
      var qp = document.getElementById("qp-overlay");
      if (qp && !qp.hidden && qp.classList && qp.classList.contains("open")) return true;
      var pal = document.getElementById("palette");
      if (pal && !pal.hidden && pal.classList && pal.classList.contains("open")) return true;
    } catch (e) {}
    return false;
  }

  function syncHint(routeName) {
    if (!hint || !btn) return;
    var route = String(routeName || "");
    if (!route) {
      try { route = document.documentElement.getAttribute("data-route") || ""; } catch (e) {}
    }
    if (!route) {
      try { if (/^#\/?start(?:[/?]|$)/.test((root.location && root.location.hash) || "")) route = "start"; } catch (e2) {}
    }
    if (!route) return;
    if (route !== "start") {
      if (hintShownOnLanding) lsSet(LS_KALI_HINT, "1");
      hideHint();
      return;
    }
    if (open || hasBlockingOverlay() || lsGet(LS_KALI_HINT) === "1" || motionLevel() === "off" || osReducedMotion() || !isLinuxClient()) {
      hideHint();
      return;
    }
    showHint();
  }

  function buildHint() {
    hint = document.createElement("div");
    hint.id = "obol-motion-hint";
    hint.className = "obol-motion-hint";
    if (typeof HTMLElement !== "undefined" && "popover" in HTMLElement.prototype && typeof hint.showPopover === "function") {
      hint.setAttribute("popover", "manual");
    }
    hint.setAttribute("role", "dialog");
    hint.setAttribute("aria-labelledby", "obol-motion-hint-title");
    hint.setAttribute("aria-describedby", "obol-motion-hint-desc");
    hint.hidden = true;
    hint.innerHTML =
      '<div class="obol-mh-top">'
      + '<span class="obol-mh-badge"><span class="obol-mh-dot" aria-hidden="true"></span>' + OBOL.ic("activity") + '<span>Kali / Linux VM Tip</span></span>'
      + '<button type="button" class="obol-mh-close" data-mh-dismiss aria-label="Dismiss CPU motion tip" title="Dismiss">&times;</button>'
      + '</div>'
      + '<h2 id="obol-motion-hint-title" class="obol-mh-title">CPU Running Hard? Turn Off Motion</h2>'
      + '<p id="obol-motion-hint-desc" class="obol-mh-desc">VM browsers render animations in software. Turn off motion here - or anytime in <span class="obol-mh-inline">' + OBOL.ic("gear") + ' Appearance</span> - to reduce CPU usage right away.</p>'
      + '<div class="obol-mh-actions">'
      + '<button type="button" class="obol-mh-btn obol-mh-btn-primary" data-mh-off>' + OBOL.ic("bolt") + '<span>Turn Off Motion</span></button>'
      + '<button type="button" class="obol-mh-btn" data-mh-open>' + OBOL.ic("gear") + '<span>Appearance</span></button>'
      + '<button type="button" class="obol-mh-btn obol-mh-btn-quiet" data-mh-dismiss><span>Got It</span></button>'
      + '</div>'
      + '<span class="obol-mh-arrow" aria-hidden="true"></span>';

    hint.addEventListener("click", function (e) {
      var t = e.target;
      if (!t || !t.closest) return;
      if (t.closest("[data-mh-off]")) {
        e.stopPropagation();
        setMotionLevel("off");
        toast("Motion turned off - low-CPU mode active");
        if (btn && btn.focus) btn.focus();
        return;
      }
      if (t.closest("[data-mh-open]")) {
        e.stopPropagation();
        dismissHint(true);
        openPanel();
        if (motionBtn && motionBtn.focus) motionBtn.focus();
        return;
      }
      if (t.closest("[data-mh-dismiss]")) {
        e.stopPropagation();
        dismissHint(true);
        if (btn && btn.focus) btn.focus();
      }
    });
    return hint;
  }

  function build() {
    btn = document.createElement("button");
    btn.id = "obol-settings-toggle"; btn.type = "button"; btn.className = "obol-settings-toggle";
    btn.setAttribute("aria-label", "Appearance settings"); btn.setAttribute("aria-expanded", "false");
    btn.title = "Appearance"; btn.innerHTML = OBOL.ic("gear");
    btn.addEventListener("click", function (e) { e.stopPropagation(); toggle(); });

    panel = document.createElement("div");
    panel.id = "obol-settings-panel"; panel.className = "obol-settings-panel"; panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-label", "Appearance settings"); panel.hidden = true;

    panel.appendChild(sectionTitle("Skin"));
    var skinWrap = document.createElement("div"); skinWrap.className = "obol-set-skins";
    SKINS.forEach(function (s) {
      var b = document.createElement("button"); b.type = "button"; b.className = "obol-set-skin"; b.dataset.skin = s.id; b.textContent = s.label;
      b.addEventListener("click", function (e) { e.stopPropagation(); setSkin(s.id); });
      skinBtns.push(b); skinWrap.appendChild(b);
    });
    panel.appendChild(skinWrap);

    panel.appendChild(sectionTitle("Effects"));
    var fx = document.createElement("div"); fx.className = "obol-set-row";
    motionBtn = document.createElement("button"); motionBtn.type = "button"; motionBtn.className = "obol-set-btn";
    motionBtn.addEventListener("click", function (e) {
      e.stopPropagation();
      var next = MOTION[(MOTION.indexOf(motionLevel()) + 1) % MOTION.length];
      setMotionLevel(next);
    });
    fx.appendChild(motionBtn);
    coinBtn = document.createElement("button"); coinBtn.type = "button"; coinBtn.className = "obol-set-btn";
    coinBtn.addEventListener("click", function (e) {
      e.stopPropagation();
      var on = coinsOn(); if (OBOL.coins) OBOL.coins.setEnabled(!on); syncCoins();
      if (!on && OBOL.coins) OBOL.coins.burst("foothold", "coins on");
    });
    fx.appendChild(coinBtn);
    panel.appendChild(fx);

    panel.appendChild(sectionTitle("Block opacity"));
    var opWrap = document.createElement("div"); opWrap.className = "obol-set-opacity";
    var opLabel = document.createElement("div"); opLabel.className = "obol-set-oplabel";
    var op = document.createElement("input"); op.type = "range"; op.min = "0.3"; op.max = "1"; op.step = "0.05"; op.value = String(surfaceAlpha());
    op.setAttribute("aria-label", "Block opacity");
    function syncOp() { opLabel.textContent = "▦ " + Math.round(parseFloat(op.value) * 100) + "% opaque"; }
    op.addEventListener("input", function (e) { e.stopPropagation(); var v = parseFloat(op.value); applySurfaceAlpha(v); lsSet(LS_OPACITY, String(v)); syncOp(); });
    op.addEventListener("click", function (e) { e.stopPropagation(); });
    syncOp(); opWrap.appendChild(opLabel); opWrap.appendChild(op); panel.appendChild(opWrap);

    // Workspace: export the active engagement or the whole workspace to JSON, and import it back.
    panel.appendChild(sectionTitle("Workspace"));
    var wsWrap = document.createElement("div"); wsWrap.className = "obol-set-row";
    var fileInput = document.createElement("input");
    fileInput.type = "file"; fileInput.accept = "application/json,.json"; fileInput.style.display = "none";
    function mkBtn(label, fn) { var b = document.createElement("button"); b.type = "button"; b.className = "obol-set-btn"; b.textContent = label; b.addEventListener("click", function (e) { e.stopPropagation(); fn(); }); return b; }
    function dstamp() { var d = new Date(); function p(n) { return String(n).padStart(2, "0"); } return d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + "-" + p(d.getHours()) + p(d.getMinutes()); }
    function slugify(s) { return String(s || "engagement").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "engagement"; }
    function download(stem, obj) {
      if (!obj) { toast("Nothing to export"); return; }
      var blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
      var a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = stem + ".json";
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
    }
    wsWrap.appendChild(mkBtn("⭳ Export Engagement", function () {
      var eng = OBOL.store.active(); download("obol-" + slugify(eng && eng.name), OBOL.store.exportEngagement());
    }));
    wsWrap.appendChild(mkBtn("⭳ Export All", function () { download("obol-workspace-" + dstamp(), OBOL.store.exportAll()); }));
    wsWrap.appendChild(mkBtn("⭱ Import File…", function () { fileInput.click(); }));
    fileInput.addEventListener("change", function () {
      var f = fileInput.files && fileInput.files[0]; if (!f) return;
      var r = new FileReader();
      r.onload = function () {
        var data; try { data = JSON.parse(r.result); } catch (e) { toast("Invalid JSON file", "err"); return; }
        OBOL.store.importData(data).then(function (n) {
          fileInput.value = "";
          if (n) { toast("Imported " + n + " engagement" + (n === 1 ? "" : "s")); if (OBOL.app && OBOL.app.renderSidebar) OBOL.app.renderSidebar(); if (OBOL.router) OBOL.router.render(); }
          else toast("No engagements found in that file", "err");
        });
      };
      r.readAsText(f);
    });
    panel.appendChild(wsWrap); panel.appendChild(fileInput);

    // Data: a full factory reset - erase every OBOL engagement, screenshot and setting in this
    // browser (a hard refresh doesn't clear IndexedDB). Always reachable from the settings panel, with a confirm.
    panel.appendChild(sectionTitle("Data"));
    var dataWrap = document.createElement("div"); dataWrap.className = "obol-set-row";
    var resetBtn = document.createElement("button");
    resetBtn.type = "button"; resetBtn.className = "obol-set-btn obol-set-danger"; resetBtn.textContent = "⚠ Full Reset, Erase All Data";
    resetBtn.addEventListener("click", function (e) {
      e.stopPropagation();
      if (!confirm("FULL RESET\n\nErase everything OBOL saved in this browser (every engagement, screenshot, and setting) and start completely fresh.\n\nThis cannot be undone. Continue?")) return;
      if (!(OBOL.store && OBOL.store.resetAll)) { location.reload(); return; }
      OBOL.store.resetAll().then(function () { toast("All data cleared, reloading fresh"); setTimeout(function () { location.reload(); }, 200); });
    });
    dataWrap.appendChild(resetBtn); panel.appendChild(dataWrap);

    var hintEl = buildHint();
    var host = document.body || document.documentElement;
    host.appendChild(hintEl); host.appendChild(panel); host.appendChild(btn);
    document.addEventListener("click", function (e) {
      var t = e.target;
      if (hintOpen && t && t.closest && (t.closest("#nav-paste") || t.closest("#nav-search"))) {
        hideHint();
      }
      if (!open) return;
      if (panel.contains(t) || t === btn) return;
      close();
    });
    document.addEventListener("keydown", function (e) {
      if (hintOpen && ((e.ctrlKey || e.metaKey) && String(e.key || "").toLowerCase() === "k")) {
        hideHint();
        return;
      }
      if (e.key === "Escape" || e.key === "Esc") {
        if (open) { close(); btn.focus(); return; }
        if (hintOpen) { dismissHint(true); btn.focus(); }
      }
    });
    if (root.addEventListener) root.addEventListener("hashchange", function () { syncHint(); });
    syncAll();
    syncHint();
  }
  function sectionTitle(t) { var h = document.createElement("div"); h.className = "obol-set-h"; h.textContent = t; return h; }
  function setSkin(id) {
    document.documentElement.setAttribute("data-skin", id);
    try { if (OBOL.store) OBOL.store.setPref("skin", id); } catch (e) {}
    if (OBOL.backdrop) OBOL.backdrop.update();
    syncSkins();
  }
  function syncSkins() { var cur = currentSkin(); skinBtns.forEach(function (b) { b.classList.toggle("active", b.dataset.skin === cur); }); }
  function syncMotion() { motionBtn.textContent = MOTION_LABEL[motionLevel()]; motionBtn.classList.toggle("active", motionLevel() !== "off"); }
  function syncCoins() { var on = coinsOn(); coinBtn.innerHTML = OBOL.ic("coin") + " Coin bursts: " + (on ? "on" : "off"); coinBtn.classList.toggle("active", on); }
  function syncAll() { syncSkins(); syncMotion(); syncCoins(); }
  function toggle() { open ? close() : openPanel(); }
  function openPanel() {
    if (hintOpen || hintShownOnLanding) dismissHint(true);
    open = true; panel.hidden = false; btn.setAttribute("aria-expanded", "true"); syncAll();
  }
  function close() { open = false; panel.hidden = true; btn.setAttribute("aria-expanded", "false"); }

  function init() { applySurfaceAlpha(surfaceAlpha()); build(); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
  OBOL.settings = {
    open: openPanel,
    close: close,
    motionLevel: motionLevel,
    setMotion: setMotionLevel,
    syncHint: syncHint,
    dismissHint: dismissHint,
    isLinuxClient: isLinuxClient
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
