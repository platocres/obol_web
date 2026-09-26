/*!
 * obol ui — settings.js — the bottom-right ⚙ appearance control.
 * A single floating button + popover for the things worth letting anyone customise: skin, motion
 * (full/reduced/off), coin bursts, and block opacity (fade the surfaces so the motion background
 * shows through). Presentation-only. Skin persists via OBOL.store prefs (pre-painted in <head>);
 * motion/opacity/coins persist to their own tiny localStorage keys that backdrop.js + coin.js read.
 */
(function (root) {
  "use strict";
  var OBOL = root.OBOL = root.OBOL || {};
  var LS_MOTION = "obol.motion", LS_OPACITY = "obol.surface-alpha";
  function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }

  var SKINS = [
    { id: "obol", label: "Obol" }, { id: "ghostwire", label: "Ghostwire" }, { id: "amber", label: "Amber" },
    { id: "neon", label: "Neon" }, { id: "daylight", label: "Daylight" }
  ];
  var MOTION = ["full", "reduced", "off"];
  var MOTION_LABEL = { full: "◉ Motion: full", reduced: "◐ Motion: reduced", off: "○ Motion: off" };

  function currentSkin() {
    try { return document.documentElement.getAttribute("data-skin") || (OBOL.store && OBOL.store.pref().skin) || "obol"; } catch (e) { return "obol"; }
  }
  function motionLevel() { var v = lsGet(LS_MOTION); return (v === "full" || v === "reduced" || v === "off") ? v : "full"; }
  function surfaceAlpha() { var v = parseFloat(lsGet(LS_OPACITY)); return (v >= 0 && v <= 1) ? v : 1; }
  function applySurfaceAlpha(v) { try { document.documentElement.style.setProperty("--surface-alpha", String(v)); } catch (e) {} }
  function coinsOn() { return !OBOL.coins || OBOL.coins.enabled(); }

  var panel = null, btn = null, open = false, skinBtns = [], motionBtn = null, coinBtn = null;

  function build() {
    btn = document.createElement("button");
    btn.id = "obol-settings-toggle"; btn.type = "button"; btn.className = "obol-settings-toggle";
    btn.setAttribute("aria-label", "Appearance settings"); btn.setAttribute("aria-expanded", "false");
    btn.title = "Appearance"; btn.textContent = "⚙";
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
      lsSet(LS_MOTION, next); if (OBOL.backdrop) OBOL.backdrop.update(); syncMotion();
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

    var host = document.body || document.documentElement;
    host.appendChild(panel); host.appendChild(btn);
    document.addEventListener("click", function (e) { if (!open) return; if (panel.contains(e.target) || e.target === btn) return; close(); });
    document.addEventListener("keydown", function (e) { if (open && (e.key === "Escape" || e.key === "Esc")) { close(); btn.focus(); } });
    syncAll();
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
  function syncCoins() { var on = coinsOn(); coinBtn.textContent = "🪙 Coin bursts: " + (on ? "on" : "off"); coinBtn.classList.toggle("active", on); }
  function syncAll() { syncSkins(); syncMotion(); syncCoins(); }
  function toggle() { open ? close() : openPanel(); }
  function openPanel() { open = true; panel.hidden = false; btn.setAttribute("aria-expanded", "true"); syncAll(); }
  function close() { open = false; panel.hidden = true; btn.setAttribute("aria-expanded", "false"); }

  function init() { applySurfaceAlpha(surfaceAlpha()); build(); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
  OBOL.settings = { open: openPanel };
})(typeof globalThis !== 'undefined' ? globalThis : this);
