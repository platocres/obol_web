/*!
 * obol ui — backdrop.js — the motion background (ported from obol-local's webapp/static/js/theme.js).
 * A single fixed, behind-everything <canvas> painted at ~30fps, chosen per skin:
 *   obol → particles · ghostwire → matrix · amber → crt · neon → synthwave · daylight → none.
 * Self-contained + presentation-only. Frame-capped, DPR-capped, and idle-paused: after 12s of no
 * input, on blur, or when the tab is hidden the loop stops dead (~0% CPU) — the next pointer/key/
 * scroll/focus revives it. Honours prefers-reduced-motion (static gradient) and a three-state
 * 'obol.motion' pref (full/reduced/off). Reads the live skin's --accent/--bg tokens so it recolours
 * with the skin. Exposes OBOL.backdrop.update() (call after a skin change). Loaded after boot so it
 * never touches the boot budget.
 */
(function (root) {
  "use strict";
  var OBOL = root.OBOL = root.OBOL || {};
  var LS_MOTION = "obol.motion";
  function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }

  // obol_web skin (data-skin) → animation name. Unlisted / daylight → none (static base).
  var SKIN_ANIM = { obol: "particles", htb: "particles", indigo: "particles", ghostwire: "matrix", amber: "crt", neon: "synthwave", daylight: null };
  function currentSkin() { try { return document.documentElement.getAttribute("data-skin") || "obol"; } catch (e) { return "obol"; } }
  function wantedAnim() { var a = SKIN_ANIM[currentSkin()]; return a === undefined ? "particles" : a; }

  var reduceMq = (root.matchMedia && root.matchMedia("(prefers-reduced-motion: reduce)")) || null;
  function osReduce() { return !!(reduceMq && reduceMq.matches); }
  function motionLevel() { var v = lsGet(LS_MOTION); return (v === "full" || v === "reduced" || v === "off") ? v : "full"; }
  function effectiveMotion() { var l = motionLevel(); return (osReduce() && l === "full") ? "reduced" : l; }
  function reduceMotion() { return effectiveMotion() === "reduced"; }

  var canvas = null, ctx = null, rafId = 0, animName = null;
  var lastFrame = 0, FRAME_MS = 1000 / 30, vw = 0, vh = 0, dpr = 1, mstate = null;
  var idlePaused = false, idleTimer = 0, IDLE_MS = 12000, resizeTimer = 0;

  function ensureCanvas() {
    if (canvas) return;
    canvas = document.createElement("canvas");
    canvas.id = "obolth-bg"; canvas.setAttribute("aria-hidden", "true");
    (document.body || document.documentElement).appendChild(canvas);
    ctx = canvas.getContext("2d");
    sizeCanvas();
    root.addEventListener("resize", onResize, { passive: true });
    document.addEventListener("visibilitychange", onVisibility);
    var wake = function () { markActive(); };
    document.addEventListener("pointermove", wake, { passive: true });
    document.addEventListener("pointerdown", wake, { passive: true });
    document.addEventListener("keydown", wake);
    document.addEventListener("wheel", wake, { passive: true });
    document.addEventListener("touchstart", wake, { passive: true });
    root.addEventListener("focus", wake);
    root.addEventListener("blur", pauseLoop);
    if (reduceMq) { var h = function () { update(); }; if (reduceMq.addEventListener) reduceMq.addEventListener("change", h); else if (reduceMq.addListener) reduceMq.addListener(h); }
  }
  function sizeCanvas() {
    if (!canvas) return;
    dpr = Math.min(root.devicePixelRatio || 1, 1.5);
    vw = root.innerWidth; vh = root.innerHeight;
    canvas.width = Math.max(1, Math.round(vw * dpr)); canvas.height = Math.max(1, Math.round(vh * dpr));
    if (ctx) ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  function onResize() { clearTimeout(resizeTimer); resizeTimer = setTimeout(function () { sizeCanvas(); if (animName) initAnim(animName); if (animName && reduceMotion()) drawStatic(animName); }, 150); }
  function onVisibility() { if (document.hidden) pauseLoop(); else if (animName && !reduceMotion()) markActive(); }
  function shouldAnimate() { return !!animName && !reduceMotion() && !document.hidden && hasFocus() && !idlePaused; }
  function hasFocus() { try { return document.hasFocus(); } catch (e) { return true; } }
  function pauseLoop() { if (rafId) { cancelAnimationFrame(rafId); rafId = 0; } }
  function setIdleFlag(on) { try { if (on) document.documentElement.setAttribute("data-idle", "1"); else document.documentElement.removeAttribute("data-idle"); } catch (e) {} }
  function markActive() {
    idlePaused = false; setIdleFlag(false); clearTimeout(idleTimer);
    idleTimer = setTimeout(function () { idlePaused = true; setIdleFlag(true); pauseLoop(); }, IDLE_MS);
    if (shouldAnimate()) startLoop();
  }
  function update() {
    try { document.documentElement.dataset.motion = effectiveMotion(); } catch (e) {}
    var w = wantedAnim();
    if (!w || effectiveMotion() === "off") { stopMotion(); return; }
    ensureCanvas(); canvas.style.display = "block";
    if (animName !== w) { animName = w; initAnim(w); }
    if (reduceMotion()) { pauseLoop(); drawStatic(w); }
    else if (!document.hidden) markActive();
  }
  function stopMotion() { animName = null; mstate = null; if (rafId) { cancelAnimationFrame(rafId); rafId = 0; } if (canvas) { if (ctx) ctx.clearRect(0, 0, vw, vh); canvas.style.display = "none"; } }
  function startLoop() { if (rafId || !shouldAnimate()) return; lastFrame = 0; rafId = requestAnimationFrame(loop); }
  function loop(ts) { if (!shouldAnimate()) { rafId = 0; return; } rafId = requestAnimationFrame(loop); if (ts - lastFrame < FRAME_MS) return; lastFrame = ts; drawFrame(animName); }

  function cssVar(name, fb) { try { var v = getComputedStyle(document.documentElement).getPropertyValue(name).trim(); return v || fb; } catch (e) { return fb; } }
  function hexA(hex, a) {
    hex = (hex || "").replace("#", "");
    if (hex.length === 3) hex = hex[0] + hex[0] + hex[1] + hex[1] + hex[2] + hex[2];
    var r = parseInt(hex.substr(0, 2), 16) || 120, g = parseInt(hex.substr(2, 2), 16) || 130, b = parseInt(hex.substr(4, 2), 16) || 240;
    return "rgba(" + r + "," + g + "," + b + "," + a.toFixed(3) + ")";
  }

  function initAnim(name) {
    if (name === "matrix") {
      var fs = 15, cols = Math.max(1, Math.ceil(vw / fs)), drops = new Array(cols);
      for (var i = 0; i < cols; i++) drops[i] = Math.random() * -40;
      mstate = { fontSize: fs, cols: cols, drops: drops, accent: cssVar("--accent", "#00ff66") };
    } else if (name === "particles") {
      var n = Math.max(28, Math.min(70, Math.round(vw * vh / 26000))), nodes = [];
      for (var p = 0; p < n; p++) nodes.push({ x: Math.random() * vw, y: Math.random() * vh, vx: (Math.random() - 0.5) * 0.28, vy: (Math.random() - 0.5) * 0.28, r: 0.8 + Math.random() * 1.7 });
      mstate = { nodes: nodes, accent: cssVar("--accent", "#6366F1"), accent2: cssVar("--accent-2", "#818CF8") };
    } else if (name === "synthwave") {
      // palms lining the road: evenly-phased on both sides so several are always in frame,
      // marching toward the viewer in tandem with the grid.
      var palms = [], PER = 7;
      for (var pi = 0; pi < PER; pi++) {
        palms.push({ ph: pi / PER, side: -1 });
        palms.push({ ph: (pi / PER) + (0.5 / PER), side: 1 });
      }
      mstate = { t: 0, palms: palms };
    } else { mstate = { t: 0 }; }
  }
  function drawFrame(name) {
    if (name === "matrix") drawMatrix();
    else if (name === "particles") drawParticles();
    else if (name === "crt") drawCrt();
    else if (name === "synthwave") drawSynthwave();
  }

  var GLYPHS = "アイウエオカキクケコサシスセソ0123456789ABCDEFﾊﾋﾌﾍﾎ$#%<>*+";
  function drawMatrix() {
    var s = mstate; if (!s) return;
    ctx.fillStyle = "rgba(0, 5, 0, 0.16)"; ctx.fillRect(0, 0, vw, vh);
    ctx.font = s.fontSize + "px ui-monospace, monospace"; ctx.textBaseline = "top";
    for (var i = 0; i < s.cols; i++) {
      var x = i * s.fontSize, y = s.drops[i] * s.fontSize;
      ctx.fillStyle = "#CFFFD6"; ctx.fillText(GLYPHS.charAt((Math.random() * GLYPHS.length) | 0), x, y);
      ctx.fillStyle = s.accent || "#00FF41"; ctx.fillText(GLYPHS.charAt((Math.random() * GLYPHS.length) | 0), x, y - s.fontSize);
      if (y > vh && Math.random() > 0.975) s.drops[i] = Math.random() * -20;
      s.drops[i] += 0.5;
    }
  }
  function drawParticles() {
    var s = mstate; if (!s) return;
    ctx.clearRect(0, 0, vw, vh);
    var nodes = s.nodes, LINK = 132;
    for (var i = 0; i < nodes.length; i++) {
      var a = nodes[i]; a.x += a.vx; a.y += a.vy;
      if (a.x < 0 || a.x > vw) a.vx *= -1; if (a.y < 0 || a.y > vh) a.vy *= -1;
      for (var j = i + 1; j < nodes.length; j++) {
        var b = nodes[j], dx = a.x - b.x, dy = a.y - b.y, d = Math.sqrt(dx * dx + dy * dy);
        if (d < LINK) { ctx.strokeStyle = hexA(s.accent, 0.12 * (1 - d / LINK)); ctx.lineWidth = 1; ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke(); }
      }
    }
    for (var k = 0; k < nodes.length; k++) { var nn = nodes[k]; ctx.beginPath(); ctx.fillStyle = hexA(s.accent2, 0.85); ctx.shadowColor = s.accent2; ctx.shadowBlur = 8; ctx.arc(nn.x, nn.y, nn.r, 0, Math.PI * 2); ctx.fill(); }
    ctx.shadowBlur = 0;
  }
  function drawCrt() {
    var s = mstate; if (!s) return; s.t += 1;
    ctx.fillStyle = "#100A00"; ctx.fillRect(0, 0, vw, vh);
    var vg = ctx.createRadialGradient(vw / 2, vh / 2, vh * 0.1, vw / 2, vh / 2, vh * 0.8);
    vg.addColorStop(0, "rgba(255,176,0,0.05)"); vg.addColorStop(1, "rgba(255,176,0,0)"); ctx.fillStyle = vg; ctx.fillRect(0, 0, vw, vh);
    ctx.fillStyle = "rgba(255,176,0,0.045)"; for (var y = 0; y < vh; y += 3) ctx.fillRect(0, y, vw, 1);
    var by = (s.t * 1.4) % (vh + 120) - 60;
    var band = ctx.createLinearGradient(0, by - 60, 0, by + 60);
    band.addColorStop(0, "rgba(255,201,71,0)"); band.addColorStop(0.5, "rgba(255,201,71,0.07)"); band.addColorStop(1, "rgba(255,201,71,0)");
    ctx.fillStyle = band; ctx.fillRect(0, by - 60, vw, 120);
    if (Math.random() > 0.9) { ctx.fillStyle = "rgba(255,176,0,0.02)"; ctx.fillRect(0, 0, vw, vh); }
  }
  var TAU = Math.PI * 2;
  function roundRectPath(x, y, w, h, r) {
    r = Math.min(r, w / 2, h / 2); ctx.beginPath();
    ctx.moveTo(x + r, y); ctx.arcTo(x + w, y, x + w, y + h, r); ctx.arcTo(x + w, y + h, x, y + h, r);
    ctx.arcTo(x, y + h, x, y, r); ctx.arcTo(x, y, x + w, y, r); ctx.closePath();
  }
  // The iconic retro sun: warm→hot vertical gradient disk with horizontal scan-gaps near the
  // waterline, wrapped in a soft magenta halo. Sits centered on the horizon.
  function drawRetroSun(cx, horizon, R) {
    var halo = ctx.createRadialGradient(cx, horizon, R * 0.25, cx, horizon, R * 2.3);
    halo.addColorStop(0, "rgba(255,120,180,0.34)"); halo.addColorStop(0.5, "rgba(255,90,150,0.12)"); halo.addColorStop(1, "rgba(255,90,150,0)");
    ctx.fillStyle = halo; ctx.fillRect(cx - R * 2.3, horizon - R * 2.3, R * 4.6, R * 2.3);
    ctx.save();
    ctx.beginPath(); ctx.arc(cx, horizon, R, 0, TAU); ctx.clip();
    var sg = ctx.createLinearGradient(0, horizon - R, 0, horizon + R);
    sg.addColorStop(0, "#FFE24B"); sg.addColorStop(0.4, "#FF9A3D"); sg.addColorStop(0.7, "#FF4D8D"); sg.addColorStop(1, "#C724B1");
    ctx.fillStyle = sg; ctx.fillRect(cx - R, horizon - R, R * 2, R * 2);
    ctx.fillStyle = "#2f0b48"; // scan-gaps read as the sky showing through the sun
    for (var gi = 0; gi < 7; gi++) { var gy = horizon - R * 0.05 + gi * (R * 0.135); ctx.fillRect(cx - R, gy, R * 2, 2 + gi * 1.5); }
    ctx.restore();
  }
  // A stylized neon palm: curved trunk + a crown of drooping fronds, drawn as glowing strokes.
  function drawPalm(x, baseY, h, col, alpha) {
    if (h < 5) return;
    ctx.save(); ctx.globalAlpha = alpha; ctx.strokeStyle = col; ctx.lineCap = "round";
    ctx.shadowColor = col; ctx.shadowBlur = Math.min(13, h * 0.07); ctx.lineWidth = Math.max(1, h * 0.03);
    var topX = x + h * 0.07, topY = baseY - h;
    ctx.beginPath(); ctx.moveTo(x, baseY); ctx.quadraticCurveTo(x + h * 0.02, baseY - h * 0.5, topX, topY); ctx.stroke();
    var F = 7;
    for (var i = 0; i < F; i++) {
      var ang = -Math.PI * 0.96 + (i / (F - 1)) * (Math.PI * 0.92);
      var len = h * 0.52;
      var cxp = topX + Math.cos(ang) * len * 0.6, cyp = topY + Math.sin(ang) * len * 0.6 - h * 0.04;
      var exp = topX + Math.cos(ang) * len, eyp = topY + Math.sin(ang) * len * 0.85 + h * 0.14;
      ctx.beginPath(); ctx.moveTo(topX, topY); ctx.quadraticCurveTo(cxp, cyp, exp, eyp); ctx.stroke();
    }
    ctx.restore();
  }
  // A boxy 1980s car seen from behind, cruising toward the sun: dark silhouette with a neon rim,
  // cyan rear glass, and the era-defining full-width red tail-light bar. Bobs gently.
  function drawCar(cx, y, w, t) {
    var h = w * 0.46, bob = Math.sin(t * 0.07) * Math.max(0.6, h * 0.03); y += bob;
    ctx.save();
    var ug = ctx.createRadialGradient(cx, y + h * 0.12, 2, cx, y + h * 0.12, w * 0.85);
    ug.addColorStop(0, "rgba(255,47,120,0.45)"); ug.addColorStop(1, "rgba(255,47,120,0)");
    ctx.fillStyle = ug; ctx.fillRect(cx - w, y - h * 0.3, w * 2, h * 1.1);
    var cw = w * 0.66;
    ctx.fillStyle = "#0b0714"; roundRectPath(cx - w / 2, y - h * 0.55, w, h * 0.55, 3); ctx.fill();
    ctx.fillStyle = "#0d0918"; roundRectPath(cx - cw / 2, y - h * 1.02, cw, h * 0.5, 3); ctx.fill();
    ctx.shadowColor = "#ff2fb9"; ctx.shadowBlur = 10; ctx.strokeStyle = "rgba(255,47,185,0.9)"; ctx.lineWidth = Math.max(1, w * 0.012);
    roundRectPath(cx - w / 2, y - h * 0.55, w, h * 0.55, 3); ctx.stroke();
    roundRectPath(cx - cw / 2, y - h * 1.02, cw, h * 0.5, 3); ctx.stroke();
    ctx.shadowBlur = 0; ctx.fillStyle = "rgba(33,230,255,0.16)"; roundRectPath(cx - cw / 2 + w * 0.06, y - h * 0.96, cw - w * 0.12, h * 0.34, 2); ctx.fill();
    ctx.shadowColor = "#ff2b5e"; ctx.shadowBlur = 14; ctx.fillStyle = "#ff2b5e"; ctx.fillRect(cx - w * 0.44, y - h * 0.34, w * 0.88, Math.max(2, h * 0.09));
    ctx.shadowBlur = 0; ctx.fillStyle = "#0b0714"; ctx.fillRect(cx - w * 0.03, y - h * 0.35, w * 0.06, h * 0.11);
    ctx.restore();
  }
  // The whole scene, shared by the live loop (t advances) and the reduced-motion still (t fixed).
  function synthScene(t, palms) {
    var horizon = Math.round(vh * 0.56), cx = vw / 2;
    var sky = ctx.createLinearGradient(0, 0, 0, horizon); sky.addColorStop(0, "#0B0620"); sky.addColorStop(1, "#3A0E5A");
    ctx.fillStyle = sky; ctx.fillRect(0, 0, vw, horizon);
    for (var st = 0; st < 60; st++) { var sx = (st * 137.5 + t * 0.15) % vw, sy = (st * 61.7) % horizon; ctx.fillStyle = "rgba(255,255,255," + (0.2 + (st % 5) * 0.12).toFixed(2) + ")"; ctx.fillRect(sx, sy, 1.4, 1.4); }
    drawRetroSun(cx, horizon, Math.min(vw, vh) * 0.17);
    ctx.fillStyle = "#0C0722"; ctx.fillRect(0, horizon, vw, vh - horizon); // ground (covers sun's lower half → clean waterline)
    ctx.shadowColor = "#F92AAD"; ctx.shadowBlur = 18; ctx.strokeStyle = "#F92AAD"; ctx.lineWidth = 2;
    ctx.beginPath(); ctx.moveTo(0, horizon); ctx.lineTo(vw, horizon); ctx.stroke(); ctx.shadowBlur = 0;
    var spacing = 42, off = (t * 1.1) % spacing; ctx.lineWidth = 1.4;
    for (var yy = horizon + off; yy < vh; yy += spacing) { var a = (yy - horizon) / (vh - horizon); ctx.strokeStyle = "rgba(36,224,255," + (0.10 + a * 0.42).toFixed(3) + ")"; ctx.beginPath(); ctx.moveTo(0, yy); ctx.lineTo(vw, yy); ctx.stroke(); }
    ctx.strokeStyle = "rgba(249,42,173,0.42)";
    for (var vx = -vw; vx <= vw * 2; vx += spacing) { ctx.beginPath(); ctx.moveTo(cx + (vx - cx) * 0.18, horizon); ctx.lineTo(vx, vh); ctx.stroke(); }
    // the car sits on the near road, small, heading for the sun
    drawCar(cx, horizon + (vh - horizon) * 0.16, Math.max(58, Math.min(140, vw * 0.07)), t);
    // palms lining the road — build, sort far→near, draw so nearer palms overlap farther ones
    var list = [];
    (palms || []).forEach(function (pm) {
      var t01 = ((t * 0.0026) + pm.ph) % 1, depth = t01 * t01;
      var y = horizon + depth * (vh - horizon);
      var x = cx + pm.side * (0.02 + depth * 0.62) * vw;
      var h = (0.03 + depth * 0.92) * (vh * 0.5);
      var alpha = Math.min(1, 0.12 + depth * 1.1);
      list.push({ x: x, y: y, h: h, alpha: alpha, depth: depth, col: pm.side < 0 ? "#21e6ff" : "#ff2fb9" });
    });
    list.sort(function (p, q) { return p.depth - q.depth; });
    list.forEach(function (p) { drawPalm(p.x, p.y, p.h, p.col, p.alpha); });
  }
  function drawSynthwave() {
    var s = mstate; if (!s) return; s.t += 1;
    synthScene(s.t, s.palms);
  }
  function drawStatic(name) {
    if (!ctx) return; ctx.clearRect(0, 0, vw, vh); var g;
    if (name === "matrix") { g = ctx.createLinearGradient(0, 0, 0, vh); g.addColorStop(0, "#001a08"); g.addColorStop(1, "#000500"); }
    else if (name === "crt") { g = ctx.createRadialGradient(vw / 2, vh / 2, vh * 0.1, vw / 2, vh / 2, vh * 0.9); g.addColorStop(0, "#1a1000"); g.addColorStop(1, "#100A00"); }
    else if (name === "synthwave") {
      // reduced-motion: a full, still frame of the sunset scene (no animation) rather than a bare gradient.
      var palms = [], PER = 7;
      for (var pi = 0; pi < PER; pi++) { palms.push({ ph: pi / PER, side: -1 }); palms.push({ ph: (pi / PER) + 0.5 / PER, side: 1 }); }
      synthScene(0, palms); return;
    }
    else { g = ctx.createRadialGradient(vw / 2, vh * 0.3, 0, vw / 2, vh * 0.3, Math.max(vw, vh) * 0.8); g.addColorStop(0, cssVar("--accent-soft", "rgba(99,102,241,0.12)")); g.addColorStop(1, cssVar("--bg", "#0A0E18")); }
    ctx.fillStyle = g; ctx.fillRect(0, 0, vw, vh);
  }

  OBOL.backdrop = { update: update, motionLevel: motionLevel };
  function init() { update(); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
})(typeof globalThis !== 'undefined' ? globalThis : this);
