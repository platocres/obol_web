/*!
 * obol ui — coin.js — the coin-burst effect (ported from obol-local's webapp/static/js/coin.js).
 * An *obol* is the coin paid to Charon — obol's namesake — so when you beat the box (a foothold,
 * privilege escalation, a captured flag) gold coins burst across the screen. Self-contained,
 * presentation-only: it shares no app state, draws on its own fixed pointer-events:none <canvas>
 * above the page, honours prefers-reduced-motion, pauses when the tab is hidden, and can be turned
 * off. It celebrates only GENUINE PROOF — bursts fire on the same proof-bound fact kinds the coach
 * reads, minted by the conservative parsers, never on noise. Exposes window.obolCoins + OBOL.coins;
 * store.js calls burstForFactKinds() with the kinds of facts just added.
 */
(function (root) {
  "use strict";
  var OBOL = root.OBOL = root.OBOL || {};

  var LS_COINS = "obol.coins", LS_MOTION = "obol.motion";
  function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }

  var reduceMq = (root.matchMedia && root.matchMedia("(prefers-reduced-motion: reduce)")) || null;
  function reduceMotion() { return !!(reduceMq && reduceMq.matches); }
  function motionLevel() { var v = lsGet(LS_MOTION); return (v === "reduced" || v === "off") ? v : "full"; }
  function fullMotion() { return motionLevel() === "full" && !reduceMotion(); }

  // ── the honest milestone table (every key is a proof fact obol_web can mint) ──
  var MILESTONES = {
    "foothold.windows": { tier: "foothold", label: "foothold", coins: 6 },
    "foothold.linux": { tier: "foothold", label: "foothold", coins: 6 },
    "foothold.webshell": { tier: "foothold", label: "web foothold", coins: 6 },
    "access.shell": { tier: "foothold", label: "shell", coins: 6 },
    "winrm.authenticated": { tier: "foothold", label: "WinRM foothold", coins: 5 },
    "credential.available": { tier: "cred", label: "validated credential", coins: 3 },
    "access.admin": { tier: "pwned", label: "admin", coins: 10 },
    "access.root": { tier: "pwned", label: "root", coins: 12 },
    "access.system": { tier: "pwned", label: "SYSTEM", coins: 12 },
    "loot.ntds": { tier: "loot", label: "domain secrets", coins: 12 },
    "objective.local_flag": { tier: "flag", label: "local flag", coins: 8 },
    "objective.user_flag": { tier: "flag", label: "user flag", coins: 8 },
    "objective.flag": { tier: "flag", label: "flag", coins: 8 },
    "objective.root_flag": { tier: "jackpot", label: "ROOT flag", coins: 16 },
    "objective.proof_flag": { tier: "jackpot", label: "proof flag", coins: 16 }
  };
  var TIER_RANK = { cred: 1, foothold: 2, loot: 3, flag: 4, pwned: 5, jackpot: 6 };
  var LOOT_KINDS = ["credential.candidate", "loot.material", "loot"];
  function isLoot(kind) {
    var head = String(kind || "").split("(")[0].trim();
    for (var i = 0; i < LOOT_KINDS.length; i++)
      if (head === LOOT_KINDS[i] || head.indexOf(LOOT_KINDS[i] + ".") === 0) return true;
    return false;
  }
  function milestoneFor(kind) {
    if (!kind) return null;
    if (MILESTONES[kind]) return MILESTONES[kind];
    var head = String(kind).split("(")[0].trim();
    if (MILESTONES[head]) return MILESTONES[head];
    for (var key in MILESTONES) if (MILESTONES.hasOwnProperty(key) && head.indexOf(key + ".") === 0) return MILESTONES[key];
    return null;
  }
  function bestMilestone(kinds) {
    var best = null;
    (kinds || []).forEach(function (k) { var m = milestoneFor(k); if (m && (!best || TIER_RANK[m.tier] > TIER_RANK[best.tier])) best = m; });
    return best;
  }
  function enabled() { var v = lsGet(LS_COINS); return v !== "0" && v !== "off" && v !== "false"; }

  // ── canvas overlay ──
  var canvas = null, ctx = null, rafId = 0, particles = [], vw = 0, vh = 0, dpr = 1;
  function ensureCanvas() {
    if (canvas) return;
    canvas = document.createElement("canvas");
    canvas.id = "obolcoin-fx"; canvas.setAttribute("aria-hidden", "true");
    canvas.style.cssText = "position:fixed;left:0;top:0;width:100vw;height:100vh;pointer-events:none;z-index:9999;";
    (document.body || document.documentElement).appendChild(canvas);
    ctx = canvas.getContext("2d"); size();
    root.addEventListener("resize", size, { passive: true });
    document.addEventListener("visibilitychange", function () { if (document.hidden && rafId) { cancelAnimationFrame(rafId); rafId = 0; } });
  }
  function size() {
    if (!canvas) return;
    dpr = Math.min(root.devicePixelRatio || 1, 2);
    vw = root.innerWidth; vh = root.innerHeight;
    canvas.width = Math.round(vw * dpr); canvas.height = Math.round(vh * dpr);
    if (ctx) ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  function spawn(m) {
    ensureCanvas();
    var n = Math.min(28, m.coins * (m.tier === "jackpot" ? 2 : 1));
    var ox = vw / 2, oy = vh * 0.34, big = m.tier === "jackpot" || m.tier === "pwned";
    for (var i = 0; i < n; i++) {
      var ang = (-Math.PI / 2) + (Math.random() - 0.5) * (big ? 2.4 : 1.7), sp = 4 + Math.random() * (big ? 9 : 6);
      particles.push({ kind: "coin", x: ox, y: oy, vx: Math.cos(ang) * sp, vy: Math.sin(ang) * sp - 3,
        r: (big ? 11 : 9) + Math.random() * 4, spin: Math.random() * Math.PI, dspin: 0.2 + Math.random() * 0.25, life: 1, decay: 0.008 + Math.random() * 0.006 });
    }
    for (var s = 0; s < n; s++) {
      particles.push({ kind: "spark", x: ox + (Math.random() - 0.5) * 60, y: oy + (Math.random() - 0.5) * 40,
        vx: (Math.random() - 0.5) * 6, vy: (Math.random() - 0.5) * 6 - 2, r: 1 + Math.random() * 2, life: 1, decay: 0.02 + Math.random() * 0.02 });
    }
    showBanner(m); if (!rafId) rafId = requestAnimationFrame(loop);
  }
  var GRAV = 0.28, DRAG = 0.99;
  function loop() {
    rafId = 0; if (document.hidden) return;
    ctx.clearRect(0, 0, vw, vh);
    var alive = [];
    for (var i = 0; i < particles.length; i++) {
      var p = particles[i];
      p.vy += GRAV; p.vx *= DRAG; p.x += p.vx; p.y += p.vy; p.life -= p.decay;
      if (p.spin !== undefined) p.spin += p.dspin;
      if (p.life > 0 && p.y < vh + 40) { draw(p); alive.push(p); }
    }
    particles = alive;
    if (particles.length) rafId = requestAnimationFrame(loop); else ctx.clearRect(0, 0, vw, vh);
  }
  function draw(p) {
    ctx.globalAlpha = Math.max(0, Math.min(1, p.life));
    if (p.kind === "spark") { ctx.fillStyle = "#FFF6C8"; ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2); ctx.fill(); ctx.globalAlpha = 1; return; }
    var sx = Math.max(0.12, Math.abs(Math.cos(p.spin)));
    ctx.save(); ctx.translate(p.x, p.y); ctx.scale(sx, 1);
    var g = ctx.createRadialGradient(-p.r * 0.3, -p.r * 0.3, p.r * 0.2, 0, 0, p.r);
    g.addColorStop(0, "#FFF1A8"); g.addColorStop(0.5, "#FFD34D"); g.addColorStop(1, "#E6A21C");
    ctx.fillStyle = g; ctx.beginPath(); ctx.arc(0, 0, p.r, 0, Math.PI * 2); ctx.fill();
    ctx.lineWidth = Math.max(1, p.r * 0.18); ctx.strokeStyle = "#B9770E"; ctx.stroke();
    ctx.fillStyle = "#B9770E"; ctx.globalAlpha *= 0.85;
    var d = p.r * 0.42;
    ctx.beginPath(); ctx.moveTo(0, -d); ctx.lineTo(d, 0); ctx.lineTo(0, d); ctx.lineTo(-d, 0); ctx.closePath(); ctx.fill();
    ctx.restore(); ctx.globalAlpha = 1;
  }
  var bannerEl = null, bannerTimer = 0;
  function showBanner(m, loot) {
    if (!bannerEl) {
      bannerEl = document.createElement("div"); bannerEl.id = "obolcoin-banner"; bannerEl.setAttribute("aria-live", "polite");
      bannerEl.style.cssText = "position:fixed;left:50%;top:26%;transform:translate(-50%,-50%);z-index:10000;pointer-events:none;" +
        "font:700 20px ui-monospace,monospace;letter-spacing:.04em;color:#FFD34D;text-shadow:0 2px 10px rgba(0,0,0,.6),0 0 18px rgba(255,211,77,.5);opacity:0;transition:opacity .18s ease;white-space:nowrap;";
      (document.body || document.documentElement).appendChild(bannerEl);
    }
    bannerEl.textContent = loot ? ("✨ loot found — " + m.label) : ("◉ PWNED — " + m.label);
    bannerEl.style.color = loot ? "#FFE9A8" : "#FFD34D"; bannerEl.style.opacity = "1";
    clearTimeout(bannerTimer); bannerTimer = setTimeout(function () { if (bannerEl) bannerEl.style.opacity = "0"; }, 1400);
  }
  function sparkleBurst(label) {
    ensureCanvas();
    var ox = vw / 2, oy = vh * 0.34;
    for (var s = 0; s < 26; s++) particles.push({ kind: "spark", x: ox + (Math.random() - 0.5) * 120, y: oy + (Math.random() - 0.5) * 70,
      vx: (Math.random() - 0.5) * 5, vy: (Math.random() - 0.5) * 5 - 1.5, r: 1 + Math.random() * 2.4, life: 1, decay: 0.014 + Math.random() * 0.014 });
    showBanner({ label: label || "loot found", tier: "loot" }, true);
    if (!rafId) rafId = requestAnimationFrame(loop);
  }

  // ── "Level Up!" — the privilege-escalation flourish ──
  var ESCALATION = { "access.admin": "admin", "access.root": "root", "access.system": "SYSTEM" };
  function escalationWin(kinds) {
    for (var i = 0; i < (kinds || []).length; i++) { var head = String(kinds[i]).split("(")[0].trim(); if (ESCALATION[head]) return ESCALATION[head]; }
    return "";
  }
  var levelEl = null, levelTimer = 0;
  function levelUp(label) {
    if (!levelEl) {
      levelEl = document.createElement("div"); levelEl.id = "obolcoin-levelup"; levelEl.setAttribute("aria-live", "polite");
      levelEl.style.cssText = "position:fixed;left:50%;top:40%;transform:translate(-50%,-50%) scale(.6);z-index:10001;pointer-events:none;" +
        "font:800 44px ui-monospace,monospace;letter-spacing:.06em;text-align:center;opacity:0;transition:opacity .16s ease,transform .28s cubic-bezier(.2,1.4,.4,1);text-shadow:0 2px 18px rgba(0,0,0,.7);white-space:nowrap;";
      (document.body || document.documentElement).appendChild(levelEl);
    }
    levelEl.innerHTML = '<div style="color:#FFD34D">★ LEVEL UP! ★</div><div style="font-size:20px;margin-top:6px;color:#7CF6C8">privilege escalation — ' + (label || "") + '</div>';
    void levelEl.offsetWidth; levelEl.style.opacity = "1"; levelEl.style.transform = "translate(-50%,-50%) scale(1)";
    spawn({ tier: "jackpot", label: "LEVEL UP", coins: 18 });
    setTimeout(function () { spawn({ tier: "jackpot", label: "LEVEL UP", coins: 14 }); }, 180);
    clearTimeout(levelTimer);
    levelTimer = setTimeout(function () { if (!levelEl) return; levelEl.style.opacity = "0"; levelEl.style.transform = "translate(-50%,-50%) scale(1.25)"; }, 1700);
  }

  // ── public API ──
  function burst(tierOrKind, label) {
    if (!enabled() || reduceMotion()) return;
    var m = (tierOrKind && tierOrKind.tier) ? tierOrKind : (milestoneFor(tierOrKind) || { tier: tierOrKind || "foothold", label: label || "pwned", coins: 8 });
    spawn(m);
  }
  // store.js calls this with the kinds of facts just minted (an evidence paste / BH ingest).
  function burstForFactKinds(kinds) {
    if (!enabled() || reduceMotion() || !kinds || !kinds.length) return;
    var lvl = escalationWin(kinds);
    if (lvl && fullMotion()) levelUp(lvl);
    var m = bestMilestone(kinds);
    if (m) { spawn(m); return; }
    if (kinds.some(isLoot)) sparkleBurst("loot found");
  }

  var api = {
    burst: burst, burstForFactKinds: burstForFactKinds, levelUp: levelUp,
    enabled: enabled, setEnabled: function (on) { lsSet(LS_COINS, on ? "1" : "0"); }, milestoneFor: milestoneFor
  };
  root.obolCoins = api; OBOL.coins = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
