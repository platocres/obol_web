/*!
 * obol ui - routes/help.js - the Help tab. The MAP of obol: what each surface is for, when to reach for
 * it, and obol's own vocabulary. Content lives in data/help-content.js (OBOL.HELP); this renders it.
 * Three sub-views (Index / Quick Start / Glossary), triage cards on the Index, a collapsible by-section
 * accordion with Go There deep links, a calm Charon quick-start, and an obol-vocabulary glossary.
 * Deep-linkable: #/help, #/help/<sectionId> (Index, that section open), #/help/start, #/help/glossary.
 * Presentation only: Help documents the app, it changes nothing.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }

  function gotoBtn(goto, label, set) {
    if (!goto) return '';
    return '<button type="button" class="help-go" data-goto="' + U.attr(goto) + '"'
      + (set ? ' data-set="' + U.attr(JSON.stringify(set)) + '"' : '') + '>' + esc(label) + ' &rsaquo;</button>';
  }

  function subRow(sub) {
    var kids = (sub.subs && sub.subs.length) ? '<div class="help-subs help-subs--deep">' + sub.subs.map(subRow).join('') + '</div>' : '';
    return '<div class="help-sub"><div class="help-sub-main">'
      + '<span class="help-sub-t">' + esc(sub.title) + '</span> '
      + '<span class="help-sub-what">' + esc(sub.what) + '</span>'
      + (sub.when ? '<div class="help-sub-when"><span class="help-lbl">When</span> ' + esc(sub.when) + '</div>' : '')
      + (sub.tip ? '<div class="help-sub-tip"><span class="help-lbl">Tip</span> ' + esc(sub.tip) + '</div>' : '')
      + '</div>'
      + gotoBtn(sub.goto || sub.href, 'Go', sub.set) + '</div>' + kids;
  }

  function sectionCard(s, open) {
    var subsHtml = '';
    if (s.groups) {
      subsHtml = s.groups.map(function (g) {
        return '<div class="help-grp"><div class="help-grp-h">' + esc(g.group) + '</div>' + (g.subs || []).map(subRow).join('') + '</div>';
      }).join('');
    } else if (s.subs) {
      subsHtml = s.subs.map(subRow).join('');
    }
    return '<details class="help-sec" id="help-' + U.attr(s.id) + '"' + (open ? ' open' : '') + '>'
      + '<summary class="help-sec-sum"><span class="help-sec-t">' + esc(s.title) + '</span>'
      + '<span class="help-sec-what">' + esc(s.what) + '</span></summary>'
      + '<div class="help-sec-body">'
      + (s.when ? '<p class="help-when"><span class="help-lbl">When</span> ' + esc(s.when) + '</p>' : '')
      + (s.tip ? '<p class="help-tip"><span class="help-lbl">Tip</span> ' + esc(s.tip) + '</p>' : '')
      + '<div class="help-goable">' + gotoBtn(s.goto || s.href, 'Go To ' + s.title) + '</div>'
      + (subsHtml ? '<div class="help-subs">' + subsHtml + '</div>' : '')
      + '</div></details>';
  }

  function renderIndex(H, focus) {
    var triage = '<div class="help-triage">' + (H.triage || []).map(function (t) {
      return '<button type="button" class="help-tri" data-goto="' + U.attr(t.goto || t.href) + '">'
        + '<span class="help-tri-t">' + esc(t.title) + '</span>'
        + '<span class="help-tri-b">' + esc(t.body) + '</span>'
        + '<span class="help-tri-cta">' + esc(t.cta) + ' &rsaquo;</span></button>';
    }).join('') + '</div>';
    var sections = (H.sections || []).map(function (s) { return sectionCard(s, s.id === focus); }).join('');
    return triage
      + '<h2 class="help-h2">Everything In OBOL, By Section</h2>'
      + '<p class="help-note">Open a section to see what it holds. Every row has a Go There.</p>'
      + '<div class="help-index">' + sections + '</div>';
  }

  function getQuickstartSteps() {
    try {
      var raw = localStorage.getItem('obol-quickstart-steps');
      return raw ? JSON.parse(raw) : {};
    } catch (e) {
      return {};
    }
  }

  function renderStart(H) {
    var stored = getQuickstartSteps();
    var steps = H.quickstart || [];
    var doneCount = 0;
    steps.forEach(function (q, i) {
      if (stored[i] || stored[q.id] || stored[q.title]) doneCount++;
    });
    var totalSteps = steps.length || 4;
    var pct = Math.round((doneCount / totalSteps) * 100);

    // the cyberpunk Charon illustration, floating in emanating ring-light (same ferryman as Stuck?)
    var intro = '<div class="help-charon">'
      + '<div class="charon-fig"><span class="charon-aura"></span><span class="charon-ring"></span><span class="charon-ring r2"></span>'
      + '<img class="charon-img" src="assets/img/charon.webp?v=2" width="216" height="216" loading="lazy" decoding="async" alt="Charon the ferryman, hooded with glowing red eyes in a skull boat on the green Styx"></div>'
      + '<p class="help-charon-say">' + esc(H.charonIntro || '') + '</p></div>';

    var progress = '<div class="help-qs-progress" role="region" aria-label="Quick Start Progress">'
      + '<div class="help-qs-progress-head">'
      + '<span class="help-qs-progress-txt">' + doneCount + ' of ' + totalSteps + ' Complete</span>'
      + '<span class="help-qs-progress-pct">' + pct + '%</span>'
      + '</div>'
      + '<div class="help-qs-progress-bar"><div class="help-qs-progress-fill" style="width:' + pct + '%;"></div></div>'
      + '</div>';

    var cards = steps.map(function (q, i) {
      var isDone = !!(stored[i] || stored[q.id] || stored[q.title]);
      return '<div class="help-qs' + (isDone ? ' is-done' : '') + '">'
        + '<div class="help-qs-check">'
        + '<label class="help-qs-step-lbl">'
        + '<input type="checkbox" class="help-qs-step-cb" data-step-idx="' + i + '" data-step-id="' + esc(q.id || '') + '"' + (isDone ? ' checked' : '') + '>'
        + '<span class="help-qs-step-title">' + (i + 1) + '. ' + esc(q.title) + '</span>'
        + '</label>'
        + '</div>'
        + '<div class="help-qs-b">'
        + (q.charon ? '<p class="help-qs-say">' + esc(q.charon) + '</p>' : '')
        + '<p class="help-qs-body">' + esc(q.body) + '</p>'
        + gotoBtn(q.goto || q.href, q.cta) + '</div></div>';
    }).join('');

    return intro + progress + '<div class="help-qs-grid">' + cards + '</div>';
  }

  function renderGlossary(H) {
    var terms = (H.glossary || []).slice().sort(function (a, b) { return a.term < b.term ? -1 : 1; }).map(function (g) {
      var see = (g.see && g.see.length) ? '<div class="help-term-see">See: ' + g.see.map(function (id) {
        return '<a href="#/help/' + U.attr(id) + '">' + esc(id) + '</a>';
      }).join(', ') + '</div>' : '';
      return '<div class="help-term"><div class="help-term-t">' + esc(g.term) + '</div>'
        + '<div class="help-term-d">' + esc(g.def) + '</div>' + see + '</div>';
    }).join('');
    return '<p class="help-note">The words OBOL uses. For pentest terms (SUID, Kerberoast, and the rest) see Learn and the field notes.</p>'
      + '<div class="help-glossary">' + terms + '</div>';
  }

  function renderManual(H) {
    var chapters = (H.manual || []).map(function (ch) {
      var itemsHtml = (ch.items || []).map(subRow).join('');
      return '<details class="help-sec" id="help-' + U.attr(ch.id) + '" open>'
        + '<summary class="help-sec-sum"><span class="help-sec-t">' + esc(ch.title) + '</span>'
        + '<span class="help-sec-what">' + esc(ch.summary || ch.what || '') + '</span></summary>'
        + '<div class="help-sec-body">'
        + '<div class="help-goable">' + gotoBtn(ch.goto || ch.href, ch.cta || ('Go To ' + ch.title)) + '</div>'
        + (itemsHtml ? '<div class="help-subs">' + itemsHtml + '</div>' : '')
        + '</div></details>';
    }).join('');
    return '<h2 class="help-h2">OBOL Operator Manual</h2>'
      + '<p class="help-note">Complete workflow guide for the Cockpit, Hero Operator Deck, epistemic path badges, sequence pastes, multi-target engagements, and standalone stations.</p>'
      + '<div class="help-index help-manual">' + chapters + '</div>';
  }

  var TABS = [['start', 'Quick Start', '#/help/start'], ['manual', 'Operator Manual', '#/help/manual'], ['index', 'Index', '#/help/index'], ['glossary', 'Glossary', '#/help/glossary']];
  function tabBar(active) {
    return '<div class="help-tabs" role="tablist">' + TABS.map(function (t) {
      return '<a class="help-tab' + (t[0] === active ? ' active' : '') + '" href="' + t[2] + '" role="tab" aria-selected="' + (t[0] === active) + '">' + esc(t[1]) + '</a>';
    }).join('') + '</div>';
  }

  function subOf(ctx) { return (ctx && ctx.args && ctx.args[0]) || ''; }

  function render(ctx) {
    var H = OBOL.HELP || {};
    var sub = subOf(ctx);
    // Quick Start leads: a bare #/help opens it. The Index tab is #/help/index; a section id
    // (#/help/engagements, from the "?" on-ramp) opens the Index focused on that section.
    var tab = sub === 'glossary' ? 'glossary' : sub === 'manual' ? 'manual' : (sub === '' || sub === 'start') ? 'start' : 'index';
    var focus = (tab === 'index' && sub && sub !== 'index') ? sub : '';
    var head = '<section class="help-route"><div class="help-head"><h1 class="route-h1">Help</h1>'
      + '<p class="route-sub">What each part of OBOL is for, and when to reach for it. This is the map. For how to pentest, see Learn and the field notes.</p></div>'
      + tabBar(tab)
      + '<div class="help-search-bar"><input type="search" id="help-search" class="help-search-input" placeholder="Search Help sections, tools, and glossary..." autocomplete="off" spellcheck="false" aria-label="Search Help"></div>'
      + '<div id="help-search-empty" class="coach-empty" hidden>No manual topics match your search.</div>';
    if (!H.sections) {
      return head + '<p class="route-sub">Help is coming online. If you just opened it, give the bundle a moment and try again.</p></section>';
    }
    var body = tab === 'start'
      ? (renderStart(H) + '<div class="help-cross-search" style="display:none">' + renderManual(H) + renderIndex(H, '') + renderGlossary(H) + '</div>')
      : tab === 'manual' ? renderManual(H) : tab === 'glossary' ? renderGlossary(H) : renderIndex(H, focus);
    return head + body + '</section>';
  }

  function mounted(ctx) {
    var mount = (ctx && ctx.mount) || document;
    // Go There (any element carrying data-goto, including the triage cards): optionally set UI state
    // (e.g. a Findings sub-view), then navigate.
    U.on(mount, 'click', '[data-goto]', function (e, b) {
      // Scope to Help: this handler is delegated on the shared #view, which outlives the route, so it
      // must ignore [data-goto] clicks owned by another route (e.g. Stuck?'s interview buttons carry
      // data-goto as a step name, not a Help route hash).
      if (OBOL.router.current().name !== 'help') return;
      var set = b.getAttribute('data-set');
      if (set) { try { var o = JSON.parse(set); OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; Object.keys(o).forEach(function (k) { eng.ui[k] = o[k]; }); }, 'ui'); } catch (x) {} }
      var go = b.getAttribute('data-goto'); if (go) location.hash = go;
    });

    // H4: Live search input filtering sections, subs, glossary terms, and quick-start cards
    U.on(mount, 'input', '#help-search, #help-q', function (e, inp) {
      var q = (inp.value || '').trim().toLowerCase();
      var crossSearch = mount.querySelector('.help-cross-search');
      if (crossSearch) crossSearch.style.display = q ? '' : 'none';
      var charonEl = mount.querySelector('.help-charon');
      if (charonEl) charonEl.style.display = q ? 'none' : '';
      var progEl = mount.querySelector('.help-qs-progress');
      if (progEl) progEl.style.display = q ? 'none' : '';
      setTimeout(function () {
        var emptyEl = mount.querySelector('#help-search-empty');
        if (emptyEl) {
          var anyHit = !q || Array.prototype.some.call(mount.querySelectorAll('.help-sec, .help-term, .help-qs'), function (el) {
            return el.style.display !== 'none' && (!el.closest('.help-cross-search') || (crossSearch && crossSearch.style.display !== 'none'));
          });
          emptyEl.hidden = anyHit;
        }
      }, 0);

      // Filter Index sections and sub-rows
      var secs = mount.querySelectorAll('.help-sec');
      Array.prototype.forEach.call(secs, function (sec) {
        if (!q) {
          sec.style.display = '';
          Array.prototype.forEach.call(sec.querySelectorAll('.help-sub'), function (sub) { sub.style.display = ''; });
          Array.prototype.forEach.call(sec.querySelectorAll('.help-grp'), function (grp) { grp.style.display = ''; });
          return;
        }
        var secSum = sec.querySelector('.help-sec-sum');
        var secSumText = secSum ? secSum.textContent.toLowerCase() : '';
        var secBody = sec.querySelector('.help-sec-body');
        var secBodyText = secBody ? secBody.textContent.toLowerCase() : '';
        var secMatches = secSumText.indexOf(q) >= 0 || secBodyText.indexOf(q) >= 0;
        var matchingSubs = 0;
        Array.prototype.forEach.call(sec.querySelectorAll('.help-sub'), function (sub) {
          var subText = sub.textContent.toLowerCase();
          var subMatches = subText.indexOf(q) >= 0;
          sub.style.display = subMatches ? '' : 'none';
          if (subMatches) matchingSubs++;
        });
        Array.prototype.forEach.call(sec.querySelectorAll('.help-grp'), function (grp) {
          var hasVisible = Array.prototype.some.call(grp.querySelectorAll('.help-sub'), function (s) { return s.style.display !== 'none'; });
          grp.style.display = hasVisible ? '' : 'none';
        });
        if (secMatches || matchingSubs > 0) {
          sec.style.display = '';
          sec.open = true;
          if (secMatches && matchingSubs === 0) {
            Array.prototype.forEach.call(sec.querySelectorAll('.help-sub'), function (sub) { sub.style.display = ''; });
            Array.prototype.forEach.call(sec.querySelectorAll('.help-grp'), function (grp) { grp.style.display = ''; });
          }
        } else {
          sec.style.display = 'none';
        }
      });

      // Filter Glossary terms
      var terms = mount.querySelectorAll('.help-term');
      Array.prototype.forEach.call(terms, function (term) {
        if (!q) {
          term.style.display = '';
          return;
        }
        var termText = term.textContent.toLowerCase();
        term.style.display = termText.indexOf(q) >= 0 ? '' : 'none';
      });

      // Filter Quick Start cards
      var qsCards = mount.querySelectorAll('.help-qs');
      Array.prototype.forEach.call(qsCards, function (card) {
        if (!q) {
          card.style.display = '';
          return;
        }
        var cardText = card.textContent.toLowerCase();
        card.style.display = cardText.indexOf(q) >= 0 ? '' : 'none';
        var emptyEl = mount.querySelector('#help-search-empty');
        if (emptyEl) {
          var anyHit = !q || Array.prototype.some.call(mount.querySelectorAll('.help-sec, .help-term, .help-qs'), function (el) {
            return el.style.display !== 'none' && (!el.closest('.help-cross-search') || (crossSearch && crossSearch.style.display !== 'none'));
          });
          emptyEl.hidden = anyHit;
        }
      });
    });

    // H5: Stepped Quick Start persistence and progress updating
    U.on(mount, 'change', '.help-qs-step-cb', function (e, cb) {
      var idx = cb.getAttribute('data-step-idx');
      var id = cb.getAttribute('data-step-id');
      var stored = getQuickstartSteps();
      if (cb.checked) {
        stored[idx] = true;
        if (id) stored[id] = true;
      } else {
        delete stored[idx];
        if (id) delete stored[id];
      }
      try {
        localStorage.setItem('obol-quickstart-steps', JSON.stringify(stored));
      } catch (err) {}
      var card = cb.closest('.help-qs');
      if (card) card.classList.toggle('is-done', cb.checked);

      var total = mount.querySelectorAll('.help-qs-step-cb').length || 4;
      var checkedCount = mount.querySelectorAll('.help-qs-step-cb:checked').length;
      var txtEl = mount.querySelector('.help-qs-progress-txt');
      if (txtEl) txtEl.textContent = checkedCount + ' of ' + total + ' Complete';
      var pctEl = mount.querySelector('.help-qs-progress-pct');
      var pct = Math.round((checkedCount / total) * 100);
      if (pctEl) pctEl.textContent = pct + '%';
      var fillEl = mount.querySelector('.help-qs-progress-fill');
      if (fillEl) fillEl.style.width = pct + '%';
    });

    // a deep link to a section opens it (the <details open> above) and scrolls it into view
    var s = subOf(ctx);
    var focus = (s && s !== 'start' && s !== 'manual' && s !== 'glossary' && s !== 'index') ? s : '';
    if (focus) {
      var el = mount.querySelector('#help-' + (window.CSS && CSS.escape ? CSS.escape(focus) : focus));
      if (el) { try { el.open = true; el.scrollIntoView({ block: 'start' }); } catch (x) {} }
    }
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.help = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
