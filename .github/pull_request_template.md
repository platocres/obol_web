## Summary

-
-
-

## Live cards / surfaces

Required for any user-visible product change. Link the exact surface a maintainer should inspect after deploy.

- Live route(s):
- Direct card/tool/path/report route(s):
- Dashboard surface, if applicable:

## Product Build Next item(s)

- Item ID(s):
- Status change(s):
- Acceptance criteria satisfied:

## Changelog / release notes

Required for every product-visible or product-governance change. Do not leave release history stale.

- CHANGELOG.md updated:
- Release doc added or updated, if versioned:
- Current release / generated sync status, if applicable:

## Evidence ingestion / Next Steps movement

Required for any command, tool card, proof control, analyzer, or path item that expects pasted terminal output, browser-observation text, or proof notes.

- Pasted Evidence source(s):
- Activity card ID(s) emitted:
- Outcome fact(s) emitted:
- Next Steps movement expected:
- Redaction / conservative-proof boundary:

## Live Integration Done Gate

Product Build Next work is not complete while its output is only a disconnected artifact, fixture, data file, hidden registry, loose doc, or proof file.

- [ ] The changed output is wired into the live route, card, dashboard, tool, analyzer, report, or runtime surface that consumes it.
- [ ] Direct user-visible route/card links are included above when a surface is affected.
- [ ] Runtime or lazy-bundle load order is updated when the new output must execute before another projection.
- [ ] Queue/progress status was changed only after live visibility wiring existed.
- [ ] Tests assert both the data artifact and the live integration path that consumes it.
- [ ] No same-surface gap parking: buildable follow-up work in the same ownership area and live surface was built now, not added as a vague future Product Build item.
- [ ] Evidence ingestion is covered when the item expects pasted terminal output, browser-observation text, or proof notes.
- [ ] Any deferred useful finding has a named blocker, blast-radius reason, missing-source proof, private-only reason, or product-gap ID that explains why it could not be built in this PR.
- [ ] The PR does not claim completion while also saying the same item has `remaining integration`, needs a `later pass`, is `not visible yet`, or is an `additive proof artifact only`.

For re-mining artifacts, run:

```bash
node tools/build-packs.js && node tools/gap-report.js --check && node tools/move-lint.js --check && node tools/lint-study.js --check
node tools/verify-parser-corpus.js && node tools/verify-replay-goldens.js && node tools/verify-all-20-mined.js
```

## Tests

```bash

```

## Safety / source-boundary notes

- Raw course text, target details, flags, credentials, cookies, screenshots, exploit recipes, listener/callback mechanics, and reusable replay steps remain private.
- Public Obol contains only rewritten, generalized, public-safe guidance and product logic.
