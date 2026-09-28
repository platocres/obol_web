# Contributing to Obol

Thanks for your interest in improving Obol. A few ground rules keep the project healthy and its
licensing clean.

## The project's license

Obol is released under the **GNU Affero General Public License v3.0** (see [LICENSE](LICENSE)).
By contributing, you agree to the terms below.

## Sign your work (Developer Certificate of Origin)

Every commit must be signed off, certifying that you wrote the code or otherwise have the right to
submit it. Add a sign-off with:

```
git commit -s
```

which appends a line to your commit message:

```
Signed-off-by: Your Name <your@email.example>
```

By signing off you certify the **Developer Certificate of Origin 1.1** (reproduced at the bottom of
this file).

## Contribution license and relicensing grant

By submitting a contribution — a pull request, patch, or any other material — you agree that:

1. Your contribution is licensed to the project and its users under the **GNU AGPL v3.0**, the same
   license as the project; **and**
2. You additionally grant **the project maintainer (platocres)** a perpetual, worldwide,
   non-exclusive, royalty-free, irrevocable license to use, reproduce, modify, sublicense, and
   **relicense** your contribution under any terms, **including proprietary or commercial licenses**,
   in addition to the AGPL.

This lets the maintainer keep Obol free and open under the AGPL while also offering the project (or a
related edition) under separate terms. You retain the copyright to your contribution — you are simply
granting these licenses.

Please do **not** submit code you do not have the right to license this way, and do **not** include
third-party code under a license incompatible with the above.

## Practical notes

- Keep changes focused, and match the surrounding code style.
- The engine is pure and UI-independent; prefer adding logic there with a test in `tests/`.
- Run the test suite before opening a pull request.

---

## Developer Certificate of Origin 1.1

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
1 Letterman Drive
Suite D4700
San Francisco, CA, 94129

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```
