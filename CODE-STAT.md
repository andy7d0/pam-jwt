# Code Statistics — `pam-jwt`

Snapshot of source, test, documentation, spec, and build assets in the
repository. Counts are produced by `wc` (bytes / lines) plus a simple
SLOC estimate (non-blank lines minus pure-comment lines beginning with
`//`, `/*`, or `*`).

Generated 2026-06-19.

## Headline totals

| Bucket            | Files |   Bytes  |  Lines  |  SLOC*  |
| ----------------- | ----: | -------: | ------: | ------: |
| Main code         |     5 |   59,663 |   1,730 |   1,040 |
| Tests             |     8 |  118,843 |   3,474 |   2,671 |
| Test fixtures     |     2 |   15,207 |     520 |     434 |
| Docs & specs      |     5 |   42,221 |     926 |      —  |
| Build & scripts   |     2 |   13,258 |     391 |     324 |
| **Project total** | **22**| **249,192** | **7,041** | **4,469** |

\* SLOC = non-blank − pure comment lines (C-style). Not applied to
markdown / config / shell (marked `—`).

## 1. Main code — `src/` + `include/`

The PAM module proper, plus its public header.

| File                       |  Bytes  |  Lines  | Non-blank | Comments |  SLOC  |
| -------------------------- | ------: | ------: | --------: | -------: | -----: |
| [`include/pam_jwt.h`](include/pam_jwt.h)     | 10,642 | 225 | 204 | 141 |  63 |
| [`src/pam_jwt.c`](src/pam_jwt.c)             | 11,506 | 287 | 263 | 124 | 139 |
| [`src/config.c`](src/config.c)               | 10,769 | 368 | 347 |  75 | 272 |
| [`src/util.c`](src/util.c)                   |  6,233 | 222 | 205 |  61 | 144 |
| [`src/jwt_verify.c`](src/jwt_verify.c)       | 20,513 | 628 | 588 | 166 | 422 |
| **Subtotal**             | **59,663** | **1,730** | **1,607** | **567** | **1,040** |

Notes:
- [`src/jwt_verify.c`](src/jwt_verify.c) is the heaviest module (cert
  load, signature verify, claim + user checks).
- [`src/pam_jwt.c`](src/pam_jwt.c) intentionally stays thin — it only
  orchestrates and dispatches into the other modules.

## 2. Tests — `tests/`

Custom C test runner plus per-module suites and the PAM integration
harness. Fixtures are listed separately in §3.

| File                                        |  Bytes  |  Lines  | Non-blank | Comments |  SLOC  |
| ------------------------------------------- | ------: | ------: | --------: | -------: | -----: |
| [`tests/test.h`](tests/test.h)                            |  5,549 | 139 | 125 |  42 |  83 |
| [`tests/test.c`](tests/test.c)                            |  1,993 |  81 |  73 |  11 |  62 |
| [`tests/run_tests.c`](tests/run_tests.c)                  |  1,539 |  59 |  51 |  12 |  39 |
| [`tests/test_config.c`](tests/test_config.c)              | 28,553 | 771 | 711 | 114 | 597 |
| [`tests/test_jwt_verify.c`](tests/test_jwt_verify.c)      | 13,335 | 414 | 383 |  90 | 293 |
| [`tests/test_claims.c`](tests/test_claims.c)              | 19,448 | 567 | 524 |  58 | 466 |
| [`tests/test_users.c`](tests/test_users.c)                | 16,732 | 474 | 440 |  62 | 378 |
| [`tests/test_util.c`](tests/test_util.c)                  | 14,207 | 429 | 387 |  54 | 333 |
| [`tests/pam_harness.c`](tests/pam_harness.c)              | 17,487 | 540 | 501 |  81 | 420 |
| **Subtotal**                              | **99,841** | **3,474** | **3,195** | **524** | **2,671** |

Test : code ratio (SLOC): 2,671 / 1,040 ≈ **2.57×**.

## 3. Test fixtures — `tests/fixtures/`

Helpers used to build certificates and mint JWTs at test time.

| File                                          |  Bytes  |  Lines  | Non-blank | Comments |  SLOC  |
| --------------------------------------------- | ------: | ------: | --------: | -------: | -----: |
| [`tests/fixtures/gen_certs.sh`](tests/fixtures/gen_certs.sh) | 2,077 |  64 |  56 |  0 |  56 |
| [`tests/fixtures/make_jwt.c`](tests/fixtures/make_jwt.c)     | 13,130 | 456 | 437 |  59 | 378 |
| **Subtotal**                                 | **15,207** | **520** | **493** | **59** | **434** |

## 4. Documentation & specs

| File                                       |  Bytes  |  Lines  | Non-blank |
| ------------------------------------------ | ------: | ------: | --------: |
| [`README.md`](README.md)                   |  4,402 |  137 |  106 |
| [`AGENTS.md`](AGENTS.md)                   |  6,849 |  163 |  133 |
| [`docs/config.md`](docs/config.md)         |  9,688 |  194 |  150 |
| [`plans/plan.md`](plans/plan.md)           | 16,237 |  311 |  280 |
| [`examples/pam-jwt.conf`](examples/pam-jwt.conf) | 5,045 |  121 |  114 |
| **Subtotal**                              | **42,221** | **926** | **783** |

Highlights:
- [`plans/plan.md`](plans/plan.md) is the primary design spec (311
  lines, the longest markdown document).
- [`AGENTS.md`](AGENTS.md) is the agent / contributor handbook.
- [`docs/config.md`](docs/config.md) is the operator reference for
  every PAM arg.
- [`examples/pam-jwt.conf`](examples/pam-jwt.conf) is the canonical
  sample configuration.

## 5. Build & scripts

| File                                                |  Bytes  |  Lines  | Non-blank |
| --------------------------------------------------- | ------: | ------: | --------: |
| [`Makefile`](Makefile)                              |  8,198 |  214 |  173 |
| [`scripts/install-deps.sh`](scripts/install-deps.sh) |  5,060 |  177 |  151 |
| **Subtotal**                                       | **13,258** | **391** | **324** |

## Methodology

- `bytes`  — `wc -c`
- `lines`  — `wc -l` (every line, including blanks)
- `non-blank` — `grep -cvE '^\s*$'`
- `comments` — `grep -cE '^\s*(//|/\*|\*)'` (rough C-style heuristic)
- `SLOC`   — `non-blank − comments`

The SLOC column intentionally counts only `//`, `/*`, and `*` lines that
start a row; trailing comments on code lines and multi-line block
comments are not deducted, so this is a *lower-bound* estimate. It is
adequate for relative comparisons between modules.

## Repository layout (for reference)

```
pam-jwt/
├── AGENTS.md
├── README.md
├── Makefile
├── CODE-STAT.md            ← this file
├── docs/config.md
├── examples/pam-jwt.conf
├── include/pam_jwt.h
├── plans/plan.md
├── scripts/install-deps.sh
├── src/
│   ├── pam_jwt.c
│   ├── config.c
│   ├── jwt_verify.c
│   └── util.c
└── tests/
    ├── run_tests.c
    ├── test.h
    ├── test.c
    ├── test_config.c
    ├── test_jwt_verify.c
    ├── test_claims.c
    ├── test_users.c
    ├── test_util.c
    ├── pam_harness.c
    └── fixtures/
        ├── gen_certs.sh
        └── make_jwt.c
```
