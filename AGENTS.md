# AGENTS.md

Guidance for AI coding agents (and humans) working on `pam-jwt`.

## Project overview

`pam-jwt` is a Linux PAM module (`pam_jwt.so`) written in C that authenticates
a user by verifying a JWT supplied as the PAM password (authtok). The JWT
signature is checked against the public key extracted from an issuer X.509
certificate. Issuer and audience claims are optionally validated. The target
user can be mapped from a configurable JWT claim (`map_field`). Username
BINDING is always enforced: the verifier requires a configurable claim
(`match_field`, recommended) -- or the JWT standard `sub` claim as a fallback
when `match_field` is unset -- to equal the requesting user. A token that
omits the bound claim (or carries it as the empty string) is rejected with
`PAM_USER_UNKNOWN`. Mapping (`map_field`) and binding (`match_field`) are
independent options that both default off, except that the implicit
sub-fallback binding is always on.

See [`plans/plan.md`](plans/plan.md) for the full design.

## Tech stack

- **Language:** C (C11)
- **PAM:** Linux-PAM (`libpam`)
- **JWT:** `libjwt` (benmcollins/libjwt) with the OpenSSL backend
- **Crypto:** OpenSSL (`PEM_read_X509` → `X509_get_pubkey`)
- **Build:** GNU `make` + `pkg-config` (libjwt, openssl, pam)

## Repository layout

```
pam-jwt/
├── AGENTS.md            # this file
├── README.md
├── Makefile
├── .gitignore
├── include/pam_jwt.h    # public API
├── src/
│   ├── pam_jwt.c        # pam_sm_authenticate + stubs
│   ├── config.c         # parse argc/argv -> struct pam_jwt_cfg
│   ├── jwt_verify.c     # cert load, sig verify, claim + user checks
│   └── util.c           # logging + helpers
├── tests/
│   ├── run_tests.c      # tiny custom test runner main
│   ├── test_config.c
│   ├── test_jwt_verify.c
│   ├── test_claims.c
│   ├── test_users.c
│   ├── pam_harness.c    # integration: pam_start / pam_authenticate
│   └── fixtures/
│       ├── gen_certs.sh # openssl: RSA + EC key/cert
│       └── make_jwt.c   # C helper minting test JWTs via libjwt
├── examples/pam-jwt.conf
├── scripts/
│   └── install-deps.sh   # Alpine/Debian build-dep installer
└── docs/config.md
```

## Build & test

Install build dependencies first. The bundled helper detects the distro and
installs the right packages (needs root or `sudo`/`doas`):

```sh
./scripts/install-deps.sh
```

Then build and test:

```sh
make            # build src/pam_jwt.so
make test       # build tests, generate fixtures, run the suite
make test-asan  # rebuild everything with AddressSanitizer + UBSan,
                # run the suite, and run LeakSanitizer at exit.
                # Use this to catch leaks/UAF/undefined behavior in
                # src/config.c and any other parser modules.
make release    # build an optimized, hardened, stripped pam_jwt.so
                # into build/release/pam_jwt.so. Does NOT rebuild the
                # default debug tree at build/, so both coexist.
make release-info  # print pam-jwt version + release .so path
make install-release # install the stripped release .so
                     # (honors DESTDIR / PREFIX)
make clean      # remove build artifacts (incl. build/release/)
make install    # install .so + example config (honors DESTDIR / PREFIX)
```

### `make release` details

The release target is intended for packaging and production deployment,
not day-to-day development. It produces a `.so` that is:

- compiled with `-O3 -flto -DNDEBUG`
- protected by a version script ([`pam_jwt.map`](pam_jwt.map)) that
  exports **only** the six `pam_sm_*` entry points Linux-PAM looks up;
  every other internal symbol is hidden
- linked with full RELRO (`-Wl,-z,relro`), immediate binding
  (`-Wl,-z,now`), GNU hash, and a SHA-1 build-id
- stripped of `.debug_*` sections via `strip --strip-debug` (the
  `.symtab`/`.strtab` and `.dynsym`/`.dynstr` tables are kept so the
  `.so` still reports a sane symbol list to `nm -D` and crash-trace
  tooling)
- reproducible across machines: `-ffile-prefix-map` and
  `-fmacro-prefix-map` rewrite absolute source paths to `.`

The version string baked into the .so (`PAM_JWT_VERSION`) comes from
`git describe --tags --always --dirty`, falling back to `dev` for
tarball builds.

The release tree at `build/release/` is independent of the debug tree
at `build/`. A normal `make` + `make test` cycle does not touch it.

Compile flags: `-Wall -Wextra -Werror -fPIC -fvisibility=hidden`.
Link: `-shared -lpam -ljwt -lssl -lcrypto` (via `pkg-config`).

Before claiming a task is done, `make clean && make && make test` must pass
with zero warnings.

## Code conventions

- One module per `.c` file matching the layout above; public API lives in
  [`include/pam_jwt.h`](include/pam_jwt.h).
- Keep `pam_sm_authenticate` orchestration thin; push logic into `config.c`,
  `jwt_verify.c`, and `util.c` so it is unit-testable without a live PAM stack.
- Use `pam_syslog` for all logging. Never use `printf`/`fprintf` in the module.
- Prefer early-return with explicit `PAM_*` result codes.
- No network-loaded configuration; all file paths are local only.
- Do not commit generated artifacts (`.o`, `.so`, test binaries, generated
  certs/tokens) — keep them in `.gitignore`.

## Security rules (non-negotiable)

- Reject `alg=none` and any algorithm outside `{RS256, ES256}`.
- Enforce that the JWT algorithm matches the certificate key type (prevents
  algorithm-confusion attacks).
- **Never** log the token, the password/authtok, or any private key material.
- Only log via `pam_syslog(LOG_AUTHPRIV | LOG_DEBUG, ...)` and only when the
  `debug` option is set.
- Always warn at `LOG_ERR` if `cert_file` is world-writable, regardless
  of the `debug` option. A world-writable issuer cert is a privilege-
  escalation precursor (any local user can substitute the trusted key),
  so the warning must reach the operator even when debug logging is
  off. Authentication is NOT refused on this condition — the operator
  is merely notified.

## Module configuration (PAM args)

| Arg | Required | Default | Meaning |
|---|---|---|---|
| `cert_file=<path>` | yes | — | Path to issuer X.509 cert (PEM) |
| `issuer=<string>` | no | unset | Require `iss` claim to equal this |
| `audience=<string>` | no | unset | Require `aud` claim to contain this |
| `map_field=<claim>` | no | unset | Set PAM user from this JWT claim |
| `fallback_user=<user>` | no | unset | PAM user when `map_field` claim is absent/empty |
| `match_field=<claim>` | no | unset | Require this claim to equal requested user; when unset, binding falls back to the JWT standard `sub` claim |
| `clock_skew=<sec>` | no | `0` | Leeway for `exp` / `nbf` validation |
| `debug` | no | off | Verbose `pam_syslog` logging (never logs tokens) |

`map_field` (mapping) and `match_field` (binding) are independent and both
default off. Username BINDING, however, is **always** enforced: when
`match_field` is unset the verifier falls back to the JWT standard `sub`
claim and requires it to equal the requesting user. A token that omits
the bound claim (or carries it as the empty string) is rejected with
`PAM_USER_UNKNOWN`. `fallback_user` is meaningful only when `map_field`
is also set; configuring it without `map_field` is rejected at parse
time as `PAM_JWT_CFG_E_INVALID_VALUE`. When the `map_field` claim is
missing or empty in a verified token, the verifier substitutes
`fallback_user` for the mapped PAM user. The substitution does NOT
participate in the binding check, which always compares the requested
user against the configured claim value (or the `sub` fallback).

## Testing strategy

Tests are self-contained in C + shell (no Python). Fixtures are generated by
[`tests/fixtures/gen_certs.sh`](tests/fixtures/gen_certs.sh) (openssl CLI) and
[`tests/fixtures/make_jwt.c`](tests/fixtures/make_jwt.c) (libjwt encoder).

Coverage required before merge:

1. **Config parser:** every arg, defaults, duplicates, missing required.
   The `leak:` group in `tests/test_config.c` is exercised by
   `make test-asan` and must remain leak-free.
1a. **Util helpers:** logging gate (debug on/off × every priority),
    `pam_jwt_strdup`, `pam_jwt_is_world_writable` (NULL/missing/regular/
    world-writable/directory/symlink), `pam_jwt_read_file` (NULL args,
    missing, directory, empty, small, 4 KiB). `tests/test_util.c` must
    remain leak-free under `make test-asan`.
2. **Cert + signature:** RSA/EC load, bad file, non-cert PEM, valid RS256/ES256,
   tampered signature, wrong key, `alg=none` rejected.
3. **Claims:** `iss`/`aud` match/mismatch/missing; expired; not-yet-valid;
   `clock_skew` behavior.
4. **Usernames:** mapping sets user; binding pass/fail (match_field and
   the implicit `sub`-fallback binding); both off is rejected (binding
   is always required); both on consistent/inconsistent; explicit
   `sub`-fallback binding rejects missing/empty/mismatched `sub`.
5. **Integration:** PAM harness via `pam_start` + `pam_authenticate` with a
   conversation callback across a scenario matrix.

## Git workflow

- Conventional commits: `feat:`, `test:`, `docs:`, `fix:`.
- `main` branch; feature branches per work area.
- Tag `v0.1.0` once build + tests are green.

## Agent checklist before finishing

- [ ] `make clean && make && make test` passes with no warnings.
- [ ] No token/password/key material is logged anywhere in the diff.
- [ ] New options are documented in [`docs/config.md`](docs/config.md),
      [`examples/pam-jwt.conf`](examples/pam-jwt.conf), and this file.
- [ ] New behavior is covered by a test.
- [ ] Commit message follows conventional commits.
