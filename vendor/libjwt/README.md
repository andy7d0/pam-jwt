# vendor/libjwt

Vendored copy of [libjwt 1.17.2](https://github.com/benmcollins/libjwt)
(commit `5cc7b4d`, tag `v1.17.2`). Integrated as a **static** library
that is linked into `pam_jwt.so` and into the test binaries.

## Why vendor?

`pam-jwt` is a Linux-PAM module and is expected to build and run on
multiple distributions. The libjwt 1.x ABI is what the module code
(`src/jwt_verify.c`, `tests/fixtures/make_jwt.c`) was written against,
and the project's CI matrix targets distros whose libjwt packages vary
widely:

| Distro             | libjwt package          | Notes                                  |
|--------------------|-------------------------|----------------------------------------|
| Debian 13 (trixie) | `libjwt-dev` 1.17.2     | ships 1.x                               |
| Alpine 3.24        | `libjwt-dev` 3.x        | ships 3.x (breaking ABI / API change)  |

Relying on whichever `libjwt-dev` the host happens to ship would mean
either forking the build per-distro or rewriting the verifier against
two incompatible APIs. Vendoring 1.17.2 (the version the source code
already targets) and linking it statically into the `.so` makes the
build **self-contained and identical on every distro**: every
`pam_jwt.so` we ship embeds the same libjwt objects, compiled with the
same compiler flags, regardless of what's installed under
`/usr/lib/`.

## What is vendored

```
vendor/libjwt/
├── README.md          this file
├── include/
│   └── jwt.h          public libjwt API header (only this is exposed
│                      to pam-jwt's own sources; everything else is
│                      kept private to the static lib)
└── src/
    ├── config.h       hand-rolled replacement for the autoconf-
    │                  generated `config.h` (see below)
    ├── base64.c       base64url encoder/decoder used by the JWS path
    ├── base64.h       internal
    ├── jwt.c          core JWT object lifecycle, JSON glue (via
    │                  jansson), and the public API entry points
    ├── jwt-openssl.c  OpenSSL crypto backend (RS256 / RS384 / RS512 /
    │                  ES256 / ES384 / ES512 / HS*)
    └── jwt-private.h  internal struct definitions shared by jwt.c
                       and the backend
```

The GnuTLS (`jwt-gnutls.c`) and Windows (`jwt-wincrypt.c`) backends
shipped by upstream are **not** vendored -- we link against OpenSSL
only, per `AGENTS.md`. Likewise `libjwt.pc.in`, the autotools /
CMake build glue, the upstream test suite, and the example programs
are not vendored. `pam-jwt` is a self-contained module; we want
exactly the objects we link and nothing else.

The vendored copy is byte-for-byte the upstream source at tag
`v1.17.2` (modulo the line-1 copyright bump that the upstream
applied in `jwt.c` / `jwt-private.h` between v1.17.0 and v1.17.2 --
the code path is identical). To upgrade, replace the files under
`vendor/libjwt/` with the contents of a fresh `git archive vX.Y.Z`
of the upstream repo and re-run `make test`.

## config.h

The upstream build produces `config.h` from `configure.ac` /
`CMakeLists.txt`. We don't run either, so the vendored `config.h`
ships pre-baked with the only define the OpenSSL backend needs:

* `HAVE_OPENSSL` -- selects the OpenSSL backend. The alternative
  backends (GnuTLS, mbedTLS) are not vendored; defining
  `HAVE_GNUTLS` here without vendoring `jwt-gnutls.c` would leave
  `jwt_sign_sha_pem` etc. undefined at link time.
* `PACKAGE` / `PACKAGE_VERSION` -- used by `jwt.c` to tag error
  strings. The values are chosen to identify the vendored copy
  distinctly from a system-installed libjwt.

If a future upstream release starts consuming a new `HAVE_*` macro
in the files we vendored, add it to `config.h` in the same shape.

## How it links

`Makefile` compiles each vendored `*.c` to `build/vendor/libjwt/*.o`
and then `$(AR)`s them into `build/vendor/libjwt/libjwt.a`. That
archive is linked into both `build/pam_jwt.so` and `build/run_tests`
(plus the ASan build under `build/asan/`).

The vendored libjwt's only runtime dependencies are OpenSSL
(`libcrypto`) and jansson (`libjansson`). Both are expected to be
present on the host -- they are system libraries on every supported
distro and pulling them in statically would balloon the `.so` for
no operational benefit.

## Updating

```
cd vendor/libjwt
rm -rf src include
git archive --format=tar v1.17.2 | tar -x
# (then re-apply the config.h added on top -- it's not in upstream)
```

Sanity-check afterwards with `make clean && make test`.
