# pam-jwt

A Linux-PAM module (`pam_jwt.so`) written in C that authenticates a user by
verifying a JWT supplied as the PAM password (authtok). The JWT signature is
checked against the public key extracted from an issuer X.509 certificate.
Issuer and audience claims are optionally validated. The target user can be
mapped from a configurable JWT claim (`map_field`) and/or a configurable claim
can be required to equal the requesting user (`match_field`). Both username
options are independent and default off. An optional `fallback_user`
substitutes for the mapped claim when it is missing or empty in a verified
token, but never participates in the `match_field` binding check.

## Status

✅ **Ready for `v0.2.0`.** All planned modules and tests are implemented; the
suite is green under `make clean && make && make test` (156 cases /
970 assertions, zero warnings). See [`plans/plan.md`](plans/plan.md) for the
full design and progress.

## Supported algorithms

- `RS256` (RSA)
- `ES256` (ECDSA P-256)

`alg=none` and any other algorithm are rejected. The JWT header algorithm is
enforced to match the certificate's public key type to prevent algorithm
confusion attacks.

## Dependencies

| Package | Purpose |
|---|---|
| `libpam` | Linux-PAM development headers |
| `libjwt` ([benmcollins/libjwt](https://github.com/benmcollins/libjwt)) | JWT encode/decode/verify |
| `openssl` | X.509 parsing, public key extraction |
| `pkg-config` | Build-time flag discovery |
| `gnu make` | Build |

On Debian/Ubuntu:

```sh
sudo apt-get install -y build-essential pkg-config libpam0g-dev libssl-dev libjwt-dev
```

On Alpine Linux:

```sh
sudo apk add alpine-sdk pkgconfig linux-pam-dev libjwt-dev openssl-dev openssl bash
```

On Fedora:

```sh
sudo dnf install -y gcc make pkg-config pam-devel openssl-devel libjwt-devel
```

> `libjwt` must be built with the OpenSSL backend (the default on most distros).

### One-shot installer

For CI or fresh VMs you can run the bundled helper, which auto-detects the
distribution and installs the right packages (uses `sudo` / `doas` when not
already root):

```sh
./scripts/install-deps.sh           # auto-detect (Alpine or Debian/Ubuntu)
./scripts/install-deps.sh alpine    # force the apk path
./scripts/install-deps.sh debian    # force the apt-get path
```

## Build

```sh
make            # build src/pam_jwt.so
make test       # build test binaries, generate fixtures, run the suite
make clean      # remove build artifacts
make install    # install .so + example config (honors DESTDIR / PREFIX)
```

Compile flags: `-Wall -Wextra -Werror -fPIC -fvisibility=hidden`.
Link flags: `-shared -lpam -ljwt -lssl -lcrypto` (via `pkg-config`).

## Configuration

Module arguments are passed via the PAM config file. Example:

```pam
auth required pam_jwt.so cert_file=/etc/pam-jwt/issuer.pem issuer=https://issuer.example.com audience=myapp debug
```

See [`examples/pam-jwt.conf`](examples/pam-jwt.conf) and
[`docs/config.md`](docs/config.md) for the full argument reference.

## Repository layout

```
pam-jwt/
├── README.md
├── AGENTS.md
├── Makefile
├── .gitignore
├── include/
│   └── pam_jwt.h
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
│   ├── test_util.c      # logging gate, strdup, world-writable, read_file
│   ├── pam_harness.c    # integration: pam_start / pam_authenticate
│   ├── test.c           # test runner implementation (asserts/tally)
│   ├── test.h           # shared TEST/TEST_GROUP/ASSERT_* macros
│   └── fixtures/
│       ├── gen_certs.sh # openssl: RSA + EC key/cert
│       └── make_jwt.c   # C helper minting test JWTs via libjwt
├── examples/
│   └── pam-jwt.conf
├── docs/
│   └── config.md
└── plans/
    └── plan.md
```

## Security

- Rejects `alg=none` and any algorithm outside `{RS256, ES256}`.
- Enforces JWT algorithm matches the certificate's public key type.
- Never logs the token, password, or any private-key material.
- All file paths are local; no network-loaded configuration.

## License

To be decided.
