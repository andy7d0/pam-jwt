# `pam_jwt.so` — Configuration reference

`pam-jwt` is a Linux-PAM module that authenticates a user by verifying a JWT
supplied as the PAM password (authtok). The JWT signature is checked against
the public key extracted from an issuer X.509 certificate.

This document is the authoritative reference for the arguments `pam_jwt.so`
accepts on the PAM config line. The companion
[`examples/pam-jwt.conf`](../examples/pam-jwt.conf) file shows ready-to-paste
examples; the high-level design lives in [`../plans/plan.md`](../plans/plan.md).

## Where the config goes

Arguments are passed via the standard PAM config file syntax, e.g.:

```pam
auth required pam_jwt.so cert_file=/etc/pam-jwt/issuer.pem issuer=https://idp.example.com/ audience=myapp match_field=uid debug
```

Multiple arguments are separated by whitespace. The PAM parser does not
support quoting or backslash escapes, so values that contain whitespace
are not portable across PAM config files; the module will reject any
value longer than `PAM_JWT_MAX_OPT_LEN` (1024 bytes) anyway.

## Argument reference

| Arg | Required | Default | Meaning |
|---|---|---|---|
| `cert_file=<path>` | **yes** | — | Path to issuer X.509 certificate (PEM) |
| `issuer=<string>` | no | unset | Require `iss` claim to equal this string |
| `audience=<string>` | no | unset | Require `aud` claim to contain this string |
| `map_field=<claim>` | no | unset | Set the PAM user from this JWT claim |
| `match_field=<claim>` | no | unset | Require this JWT claim to equal the requested user |
| `clock_skew=<sec>` | no | `0` | Leeway (seconds) for `exp` / `nbf` validation |
| `debug` | no | off | Verbose `pam_syslog` logging (never logs tokens) |

### `cert_file` (required)

Path to the issuer X.509 certificate in PEM format. The module extracts the
public key from the certificate and uses it as the only key material
trusted to verify incoming JWTs. The file must be readable by the
process performing authentication.

If the file is world-writable, the module emits a warning at
`LOG_DEBUG` (only visible when `debug` is on) — the auth result is
unaffected, but the condition is a configuration mistake worth surfacing.

### `issuer` (optional)

When set, the JWT's `iss` claim must be a string and must equal this value
exactly. Useful for multi-tenant setups where one IdP serves several
audiences and you want to pin authentication to a specific issuer URL.

If the option is not set, the `iss` claim is not inspected.

### `audience` (optional)

When set, the JWT's `aud` claim must be present and must contain this
string. Containment is checked in the standard way:

- If `aud` is a string, it must equal the configured value.
- If `aud` is an array, the configured value must be one of its elements.
- If `aud` is missing or is a non-string/non-array value, the token is
  rejected.

If the option is not set, the `aud` claim is not inspected.

### `map_field` (optional, independent)

When set, the value of the named JWT claim is written back as the PAM
user via `pam_set_data()` / `pam_get_user()`. Independent of
`match_field` and defaults to off.

The claim must exist, must be a string, and must be non-empty. A token
that does not carry the claim (or carries a non-string value) is
rejected.

### `match_field` (optional, independent)

When set, the value of the named JWT claim must equal the user that
initiated the authentication (typically the result of
`pam_get_user()`). Useful as a binding check that prevents a stolen
token from being replayed against a different local account.

The claim must exist, must be a string, and must be non-empty. A token
that does not carry the claim (or carries a non-string value) is
rejected.

`map_field` and `match_field` are independent: enabling both is
allowed. The recommended pattern is to set `match_field` to a stable
account id (e.g. `sub` or `uid`) and `map_field` to a human-friendly
name (e.g. `preferred_username`).

### `clock_skew` (optional)

Non-negative integer giving the leeway in seconds applied to the
`exp` and `nbf` claims. A value of `0` (the default) means the
timestamps are checked strictly. `30`–`60` is a reasonable value for
most setups where the issuer and this host are not NTP-locked.

Negative values are rejected at parse time.

### `debug` (optional flag)

A bare flag (no value) that enables verbose `pam_syslog()` logging
under the `authpriv` facility at `LOG_DEBUG` priority. Useful when
first deploying or when investigating rejected tokens.

The module never logs the JWT, the authtok, or any private key
material, with or without `debug`. The flag only widens the
priority gate for *operational* messages (e.g. "cert file
world-writable", "alg mismatch", "exp in the past").

## Algorithms

The module accepts exactly two algorithms and enforces that the JWT's
`alg` header matches the certificate's public key type. This blocks
both the well-known `alg=none` bypass and the family of
algorithm-confusion attacks:

| `alg` | Allowed cert key type |
|---|---|
| `RS256` | RSA |
| `ES256` | EC (P-256) |

Any other `alg` value — including `none`, `HS*`, `RS*` against an EC
key, `ES*` against an RSA key, or unknown strings — causes
`pam_sm_authenticate()` to return `PAM_AUTH_ERR`.

## Return codes

`pam_sm_authenticate()` uses the standard PAM result codes:

| Code | Meaning |
|---|---|
| `PAM_SUCCESS` | The JWT verified, all configured claim / user checks passed. |
| `PAM_AUTH_ERR` | The JWT is missing, malformed, has an invalid signature, an unsupported or mismatched `alg`, an untrusted issuer / audience, an expired / not-yet-valid timestamp (within `clock_skew`), a failed `match_field` check, or any other verification failure. |
| `PAM_USER_UNKNOWN` | `pam_get_user()` returned no user. |
| `PAM_AUTHTOK_ERR` | `pam_get_authtok()` failed to retrieve the token. |
| `PAM_SERVICE_ERR` | Module arguments could not be parsed, the cert file is missing or unreadable, or another internal error occurred. |
| `PAM_BUF_ERR` | Memory allocation failure. |

The module never logs the token, the authtok, or any private key
material. Operational failures (bad cert file, alg mismatch, etc.)
are surfaced via `pam_syslog(LOG_AUTHPRIV|LOG_DEBUG, ...)` and only
visible when `debug` is set.

## Security notes

- **No network-loaded configuration.** All paths are local; there is
  no `issuer URL` field that triggers a network fetch.
- **Algorithms are pinned.** The allowlist is `{RS256, ES256}`. The
  `alg` header is matched against the certificate's key type, so a
  malicious token claiming `RS256` against an EC issuer cert (or
  vice versa) is rejected.
- **The token is the password.** Anything that ends up in the PAM
  conversation function's password prompt is treated as the JWT.
  Make sure the surrounding PAM service is configured to consume the
  password in-band (i.e. the standard `pam_get_authtok()` path) and
  is not echoing it back to the caller.
- **No token, no key material in logs.** The module's logging helpers
  ([`src/util.c`](../src/util.c)) only accept `printf`-style format
  strings. There is no API to log the token, the authtok, or the
  certificate's private key (which is never loaded anyway, since we
  only use the public key half of the cert).
