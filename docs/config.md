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
| `fallback_user=<user>` | no | unset | PAM user used when the `map_field` claim is missing or empty in a verified token |
| `match_field=<claim>` | no | unset | Require this JWT claim to equal the requested user |
| `clock_skew=<sec>` | no | `0` | Leeway (seconds) for `exp` / `nbf` validation |
| `debug` | no | off | Verbose `pam_syslog` logging (never logs tokens) |

### `cert_file` (required)

Path to the issuer X.509 certificate in PEM format. The module extracts the
public key from the certificate and uses it as the only key material
trusted to verify incoming JWTs. The file must be readable by the
process performing authentication.

If the file is world-writable, the module emits a warning at
`LOG_ERR` (under the `authpriv` facility) **regardless of the `debug`
option**. Authentication is not refused on this condition — operators
are merely notified that a local user could substitute the trusted
issuer key, which is a privilege-escalation precursor. Fix the file
mode (`chmod 0644` or stricter) and rotate the certificate if the
condition was unintentional.

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
rejected, unless `fallback_user` is also configured (see below).

### `fallback_user` (optional, requires `map_field`)

When `map_field` is configured and the verified token does not carry
the mapped claim (the claim is missing, or its value is the empty
string), the verifier uses `fallback_user` as the PAM user instead of
rejecting the token. The mapped-user check still passes, so a single
service account can authenticate any token whose IdP omits the
configured claim.

The substitution is restricted to the mapping step. If `match_field`
is also configured, the requested user is still compared against the
claim named by `match_field` -- the fallback does NOT participate in
the binding check. Configuring `fallback_user` without `map_field` is
rejected at parse time as `PAM_JWT_CFG_E_INVALID_VALUE`.

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

### Implicit binding: `sub` fallback (always enforced)

User matching is **always** required: there is no "verify the
signature and call it a day" mode. When `match_field` is **not**
configured, the verifier falls back to the JWT standard `sub` claim
(per RFC 7519, the subject of the token -- the entity the IdP is
identifying) and requires it to equal the user that initiated
authentication. A token that omits `sub`, or carries it as the empty
string, is rejected with `PAM_USER_UNKNOWN` -- the empty-string path
prevents a buggy IdP that wipes the claim from accidentally matching
every requested user.

Operators who want to bind to a custom claim (e.g. `uid`,
`preferred_username`, `email`) should set `match_field` to that claim
name. Operators who want the canonical RFC 7519 behaviour can simply
leave `match_field` unset and ensure their IdP always issues a
non-empty `sub`.

### `clock_skew` (optional)

Non-negative integer giving the leeway in seconds applied to the
`exp` and `nbf` claims. A value of `0` (the default) means the
timestamps are checked strictly. `30`–`60` is a reasonable value for
most setups where the issuer and this host are not NTP-locked.

Negative values are rejected at parse time. A leading `+` (e.g.
`clock_skew=+30`) is accepted for compatibility with operators used
to writing signed integers; the `+` is purely cosmetic and `30` and
`+30` parse to the same value.

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

`pam_sm_authenticate()` ([`src/pam_jwt.c`](../src/pam_jwt.c)) uses the
standard PAM result codes. The verifier ([`src/jwt_verify.c`](../src/jwt_verify.c))
returns its own codes for token-level failures; `pam_sm_authenticate()`
propagates them unchanged, except where noted.

| Code | Returned by | Meaning |
|---|---|---|
| `PAM_SUCCESS` | `pam_sm_authenticate` | The JWT verified, all configured claim / user checks passed. The optional mapped user (the `map_field` claim value, or `fallback_user` if the claim was missing/empty) has been stashed for `pam_sm_setcred` to promote to `PAM_USER`. |
| `PAM_AUTH_ERR` | `pam_sm_authenticate`, `pam_jwt_verify` | The authtok could not be retrieved from the PAM conversation, the token is empty, the token is malformed, the signature is invalid, the JWT `alg` is outside `{RS256, ES256}` or does not match the certificate key type, the time-based claims (`exp` / `nbf`) fall outside the `clock_skew` window, the `iss` claim does not match the configured `issuer`, the `aud` claim does not contain the configured `audience`, or the `map_field` claim is missing, non-string, or empty in the token AND no `fallback_user` was configured. |
| `PAM_USER_UNKNOWN` | `pam_sm_authenticate`, `pam_jwt_verify` | `pam_get_user()` returned no user (or an empty string), **or** the bound claim (the claim named by `match_field`, or the JWT standard `sub` claim when `match_field` is unset) is missing, empty, or does not equal the user that initiated authentication. |
| `PAM_SERVICE_ERR` | `pam_sm_authenticate`, `pam_jwt_verify` | Module arguments could not be parsed (`cert_file` missing, malformed value, duplicate, OOM during parse, ...), the cert file is missing or unreadable, the cert file is not a valid X.509 PEM, or another internal error occurred (e.g. an unexpected `NULL` argument reaching the verifier). |
| `PAM_BUF_ERR` | `pam_sm_authenticate`, `pam_jwt_verify` | Memory allocation failure (e.g. cloning the mapped-user claim, or stashing it via `pam_set_data()`). |

> Note: `PAM_AUTHTOK_ERR` is **not** used. When `pam_get_authtok()`
> fails or returns an empty token, [`src/pam_jwt.c`](../src/pam_jwt.c)
> returns `PAM_AUTH_ERR` so the caller observes a uniform
> authentication failure rather than a transport-level authtok error.

The other PAM entry points in [`src/pam_jwt.c`](../src/pam_jwt.c)
return:

- `pam_sm_setcred()` → `PAM_SUCCESS` (promotes the optional mapped user
  to `PAM_USER` on `PAM_ESTABLISH_CRED` / `PAM_REINITIALIZE_CRED`,
  no-op otherwise).
- `pam_sm_acct_mgmt()`, `pam_sm_open_session()`,
  `pam_sm_close_session()` → `PAM_SUCCESS` (pam_jwt does not
  participate in account / session management).
- `pam_sm_chauthtok()` → `PAM_IGNORE` (the credential is a JWT, not a
  Unix password; there is nothing for this module to change).

The module never logs the token, the authtok, or any private key
material. Operational failures (bad cert file, alg mismatch, etc.)
are surfaced via `pam_syslog(LOG_AUTHPRIV|LOG_DEBUG, ...)` and only
visible when `debug` is set. The single exception is the
"cert_file is world-writable" warning, which is always emitted at
`LOG_ERR` because it points at a privilege-escalation precursor the
operator must see.

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
