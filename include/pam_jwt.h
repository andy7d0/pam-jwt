/*
 * include/pam_jwt.h
 *
 * Public API for the pam_jwt PAM module. The actual entry point
 * pam_sm_authenticate() lives in src/pam_jwt.c; the rest of the surface
 * here exists so that configuration parsing, JWT verification, and utility
 * helpers can be unit-tested without a live PAM stack.
 *
 * Security: never log the authtok, the JWT, or any private key material.
 */

#ifndef PAM_JWT_H
#define PAM_JWT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <syslog.h>

#ifdef __cplusplus
extern "C"
{
#endif

/* Maximum length of any string option taken from PAM args (e.g. file paths,
 * claim names, issuer/audience values). Keep generous but bounded so that
 * configuration parsing never overflows. */
#define PAM_JWT_MAX_OPT_LEN 1024

    /* Module configuration. All pointer fields are owned by the cfg and must
     * be released via pam_jwt_cfg_free(). Strings are NUL-terminated; the
     * optional fields are NULL when not configured. */
    struct pam_jwt_cfg
    {
        char *cert_file;     /* required: path to issuer X.509 cert (PEM) */
        char *issuer;        /* optional: required value of "iss" claim */
        char *audience;      /* optional: required value of "aud" claim */
        char *map_field;     /* optional: claim name to set PAM user from */
        char *fallback_user; /* optional: PAM user when map_field absent */
        char *match_field;   /* optional: claim name required to equal user */
        int clock_skew;      /* optional: leeway in seconds for exp/nbf */
        bool debug;          /* optional: enable pam_syslog debug logging */
    };

    /* Result of parsing PAM argc/argv. */
    enum pam_jwt_cfg_status
    {
        PAM_JWT_CFG_OK = 0,
        PAM_JWT_CFG_E_MISSING_REQUIRED, /* required arg (cert_file) missing */
        PAM_JWT_CFG_E_INVALID_VALUE,    /* malformed arg value */
        PAM_JWT_CFG_E_DUPLICATE,        /* arg given more than once */
        PAM_JWT_CFG_E_OOM,              /* allocation failure */
        PAM_JWT_CFG_E_INTERNAL          /* unexpected internal error */
    };

    /* Initialize a cfg to safe defaults. Safe to call multiple times. */
    void pam_jwt_cfg_init(struct pam_jwt_cfg *cfg);

    /* Release any heap-owned fields inside cfg. The struct itself is not freed. */
    void pam_jwt_cfg_free(struct pam_jwt_cfg *cfg);

    /* Parse module arguments (PAM argc/argv) into cfg. Returns PAM_JWT_CFG_OK
     * on success or an enum pam_jwt_cfg_status error code. On error, cfg is
     * left in a valid (freed) state suitable for pam_jwt_cfg_free(). */
    enum pam_jwt_cfg_status pam_jwt_cfg_parse(int argc, const char **argv,
                                              struct pam_jwt_cfg *cfg);

    /* --- Utility helpers (src/util.c) -------------------------------------------
     *
     * These helpers exist so the rest of the module never touches the syslog
     * API or POSIX stat() directly. That keeps the call sites uniform and the
     * security-relevant guarantees ("never log secrets", "warn if cert_file is
     * world-writable") enforceable from a single file.
     */

    /* Decide whether a syslog-style message of `priority` should be emitted
     * given the configured `debug` flag.
     *
     *   - When debug is false, only messages at or above LOG_ERR pass the gate.
     *     This keeps critical failures visible in syslog while keeping chatty
     *     LOG_DEBUG / LOG_INFO out of it.
     *   - When debug is true, everything passes.
     *
     * The priority argument uses the standard <syslog.h> constants
     * (LOG_EMERG .. LOG_DEBUG) plus the optional LOG_AUTHPRIV facility bit.
     *
     * This is a pure function: it performs no I/O and is safe to call from
     * any context. It exists primarily so unit tests can verify the gating
     * decision without depending on a live syslog. */
    bool pam_jwt_log_should_emit(bool debug, int priority);

    /* Emit a pam_syslog message iff the (debug, priority) gate allows it.
     *
     * When the gate denies the message, the call is a cheap no-op. When it
     * allows, the message is forwarded to pam_syslog with LOG_AUTHPRIV OR'd
     * into the priority so it lands in authpriv.* regardless of the priority
     * the caller requested (per AGENTS.md).
     *
     * `pamh` may be NULL -- pam_syslog tolerates a NULL handle. `fmt` is a
     * printf-style format string. The function never logs tokens, passwords,
     * or private-key material; the format string is the caller's contract.
     *
     * Declared with the printf format attribute on compilers that support it
     * (GCC, Clang) so misuses surface at build time. */
    void pam_jwt_log(pam_handle_t *pamh, bool debug, int priority,
                     const char *fmt, ...)
#if defined(__GNUC__) || defined(__clang__)
        __attribute__((format(printf, 4, 5)))
#endif
        ;

    /* Duplicate a NUL-terminated string into a freshly malloc'd buffer.
     * Returns NULL on OOM or if `s` is NULL. The returned pointer is owned
     * by the caller and must be released with free(). An empty input
     * produces an allocated empty string (""), distinct from NULL. */
    char *pam_jwt_strdup(const char *s);

    /* Return true iff `path` is a regular file that is world-writable
     * (mode bit S_IWOTH set in st_mode). Returns false on:
     *   - NULL path
     *   - stat() failure (missing file, permission denied, ENOTDIR, ...)
     *   - anything that is not a regular file (directories, symlinks to
     *     directories, sockets, ...)
     *
     * Note: stat() follows symlinks, so this is the effective permission
     * of the final target, which is what an attacker would be racing against.
     *
     * Per AGENTS.md, callers that load an X.509 certificate from `path` use
     * this helper to warn at LOG_DEBUG level when the file is world-writable. */
    bool pam_jwt_is_world_writable(const char *path);

    /* Read the entire contents of `path` into a freshly malloc'd buffer.
     * On success the buffer is NUL-terminated, *out_size receives the byte
     * length excluding the trailing NUL, and the function returns true.
     *
     * On failure (NULL path, stat failure, OOM, read error, or the file
     * being non-regular) the function returns false and *out is set to NULL
     * and *out_size to 0. The caller must NOT free *out when false is
     * returned.
     *
     * The buffer is owned by the caller and must be released with free().
     * This helper is used by src/jwt_verify.c to slurp small config files
     * (e.g. the issuer certificate) without dragging stdio into the module. */
    bool pam_jwt_read_file(const char *path, char **out, size_t *out_size);

    /* --- JWT verification (src/jwt_verify.c) ------------------------------------
     *
     * The verifier is split into two layers so it can be unit-tested without
     * a live PAM stack:
     *
     *   1. pam_jwt_load_cert() parses an issuer X.509 certificate, extracts
     *      the public key, and renders it as a PEM string suitable for
     *      libjwt's verification path. It also classifies the key as RSA or
     *      EC so the caller can reject algorithm-confusion attacks (a token
     *      whose `alg` does not match the certificate's key type).
     *
     *   2. pam_jwt_verify() runs the full checks the PAM entry point needs:
     *      decode + signature verify, alg allowlist, exp/nbf with clock
     *      skew, optional iss/aud match, and optional username mapping
     *      (map_field) / binding (match_field).
     */

    /* Discriminator for the kind of public key extracted from the issuer
     * certificate. Used to enforce that the JWT `alg` matches the key type
     * (e.g. RS256 to RSA, ES256 to EC). */
    enum pam_jwt_key_type
    {
        PAM_JWT_KEY_NONE = 0, /* unset / failure */
        PAM_JWT_KEY_RSA,      /* RSA public key */
        PAM_JWT_KEY_EC        /* Elliptic-curve public key */
    };

    /* Load the issuer X.509 certificate at `cert_file`, extract its public
     * key, and render it as a NUL-terminated PEM string suitable for
     * libjwt. On success:
     *   - *out_pem is a freshly malloc'd, NUL-terminated buffer containing
     *     the PEM (BEGIN PUBLIC KEY ... END PUBLIC KEY). The caller owns it
     *     and must release it with free().
     *   - *out_pem_len receives the byte length excluding the trailing NUL.
     *   - *out_key_type receives PAM_JWT_KEY_RSA or PAM_JWT_KEY_EC.
     *
     * On failure (NULL args, unreadable file, non-cert PEM, non-RSA/EC key,
     * OOM, ...), *out_pem is set to NULL, *out_pem_len to 0, and
     * *out_key_type to PAM_JWT_KEY_NONE. The function never logs secrets.
     *
     * Returns true on success, false on any failure. */
    bool pam_jwt_load_cert(const char *cert_file, char **out_pem,
                           size_t *out_pem_len,
                           enum pam_jwt_key_type *out_key_type);

    /* Verify a JWT `token` (NUL-terminated) against the configuration `cfg`,
     * loading the issuer certificate from `cfg->cert_file` and applying the
     * optional issuer / audience / username mapping rules plus the always-
     * enforced username binding rule.
     *
     * `pamh` is forwarded to pam_syslog for diagnostic messages and may be
     * NULL. `requested_user` is the PAM user that initiated authentication
     * (typically from pam_get_user()). `out_mapped_user` is an output: when
     * cfg->map_field is configured AND verification succeeds, *out_mapped_user
     * is set to a freshly malloc'd, NUL-terminated copy of the mapped claim
     * value. The caller owns it and must release it with free(). When
     * map_field is not configured the field is set to NULL.
     *
     * Username BINDING is always required -- there is no "verify the
     * signature and call it a day" mode. The bound claim is selected as
     * follows:
     *
     *   - When cfg->match_field is set, the verifier reads that claim and
     *     requires it to equal `requested_user`. The claim must be present
     *     and non-empty.
     *   - When cfg->match_field is unset, the verifier falls back to the
     *     JWT standard "sub" claim (RFC 7519) and requires it to equal
     *     `requested_user`. The claim must be present and non-empty.
     *
     * In both cases a missing or empty bound claim, or one that does not
     * equal `requested_user`, is rejected with PAM_USER_UNKNOWN. Binding
     * is checked BEFORE mapping so a misconfigured deployment fails closed
     * rather than silently substituting the user.
     *
     * If cfg->map_field is configured AND cfg->fallback_user is configured
     * AND the token does not carry a usable mapped claim (missing, non-
     * string, or empty), *out_mapped_user is populated with a freshly
     * malloc'd copy of cfg->fallback_user instead of the verifier failing.
     * In that case the mapped-user check is still satisfied (PAM_SUCCESS),
     * but binding via the rule above (match_field or sub) continues to
     * compare the requested user against the corresponding claim value --
     * the fallback does NOT participate in the binding check.
     *
     * Return codes follow the Linux-PAM convention:
     *   - PAM_SUCCESS (0): authentication succeeds
     *   - PAM_AUTH_ERR: signature invalid, alg rejected, claim mismatch,
     *                   expired/not-yet-valid, malformed token, ...
     *   - PAM_USER_UNKNOWN: the bound claim (match_field, or "sub" as a
     *                      fallback) is missing, empty, or does not equal
     *                      `requested_user`
     *   - PAM_SERVICE_ERR: configuration error (missing cert_file), cert
     *                     load failure, OOM
     *   - PAM_BUF_ERR: memory allocation failure inside libjwt
     *
     * The function NEVER logs the token, the authtok, or any private-key
     * material. */
    int pam_jwt_verify(pam_handle_t *pamh, const struct pam_jwt_cfg *cfg,
                       const char *token, const char *requested_user,
                       char **out_mapped_user);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PAM_JWT_H */
