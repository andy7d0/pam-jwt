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
        char *cert_file;   /* required: path to issuer X.509 cert (PEM) */
        char *issuer;      /* optional: required value of "iss" claim */
        char *audience;    /* optional: required value of "aud" claim */
        char *map_field;   /* optional: claim name to set PAM user from */
        char *match_field; /* optional: claim name required to equal user */
        int clock_skew;    /* optional: leeway in seconds for exp/nbf */
        bool debug;        /* optional: enable pam_syslog debug logging */
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

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PAM_JWT_H */
