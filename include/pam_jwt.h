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

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum length of any string option taken from PAM args (e.g. file paths,
 * claim names, issuer/audience values). Keep generous but bounded so that
 * configuration parsing never overflows. */
#define PAM_JWT_MAX_OPT_LEN 1024

/* Module configuration. All pointer fields are owned by the cfg and must
 * be released via pam_jwt_cfg_free(). Strings are NUL-terminated; the
 * optional fields are NULL when not configured. */
struct pam_jwt_cfg {
    char *cert_file;        /* required: path to issuer X.509 cert (PEM) */
    char *issuer;           /* optional: required value of "iss" claim */
    char *audience;         /* optional: required value of "aud" claim */
    char *map_field;        /* optional: claim name to set PAM user from */
    char *match_field;      /* optional: claim name required to equal user */
    int   clock_skew;       /* optional: leeway in seconds for exp/nbf */
    bool  debug;            /* optional: enable pam_syslog debug logging */
};

/* Result of parsing PAM argc/argv. */
enum pam_jwt_cfg_status {
    PAM_JWT_CFG_OK = 0,
    PAM_JWT_CFG_E_MISSING_REQUIRED,  /* required arg (cert_file) missing */
    PAM_JWT_CFG_E_INVALID_VALUE,     /* malformed arg value */
    PAM_JWT_CFG_E_DUPLICATE,         /* arg given more than once */
    PAM_JWT_CFG_E_OOM,               /* allocation failure */
    PAM_JWT_CFG_E_INTERNAL           /* unexpected internal error */
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

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PAM_JWT_H */
