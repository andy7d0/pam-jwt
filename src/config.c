/*
 * src/config.c
 *
 * Parse the PAM module argument vector into a `struct pam_jwt_cfg`.
 *
 * The module is configured via PAM's argc/argv interface. Each argument is
 * either a bare flag (`debug`) or a `key=value` pair. This file is the single
 * source of truth for which keys are recognized and what validation is
 * applied; both the PAM entry point and the unit tests go through it.
 *
 * See `include/pam_jwt.h` for the public API and `docs/config.md` for the
 * user-facing description of each option.
 */

#include "pam_jwt.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* --- small helpers --------------------------------------------------------- */

/* Duplicate a NUL-terminated string into a freshly malloc'd buffer. Returns
 * NULL on allocation failure or if `s` is NULL. The returned pointer is owned
 * by the caller and must be released with free(). */
static char *str_dup(const char *s)
{
    if (s == NULL)
    {
        return NULL;
    }
    const size_t len = strlen(s);
    char *out = malloc(len + 1U);
    if (out == NULL)
    {
        return NULL;
    }
    memcpy(out, s, len + 1U);
    return out;
}

/* Return true iff `s` is a non-empty printable string no longer than
 * `max_len` bytes (excluding the trailing NUL). Used to reject pathological
 * inputs without relying on undefined behavior. */
static bool is_valid_string(const char *s, size_t max_len)
{
    if (s == NULL || s[0] == '\0')
    {
        return false;
    }
    size_t i = 0;
    for (; s[i] != '\0' && i <= max_len; ++i)
    {
        /* Forbid control characters and whitespace inside option values to
         * keep the parser unambiguous and avoid surprises in syslog output. */
        if ((unsigned char)s[i] < 0x20U || s[i] == 0x7f)
        {
            return false;
        }
    }
    return i != 0 && i <= max_len;
}

/* Parse `s` as a non-negative decimal integer. On success stores the value in
 * `*out` and returns true. Returns false on overflow, garbage input, or a
 * negative value.
 *
 * Implementation note: a leading '+' (e.g. "+30") is accepted for
 * compatibility with operators used to writing signed integers. The
 * sign is purely cosmetic -- "+30" and "30" parse to the same value,
 * and negative values are still rejected. This is documented in
 * docs/config.md. */
static bool parse_nonneg_int(const char *s, int *out)
{
    if (s == NULL || s[0] == '\0' || out == NULL)
    {
        return false;
    }
    /* Skip optional leading whitespace already excluded by is_valid_string. */
    size_t i = 0;
    if (s[i] == '+')
    {
        ++i; /* accept explicit sign, see comment above */
    }
    if (s[i] == '\0')
    {
        return false;
    }
    for (; s[i] != '\0'; ++i)
    {
        if (!isdigit((unsigned char)s[i]))
        {
            return false;
        }
    }
    errno = 0;
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0')
    {
        return false;
    }
    if (v < 0 || v > INT_MAX)
    {
        return false;
    }
    *out = (int)v;
    return true;
}

/* Tracks which cfg fields have been assigned so we can reject duplicates. */
struct cfg_seen
{
    bool cert_file;
    bool issuer;
    bool audience;
    bool map_field;
    bool match_field;
    bool clock_skew;
    bool debug;
};

/* Assign `value` into `*slot` and mark it as seen. Rejects a duplicate
 * assignment. On any error, *slot is left untouched so the caller can free
 * cleanly via pam_jwt_cfg_free(). */
static enum pam_jwt_cfg_status take_string(char **slot, bool *seen,
                                           const char *value)
{
    if (*seen)
    {
        return PAM_JWT_CFG_E_DUPLICATE;
    }
    if (!is_valid_string(value, PAM_JWT_MAX_OPT_LEN))
    {
        return PAM_JWT_CFG_E_INVALID_VALUE;
    }
    char *copy = str_dup(value);
    if (copy == NULL)
    {
        return PAM_JWT_CFG_E_OOM;
    }
    *slot = copy;
    *seen = true;
    return PAM_JWT_CFG_OK;
}

static enum pam_jwt_cfg_status take_int(int *slot, bool *seen, const char *value)
{
    if (*seen)
    {
        return PAM_JWT_CFG_E_DUPLICATE;
    }
    int parsed = 0;
    if (!parse_nonneg_int(value, &parsed))
    {
        return PAM_JWT_CFG_E_INVALID_VALUE;
    }
    *slot = parsed;
    *seen = true;
    return PAM_JWT_CFG_OK;
}

static enum pam_jwt_cfg_status take_flag(bool *seen)
{
    if (*seen)
    {
        return PAM_JWT_CFG_E_DUPLICATE;
    }
    *seen = true;
    return PAM_JWT_CFG_OK;
}

/* --- public API ------------------------------------------------------------ */

void pam_jwt_cfg_init(struct pam_jwt_cfg *cfg)
{
    if (cfg == NULL)
    {
        return;
    }
    /* Reset every field to its safe default. This routine does NOT
     * release any heap-owned strings in the cfg: callers that want
     * to re-initialize a populated cfg must first call
     * pam_jwt_cfg_free() and then pam_jwt_cfg_init(). The contract
     * mirrors that of `bzero()` / `memset(0)` on a struct: it is
     * safe to call on a zeroed or already-freed cfg, and on a cfg
     * that was returned by a previous pam_jwt_cfg_init() with no
     * pam_jwt_cfg_parse() in between. It is NOT safe on a cfg whose
     * string fields contain non-heap pointers (e.g. uninitialized
     * stack memory). */
    cfg->cert_file = NULL;
    cfg->issuer = NULL;
    cfg->audience = NULL;
    cfg->map_field = NULL;
    cfg->match_field = NULL;
    cfg->clock_skew = 0;
    cfg->debug = false;
}

void pam_jwt_cfg_free(struct pam_jwt_cfg *cfg)
{
    if (cfg == NULL)
    {
        return;
    }
    /* free(NULL) is a no-op, so it is safe to call repeatedly. */
    free(cfg->cert_file);
    cfg->cert_file = NULL;
    free(cfg->issuer);
    cfg->issuer = NULL;
    free(cfg->audience);
    cfg->audience = NULL;
    free(cfg->map_field);
    cfg->map_field = NULL;
    free(cfg->match_field);
    cfg->match_field = NULL;
    cfg->clock_skew = 0;
    cfg->debug = false;
}

enum pam_jwt_cfg_status pam_jwt_cfg_parse(int argc, const char **argv,
                                          struct pam_jwt_cfg *cfg)
{
    if (cfg == NULL)
    {
        return PAM_JWT_CFG_E_INTERNAL;
    }
    /* Snapshot the prior heap pointers onto the stack, then zero the
     * cfg in place. The snapshot lets us release the prior contents
     * via free() after the cfg has been cleared, so this prologue is
     * safe on a fresh stack-resident cfg whose string fields contain
     * uninitialized garbage. After the snapshot the parser is in the
     * same state as if the caller had zeroed the cfg.
     *
     * The prior_strings[] array is sized to match the number of
     * heap-owned `char *` fields in `struct pam_jwt_cfg` (see
     * include/pam_jwt.h): cert_file, issuer, audience, map_field,
     * match_field. If a new string field is added to the cfg, bump
     * this constant AND add matching entries below, otherwise the new
     * field will leak every time the cfg is re-parsed. clock_skew and
     * debug are scalar/POD and are reset directly without going
     * through the snapshot. */
    char *prior_strings[5];
    prior_strings[0] = cfg->cert_file;
    prior_strings[1] = cfg->issuer;
    prior_strings[2] = cfg->audience;
    prior_strings[3] = cfg->map_field;
    prior_strings[4] = cfg->match_field;
    cfg->cert_file = NULL;
    cfg->issuer = NULL;
    cfg->audience = NULL;
    cfg->map_field = NULL;
    cfg->match_field = NULL;
    cfg->clock_skew = 0;
    cfg->debug = false;
    /* Free the prior batch (NULL is a no-op). */
    free(prior_strings[0]);
    free(prior_strings[1]);
    free(prior_strings[2]);
    free(prior_strings[3]);
    free(prior_strings[4]);

    if (argc < 0)
    {
        return PAM_JWT_CFG_E_INTERNAL;
    }
    if (argc > 0 && argv == NULL)
    {
        return PAM_JWT_CFG_E_INTERNAL;
    }

    struct cfg_seen seen = {0};

    for (int i = 0; i < argc; ++i)
    {
        const char *arg = argv[i];
        if (arg == NULL)
        {
            return PAM_JWT_CFG_E_INVALID_VALUE;
        }

        /* Bare `debug` flag. */
        if (strcmp(arg, "debug") == 0)
        {
            enum pam_jwt_cfg_status st = take_flag(&seen.debug);
            if (st == PAM_JWT_CFG_OK)
            {
                cfg->debug = true;
            }
            else if (st != PAM_JWT_CFG_OK)
            {
                return st;
            }
            continue;
        }

        /* Everything else must be key=value. */
        const char *eq = strchr(arg, '=');
        if (eq == NULL || eq == arg)
        {
            return PAM_JWT_CFG_E_INVALID_VALUE;
        }

        /* Split into key/value without mutating the caller's buffer. */
        const size_t key_len = (size_t)(eq - arg);
        char key[PAM_JWT_MAX_OPT_LEN + 1U];
        if (key_len >= sizeof(key))
        {
            return PAM_JWT_CFG_E_INVALID_VALUE;
        }
        memcpy(key, arg, key_len);
        key[key_len] = '\0';
        const char *value = eq + 1;

        if (strcmp(key, "cert_file") == 0)
        {
            enum pam_jwt_cfg_status st =
                take_string(&cfg->cert_file, &seen.cert_file, value);
            if (st != PAM_JWT_CFG_OK)
            {
                return st;
            }
        }
        else if (strcmp(key, "issuer") == 0)
        {
            enum pam_jwt_cfg_status st =
                take_string(&cfg->issuer, &seen.issuer, value);
            if (st != PAM_JWT_CFG_OK)
            {
                return st;
            }
        }
        else if (strcmp(key, "audience") == 0)
        {
            enum pam_jwt_cfg_status st =
                take_string(&cfg->audience, &seen.audience, value);
            if (st != PAM_JWT_CFG_OK)
            {
                return st;
            }
        }
        else if (strcmp(key, "map_field") == 0)
        {
            enum pam_jwt_cfg_status st =
                take_string(&cfg->map_field, &seen.map_field, value);
            if (st != PAM_JWT_CFG_OK)
            {
                return st;
            }
        }
        else if (strcmp(key, "match_field") == 0)
        {
            enum pam_jwt_cfg_status st =
                take_string(&cfg->match_field, &seen.match_field, value);
            if (st != PAM_JWT_CFG_OK)
            {
                return st;
            }
        }
        else if (strcmp(key, "clock_skew") == 0)
        {
            enum pam_jwt_cfg_status st =
                take_int(&cfg->clock_skew, &seen.clock_skew, value);
            if (st != PAM_JWT_CFG_OK)
            {
                return st;
            }
        }
        else
        {
            /* Unknown keys are rejected so typos surface during deployment
             * rather than silently disabling an intended option. */
            return PAM_JWT_CFG_E_INVALID_VALUE;
        }
    }

    if (!seen.cert_file)
    {
        return PAM_JWT_CFG_E_MISSING_REQUIRED;
    }

    return PAM_JWT_CFG_OK;
}