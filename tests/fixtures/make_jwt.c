/*
 * tests/fixtures/make_jwt.c
 *
 * Tiny CLI helper that mints JWTs for the pam-jwt test suite. Built as a
 * standalone binary by the Makefile; not part of the test runner. It
 * speaks the same flags the unit tests need:
 *
 *   make_jwt --alg <RS256|ES256|none> --key <path>
 *             [--iss <s>] [--aud <s>] [--aud-json <json-array>]
 *             [--sub <s>]
 *             [--exp <unix-secs>] [--nbf <unix-secs>]
 *             [--claim key=value ...]
 *
 * Output: the encoded JWT on stdout (no trailing newline). Exit 0 on
 * success, non-zero on any failure.
 *
 * The claim flags let tests fabricate the specific shape of token they
 * need (mapping, binding, mismatch, expired, array-aud, ...) without
 * growing the helper into a small config language.
 *
 * --aud and --aud-json are mutually exclusive: --aud writes the aud
 * claim as a plain JSON string, --aud-json writes it as a JSON array
 * verbatim (used to test the array-audience code path in the verifier).
 */

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <jwt.h>

/* Small store for --claim k=v pairs. We keep them on the stack because the
 * argument strings outlive main()'s body, and we cap the count so a
 * runaway --claim list can't exhaust the stack. */
#define MAX_DEFERRED_CLAIMS 32
struct deferred_claim
{
    char *k;
    char *v;
};
static struct deferred_claim deferred[MAX_DEFERRED_CLAIMS];
static int deferred_count = 0;

/* Read an entire file into a freshly malloc'd, NUL-terminated buffer.
 * Caller frees with free(). Returns NULL on failure. */
static char *slurp(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL)
    {
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0)
    {
        fclose(f);
        return NULL;
    }
    long sz = ftell(f);
    if (sz < 0)
    {
        fclose(f);
        return NULL;
    }
    rewind(f);
    char *buf = malloc((size_t)sz + 1U);
    if (buf == NULL)
    {
        fclose(f);
        return NULL;
    }
    size_t got = fread(buf, 1U, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz)
    {
        free(buf);
        return NULL;
    }
    buf[sz] = '\0';
    return buf;
}

/* Look up an argv-style "--key value" pair starting at index `*i`. On
 * success advances `*i` past the value and returns the value pointer
 * (still owned by argv). On missing value returns NULL. */
static const char *arg_value(char *const argv[], int argc, int *i,
                             const char *flag)
{
    if (*i + 1 >= argc)
    {
        fprintf(stderr, "make_jwt: missing value for %s\n", flag);
        return NULL;
    }
    (*i)++;
    return argv[*i];
}

/* Parse "key=value" into two pieces by writing a NUL into the '='. The
 * returned pointers are owned by the input string. */
static bool split_kv(char *arg, char **key, char **val)
{
    char *eq = strchr(arg, '=');
    if (eq == NULL)
    {
        return false;
    }
    *eq = '\0';
    *key = arg;
    *val = eq + 1;
    return true;
}

/* Add a grant with either a string or integer value to the JWT. We try
 * integer parsing first; if that fails we fall back to string. */
static bool add_grant_auto(jwt_t *jwt, const char *name, const char *value)
{
    /* All-digit (with optional leading +) => integer. */
    size_t i = (value[0] == '+') ? 1U : 0U;
    bool is_int = value[i] != '\0';
    for (; value[i] != '\0'; ++i)
    {
        if (!isdigit((unsigned char)value[i]))
        {
            is_int = false;
            break;
        }
    }
    if (is_int)
    {
        char *end = NULL;
        errno = 0;
        long v = strtol(value, &end, 10);
        if (errno == 0 && end != value && *end == '\0')
        {
            return jwt_add_grant_int(jwt, name, v) == 0;
        }
    }
    return jwt_add_grant(jwt, name, value) == 0;
}

int main(int argc, char *argv[])
{
    const char *alg_str = "RS256";
    const char *key_path = NULL;
    const char *iss = NULL;
    const char *aud = NULL;
    const char *aud_json = NULL;
    const char *sub = NULL;
    long exp = 0;
    long nbf = 0;
    bool have_exp = false;
    bool have_nbf = false;

    /* Tracks which args we already saw so duplicates surface loudly. */
    bool saw_alg = false, saw_key = false, saw_iss = false, saw_aud = false;
    bool saw_aud_json = false;
    bool saw_sub = false, saw_exp = false, saw_nbf = false;

    if (argc < 2)
    {
        goto usage;
    }

    for (int i = 1; i < argc; ++i)
    {
        const char *a = argv[i];
        if (strcmp(a, "--alg") == 0)
        {
            if (saw_alg)
            {
                fprintf(stderr, "make_jwt: --alg given twice\n");
                return 2;
            }
            alg_str = arg_value(argv, argc, &i, "--alg");
            if (alg_str == NULL)
            {
                return 2;
            }
            saw_alg = true;
        }
        else if (strcmp(a, "--key") == 0)
        {
            if (saw_key)
            {
                fprintf(stderr, "make_jwt: --key given twice\n");
                return 2;
            }
            key_path = arg_value(argv, argc, &i, "--key");
            if (key_path == NULL)
            {
                return 2;
            }
            saw_key = true;
        }
        else if (strcmp(a, "--iss") == 0)
        {
            if (saw_iss)
            {
                fprintf(stderr, "make_jwt: --iss given twice\n");
                return 2;
            }
            iss = arg_value(argv, argc, &i, "--iss");
            if (iss == NULL)
            {
                return 2;
            }
            saw_iss = true;
        }
        else if (strcmp(a, "--aud") == 0)
        {
            if (saw_aud)
            {
                fprintf(stderr, "make_jwt: --aud given twice\n");
                return 2;
            }
            aud = arg_value(argv, argc, &i, "--aud");
            if (aud == NULL)
            {
                return 2;
            }
            saw_aud = true;
        }
        else if (strcmp(a, "--aud-json") == 0)
        {
            if (saw_aud_json)
            {
                fprintf(stderr, "make_jwt: --aud-json given twice\n");
                return 2;
            }
            aud_json = arg_value(argv, argc, &i, "--aud-json");
            if (aud_json == NULL)
            {
                return 2;
            }
            saw_aud_json = true;
        }
        else if (strcmp(a, "--sub") == 0)
        {
            if (saw_sub)
            {
                fprintf(stderr, "make_jwt: --sub given twice\n");
                return 2;
            }
            sub = arg_value(argv, argc, &i, "--sub");
            if (sub == NULL)
            {
                return 2;
            }
            saw_sub = true;
        }
        else if (strcmp(a, "--exp") == 0)
        {
            if (saw_exp)
            {
                fprintf(stderr, "make_jwt: --exp given twice\n");
                return 2;
            }
            const char *v = arg_value(argv, argc, &i, "--exp");
            if (v == NULL)
            {
                return 2;
            }
            exp = strtol(v, NULL, 10);
            have_exp = true;
            saw_exp = true;
        }
        else if (strcmp(a, "--nbf") == 0)
        {
            if (saw_nbf)
            {
                fprintf(stderr, "make_jwt: --nbf given twice\n");
                return 2;
            }
            const char *v = arg_value(argv, argc, &i, "--nbf");
            if (v == NULL)
            {
                return 2;
            }
            nbf = strtol(v, NULL, 10);
            have_nbf = true;
            saw_nbf = true;
        }
        else if (strcmp(a, "--claim") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "make_jwt: missing value for --claim\n");
                return 2;
            }
            i++;
            /* Defer the actual add: we need the jwt object below. */
            char *kv = argv[i];
            char *k = NULL;
            char *val = NULL;
            if (!split_kv(kv, &k, &val) || k[0] == '\0' || val == NULL)
            {
                fprintf(stderr, "make_jwt: --claim must be key=value\n");
                return 2;
            }
            /* Store as a small one-shot list by abusing argv ordering: we
             * just remember the position. */
            deferred_count++;
            if (deferred_count > 32)
            {
                fprintf(stderr, "make_jwt: too many --claim flags\n");
                return 2;
            }
            deferred[deferred_count - 1].k = k;
            deferred[deferred_count - 1].v = val;
        }
        else
        {
            fprintf(stderr, "make_jwt: unknown flag: %s\n", a);
            return 2;
        }
    }

    if (!saw_key)
    {
        fprintf(stderr, "make_jwt: --key is required\n");
        goto usage;
    }
    if (saw_aud && saw_aud_json)
    {
        fprintf(stderr, "make_jwt: --aud and --aud-json are mutually exclusive\n");
        return 2;
    }

    jwt_alg_t alg = jwt_str_alg(alg_str);
    if (alg == JWT_ALG_INVAL)
    {
        fprintf(stderr, "make_jwt: invalid --alg %s\n", alg_str);
        return 2;
    }

    char *key_pem = slurp(key_path);
    if (key_pem == NULL)
    {
        fprintf(stderr, "make_jwt: cannot read --key %s\n", key_path);
        return 1;
    }

    jwt_t *jwt = NULL;
    if (jwt_new(&jwt) != 0)
    {
        free(key_pem);
        fprintf(stderr, "make_jwt: jwt_new failed\n");
        return 1;
    }
    /* For alg=none libjwt requires a NULL key (no signing material). For
     * everything else we pass the PEM key bytes verbatim -- libjwt
     * understands both private (signing) and public (verifying) keys
     * for all the algorithms we care about. */
    const unsigned char *key_bytes =
        (alg == JWT_ALG_NONE) ? NULL : (const unsigned char *)key_pem;
    int key_len = (alg == JWT_ALG_NONE) ? 0 : (int)strlen(key_pem);
    if (jwt_set_alg(jwt, alg, key_bytes, key_len) != 0)
    {
        jwt_free(jwt);
        free(key_pem);
        fprintf(stderr, "make_jwt: jwt_set_alg failed\n");
        return 1;
    }

    if (iss != NULL && jwt_add_grant(jwt, "iss", iss) != 0)
    {
        goto jwt_err;
    }
    if (aud != NULL && jwt_add_grant(jwt, "aud", aud) != 0)
    {
        goto jwt_err;
    }
    if (aud_json != NULL)
    {
        /* libjwt's jwt_add_grants_json() requires a JSON object whose
         * top level is the claim hash, so wrap the user-supplied array
         * in {"aud": [...]}. The wrapper is built on the stack; the
         * combined length is bounded by the input plus a fixed prefix
         * and suffix, so a small buffer is enough. */
        size_t in_len = strlen(aud_json);
        if (in_len + 16U > 1024U)
        {
            fprintf(stderr, "make_jwt: --aud-json too long\n");
            goto jwt_err;
        }
        char wrapped[1024];
        int n = snprintf(wrapped, sizeof(wrapped),
                         "{\"aud\":%s}", aud_json);
        if (n < 0 || (size_t)n >= sizeof(wrapped))
        {
            fprintf(stderr, "make_jwt: --aud-json too long\n");
            goto jwt_err;
        }
        if (jwt_add_grants_json(jwt, wrapped) != 0)
        {
            fprintf(stderr, "make_jwt: invalid --aud-json (must be a JSON array)\n");
            goto jwt_err;
        }
    }
    if (sub != NULL && jwt_add_grant(jwt, "sub", sub) != 0)
    {
        goto jwt_err;
    }
    if (have_exp && jwt_add_grant_int(jwt, "exp", exp) != 0)
    {
        goto jwt_err;
    }
    if (have_nbf && jwt_add_grant_int(jwt, "nbf", nbf) != 0)
    {
        goto jwt_err;
    }
    for (int i = 0; i < deferred_count; ++i)
    {
        if (!add_grant_auto(jwt, deferred[i].k, deferred[i].v))
        {
            goto jwt_err;
        }
    }

    char *encoded = jwt_encode_str(jwt);
    if (encoded == NULL)
    {
        goto jwt_err;
    }
    fputs(encoded, stdout);
    /* jwt_encode_str returns a string the caller must release via
     * jwt_free_str(); that helper is the correct one for strings
     * produced by the library even though it ultimately calls free(). */
    jwt_free_str(encoded);
    jwt_free(jwt);
    /* Scrub the key material before freeing it. The key is held as a
     * PEM blob (a private key for the test signer); zeroing it before
     * free keeps any heap-inspection tools from picking up the secret. */
    memset(key_pem, 0, strlen(key_pem));
    free(key_pem);
    return 0;

jwt_err:
    jwt_free(jwt);
    memset(key_pem, 0, strlen(key_pem));
    free(key_pem);
    fprintf(stderr, "make_jwt: failed to assemble/encode JWT\n");
    return 1;

usage:
    fprintf(stderr,
            "usage: make_jwt --key <pem> [--alg RS256|ES256|none]\n"
            "                 [--iss S] [--aud S] [--aud-json <json-array>]\n"
            "                 [--sub S]\n"
            "                 [--exp N] [--nbf N]\n"
            "                 [--claim key=value ...]\n");
    return 2;
}
