/*
 * tests/test_claims.c
 *
 * Unit tests focused on JWT claim handling in src/jwt_verify.c:
 *
 *   - `iss` (issuer): configured / unconfigured, match, mismatch, missing.
 *   - `aud` (audience): same matrix as `iss`.
 *   - `exp` / `nbf`: expired, not-yet-valid, clock_skew leeway rescue.
 *
 * The cert+signature path is already exhaustively covered in
 * tests/test_jwt_verify.c; this group assumes a valid signature and
 * focuses on the claim-checking logic. Tokens are minted on demand by
 * tests/fixtures/make_jwt via popen() so no private key material lives
 * in this process.
 */

#include "test.h"
#include "pam_jwt.h"

#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <security/pam_appl.h>

/* --- paths & helpers ------------------------------------------------------- */

#ifndef FIX_DIR
/* The Makefile passes -DFIX_DIR=... into CFLAGS for the test files that
 * need to talk to the fixtures directory. Fall back to the canonical
 * relative path so the test still compiles when invoked manually. */
#define FIX_DIR "tests/fixtures"
#endif
#ifndef MAKE_JWT
#define MAKE_JWT "tests/fixtures/make_jwt"
#endif

#define RSA_CERT FIX_DIR "/rsa_issuer.pem"
#define RSA_KEY FIX_DIR "/rsa_issuer.key"

/* Ensure popen() can find the make_jwt binary the Makefile drops into
 * build/tests/fixtures/. We try a couple of plausible locations and
 * prepend the first one that exists to $PATH. */
static void ensure_path(void)
{
    const char *pwd = getenv("PWD");
    char buf[PATH_MAX];
    if (pwd == NULL)
    {
        pwd = ".";
    }
    snprintf(buf, sizeof(buf), "%s/build", pwd);
    struct stat st;
    if (stat(buf, &st) == 0 && S_ISDIR(st.st_mode))
    {
        const char *old = getenv("PATH");
        char newpath[PATH_MAX * 2];
        if (old != NULL)
        {
            snprintf(newpath, sizeof(newpath), "%s:%s", buf, old);
        }
        else
        {
            snprintf(newpath, sizeof(newpath), "%s", buf);
        }
        setenv("PATH", newpath, 1);
    }
}

/* Read all of stdout from a popen()'d command. Returns NULL on failure
 * or non-zero exit; on success the caller owns the malloc'd buffer. */
static char *popen_capture(const char *cmd)
{
    FILE *p = popen(cmd, "re");
    if (p == NULL)
    {
        return NULL;
    }
    size_t cap = 4096;
    size_t len = 0;
    char *out = malloc(cap);
    if (out == NULL)
    {
        pclose(p);
        return NULL;
    }
    for (;;)
    {
        if (len + 1U >= cap)
        {
            size_t newcap = cap * 2U;
            char *nb = realloc(out, newcap);
            if (nb == NULL)
            {
                free(out);
                pclose(p);
                return NULL;
            }
            out = nb;
            cap = newcap;
        }
        size_t got = fread(out + len, 1U, cap - len - 1U, p);
        if (got == 0)
        {
            break;
        }
        len += got;
    }
    out[len] = '\0';
    int rc = pclose(p);
    if (rc != 0)
    {
        free(out);
        return NULL;
    }
    return out;
}

/* Build a `make_jwt` invocation and return its stdout. Variadic so each
 * test only declares the flags it actually needs. */
static char *make_token(const char *arg0, ...)
{
    char cmd[8192];
    size_t off = 0;
    int rc = snprintf(cmd + off, sizeof(cmd) - off, "%s", MAKE_JWT);
    if (rc < 0 || (size_t)rc >= sizeof(cmd) - off)
    {
        return NULL;
    }
    off += (size_t)rc;

    const char *args[64];
    int n = 0;
    args[n++] = arg0;
    va_list ap;
    va_start(ap, arg0);
    while (n < (int)(sizeof(args) / sizeof(args[0])))
    {
        const char *a = va_arg(ap, const char *);
        if (a == NULL)
        {
            break;
        }
        args[n++] = a;
    }
    va_end(ap);

    for (int i = 0; i < n; ++i)
    {
        rc = snprintf(cmd + off, sizeof(cmd) - off, " '%s'", args[i]);
        if (rc < 0 || (size_t)rc >= sizeof(cmd) - off)
        {
            return NULL;
        }
        off += (size_t)rc;
    }

    return popen_capture(cmd);
}

/* --- cfg helpers ----------------------------------------------------------- */

static struct pam_jwt_cfg make_cfg(const char *cert)
{
    struct pam_jwt_cfg cfg;
    pam_jwt_cfg_init(&cfg);
    cfg.cert_file = pam_jwt_strdup(cert);
    return cfg;
}

/* --- TEST_GROUP ------------------------------------------------------------ */

TEST_GROUP(claims)
{
    /* --- iss --------------------------------------------------------------- */

    TEST("iss: match -> success")
    {
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--iss", "https://issuer.example", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.issuer = pam_jwt_strdup("https://issuer.example");
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "anyone", NULL),
                      PAM_SUCCESS);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("iss: mismatch -> AUTH_ERR")
    {
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--iss", "https://issuer.example", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.issuer = pam_jwt_strdup("https://evil.example");
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "anyone", NULL),
                      PAM_AUTH_ERR);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("iss: configured but missing in token -> AUTH_ERR")
    {
        ensure_path();
        /* No --iss flag -> token has no iss claim. */
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY, NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.issuer = pam_jwt_strdup("https://issuer.example");
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "anyone", NULL),
                      PAM_AUTH_ERR);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("iss: not configured and missing -> success")
    {
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY, NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "anyone", NULL),
                      PAM_SUCCESS);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("iss: not configured but present -> success (informational only)")
    {
        ensure_path();
        /* If the operator chose not to enforce `iss`, the presence of
         * the claim must not cause a failure -- it's purely informational
         * to whoever inspects the token later. */
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--iss", "https://anywhere.example", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "anyone", NULL),
                      PAM_SUCCESS);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    /* --- aud --------------------------------------------------------------- */

    TEST("aud: match -> success")
    {
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--aud", "my-service", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.audience = pam_jwt_strdup("my-service");
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "anyone", NULL),
                      PAM_SUCCESS);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("aud: mismatch -> AUTH_ERR")
    {
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--aud", "my-service", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.audience = pam_jwt_strdup("other-service");
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "anyone", NULL),
                      PAM_AUTH_ERR);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("aud: configured but missing in token -> AUTH_ERR")
    {
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY, NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.audience = pam_jwt_strdup("my-service");
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "anyone", NULL),
                      PAM_AUTH_ERR);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("aud: not configured and missing -> success")
    {
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY, NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "anyone", NULL),
                      PAM_SUCCESS);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    /* --- exp / nbf -------------------------------------------------------- */

    TEST("exp: expired token -> AUTH_ERR")
    {
        ensure_path();
        /* 10^9 s ~= Sep 2001. Far enough in the past to be robust against
         * any clock drift the runner might have. */
        char exp[32];
        snprintf(exp, sizeof(exp), "%ld", 1000000000L);
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--exp", exp, NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "anyone", NULL),
                      PAM_AUTH_ERR);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("nbf: not-yet-valid token -> AUTH_ERR")
    {
        ensure_path();
        /* 10^10 s ~= year 2286. Well past any plausible wall clock. */
        char nbf[32];
        snprintf(nbf, sizeof(nbf), "%ld", 10000000000L);
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--nbf", nbf, NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "anyone", NULL),
                      PAM_AUTH_ERR);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("clock_skew: rescues a just-expired token")
    {
        ensure_path();
        /* Token expired 5s ago; cfg clock_skew=10 must accept it. */
        long now = (long)time(NULL);
        char exp[32];
        snprintf(exp, sizeof(exp), "%ld", now - 5L);
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--exp", exp, NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.clock_skew = 10;
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "anyone", NULL),
                      PAM_SUCCESS);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("clock_skew: rejects a far-expired token")
    {
        ensure_path();
        char exp[32];
        snprintf(exp, sizeof(exp), "%ld", 1000000000L);
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--exp", exp, NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.clock_skew = 60; /* 1 minute cannot rescue 25 years */
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "anyone", NULL),
                      PAM_AUTH_ERR);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("clock_skew: rescues a token that is just-not-yet-valid")
    {
        ensure_path();
        /* nbf = now + 5s; cfg clock_skew=10 must accept it. */
        long now = (long)time(NULL);
        char nbf[32];
        snprintf(nbf, sizeof(nbf), "%ld", now + 5L);
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--nbf", nbf, NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.clock_skew = 10;
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "anyone", NULL),
                      PAM_SUCCESS);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("clock_skew: default (0) does NOT rescue even a 1s expired token")
    {
        ensure_path();
        /* Token expired 1s ago. With clock_skew=0 (default) this must
         * fail; the operator must opt into leeway explicitly. */
        long now = (long)time(NULL);
        char exp[32];
        snprintf(exp, sizeof(exp), "%ld", now - 1L);
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--exp", exp, NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "anyone", NULL),
                      PAM_AUTH_ERR);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("iss + aud: both configured, both match -> success")
    {
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--iss", "https://issuer.example",
                               "--aud", "my-service", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.issuer = pam_jwt_strdup("https://issuer.example");
        cfg.audience = pam_jwt_strdup("my-service");
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "anyone", NULL),
                      PAM_SUCCESS);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("iss + aud: iss matches but aud missing -> AUTH_ERR")
    {
        ensure_path();
        /* aud present in token, but cfg expects a different value. */
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--iss", "https://issuer.example",
                               "--aud", "my-service", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.issuer = pam_jwt_strdup("https://issuer.example");
        cfg.audience = pam_jwt_strdup("other-service");
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "anyone", NULL),
                      PAM_AUTH_ERR);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }
}
TEST_GROUP_END(claims)
