/*
 * tests/test_users.c
 *
 * Unit tests focused on username mapping and binding in
 * src/jwt_verify.c:
 *
 *   - map_field: sets *out_mapped_user from the configured claim
 *   - map_field: missing claim in token -> AUTH_ERR
 *   - map_field: empty claim value in token -> AUTH_ERR (no empty PAM_USER)
 *   - match_field: equal to requested user -> success
 *   - match_field: mismatch -> PAM_USER_UNKNOWN
 *   - match_field: empty claim value in token -> USER_UNKNOWN (binding fails)
 *   - both off: verification succeeds with no mapping
 *   - both on, consistent: success, mapped user populated
 *   - both on, inconsistent: PAM_USER_UNKNOWN (binding fires first)
 *   - map_field with no match_field: ignore requested user
 *   - match_field with no map_field: requested user enforced, no output
 *
 * The verifier handles the order: match_field is checked BEFORE map_field
 * so a misconfigured deployment fails closed with PAM_USER_UNKNOWN
 * rather than silently substituting the user.
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
#include <linux/limits.h>

/* --- paths & helpers ------------------------------------------------------- */

#ifndef FIX_DIR
#define FIX_DIR "tests/fixtures"
#endif
#ifndef MAKE_JWT
#define MAKE_JWT "tests/fixtures/make_jwt"
#endif

#define RSA_CERT FIX_DIR "/rsa_issuer.pem"
#define RSA_KEY FIX_DIR "/rsa_issuer.key"

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

static struct pam_jwt_cfg make_cfg(const char *cert)
{
    struct pam_jwt_cfg cfg;
    pam_jwt_cfg_init(&cfg);
    cfg.cert_file = pam_jwt_strdup(cert);
    return cfg;
}

/* --- TEST_GROUP ------------------------------------------------------------ */

TEST_GROUP(users)
{
    /* --- map_field only --------------------------------------------------- */

    TEST("map_field: claim present -> mapped user populated")
    {
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "internal-id",
                               "--claim", "preferred_username=alice", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.map_field = pam_jwt_strdup("preferred_username");
        char *mapped = NULL;
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "ignored", &mapped),
                      PAM_SUCCESS);
        ASSERT_TRUE(mapped != NULL);
        ASSERT_STR_EQ(mapped, "alice");
        free(mapped);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("map_field: missing claim -> AUTH_ERR, *out_mapped = NULL")
    {
        ensure_path();
        /* Token has no "preferred_username" claim. */
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY, NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.map_field = pam_jwt_strdup("preferred_username");
        char *mapped = (char *)0xdeadbeef;
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "ignored", &mapped),
                      PAM_AUTH_ERR);
        ASSERT_TRUE(mapped == NULL);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("map_field: empty claim value -> AUTH_ERR, *out_mapped = NULL")
    {
        /* docs/config.md says the mapped claim must be non-empty. A
         * token whose map_field claim is an empty string is well-
         * formed JSON but must NOT be promoted to PAM_USER as "".
         * The verifier rejects it with PAM_AUTH_ERR so the failure
         * is symmetric with the missing-claim path and we never
         * surface an empty username to setcred. */
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--claim", "preferred_username=", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.map_field = pam_jwt_strdup("preferred_username");
        char *mapped = (char *)0xdeadbeef;
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "ignored", &mapped),
                      PAM_AUTH_ERR);
        ASSERT_TRUE(mapped == NULL);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("map_field: empty claim value, match_field also on -> AUTH_ERR (not USER_UNKNOWN)")
    {
        /* When both map_field and match_field are configured and the
         * map_field claim is empty, the verifier must reject at the
         * mapping step (PAM_AUTH_ERR) rather than fall through to
         * the binding check, which would surface a misleading
         * PAM_USER_UNKNOWN. Order is: match_field first, then
         * map_field, so an empty match_field claim still triggers
         * the binding path -- here we leave match_field's claim
         * non-empty so the binding passes and only the empty
         * map_field can fire. */
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "internal-id",
                               "--claim", "username=alice",
                               "--claim", "preferred_username=", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.match_field = pam_jwt_strdup("username");
        cfg.map_field = pam_jwt_strdup("preferred_username");
        char *mapped = (char *)0xdeadbeef;
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "alice", &mapped),
                      PAM_AUTH_ERR);
        ASSERT_TRUE(mapped == NULL);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("map_field: claim present, out_mapped is NULL pointer")
    {
        /* When the caller passes NULL for out_mapped, mapping is
         * effectively off even though the cfg says it's on. The
         * verifier must still succeed; it just doesn't surface the
         * mapped name anywhere. */
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "internal-id",
                               "--claim", "preferred_username=alice", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.map_field = pam_jwt_strdup("preferred_username");
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "ignored", NULL),
                      PAM_SUCCESS);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("map_field: requested user is ignored")
    {
        /* map_field does not constrain `requested_user`; it only
         * reads a claim and hands it back. The application is then
         * free to compare the mapped name against the local user db. */
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--claim", "preferred_username=alice", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.map_field = pam_jwt_strdup("preferred_username");
        char *mapped = NULL;
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "bob", &mapped),
                      PAM_SUCCESS);
        ASSERT_TRUE(mapped != NULL);
        ASSERT_STR_EQ(mapped, "alice");
        free(mapped);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    /* --- match_field only ------------------------------------------------- */

    TEST("match_field: equal -> success")
    {
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "alice",
                               "--claim", "username=alice", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.match_field = pam_jwt_strdup("username");
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "alice", NULL),
                      PAM_SUCCESS);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("match_field: mismatch -> USER_UNKNOWN")
    {
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "alice",
                               "--claim", "username=alice", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.match_field = pam_jwt_strdup("username");
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "bob", NULL),
                      PAM_USER_UNKNOWN);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("match_field: claim missing in token -> USER_UNKNOWN")
    {
        ensure_path();
        /* Token has no `username` claim at all. */
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY, NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.match_field = pam_jwt_strdup("username");
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "alice", NULL),
                      PAM_USER_UNKNOWN);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("match_field: claim present but empty, requested user non-empty -> USER_UNKNOWN")
    {
        /* An empty `username` claim is well-formed (the verifier treats
         * it as a string) but cannot equal a non-empty requested user.
         * This guards against a token whose match_field claim is
         * accidentally wiped by a buggy IdP. */
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--claim", "username=", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.match_field = pam_jwt_strdup("username");
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "alice", NULL),
                      PAM_USER_UNKNOWN);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    /* --- both off --------------------------------------------------------- */

    TEST("both off: success, no mapping output")
    {
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY, NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        char *mapped = (char *)0xdeadbeef;
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "alice", &mapped),
                      PAM_SUCCESS);
        ASSERT_TRUE(mapped == NULL);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    /* --- both on, consistent / inconsistent ------------------------------ */

    TEST("both on, consistent -> success, mapped user populated")
    {
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "alice",
                               "--claim", "username=alice", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.map_field = pam_jwt_strdup("username");
        cfg.match_field = pam_jwt_strdup("username");
        char *mapped = NULL;
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "alice", &mapped),
                      PAM_SUCCESS);
        ASSERT_TRUE(mapped != NULL);
        ASSERT_STR_EQ(mapped, "alice");
        free(mapped);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("both on, inconsistent -> USER_UNKNOWN, *out_mapped stays NULL")
    {
        ensure_path();
        /* Token's username claim is "alice" but the request is for
         * "bob". The verifier must fail closed on the binding check
         * and NOT leak the mapped user to the caller. */
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "alice",
                               "--claim", "username=alice", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.map_field = pam_jwt_strdup("username");
        cfg.match_field = pam_jwt_strdup("username");
        char *mapped = (char *)0xdeadbeef;
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "bob", &mapped),
                      PAM_USER_UNKNOWN);
        ASSERT_TRUE(mapped == NULL);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    /* --- map + match use DIFFERENT claims -------------------------------- */

    TEST("map_field != match_field, both populated consistently -> success")
    {
        ensure_path();
        /* `username` is the identity used for binding, `preferred_username`
         * is the actual Unix account we want PAM to use. */
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "id-1234",
                               "--claim", "username=alice@example.com",
                               "--claim", "preferred_username=alice", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.map_field = pam_jwt_strdup("preferred_username");
        cfg.match_field = pam_jwt_strdup("username");
        char *mapped = NULL;
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok,
                                     "alice@example.com", &mapped),
                      PAM_SUCCESS);
        ASSERT_TRUE(mapped != NULL);
        ASSERT_STR_EQ(mapped, "alice");
        free(mapped);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("map_field != match_field, binding mismatch -> USER_UNKNOWN")
    {
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "id-1234",
                               "--claim", "username=alice@example.com",
                               "--claim", "preferred_username=alice", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.map_field = pam_jwt_strdup("preferred_username");
        cfg.match_field = pam_jwt_strdup("username");
        char *mapped = (char *)0xdeadbeef;
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok,
                                     "bob@example.com", &mapped),
                      PAM_USER_UNKNOWN);
        ASSERT_TRUE(mapped == NULL);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }
}
TEST_GROUP_END(users)
