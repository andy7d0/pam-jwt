/*
 * tests/test_users.c
 *
 * Unit tests focused on username mapping and binding in
 * src/jwt_verify.c:
 *
 *   - map_field: sets *out_mapped_user from the configured claim
 *   - map_field: missing claim in token -> AUTH_ERR (or fallback_user)
 *   - map_field: empty claim value in token -> AUTH_ERR (or fallback_user)
 *   - fallback_user: substitutes for a missing/empty map_field claim
 *   - fallback_user: ignored when map_field claim is present and non-empty
 *   - fallback_user: does NOT participate in the binding check
 *   - match_field: equal to requested user -> success
 *   - match_field: mismatch -> PAM_USER_UNKNOWN
 *   - match_field: empty claim value in token -> USER_UNKNOWN (binding fails)
 *   - both on, consistent: success, mapped user populated
 *   - both on, inconsistent: PAM_USER_UNKNOWN (binding fires first)
 *   - map_field with match_field (sub-fallback): both checks pass when
 *     the bound claim and the map claim line up
 *
 * Username BINDING is always required. The bound claim is selected as
 *   - match_field, when configured; otherwise
 *   - the JWT standard "sub" claim.
 * The dedicated sub-fallback matrix (match, mismatch, empty, missing)
 * lives in this file too, so the implicit-binding guarantee gets the
 * same coverage as the explicit match_field path.
 *
 * The verifier handles the order: binding (match_field or sub) is
 * checked BEFORE mapping so a misconfigured deployment fails closed
 * with PAM_USER_UNKNOWN rather than silently substituting the user.
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
    /* --- map_field only --------------------------------------------------- *
     *
     * All map_field-only tests below carry a token whose `sub` matches
     * the requested user so the always-on binding step passes; the
     * tests then focus on the mapping step. The string "ignored" is
     * used as a sentinel requested user purely to flag "this test is
     * not exercising the binding step": a token with --sub=ignored
     * satisfies the binding without coupling the test to a real Unix
     * account name. */
    TEST("map_field: claim present -> mapped user populated")
    {
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "ignored",
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
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "ignored", NULL);
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
                               "--sub", "ignored",
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
                               "--sub", "ignored",
                               "--claim", "preferred_username=alice", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.map_field = pam_jwt_strdup("preferred_username");
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "ignored", NULL),
                      PAM_SUCCESS);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("map_field: requested user is bound via sub, mapped value is separate")
    {
        /* With match_field unset the verifier binds the requested user
         * against the JWT `sub` claim. map_field is independent: it
         * reads a different claim and hands it back to the caller.
         * The application is free to use the mapped name for whatever
         * purpose it wants; the binding check is not bypassed. */
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "bob",
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

    /* --- both off --------------------------------------------------------- *
     *
     * With both map_field and match_field unset, the binding step
     * still fires against the JWT `sub` claim (always-on binding).
     * These cases pin the contract: a token with a matching `sub`
     * succeeds with no mapping, and a token missing `sub` is
     * rejected with PAM_USER_UNKNOWN. */

    TEST("both off + matching sub: success, no mapping output")
    {
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "alice", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        char *mapped = (char *)0xdeadbeef;
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "alice", &mapped),
                      PAM_SUCCESS);
        ASSERT_TRUE(mapped == NULL);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("both off + no sub claim: USER_UNKNOWN")
    {
        ensure_path();
        /* No --sub flag -> the token has no `sub` claim. Without
         * match_field the verifier falls back to `sub`, finds it
         * missing, and rejects the request with PAM_USER_UNKNOWN.
         * The old "both off is fine" behaviour is no longer
         * supported: user matching is always required. */
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY, NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        char *mapped = (char *)0xdeadbeef;
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "alice", &mapped),
                      PAM_USER_UNKNOWN);
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

    /* --- fallback_user ----------------------------------------------------
     *
     * fallback_user only matters when map_field is set: the verifier
     * substitutes the configured string for the mapped claim when the
     * token omits (or empties) the claim. The substitution is a
     * mapping concern -- it never participates in the match_field
     * binding check.
     */

    TEST("fallback_user: missing claim -> success, mapped == fallback")
    {
        ensure_path();
        /* Token has no "preferred_username" claim at all. Without
         * fallback_user this would fail with PAM_AUTH_ERR; with it,
         * the verifier substitutes the configured string and succeeds.
         * The token still carries a `sub` so the always-on binding
         * step passes. */
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "ignored", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.map_field = pam_jwt_strdup("preferred_username");
        cfg.fallback_user = pam_jwt_strdup("service-acct");
        char *mapped = NULL;
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "ignored", &mapped),
                      PAM_SUCCESS);
        ASSERT_TRUE(mapped != NULL);
        ASSERT_STR_EQ(mapped, "service-acct");
        free(mapped);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("fallback_user: empty claim -> success, mapped == fallback")
    {
        ensure_path();
        /* Token carries the claim but the value is the empty string.
         * Without fallback_user this would fail with PAM_AUTH_ERR; with
         * it, the verifier substitutes the configured string. */
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "ignored",
                               "--claim", "preferred_username=", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.map_field = pam_jwt_strdup("preferred_username");
        cfg.fallback_user = pam_jwt_strdup("service-acct");
        char *mapped = (char *)0xdeadbeef;
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "ignored", &mapped),
                      PAM_SUCCESS);
        ASSERT_TRUE(mapped != NULL);
        ASSERT_STR_EQ(mapped, "service-acct");
        free(mapped);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("fallback_user: populated claim -> mapped == claim, NOT fallback")
    {
        ensure_path();
        /* When the token carries a non-empty claim, the verifier must
         * use it -- fallback_user is only consulted when the claim is
         * absent or empty. */
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "ignored",
                               "--claim", "preferred_username=alice", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.map_field = pam_jwt_strdup("preferred_username");
        cfg.fallback_user = pam_jwt_strdup("service-acct");
        char *mapped = NULL;
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "ignored", &mapped),
                      PAM_SUCCESS);
        ASSERT_TRUE(mapped != NULL);
        ASSERT_STR_EQ(mapped, "alice");
        free(mapped);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("fallback_user: ignored when map_field is unset")
    {
        /* Sanity check: with map_field off, fallback_user is dead
         * config -- the verifier never consults it, never sets a
         * mapped user, and the token still verifies (provided the
         * sub-fallback binding passes). */
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "alice", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.fallback_user = pam_jwt_strdup("service-acct");
        char *mapped = (char *)0xdeadbeef;
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "alice", &mapped),
                      PAM_SUCCESS);
        ASSERT_TRUE(mapped == NULL);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("fallback_user: match_field still binds even when fallback applies")
    {
        /* The fallback substitution does NOT participate in the
         * match_field binding. Here the token has no mapped claim
         * (so fallback_user wins for the mapped user) but the
         * match_field claim IS present and must still equal the
         * requested user. */
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "internal-id",
                               "--claim", "username=alice", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.map_field = pam_jwt_strdup("preferred_username");
        cfg.fallback_user = pam_jwt_strdup("service-acct");
        cfg.match_field = pam_jwt_strdup("username");
        char *mapped = (char *)0xdeadbeef;
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "alice", &mapped),
                      PAM_SUCCESS);
        ASSERT_TRUE(mapped != NULL);
        ASSERT_STR_EQ(mapped, "service-acct");
        free(mapped);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("fallback_user: match_field mismatch still rejects even when fallback applies")
    {
        /* Same as above but the binding fails: fallback_user must
         * NOT silently grant access when the match_field claim does
         * not equal the requested user. */
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "internal-id",
                               "--claim", "username=alice", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.map_field = pam_jwt_strdup("preferred_username");
        cfg.fallback_user = pam_jwt_strdup("service-acct");
        cfg.match_field = pam_jwt_strdup("username");
        char *mapped = (char *)0xdeadbeef;
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "bob", &mapped),
                      PAM_USER_UNKNOWN);
        ASSERT_TRUE(mapped == NULL);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    /* --- implicit sub-fallback binding -----------------------------------
     *
     * Username binding is ALWAYS enforced. When match_field is unset
     * the verifier falls back to the JWT standard `sub` claim (RFC
     * 7519) and requires it to equal the requested user. The cases
     * below pin the contract for the implicit binding path: success
     * on match, USER_UNKNOWN on mismatch / empty / missing.
     */

    TEST("sub-fallback binding: matching sub -> success, no mapping")
    {
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "alice", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        char *mapped = (char *)0xdeadbeef;
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "alice", &mapped),
                      PAM_SUCCESS);
        ASSERT_TRUE(mapped == NULL);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("sub-fallback binding: sub mismatch -> USER_UNKNOWN")
    {
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "alice", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        char *mapped = (char *)0xdeadbeef;
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "bob", &mapped),
                      PAM_USER_UNKNOWN);
        ASSERT_TRUE(mapped == NULL);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("sub-fallback binding: empty sub claim -> USER_UNKNOWN")
    {
        /* An empty `sub` claim is well-formed JSON but must NOT be
         * treated as a wildcard. A buggy IdP that wipes `sub` must
         * not accidentally match every requested user. */
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        char *mapped = (char *)0xdeadbeef;
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "alice", &mapped),
                      PAM_USER_UNKNOWN);
        ASSERT_TRUE(mapped == NULL);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("sub-fallback binding: missing sub claim -> USER_UNKNOWN")
    {
        /* No --sub flag at all. The verifier must reach for `sub`
         * and reject when it is absent. */
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY, NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        char *mapped = (char *)0xdeadbeef;
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "alice", &mapped),
                      PAM_USER_UNKNOWN);
        ASSERT_TRUE(mapped == NULL);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("sub-fallback binding: with map_field, sub still binds")
    {
        /* map_field is independent from binding. The bound claim
         * (sub, in this case) must equal the requested user AND
         * the mapped claim (preferred_username) is handed back to
         * the caller. Here the binding passes; mapping populates
         * *out_mapped_user with the mapped claim. */
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "id-1234",
                               "--claim", "preferred_username=alice", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.map_field = pam_jwt_strdup("preferred_username");
        char *mapped = NULL;
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "id-1234", &mapped),
                      PAM_SUCCESS);
        ASSERT_TRUE(mapped != NULL);
        ASSERT_STR_EQ(mapped, "alice");
        free(mapped);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("sub-fallback binding: with map_field, sub mismatch rejects")
    {
        /* As above but the requested user does not equal `sub`.
         * The verifier must fail closed with PAM_USER_UNKNOWN and
         * NOT leak the mapped claim to the caller. */
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "id-1234",
                               "--claim", "preferred_username=alice", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        cfg.map_field = pam_jwt_strdup("preferred_username");
        char *mapped = (char *)0xdeadbeef;
        ASSERT_INT_EQ(pam_jwt_verify(NULL, &cfg, tok, "evil", &mapped),
                      PAM_USER_UNKNOWN);
        ASSERT_TRUE(mapped == NULL);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }
}
TEST_GROUP_END(users)
