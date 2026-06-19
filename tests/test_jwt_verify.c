/*
 * tests/test_jwt_verify.c
 *
 * Unit tests for src/jwt_verify.c: pam_jwt_load_cert() and
 * pam_jwt_verify(). The verifier covers the bulk of the security-critical
 * behavior of pam-jwt so this file is the largest test group in the
 * suite.
 *
 * Coverage targets (from AGENTS.md / plans/plan.md):
 *
 *   1. Cert + signature:
 *      - load RSA cert -> key_type == PAM_JWT_KEY_RSA
 *      - load EC cert  -> key_type == PAM_JWT_KEY_EC
 *      - load missing file -> failure
 *      - load directory -> failure
 *      - load non-cert PEM (private key file) -> failure
 *      - valid RS256 token verifies
 *      - valid ES256 token verifies
 *      - tampered signature rejected
 *      - token signed by wrong key rejected
 *      - alg=none rejected
 *
 *   2. Claims:
 *      - iss match -> success
 *      - iss mismatch -> PAM_AUTH_ERR
 *      - iss configured but missing in token -> PAM_AUTH_ERR
 *      - iss not configured and missing -> success
 *      - aud match/mismatch/missing analogous to iss
 *      - expired token rejected
 *      - not-yet-valid token rejected
 *      - clock_skew rescues a just-expired / just-not-yet-valid token
 *
 *   3. Usernames:
 *      - map_field sets *out_mapped_user
 *      - map_field missing claim -> PAM_AUTH_ERR
 *      - match_field equal -> success
 *      - match_field mismatch -> PAM_USER_UNKNOWN
 *      - both off -> no mapping, no binding
 *      - both on and consistent -> success with mapped user
 *      - both on and inconsistent -> PAM_USER_UNKNOWN
 *
 * Fixtures are produced by tests/fixtures/gen_certs.sh and the JWTs are
 * minted on demand by tests/fixtures/make_jwt. Both are invoked through
 * popen() so the test process never holds a private key in memory.
 */

#include "test.h"
#include "pam_jwt.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <linux/limits.h>

/* --- paths & helpers ------------------------------------------------------- */

#ifndef FIX_DIR
/* The Makefile passes -DFIX_DIR=... into the CFLAGS for this file. We
 * fall back to the relative path so the test still runs when the file
 * is compiled manually. */
#define FIX_DIR "tests/fixtures"
#endif
#ifndef MAKE_JWT
#define MAKE_JWT "tests/fixtures/make_jwt"
#endif

#define RSA_CERT FIX_DIR "/rsa_issuer.pem"
#define RSA_KEY FIX_DIR "/rsa_issuer.key"
#define EC_CERT FIX_DIR "/ec_issuer.pem"
#define EC_KEY FIX_DIR "/ec_issuer.key"
#define OTHER_RSA_CERT FIX_DIR "/other_rsa.pem"
#define OTHER_RSA_KEY FIX_DIR "/other_rsa.key"

/* Append `extra` to the run-time PATH so child processes (popen) can
 * find binaries the Makefile places in build/. */
static void ensure_path(void)
{
    /* Look for "build/" by scanning $PWD, then by searching upward. */
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
 * or an empty pipe; on success the caller owns the malloc'd buffer. */
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

/* Build a `make_jwt` invocation and return its stdout. The argument
 * list is read until a NULL sentinel; the sentinel is NOT forwarded
 * to make_jwt. Cap is 64 args which is well above what any test needs. */
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

/* Build a minimal cfg with just cert_file pointing at `cert`. The caller
 * may overlay additional options before passing it to pam_jwt_verify. */
static struct pam_jwt_cfg make_cfg(const char *cert)
{
    struct pam_jwt_cfg cfg;
    pam_jwt_cfg_init(&cfg);
    cfg.cert_file = pam_jwt_strdup(cert);
    return cfg;
}

/* Convenience wrapper around pam_jwt_verify that takes a literal mapped
 * pointer the test owns; frees any heap-owned cfg strings it created. */
static int verify(const struct pam_jwt_cfg *cfg, const char *token,
                  const char *user, char **out_mapped)
{
    if (out_mapped != NULL)
    {
        *out_mapped = NULL;
    }
    return pam_jwt_verify(NULL, cfg, token, user, out_mapped);
}

/* --- TEST_GROUP ------------------------------------------------------------ */

TEST_GROUP(jwt_verify)
{
    /* pam_jwt_load_cert / pam_jwt_verify -- cert loading. */
    TEST("load_cert: RSA cert -> RSA key type, non-empty PEM")
    {
        char *pem = NULL;
        size_t len = 0;
        enum pam_jwt_key_type kt = PAM_JWT_KEY_NONE;
        bool ok = pam_jwt_load_cert(RSA_CERT, &pem, &len, &kt);
        ASSERT_TRUE(ok);
        ASSERT_TRUE(pem != NULL);
        ASSERT_TRUE(len > 0);
        ASSERT_INT_EQ((int)kt, (int)PAM_JWT_KEY_RSA);
        /* Must look like a PEM-encoded public key. We don't pin to a
         * specific PEM armor string because OpenSSL versions may emit
         * different headers ("PUBLIC KEY" vs "RSA PUBLIC KEY"), but
         * BEGIN/END markers are universal. */
        ASSERT_TRUE(strstr(pem, "BEGIN") != NULL);
        ASSERT_TRUE(strstr(pem, "END") != NULL);
        free(pem);
    }

    TEST("load_cert: EC cert -> EC key type")
    {
        char *pem = NULL;
        size_t len = 0;
        enum pam_jwt_key_type kt = PAM_JWT_KEY_NONE;
        bool ok = pam_jwt_load_cert(EC_CERT, &pem, &len, &kt);
        ASSERT_TRUE(ok);
        ASSERT_TRUE(pem != NULL);
        ASSERT_TRUE(len > 0);
        ASSERT_INT_EQ((int)kt, (int)PAM_JWT_KEY_EC);
        free(pem);
    }

    TEST("load_cert: missing file -> failure")
    {
        char *pem = NULL;
        size_t len = 99;
        enum pam_jwt_key_type kt = PAM_JWT_KEY_RSA;
        bool ok = pam_jwt_load_cert(FIX_DIR "/does-not-exist.pem",
                                    &pem, &len, &kt);
        ASSERT_TRUE(!ok);
        ASSERT_TRUE(pem == NULL);
        ASSERT_INT_EQ((int)len, 0);
        ASSERT_INT_EQ((int)kt, (int)PAM_JWT_KEY_NONE);
    }

    TEST("load_cert: directory -> failure")
    {
        char *pem = (char *)0xdead;
        size_t len = 99;
        enum pam_jwt_key_type kt = PAM_JWT_KEY_RSA;
        bool ok = pam_jwt_load_cert(FIX_DIR, &pem, &len, &kt);
        ASSERT_TRUE(!ok);
        ASSERT_TRUE(pem == NULL);
        ASSERT_INT_EQ((int)len, 0);
        ASSERT_INT_EQ((int)kt, (int)PAM_JWT_KEY_NONE);
    }

    TEST("load_cert: non-cert PEM (private key file) -> failure")
    {
        char *pem = (char *)0xdead;
        size_t len = 99;
        enum pam_jwt_key_type kt = PAM_JWT_KEY_RSA;
        bool ok = pam_jwt_load_cert(RSA_KEY, &pem, &len, &kt);
        ASSERT_TRUE(!ok);
        ASSERT_TRUE(pem == NULL);
        ASSERT_INT_EQ((int)len, 0);
        ASSERT_INT_EQ((int)kt, (int)PAM_JWT_KEY_NONE);
    }

    TEST("load_cert: NULL outputs are safe and produce false")
    {
        ASSERT_TRUE(!pam_jwt_load_cert(RSA_CERT, NULL, NULL, NULL));
    }

    /* --- signature verification ----------------------------------------- */

    TEST("verify: valid RS256 token verifies")
    {
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "anyone", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        ASSERT_INT_EQ(verify(&cfg, tok, "anyone", NULL), PAM_SUCCESS);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("verify: valid ES256 token verifies")
    {
        ensure_path();
        char *tok = make_token("--alg", "ES256", "--key", EC_KEY,
                               "--sub", "anyone", NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(EC_CERT);
        ASSERT_INT_EQ(verify(&cfg, tok, "anyone", NULL), PAM_SUCCESS);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("verify: wrong key (RSA cert vs RSA-signed-with-other) -> AUTH_ERR")
    {
        ensure_path();
        /* Sign with the OTHER RSA key, but present the rsa_issuer cert. */
        char *tok = make_token("--alg", "RS256", "--key", OTHER_RSA_KEY, NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        ASSERT_INT_EQ(verify(&cfg, tok, "anyone", NULL), PAM_AUTH_ERR);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("verify: alg=none is rejected")
    {
        ensure_path();
        /* alg=none means libjwt still encodes the token but jwt_decode
         * rejects it because we provide a non-NULL key. */
        char *tok = make_token("--alg", "none", "--key", RSA_KEY, NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        ASSERT_INT_EQ(verify(&cfg, tok, "anyone", NULL), PAM_AUTH_ERR);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("verify: alg-confusion (RS256 vs EC cert) -> AUTH_ERR")
    {
        ensure_path();
        /* Sign with RSA but verify against the EC cert. */
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY, NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(EC_CERT);
        ASSERT_INT_EQ(verify(&cfg, tok, "anyone", NULL), PAM_AUTH_ERR);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("verify: alg-confusion (ES256 vs RSA cert) -> AUTH_ERR")
    {
        ensure_path();
        char *tok = make_token("--alg", "ES256", "--key", EC_KEY, NULL);
        ASSERT_TRUE(tok != NULL);
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        ASSERT_INT_EQ(verify(&cfg, tok, "anyone", NULL), PAM_AUTH_ERR);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    TEST("verify: tampered signature -> AUTH_ERR")
    {
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY, NULL);
        ASSERT_TRUE(tok != NULL);
        /* Flip a byte in the middle of the signature segment, well
         * clear of the trailing base64 padding bits. base64url
         * encodes 3 input bytes as 4 chars, and the last input byte
         * of any base64url group whose input length is not a
         * multiple of 3 contributes only the high bits of the
         * final char -- the low bits are zero-padded and not part
         * of the signature, so flipping the very last char can
         * leave the signature byte-identical. We find the second
         * '.' (the boundary between payload and signature) and
         * toggle a char 4 positions past it, which lands squarely
         * inside a fully-decoded signature byte. */
        const char *sig = strchr(tok, '.');
        ASSERT_TRUE(sig != NULL);
        sig = strchr(sig + 1, '.');
        ASSERT_TRUE(sig != NULL);
        char *target = (char *)sig + 4;
        *target = (*target == 'A') ? 'B' : 'A';
        struct pam_jwt_cfg cfg = make_cfg(RSA_CERT);
        ASSERT_INT_EQ(verify(&cfg, tok, "anyone", NULL), PAM_AUTH_ERR);
        pam_jwt_cfg_free(&cfg);
        free(tok);
    }

    /* Claims (iss/aud/exp/nbf/clock_skew) and usernames (map_field /
     * match_field) are covered in tests/test_claims.c and
     * tests/test_users.c respectively -- this group focuses on the
     * cert-loading and signature-verification paths. */
}
TEST_GROUP_END(jwt_verify)
