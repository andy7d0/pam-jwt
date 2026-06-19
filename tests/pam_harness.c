/*
 * tests/pam_harness.c
 *
 * Integration tests for pam_jwt.so. These run the real PAM entry point
 * (`pam_sm_authenticate`) via libpam's `pam_start_confdir`, supplying a
 * conversation callback that hands the module a JWT as the password.
 *
 * The integration layer catches mistakes the unit tests can't:
 *
 *   - argv/argc parsing when wired through the PAM stack
 *   - mis-wired module argument quoting (commas, equals signs)
 *   - pam_get_user / pam_get_authtok return-code handling
 *   - the mapped-user promotion in pam_sm_setcred
 *
 * Each scenario builds a small pam.d-style service file in a tmpdir,
 * points pam_start_confdir at that dir, runs pam_authenticate, and
 * asserts the resulting PAM return code (and, where applicable, the
 * post-setcred PAM_USER value).
 *
 * The harness must NEVER log or print the JWT, the password, or any
 * private key material.
 */

#include "test.h"

#include <dlfcn.h>
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
#include <security/pam_modules.h>
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

/* Where pam_start_confdir looks up `<service>`. The directory layout
 * mirrors /etc/pam.d/, so we just point it at `build/pam.d` and drop
 * one file per scenario in there. */
#define PAMD_DIR "build/pam.d"

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
            snprintf(newpath, sizeof(newpath), "%s:%s", old, buf);
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

/* Build a `make_jwt` invocation and return its stdout. Variadic args
 * are concatenated verbatim into a shell-style command line; the
 * argument list MUST be terminated by a NULL sentinel. The sentinel
 * is not forwarded to make_jwt. */
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

    va_list ap;
    va_start(ap, arg0);
    /* arg0 is the first argument; iterate until we hit the NULL
     * sentinel that terminates the argument list. */
    const char *args[64];
    int n = 0;
    args[n++] = arg0;
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

/* --- per-test fixture: write a pam.d service file ------------------------ */

/* Write a pam.d-style service file that wires the `auth` stack to
 * pam_jwt.so with the given cfg args. The cfg string is passed through
 * verbatim, with each token space-separated. Returns 0 on success. */
static int write_service_file(const char *service, const char *cfg_args)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", PAMD_DIR, service);
    if (n < 0 || (size_t)n >= sizeof(path))
    {
        return -1;
    }
    /* Ensure the directory exists. mkdir -p semantics without a shell. */
    if (mkdir(PAMD_DIR, 0700) != 0 && errno != EEXIST)
    {
        return -1;
    }
    FILE *f = fopen(path, "w");
    if (f == NULL)
    {
        return -1;
    }
    /* Resolve the absolute path to the .so so libpam's module loader
     * can find it regardless of cwd. Relative paths inside a pam.d
     * rule are looked up against an unpredictable base. */
    const char *pwd = getenv("PWD");
    if (pwd == NULL)
    {
        pwd = ".";
    }
    char sopath[PATH_MAX];
    snprintf(sopath, sizeof(sopath), "%s/build/pam_jwt.so", pwd);
    fprintf(f,
            "# Auto-generated by tests/pam_harness.c for service %s\n"
            "auth required %s %s\n",
            service, sopath, cfg_args);
    fclose(f);
    return 0;
}

/* --- conversation callback ---------------------------------------------- */

/* We hand the conversation a fixed password (the JWT) for any prompt
 * the module issues. pam_jwt issues two prompts at most: pam_get_user
 * (which the service stack normally pre-fills) and pam_get_authtok
 * (the password / JWT). We respond to any prompt with the configured
 * response string. */
struct conv_state
{
    const char *response; /* what to return for any prompt */
};

static int conversation(int n, const struct pam_message **msg,
                        struct pam_response **resp, void *appdata_ptr)
{
    struct conv_state *st = (struct conv_state *)appdata_ptr;
    if (n <= 0)
    {
        return PAM_CONV_ERR;
    }
    *resp = calloc((size_t)n, sizeof(struct pam_response));
    if (*resp == NULL)
    {
        return PAM_BUF_ERR;
    }
    for (int i = 0; i < n; ++i)
    {
        int style = msg[i]->msg_style;
        (void)style; /* unused; we answer every style the same */
        if (st->response != NULL)
        {
            (*resp)[i].resp = strdup(st->response);
            if ((*resp)[i].resp == NULL)
            {
                /* Free whatever we already allocated and bail. */
                for (int j = 0; j < i; ++j)
                {
                    free((*resp)[j].resp);
                }
                free(*resp);
                *resp = NULL;
                return PAM_BUF_ERR;
            }
        }
        else
        {
            (*resp)[i].resp = NULL;
        }
    }
    return PAM_SUCCESS;
}

/* --- pam_start_confdir wrapper ------------------------------------------- */

/* Resolve pam_start_confdir dynamically so we don't need to link against
 * a specific libpam version. Returns NULL on failure. */
typedef int (*pam_start_confdir_fn)(const char *, const char *,
                                    const struct pam_conv *,
                                    const char *, pam_handle_t **);

static pam_start_confdir_fn resolve_pam_start_confdir(void)
{
    /* Clear any previous dlerror() state. */
    dlerror();
    void *h = dlopen("libpam.so.0", RTLD_LAZY | RTLD_GLOBAL);
    if (h == NULL)
    {
        return NULL;
    }
    pam_start_confdir_fn fn =
        (pam_start_confdir_fn)dlsym(h, "pam_start_confdir");
    return fn;
}

/* Drive one authentication scenario end-to-end. Returns the pam_authenticate()
 * result code (so the test can compare against the expected PAM_* value).
 * Optionally writes the post-setcred PAM_USER value into *out_user (a
 * malloc'd buffer owned by the caller; NULL if mapping was not applied). */
static int run_scenario(const char *service, const char *user,
                        const char *jwt, char **out_user)
{
    if (out_user != NULL)
    {
        *out_user = NULL;
    }
    static pam_start_confdir_fn start_fn = NULL;
    static int start_fn_resolved = 0;
    if (!start_fn_resolved)
    {
        start_fn = resolve_pam_start_confdir();
        start_fn_resolved = 1;
    }
    if (start_fn == NULL)
    {
        return PAM_SERVICE_ERR;
    }

    struct conv_state st = {.response = jwt};
    struct pam_conv conv = {.conv = conversation, .appdata_ptr = &st};

    pam_handle_t *pamh = NULL;
    int rc = start_fn(service, user, &conv, PAMD_DIR, &pamh);
    if (rc != PAM_SUCCESS || pamh == NULL)
    {
        return rc != 0 ? rc : PAM_SERVICE_ERR;
    }

    /* pam_authenticate dispatches into the auth stack, which (per our
     * generated service file) is just `pam_jwt.so required`. */
    int auth_rc = pam_authenticate(pamh, 0);

    if (auth_rc == PAM_SUCCESS && out_user != NULL)
    {
        /* Promote the optional mapped user (if any) and read it back. */
        (void)pam_setcred(pamh, PAM_ESTABLISH_CRED);
        const void *mapped_user = NULL;
        int drc = pam_get_data(pamh, "pam_jwt_mapped_user", &mapped_user);
        if (drc == PAM_SUCCESS && mapped_user != NULL)
        {
            *out_user = strdup((const char *)mapped_user);
        }
        else
        {
            /* Fall back to whatever PAM_USER was set to; this is what
             * applications actually see when no mapping was applied. */
            const char *u = NULL;
            if (pam_get_item(pamh, PAM_USER, (const void **)&u) == PAM_SUCCESS && u != NULL)
            {
                *out_user = strdup(u);
            }
        }
    }

    pam_end(pamh, auth_rc);
    return auth_rc;
}

/* Convenience: drive a scenario with NO request to capture mapped user. */
static int run_simple(const char *service, const char *user, const char *jwt)
{
    return run_scenario(service, user, jwt, NULL);
}

/* --- TEST_GROUP ---------------------------------------------------------- */

TEST_GROUP(pam_harness)
{
    /* All test tokens carry --sub=alice (or --sub=anyone for tests
     * that pass a different requested user) so the always-on binding
     * check does not short-circuit the case the test is targeting.
     * The dedicated sub-binding matrix lives in tests/test_users.c. */
    TEST("module loads and a valid RS256 token authenticates")
    {
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "alice", NULL);
        ASSERT_TRUE(tok != NULL);
        ASSERT_INT_EQ(write_service_file("pam_jwt_test_ok",
                                         "cert_file=" RSA_CERT),
                      0);
        ASSERT_INT_EQ(run_simple("pam_jwt_test_ok", "alice", tok),
                      PAM_SUCCESS);
        free(tok);
    }

    TEST("invalid signature is rejected with AUTH_ERR")
    {
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "alice", NULL);
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
        ASSERT_INT_EQ(write_service_file("pam_jwt_test_badsig",
                                         "cert_file=" RSA_CERT),
                      0);
        ASSERT_INT_EQ(run_simple("pam_jwt_test_badsig", "alice", tok),
                      PAM_AUTH_ERR);
        free(tok);
    }

    TEST("expired token is rejected with AUTH_ERR")
    {
        ensure_path();
        char exp[32];
        snprintf(exp, sizeof(exp), "%ld", 1000000000L);
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "alice",
                               "--exp", exp, NULL);
        ASSERT_TRUE(tok != NULL);
        ASSERT_INT_EQ(write_service_file("pam_jwt_test_expired",
                                         "cert_file=" RSA_CERT),
                      0);
        ASSERT_INT_EQ(run_simple("pam_jwt_test_expired", "alice", tok),
                      PAM_AUTH_ERR);
        free(tok);
    }

    TEST("missing cert_file produces SERVICE_ERR")
    {
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "alice", NULL);
        ASSERT_TRUE(tok != NULL);
        /* Empty arg list: parser must reject with PAM_SERVICE_ERR at the
         * entry point, never with a spurious AUTH_ERR. */
        ASSERT_INT_EQ(write_service_file("pam_jwt_test_nocert", ""), 0);
        ASSERT_INT_EQ(run_simple("pam_jwt_test_nocert", "alice", tok),
                      PAM_SERVICE_ERR);
        free(tok);
    }

    TEST("issuer mismatch -> AUTH_ERR through the stack")
    {
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "alice",
                               "--iss", "https://issuer.example", NULL);
        ASSERT_TRUE(tok != NULL);
        char cfg[256];
        snprintf(cfg, sizeof(cfg),
                 "cert_file=%s issuer=https://other.example", RSA_CERT);
        ASSERT_INT_EQ(write_service_file("pam_jwt_test_issmm", cfg), 0);
        ASSERT_INT_EQ(run_simple("pam_jwt_test_issmm", "alice", tok),
                      PAM_AUTH_ERR);
        free(tok);
    }

    TEST("match_field mismatch -> USER_UNKNOWN through the stack")
    {
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "alice",
                               "--claim", "username=alice", NULL);
        ASSERT_TRUE(tok != NULL);
        char cfg[256];
        snprintf(cfg, sizeof(cfg),
                 "cert_file=%s match_field=username", RSA_CERT);
        ASSERT_INT_EQ(write_service_file("pam_jwt_test_matchmm", cfg), 0);
        ASSERT_INT_EQ(run_simple("pam_jwt_test_matchmm", "bob", tok),
                      PAM_USER_UNKNOWN);
        free(tok);
    }

    TEST("map_field populates PAM_USER after setcred")
    {
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "alice",
                               "--claim", "preferred_username=alice", NULL);
        ASSERT_TRUE(tok != NULL);
        char cfg[256];
        snprintf(cfg, sizeof(cfg),
                 "cert_file=%s map_field=preferred_username", RSA_CERT);
        ASSERT_INT_EQ(write_service_file("pam_jwt_test_map", cfg), 0);
        char *user = NULL;
        int rc = run_scenario("pam_jwt_test_map", "alice", tok, &user);
        ASSERT_INT_EQ(rc, PAM_SUCCESS);
        ASSERT_TRUE(user != NULL);
        ASSERT_STR_EQ(user, "alice");
        free(user);
        free(tok);
    }

    TEST("match_field equal + map_field -> PAM_USER == mapped value")
    {
        ensure_path();
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "alice@example.com",
                               "--claim", "username=alice@example.com",
                               "--claim", "preferred_username=alice", NULL);
        ASSERT_TRUE(tok != NULL);
        char cfg[256];
        snprintf(cfg, sizeof(cfg),
                 "cert_file=%s match_field=username "
                 "map_field=preferred_username",
                 RSA_CERT);
        ASSERT_INT_EQ(write_service_file("pam_jwt_test_bindmap", cfg), 0);
        char *user = NULL;
        int rc = run_scenario("pam_jwt_test_bindmap", "alice@example.com",
                              tok, &user);
        ASSERT_INT_EQ(rc, PAM_SUCCESS);
        ASSERT_TRUE(user != NULL);
        ASSERT_STR_EQ(user, "alice");
        free(user);
        free(tok);
    }

    TEST("clock_skew=10 rescues just-expired token")
    {
        ensure_path();
        long now = (long)time(NULL);
        char exp[32];
        snprintf(exp, sizeof(exp), "%ld", now - 5L);
        char *tok = make_token("--alg", "RS256", "--key", RSA_KEY,
                               "--sub", "alice",
                               "--exp", exp, NULL);
        ASSERT_TRUE(tok != NULL);
        char cfg[256];
        snprintf(cfg, sizeof(cfg),
                 "cert_file=%s clock_skew=10", RSA_CERT);
        ASSERT_INT_EQ(write_service_file("pam_jwt_test_skew", cfg), 0);
        ASSERT_INT_EQ(run_simple("pam_jwt_test_skew", "alice", tok),
                      PAM_SUCCESS);
        free(tok);
    }

    TEST("empty authtok -> AUTH_ERR")
    {
        ensure_path();
        ASSERT_INT_EQ(write_service_file("pam_jwt_test_empty",
                                         "cert_file=" RSA_CERT),
                      0);
        ASSERT_INT_EQ(run_simple("pam_jwt_test_empty", "alice", ""),
                      PAM_AUTH_ERR);
    }
}
TEST_GROUP_END(pam_harness)
