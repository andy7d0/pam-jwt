/*
 * tests/test_config.c
 *
 * Unit tests for src/config.c: pam_jwt_cfg_parse() and the
 * pam_jwt_cfg_init() / pam_jwt_cfg_free() lifecycle.
 *
 * Coverage targets (from AGENTS.md):
 *   - every option (cert_file, issuer, audience, map_field,
 *     match_field, clock_skew, debug)
 *   - defaults when an option is omitted
 *   - duplicate detection
 *   - missing required (cert_file)
 *   - invalid values (empty, too long, control chars, non-numeric
 *     clock_skew, unknown keys, missing '=' separator, NULL inputs)
 *   - error path leaves cfg in a free()-safe state
 *
 * No fixtures, no network, no secrets. The parser is pure data-in /
 * data-out, so all tests are hermetic.
 */

#include "test.h"
#include "pam_jwt.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* --- helpers --------------------------------------------------------------- */

/* Build a fresh, mutable argv array on the heap. The strings themselves
 * are taken from `storage` which the caller owns. Returns NULL on OOM. */
static const char **make_argv(char *const *storage, int n)
{
    const char **argv = calloc((size_t)n, sizeof(*argv));
    if (argv == NULL)
    {
        return NULL;
    }
    for (int i = 0; i < n; ++i)
    {
        argv[i] = storage[i];
    }
    return argv;
}

/* Convenience: parse a fixed list of literal C strings. The strings are
 * read-only; the parser must not mutate them, and we pass them through
 * a const-correct argv. */
static enum pam_jwt_cfg_status parse_lits(struct pam_jwt_cfg *cfg,
                                          int n, const char *a0,
                                          const char *a1, const char *a2,
                                          const char *a3, const char *a4,
                                          const char *a5, const char *a6)
{
    const char *argv[7] = {a0, a1, a2, a3, a4, a5, a6};
    if (n < 0 || n > 7)
    {
        return PAM_JWT_CFG_E_INTERNAL;
    }
    return pam_jwt_cfg_parse(n, argv, cfg);
}

/* --- TEST_GROUP ------------------------------------------------------------ */

TEST_GROUP(config)
{
    /* init on a zeroed struct yields all NULLs and zero defaults. */
    TEST("init zeroes every field")
    {
        struct pam_jwt_cfg cfg;
        memset(&cfg, 0, sizeof(cfg));
        pam_jwt_cfg_init(&cfg);
        ASSERT_TRUE(cfg.cert_file == NULL);
        ASSERT_TRUE(cfg.issuer == NULL);
        ASSERT_TRUE(cfg.audience == NULL);
        ASSERT_TRUE(cfg.map_field == NULL);
        ASSERT_TRUE(cfg.match_field == NULL);
        ASSERT_INT_EQ(cfg.clock_skew, 0);
        ASSERT_TRUE(cfg.debug == false);

        /* free() on a freshly-init cfg must not crash and must remain
         * safe to call twice. */
        pam_jwt_cfg_free(&cfg);
        pam_jwt_cfg_free(&cfg);
        ASSERT_TRUE(cfg.cert_file == NULL);
    }

    TEST("init on NULL is a no-op")
    {
        /* Must not crash. If it does, the test process dies. */
        pam_jwt_cfg_init(NULL);
        pam_jwt_cfg_free(NULL);
        ASSERT_TRUE(1);
    }

    /* Minimal happy path: only cert_file. */
    TEST("minimal: only cert_file")
    {
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st =
            parse_lits(&cfg, 1, "cert_file=/etc/jwt/issuer.pem",
                       NULL, NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_OK);
        ASSERT_STR_EQ(cfg.cert_file, "/etc/jwt/issuer.pem");
        ASSERT_TRUE(cfg.issuer == NULL);
        ASSERT_TRUE(cfg.audience == NULL);
        ASSERT_TRUE(cfg.map_field == NULL);
        ASSERT_TRUE(cfg.match_field == NULL);
        ASSERT_INT_EQ(cfg.clock_skew, 0);
        ASSERT_TRUE(cfg.debug == false);
        pam_jwt_cfg_free(&cfg);
    }

    /* Every optional field, plus debug, in one go. */
    TEST("all options set at once")
    {
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 7,
            "cert_file=/etc/jwt/issuer.pem",
            "issuer=https://idp.example.com/",
            "audience=pam-login",
            "map_field=preferred_username",
            "match_field=uid",
            "clock_skew=30",
            "debug");
        ASSERT_INT_EQ(st, PAM_JWT_CFG_OK);
        ASSERT_STR_EQ(cfg.cert_file, "/etc/jwt/issuer.pem");
        ASSERT_STR_EQ(cfg.issuer, "https://idp.example.com/");
        ASSERT_STR_EQ(cfg.audience, "pam-login");
        ASSERT_STR_EQ(cfg.map_field, "preferred_username");
        ASSERT_STR_EQ(cfg.match_field, "uid");
        ASSERT_INT_EQ(cfg.clock_skew, 30);
        ASSERT_TRUE(cfg.debug == true);
        pam_jwt_cfg_free(&cfg);
    }

    /* No arguments at all -> missing required. */
    TEST("no args -> missing required")
    {
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_E_MISSING_REQUIRED);
        pam_jwt_cfg_free(&cfg);
    }

    TEST("only debug -> missing required")
    {
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st =
            parse_lits(&cfg, 1, "debug", NULL, NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_E_MISSING_REQUIRED);
        ASSERT_TRUE(cfg.debug == true);
        ASSERT_TRUE(cfg.cert_file == NULL);
        pam_jwt_cfg_free(&cfg);
    }

    /* Duplicate detection: one dup per duplicate-aware field. */
    TEST("duplicate cert_file")
    {
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 2, "cert_file=/a.pem", "cert_file=/b.pem",
            NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_E_DUPLICATE);
        pam_jwt_cfg_free(&cfg);
    }

    TEST("duplicate debug flag")
    {
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 3, "cert_file=/a.pem", "debug", "debug",
            NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_E_DUPLICATE);
        ASSERT_TRUE(cfg.debug == true);
        ASSERT_STR_EQ(cfg.cert_file, "/a.pem");
        pam_jwt_cfg_free(&cfg);
    }

    TEST("duplicate clock_skew")
    {
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 3, "cert_file=/a.pem", "clock_skew=5", "clock_skew=10",
            NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_E_DUPLICATE);
        /* first value is the one that stuck */
        ASSERT_INT_EQ(cfg.clock_skew, 5);
        pam_jwt_cfg_free(&cfg);
    }

    TEST("duplicate issuer")
    {
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 3, "cert_file=/a.pem",
            "issuer=https://a.example/", "issuer=https://b.example/",
            NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_E_DUPLICATE);
        ASSERT_STR_EQ(cfg.issuer, "https://a.example/");
        pam_jwt_cfg_free(&cfg);
    }

    /* Invalid values. */
    TEST("empty value for cert_file")
    {
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 1, "cert_file=", NULL, NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_E_INVALID_VALUE);
        ASSERT_TRUE(cfg.cert_file == NULL);
        pam_jwt_cfg_free(&cfg);
    }

    TEST("missing '=' separator")
    {
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 1, "cert_file", NULL, NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_E_INVALID_VALUE);
        ASSERT_TRUE(cfg.cert_file == NULL);
        pam_jwt_cfg_free(&cfg);
    }

    TEST("empty key (starts with '=')")
    {
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 1, "=value", NULL, NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_E_INVALID_VALUE);
        pam_jwt_cfg_free(&cfg);
    }

    TEST("unknown key is rejected")
    {
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 2, "cert_file=/a.pem", "wat=42",
            NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_E_INVALID_VALUE);
        /* cert_file was parsed first and remains valid. */
        ASSERT_STR_EQ(cfg.cert_file, "/a.pem");
        pam_jwt_cfg_free(&cfg);
    }

    TEST("clock_skew non-numeric")
    {
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 2, "cert_file=/a.pem", "clock_skew=abc",
            NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_E_INVALID_VALUE);
        /* Default preserved. */
        ASSERT_INT_EQ(cfg.clock_skew, 0);
        pam_jwt_cfg_free(&cfg);
    }

    TEST("clock_skew negative is rejected")
    {
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 2, "cert_file=/a.pem", "clock_skew=-1",
            NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_E_INVALID_VALUE);
        ASSERT_INT_EQ(cfg.clock_skew, 0);
        pam_jwt_cfg_free(&cfg);
    }

    TEST("clock_skew with leading '+' is accepted and equals the unsigned form")
    {
        /* The parser accepts an explicit '+' sign on non-negative
         * integers for compatibility with operators used to writing
         * signed integers. "+30" and "30" must parse to the same value.
         * Documented in docs/config.md. */
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 2, "cert_file=/a.pem", "clock_skew=+30",
            NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_OK);
        ASSERT_INT_EQ(cfg.clock_skew, 30);
        pam_jwt_cfg_free(&cfg);
    }

    TEST("clock_skew overflow is rejected")
    {
        struct pam_jwt_cfg cfg;
        /* INT_MAX = 2147483647 -> 99999999999 exceeds int range */
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 2, "cert_file=/a.pem", "clock_skew=99999999999",
            NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_E_INVALID_VALUE);
        ASSERT_INT_EQ(cfg.clock_skew, 0);
        pam_jwt_cfg_free(&cfg);
    }

    TEST("clock_skew accepts zero but rejects second value as duplicate")
    {
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 3, "cert_file=/a.pem", "clock_skew=0", "clock_skew=+7",
            NULL, NULL, NULL, NULL);
        /* Second clock_skew must be rejected as duplicate. */
        ASSERT_INT_EQ(st, PAM_JWT_CFG_E_DUPLICATE);
        ASSERT_INT_EQ(cfg.clock_skew, 0);
        pam_jwt_cfg_free(&cfg);
    }

    TEST("control char in value is rejected")
    {
        struct pam_jwt_cfg cfg;
        /* 0x07 embedded in the value. Use string concatenation so the
         * hex escape is terminated cleanly. */
        const char *arg = "issuer=abc\x07"
                          "def";
        enum pam_jwt_cfg_status st =
            parse_lits(&cfg, 1, arg,
                       NULL, NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_E_INVALID_VALUE);
        ASSERT_TRUE(cfg.issuer == NULL);
        pam_jwt_cfg_free(&cfg);
    }

    TEST("whitespace in value is accepted (not a control char)")
    {
        /* The parser forbids control bytes (<0x20) and 0x7f, but plain
         * spaces (0x20) and higher are allowed in values. Document the
         * boundary on the high side. */
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 2, "cert_file=/a.pem", "issuer=abc def",
            NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_OK);
        ASSERT_STR_EQ(cfg.issuer, "abc def");
        pam_jwt_cfg_free(&cfg);
    }

    TEST("0x7f (DEL) in value is rejected")
    {
        struct pam_jwt_cfg cfg;
        const char *arg = "issuer=abc\x7f"
                          "def";
        enum pam_jwt_cfg_status st =
            parse_lits(&cfg, 1, arg,
                       NULL, NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_E_INVALID_VALUE);
        ASSERT_TRUE(cfg.issuer == NULL);
        pam_jwt_cfg_free(&cfg);
    }

    TEST("over-long value is rejected (just under cap is ok)")
    {
        struct pam_jwt_cfg cfg;
        /* Build a value of exactly PAM_JWT_MAX_OPT_LEN bytes -> accepted. */
        char *ok = malloc(PAM_JWT_MAX_OPT_LEN + 1U);
        ASSERT_TRUE(ok != NULL);
        memset(ok, 'a', PAM_JWT_MAX_OPT_LEN);
        ok[PAM_JWT_MAX_OPT_LEN] = '\0';

        char *arg_ok = malloc(PAM_JWT_MAX_OPT_LEN + 32);
        ASSERT_TRUE(arg_ok != NULL);
        snprintf(arg_ok, PAM_JWT_MAX_OPT_LEN + 32, "issuer=%s", ok);

        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 2, "cert_file=/a.pem", arg_ok,
            NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_OK);
        ASSERT_TRUE(cfg.issuer != NULL);
        ASSERT_INT_EQ((int)strlen(cfg.issuer), PAM_JWT_MAX_OPT_LEN);
        pam_jwt_cfg_free(&cfg);
        free(arg_ok);
        free(ok);

        /* One byte over the cap -> rejected. */
        char *too_long = malloc(PAM_JWT_MAX_OPT_LEN + 2U);
        ASSERT_TRUE(too_long != NULL);
        memset(too_long, 'b', PAM_JWT_MAX_OPT_LEN + 1U);
        too_long[PAM_JWT_MAX_OPT_LEN + 1U] = '\0';

        char *arg_too_long = malloc(PAM_JWT_MAX_OPT_LEN + 64);
        ASSERT_TRUE(arg_too_long != NULL);
        snprintf(arg_too_long, PAM_JWT_MAX_OPT_LEN + 64,
                 "issuer=%s", too_long);

        st = parse_lits(&cfg, 2, "cert_file=/a.pem", arg_too_long,
                        NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_E_INVALID_VALUE);
        ASSERT_TRUE(cfg.issuer == NULL);
        pam_jwt_cfg_free(&cfg);
        free(arg_too_long);
        free(too_long);
    }

    /* Argument-vector sanity checks. */
    TEST("NULL cfg is an internal error")
    {
        const char *argv[1] = {"cert_file=/a.pem"};
        enum pam_jwt_cfg_status st = pam_jwt_cfg_parse(1, argv, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_E_INTERNAL);
    }

    TEST("argc<0 is an internal error")
    {
        struct pam_jwt_cfg cfg;
        const char *argv[1] = {"cert_file=/a.pem"};
        enum pam_jwt_cfg_status st = pam_jwt_cfg_parse(-1, argv, &cfg);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_E_INTERNAL);
    }

    TEST("argc>0 with NULL argv is an internal error")
    {
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = pam_jwt_cfg_parse(1, NULL, &cfg);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_E_INTERNAL);
    }

    TEST("NULL argv[i] entry is an invalid value")
    {
        char *storage[1] = {NULL};
        const char **argv = make_argv(storage, 1);
        ASSERT_TRUE(argv != NULL);
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = pam_jwt_cfg_parse(1, argv, &cfg);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_E_INVALID_VALUE);
        free(argv);
        pam_jwt_cfg_free(&cfg);
    }

    /* Order independence: the parser must accept options in any order. */
    TEST("options accepted in any order")
    {
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 7,
            "debug",
            "clock_skew=15",
            "match_field=uid",
            "map_field=sub",
            "audience=pam-login",
            "issuer=https://idp.example/",
            "cert_file=/etc/jwt/issuer.pem");
        ASSERT_INT_EQ(st, PAM_JWT_CFG_OK);
        ASSERT_STR_EQ(cfg.cert_file, "/etc/jwt/issuer.pem");
        ASSERT_STR_EQ(cfg.issuer, "https://idp.example/");
        ASSERT_STR_EQ(cfg.audience, "pam-login");
        ASSERT_STR_EQ(cfg.map_field, "sub");
        ASSERT_STR_EQ(cfg.match_field, "uid");
        ASSERT_INT_EQ(cfg.clock_skew, 15);
        ASSERT_TRUE(cfg.debug == true);
        pam_jwt_cfg_free(&cfg);
    }

    /* Re-parse into a previously-used cfg must wipe stale state. The
     * parser releases any prior heap-owned strings before re-init'ing
     * the cfg, so a successful parse followed by another successful
     * parse into the same cfg must not leak. */
    TEST("re-parse resets prior state")
    {
        struct pam_jwt_cfg cfg;
        pam_jwt_cfg_init(&cfg);
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 4, "cert_file=/a.pem", "issuer=old",
            "clock_skew=99", "debug", NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_OK);
        ASSERT_STR_EQ(cfg.issuer, "old");
        ASSERT_INT_EQ(cfg.clock_skew, 99);
        ASSERT_TRUE(cfg.debug == true);

        /* Now re-parse with a minimal valid set; all extras should drop. */
        st = parse_lits(&cfg, 1, "cert_file=/b.pem",
                        NULL, NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_OK);
        ASSERT_STR_EQ(cfg.cert_file, "/b.pem");
        ASSERT_TRUE(cfg.issuer == NULL);
        ASSERT_TRUE(cfg.audience == NULL);
        ASSERT_TRUE(cfg.map_field == NULL);
        ASSERT_TRUE(cfg.match_field == NULL);
        ASSERT_INT_EQ(cfg.clock_skew, 0);
        ASSERT_TRUE(cfg.debug == false);
        pam_jwt_cfg_free(&cfg);
    }

    /* Parse failure must leave cfg in a free()-safe state. */
    TEST("failed parse leaves cfg free()-safe")
    {
        struct pam_jwt_cfg cfg;
        /* A mid-stream invalid value, but some valid options were set
         * before it. cfg_free() must not double-free anything. */
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 3, "cert_file=/a.pem", "issuer=ok", "clock_skew=oops",
            NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_E_INVALID_VALUE);
        /* Calling free twice must not crash and must leave all pointers NULL. */
        pam_jwt_cfg_free(&cfg);
        pam_jwt_cfg_free(&cfg);
        ASSERT_TRUE(cfg.cert_file == NULL);
        ASSERT_TRUE(cfg.issuer == NULL);
        ASSERT_TRUE(cfg.audience == NULL);
        ASSERT_TRUE(cfg.map_field == NULL);
        ASSERT_TRUE(cfg.match_field == NULL);
    }

    /* map_field and match_field default to NULL when omitted. */
    TEST("map_field and match_field default to NULL")
    {
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 1, "cert_file=/a.pem",
            NULL, NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_OK);
        ASSERT_TRUE(cfg.map_field == NULL);
        ASSERT_TRUE(cfg.match_field == NULL);
        pam_jwt_cfg_free(&cfg);
    }

    /* map_field set, match_field unset (independent). */
    TEST("map_field set alone")
    {
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 2, "cert_file=/a.pem", "map_field=email",
            NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_OK);
        ASSERT_STR_EQ(cfg.map_field, "email");
        ASSERT_TRUE(cfg.match_field == NULL);
        pam_jwt_cfg_free(&cfg);
    }

    TEST("match_field set alone")
    {
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 2, "cert_file=/a.pem", "match_field=uid",
            NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_OK);
        ASSERT_TRUE(cfg.map_field == NULL);
        ASSERT_STR_EQ(cfg.match_field, "uid");
        pam_jwt_cfg_free(&cfg);
    }

    TEST("both map_field and match_field set, consistent")
    {
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 3, "cert_file=/a.pem",
            "map_field=preferred_username", "match_field=preferred_username",
            NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_OK);
        ASSERT_STR_EQ(cfg.map_field, "preferred_username");
        ASSERT_STR_EQ(cfg.match_field, "preferred_username");
        pam_jwt_cfg_free(&cfg);
    }

    TEST("debug is false by default")
    {
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 1, "cert_file=/a.pem",
            NULL, NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_OK);
        ASSERT_TRUE(cfg.debug == false);
        pam_jwt_cfg_free(&cfg);
    }

    TEST("clock_skew defaults to 0")
    {
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 1, "cert_file=/a.pem",
            NULL, NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_OK);
        ASSERT_INT_EQ(cfg.clock_skew, 0);
        pam_jwt_cfg_free(&cfg);
    }

    /* Copy semantics: strings returned by the parser must be independent
     * copies. Mutating the caller's argv must not affect the cfg. */
    TEST("parser copies string values")
    {
        char buf[] = "cert_file=/etc/jwt/issuer.pem";
        char *storage[1] = {buf};
        const char **argv = make_argv(storage, 1);
        ASSERT_TRUE(argv != NULL);
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = pam_jwt_cfg_parse(1, argv, &cfg);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_OK);
        /* Stomp the source buffer. */
        memset(buf, 'X', sizeof(buf) - 1U);
        /* cfg must still hold the original value. */
        ASSERT_STR_EQ(cfg.cert_file, "/etc/jwt/issuer.pem");
        free(argv);
        pam_jwt_cfg_free(&cfg);
    }

    TEST("second parse call frees prior strings (no crash)")
    {
        /* This test only proves the re-parse path doesn't crash.
         * Whether the prior strings are actually freed is verified
         * separately by `leak: re-parse frees all prior strings`,
         * which only succeeds when run under ASan/LSan. */
        struct pam_jwt_cfg cfg;
        pam_jwt_cfg_init(&cfg);
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 2, "cert_file=/first.pem", "issuer=first-iss",
            NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_OK);
        st = parse_lits(&cfg, 2, "cert_file=/second.pem", "issuer=second-iss",
                        NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_OK);
        ASSERT_STR_EQ(cfg.cert_file, "/second.pem");
        ASSERT_STR_EQ(cfg.issuer, "second-iss");
        pam_jwt_cfg_free(&cfg);
    }

    /* ---------------------------------------------------------------------
     * Leak-stress tests.
     *
     * The cases below are designed to be silent under a plain build but
     * loud under AddressSanitizer + LeakSanitizer (`make test-asan`):
     * any missing `free()` in src/config.c — for instance forgetting to
     * drop a partially-allocated string when a later argument fails, or
     * not freeing the previous value on a re-parse — is reported by LSan
     * at process exit and turns the run red.
     *
     * We deliberately do not assert on leak counts inside the test
     * bodies: that would couple the suite to the sanitizer. The
     * sanitizer runs the leak check at exit regardless.
     * ------------------------------------------------------------------- */

    TEST("leak: full happy-path parse + free")
    {
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 7,
            "cert_file=/etc/jwt/issuer.pem",
            "issuer=https://idp.example.com/",
            "audience=pam-login",
            "map_field=preferred_username",
            "match_field=uid",
            "clock_skew=30",
            "debug");
        ASSERT_INT_EQ(st, PAM_JWT_CFG_OK);
        ASSERT_STR_EQ(cfg.cert_file, "/etc/jwt/issuer.pem");
        ASSERT_STR_EQ(cfg.issuer, "https://idp.example.com/");
        ASSERT_STR_EQ(cfg.audience, "pam-login");
        ASSERT_STR_EQ(cfg.map_field, "preferred_username");
        ASSERT_STR_EQ(cfg.match_field, "uid");
        pam_jwt_cfg_free(&cfg);
    }

    TEST("leak: re-parse frees all prior strings")
    {
        /* Both calls succeed; on the second call take_string()
         * overwrites cfg->cert_file and cfg->issuer with fresh
         * allocations. The first call's two allocations must be
         * released by pam_jwt_cfg_init() (via free()) before the
         * second call's str_dup() runs. LSan catches any leak. */
        struct pam_jwt_cfg cfg;
        for (int i = 0; i < 16; ++i)
        {
            enum pam_jwt_cfg_status st = parse_lits(
                &cfg, 5,
                "cert_file=/path/a/cert.pem",
                "issuer=https://idp.example/old",
                "audience=pam-login",
                "map_field=sub",
                "match_field=uid",
                NULL, NULL);
            ASSERT_INT_EQ(st, PAM_JWT_CFG_OK);
        }
        pam_jwt_cfg_free(&cfg);
    }

    TEST("leak: duplicate detection on a fresh cfg")
    {
        /* The first cert_file is accepted; the second triggers
         * E_DUPLICATE after take_string() has already allocated and
         * installed the first string into the cfg. cfg_free() at the
         * end must release that allocation. */
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 2, "cert_file=/a.pem", "cert_file=/b.pem",
            NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_E_DUPLICATE);
        ASSERT_STR_EQ(cfg.cert_file, "/a.pem");
        pam_jwt_cfg_free(&cfg);
    }

    TEST("leak: failed parse after partial success")
    {
        /* cert_file and issuer are accepted; clock_skew=oops fails.
         * Both accepted strings must still be reachable through cfg
         * so cfg_free() can release them. LSan will flag any leak
         * here. */
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 3, "cert_file=/a.pem", "issuer=https://idp.example/",
            "clock_skew=oops", NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_E_INVALID_VALUE);
        ASSERT_STR_EQ(cfg.cert_file, "/a.pem");
        ASSERT_STR_EQ(cfg.issuer, "https://idp.example/");
        pam_jwt_cfg_free(&cfg);
    }

    TEST("leak: failed parse early in argv")
    {
        /* Even an early failure must not leak the (non-)allocation
         * that preceded it. With no strings accepted, there is
         * nothing to free, but the test guards against a future
         * change that allocates before validation. */
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 1, "wat=42", NULL, NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_E_INVALID_VALUE);
        pam_jwt_cfg_free(&cfg);
    }

    TEST("leak: init + free on a stack cfg is idempotent")
    {
        /* Many init/free cycles on a stack-resident cfg. The cfg
         * itself is not heap-allocated so the only thing that could
         * leak is whatever pam_jwt_cfg_init() touches (nothing) or
         * whatever pam_jwt_cfg_free() touches (frees and NULLs the
         * string slots). */
        for (int i = 0; i < 32; ++i)
        {
            struct pam_jwt_cfg cfg;
            pam_jwt_cfg_init(&cfg);
            pam_jwt_cfg_free(&cfg);
        }
    }

    TEST("leak: init + parse + free loop")
    {
        /* Hammer the lifecycle to surface UAF / leak / double-free
         * in pam_jwt_cfg_parse()'s pam_jwt_cfg_init() prologue. */
        struct pam_jwt_cfg cfg;
        for (int i = 0; i < 32; ++i)
        {
            enum pam_jwt_cfg_status st = parse_lits(
                &cfg, 2,
                "cert_file=/etc/jwt/issuer.pem",
                "issuer=https://idp.example/",
                NULL, NULL, NULL, NULL, NULL);
            ASSERT_INT_EQ(st, PAM_JWT_CFG_OK);
            pam_jwt_cfg_free(&cfg);
        }
    }

    TEST("leak: failed parse followed by successful parse")
    {
        /* First call leaves a half-built cfg behind (cert_file set,
         * issuer rejected). The second call re-enters via
         * pam_jwt_cfg_init() which must free the first cert_file
         * before the new str_dup() runs. */
        struct pam_jwt_cfg cfg;
        enum pam_jwt_cfg_status st = parse_lits(
            &cfg, 2, "cert_file=/a.pem", "issuer=",
            NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_E_INVALID_VALUE);
        st = parse_lits(
            &cfg, 2, "cert_file=/b.pem", "issuer=https://idp.example/",
            NULL, NULL, NULL, NULL, NULL);
        ASSERT_INT_EQ(st, PAM_JWT_CFG_OK);
        ASSERT_STR_EQ(cfg.cert_file, "/b.pem");
        ASSERT_STR_EQ(cfg.issuer, "https://idp.example/");
        pam_jwt_cfg_free(&cfg);
    }
}
TEST_GROUP_END(config)
