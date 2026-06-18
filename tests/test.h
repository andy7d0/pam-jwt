/*
 * tests/test.h
 *
 * Tiny custom test runner shared by every test_*.c in this directory.
 *
 * Usage in a test source:
 *
 *   TEST_GROUP(config) {
 *       TEST("name") {
 *           ASSERT_TRUE(...);
 *       }
 *       TEST("other") {
 *           ASSERT_INT_EQ(x, 1);
 *       }
 *   } TEST_GROUP_END(config)
 *
 * The `TEST_GROUP(name) { ... } TEST_GROUP_END(name)` block is a
 * function definition whose body is the group's test cases. Each
 * `TEST("...") { ... }` block is a compound statement inside it.
 *
 * Design goals:
 *   - No external dependencies (no cmocka, no Unity, no libcunit).
 *   - Compiles cleanly under -Wall -Wextra -Werror -std=c11.
 *   - Failed assertions print file:line + a short message and
 *     increment a failure counter; the process exit code reflects
 *     the total number of failures (capped at 255).
 *   - Never logs secrets: only test names and small literal messages.
 */

#ifndef PAM_JWT_TEST_H
#define PAM_JWT_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Per-group state. Each test_*.c owns one of these via TEST_GROUP(). */
struct test_state
{
    const char *name;      /* group name, e.g. "config" */
    int run;               /* assertions executed */
    int failed;            /* assertions that failed */
    int cases;             /* TEST() blocks entered */
    int case_failed;       /* did the current case fail? */
    const char *case_name; /* current case name, for diagnostics */
};

/* Global tally accumulated across groups. */
struct test_totals
{
    int cases;
    int failed_cases;
    int asserts;
    int failed_asserts;
};

extern struct test_totals test_totals_g;
extern struct test_state *test_current_state;

void test_group_begin(struct test_state *s, const char *name);
void test_group_end(struct test_state *s);
void test_case_begin(const char *name);
void test_case_end(void);
void test_fail(const char *file, int line, const char *expr, const char *msg);

/* --- Macros ---------------------------------------------------------------- */

/* Begin a test group. Opens a function `void name##_run(void)`. The
 * caller writes a `{` immediately after, then zero or more TEST()
 * blocks, then a closing `} TEST_GROUP_END(name)`. */
#define TEST_GROUP(NAME)                         \
    static struct test_state test_state_g = {0}; \
    void NAME##_run(void);                       \
    void NAME##_run(void)                        \
    {                                            \
        struct test_state *s = &test_state_g;    \
        test_current_state = s;                  \
        test_group_begin(s, #NAME);

/* End of a test group. Closes the function opened by TEST_GROUP. */
#define TEST_GROUP_END(NAME)   \
    test_group_end(s);         \
    test_current_state = NULL; \
    }

/* Define a single test case. The body is a normal compound statement. */
#define TEST(name)         \
    test_case_begin(name); \
    if (1)

/* Assertion: condition must be true. `msg` is a printf-style format string
 * (may be empty). Arguments are forwarded. */
#define ASSERT_TRUE(cond)                             \
    do                                                \
    {                                                 \
        s->run++;                                     \
        test_totals_g.asserts++;                      \
        if (!(cond))                                  \
        {                                             \
            test_fail(__FILE__, __LINE__, #cond, ""); \
        }                                             \
    } while (0)

/* Assertion: two strings must compare equal. NULLs are tolerated and
 * are reported as part of the failure message (no token material
 * should ever flow through this macro). */
#define ASSERT_STR_EQ(actual, expected)                      \
    do                                                       \
    {                                                        \
        s->run++;                                            \
        test_totals_g.asserts++;                             \
        const char *_a = (actual);                           \
        const char *_e = (expected);                         \
        if (_a == NULL || _e == NULL || strcmp(_a, _e) != 0) \
        {                                                    \
            test_fail(__FILE__, __LINE__,                    \
                      "strcmp(" #actual ", " #expected ")",  \
                      _a ? _a : "(null)");                   \
        }                                                    \
    } while (0)

/* Assertion: two integers must be equal. */
#define ASSERT_INT_EQ(actual, expected)                   \
    do                                                    \
    {                                                     \
        s->run++;                                         \
        test_totals_g.asserts++;                          \
        long _a = (long)(actual);                         \
        long _e = (long)(expected);                       \
        if (_a != _e)                                     \
        {                                                 \
            char _buf[64];                                \
            snprintf(_buf, sizeof(_buf),                  \
                     "actual=%ld expected=%ld", _a, _e);  \
            test_fail(__FILE__, __LINE__, #actual, _buf); \
        }                                                 \
    } while (0)

#endif /* PAM_JWT_TEST_H */
