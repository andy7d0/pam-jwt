/*
 * tests/test.c
 *
 * Implementation of the helpers declared in tests/test.h. Single
 * translation unit so every test binary links the same reporting
 * code regardless of which test_*.c files are compiled in.
 *
 * Output goes to stderr so it stays out of the way of any future
 * test that might capture stdout. The process exit code reflects
 * the number of failed assertions (capped at 255).
 */

#include "test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct test_totals test_totals_g = {0};
struct test_state *test_current_state = NULL;

void test_group_begin(struct test_state *s, const char *name)
{
    memset(s, 0, sizeof(*s));
    s->name = name;
    fprintf(stderr, "== test group: %s ==\n", s->name);
}

void test_group_end(struct test_state *s)
{
    fprintf(stderr, "-- %s: %d/%d assertions ok (%d cases)\n",
            s->name, s->run - s->failed, s->run, s->cases);
    if (s->failed != 0)
    {
        fprintf(stderr, "   FAIL group %s: %d assertion(s) failed\n",
                s->name, s->failed);
    }
}

void test_case_begin(const char *name)
{
    struct test_state *s = test_current_state;
    if (s == NULL)
    {
        return;
    }
    s->cases++;
    test_totals_g.cases++;
    s->case_name = name;
    s->case_failed = 0;
}

void test_case_end(void)
{
    struct test_state *s = test_current_state;
    if (s == NULL)
    {
        return;
    }
    if (s->case_failed)
    {
        test_totals_g.failed_cases++;
        fprintf(stderr, "   FAIL [%s] %s\n", s->name, s->case_name);
    }
}

void test_fail(const char *file, int line, const char *expr, const char *msg)
{
    struct test_state *s = test_current_state;
    if (s == NULL)
    {
        return;
    }
    s->failed++;
    test_totals_g.failed_asserts++;
    s->case_failed = 1;
    fprintf(stderr, "   %s:%d: assert(%s) failed%s%s\n",
            file, line, expr,
            (msg && msg[0] != '\0') ? ": " : "",
            (msg && msg[0] != '\0') ? msg : "");
}
