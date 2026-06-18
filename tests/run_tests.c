/*
 * tests/run_tests.c
 *
 * Entry point for the pam-jwt test suite. Calls each test group in
 * turn and returns the number of failed assertions as the process
 * exit code (capped at 255 so it fits in a single byte).
 *
 * Groups are added by appending a `void group_run(void);` declaration
 * and a call below — no central registry needed.
 */

#include <stdio.h>
#include <stdlib.h>

#include "test.h"

/* Forward declarations for each test group. The TEST_GROUP(name)
 * macro defines `void name##_run(void)`. */
void config_run(void);

int main(void)
{
    fprintf(stderr, "pam-jwt test suite\n");
    fprintf(stderr, "==================\n");

    config_run();

    fprintf(stderr, "==================\n");
    fprintf(stderr,
            "totals: %d/%d assertions, %d/%d cases\n",
            test_totals_g.asserts - test_totals_g.failed_asserts,
            test_totals_g.asserts,
            test_totals_g.cases - test_totals_g.failed_cases,
            test_totals_g.cases);

    if (test_totals_g.failed_asserts == 0 &&
        test_totals_g.failed_cases == 0)
    {
        fprintf(stderr, "ALL TESTS PASSED\n");
        return 0;
    }

    fprintf(stderr, "TESTS FAILED\n");
    if (test_totals_g.failed_asserts > 255)
    {
        return 255;
    }
    return test_totals_g.failed_asserts;
}
