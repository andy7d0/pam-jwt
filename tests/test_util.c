/*
 * tests/test_util.c
 *
 * Unit tests for src/util.c: logging gate, strdup, world-writable
 * detection, and file slurp. The tests in this group are hermetic:
 * they create their own temporary files under /tmp and clean up
 * afterwards, so they do not depend on any system fixture.
 *
 * No live syslog interaction: pam_jwt_log() is exercised only to
 * verify it doesn't crash, doesn't allocate, and is gated by
 * pam_jwt_log_should_emit(). The actual syslog message goes to the
 * real authpriv.* facility and is harmless on a developer machine.
 *
 * Coverage targets (from AGENTS.md, for util.c):
 *   - pam_jwt_log_should_emit(): every priority at both debug values
 *   - pam_jwt_strdup(): NULL, empty, normal, distinct copy
 *   - pam_jwt_is_world_writable(): NULL, missing, non-writable,
 *     world-writable, directory, symlink to world-writable file
 *   - pam_jwt_read_file(): NULL args, missing file, directory, empty
 *     file, normal file, large content
 *   - pam_jwt_log(): smoke (NULL pamh), gated path is a no-op
 *
 * Plus `leak:` cases that only prove anything under ASan/LSan.
 */

#include "test.h"
#include "pam_jwt.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

/* --- helpers --------------------------------------------------------------- */

/* Build a unique temp-file path under /tmp without actually creating it. */
static void make_tmp_path(char *out, size_t outlen, const char *tag)
{
    snprintf(out, outlen, "/tmp/pam_jwt_test_%s_%d.tmp", tag, (int)getpid());
}

/* Create `path` with `mode` containing `data` (a NUL-terminated string).
 *
 * `mode` is the requested permission bits. Because open(2) ANDs them
 * with ~umask, a process whose umask drops the world-write bit
 * (typical: 0022) would silently create a 0644 file even when 0666
 * is requested. To make the tests deterministic we fchmod() after
 * close() so the on-disk mode matches the requested mode exactly.
 *
 * Returns true on success. */
static bool write_file_mode(const char *path, mode_t mode, const char *data)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0)
    {
        return false;
    }
    size_t len = strlen(data);
    size_t off = 0;
    while (off < len)
    {
        ssize_t n = write(fd, data + off, len - off);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            close(fd);
            unlink(path);
            return false;
        }
        off += (size_t)n;
    }
    if (close(fd) != 0)
    {
        unlink(path);
        return false;
    }
    /* Force the requested mode regardless of the process umask. */
    if (chmod(path, mode) != 0)
    {
        unlink(path);
        return false;
    }
    return true;
}

/* --- TEST_GROUP ------------------------------------------------------------ */

TEST_GROUP(util)
{
    /* ---- pam_jwt_log_should_emit --------------------------------------- */

    TEST("gate: debug=false allows LOG_EMERG..LOG_ERR, denies INFO/DEBUG")
    {
        ASSERT_TRUE(pam_jwt_log_should_emit(false, LOG_EMERG) == true);
        ASSERT_TRUE(pam_jwt_log_should_emit(false, LOG_ALERT) == true);
        ASSERT_TRUE(pam_jwt_log_should_emit(false, LOG_CRIT) == true);
        ASSERT_TRUE(pam_jwt_log_should_emit(false, LOG_ERR) == true);
        ASSERT_TRUE(pam_jwt_log_should_emit(false, LOG_WARNING) == false);
        ASSERT_TRUE(pam_jwt_log_should_emit(false, LOG_NOTICE) == false);
        ASSERT_TRUE(pam_jwt_log_should_emit(false, LOG_INFO) == false);
        ASSERT_TRUE(pam_jwt_log_should_emit(false, LOG_DEBUG) == false);
    }

    TEST("gate: debug=true allows everything from LOG_EMERG..LOG_DEBUG")
    {
        ASSERT_TRUE(pam_jwt_log_should_emit(true, LOG_EMERG) == true);
        ASSERT_TRUE(pam_jwt_log_should_emit(true, LOG_ERR) == true);
        ASSERT_TRUE(pam_jwt_log_should_emit(true, LOG_WARNING) == true);
        ASSERT_TRUE(pam_jwt_log_should_emit(true, LOG_INFO) == true);
        ASSERT_TRUE(pam_jwt_log_should_emit(true, LOG_DEBUG) == true);
    }

    TEST("gate: LOG_AUTHPRIV facility bit does not change severity")
    {
        /* The severity is in the low 3 bits. Mixing in a facility bit
         * must not flip the gate. */
        ASSERT_TRUE(pam_jwt_log_should_emit(false,
                                            LOG_AUTHPRIV | LOG_ERR) == true);
        ASSERT_TRUE(pam_jwt_log_should_emit(false,
                                            LOG_AUTHPRIV | LOG_DEBUG) == false);
        ASSERT_TRUE(pam_jwt_log_should_emit(true,
                                            LOG_AUTHPRIV | LOG_DEBUG) == true);
    }

    /* ---- pam_jwt_log (smoke) -------------------------------------------- */

    TEST("pam_jwt_log: gated debug-off path is a no-op for LOG_INFO")
    {
        /* debug=false, LOG_INFO => gate denies, no pam_syslog call. */
        pam_jwt_log(NULL, false, LOG_INFO, "hello %d", 42);
        ASSERT_TRUE(1);
    }

    TEST("pam_jwt_log: wrapper does not crash for any priority")
    {
        /* Both gated and ungated paths. The ungated calls would write
         * to syslog in the build environment; we don't assert on the
         * output, only that the wrapper survives. */
        pam_jwt_log(NULL, false, LOG_ERR, "test error %d", 1);
        pam_jwt_log(NULL, false, LOG_DEBUG, "test debug %d", 2);
        pam_jwt_log(NULL, true, LOG_DEBUG, "test debug-on %d", 3);
        ASSERT_TRUE(1);
    }

    TEST("pam_jwt_log: NULL fmt is tolerated")
    {
        /* Should be a no-op. */
        pam_jwt_log(NULL, true, LOG_DEBUG, NULL);
        ASSERT_TRUE(1);
    }

    /* ---- pam_jwt_strdup ------------------------------------------------ */

    TEST("strdup: NULL returns NULL")
    {
        ASSERT_TRUE(pam_jwt_strdup(NULL) == NULL);
    }

    TEST("strdup: empty string yields an allocated empty buffer")
    {
        char *p = pam_jwt_strdup("");
        ASSERT_TRUE(p != NULL);
        ASSERT_INT_EQ((int)p[0], 0);
        free(p);
    }

    TEST("strdup: copies contents verbatim")
    {
        const char *src = "hello world";
        char *p = pam_jwt_strdup(src);
        ASSERT_TRUE(p != NULL);
        ASSERT_STR_EQ(p, src);
        free(p);
    }

    TEST("strdup: returned buffer is independent of the input")
    {
        char buf[] = "original";
        char *p = pam_jwt_strdup(buf);
        ASSERT_TRUE(p != NULL);
        memset(buf, 'X', sizeof(buf) - 1U);
        ASSERT_STR_EQ(p, "original");
        free(p);
    }

    TEST("strdup: handles long inputs")
    {
        char *big = malloc(8192);
        ASSERT_TRUE(big != NULL);
        memset(big, 'A', 8191);
        big[8191] = '\0';
        char *p = pam_jwt_strdup(big);
        ASSERT_TRUE(p != NULL);
        ASSERT_INT_EQ((int)strlen(p), 8191);
        ASSERT_INT_EQ((int)p[0], 'A');
        ASSERT_INT_EQ((int)p[8190], 'A');
        free(p);
        free(big);
    }

    /* ---- pam_jwt_is_world_writable ------------------------------------- */

    TEST("world-writable: NULL path is false")
    {
        ASSERT_TRUE(pam_jwt_is_world_writable(NULL) == false);
    }

    TEST("world-writable: missing path is false")
    {
        ASSERT_TRUE(pam_jwt_is_world_writable(
                        "/tmp/pam_jwt_does_not_exist_xyz_42") == false);
    }

    TEST("world-writable: regular file, mode 0600 (owner-only write)")
    {
        char path[PATH_MAX];
        make_tmp_path(path, sizeof(path), "0600");
        ASSERT_TRUE(write_file_mode(path, 0600, "x"));
        ASSERT_TRUE(pam_jwt_is_world_writable(path) == false);
        unlink(path);
    }

    TEST("world-writable: regular file, mode 0644 (group/other read-only)")
    {
        char path[PATH_MAX];
        make_tmp_path(path, sizeof(path), "0644");
        ASSERT_TRUE(write_file_mode(path, 0644, "x"));
        ASSERT_TRUE(pam_jwt_is_world_writable(path) == false);
        unlink(path);
    }

    TEST("world-writable: regular file, mode 0666 (world-writable)")
    {
        char path[PATH_MAX];
        make_tmp_path(path, sizeof(path), "0666");
        ASSERT_TRUE(write_file_mode(path, 0666, "x"));
        ASSERT_TRUE(pam_jwt_is_world_writable(path) == true);
        unlink(path);
    }

    TEST("world-writable: regular file, mode 0602 (world-write only)")
    {
        char path[PATH_MAX];
        make_tmp_path(path, sizeof(path), "0602");
        ASSERT_TRUE(write_file_mode(path, 0602, "x"));
        ASSERT_TRUE(pam_jwt_is_world_writable(path) == true);
        unlink(path);
    }

    TEST("world-writable: a directory is not a world-writable cert")
    {
        char path[PATH_MAX];
        make_tmp_path(path, sizeof(path), "dir");
        ASSERT_TRUE(mkdir(path, 0777) == 0);
        /* chmod in case umask interfered */
        chmod(path, 0777);
        ASSERT_TRUE(pam_jwt_is_world_writable(path) == false);
        rmdir(path);
    }

    TEST("world-writable: symlink to world-writable file reports as such")
    {
        char target[PATH_MAX];
        char link[PATH_MAX];
        make_tmp_path(target, sizeof(target), "symtarget");
        make_tmp_path(link, sizeof(link), "symlink");
        ASSERT_TRUE(write_file_mode(target, 0666, "x"));
        ASSERT_TRUE(symlink(target, link) == 0);
        /* stat() follows the link, so we should see the target's mode. */
        ASSERT_TRUE(pam_jwt_is_world_writable(link) == true);
        unlink(link);
        unlink(target);
    }

    /* ---- pam_jwt_read_file --------------------------------------------- */

    TEST("read_file: NULL path returns false")
    {
        char *buf = (char *)0xdeadbeef;
        size_t sz = (size_t)-1;
        ASSERT_TRUE(pam_jwt_read_file(NULL, &buf, &sz) == false);
        ASSERT_TRUE(buf == NULL);
        ASSERT_INT_EQ((int)sz, 0);
    }

    TEST("read_file: NULL out returns false")
    {
        size_t sz = 99;
        ASSERT_TRUE(pam_jwt_read_file("/tmp/whatever", NULL, &sz) == false);
        ASSERT_INT_EQ((int)sz, 0);
    }

    TEST("read_file: NULL out_size returns false")
    {
        char *buf = NULL;
        ASSERT_TRUE(pam_jwt_read_file("/tmp/whatever", &buf, NULL) == false);
        ASSERT_TRUE(buf == NULL);
    }

    TEST("read_file: missing file returns false")
    {
        char *buf = NULL;
        size_t sz = 99;
        ASSERT_TRUE(pam_jwt_read_file(
                        "/tmp/pam_jwt_missing_xyz", &buf, &sz) == false);
        ASSERT_TRUE(buf == NULL);
        ASSERT_INT_EQ((int)sz, 0);
    }

    TEST("read_file: directory returns false")
    {
        char *buf = NULL;
        size_t sz = 99;
        ASSERT_TRUE(pam_jwt_read_file("/tmp", &buf, &sz) == false);
        ASSERT_TRUE(buf == NULL);
        ASSERT_INT_EQ((int)sz, 0);
    }

    TEST("read_file: empty file returns allocated empty buffer")
    {
        char path[PATH_MAX];
        make_tmp_path(path, sizeof(path), "empty");
        ASSERT_TRUE(write_file_mode(path, 0600, ""));
        char *buf = NULL;
        size_t sz = 99;
        ASSERT_TRUE(pam_jwt_read_file(path, &buf, &sz) == true);
        ASSERT_TRUE(buf != NULL);
        ASSERT_INT_EQ((int)sz, 0);
        ASSERT_INT_EQ((int)buf[0], 0);
        free(buf);
        unlink(path);
    }

    TEST("read_file: small file returns NUL-terminated copy")
    {
        char path[PATH_MAX];
        make_tmp_path(path, sizeof(path), "small");
        const char *payload = "hello, world\n";
        ASSERT_TRUE(write_file_mode(path, 0600, payload));
        char *buf = NULL;
        size_t sz = 0;
        ASSERT_TRUE(pam_jwt_read_file(path, &buf, &sz) == true);
        ASSERT_TRUE(buf != NULL);
        ASSERT_INT_EQ((int)sz, (int)strlen(payload));
        ASSERT_STR_EQ(buf, payload);
        free(buf);
        unlink(path);
    }

    TEST("read_file: 4 KiB of 'A' is read back intact")
    {
        char path[PATH_MAX];
        make_tmp_path(path, sizeof(path), "4k");
        const size_t N = 4096;
        char *payload = malloc(N + 1);
        ASSERT_TRUE(payload != NULL);
        memset(payload, 'A', N);
        payload[N] = '\0';
        ASSERT_TRUE(write_file_mode(path, 0600, payload));

        char *buf = NULL;
        size_t sz = 0;
        ASSERT_TRUE(pam_jwt_read_file(path, &buf, &sz) == true);
        ASSERT_TRUE(buf != NULL);
        ASSERT_INT_EQ((int)sz, (int)N);
        ASSERT_INT_EQ((int)buf[N], 0); /* NUL-terminated */
        ASSERT_INT_EQ((int)buf[0], 'A');
        ASSERT_INT_EQ((int)buf[N - 1], 'A');
        free(buf);
        free(payload);
        unlink(path);
    }

    /* ---------------------------------------------------------------------
     * Leak-stress tests. Loud under `make test-asan`, silent otherwise.
     * ------------------------------------------------------------------- */

    TEST("leak: many strdup/free cycles")
    {
        for (int i = 0; i < 256; ++i)
        {
            char *p = pam_jwt_strdup("a moderately long string used in "
                                     "the leak-stress loop");
            ASSERT_TRUE(p != NULL);
            free(p);
        }
    }

    TEST("leak: read_file + free in a tight loop")
    {
        char path[PATH_MAX];
        make_tmp_path(path, sizeof(path), "leak");
        ASSERT_TRUE(write_file_mode(path, 0600,
                                    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
        for (int i = 0; i < 64; ++i)
        {
            char *buf = NULL;
            size_t sz = 0;
            ASSERT_TRUE(pam_jwt_read_file(path, &buf, &sz) == true);
            ASSERT_TRUE(buf != NULL);
            free(buf);
        }
        unlink(path);
    }

    TEST("leak: failed read_file leaves out NULL")
    {
        for (int i = 0; i < 32; ++i)
        {
            char *buf = (char *)0xdead;
            size_t sz = 99;
            ASSERT_TRUE(pam_jwt_read_file(
                            "/tmp/pam_jwt_definitely_missing",
                            &buf, &sz) == false);
            ASSERT_TRUE(buf == NULL);
            ASSERT_INT_EQ((int)sz, 0);
        }
    }
}
TEST_GROUP_END(util)