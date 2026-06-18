/*
 * src/util.c
 *
 * Logging facade and small helpers shared by the rest of the module.
 *
 * This file is the *only* place in pam_jwt.so that touches the syslog
 * API or POSIX stat(). Centralising them lets us:
 *
 *   - Guarantee the security rules from AGENTS.md:
 *       * never log the JWT, the authtok, or private-key material
 *       * always route through pam_syslog(..., LOG_AUTHPRIV | priority)
 *       * gate chatty output behind the cfg's debug flag
 *   - Surface the "cert_file is world-writable" warning from one
 *     well-audited place.
 *   - Provide helpers (strdup, file slurp) that the parser and the JWT
 *     verifier can share without each growing a private copy.
 *
 * The helpers declared here are pure C; they are unit-tested in
 * tests/test_util.c without spinning up a live PAM stack or PAM
 * conversation. The only place pam_syslog is actually invoked is the
 * tiny wrapper pam_jwt_log(), so unit tests can verify the gating
 * decision via pam_jwt_log_should_emit() and never touch syslog.
 */

#include "pam_jwt.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

/* --- logging --------------------------------------------------------------- */

/* Return the priority portion of a syslog priority word (mask out the
 * facility bits). <syslog.h> defines priorities as small integers
 * (LOG_EMERG=0..LOG_DEBUG=7) and facilities as the high bits; mixing
 * them is common (e.g. LOG_AUTHPRIV|LOG_ERR). For our gating purposes
 * we only care about the severity. */
static int priority_severity(int priority)
{
    /* LOG_PRIMASK is the standard mask; fall back to a hard-coded 0x07
     * for environments that don't expose it. */
#ifdef LOG_PRIMASK
    return priority & LOG_PRIMASK;
#else
    return priority & 0x07;
#endif
}

bool pam_jwt_log_should_emit(bool debug, int priority)
{
    const int sev = priority_severity(priority);
    if (debug)
    {
        /* Debug mode: emit everything from LOG_EMERG through LOG_DEBUG. */
        return true;
    }
    /* Normal mode: emit at most LOG_ERR (and the more severe ones).
     * This keeps authentication failures and module-load errors in
     * syslog without flooding it with chatty INFO/DEBUG traffic. */
    return sev <= LOG_ERR;
}

void pam_jwt_log(pam_handle_t *pamh, bool debug, int priority,
                 const char *fmt, ...)
{
    if (!pam_jwt_log_should_emit(debug, priority))
    {
        return;
    }
    if (fmt == NULL)
    {
        return;
    }

    /* Per AGENTS.md, every log line goes through LOG_AUTHPRIV so
     * auth events land in authpriv.* regardless of the caller's
     * requested facility. The caller's severity is preserved. */
    const int authpriv_priority = LOG_AUTHPRIV | priority_severity(priority);

    /* pam_syslog takes a printf format, not a va_list. We render the
     * caller's message into a bounded stack buffer and forward it as
     * a single "%s" argument. The 1 KiB cap is generous for diagnostic
     * messages and keeps a runaway format string from exhausting the
     * PAM stack's stack space. */
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0)
    {
        /* Encoding failure — nothing useful to log. */
        return;
    }
    pam_syslog(pamh, authpriv_priority, "%s", buf);
}

/* --- string helpers -------------------------------------------------------- */

char *pam_jwt_strdup(const char *s)
{
    if (s == NULL)
    {
        return NULL;
    }
    const size_t len = strlen(s);
    /* len + 1U cannot overflow because strlen returned a value that fit
     * in size_t and we add one byte. */
    char *out = malloc(len + 1U);
    if (out == NULL)
    {
        return NULL;
    }
    memcpy(out, s, len + 1U);
    return out;
}

/* --- file-system helpers --------------------------------------------------- */

bool pam_jwt_is_world_writable(const char *path)
{
    if (path == NULL)
    {
        return false;
    }
    struct stat st;
    if (stat(path, &st) != 0)
    {
        /* Missing file, permission denied, or some other stat failure:
         * not world-writable by any definition we care about. */
        return false;
    }
    /* Only regular files can be cert files. Reject directories, sockets,
     * devices, etc. to avoid false positives and to keep the warning
     * semantically meaningful. */
    if (!S_ISREG(st.st_mode))
    {
        return false;
    }
    return (st.st_mode & S_IWOTH) != 0;
}

bool pam_jwt_read_file(const char *path, char **out, size_t *out_size)
{
    if (out != NULL)
    {
        *out = NULL;
    }
    if (out_size != NULL)
    {
        *out_size = 0;
    }
    if (path == NULL || out == NULL || out_size == NULL)
    {
        return false;
    }

    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
    {
        return false;
    }
    /* Cap the file size at 16 MiB. Cert files are small; this guard
     * keeps a malicious or accidental huge file from exhausting memory
     * inside the PAM stack. */
    if (st.st_size < 0 || st.st_size > (off_t)(16U * 1024U * 1024U))
    {
        errno = EFBIG;
        return false;
    }
    const size_t want = (size_t)st.st_size;

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        return false;
    }

    char *buf = malloc(want + 1U);
    if (buf == NULL)
    {
        close(fd);
        return false;
    }

    size_t got = 0;
    while (got < want)
    {
        ssize_t n = read(fd, buf + got, want - got);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            free(buf);
            close(fd);
            return false;
        }
        if (n == 0)
        {
            /* EOF before the expected size — file was truncated under us. */
            free(buf);
            close(fd);
            return false;
        }
        got += (size_t)n;
    }
    close(fd);

    buf[want] = '\0';
    *out = buf;
    *out_size = want;
    return true;
}