/*
 * src/pam_jwt.c
 *
 * Linux-PAM entry points for the pam_jwt module.
 *
 * The PAM framework calls pam_sm_authenticate() when the application invokes
 * pam_authenticate(3). That is the only entry point that does meaningful
 * work here; the rest are stubs because pam_jwt does not implement
 * credential establishment, account management, or session handling.
 *
 * The body of pam_sm_authenticate() is intentionally thin -- all of the
 * interesting logic lives in:
 *
 *   - src/config.c      (argument parsing)
 *   - src/jwt_verify.c  (cert load, signature verify, claim / user checks)
 *   - src/util.c        (logging + small helpers)
 *
 * Keeping this file thin makes the verifier unit-testable without a live
 * PAM stack (see tests/test_jwt_verify.c). The framework-level glue --
 * pulling the user and the authtok out of pamh, returning PAM result
 * codes, and propagating an optional mapped username to PAM_USER --
 * lives here because it is the only place that touches libpam directly.
 *
 * Security: this file never logs the authtok, the JWT, or any private
 * key material. Configuration errors are reported at LOG_ERR (so they
 * always make it to syslog), debug traces at LOG_DEBUG (only when the
 * `debug` option is set).
 *
 * Visibility: the .so is built with -fvisibility=hidden, so the PAM
 * entry points are tagged __attribute__((visibility("default"))) so
 * dlopen() inside libpam can find them by name.
 */

#include "pam_jwt.h"

#include <stdlib.h>
#include <string.h>

#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <syslog.h>

/* On glibc, PAM_EXTERN expands to plain `extern`; that does not override
 * the global -fvisibility=hidden setting used by the Makefile, so the
 * entry points would otherwise be invisible to libpam's dlopen(). The
 * attribute forces the symbols into the dynamic symbol table. */
#if defined(__GNUC__) || defined(__clang__)
#define PAM_JWT_EXPORT __attribute__((visibility("default")))
#else
#define PAM_JWT_EXPORT
#endif

/* Key used to thread the mapped PAM user (set when cfg->map_field is
 * configured) from pam_sm_authenticate() to pam_sm_setcred(), which is
 * the stage at which some applications actually read PAM_USER. The key
 * is internal to this module; libpam treats it as an opaque string. */
#define PAM_JWT_MAPPED_USER_KEY "pam_jwt_mapped_user"

/* --- internal helpers ------------------------------------------------------ */

/* pam_set_data() cleanup: frees the heap-allocated mapped user string.
 * Invoked by libpam at pam_end() or when the slot is overwritten. The
 * pamh and error_status parameters are unused; we always release the
 * buffer unconditionally. */
static void mapped_user_cleanup(pam_handle_t *pamh, void *data,
                                int error_status)
{
    (void)pamh;
    (void)error_status;
    free(data);
}

/* Retrieve a previously-stored mapped username (written by
 * pam_sm_authenticate when cfg->map_field is configured), promote it
 * to PAM_USER via pam_set_item, then clear the slot so subsequent
 * setcred() calls do not re-apply it. Returns true when a mapped user
 * was successfully promoted, false otherwise (including "nothing
 * stored", which is a normal no-op). */
static bool promote_mapped_user(pam_handle_t *pamh)
{
    const void *stored = NULL;
    int rc = pam_get_data(pamh, PAM_JWT_MAPPED_USER_KEY, &stored);
    if (rc != PAM_SUCCESS || stored == NULL)
    {
        return false;
    }
    const char *mapped = (const char *)stored;
    /* pam_set_item copies the string internally, so we can drop our
     * reference immediately afterwards. */
    int src_rc = pam_set_item(pamh, PAM_USER, mapped);
    /* Clearing the slot via pam_set_data(key, NULL, ...) invokes the
     * cleanup callback above, which releases the heap copy. After this
     * call pam_get_data returns PAM_NO_MODULE_DATA and the slot is
     * gone for the lifetime of the pamh. */
    (void)pam_set_data(pamh, PAM_JWT_MAPPED_USER_KEY, NULL,
                       mapped_user_cleanup);
    return src_rc == PAM_SUCCESS;
}

/* --- PAM entry points ------------------------------------------------------ */

PAM_EXTERN PAM_JWT_EXPORT int pam_sm_authenticate(pam_handle_t *pamh,
                                                  int flags, int argc,
                                                  const char **argv)
{
    (void)flags;

    /* Parse the module arguments. A configuration error is a service
     * error (the administrator misconfigured pam_jwt.so), not a user
     * authentication failure. */
    struct pam_jwt_cfg cfg;
    pam_jwt_cfg_init(&cfg);
    enum pam_jwt_cfg_status cst = pam_jwt_cfg_parse(argc, argv, &cfg);
    if (cst != PAM_JWT_CFG_OK)
    {
        pam_jwt_log(pamh, false, LOG_ERR,
                    "pam_jwt: configuration error (code %d)", (int)cst);
        pam_jwt_cfg_free(&cfg);
        return PAM_SERVICE_ERR;
    }

    /* Resolve the user the application is trying to authenticate.
     * pam_get_user() returns the value previously set by the
     * application (typically from the PAM service config or an
     * earlier module), or whatever the conversation function supplies
     * when prompted. */
    const char *requested_user = NULL;
    int rc = pam_get_user(pamh, &requested_user, NULL);
    if (rc != PAM_SUCCESS || requested_user == NULL ||
        requested_user[0] == '\0')
    {
        pam_jwt_log(pamh, cfg.debug, LOG_DEBUG,
                    "pam_jwt: pam_get_user failed");
        pam_jwt_cfg_free(&cfg);
        return PAM_USER_UNKNOWN;
    }

    /* Pull the authtok -- in our case the JWT, supplied as the
     * password through the application's conversation function.
     * pam_get_authtok() handles the prompt-supply dance for us and
     * returns whatever the application handed in via conv().
     *
     * An empty / missing token is treated as a normal authentication
     * failure so we never leak configuration problems to the caller. */
    const char *token = NULL;
    rc = pam_get_authtok(pamh, PAM_AUTHTOK, &token, NULL);
    if (rc != PAM_SUCCESS || token == NULL || token[0] == '\0')
    {
        pam_jwt_cfg_free(&cfg);
        return PAM_AUTH_ERR;
    }

    /* Run the full verifier. `mapped_user` is populated only when
     * cfg->map_field is configured AND verification succeeds; in
     * every other case it stays NULL. Ownership transfers to the
     * framework via pam_set_data() below. */
    char *mapped_user = NULL;
    int vrc = pam_jwt_verify(pamh, &cfg, token, requested_user,
                             &mapped_user);

    /* Free the cfg immediately: from here on we no longer need the
     * parsed options. Freeing early also shrinks the window in which
     * a stray log call could see cert_file or issuer values. */
    pam_jwt_cfg_free(&cfg);

    if (vrc != PAM_SUCCESS)
    {
        /* pam_jwt_verify() has already emitted any relevant debug
         * diagnostics. Free the mapped_user defensively (it is only
         * populated on success, so this is almost always a no-op). */
        free(mapped_user);
        return vrc;
    }

    /* Verification succeeded. If a username mapping was requested,
     * hand the mapped username to the framework so pam_sm_setcred
     * can promote it to PAM_USER. pam_set_data() takes ownership of
     * the buffer; do NOT free `mapped_user` afterwards. */
    if (mapped_user != NULL)
    {
        int sdr = pam_set_data(pamh, PAM_JWT_MAPPED_USER_KEY, mapped_user,
                               mapped_user_cleanup);
        if (sdr != PAM_SUCCESS)
        {
            pam_jwt_log(pamh, false, LOG_ERR,
                        "pam_jwt: pam_set_data failed");
            free(mapped_user);
            return PAM_BUF_ERR;
        }
    }

    return PAM_SUCCESS;
}

PAM_EXTERN PAM_JWT_EXPORT int pam_sm_setcred(pam_handle_t *pamh, int flags,
                                             int argc, const char **argv)
{
    (void)argc;
    (void)argv;

    /* Per pam_setcred(3), `flags` selects one of:
     *   - PAM_ESTABLISH_CRED     : initial credential setup
     *   - PAM_REINITIALIZE_CRED  : re-establishing creds
     *   - PAM_DELETE_CRED        : teardown
     *   - PAM_REFRESH_CRED       : refresh (rare)
     *
     * pam_jwt's only credential side-effect is the optional username
     * mapping (cfg->map_field). The mapped user was stashed by
     * pam_sm_authenticate; we promote it to PAM_USER here on the
     * ESTABLISH / REINITIALIZE paths so applications that read
     * PAM_USER at the setcred stage see the right name. For
     * DELETE / REFRESH there is nothing for us to undo (we never
     * spawned any resource), so we return PAM_SUCCESS without
     * touching PAM_USER -- the mapped_user data slot is released
     * by the cleanup callback at pam_end. */
    if ((flags & PAM_ESTABLISH_CRED) != 0 ||
        (flags & PAM_REINITIALIZE_CRED) != 0)
    {
        (void)promote_mapped_user(pamh);
    }
    return PAM_SUCCESS;
}

PAM_EXTERN PAM_JWT_EXPORT int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                               int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    /* Account management is intentionally not implemented: pam_jwt's
     * job is to verify the bearer token at authentication time;
     * whatever account policy the system has for the authenticated
     * user (expiry, nologin, ...) is the job of other modules in
     * the stack (typically pam_unix or pam_nologin). */
    return PAM_SUCCESS;
}

PAM_EXTERN PAM_JWT_EXPORT int pam_sm_open_session(pam_handle_t *pamh,
                                                  int flags, int argc,
                                                  const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    /* pam_jwt does not participate in session management. Returning
     * PAM_SUCCESS keeps the module in the stack without doing
     * anything; PAM_IGNORE would silently drop it from the session
     * phase, which we don't want because other modules may rely on
     * the module being present for ordering. */
    return PAM_SUCCESS;
}

PAM_EXTERN PAM_JWT_EXPORT int pam_sm_close_session(pam_handle_t *pamh,
                                                   int flags, int argc,
                                                   const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    /* Mirror pam_sm_open_session: nothing to undo. */
    return PAM_SUCCESS;
}

PAM_EXTERN PAM_JWT_EXPORT int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
                                               int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    /* pam_jwt does not implement password changing: the credential
     * is a JWT, not a Unix password. Returning PAM_IGNORE signals to
     * libpam "this module does not handle this operation, please
     * continue with the next module in the stack" rather than
     * succeeding vacuously. */
    return PAM_IGNORE;
}
