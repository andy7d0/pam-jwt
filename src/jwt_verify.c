/*
 * src/jwt_verify.c
 *
 * JWT verification core for pam_jwt.
 *
 * Responsibilities:
 *   - Load the issuer X.509 certificate from cfg->cert_file, extract the
 *     public key, and render it as a PEM string suitable for libjwt.
 *   - Decode the token, verify the signature, and enforce the algorithm
 *     allowlist ({RS256, ES256}) plus an algorithm-vs-key-type match
 *     (prevents algorithm-confusion attacks against an RSA cert).
 *   - Validate time-based claims (exp, nbf) with the configured clock_skew.
 *   - Optionally enforce iss / aud equality with the configured values.
 *   - Optionally map the PAM user from a configurable claim
 *     (cfg->map_field) and/or require a configurable claim to equal the
 *     requested user (cfg->match_field).
 *
 * Security rules enforced here (from AGENTS.md):
 *   - alg=none and any algorithm outside {RS256, ES256} is rejected.
 *   - The JWT's `alg` must match the certificate's key type (RSA vs EC).
 *   - Never log the token, the password, or any private-key material.
 *   - Warn (debug) when cert_file is world-writable.
 *
 * The module never logs the token, authtok, or private key material; it
 * may log small structural facts (e.g. "expired", "iss mismatch",
 * "alg=HS256 rejected") at LOG_DEBUG when the cfg debug flag is set.
 */

#include "pam_jwt.h"

#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <jwt.h>

/* --- small helpers --------------------------------------------------------- */

/* Predicate: is `alg` one of the algorithms we accept? Currently RS256 and
 * ES256 are the only ones we trust. */
static bool alg_is_allowed(jwt_alg_t alg)
{
    return alg == JWT_ALG_RS256 || alg == JWT_ALG_ES256;
}

/* Predicate: does `alg` match the certificate's key type? RS256 must
 * ride an RSA key; ES256 must ride an EC key. Anything else is treated as
 * a possible algorithm-confusion attack and rejected. */
static bool alg_matches_key(jwt_alg_t alg, enum pam_jwt_key_type key_type)
{
    if (alg == JWT_ALG_RS256)
    {
        return key_type == PAM_JWT_KEY_RSA;
    }
    if (alg == JWT_ALG_ES256)
    {
        return key_type == PAM_JWT_KEY_EC;
    }
    return false;
}

/* --- certificate loading --------------------------------------------------- */

bool pam_jwt_load_cert(const char *cert_file, char **out_pem,
                       size_t *out_pem_len,
                       enum pam_jwt_key_type *out_key_type)
{
    if (out_pem != NULL)
    {
        *out_pem = NULL;
    }
    if (out_pem_len != NULL)
    {
        *out_pem_len = 0;
    }
    if (out_key_type != NULL)
    {
        *out_key_type = PAM_JWT_KEY_NONE;
    }
    if (cert_file == NULL || out_pem == NULL || out_pem_len == NULL ||
        out_key_type == NULL)
    {
        return false;
    }

    /* Slurp the PEM file into memory. OpenSSL's BIO_new_file takes a FILE*,
     * but reading the bytes first keeps BIO management simpler and lets us
     * use the helpers already declared in pam_jwt.h. */
    char *pem_buf = NULL;
    size_t pem_len = 0;
    if (!pam_jwt_read_file(cert_file, &pem_buf, &pem_len) || pem_buf == NULL)
    {
        /* pam_jwt_read_file() failed: bad path, non-regular file, OOM, ... */
        return false;
    }

    /* Build a read-only memory BIO over the slurped bytes. */
    BIO *bio = BIO_new_mem_buf(pem_buf, (int)pem_len);
    if (bio == NULL)
    {
        free(pem_buf);
        return false;
    }

    /* Parse the certificate. PEM_read_X509 takes a BIO, returns NULL on
     * failure. Any non-NULL X509* must be X509_free()d. */
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (cert == NULL)
    {
        /* Not a valid X.509 PEM (could be a public/private key, a CSR,
         * garbage, etc.). */
        free(pem_buf);
        return false;
    }

    /* Extract the public key. X509_get_pubkey returns a fresh EVP_PKEY that
     * must be freed. NULL on failure. */
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    X509_free(cert);
    if (pkey == NULL)
    {
        free(pem_buf);
        return false;
    }

    /* Classify the key. We refuse anything that isn't RSA or EC so the
     * caller can apply an algorithm-vs-key-type match. */
    enum pam_jwt_key_type key_type = PAM_JWT_KEY_NONE;
    int nid = EVP_PKEY_base_id(pkey);
    if (nid == EVP_PKEY_RSA)
    {
        key_type = PAM_JWT_KEY_RSA;
    }
    else if (nid == EVP_PKEY_EC)
    {
        key_type = PAM_JWT_KEY_EC;
    }
    else
    {
        EVP_PKEY_free(pkey);
        free(pem_buf);
        return false;
    }

    /* Render the public key as a generic SubjectPublicKeyInfo PEM so it
     * can be fed to libjwt regardless of the inner key type. */
    BIO *out_bio = BIO_new(BIO_s_mem());
    if (out_bio == NULL)
    {
        EVP_PKEY_free(pkey);
        free(pem_buf);
        return false;
    }
    if (PEM_write_bio_PUBKEY(out_bio, pkey) != 1)
    {
        BIO_free(out_bio);
        EVP_PKEY_free(pkey);
        free(pem_buf);
        return false;
    }

    /* Copy the BIO contents out as a NUL-terminated string. */
    char *bio_data = NULL;
    long bio_len = BIO_get_mem_data(out_bio, &bio_data);
    if (bio_data == NULL || bio_len <= 0)
    {
        BIO_free(out_bio);
        EVP_PKEY_free(pkey);
        free(pem_buf);
        return false;
    }
    char *out = malloc((size_t)bio_len + 1U);
    if (out == NULL)
    {
        BIO_free(out_bio);
        EVP_PKEY_free(pkey);
        free(pem_buf);
        return false;
    }
    memcpy(out, bio_data, (size_t)bio_len);
    out[bio_len] = '\0';

    BIO_free(out_bio);
    EVP_PKEY_free(pkey);
    free(pem_buf);

    *out_pem = out;
    *out_pem_len = (size_t)bio_len;
    *out_key_type = key_type;
    return true;
}

/* --- token verification ---------------------------------------------------- */

/* Compare two NUL-terminated strings for equality. Returns true iff both
 * pointers are non-NULL and the strings match byte-for-byte. Centralised so
 * the binding/mapping checks have a single source of truth. */
static bool str_eq(const char *a, const char *b)
{
    if (a == NULL || b == NULL)
    {
        return false;
    }
    return strcmp(a, b) == 0;
}

/* Skip JSON whitespace at p. Returns a pointer to the first non-WS byte
 * or to the trailing NUL. */
static const char *json_skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
    {
        p++;
    }
    return p;
}

/* Decode the JSON string starting just past the opening double-quote at
 * pp. Writes the decoded bytes into out (capacity out_cap) and NUL-
 * terminates on success. On return *pp points just past the closing
 * double-quote (or the trailing NUL on malformed input). Returns false
 * on overflow or an unterminated string.
 *
 * The JSON escape sequences RFC 8259 mandates inside a string literal
 * are handled: \" \\ \/ \n \t \r \b \f. Other escapes (notably \uXXXX)
 * are passed through verbatim, which is deliberately lenient -- the
 * input here comes from a JWT we have already parsed, so a strictly
 * conforming decode is not required for security. */
static bool json_decode_string(const char **pp, char *out, size_t out_cap)
{
    const char *p = *pp;
    size_t n = 0;
    while (*p != '\0')
    {
        char c = *p;
        if (c == '"')
        {
            p++;
            if (n + 1U >= out_cap)
            {
                return false;
            }
            out[n] = '\0';
            *pp = p;
            return true;
        }
        if (c == '\\' && p[1] != '\0')
        {
            p++;
            switch (*p)
            {
            case '"':
                c = '"';
                break;
            case '\\':
                c = '\\';
                break;
            case '/':
                c = '/';
                break;
            case 'n':
                c = '\n';
                break;
            case 't':
                c = '\t';
                break;
            case 'r':
                c = '\r';
                break;
            case 'b':
                c = '\b';
                break;
            case 'f':
                c = '\f';
                break;
            default:
                /* Unknown escape (e.g. unicode). Pass through both
                 * the backslash and the next char verbatim. */
                if (n + 2U >= out_cap)
                {
                    return false;
                }
                out[n++] = '\\';
                c = *p;
                p++;
                out[n++] = c;
                continue;
            }
            p++;
        }
        else
        {
            p++;
        }
        if (n + 1U >= out_cap)
        {
            return false;
        }
        out[n++] = c;
    }
    /* Unterminated string. */
    return false;
}

/* Return true iff needle equals one of the JSON string elements of the
 * JSON array at arr. The array must start with [. Comparison is byte-
 * for-byte after JSON unescaping, which matches the cfg-side value
 * (operators configure audience as plain strings, never JSON). */
static bool array_contains_string(const char *arr, const char *needle)
{
    const char *p = json_skip_ws(arr);
    if (*p != '[')
    {
        return false;
    }
    p++;
    char buf[1024];
    for (;;)
    {
        p = json_skip_ws(p);
        if (*p == ']')
        {
            return false;
        }
        if (*p != '"')
        {
            /* Non-string element (number, object, ...) is not a match. */
            return false;
        }
        p++;
        if (!json_decode_string(&p, buf, sizeof(buf)))
        {
            return false;
        }
        if (strcmp(buf, needle) == 0)
        {
            return true;
        }
        p = json_skip_ws(p);
        if (*p == ',')
        {
            p++;
            continue;
        }
        if (*p == ']')
        {
            return false;
        }
        /* Malformed: missing comma or closing bracket. */
        return false;
    }
}

/* Implement the audience containment check described in docs/config.md:
 *   1. If the token's aud claim is a JSON string and equals expected,
 *      return true.
 *   2. If the token's aud claim is a JSON array of strings and one of
 *      the elements equals expected, return true.
 *   3. Otherwise (missing claim, wrong type, or no match), return
 *      false.
 *
 * libjwt's jwt_get_grant() only returns string-typed grants, so the
 * array path is reached via jwt_get_grants_json(). Both return paths
 * leave a malloc'd string from libjwt that we must release. */
static bool audience_matches(jwt_t *jwt, const char *expected)
{
    const char *aud_str = jwt_get_grant(jwt, "aud");
    if (aud_str != NULL)
    {
        return strcmp(aud_str, expected) == 0;
    }
    char *aud_json = jwt_get_grants_json(jwt, "aud");
    if (aud_json == NULL)
    {
        return false;
    }
    bool ok = array_contains_string(aud_json, expected);
    free(aud_json);
    return ok;
}

/* Validate time-based claims (exp, nbf) using libjwt's validation object.
 * Returns true on success. */
static bool check_time_claims(jwt_t *jwt, int clock_skew)
{
    jwt_valid_t *valid = NULL;
    if (jwt_valid_new(&valid, jwt_get_alg(jwt)) != 0 || valid == NULL)
    {
        return false;
    }
    /* jwt_valid_set_now() defaults to time(NULL); we set it explicitly so
     * tests can be deterministic when they ever need to. */
    (void)jwt_valid_set_now(valid, time(NULL));
    if (clock_skew > 0)
    {
        (void)jwt_valid_set_exp_leeway(valid, (time_t)clock_skew);
        (void)jwt_valid_set_nbf_leeway(valid, (time_t)clock_skew);
    }
    unsigned int status = jwt_validate(jwt, valid);
    jwt_valid_free(valid);

    /* We only care about exp / nbf here. iss/aud/sub are checked by hand
     * so we can reuse libjwt's matching for time only. */
    return (status & (JWT_VALIDATION_EXPIRED | JWT_VALIDATION_TOO_NEW)) == 0;
}

int pam_jwt_verify(pam_handle_t *pamh, const struct pam_jwt_cfg *cfg,
                   const char *token, const char *requested_user,
                   char **out_mapped_user)
{
    /* Initialize all out params up-front so a failure in the middle of
     * this function leaves the caller with a known-clean state. */
    if (out_mapped_user != NULL)
    {
        *out_mapped_user = NULL;
    }

    /* Default the result to success; every failure path below jumps to
     * `cleanup` after setting `ret` to the appropriate PAM_* code. The
     * teardown is shared so we never duplicate `jwt_free`/`memset`/`free`
     * across the half-dozen failure branches. */
    int ret = PAM_SUCCESS;
    char *pubkey_pem = NULL;
    size_t pubkey_len = 0;
    jwt_t *jwt = NULL;

    if (cfg == NULL || token == NULL || requested_user == NULL)
    {
        return PAM_SERVICE_ERR;
    }
    if (cfg->cert_file == NULL)
    {
        /* Defensive: the config parser already enforces this, but the
         * verifier may be called directly from tests. */
        return PAM_SERVICE_ERR;
    }

    /* Sanity-check the token: libjwt rejects empty strings but the early
     * return keeps the code obvious. */
    if (token[0] == '\0')
    {
        return PAM_AUTH_ERR;
    }

    /* Load the issuer certificate. We intentionally pull this on every
     * call (rather than caching at config time) so a cert rotation is
     * picked up without restarting the PAM stack. The cert is small. */
    enum pam_jwt_key_type key_type = PAM_JWT_KEY_NONE;
    if (!pam_jwt_load_cert(cfg->cert_file, &pubkey_pem, &pubkey_len,
                           &key_type))
    {
        pam_jwt_log(pamh, cfg->debug, LOG_ERR,
                    "pam_jwt: failed to load issuer certificate");
        ret = PAM_SERVICE_ERR;
        goto cleanup;
    }

    /* Defence-in-depth: warn (debug) if the cert file is world-writable.
     * This catches a misconfigured deployment before it becomes a
     * privilege-escalation vector. */
    if (cfg->debug && pam_jwt_is_world_writable(cfg->cert_file))
    {
        pam_jwt_log(pamh, true, LOG_DEBUG,
                    "pam_jwt: cert_file is world-writable");
    }

    /* Decode + verify signature. libjwt's jwt_decode also accepts the
     * alg=none "unsigned" case; we treat that as an authentication
     * failure unconditionally (it would not pass jwt_decode's signature
     * check anyway, since we provide a non-NULL key, but we re-check
     * the alg explicitly below to be safe and to be able to emit a
     * precise diagnostic). */
    int rc = jwt_decode(&jwt, token,
                        (const unsigned char *)pubkey_pem,
                        (int)pubkey_len);
    if (rc != 0 || jwt == NULL)
    {
        /* jwt_decode() failed: malformed token, bad signature, or
         * alg/key mismatch. */
        pam_jwt_log(pamh, cfg->debug, LOG_DEBUG,
                    "pam_jwt: jwt_decode failed (bad signature or format)");
        ret = PAM_AUTH_ERR;
        goto cleanup;
    }

    jwt_alg_t alg = jwt_get_alg(jwt);
    if (!alg_is_allowed(alg) || !alg_matches_key(alg, key_type))
    {
        /* jwt_alg_str() returns a static, non-secret string from libjwt
         * (e.g. "RS256", "HS256"); safe to log. We only reach this branch
         * on a disallowed alg, so the diagnostic is the only useful signal
         * an operator gets about what the token actually claimed. */
        const char *alg_name = jwt_alg_str(alg);
        pam_jwt_log(pamh, cfg->debug, LOG_DEBUG,
                    "pam_jwt: rejecting token with disallowed alg=%s",
                    alg_name != NULL ? alg_name : "?");
        ret = PAM_AUTH_ERR;
        goto cleanup;
    }

    /* Validate exp / nbf with clock_skew. */
    if (!check_time_claims(jwt, cfg->clock_skew))
    {
        pam_jwt_log(pamh, cfg->debug, LOG_DEBUG,
                    "pam_jwt: token expired or not yet valid");
        ret = PAM_AUTH_ERR;
        goto cleanup;
    }

    /* Optional issuer match. */
    if (cfg->issuer != NULL)
    {
        const char *iss = jwt_get_grant(jwt, "iss");
        if (!str_eq(iss, cfg->issuer))
        {
            pam_jwt_log(pamh, cfg->debug, LOG_DEBUG,
                        "pam_jwt: iss claim does not match");
            ret = PAM_AUTH_ERR;
            goto cleanup;
        }
    }

    /* Optional audience match. libjwt only checks `aud` against a single
     * string when you ask it to, so we do it by hand. The token's `aud`
     * may be a JSON string or an array of strings; audience_matches()
     * handles both. */
    if (cfg->audience != NULL && !audience_matches(jwt, cfg->audience))
    {
        pam_jwt_log(pamh, cfg->debug, LOG_DEBUG,
                    "pam_jwt: aud claim does not match");
        ret = PAM_AUTH_ERR;
        goto cleanup;
    }

    /* Optional username binding: required claim must equal requested_user.
     * Done before mapping so a misconfigured deployment fails closed
     * with PAM_USER_UNKNOWN rather than silently substituting the user. */
    if (cfg->match_field != NULL)
    {
        const char *claim = jwt_get_grant(jwt, cfg->match_field);
        if (!str_eq(claim, requested_user))
        {
            pam_jwt_log(pamh, cfg->debug, LOG_DEBUG,
                        "pam_jwt: match_field claim does not equal user");
            ret = PAM_USER_UNKNOWN;
            goto cleanup;
        }
    }

    /* Optional username mapping: hand the caller a malloc'd copy of the
     * claim value when map_field is configured. The mapped claim must
     * exist AND be non-empty: docs/config.md documents the mapped user
     * as a PAM user name and an empty string here would either be
     * promoted to PAM_USER as "" or, if match_field is also on, fail
     * the binding check with a confusing PAM_USER_UNKNOWN. Reject up
     * front with PAM_AUTH_ERR so the failure mode is consistent with
     * the "missing claim" path and never produces an empty user. */
    if (cfg->map_field != NULL && out_mapped_user != NULL)
    {
        const char *claim = jwt_get_grant(jwt, cfg->map_field);
        if (claim == NULL)
        {
            pam_jwt_log(pamh, cfg->debug, LOG_DEBUG,
                        "pam_jwt: map_field claim missing in token");
            ret = PAM_AUTH_ERR;
            goto cleanup;
        }
        if (claim[0] == '\0')
        {
            pam_jwt_log(pamh, cfg->debug, LOG_DEBUG,
                        "pam_jwt: map_field claim is empty in token");
            ret = PAM_AUTH_ERR;
            goto cleanup;
        }
        char *copy = pam_jwt_strdup(claim);
        if (copy == NULL)
        {
            ret = PAM_BUF_ERR;
            goto cleanup;
        }
        *out_mapped_user = copy;
    }

cleanup:
    /* Single teardown point: release the parsed token (if any) and wipe
     * then free the heap-allocated PEM buffer. Both are NULL-safe. The
     * mapped user (if any) was handed off to the caller via
     * *out_mapped_user and is NOT freed here. */
    if (jwt != NULL)
    {
        jwt_free(jwt);
    }
    if (pubkey_pem != NULL)
    {
        /* The key is public, but the buffer was heap-allocated; wiping
         * before free keeps reentrancy-safe hygiene cheap. */
        memset(pubkey_pem, 0, pubkey_len);
        free(pubkey_pem);
    }
    return ret;
}
