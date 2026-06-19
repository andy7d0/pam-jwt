/*
 * vendor/libjwt/src/config.h
 *
 * Hand-rolled configuration header for the vendored libjwt 1.17.2. The
 * upstream build (autotools / CMake) produces a `config.h` for us; since
 * we compile the library directly out of vendor/, we ship a minimal one
 * that defines only what the OpenSSL backend needs.
 *
 *   HAVE_OPENSSL  -- selects the OpenSSL crypto backend (the only one
 *                    vendored). Defined; the alternative would be
 *                    HAVE_GNUTLS / HAVE_MBEDTLS, but those backends
 *                    are NOT vendored.
 *
 *   PACKAGE /
 *   PACKAGE_VERSION
 *                 -- referenced in jwt.c error strings. Hard-coded to
 *                    the vendored tag so `pam_jwt -V` style diagnostics
 *                    attribute the right thing.
 *
 * All other macros the upstream `configure` script probes for (HAVE_*
 * feature checks, etc.) are NOT defined here; the vendored .c files
 * don't actually consume them in the paths we exercise, but if a future
 * vendored source gains a new dependency this file is the place to
 * extend it.
 *
 * DO NOT add HAVE_GNUTLS or any non-OpenSSL crypto backend: doing so
 * would require vendoring that backend too, and the project does not
 * link against GnuTLS / mbedTLS / Windows CryptoAPI.
 */
#ifndef LIBJWT_VENDORED_CONFIG_H
#define LIBJWT_VENDORED_CONFIG_H

#define HAVE_OPENSSL 1

/* Upstream identity strings used in error / log messages. Keep them
 * stable so callers (and our own debug builds) can tell the vendored
 * copy apart from a system-installed libjwt.so. */
#define PACKAGE "pam-jwt-vendored-libjwt"
#define PACKAGE_VERSION "1.17.2"

#endif /* LIBJWT_VENDORED_CONFIG_H */
