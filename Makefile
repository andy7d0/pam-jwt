# pam-jwt — Makefile
#
# Build the Linux-PAM module pam_jwt.so. Run `make test` for the test suite.

# --- Toolchain ---------------------------------------------------------------

CC          ?= cc
PKG_CONFIG  ?= pkg-config

# --- Install layout ----------------------------------------------------------

PREFIX ?= /usr/local
DESTDIR ?=

INSTALL_DIR      := $(DESTDIR)$(PREFIX)/lib/security
INSTALL_CONF_DIR := $(DESTDIR)$(PREFIX)/share/pam-jwt

# --- pkg-config flags --------------------------------------------------------

# PAM pkg-config module name varies by distro:
#   - Debian / Ubuntu derivatives ship it as `pam`
#   - Some other distros ship it as `libpam`
# Probe for `pam` first, fall back to `libpam`.
PKG_PAM := $(shell if $(PKG_CONFIG) --exists pam; then echo pam; elif $(PKG_CONFIG) --exists libpam; then echo libpam; else echo pam; fi)

# libjwt is VENDORED under vendor/libjwt/ (see vendor/libjwt/README.md) and
# is linked in as a static archive from $(VENDOR_LIB). The system libjwt
# (whatever version the host happens to ship -- 1.x on Debian, 3.x on
# Alpine 3.24) is intentionally NOT a build-time dependency. jansson is a
# runtime dep of the vendored libjwt 1.x and stays a system library.
PKGS   := $(PKG_PAM) jansson openssl
PKG_CFLAGS  := $(shell $(PKG_CONFIG) --cflags $(PKGS))
PKG_LDLIBS  := $(shell $(PKG_CONFIG) --libs   $(PKGS))

# --- Compile / link flags ----------------------------------------------------

# pam-jwt's own sources: strict. -Werror is non-negotiable per AGENTS.md
# so a future maintainer never ships a tree that builds with warnings.
WARNINGS  := -Wall -Wextra -Werror
COMMON_CFLAGS := -std=c11 -fPIC -fvisibility=hidden \
                 -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L \
                 $(WARNINGS) $(PKG_CFLAGS) \
                 -Iinclude -Ivendor/libjwt/include

# Vendored libjwt 1.17.2: relaxed. We did not write this code and do
# not want to fork it on every new compiler release, so we keep -Wall
# (so genuine issues still surface) but drop -Wextra and -Werror. This
# matches the upstream build's default (autotools only enables -Werror
# when --enable-werror is passed at configure time). The vendored
# config.h / API surface we depend on is exercised by the test suite,
# so regressions in libjwt itself are still caught at `make test` /
# `make test-asan` time.
VENDOR_WARNINGS := -Wall
VENDOR_CFLAGS  := -std=c11 -fPIC -fvisibility=default \
                  -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L \
                  $(VENDOR_WARNINGS) $(PKG_CFLAGS) \
                  -Ivendor/libjwt/include -Ivendor/libjwt/src

# Release build flags. Used only by the `make release` target. The debug
# build path (the default `all` target) is unaffected.
#
#   -O3 -flto          : maximum optimization + link-time optimization
#   -DNDEBUG           : drop assert()s
#   -D_FORTIFY_SOURCE=2: runtime bounds checking in libc calls
#   -fstack-protector-strong : canary on functions with locals
#   -fno-plt           : PLT-free calls (smaller .so, slightly faster)
#   -fno-semantic-interposition : keep our symbols visible to LTO only
#   -fdata-sections -ffunction-sections + --gc-sections : drop dead code
#   -ffile-prefix-map / -fmacro-prefix-map : reproducible paths in .so
#   -fno-unwind-tables -fno-asynchronous-unwind-tables : smaller unwind data
#   -fno-ident         : drop the GCC version ident string
#
# LDFLAGS additions enable full RELRO + immediate binding + GNU_HASH +
# build-id, and pass the version script exported via -fvisibility=hidden.
RELEASE_CFLAGS := -O3 -flto -DNDEBUG \
                  -D_FORTIFY_SOURCE=2 \
                  -fstack-protector-strong \
                  -fno-plt -fno-semantic-interposition \
                  -fdata-sections -ffunction-sections \
                  -ffile-prefix-map=$(CURDIR)=. \
                  -fmacro-prefix-map=$(CURDIR)=. \
                  -fno-unwind-tables -fno-asynchronous-unwind-tables \
                  -fno-ident \
                  $(COMMON_CFLAGS)
RELEASE_LDFLAGS := -Wl,-O1 -Wl,--gc-sections \
                   -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack \
                   -Wl,--build-id=sha1 \
                   -Wl,--hash-style=gnu \
                   -Wl,--version-script=$(CURDIR)/pam_jwt.map

# Convenience: the path users typically want after a release build.
STRIP ?= strip
VERSION_SCRIPT := $(CURDIR)/pam_jwt.map
# Version string embedded in the .so via -DPAM_JWT_VERSION. Prefer
# `git describe` so packaged builds are tagged, falling back to "dev"
# for tarball builds.
PAM_JWT_VERSION := $(shell git describe --tags --always --dirty 2>/dev/null \
                              || echo "dev")

# AddressSanitizer + UndefinedBehaviorSanitizer flags. Opt-in via
# `make test-asan`. LeakSanitizer (bundled with ASan) runs at process
# exit and makes the binary return non-zero on any leaked block,
# which is exactly the check `tests/test_config.c`'s `leak:` cases
# rely on. ASan is added to both CFLAGS and LDFLAGS so the same
# instrumentation is used for compilation and link.
ASAN_FLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer -g
ASAN_LDLIBS := -fsanitize=address,undefined

# --- Directories / files -----------------------------------------------------

SRCDIR      := src
INCDIR      := include
BUILDDIR    := build
TESTDIR     := tests
FIXDIR      := $(TESTDIR)/fixtures
VENDORDIR   := vendor/libjwt

LIB_SRCS    := $(wildcard $(SRCDIR)/*.c)
LIB_OBJS    := $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(LIB_SRCS))
LIB_SO      := $(BUILDDIR)/pam_jwt.so

# Vendored libjwt 1.17.2 sources (see vendor/libjwt/README.md). Compiled
# into a static archive and linked into both pam_jwt.so and the test
# binaries so the build does not depend on whatever libjwt-dev the host
# happens to ship. We deliberately exclude jwt-gnutls.c and jwt-wincrypt.c
# (neither backend is supported by pam-jwt -- we use OpenSSL only).
VENDOR_SRCS := $(VENDORDIR)/src/base64.c \
               $(VENDORDIR)/src/jwt.c \
               $(VENDORDIR)/src/jwt-openssl.c
VENDOR_OBJS := $(patsubst $(VENDORDIR)/src/%.c,$(BUILDDIR)/vendor/%.o,$(VENDOR_SRCS))
VENDOR_LIB  := $(BUILDDIR)/vendor/libjwt.a

EXAMPLE_CONF := examples/pam-jwt.conf

# --- Targets -----------------------------------------------------------------

.PHONY: all test check test-asan clean install uninstall \
        release release-info install-release

all: $(LIB_SO)

# $(LIB_SO) depends on the vendored libjwt static archive so the
# jwt_verify.c / pam_jwt.c calls into libjwt are satisfied at link
# time. The static archive is built below.
$(LIB_SO): $(LIB_OBJS) $(VENDOR_LIB) | $(BUILDDIR)
	$(CC) -shared -Wl,-soname,pam_jwt.so -o $@ \
	    -Wl,--whole-archive $(VENDOR_LIB) -Wl,--no-whole-archive \
	    $(LIB_OBJS) $(PKG_LDLIBS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.c | $(BUILDDIR)
	$(CC) $(COMMON_CFLAGS) -c $< -o $@

$(BUILDDIR):
	@mkdir -p $@

# --- Vendored libjwt (static) -----------------------------------------------

# Compile each vendored libjwt source into a position-independent object.
# The vendored library has its own private headers in vendor/libjwt/src/
# (config.h, base64.h, jwt-private.h), so the include path needs to point
# there in addition to the public include/. We deliberately do NOT pass
# -fvisibility=hidden here: libjwt symbols must remain visible inside
# the .a so the linker can resolve them when they are pulled in by
# pam_jwt.c / jwt_verify.c / make_jwt.c. The flags come from
# $(VENDOR_CFLAGS) (relaxed warnings; see comment above) so the
# upstream libjwt code does not need to be patched to compile cleanly
# under -Wextra / -Werror.
$(BUILDDIR)/vendor/%.o: $(VENDORDIR)/src/%.c | $(BUILDDIR)/vendor
	$(CC) $(VENDOR_CFLAGS) -c $< -o $@

# Pack the vendored objects into a static archive. `ar rcs` creates the
# archive if needed and adds an index so the linker can pull only the
# objects it actually references.
$(VENDOR_LIB): $(VENDOR_OBJS) | $(BUILDDIR)/vendor
	$(AR) rcs $@ $(VENDOR_OBJS)

$(BUILDDIR)/vendor:
	@mkdir -p $@

# --- Tests -------------------------------------------------------------------

TEST_BIN := $(BUILDDIR)/run_tests
TEST_SRCS := $(wildcard $(TESTDIR)/*.c)
TEST_OBJS := $(patsubst $(TESTDIR)/%.c,$(BUILDDIR)/tests/%.o,$(TEST_SRCS))
# Pull in the library object files so test binaries can call e.g.
# pam_jwt_cfg_parse() without the full .so being loaded. The vendored
# libjwt archive is also linked in so jwt_verify.c calls into libjwt
# resolve.
TEST_LIB_OBJS := $(LIB_OBJS) $(VENDOR_LIB)
TEST_CFLAGS := $(COMMON_CFLAGS) -Itests
TEST_LDLIBS := $(PKG_LDLIBS) -ldl

# Whole-archive is needed so symbols from libjwt that pam_jwt.c / the
# tests don't directly reference are still pulled out of the .a (some
# libjwt entry points are reached indirectly through function pointers
# or the headers-only references in jwt-private.h).
$(TEST_BIN): $(TEST_OBJS) $(TEST_LIB_OBJS) | $(BUILDDIR)/tests
	$(CC) -o $@ \
	    -Wl,--whole-archive $(VENDOR_LIB) -Wl,--no-whole-archive \
	    $(TEST_OBJS) $(LIB_OBJS) $(TEST_LDLIBS)

# Per-file CFLAGS additions. test_jwt_verify.c mints tokens by exec'ing
# tests/fixtures/make_jwt and reading tests/fixtures/*.pem/*.key, so it
# needs to know the fixture directory at compile time. We inject -D
# flags per object via a per-target CC command rather than a global
# CFLAGS bump so the other test objects don't pick up the defines.
FIX_DIR   := $(TESTDIR)/fixtures
MAKE_JWT  := $(FIX_DIR)/make_jwt

$(BUILDDIR)/tests/test_jwt_verify.o: $(TESTDIR)/test_jwt_verify.c | $(BUILDDIR)/tests
	$(CC) $(TEST_CFLAGS) -DFIX_DIR='"$(FIX_DIR)"' -DMAKE_JWT='"$(MAKE_JWT)"' -c $< -o $@

$(BUILDDIR)/tests/%.o: $(TESTDIR)/%.c | $(BUILDDIR)/tests
	$(CC) $(TEST_CFLAGS) -c $< -o $@

$(BUILDDIR)/tests:
	@mkdir -p $@

# `make test` runs the unit test suite. Fixture-generating steps
# (`tests/fixtures/gen_certs.sh`, `tests/fixtures/make_jwt.c`) are
# owned by later test groups (jwt_verify, claims, users) and are
# only invoked if the fixture scripts exist; the config-parser
# tests need no fixtures at all.
FIXTURE_SCRIPT := $(FIXDIR)/gen_certs.sh
FIXTURE_BIN    := $(FIXDIR)/make_jwt

test check: $(TEST_BIN)
	@if [ -f $(FIXTURE_SCRIPT) ]; then \
	    bash $(FIXTURE_SCRIPT) $(FIXDIR); \
	else \
	    echo "(skipping $(FIXTURE_SCRIPT); not present yet)"; \
	fi
	@if [ -f $(FIXDIR)/make_jwt.c ]; then \
	    $(MAKE) -s $(FIXTURE_BIN) FIXDIR=$(FIXDIR) BUILDDIR=$(BUILDDIR); \
	else \
	    echo "(skipping make_jwt build; source not present yet)"; \
	fi
	@$(TEST_BIN)

$(FIXDIR)/make_jwt: $(FIXDIR)/make_jwt.c $(VENDOR_LIB) | $(BUILDDIR)
	$(CC) $(COMMON_CFLAGS) -I$(FIXDIR) -o $@ $< \
	    -Wl,--whole-archive $(VENDOR_LIB) -Wl,--no-whole-archive \
	    $(PKG_LDLIBS)

# `make test-asan` rebuilds the test binary with AddressSanitizer +
# UndefinedBehaviorSanitizer enabled. LeakSanitizer (bundled with
# ASan) runs at process exit and turns the run red on any leaked
# heap block, UAF, or out-of-bounds access. Use this target before
# claiming a parser/verify change is leak-free.
#
# The target re-invokes make with a separate build directory so the
# fast `make test` path stays green and incremental.
ASAN_BUILDDIR := $(BUILDDIR)/asan

# Object files linked into the ASan test binary. Each module under
# $(SRCDIR) is built with ASan/UBSan instrumentation; test modules
# under $(TESTDIR) are likewise. Keep this list in sync as new
# tests land -- if a new test_*.c is added, append its object here
# and the corresponding forward decl + call in tests/run_tests.c.
# Library objects linked into the ASan test binary. Note that
# pam_jwt.o is deliberately NOT in this list: linking it into
# run_tests would define pam_sm_authenticate() and friends in the
# test process, conflicting with the dlopen() of the .so in the
# pam_harness integration tests. The .so gets its own list below.
ASAN_LIB_OBJS := \
    $(ASAN_BUILDDIR)/config.o \
    $(ASAN_BUILDDIR)/jwt_verify.o \
    $(ASAN_BUILDDIR)/util.o

# Vendored libjwt objects compiled with ASan instrumentation. Built
# inline below (no separate archive) so the .o files are guaranteed to
# carry the sanitizer instrumentation the rest of the test binary
# carries -- a separately-built libjwt.a would not be instrumented and
# would hide leaks / UAF behind a sanitizer-invisible wall.
ASAN_VENDOR_OBJS := \
    $(ASAN_BUILDDIR)/vendor/base64.o \
    $(ASAN_BUILDDIR)/vendor/jwt.o \
    $(ASAN_BUILDDIR)/vendor/jwt-openssl.o

ASAN_SO_OBJS := \
    $(ASAN_LIB_OBJS) \
    $(ASAN_BUILDDIR)/pam_jwt.o \
    $(ASAN_VENDOR_OBJS)

ASAN_TEST_OBJS := \
    $(ASAN_BUILDDIR)/tests/run_tests.o \
    $(ASAN_BUILDDIR)/tests/test.o \
    $(ASAN_BUILDDIR)/tests/test_claims.o \
    $(ASAN_BUILDDIR)/tests/test_config.o \
    $(ASAN_BUILDDIR)/tests/test_jwt_verify.o \
    $(ASAN_BUILDDIR)/tests/test_users.o \
    $(ASAN_BUILDDIR)/tests/test_util.o \
    $(ASAN_BUILDDIR)/tests/pam_harness.o

test-asan:
	@echo "== building with ASan + UBSan =="
	@$(MAKE) --no-print-directory clean
	@mkdir -p $(ASAN_BUILDDIR)/tests $(ASAN_BUILDDIR)/vendor $(BUILDDIR)
	@for f in $(SRCDIR)/*.c; do \
	    $(CC) $(COMMON_CFLAGS) $(ASAN_FLAGS) -c $$f -o $(ASAN_BUILDDIR)/$$(basename $$f .c).o; \
	done
	@for f in $(TESTDIR)/*.c; do \
	    $(CC) $(COMMON_CFLAGS) -Itests $(ASAN_FLAGS) \
	        -DFIX_DIR='"$(FIXDIR)"' -DMAKE_JWT='"$(FIXDIR)/make_jwt"' \
	        -c $$f -o $(ASAN_BUILDDIR)/tests/$$(basename $$f .c).o; \
	done
	# Vendored libjwt, compiled with the same sanitizer instrumentation
	# as the rest of the binary. Putting these in a separate archive
	# would silently hide leaks / UAF in libjwt code from the sanitizer.
	# We use VENDOR_CFLAGS (relaxed warnings) + ASAN_FLAGS (sanitizers),
	# so sanitizer coverage on the vendored code stays maximal even
	# though we don't own the source.
	@for f in $(VENDOR_SRCS); do \
	    $(CC) $(VENDOR_CFLAGS) $(ASAN_FLAGS) \
	        -c $$f -o $(ASAN_BUILDDIR)/vendor/$$(basename $$f .c).o; \
	done
	@$(CC) -o $(ASAN_BUILDDIR)/run_tests \
	    $(ASAN_TEST_OBJS) $(ASAN_LIB_OBJS) $(ASAN_VENDOR_OBJS) \
	    $(PKG_LDLIBS) $(ASAN_LDLIBS) -ldl
	# The pam_harness integration tests dlopen() pam_jwt.so via libpam,
	# so we must also build the .so (with ASan instrumentation baked in)
	# and place it at the path tests/pam_harness.c hard-codes. Note
	# that the .so object list is ASAN_SO_OBJS, not ASAN_LIB_OBJS: the
	# latter deliberately omits pam_jwt.o to avoid double-defining
	# pam_sm_authenticate() inside run_tests.
	@$(CC) -shared -Wl,-soname,pam_jwt.so \
	    -o $(BUILDDIR)/pam_jwt.so \
	    $(ASAN_SO_OBJS) \
	    $(PKG_LDLIBS) $(ASAN_LDLIBS)
	@echo "== running under ASan =="
	@UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
	 ASAN_OPTIONS=detect_leaks=1:strict_string_checks=1:halt_on_error=1 \
	 $(ASAN_BUILDDIR)/run_tests
	@echo "== ASan run clean =="

# --- Release -----------------------------------------------------------------

# `make release` builds an optimized, stripped, hardened pam_jwt.so
# into build/release/pam_jwt.so. It does NOT rebuild the default debug
# tree at build/, so both can coexist. The release .so:
#
#   * is compiled with -O3 -flto and -DNDEBUG
#   * has hidden visibility + a version script exporting only pam_sm_*
#   * has full RELRO, immediate binding, GNU hash, build-id
#   * has its ELF debug sections stripped via $(STRIP) --strip-debug
#     (strips .debug_*, leaves .dynsym / .dynstr / .symtab / .strtab
#     so file(1) and ldd(1) still report the .so correctly)
#   * embeds a PAM_JWT_VERSION string (git describe, or "dev")
#
# Use `make install-release` to install it into $(INSTALL_DIR).
#
# Override the toolchain if you need to: `make release CC=clang`.
RELEASE_BUILDDIR := $(BUILDDIR)/release
RELEASE_OBJS    := $(patsubst $(SRCDIR)/%.c,$(RELEASE_BUILDDIR)/%.o,$(LIB_SRCS))
# Vendored libjwt objects built with the same release flags as the
# pam-jwt sources. Linked in whole-archive below so LTO can inline
# libjwt functions into pam_jwt.so and the version script still hides
# everything but the pam_sm_* entry points.
RELEASE_VENDOR_OBJS := \
    $(RELEASE_BUILDDIR)/vendor/base64.o \
    $(RELEASE_BUILDDIR)/vendor/jwt.o \
    $(RELEASE_BUILDDIR)/vendor/jwt-openssl.o
RELEASE_SO      := $(RELEASE_BUILDDIR)/pam_jwt.so

# The release build needs its own pam_jwt.so entry in the .gitignore
# so accidental `git status` noise stays out.
.PHONY: release-tree
release-tree:
	@mkdir -p $(RELEASE_BUILDDIR) $(RELEASE_BUILDDIR)/vendor

# Release .o files need LTO-aware CFLAGS + a -DPAM_JWT_VERSION define
# baked in. We deliberately drop -g from the embedded debug info so
# the strip-debug step below has something to strip; the .so stays
# small but identifiers remain in the dynsym.
$(RELEASE_BUILDDIR)/%.o: $(SRCDIR)/%.c | release-tree
	$(CC) $(RELEASE_CFLAGS) -DPAM_JWT_VERSION='"$(PAM_JWT_VERSION)"' \
	      -c $< -o $@

# Vendored libjwt, compiled with the release flags but with relaxed
# warnings (we did not write the upstream code; do not let its
# -Wsign-compare / -Wpointer-sign issues gate pam-jwt's release
# build). Mirrors the non-release build's -fvisibility=default so
# libjwt symbols are visible to the linker during whole-archive
# inclusion, then become hidden again at the .so boundary via the
# version script.
$(RELEASE_BUILDDIR)/vendor/%.o: $(VENDORDIR)/src/%.c | release-tree
	$(CC) $(RELEASE_CFLAGS) -fvisibility=default -I$(VENDORDIR)/src \
	      -DPAM_JWT_VERSION='"$(PAM_JWT_VERSION)"' \
	      -Wno-error -Wno-sign-compare -Wno-pointer-sign \
	      -c $< -o $@

# Link the release .so. -flto requires LTO on the link command too,
# so the per-object LTO bitcode is merged at link time. The version
# script restricts the dynamic symbol table to the pam_sm_* entries
# that Linux-PAM looks up at module load.
$(RELEASE_SO): $(RELEASE_OBJS) $(RELEASE_VENDOR_OBJS) $(VERSION_SCRIPT) | release-tree
	$(CC) -shared -Wl,-soname,pam_jwt.so -flto \
	      $(RELEASE_LDFLAGS) \
	      -Wl,--whole-archive $(RELEASE_VENDOR_OBJS) -Wl,--no-whole-archive \
	      -o $@ $(RELEASE_OBJS) $(PKG_LDLIBS)

# Strip debug sections in-place. We keep .dynsym / .dynstr so the
# dynamic loader can still resolve symbols and the .so reports a sane
# list of exported entry points via `nm -D`. We do NOT run `strip
# --strip-unneeded` because that removes .symtab/.strtab, which some
# distributions' debug-info tooling prefers to retain.
$(RELEASE_SO).stripped: $(RELEASE_SO)
	$(STRIP) --strip-debug -o $@ $<

# Phony entry point. Always rebuilds, so a `make release` after a
# source change picks up the new bits without a manual `make clean`.
release: $(RELEASE_SO).stripped
	@echo "release .so: $(RELEASE_SO).stripped"
	@echo "version:     $(PAM_JWT_VERSION)"
	@ls -l $(RELEASE_SO).stripped

# Quick version stamp for packaging scripts / CI logs.
release-info:
	@echo "pam-jwt version: $(PAM_JWT_VERSION)"
	@echo "release .so:     $(RELEASE_SO).stripped"

# Install the stripped release .so. Honors $(DESTDIR) and $(PREFIX)
# exactly like the regular `install` target.
install-release: release
	install -d $(INSTALL_DIR)
	install -m 0644 $(RELEASE_SO).stripped $(INSTALL_DIR)/pam_jwt.so

# --- Install / uninstall -----------------------------------------------------

install: $(LIB_SO) $(EXAMPLE_CONF)
	install -d $(INSTALL_DIR) $(INSTALL_CONF_DIR)
	install -m 0644 $(LIB_SO) $(INSTALL_DIR)/pam_jwt.so
	install -m 0644 $(EXAMPLE_CONF) $(INSTALL_CONF_DIR)/pam-jwt.conf

uninstall:
	rm -f $(INSTALL_DIR)/pam_jwt.so
	rm -f $(INSTALL_CONF_DIR)/pam-jwt.conf

# --- Clean -------------------------------------------------------------------

clean:
	rm -rf $(BUILDDIR)
# Note: $(BUILDDIR) already covers build/release/ since release lives
# under build/. No additional path needed here.
