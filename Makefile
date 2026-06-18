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

PKGS   := $(PKG_PAM) libjwt openssl
PKG_CFLAGS  := $(shell $(PKG_CONFIG) --cflags $(PKGS))
PKG_LDLIBS  := $(shell $(PKG_CONFIG) --libs   $(PKGS))

# --- Compile / link flags ----------------------------------------------------

WARNINGS  := -Wall -Wextra -Werror
COMMON_CFLAGS := -std=c11 -fPIC -fvisibility=hidden \
                 -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L \
                 $(WARNINGS) $(PKG_CFLAGS) -Iinclude

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

LIB_SRCS    := $(wildcard $(SRCDIR)/*.c)
LIB_OBJS    := $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(LIB_SRCS))
LIB_SO      := $(BUILDDIR)/pam_jwt.so

EXAMPLE_CONF := examples/pam-jwt.conf

# --- Targets -----------------------------------------------------------------

.PHONY: all test check test-asan clean install uninstall

all: $(LIB_SO)

$(LIB_SO): $(LIB_OBJS) | $(BUILDDIR)
	$(CC) -shared -Wl,-soname,pam_jwt.so -o $@ $(LIB_OBJS) $(PKG_LDLIBS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.c | $(BUILDDIR)
	$(CC) $(COMMON_CFLAGS) -c $< -o $@

$(BUILDDIR):
	@mkdir -p $@

# --- Tests -------------------------------------------------------------------

TEST_BIN := $(BUILDDIR)/run_tests
TEST_SRCS := $(wildcard $(TESTDIR)/*.c)
TEST_OBJS := $(patsubst $(TESTDIR)/%.c,$(BUILDDIR)/tests/%.o,$(TEST_SRCS))
# Pull in the library object files so test binaries can call e.g.
# pam_jwt_cfg_parse() without the full .so being loaded.
TEST_LIB_OBJS := $(LIB_OBJS)
TEST_CFLAGS := $(COMMON_CFLAGS) -Itests
TEST_LDLIBS := $(PKG_LDLIBS) -ldl

$(TEST_BIN): $(TEST_OBJS) $(TEST_LIB_OBJS) | $(BUILDDIR)/tests
	$(CC) -o $@ $(TEST_OBJS) $(TEST_LIB_OBJS) $(TEST_LDLIBS)

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

$(FIXDIR)/make_jwt: $(FIXDIR)/make_jwt.c | $(BUILDDIR)
	$(CC) $(COMMON_CFLAGS) -I$(FIXDIR) -o $@ $< $(PKG_LDLIBS)

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
ASAN_LIB_OBJS := \
    $(ASAN_BUILDDIR)/config.o \
    $(ASAN_BUILDDIR)/util.o

ASAN_TEST_OBJS := \
    $(ASAN_BUILDDIR)/tests/run_tests.o \
    $(ASAN_BUILDDIR)/tests/test.o \
    $(ASAN_BUILDDIR)/tests/test_config.o \
    $(ASAN_BUILDDIR)/tests/test_util.o

test-asan:
	@echo "== building with ASan + UBSan =="
	@$(MAKE) --no-print-directory clean
	@mkdir -p $(ASAN_BUILDDIR)/tests
	@for f in $(SRCDIR)/*.c; do \
	    $(CC) $(COMMON_CFLAGS) $(ASAN_FLAGS) -c $$f -o $(ASAN_BUILDDIR)/$$(basename $$f .c).o; \
	done
	@for f in $(TESTDIR)/*.c; do \
	    $(CC) $(COMMON_CFLAGS) -Itests $(ASAN_FLAGS) -c $$f -o $(ASAN_BUILDDIR)/tests/$$(basename $$f .c).o; \
	done
	@$(CC) -o $(ASAN_BUILDDIR)/run_tests \
	    $(ASAN_TEST_OBJS) $(ASAN_LIB_OBJS) \
	    $(PKG_LDLIBS) $(ASAN_LDLIBS) -ldl
	@echo "== running under ASan =="
	@UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
	 ASAN_OPTIONS=detect_leaks=1:strict_string_checks=1:halt_on_error=1 \
	 $(ASAN_BUILDDIR)/run_tests
	@echo "== ASan run clean =="

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
