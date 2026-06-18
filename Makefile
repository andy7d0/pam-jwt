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

.PHONY: all test check clean install uninstall

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
TEST_CFLAGS := $(COMMON_CFLAGS) -Itests
TEST_LDLIBS := $(PKG_LDLIBS) -ldl

$(TEST_BIN): $(TEST_OBJS) | $(BUILDDIR)/tests
	$(CC) -o $@ $(TEST_OBJS) $(TEST_LDLIBS)

$(BUILDDIR)/tests/%.o: $(TESTDIR)/%.c | $(BUILDDIR)/tests
	$(CC) $(TEST_CFLAGS) -c $< -o $@

$(BUILDDIR)/tests:
	@mkdir -p $@

test check: $(TEST_BIN)
	@bash $(FIXDIR)/gen_certs.sh $(FIXDIR)
	@$(MAKE) -s $(FIXDIR)/make_jwt FIXDIR=$(FIXDIR) BUILDDIR=$(BUILDDIR)
	@$(TEST_BIN)

$(FIXDIR)/make_jwt: $(FIXDIR)/make_jwt.c | $(BUILDDIR)
	$(CC) $(COMMON_CFLAGS) -I$(FIXDIR) -o $@ $< $(PKG_LDLIBS)

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
