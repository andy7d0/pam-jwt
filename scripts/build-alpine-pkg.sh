#!/usr/bin/env bash
#
# build-alpine-pkg.sh — build a release .apk for pam-jwt in a container.
#
# Approach (deliberately NOT using abuild):
#
#   1. Bind-mount the pam-jwt source tree (read-only) at /src, the
#      output directory (read-write) at /out, and this script's
#      embedded build recipe (read-only) at /build/inner.sh.
#   2. The container runs `sh /build/inner.sh`, which performs:
#        cp -a /src /tmp/src
#        apk update + apk add <build deps>
#        make -j$N release PREFIX=/usr PAM_JWT_VERSION=<ver>
#        make install-release PREFIX=/usr DESTDIR=/pkg
#        writes a hand-rolled .PKGINFO from env vars
#        optionally signs the .PKGINFO with openssl(1) if a key
#          is mounted at /signing/key.rsa.priv
#        assembles the .apk as `gzip -n -9 ( tar -C /pkg )` plus
#          a concatenated .PKGINFO and optional .SIGN.RSA.* trailer
#        installs the result to /out/pam-jwt.apk
#   3. Back on the host, the script renames the artifact to
#      <out>/pam-jwt-<version>.apk and prints its contents.
#
# The host's source tree is mounted read-only; `make release` needs
# a writable tree to create build/, so the inner script copies /src
# to /tmp/src first. This keeps the developer checkout clean.
#
# libjwt is VENDORED under vendor/libjwt/ and is built by the
# project's own Makefile, so the host's libjwt-dev is irrelevant;
# we are immune to Alpine's 1.x → 3.x ABI break.
#
# Usage:
#   ./scripts/build-alpine-pkg.sh
#   ./scripts/build-alpine-pkg.sh --out dist/
#   ./scripts/build-alpine-pkg.sh --runtime podman
#   ./scripts/build-alpine-pkg.sh --alpine 3.24
#   ./scripts/build-alpine-pkg.sh --sign-key /path/to/priv.key
#
# Environment variables:
#   RUNTIME        override container runtime (docker|podman). Auto-detected.
#   ALPINE_TAG     override the base image tag (default: alpine:latest).
#
# Exit codes:
#   0  package built successfully
#   1  usage / argument error
#   2  required tool missing
#   3  container build failed
#   4  package assembly failed

set -euo pipefail

readonly SCRIPT_NAME=${0##*/}
readonly SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
readonly REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

log()  { printf '[%s] %s\n'  "$SCRIPT_NAME" "$*" >&2; }
err()  { printf '[%s] error: %s\n' "$SCRIPT_NAME" "$*" >&2; }
die()  { err "$@"; exit 1; }

usage() {
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
}

# --- Defaults ----------------------------------------------------------------

OUT_DIR="$REPO_ROOT/dist"
RUNTIME="${RUNTIME:-}"
ALPINE_TAG="${ALPINE_TAG:-alpine:latest}"
SIGN_KEY=""
JOBS="$(nproc 2>/dev/null || echo 2)"

# --- Arg parsing -------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        --out)
            [[ $# -ge 2 ]] || die "--out requires a directory argument"
            OUT_DIR=$2
            shift 2
            ;;
        --runtime)
            [[ $# -ge 2 ]] || die "--runtime requires docker|podman"
            RUNTIME=$2
            shift 2
            ;;
        --alpine)
            [[ $# -ge 2 ]] || die "--alpine requires a tag (e.g. 3.24)"
            ALPINE_TAG="alpine:$2"
            shift 2
            ;;
        --sign-key)
            [[ $# -ge 2 ]] || die "--sign-key requires a path"
            SIGN_KEY=$2
            shift 2
            ;;
        -j|--jobs)
            [[ $# -ge 2 ]] || die "--jobs requires a number"
            JOBS=$2
            shift 2
            ;;
        *)
            die "unknown argument: $1 (try --help)"
            ;;
    esac
done

mkdir -p "$OUT_DIR"
OUT_DIR=$(cd "$OUT_DIR" && pwd)   # absolute

# --- Sanity checks -----------------------------------------------------------

command -v tar  >/dev/null 2>&1 || die "host is missing 'tar'"
command -v gzip >/dev/null 2>&1 || die "host is missing 'gzip'"

# Pick a container runtime. Podman is preferred on rootless hosts
# (no daemon, no /var/run/docker.sock required); Docker is the
# familiar fallback. Auto-detect in that order.
if [[ -z "$RUNTIME" ]]; then
    if command -v podman >/dev/null 2>&1; then
        RUNTIME=podman
    elif command -v docker >/dev/null 2>&1; then
        RUNTIME=docker
    else
        die "neither podman nor docker found; install one or set RUNTIME="
    fi
fi
command -v "$RUNTIME" >/dev/null 2>&1 \
    || die "container runtime '$RUNTIME' not found on PATH"

log "runtime:        $RUNTIME"
log "alpine image:   $ALPINE_TAG"
log "out dir:        $OUT_DIR"
log "parallel jobs:  $JOBS"
log "sign key:       ${SIGN_KEY:-<none - package will be unsigned>}"
log "repo root:      $REPO_ROOT"

# --- Package metadata --------------------------------------------------------
#
# These map 1:1 onto fields apk would write into .PKGINFO. The values
# are kept in sync with AGENTS.md / examples/pam-jwt.conf and are the
# canonical place to bump on a new release. Version comes from
# `git describe --tags --always --dirty` (same as the .so's embedded
# PAM_JWT_VERSION), falling back to "dev" for tarball builds.

PKG_NAME="pam-jwt"
PKG_VERSION=$(git -C "$REPO_ROOT" describe --tags --always --dirty 2>/dev/null \
                  || echo "dev")
# apk's version comparator rejects characters that are not in
# [0-9A-Za-z._+-]. Strip anything else so the same version string
# works as a git tag AND as an apk version.
PKG_VERSION=$(printf '%s' "$PKG_VERSION" | tr -c '0-9A-Za-z._+-' '-')
PKG_DESC="Linux-PAM module that authenticates a user by verifying a JWT"
PKG_ARCH="x86_64"
PKG_LICENSE="MIT"
PKG_URL="https://github.com/benmcollins/pam-jwt"
PKG_DEPENDS="linux-pam libcrypto3 libssl3 jansson"

log "package:        $PKG_NAME-$PKG_VERSION"

# --- Inner build script ------------------------------------------------------
#
# This script is written to a temp file on the host and bind-mounted
# into the container at /build/inner.sh. The container invokes it
# with `sh /build/inner.sh`. Mounting the script (instead of piping
# it via stdin) keeps argv size small, makes the script easy to
# inspect post-mortem, and works identically with BusyBox `sh` and
# GNU `bash` inside the container.
#
# Quoting note: the heredoc uses a QUOTED delimiter ('INNER_EOF') so
# the host does NOT expand $PKG_NAME etc. The inner script reads
# those values from the environment (set via `docker run -e`).

INNER_SCRIPT='set -eu

# The runtime bind-mounts:
#   /src                $REPO_ROOT  (read-only, copied to /tmp/src)
#   /out                $OUT_DIR    (read-write)
#   /build/inner.sh                 (this file, read-only)
#   /signing/key.rsa.priv           (only if --sign-key was passed)
log()  { printf "[inner] %s\n"  "$*" >&2; }
die()  { printf "[inner] error: %s\n" "$*" >&2; exit 1; }
log "copying /src -> /tmp/src"
cp -a /src /tmp/src
cd /tmp/src


# apk repositories need to be reachable; on a brand-new image the
# index is empty, so refresh once. `apk add` would refresh on demand
# anyway, but doing it explicitly surfaces network problems early.
log "apk update"
apk update

# Build dependencies. linux-pam-dev / jansson-dev / openssl-dev match
# what scripts/install-deps.sh installs on a normal Alpine host. We
# deliberately do NOT install libjwt-dev: libjwt is VENDORED in
# vendor/libjwt/ and is built by the project'"'"'s own Makefile, so we
# are immune to the 1.x -> 3.x ABI break Alpine made in 3.20+.
log "apk add build deps"
apk add --no-cache \
    alpine-sdk \
    pkgconfig \
    linux-pam-dev \
    jansson-dev \
    openssl-dev \
    openssl \
    bash \
    ca-certificates

# Sanity check the vendored libjwt tree is present and looks sane.
[ -f vendor/libjwt/include/jwt.h ] \
    || die "vendor/libjwt/include/jwt.h missing - clone with submodules?"
[ -d vendor/libjwt/src ] \
    || die "vendor/libjwt/src missing - clone with submodules?"

# The release build bakes a version string into the .so via
# -DPAM_JWT_VERSION. We pass the same value the host computed so the
# .apk filename, the embedded .so version, and the .PKGINFO all
# agree.
log "make release (jobs='"'"'$JOBS'"'"' PREFIX=/usr)"
make -j"$JOBS" release \
    PREFIX=/usr \
    PAM_JWT_VERSION="$PAM_JWT_VERSION"

# Stage the install tree at /pkg. The release .so lands in
# /pkg/usr/lib/security/pam_jwt.so.
log "make install-release (DESTDIR=/pkg)"
make install-release \
    PREFIX=/usr \
    DESTDIR=/pkg

# The .so must not have lost its soname during the install. Quick
# sanity check.
SO=/pkg/usr/lib/security/pam_jwt.so
[ -f "$SO" ] || die "release .so not found at $SO"
SONAME=$(readelf -d "$SO" 2>/dev/null | awk "/SONAME/ {print \$5; exit}" \
             | tr -d "[]")
[ "$SONAME" = "pam_jwt.so" ] \
    || die "soname mismatch: expected pam_jwt.so, got '"'"'$SONAME'"'"'"

# Drop the example config into the staging tree so installing the
# .apk gives the operator a starting point without an extra download.
install -d /pkg/usr/share/pam-jwt
install -m 0644 /tmp/src/examples/pam-jwt.conf \
                 /pkg/usr/share/pam-jwt/pam-jwt.conf

# Build the .PKGINFO header. Field order is not significant to apk,
# but we keep it stable so the output is reproducible across builds.
# `size` is the sum of all installed file sizes; apk-tools will
# report the same number via `apk info -s`.
TOTAL_BYTES=$(find /pkg -type f -exec stat -c%s {} + \
              | awk "BEGIN{s=0} {s+=\$1} END{print s}")

PKGINFO=/tmp/.PKGINFO
{
    printf "pkgname = %s\n"    "$PKG_NAME"
    printf "pkgver = %s\n"     "$PAM_JWT_VERSION"
    printf "pkgdesc = %s\n"    "$PKG_DESC"
    printf "url = %s\n"        "$PKG_URL"
    printf "arch = %s\n"       "$PKG_ARCH"
    printf "license = %s\n"    "$PKG_LICENSE"
    printf "size = %s\n"       "$TOTAL_BYTES"
    for d in $PKG_DEPENDS; do
        printf "depend = %s\n" "$d"
    done
} > "$PKGINFO"

# Optional: signature. If the host mounted a signing key at
# /signing/key.rsa.priv (see --sign-key on the host), generate a
# .SIGN.RSA.*.sig file alongside the .apk. apk ignores the signature
# when --allow-untrusted is passed, so unsigned packages are still
# installable for development; signed packages are what a real
# repository would carry.
SIGNATURE=""
if [ -f /signing/key.rsa.priv ]; then
    log "signing package with /signing/key.rsa.priv"
    SIGNAME=".SIGN.RSA.$(basename "$PKG_NAME").rsa.priv"
    openssl dgst -sha1 -sign /signing/key.rsa.priv \
        -out "/tmp/$SIGNAME" "$PKGINFO"
    SIGNATURE="$SIGNAME"
fi

# Assemble the .apk on disk INSIDE the container, then drop it into
# the host-bound /out. Format: gzip( tar(files) ) + appended
# .PKGINFO + optional .SIGN.RSA.*.sig. apk'"'"'s loader concatenates
# the signed manifest at the end of the gzip stream and reads it
# back after gunzipping the payload.
log "assembling .apk"
APK=/tmp/pam-jwt.apk
rm -f -- "$APK"
[ -n "$SIGNATURE" ] && rm -f -- "/tmp/$SIGNATURE"

# `tar` with explicit entries makes the .apk reproducible regardless
# of how the staging tree was created. Order is sorted for
# determinism; mtimes are forced to SOURCE_DATE_EPOCH when set.
export LC_ALL=C
( cd /pkg && \
  find . -type f -print | LC_ALL=C sort | \
  tar --owner=0 --group=0 --mode=u+w,go-w,a+rX \
      ${SOURCE_DATE_EPOCH:+--mtime=@$SOURCE_DATE_EPOCH} \
      --transform "s,^\\./,," \
      -cf - -T - ) \
  | gzip -n -9 > "$APK"
cat "$PKGINFO" >> "$APK"
if [ -n "$SIGNATURE" ]; then
    cat "/tmp/$SIGNATURE" >> "$APK"
fi

# Hand the .apk back to the host. The output dir is bind-mounted at
# /out (read-write) by the host script; writing here makes the file
# appear on the host at $OUT_DIR/pam-jwt.apk.
install -m 0644 "$APK" /out/pam-jwt.apk
log "build complete"
'

# --- Stage the inner script on the host -------------------------------------

# Write to a tempdir we control so the bind-mount has a stable path.
# We use mktemp -d so multiple parallel invocations do not collide;
# the tempdir is cleaned up in a trap so we do not leave litter in
# $TMPDIR after the build (success OR failure).
INNER_DIR=$(mktemp -d -t pam-jwt-apk-build.XXXXXXXX)
trap 'rm -rf "$INNER_DIR"' EXIT
INNER_PATH="$INNER_DIR/inner.sh"
printf '%s\n' "$INNER_SCRIPT" > "$INNER_PATH"
chmod 0644 "$INNER_PATH"

# --- Run the container -------------------------------------------------------
#
# Bind-mounts:
#   $REPO_ROOT          -> /src                (read-only)
#   $OUT_DIR            -> /out                (read-write)
#   $INNER_PATH         -> /build/inner.sh     (read-only)
#   $SIGN_KEY (opt.)    -> /signing/key.rsa.priv (read-only)
#
# Environment:
#   PAM_JWT_VERSION  same value the host computed, for .PKGINFO.
#   PKG_NAME/...     package metadata, so the inner script can
#                    build .PKGINFO without re-deriving anything.
#   JOBS             parallel make jobs.
#   SOURCE_DATE_EPOCH  if set, fixed mtimes for reproducible .apks.

CTR_NAME="pam-jwt-apk-build-$$"
RUN_ARGS=(
    --name "$CTR_NAME"
    --rm
    -e "PAM_JWT_VERSION=$PKG_VERSION"
    -e "PKG_NAME=$PKG_NAME"
    -e "PKG_VERSION=$PKG_VERSION"
    -e "PKG_DESC=$PKG_DESC"
    -e "PKG_ARCH=$PKG_ARCH"
    -e "PKG_LICENSE=$PKG_LICENSE"
    -e "PKG_URL=$PKG_URL"
    -e "PKG_DEPENDS=$PKG_DEPENDS"
    -e "JOBS=$JOBS"
)
if [[ -n "${SOURCE_DATE_EPOCH:-}" ]]; then
    RUN_ARGS+=( -e "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" )
fi

VOL_ARGS=(
    -v "$REPO_ROOT:/src:ro"
    -v "$OUT_DIR:/out:rw"
    -v "$INNER_PATH:/build/inner.sh:ro"
)
if [[ -n "$SIGN_KEY" ]]; then
    [[ -r "$SIGN_KEY" ]] || die "sign key not readable: $SIGN_KEY"
    SIGN_KEY_ABS=$(cd "$(dirname "$SIGN_KEY")" && pwd)/$(basename "$SIGN_KEY")
    VOL_ARGS+=( -v "$SIGN_KEY_ABS:/signing/key.rsa.priv:ro" )
fi

log "launching $RUNTIME run $ALPINE_TAG"
# We never need a TTY for the build, so `-t` is intentionally omitted
# (also dodges the "the input device is not a TTY" failure on CI).
if ! "$RUNTIME" run "${RUN_ARGS[@]}" "${VOL_ARGS[@]}" "$ALPINE_TAG" \
        sh /build/inner.sh; then
    die "container build failed (see output above)"
fi

# --- Verify + report ---------------------------------------------------------

# The inner script writes the .apk to /out/pam-jwt.apk, which is
# bind-mounted to $OUT_DIR on the host. Rename so the final filename
# embeds the version, matching the alpine package naming convention.
# Unsigned packages install with `apk add --allow-untrusted`.
APK_NAME="${PKG_NAME}-${PKG_VERSION}.apk"
if [[ -f "$OUT_DIR/pam-jwt.apk" ]]; then
    mv "$OUT_DIR/pam-jwt.apk" "$OUT_DIR/$APK_NAME"
fi

if [[ ! -f "$OUT_DIR/$APK_NAME" ]]; then
    die "expected $OUT_DIR/$APK_NAME was not produced"
fi

APK_SIZE=$(stat -c%s "$OUT_DIR/$APK_NAME" 2>/dev/null \
               || stat -f%z "$OUT_DIR/$APK_NAME")
log "wrote $OUT_DIR/$APK_NAME ($APK_SIZE bytes)"

# Quick post-mortem: list the package's payload so the operator
# can eyeball the install layout without unpacking the .apk by hand.
# We use `tar -tzf` against the gzip-compressed prefix only; the
# trailer (PKGINFO + optional signature) is concatenated after the
# gzip stream and would surface as a `tar: Unexpected EOF` warning,
# which we silence.
log "package contents:"
tar -tzf "$OUT_DIR/$APK_NAME" 2>/dev/null \
    | sed 's/^/    /' \
    || true

log "install with:  apk add --allow-untrusted $OUT_DIR/$APK_NAME"
