#!/usr/bin/env bash
#
# install-deps.sh — install build dependencies for pam-jwt.
#
# Supports:
#   - Alpine Linux  (apk)
#   - Debian / Ubuntu / derivatives (apt-get)
#
# Usage:
#   ./scripts/install-deps.sh           # auto-detect distro and install
#   ./scripts/install-deps.sh alpine    # force Alpine path
#   ./scripts/install-deps.sh debian    # force Debian/Ubuntu path
#
# Exit codes:
#   0  success
#   1  unsupported distribution
#   2  required tool missing (sudo, apk, apt-get, etc.)
#   3  package installation failed
#
# Environment variables:
#   SUDO        override privilege-escalation command (default: auto-detect)

set -euo pipefail

readonly SCRIPT_NAME=${0##*/}

log()  { printf '[%s] %s\n'  "$SCRIPT_NAME" "$*" >&2; }
err()  { printf '[%s] error: %s\n' "$SCRIPT_NAME" "$*" >&2; }
die()  { err "$@"; exit 1; }

usage() {
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

detect_sudo() {
    if [[ -n "${SUDO:-}" ]]; then
        return 0
    fi
    if [[ $EUID -eq 0 ]]; then
        SUDO=""
    elif command -v sudo >/dev/null 2>&1; then
        SUDO=sudo
    elif command -v doas >/dev/null 2>&1; then
        SUDO=doas
    else
        die "need root, sudo, or doas to install packages"
    fi
}

run_privileged() {
    if [[ $EUID -eq 0 ]]; then
        "$@"
    else
        "$SUDO" "$@"
    fi
}

# ---------------------------------------------------------------------------
# Alpine Linux
# ---------------------------------------------------------------------------

install_alpine() {
    require_cmd apk

    # libjwt is VENDORED under vendor/libjwt/ and is built as part of
    # `make`. We deliberately do NOT install the system libjwt-dev
    # (Alpine 3.24 ships 3.x whose ABI/API breaks pam-jwt's verifier).
    local pkgs=(
        alpine-sdk      # gcc, make, libc-dev, etc.
        pkgconfig
        linux-pam-dev
        jansson-dev     # runtime dep of the vendored libjwt 1.x
        openssl-dev
        openssl
        bash
    )

    log "apk: refreshing package index"
    run_privileged apk update

    log "apk: installing ${pkgs[*]}"
    run_privileged apk add --no-interactive "${pkgs[@]}" \
        || die "apk add failed"

    log "Alpine dependencies installed"
}

# ---------------------------------------------------------------------------
# Debian / Ubuntu
# ---------------------------------------------------------------------------

install_debian() {
    require_cmd apt-get

    # libpam0g-dev's pam.pc on Debian/Ubuntu declares `Requires.private: audit`,
    # so pkg-config emits a warning unless libaudit-dev is present. The warning
    # is harmless for a shared-module build (we only need -lpam), but we install
    # libaudit-dev to keep `pkg-config --cflags pam` clean.
    # libjwt is VENDORED under vendor/libjwt/ and is built as part of
    # `make`. We deliberately do NOT install the system libjwt-dev
    # even though Debian 13 / Ubuntu 24.04+ ship 1.x, because Alpine
    # 3.24 ships 3.x and we want one build recipe for every distro.
    local pkgs=(
        build-essential
        pkg-config
        libpam0g-dev
        libaudit-dev
        libjansson-dev  # runtime dep of the vendored libjwt 1.x
        libssl-dev
        openssl
    )

    log "apt: refreshing package index"
    run_privileged apt-get update

    log "apt: installing ${pkgs[*]}"
    # DEBIAN_FRONTEND=noninteractive avoids prompts on minimal images.
    DEBIAN_FRONTEND=noninteractive run_privileged apt-get install -y --no-install-recommends "${pkgs[@]}" \
        || die "apt-get install failed"

    log "Debian/Ubuntu dependencies installed"
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

main() {
    local force=""
    if [[ $# -gt 0 ]]; then
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            alpine|alpine-linux)
                force=alpine
                ;;
            debian|ubuntu|debian-ubuntu)
                force=debian
                ;;
            *)
                err "unknown argument: $1"
                usage
                exit 1
                ;;
        esac
    fi

    local distro=""
    if [[ -n "$force" ]]; then
        distro=$force
    elif [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "${ID:-}:${ID_LIKE:-}" in
            alpine:*|*:alpine) distro=alpine ;;
            debian:*|ubuntu:*|*:debian|*:ubuntu) distro=debian ;;
            *)
                err "unsupported distribution: ${ID:-unknown} (${PRETTY_NAME:-no pretty name})"
                err "pass 'alpine' or 'debian' explicitly"
                exit 1
                ;;
        esac
    else
        die "cannot detect distribution: /etc/os-release not readable"
    fi

    detect_sudo

    log "target distribution: $distro"
    case "$distro" in
        alpine) install_alpine ;;
        debian) install_debian ;;
    esac

    log "verify with: pkg-config --modversion pam jansson openssl"
}

main "$@"
