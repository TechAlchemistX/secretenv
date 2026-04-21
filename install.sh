#!/bin/sh
# secretenv installer — https://secretenv.io
#
# Downloads a signed, checksummed release binary from GitHub Releases
# and installs it to the chosen prefix. Pure POSIX sh — works under
# dash, bash, zsh, and busybox ash.
#
# Usage:
#   curl -sfSL https://secretenv.io/install.sh | sh
#   curl -sfSL https://secretenv.io/install.sh | sh -s -- --version v0.1.0
#   curl -sfSL https://secretenv.io/install.sh | sh -s -- --prefix "$HOME/.local/bin"
#   curl -sfSL https://secretenv.io/install.sh | sh -s -- --profile engineering
#
# Environment overrides:
#   SECRETENV_PROFILE_URL   Base URL for --profile fetches
#                           (default: https://secretenv.io/profiles)
#
# Exit codes: 0 on success, non-zero on any error with a clear message.

set -eu

REPO="TechAlchemistX/secretenv"
BINARY="secretenv"
PREFIX="/usr/local/bin"
VERSION=""
PROFILE=""
PROFILE_BASE_URL="${SECRETENV_PROFILE_URL:-https://secretenv.io/profiles}"

usage() {
    cat <<'EOF'
secretenv installer

Usage:
  install.sh [--version <v>] [--prefix <path>] [--profile <name>]

Options:
  --version <v>     Install a specific release (default: latest, e.g. v0.1.0).
  --prefix <path>   Directory to install the binary into (default: /usr/local/bin).
  --profile <name>  After install, fetch a distribution profile config to
                    $XDG_CONFIG_HOME/secretenv/config.toml (skipped if the file
                    already exists).
  --help, -h        Show this help.
EOF
}

die() { printf 'install.sh: error: %s\n' "$*" >&2; exit 1; }
info() { printf 'install.sh: %s\n' "$*"; }

require() {
    command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not found on PATH"
}

detect_target() {
    os=$(uname -s)
    arch=$(uname -m)
    case "$os/$arch" in
        Darwin/x86_64)             echo "x86_64-apple-darwin" ;;
        Darwin/arm64)              echo "aarch64-apple-darwin" ;;
        Linux/x86_64)              echo "x86_64-unknown-linux-gnu" ;;
        Linux/aarch64|Linux/arm64) echo "aarch64-unknown-linux-gnu" ;;
        *) die "unsupported platform: $os/$arch" ;;
    esac
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        die "no SHA-256 tool found (need 'sha256sum' or 'shasum')"
    fi
}

# ---- argument parsing -------------------------------------------------

while [ $# -gt 0 ]; do
    case "$1" in
        --version) [ $# -ge 2 ] || die "--version needs a value"; VERSION="$2"; shift 2 ;;
        --prefix)  [ $# -ge 2 ] || die "--prefix needs a value";  PREFIX="$2";  shift 2 ;;
        --profile) [ $# -ge 2 ] || die "--profile needs a value"; PROFILE="$2"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
done

require curl
require tar

# ---- resolve version --------------------------------------------------

if [ -z "$VERSION" ]; then
    info "resolving latest release..."
    VERSION=$(curl -sfSL "https://api.github.com/repos/$REPO/releases/latest" \
              | awk -F '"' '/"tag_name":/ {print $4; exit}')
    [ -n "$VERSION" ] || die "could not resolve latest version from GitHub API"
fi

TARGET=$(detect_target)
TARBALL="secretenv-${VERSION}-${TARGET}.tar.gz"
BASE_URL="https://github.com/$REPO/releases/download/$VERSION"

# ---- download + verify ------------------------------------------------

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT HUP TERM

info "downloading $TARBALL ($VERSION)..."
curl -sfSL -o "$tmp/$TARBALL"      "$BASE_URL/$TARBALL"      || die "failed to download $TARBALL"
curl -sfSL -o "$tmp/checksums.txt" "$BASE_URL/checksums.txt" || die "failed to download checksums.txt"

expected=$(awk -v f="$TARBALL" '$2==f {print $1; exit}' "$tmp/checksums.txt")
[ -n "$expected" ] || die "no SHA-256 for $TARBALL in checksums.txt"
actual=$(sha256_of "$tmp/$TARBALL")
[ "$expected" = "$actual" ] || \
    die "SHA-256 mismatch for $TARBALL (expected $expected, got $actual)"
info "SHA-256 verified"

# ---- extract + install ------------------------------------------------

tar -xzf "$tmp/$TARBALL" -C "$tmp"
src="$tmp/$BINARY"
[ -x "$src" ] || die "binary '$BINARY' not found inside $TARBALL"

# Ensure prefix exists, using sudo only if we must.
if [ ! -d "$PREFIX" ]; then
    mkdir -p "$PREFIX" 2>/dev/null || sudo mkdir -p "$PREFIX" || die "failed to create $PREFIX"
fi

dest="$PREFIX/$BINARY"
if install -m 0755 "$src" "$dest" 2>/dev/null; then
    :
else
    info "installing to $dest requires elevated privileges..."
    sudo install -m 0755 "$src" "$dest" || die "failed to install $dest"
fi
info "installed $VERSION -> $dest"

# ---- optional distribution profile -----------------------------------

if [ -n "$PROFILE" ]; then
    cfg="${XDG_CONFIG_HOME:-$HOME/.config}/secretenv/config.toml"
    if [ -e "$cfg" ]; then
        info "config already exists at $cfg — skipping profile '$PROFILE' (use 'secretenv setup --force' to overwrite)"
    else
        info "installing profile '$PROFILE' -> $cfg"
        mkdir -p "$(dirname "$cfg")"
        curl -sfSL -o "$cfg" "$PROFILE_BASE_URL/$PROFILE.toml" \
            || die "failed to download profile '$PROFILE' from $PROFILE_BASE_URL/$PROFILE.toml"
    fi
fi

info "done. try: $BINARY --version"
