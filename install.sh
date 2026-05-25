#!/bin/sh
# shellcheck shell=sh
#
# Steer install script
# Repo: https://github.com/enforcegrid/steer
# Docs: https://github.com/enforcegrid/steer#readme
#
# Downloads the appropriate Steer binary for the host OS/arch from GitHub
# Releases, verifies its SHA256 against the published SHA256SUMS file, and
# installs it to a sane location on $PATH.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/enforcegrid/steer/main/install.sh | sh
#
# Environment variables:
#   STEER_VERSION         Pin to a specific release tag (e.g. v0.1.0).
#                         Default: latest GitHub release.
#   STEER_INSTALL_DIR     Override install directory.
#                         Default: /usr/local/bin if writable, else
#                         $HOME/.local/bin.
#   STEER_NO_MODIFY_PATH  If "1", suppress the PATH warning when installing
#                         to a directory that is not on $PATH.
#   STEER_DRY_RUN         If "1", print what would be done and exit before
#                         downloading anything. Safe for CI smoke tests.
#
# This script is POSIX sh. No bashisms. Verified with `shellcheck -s sh`.

set -eu

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPO_OWNER="enforcegrid"
REPO_NAME="steer"
REPO_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}"
DOCS_URL="${REPO_URL}#readme"
QUICKSTART_URL="${REPO_URL}#quick-start"

# Set by main(); declared up front so cleanup() can reference safely.
TMPDIR_STEER=""

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

# Detect TTY for color output. Disabled when stdout is not a terminal,
# when NO_COLOR is set, or when TERM is dumb.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != "dumb" ]; then
    BOLD=$(printf '\033[1m')
    DIM=$(printf '\033[2m')
    RED=$(printf '\033[31m')
    GREEN=$(printf '\033[32m')
    YELLOW=$(printf '\033[33m')
    BLUE=$(printf '\033[34m')
    RESET=$(printf '\033[0m')
else
    BOLD=""
    DIM=""
    RED=""
    GREEN=""
    YELLOW=""
    BLUE=""
    RESET=""
fi

info() {
    printf '%s%sinfo%s: %s\n' "$BOLD" "$BLUE" "$RESET" "$1"
}

warn() {
    printf '%s%swarn%s: %s\n' "$BOLD" "$YELLOW" "$RESET" "$1" >&2
}

err() {
    printf '%s%serror%s: %s\n' "$BOLD" "$RED" "$RESET" "$1" >&2
    exit 1
}

success() {
    printf '%s%s%s\n' "$BOLD$GREEN" "$1" "$RESET"
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

cleanup() {
    if [ -n "$TMPDIR_STEER" ] && [ -d "$TMPDIR_STEER" ]; then
        rm -rf "$TMPDIR_STEER"
    fi
}
trap cleanup EXIT INT TERM HUP

# ---------------------------------------------------------------------------
# Command/tool helpers
# ---------------------------------------------------------------------------

has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

require_cmd() {
    if ! has_cmd "$1"; then
        err "required command not found: $1"
    fi
}

# ---------------------------------------------------------------------------
# OS/arch detection
# ---------------------------------------------------------------------------

detect_target() {
    _ostype=$(uname -s 2>/dev/null || echo unknown)
    _cputype=$(uname -m 2>/dev/null || echo unknown)

    case "$_ostype" in
        Darwin)
            _os="apple-darwin"
            ;;
        Linux)
            _os="unknown-linux-gnu"
            ;;
        FreeBSD|OpenBSD|NetBSD|DragonFly)
            err "unsupported OS: $_ostype. Supported: macOS (Darwin), Linux. See $DOCS_URL"
            ;;
        MINGW*|MSYS*|CYGWIN*|Windows_NT)
            err "Windows is not supported by this script. Download the .zip from $REPO_URL/releases and extract manually."
            ;;
        *)
            err "unsupported OS: $_ostype. Supported: macOS, Linux. See $DOCS_URL"
            ;;
    esac

    case "$_cputype" in
        x86_64|amd64)
            _arch="x86_64"
            ;;
        arm64|aarch64)
            _arch="aarch64"
            ;;
        *)
            err "unsupported CPU architecture: $_cputype. Supported: x86_64, aarch64/arm64. See $DOCS_URL"
            ;;
    esac

    # Apple-Darwin uses 'aarch64' in Rust triples; macOS uname reports 'arm64'.
    # Our mapping above normalises both to 'aarch64', then the triple is built
    # consistently. (e.g. aarch64-apple-darwin, x86_64-apple-darwin)
    TARGET="${_arch}-${_os}"
}

# ---------------------------------------------------------------------------
# Version resolution
# ---------------------------------------------------------------------------

# Validate that a version string looks like a release tag: vMAJOR.MINOR.PATCH
# with optional pre-release suffix. We are strict because this string is
# interpolated into URLs.
validate_version() {
    case "$1" in
        v[0-9]*)
            # Reject anything containing shell metacharacters or whitespace.
            case "$1" in
                *[!A-Za-z0-9._+-]*)
                    err "invalid STEER_VERSION '$1': contains disallowed characters"
                    ;;
            esac
            ;;
        *)
            err "invalid STEER_VERSION '$1': must start with 'v' (e.g. v0.1.0)"
            ;;
    esac
}

# Resolve latest tag via the /releases/latest redirect. GitHub returns a
# 302 to /releases/tag/vX.Y.Z and we parse the Location header. This dodges
# the GitHub API rate limit (60 req/hr unauthenticated).
resolve_latest_version() {
    _latest_url="${REPO_URL}/releases/latest"
    _redirect=$(curl -sSI --tlsv1.2 --proto '=https' -o /dev/null -w '%{redirect_url}' --retry 1 --retry-delay 2 "$_latest_url" 2>/dev/null || true)
    if [ -z "$_redirect" ]; then
        err "failed to fetch latest release tag from $_latest_url. Check your network connection or set STEER_VERSION explicitly."
    fi
    # Extract trailing tag: .../releases/tag/vX.Y.Z
    case "$_redirect" in
        */releases/tag/*)
            VERSION=$(printf '%s' "$_redirect" | sed -n 's|.*/releases/tag/\(.*\)$|\1|p' | tr -d '\r\n')
            ;;
        */releases|*/releases/)
            err "no releases published yet at $REPO_URL. Wait for the first release or set STEER_VERSION explicitly."
            ;;
        *)
            err "unexpected redirect target '$_redirect'. Set STEER_VERSION explicitly to work around this."
            ;;
    esac
    if [ -z "$VERSION" ]; then
        err "failed to parse latest version from redirect '$_redirect'. Set STEER_VERSION explicitly to work around this."
    fi
}

# ---------------------------------------------------------------------------
# Download with one retry on failure
# ---------------------------------------------------------------------------

download() {
    # $1 = url, $2 = output path
    # --tlsv1.2 + --proto '=https' refuse downgrade/redirect to plaintext HTTP.
    # Critical for security-tool installers: prevents `-L` from following a
    # hostile redirect to http://. Mirrors rustup-init.sh's behavior.
    _url=$1
    _out=$2
    if curl -fsSL --tlsv1.2 --proto '=https' --retry 1 --retry-delay 2 -o "$_out" "$_url"; then
        return 0
    fi
    warn "download failed, retrying once: $_url"
    sleep 2
    if curl -fsSL --tlsv1.2 --proto '=https' --retry 1 --retry-delay 4 -o "$_out" "$_url"; then
        return 0
    fi
    err "failed to download $_url after retry. Check your network connection."
}

# ---------------------------------------------------------------------------
# Checksum verification
# ---------------------------------------------------------------------------

# Detect which sha256 tool is available. Linux ships sha256sum; macOS ships
# shasum. We feature-detect rather than branching on OS.
sha256_of() {
    if has_cmd sha256sum; then
        sha256sum "$1" | awk '{print $1}'
    elif has_cmd shasum; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        err "no sha256 tool found (need sha256sum or shasum)"
    fi
}

verify_checksum() {
    # $1 = path to artifact, $2 = path to SHA256SUMS, $3 = artifact filename as it appears in SHA256SUMS
    _file=$1
    _sums=$2
    _name=$3

    # Lines in SHA256SUMS look like: "<hex>  <filename>"
    # awk with exact field-2 string equality — avoids the '.' regex-wildcard
    # collision that grep would have on filenames like "steer-v0.1.0-...tar.gz"
    _expected=$(awk -v n="$_name" '$2 == n { print $1; exit }' "$_sums")
    if [ -z "$_expected" ]; then
        err "checksum entry for '${_name}' not found in SHA256SUMS. Release may be incomplete or tampered."
    fi
    _actual=$(sha256_of "$_file")
    if [ "$_expected" != "$_actual" ]; then
        err "SHA256 mismatch for ${_name}!
  expected: $_expected
  actual:   $_actual
Refusing to install. The download may be corrupt or tampered with."
    fi
    info "SHA256 verified: ${_name}"
}

# ---------------------------------------------------------------------------
# Install dir resolution
# ---------------------------------------------------------------------------

# Returns 0 if the directory exists and is writable without sudo.
dir_is_writable() {
    [ -d "$1" ] && [ -w "$1" ]
}

resolve_install_dir() {
    if [ -n "${STEER_INSTALL_DIR:-}" ]; then
        INSTALL_DIR=$STEER_INSTALL_DIR
        mkdir -p "$INSTALL_DIR" 2>/dev/null || err "STEER_INSTALL_DIR ($INSTALL_DIR) is not creatable."
        if ! dir_is_writable "$INSTALL_DIR"; then
            err "STEER_INSTALL_DIR ($INSTALL_DIR) is not writable."
        fi
        return 0
    fi
    if dir_is_writable "/usr/local/bin"; then
        INSTALL_DIR="/usr/local/bin"
        return 0
    fi
    _user_bin="${HOME}/.local/bin"
    if mkdir -p "$_user_bin" 2>/dev/null && dir_is_writable "$_user_bin"; then
        INSTALL_DIR=$_user_bin
        return 0
    fi
    err "no writable install directory. Tried /usr/local/bin and \$HOME/.local/bin.
Set STEER_INSTALL_DIR to a writable location or re-run with elevated privileges."
}

# Check whether install dir is on $PATH (colon-separated, exact-match component).
dir_on_path() {
    case ":${PATH}:" in
        *":$1:"*) return 0 ;;
        *) return 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# Config asset placement (steer.example.yaml, default.cedar)
# ---------------------------------------------------------------------------

# Place bundled config samples into $HOME/.config/steer/ if they don't already
# exist. We never overwrite existing user config.
install_config_assets() {
    _src=$1                        # extracted tarball root
    _cfg_dir="${HOME}/.config/steer"
    _pol_dir="${_cfg_dir}/policies"
    mkdir -p "$_pol_dir" 2>/dev/null || {
        warn "could not create ${_cfg_dir}; skipping bundled config install."
        return 0
    }

    if [ -f "${_src}/steer.example.yaml" ] && [ ! -f "${_cfg_dir}/steer.example.yaml" ]; then
        cp "${_src}/steer.example.yaml" "${_cfg_dir}/steer.example.yaml"
        info "installed sample config: ${_cfg_dir}/steer.example.yaml"
    fi

    if [ -f "${_src}/dsl/policies/default.cedar" ] && [ ! -f "${_pol_dir}/default.cedar" ]; then
        cp "${_src}/dsl/policies/default.cedar" "${_pol_dir}/default.cedar"
        info "installed default policy: ${_pol_dir}/default.cedar"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    require_cmd uname
    require_cmd curl
    require_cmd tar
    require_cmd grep
    require_cmd awk
    require_cmd sed

    detect_target
    info "detected target: ${TARGET}"

    if [ -n "${STEER_VERSION:-}" ]; then
        validate_version "$STEER_VERSION"
        VERSION=$STEER_VERSION
        info "using pinned version: ${VERSION}"
    else
        info "resolving latest version..."
        resolve_latest_version
        validate_version "$VERSION"
        info "latest version: ${VERSION}"
    fi

    ARTIFACT="steer-${VERSION}-${TARGET}.tar.gz"
    ARTIFACT_URL="${REPO_URL}/releases/download/${VERSION}/${ARTIFACT}"
    SUMS_URL="${REPO_URL}/releases/download/${VERSION}/SHA256SUMS"

    resolve_install_dir
    info "install dir: ${INSTALL_DIR}"

    if [ "${STEER_DRY_RUN:-}" = "1" ]; then
        printf '\n%sDry run summary:%s\n' "$BOLD" "$RESET"
        printf '  target:       %s\n' "$TARGET"
        printf '  version:      %s\n' "$VERSION"
        printf '  artifact:     %s\n' "$ARTIFACT"
        printf '  artifact url: %s\n' "$ARTIFACT_URL"
        printf '  sums url:     %s\n' "$SUMS_URL"
        printf '  install dir:  %s\n' "$INSTALL_DIR"
        printf '  sha256 tool:  %s\n' "$(has_cmd sha256sum && echo sha256sum || (has_cmd shasum && echo 'shasum -a 256') || echo none)"
        printf '%s(dry run: nothing was downloaded or installed)%s\n' "$DIM" "$RESET"
        return 0
    fi

    # Create temp workspace.
    TMPDIR_STEER=$(mktemp -d 2>/dev/null || mktemp -d -t steer-install)
    [ -d "$TMPDIR_STEER" ] || err "failed to create temp directory"

    info "downloading ${ARTIFACT}..."
    download "$ARTIFACT_URL" "${TMPDIR_STEER}/${ARTIFACT}"

    info "downloading SHA256SUMS..."
    download "$SUMS_URL" "${TMPDIR_STEER}/SHA256SUMS"

    verify_checksum "${TMPDIR_STEER}/${ARTIFACT}" "${TMPDIR_STEER}/SHA256SUMS" "${ARTIFACT}"

    info "extracting..."
    if ! tar -xzf "${TMPDIR_STEER}/${ARTIFACT}" -C "$TMPDIR_STEER"; then
        err "tarball extraction failed. Archive may be corrupt."
    fi

    # The tarball contains a top-level directory: steer-vX.Y.Z-<target>/
    _extracted="${TMPDIR_STEER}/steer-${VERSION}-${TARGET}"
    if [ ! -d "$_extracted" ]; then
        err "expected directory ${_extracted} not present after extraction. Release layout mismatch."
    fi
    if [ ! -f "${_extracted}/steer" ]; then
        err "binary 'steer' not found in extracted tarball at ${_extracted}/steer."
    fi

    info "installing to ${INSTALL_DIR}/steer..."
    # Install via temp move + rename to keep target dir consistent on failure.
    _dest="${INSTALL_DIR}/steer"
    if ! cp "${_extracted}/steer" "${_dest}.new"; then
        err "failed to copy binary to ${INSTALL_DIR}. Permissions?"
    fi
    chmod +x "${_dest}.new"
    mv "${_dest}.new" "$_dest"

    install_config_assets "$_extracted"

    # Post-install summary
    printf '\n'
    success "Installed steer ${VERSION} to ${_dest}"

    if ! dir_on_path "$INSTALL_DIR" && [ "${STEER_NO_MODIFY_PATH:-}" != "1" ]; then
        warn "${INSTALL_DIR} is not on your \$PATH."
        printf '  Add it by appending one of these to your shell profile:\n'
        # The literal $PATH below is intentional — it is shell guidance for the user.
        # shellcheck disable=SC2016
        printf '    %sexport PATH="%s:$PATH"%s\n' "$DIM" "$INSTALL_DIR" "$RESET"
        printf '  Then reload your shell, e.g. %ssource ~/.bashrc%s or %ssource ~/.zshrc%s.\n' "$DIM" "$RESET" "$DIM" "$RESET"
    fi

    printf '\n'
    printf '%sNext steps:%s\n' "$BOLD" "$RESET"
    printf '  steer --version\n'
    printf '  steer --port 8080\n'
    printf '\n'
    printf '  Quick start: %s\n' "$QUICKSTART_URL"
    printf '  Docs:        %s\n' "$DOCS_URL"
    printf '\n'
}

main "$@"
