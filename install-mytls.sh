#!/usr/bin/env bash
#
# Install this checkout of mitmproxy into an existing Python, with cryptography
# built from source against the same OpenSSL that Python's own `ssl` module is
# linked against - the mytls fork, for upstream TLS fingerprints.
#
#   ./install-mytls.sh                          # into the shell's default python3
#   ./install-mytls.sh --mytls ../mytls/python  # also (re)install the mytls package
#   ./install-mytls.sh --python /path/to/python3 --editable
#
# Options:
#   --python PATH   interpreter to install into. Default: python3 as the shell
#                   resolves it outside any project directory, i.e. the global
#                   pyenv version rather than this repository's .python-version.
#   --mytls DIR     also install the mytls Python package from DIR
#                   (needed for the http2_fingerprint option).
#   --editable      install mitmproxy in editable mode, so it follows this checkout.
#   --yes, -y       do not ask for confirmation.
#   -h, --help
#
# Steps:
#   1. find the OpenSSL the interpreter's _ssl module links, and require that it
#      is the mytls fork (exports SSL_set_fp_profile) and has its headers
#   2. build a cryptography wheel from source, linked dynamically against that
#      OpenSSL, and check the linkage before anything is installed
#   3. on musl, install a placeholder for mitmproxy-linux, which has no musl
#      wheel and is only needed for `--mode local`
#   4. install mitmproxy from this checkout, constrained to the versions in uv.lock
#   5. verify: OpenSSL version, fingerprint symbols, the http2_fingerprint option
#
# Needs: uv (to read uv.lock), a Rust toolchain and a C compiler.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY_ARG="" MYTLS_SRC="" EDITABLE=0 ASSUME_YES=0

while [ $# -gt 0 ]; do
    case "$1" in
        --python)   PY_ARG="${2:?--python needs a path}"; shift ;;
        --mytls)    MYTLS_SRC="${2:?--mytls needs a directory}"; shift ;;
        --editable) EDITABLE=1 ;;
        --yes|-y)   ASSUME_YES=1 ;;
        -h|--help)  awk 'NR > 1 && !/^#/ {exit} NR > 1 {sub(/^# ?/, ""); print}' "$0"; exit 0 ;;
        *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
    esac
    shift
done

say()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m warning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m error:\033[0m %s\n' "$*" >&2; exit 1; }

# musl's ldd exits 127 on any object with unresolved symbols, which every Python
# extension module has (Py* come from the interpreter), but it still prints the
# DT_NEEDED lines first. Hence `|| true`, and LD_LIBRARY_PATH unset: what counts
# is what the object finds on its own.
libssl_of() {
    { env -u LD_LIBRARY_PATH ldd "$1" 2>/dev/null || true; } | awk '/libssl\.so/ {print $3; exit}'
}

[ -f "$ROOT/pyproject.toml" ] && [ -f "$ROOT/uv.lock" ] && [ -d "$ROOT/mitmproxy" ] \
    || die "run this from a mitmproxy checkout (pyproject.toml, uv.lock and mitmproxy/ must be beside it)"
command -v uv >/dev/null || die "uv is required to read uv.lock"
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
command -v cargo >/dev/null || die "a Rust toolchain is required (cargo not found)"
command -v cc >/dev/null || command -v gcc >/dev/null || die "a C compiler is required"
command -v ldd >/dev/null || die "ldd is required to check linkage"

# --- 1. the interpreter and its OpenSSL --------------------------------------
# Resolved from / so that a pyenv shim picks the global version, not whatever
# .python-version says in the directory this was started from.
PY="${PY_ARG:-python3}"
PY="$(cd / && command -v "$PY")" || die "$PY not found"
PY="$(cd / && "$PY" -c 'import sys; print(sys.executable)')" || die "$PY does not run"
"$PY" -c 'import sys; sys.exit(sys.version_info < (3, 12))' \
    || die "$PY is $("$PY" -V 2>&1); mitmproxy needs Python >= 3.12"

if "$PY" - <<'EOF'
import os, sys, sysconfig
managed = os.path.exists(os.path.join(sysconfig.get_path("stdlib"), "EXTERNALLY-MANAGED"))
sys.exit(0 if managed and sys.prefix == sys.base_prefix else 1)
EOF
then
    die "$PY is managed by the system package manager (PEP 668); use a pyenv or venv interpreter"
fi

SSL_MOD="$("$PY" -c 'import _ssl; print(_ssl.__file__)' 2>/dev/null)" \
    || die "$PY has no _ssl module, so there is no OpenSSL to build against"
LIBSSL="$(libssl_of "$SSL_MOD")"
[ -n "$LIBSSL" ] || die "cannot tell which libssl $SSL_MOD links (static or no ldd output)"
LIBSSL="$(readlink -f "$LIBSSL")"
LIBDIR="$(dirname "$LIBSSL")"
PREFIX="$(dirname "$LIBDIR")"
[ -f "$PREFIX/include/openssl/ssl.h" ] \
    || die "$PY links $LIBSSL, but $PREFIX/include/openssl/ssl.h is missing - cryptography needs the headers"
"$PY" - "$LIBSSL" <<'EOF' || die "$LIBSSL is not the mytls fork (no SSL_set_fp_profile); mitmproxy's upstream TLS could not be fingerprinted"
import ctypes, sys
ctypes.CDLL(sys.argv[1]).SSL_set_fp_profile
EOF
SSL_VERSION="$("$PY" -c 'import ssl; print(ssl.OPENSSL_VERSION)')"

MUSL=0
compgen -G '/lib/ld-musl-*.so.1' >/dev/null && MUSL=1

VERSION="$(cd "$ROOT" && "$PY" -c 'from mitmproxy.version import VERSION; print(VERSION)' 2>/dev/null \
    || sed -n 's/^VERSION = "\(.*\)"/\1/p' "$ROOT/mitmproxy/version.py")"
BRANCH="$(git -C "$ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
COMMIT="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo '?')"

cat <<EOF

  mitmproxy   $VERSION from $ROOT ($BRANCH @ $COMMIT)$([ "$EDITABLE" = 1 ] && echo ', editable')
  into        $PY ($("$PY" -V 2>&1))
  OpenSSL     $SSL_VERSION
              $LIBSSL  (linked by $PY's ssl module)
  libc        $([ "$MUSL" = 1 ] && echo 'musl - mitmproxy-linux gets a placeholder' || echo 'glibc')
  mytls       ${MYTLS_SRC:-not reinstalled (--mytls DIR to install it)}

Packages already in this interpreter are upgraded to the versions in uv.lock
where mitmproxy needs them, cryptography included.
EOF
if [ "$ASSUME_YES" = 0 ]; then
    [ -t 0 ] || die "not a terminal; pass --yes to proceed"
    printf 'continue? [y/N] '
    read -r reply
    case "$reply" in [yY]*) ;; *) die "aborted" ;; esac
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export PYTHONNOUSERSITE=1      # keep ~/.local out of what pip considers installed
export PIP_DISABLE_PIP_VERSION_CHECK=1

say "pinning to uv.lock"
uv export --project "$ROOT" --frozen --no-dev --no-hashes --no-emit-project --no-header \
    --quiet -o "$WORK/constraints.txt"
pinned() { sed -n "s/^$1==\([^ ;]*\).*/\1/p" "$WORK/constraints.txt" | head -n1; }
CRYPTO_VERSION="$(pinned cryptography)"
LINUX_VERSION="$(pinned mitmproxy-linux)"
[ -n "$CRYPTO_VERSION" ] || die "uv.lock pins no cryptography version"
echo "  cryptography $CRYPTO_VERSION, mitmproxy-rs $(pinned mitmproxy-rs)"

# --- 2. cryptography against that OpenSSL ------------------------------------
say "building cryptography $CRYPTO_VERSION against $PREFIX"
export OPENSSL_DIR="$PREFIX"
unset OPENSSL_STATIC OPENSSL_LIB_DIR OPENSSL_INCLUDE_DIR
# rpath: load this libssl at runtime rather than one on the default search path.
# -crt-static: on musl a Rust cdylib is otherwise linked against a static libc.
RUSTFLAGS="-C link-arg=-Wl,-rpath,$LIBDIR"
[ "$MUSL" = 1 ] && RUSTFLAGS="-C target-feature=-crt-static $RUSTFLAGS"
export RUSTFLAGS
# --no-cache-dir: a wheel cached from an earlier build against another OpenSSL
# would otherwise be reused without a word.
"$PY" -m pip wheel --quiet --no-deps --no-cache-dir --no-binary cryptography \
    -w "$WORK/wheels" "cryptography==$CRYPTO_VERSION"
WHEEL="$(ls "$WORK"/wheels/cryptography-*.whl)"

mkdir -p "$WORK/check"
"$PY" - "$WHEEL" "$WORK/check" <<'EOF'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    name = next(n for n in z.namelist()
                if n.startswith("cryptography/hazmat/bindings/_rust") and n.endswith(".so"))
    z.extract(name, sys.argv[2])
    print(name)
EOF
BUILT="$(find "$WORK/check" -name '_rust*.so' | head -n1)"
[ "$(readlink -f "$(libssl_of "$BUILT")" 2>/dev/null)" = "$LIBSSL" ] \
    || die "the cryptography build links $(libssl_of "$BUILT" || echo 'no libssl'), not $LIBSSL - nothing was installed"
echo "  links $LIBSSL"
"$PY" -m pip install --quiet --no-deps --force-reinstall "$WHEEL"

# --- 3. mitmproxy-linux on musl -----------------------------------------------
if [ "$MUSL" = 1 ] && [ -n "$LINUX_VERSION" ]; then
    say "installing a placeholder for mitmproxy-linux $LINUX_VERSION (no musl wheel)"
    mkdir -p "$WORK/placeholder/mitmproxy_linux"
    cat > "$WORK/placeholder/pyproject.toml" <<TOML
[build-system]
requires = ["setuptools>=61"]
build-backend = "setuptools.build_meta"

[project]
name = "mitmproxy-linux"
version = "$LINUX_VERSION"
description = "Placeholder: the real eBPF redirector has no musl wheel"
requires-python = ">=3.12"

[tool.setuptools.packages.find]
include = ["mitmproxy_linux"]
TOML
    cat > "$WORK/placeholder/mitmproxy_linux/__init__.py" <<'PY_EOF'
"""Placeholder installed by mitmproxy's install-mytls.sh. Not the real package.

The real mitmproxy-linux ships a Rust/eBPF redirector and publishes manylinux
wheels only, so it cannot be built on musl without a nightly toolchain and
bpf-linker. It serves `mitmdump --mode local` and nothing else; mitmproxy_rs
needs it to import. This fails loudly if the redirector is ever actually used.
"""

_WHY = ("mitmdump --mode local needs the real mitmproxy-linux, an eBPF "
        "redirector with no musl wheel. Use --mode wireguard or a plain proxy.")


class LocalRedirector:
    def __init__(self, *args, **kwargs):
        raise NotImplementedError(_WHY)

    @staticmethod
    def describe_spec(*args, **kwargs):
        return ""


def __getattr__(name):
    raise AttributeError(f"{name}: {_WHY}")
PY_EOF
    "$PY" -m pip install --quiet --no-deps --force-reinstall "$WORK/placeholder"
fi

# --- 4. mitmproxy --------------------------------------------------------------
say "installing mitmproxy from $ROOT"
# cryptography is already installed at the pinned version, so it is left alone;
# --no-binary is there so that a mismatch builds from source rather than pulling
# the official wheel with its own statically linked OpenSSL.
if [ "$EDITABLE" = 1 ]; then
    "$PY" -m pip install --quiet --no-binary cryptography -c "$WORK/constraints.txt" -e "$ROOT"
else
    "$PY" -m pip install --quiet --no-binary cryptography -c "$WORK/constraints.txt" "$ROOT"
fi

if [ -n "$MYTLS_SRC" ]; then
    say "installing mytls from $MYTLS_SRC"
    rm -rf "$MYTLS_SRC/build" "$MYTLS_SRC"/*.egg-info
    "$PY" -m pip install --quiet "$MYTLS_SRC"
fi

# --- 5. verify -------------------------------------------------------------------
say "checking"
INSTALLED="$("$PY" -c 'from cryptography.hazmat.bindings import _rust; print(_rust.__file__)')"
[ "$(readlink -f "$(libssl_of "$INSTALLED")")" = "$LIBSSL" ] \
    || die "installed cryptography links $(libssl_of "$INSTALLED"), not $LIBSSL"
"$PY" - "$LIBSSL" <<'EOF'
import ctypes, sys
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.bindings import _rust
from mitmproxy import options, version

print(f"  mitmproxy    {version.VERSION}")
print(f"  cryptography OpenSSL {backend.openssl_version_text()}")
ctypes.CDLL(_rust.__file__).SSL_set_fp_profile      # through cryptography's own link
print(f"  fingerprint  SSL_set_fp_profile reachable from cryptography")
if "http2_fingerprint" not in options.Options():
    sys.exit("  !! this mitmproxy has no http2_fingerprint option - wrong checkout?")
print("  option       http2_fingerprint present")
try:
    import mytls
except ImportError:
    print("  mytls        NOT installed - http2_fingerprint and the upstream TLS addon "
          "need it (--mytls DIR)")
else:
    note = "" if hasattr(mytls, "upstream_addon_path") else \
        " (old: no upstream_addon_path, reinstall with --mytls DIR)"
    print(f"  mytls        {mytls.__file__}{note}")
    print(f"               {mytls.check()}")
EOF

if ! "$PY" -m pip check >"$WORK/pipcheck" 2>&1; then
    warn "pip check reports conflicts among the packages in this interpreter:"
    sed 's/^/    /' "$WORK/pipcheck" >&2
fi

MITMDUMP="$(dirname "$PY")/mitmdump"
if command -v pyenv >/dev/null && case "$PY" in "$(pyenv root)"/*) true ;; *) false ;; esac; then
    pyenv rehash
fi
"$MITMDUMP" --version | sed 's/^/  /'

cat <<EOF

$(say "done")
  mitmdump: $MITMDUMP

  mitmdump -s "\$("$PY" -c 'import mytls; print(mytls.upstream_addon_path())')" \\
      --set fp_profile=chrome --set http2_fingerprint=chrome --set http3=false
EOF
