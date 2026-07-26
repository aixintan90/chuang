#!/bin/sh
# skillxray installer — downloads one Python file and drops a launcher on PATH.
# Usage:  curl -fsSL https://raw.githubusercontent.com/aixintan90/skillxray/main/install.sh | sh
# Opt out of PATH edits with SKILLXRAY_NO_MODIFY_PATH=1. Override dir with SKILLXRAY_INSTALL_DIR.
set -eu

REPO="aixintan90/skillxray"
SRC_URL="https://raw.githubusercontent.com/${REPO}/main/skillxray.py"

say() { printf '%s\n' "$1" >&2; }
err() { say "skillxray install: error: $1"; exit 1; }

main() {
    command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1 \
        || err "Python 3.9+ is required but was not found on PATH."
    PY="$(command -v python3 || command -v python)"

    BIN_DIR="${SKILLXRAY_INSTALL_DIR:-${XDG_BIN_HOME:-$HOME/.local/bin}}"
    mkdir -p "$BIN_DIR"
    LIB_DIR="$HOME/.skillxray"
    mkdir -p "$LIB_DIR"

    tmp="$(mktemp)"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$SRC_URL" -o "$tmp" || err "download failed: $SRC_URL"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$tmp" "$SRC_URL" || err "download failed: $SRC_URL"
    else
        err "need curl or wget to download skillxray."
    fi
    grep -q "skillxray" "$tmp" || err "downloaded file does not look like skillxray."
    mv "$tmp" "$LIB_DIR/skillxray.py"

    launcher="$BIN_DIR/skillxray"
    cat > "$launcher" <<EOF
#!/bin/sh
exec "$PY" "$LIB_DIR/skillxray.py" "\$@"
EOF
    chmod +x "$launcher"

    say "installed skillxray -> $launcher"
    say "               source $LIB_DIR/skillxray.py"

    case ":$PATH:" in
        *":$BIN_DIR:"*) ;;
        *)
            if [ "${SKILLXRAY_NO_MODIFY_PATH:-0}" = "1" ]; then
                say "note: $BIN_DIR is not on PATH. Add it yourself:"
                say "  export PATH=\"$BIN_DIR:\$PATH\""
            else
                say "note: $BIN_DIR is not on your PATH. Add this to your shell profile:"
                say "  export PATH=\"$BIN_DIR:\$PATH\""
            fi
            ;;
    esac
    say ""
    say "try it:  skillxray scan anthropics/skills"
}

main "$@" || exit 1
