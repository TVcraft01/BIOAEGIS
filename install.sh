#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/TVcraft01/BIOAEGIS.git"
INSTALL_DIR="${BIOAEGIS_HOME:-$HOME/.local/share/bioaegis}"
BIN_DIR="${BIOAEGIS_BIN:-$HOME/.local/bin}"
LAUNCHER="$BIN_DIR/bioaegis"

say() { printf '[BIOAEGIS] %s\n' "$1"; }
fatal() { printf '[BIOAEGIS] ERROR: %s\n' "$1" >&2; exit 1; }

command -v git >/dev/null 2>&1 || fatal "git is required. Install it with your distribution package manager."
command -v python3 >/dev/null 2>&1 || fatal "python3 is required. Install it with your distribution package manager."

PYTHON="$(command -v python3)"

say "Installing to $INSTALL_DIR"
mkdir -p "$(dirname "$INSTALL_DIR")" "$BIN_DIR"

if [ -d "$INSTALL_DIR/.git" ]; then
    say "Existing installation found — synchronizing with origin/main"
    git -C "$INSTALL_DIR" fetch origin main
    git -C "$INSTALL_DIR" reset --hard origin/main
else
    if [ -e "$INSTALL_DIR" ]; then
        fatal "$INSTALL_DIR exists but is not a BIOAEGIS git checkout. Set BIOAEGIS_HOME to another path."
    fi
    say "Cloning BIOAEGIS"
    git clone --branch main "$REPO_URL" "$INSTALL_DIR"
fi

[ -f "$INSTALL_DIR/bioaegis/__main__.py" ] || fatal "The BIOAEGIS package is incomplete after synchronization."
[ -f "$INSTALL_DIR/requirements-dev.txt" ] || fatal "requirements-dev.txt is missing after synchronization."

if [ ! -d "$INSTALL_DIR/.venv" ]; then
    say "Creating Python virtual environment"
    "$PYTHON" -m venv "$INSTALL_DIR/.venv"
fi

VENV_PYTHON="$INSTALL_DIR/.venv/bin/python"
[ -x "$VENV_PYTHON" ] || fatal "Could not create the Python virtual environment."

say "Installing development/test dependencies"
"$VENV_PYTHON" -m pip install -r "$INSTALL_DIR/requirements-dev.txt"

say "Verifying BIOAEGIS package"
"$VENV_PYTHON" -c 'import bioaegis; import bioaegis.__main__; print(f"BIOAEGIS {bioaegis.__version__} OK")'

cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "$INSTALL_DIR"
exec "$VENV_PYTHON" -m bioaegis "\$@"
EOF
chmod +x "$LAUNCHER"

say "Installation complete."
say "Launcher: $LAUNCHER"

case ":${PATH}:" in
    *":$BIN_DIR:"*)
        say "Run: bioaegis"
        ;;
    *)
        say "$BIN_DIR is not currently in PATH."
        say "Run directly: $LAUNCHER"
        say "Or add it to PATH, then run: bioaegis"
        ;;
esac
