#!/usr/bin/env bash
set -euo pipefail

INSTALLER_VERSION="2026-09-14.3"
REPO_URL="https://github.com/TVcraft01/BIOAEGIS.git"
INSTALL_DIR="${BIOAEGIS_HOME:-$HOME/.local/share/bioaegis}"
BIN_DIR="${BIOAEGIS_BIN:-$HOME/.local/bin}"
LAUNCHER="$BIN_DIR/bioaegis"

say() { printf '[BIOAEGIS] %s\n' "$1"; }
fatal() { printf '[BIOAEGIS] ERROR: %s\n' "$1" >&2; exit 1; }

command -v git >/dev/null 2>&1 || fatal "git is required. Install it with your distribution package manager."
command -v python3 >/dev/null 2>&1 || fatal "python3 is required. Install it with your distribution package manager."
command -v mktemp >/dev/null 2>&1 || fatal "mktemp is required."

PYTHON="$(command -v python3)"

say "Installer $INSTALLER_VERSION"
say "Installing to $INSTALL_DIR"
mkdir -p "$(dirname "$INSTALL_DIR")" "$BIN_DIR"

# Always obtain a clean checkout in a temporary directory. This avoids stale
# local files, interrupted installs, and rebase configuration in old checkouts.
TMP_PARENT="$(mktemp -d "${TMPDIR:-/tmp}/bioaegis-install.XXXXXX")"
TMP_REPO="$TMP_PARENT/repo"
cleanup() { rm -rf "$TMP_PARENT"; }
trap cleanup EXIT

say "Downloading BIOAEGIS from origin/main"
git clone --quiet --branch main --single-branch "$REPO_URL" "$TMP_REPO"

[ -f "$TMP_REPO/bioaegis/__main__.py" ] || fatal "The downloaded BIOAEGIS package is incomplete."
[ -f "$TMP_REPO/bioaegis/__init__.py" ] || fatal "The downloaded BIOAEGIS package is incomplete."
[ -f "$TMP_REPO/requirements-dev.txt" ] || fatal "requirements-dev.txt is missing from origin/main."

if [ -d "$INSTALL_DIR/.git" ]; then
    say "Existing installation found — replacing it with the verified checkout"
    rm -rf "$INSTALL_DIR"
elif [ -e "$INSTALL_DIR" ]; then
    fatal "$INSTALL_DIR exists but is not a BIOAEGIS git checkout. Set BIOAEGIS_HOME to another path."
fi

mv "$TMP_REPO" "$INSTALL_DIR"

say "Creating Python virtual environment"
rm -rf "$INSTALL_DIR/.venv"
"$PYTHON" -m venv "$INSTALL_DIR/.venv"

VENV_PYTHON="$INSTALL_DIR/.venv/bin/python"
[ -x "$VENV_PYTHON" ] || fatal "Could not create the Python virtual environment."

say "Installing dependencies"
"$VENV_PYTHON" -m pip install -r "$INSTALL_DIR/requirements-dev.txt"

say "Verifying BIOAEGIS package"
(
    cd "$INSTALL_DIR"
    "$VENV_PYTHON" -c 'import bioaegis; import bioaegis.__main__; print(f"BIOAEGIS {bioaegis.__version__} OK")'
)

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
