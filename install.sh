#!/usr/bin/env bash
set -euo pipefail

INSTALLER_VERSION="2026-09-17.11"
REPO_URL="https://github.com/TVcraft01/BIOAEGIS.git"
INSTALL_DIR="${BIOAEGIS_HOME:-$HOME/.local/share/bioaegis}"
BIN_DIR="${BIOAEGIS_BIN:-$HOME/.local/bin}"
LAUNCHER="$BIN_DIR/bioaegis"
APP_LAUNCHER="$BIN_DIR/bioaegis-app"
SERVICE_DIR="$HOME/.config/systemd/user"
SERVICE_FILE="$SERVICE_DIR/bioaegis-user.service"
UPDATE_SERVICE_FILE="$SERVICE_DIR/bioaegis-update.service"
UPDATE_TIMER_FILE="$SERVICE_DIR/bioaegis-update.timer"
APP_DIR="$HOME/.local/share/applications"
DESKTOP_FILE="$APP_DIR/bioaegis.desktop"
AUTOSTART_DIR="$HOME/.config/autostart"
AUTOSTART_FILE="$AUTOSTART_DIR/bioaegis.desktop"

say() { printf '[BIOAEGIS] %s\n' "$1"; }
fatal() { printf '[BIOAEGIS] ERROR: %s\n' "$1" >&2; exit 1; }

command -v git >/dev/null 2>&1 || fatal "git is required. Install it with your distribution package manager."
command -v python3 >/dev/null 2>&1 || fatal "python3 is required. Install it with your distribution package manager."
command -v mktemp >/dev/null 2>&1 || fatal "mktemp is required."
command -v uname >/dev/null 2>&1 || fatal "uname is required."

PYTHON="$(command -v python3)"

say "Installer $INSTALLER_VERSION"
say "Installing to $INSTALL_DIR"
mkdir -p "$(dirname "$INSTALL_DIR")" "$BIN_DIR"

TMP_PARENT="$(mktemp -d "${TMPDIR:-/tmp}/bioaegis-install.XXXXXX")"
TMP_REPO="$TMP_PARENT/repo"
cleanup() { rm -rf "$TMP_PARENT"; }
trap cleanup EXIT

say "Downloading BIOAEGIS from origin/main"
git clone --quiet --branch main --single-branch "$REPO_URL" "$TMP_REPO"

[ -f "$TMP_REPO/pyproject.toml" ] || fatal "pyproject.toml is missing from origin/main."
[ -f "$TMP_REPO/bioaegis/__main__.py" ] || fatal "The downloaded BIOAEGIS package is incomplete."
[ -f "$TMP_REPO/bioaegis/app.py" ] || fatal "The desktop launcher is missing from origin/main."
[ -f "$TMP_REPO/bioaegis/protection.py" ] || fatal "The continuous protection engine is missing from origin/main."
[ -f "$TMP_REPO/bioaegis/tamper.py" ] || fatal "The installation integrity module is missing from origin/main."
[ -f "$TMP_REPO/bioaegis/updates.py" ] || fatal "The signed update verifier is missing from origin/main."
[ -f "$TMP_REPO/bioaegis/trusted_update_key.pem" ] || fatal "The update trust anchor is missing from origin/main."
[ -f "$TMP_REPO/requirements-dev.txt" ] || fatal "requirements-dev.txt is missing from origin/main."
[ -d "$TMP_REPO/tests" ] || fatal "The BIOAEGIS test suite is missing from origin/main."
[ -f "$TMP_REPO/service/bioaegis-user.service" ] || fatal "The protection service template is missing from origin/main."
[ -f "$TMP_REPO/service/bioaegis-update.service" ] || fatal "The update service template is missing from origin/main."
[ -f "$TMP_REPO/service/bioaegis-update.timer" ] || fatal "The update timer template is missing from origin/main."

if command -v systemctl >/dev/null 2>&1; then
    systemctl --user stop bioaegis-user.service >/dev/null 2>&1 || true
    systemctl --user stop bioaegis-update.timer >/dev/null 2>&1 || true
fi

# Never remove the installation while the invoking shell is inside it.
CURRENT_DIR="$(pwd -P)"
case "$CURRENT_DIR/" in
    "$INSTALL_DIR"/*)
        say "Current directory is inside the installation; moving the shell to $HOME before replacement"
        cd "${HOME:-/}"
        ;;
esac

if [ -d "$INSTALL_DIR/.git" ]; then
    say "Existing installation found — replacing it with the verified checkout"
    rm -rf "$INSTALL_DIR"
elif [ -e "$INSTALL_DIR" ]; then
    fatal "$INSTALL_DIR exists but is not a BIOAEGIS git checkout. Set BIOAEGIS_HOME to another path."
fi

mv "$TMP_REPO" "$INSTALL_DIR"
[ -f "$INSTALL_DIR/bioaegis/__init__.py" ] || fatal "BIOAEGIS package was not installed at the expected path."
[ -f "$INSTALL_DIR/bioaegis/__main__.py" ] || fatal "BIOAEGIS entry point was not installed at the expected path."

say "Creating Python virtual environment"
rm -rf "$INSTALL_DIR/.venv"
"$PYTHON" -m venv "$INSTALL_DIR/.venv"
VENV_DIR="$INSTALL_DIR/.venv"
VENV_PYTHON="$VENV_DIR/bin/python"
VENV_BIOAEGIS="$VENV_DIR/bin/bioaegis"
VENV_APP="$VENV_DIR/bin/bioaegis-app"
[ -x "$VENV_PYTHON" ] || fatal "Could not create the Python virtual environment."

say "Installing BIOAEGIS package, desktop runtime, update verifier, and test dependencies"
"$VENV_PYTHON" -m pip install --upgrade pip
case "$(uname -s)" in
    Linux)
        say "Linux detected — installing Qt/PySide6 native desktop backend"
        "$VENV_PYTHON" -m pip install "${INSTALL_DIR}[desktop-qt,updates]"
        ;;
    *)
        "$VENV_PYTHON" -m pip install "${INSTALL_DIR}[desktop,updates]"
        ;;
esac
"$VENV_PYTHON" -m pip install -r "$INSTALL_DIR/requirements-dev.txt"

say "Verifying BIOAEGIS package"
"$VENV_PYTHON" -c 'import bioaegis; import bioaegis.__main__; import bioaegis.app; import bioaegis.protection; import bioaegis.tamper; import bioaegis.updates; print(f"BIOAEGIS {bioaegis.__version__} OK")'

say "Running BIOAEGIS self-tests"
"$VENV_PYTHON" -m pytest -q "$INSTALL_DIR/tests"

say "Creating installation integrity manifest"
BIOAEGIS_HOME="$INSTALL_DIR" "$VENV_BIOAEGIS" test >/dev/null 2>&1 || true
"$VENV_PYTHON" -c 'from bioaegis.tamper import write_manifest; import os; write_manifest(os.environ["BIOAEGIS_HOME"])'