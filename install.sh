#!/usr/bin/env bash
set -euo pipefail

INSTALLER_VERSION="2026-09-17.9"
REPO_URL="https://github.com/TVcraft01/BIOAEGIS.git"
INSTALL_DIR="${BIOAEGIS_HOME:-$HOME/.local/share/bioaegis}"
BIN_DIR="${BIOAEGIS_BIN:-$HOME/.local/bin}"
LAUNCHER="$BIN_DIR/bioaegis"
APP_LAUNCHER="$BIN_DIR/bioaegis-app"
SERVICE_DIR="$HOME/.config/systemd/user"
SERVICE_FILE="$SERVICE_DIR/bioaegis-user.service"
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
[ -f "$TMP_REPO/requirements-dev.txt" ] || fatal "requirements-dev.txt is missing from origin/main."
[ -d "$TMP_REPO/tests" ] || fatal "The BIOAEGIS test suite is missing from origin/main."
[ -f "$TMP_REPO/service/bioaegis-user.service" ] || fatal "The protection service template is missing from origin/main."

# Stop the old service before replacing its code. This prevents it from holding
# deleted modules open during an upgrade.
if command -v systemctl >/dev/null 2>&1; then
    systemctl --user stop bioaegis-user.service >/dev/null 2>&1 || true
fi

# Never remove the installation while the invoking shell is inside it.
# Otherwise the shell keeps a deleted cwd and Python/pip can fail with getcwd errors.
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

VENV_PYTHON="$INSTALL_DIR/.venv/bin/python"
[ -x "$VENV_PYTHON" ] || fatal "Could not create the Python virtual environment."

say "Installing BIOAEGIS package, desktop runtime, update verifier, and test dependencies"
"$VENV_PYTHON" -m pip install --upgrade pip
case "$(uname -s)" in
    Linux)
        say "Linux detected — installing Qt/PySide6 native desktop backend"
        "$VENV_PYTHON" -m pip install -e "${INSTALL_DIR}[desktop-qt,updates]"
        ;;
    *)
        "$VENV_PYTHON" -m pip install -e "${INSTALL_DIR}[desktop,updates]"
        ;;
esac
"$VENV_PYTHON" -m pip install -r "$INSTALL_DIR/requirements-dev.txt"

say "Verifying BIOAEGIS package"
PYTHONPATH="$INSTALL_DIR" "$VENV_PYTHON" -c 'import bioaegis; import bioaegis.__main__; import bioaegis.app; import bioaegis.protection; import bioaegis.tamper; import bioaegis.updates; print(f"BIOAEGIS {bioaegis.__version__} OK")'

say "Running BIOAEGIS self-tests"
PYTHONPATH="$INSTALL_DIR" "$VENV_PYTHON" -m pytest -q "$INSTALL_DIR/tests"

say "Creating installation integrity manifest"
PYTHONPATH="$INSTALL_DIR" "$VENV_PYTHON" -c 'from bioaegis.tamper import write_manifest; write_manifest("$INSTALL_DIR")'

cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH="$INSTALL_DIR\${PYTHONPATH:+:\$PYTHONPATH}"
cd "$INSTALL_DIR"
exec "$VENV_PYTHON" -m bioaegis "\$@"
EOF
chmod +x "$LAUNCHER"

cat > "$APP_LAUNCHER" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH="$INSTALL_DIR\${PYTHONPATH:+:\$PYTHONPATH}"
cd "$INSTALL_DIR"
exec "$VENV_PYTHON" -m bioaegis.app "\$@"
EOF
chmod +x "$APP_LAUNCHER"

# Ensure protected content directories exist so the hardened user service can
# enter its writable paths without depending on the desktop having created them.
mkdir -p "$HOME/Downloads" "$HOME/Desktop" "$HOME/Documents"

# Install the defensive monitor as a user service so protection does not depend
# on the graphical console staying open.
if command -v systemctl >/dev/null 2>&1; then
    mkdir -p "$SERVICE_DIR"
    cp "$INSTALL_DIR/service/bioaegis-user.service" "$SERVICE_FILE"
    if systemctl --user daemon-reload >/dev/null 2>&1 && systemctl --user enable --now bioaegis-user.service >/dev/null 2>&1; then
        say "Defensive monitor enabled and started automatically"
    else
        say "Systemd is present, but the user monitor could not be started automatically"
    fi
else
    say "systemd user manager not available; background monitor is not auto-enabled"
fi

# Add BIOAEGIS to the desktop application menu.
mkdir -p "$APP_DIR"
cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Name=BIOAEGIS Security Console
Comment=Biologically inspired defensive security console
Exec=$APP_LAUNCHER
Icon=security-high
Terminal=false
Categories=Security;System;
StartupNotify=true
EOF
chmod 0644 "$DESKTOP_FILE"

# Automatically open the graphical console at desktop login.
mkdir -p "$AUTOSTART_DIR"
cat > "$AUTOSTART_FILE" <<EOF
[Desktop Entry]
Type=Application
Name=BIOAEGIS Security Console
Comment=Start BIOAEGIS security console
Exec=$APP_LAUNCHER
Icon=security-high
Terminal=false
X-GNOME-Autostart-enabled=true
X-KDE-autostart-after=panel
EOF
chmod 0644 "$AUTOSTART_FILE"

say "Installation complete."
say "BIOAEGIS protection runs in the background automatically."
say "The security console is registered in the application menu and desktop login startup."
say "Signed update verification is installed; automatic updates remain fail-closed until a signed release manifest is published."

# Launch the console immediately when a graphical session exists. Future boots
# use the desktop autostart entry; the protection service is independent of it.
if [ "${BIOAEGIS_NO_AUTOSTART:-0}" != "1" ] && { [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; }; then
    nohup "$APP_LAUNCHER" >/tmp/bioaegis-app.log 2>&1 &
    say "Security console started"
fi
