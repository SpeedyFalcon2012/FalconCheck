#!/bin/sh
# Open the optional per-user menu setup. No sudo or system installation.
APP_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
exec python3 "$APP_DIR/install_launcher.py"
