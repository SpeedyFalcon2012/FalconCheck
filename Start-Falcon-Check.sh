#!/bin/sh
# Start the portable copy. This script never installs or changes anything.
APP_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
exec python3 "$APP_DIR/falcon_check.py" --gui "$@"
