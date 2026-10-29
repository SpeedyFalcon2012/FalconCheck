#!/usr/bin/env python3
"""One-time, per-user application menu setup. Never requires sudo.

Default: reviewable setup window. --cli: perform setup from the terminal.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile

APP_ID = "falcon-check-local"
PAYLOAD = ("falcon_check.py", "falcon_engine.py", "falcon_formats.py", "falcon_worker.py",
           "falcon_executable.py", "falcon_update.py", "falcon_python.py", "falcon_explain.py",
           "falcon_antivirus.py", "falcon_av_window.py", "falcon_remediate.py", "falcon_fix_window.py",
           "falcon_gui.py", "falcon_picker.py",
           "falcon-check.svg", "install_launcher.py")
MANAGED_KEY = "X-Falcon-Check-Managed=true"


def data_directory():
    configured = os.environ.get("XDG_DATA_HOME", "")
    if configured and Path(configured).is_absolute():
        return Path(configured)
    return Path.home() / ".local" / "share"


def desktop_string(value):
    value = str(value)
    if any(character in value for character in "\x00\n\r"):
        raise ValueError("Launcher paths cannot contain NUL or line breaks.")
    return value.replace("\\", "\\\\").replace("\t", "\\t")


def exec_argument(value):
    """Desktop Entry quoting, NOT shell quoting. There is no shell in Exec."""
    value = str(value)
    # Apply command quoting first, then the Desktop Entry string escaping.
    quoted = "".join("\\" + ch if ch in '\\"`$' else ch for ch in value)
    return desktop_string('"' + quoted.replace("%", "%%") + '"')


def desktop_contents(app_dir, python_executable, version=None):
    return "\n".join([
        "[Desktop Entry]", "Type=Application", "Version=1.0", "Name=Falcon Check",
        "Comment=Inspect files locally for selected suspicious patterns",
        "Exec=" + exec_argument(python_executable) + " " + exec_argument(app_dir / "falcon_check.py") + " --gui",
        "Icon=" + desktop_string(app_dir / "falcon-check.svg"), "Terminal=false",
        "Categories=Utility;", "Keywords=file;scan;inspect;", "StartupNotify=false", "StartupWMClass=FalconCheck",
        MANAGED_KEY, "X-Falcon-Check-Version=" + (version or "unknown"), "",
    ])


def atomic_write(path, data, mode=0o644):
    """Replace one owned file without following a destination symlink."""
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=str(path.parent), delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(data)
        temporary.chmod(mode)
        os.replace(str(temporary), str(path))
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def install(source=None, data_home=None, python_executable=None, payload_names=None):
    """Copy the app to a stable user location, then register its menu entry."""
    source = Path(source) if source is not None else Path(__file__).parent
    data_home = Path(data_home) if data_home is not None else data_directory()
    if not data_home.is_absolute():
        raise ValueError("Application data directory must be absolute.")
    python_executable = str(python_executable or sys.executable)
    if "=" in python_executable:
        raise ValueError("This Python executable path cannot be used in a desktop launcher.")
    app_dir = data_home / "falcon-check"
    marker = app_dir / "install.json"
    menu_dir = data_home / "applications"
    desktop = menu_dir / "falcon-check.desktop"
    # Prepare source and launcher before writing anything.
    names = tuple(payload_names) if payload_names is not None else PAYLOAD
    if not set(PAYLOAD).issubset(names) or len(set(names)) != len(names) or any(
            not re.fullmatch(r'[A-Za-z0-9_-]+\.(?:py|svg)', name) for name in names):
        raise ValueError("Unsupported application file list.")
    payload = {name: (source / name).read_bytes() for name in names}
    version = source_version(payload["falcon_check.py"])
    # Validate launcher paths before creating anything.
    desktop_contents(app_dir, python_executable, version)
    if app_dir.is_symlink():
        raise ValueError("Refusing to install through a linked Falcon Check folder.")
    if app_dir.exists():
        if not app_dir.is_dir() or not marker.is_file() or marker.is_symlink():
            raise ValueError("The destination exists but is not a recognized Falcon Check installation.")
        if json.loads(marker.read_text())["app_id"] != APP_ID:
            raise ValueError("The destination belongs to another application.")
    if desktop.is_symlink():
        raise ValueError("Refusing to replace a linked menu entry.")
    if desktop.exists() and MANAGED_KEY not in desktop.read_text().splitlines():
        raise ValueError("A different Falcon Check menu entry already exists; it was left unchanged.")
    app_dir.mkdir(parents=True, exist_ok=True)
    menu_dir.mkdir(parents=True, exist_ok=True)
    releases = app_dir / "releases"
    if releases.is_symlink():
        raise ValueError("Refusing a linked releases folder.")
    releases.mkdir(exist_ok=True)
    marker_data = {"app_id": APP_ID, "python": python_executable, "files": list(names)}
    if not marker.exists():
        atomic_write(marker, json.dumps(marker_data, indent=2).encode("utf-8"))
    release = Path(tempfile.mkdtemp(prefix="v" + version + "-", dir=str(releases)))
    try:
        for name, data in payload.items():
            atomic_write(release / name, data)
        # Existing installations keep their files. Switch the menu only after
        # the entire new release exists; a copy failure leaves it unchanged.
        atomic_write(desktop, desktop_contents(release, python_executable, version).encode("utf-8"))
    except Exception:
        shutil.rmtree(release)
        raise
    return release, desktop


def source_version(data):
    match = re.search(rb'^VERSION = "([0-9]{1,4}\.[0-9]{1,4}(?:\.[0-9]{1,4})?)"$', data, re.M)
    if not match:
        raise ValueError("Source has no supported version declaration.")
    return match.group(1).decode("ascii")


def setup_window():
    try:
        import tkinter as tk
        from tkinter import ttk, messagebox
        root = tk.Tk()
    except Exception as error:
        print("Could not open the setup window:", ascii(str(error)))
        print("Terminal setup: python3 install_launcher.py --cli")
        return 2
    root.title("Set up Falcon Check")
    root.geometry("570x345")
    root.resizable(False, False)
    frame = ttk.Frame(root, padding=24)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text="Open Falcon Check from your menu", font=("DejaVu Sans", 15, "bold")).pack(anchor="w")
    ttk.Label(frame, text=("Add a launcher for your account. After setup, search for Falcon Check "
                          "in the application menu and click it.\n\n"
                          "The app will be copied to a stable location, so moving your extracted "
                          "version folders won't break the launcher. No sudo or downloads."),
              wraplength=510, justify="left").pack(anchor="w", pady=(14, 12))
    location = data_directory() / "falcon-check"
    ttk.Label(frame, text="App location: " + str(location), wraplength=510).pack(anchor="w", pady=(0, 10))
    status = ttk.Label(frame, text="Ready to add or update the menu launcher.", wraplength=510)
    status.pack(anchor="w", pady=(0, 12))
    buttons = ttk.Frame(frame)
    buttons.pack(fill="x")

    def add_launcher():
        try:
            install()
        except Exception as error:
            messagebox.showerror("Setup could not finish", str(error), parent=root)
            return
        status.configure(text="Added. Open your application menu and search for Falcon Check.")
        install_button.configure(state="disabled", text="Added to menu")

    install_button = ttk.Button(buttons, text="Add to application menu", command=add_launcher)
    install_button.pack(side="left")
    ttk.Button(buttons, text="Close", command=root.destroy).pack(side="right")
    root.mainloop()
    return 0


def main():
    parser = argparse.ArgumentParser(description="Add Falcon Check to your own application menu")
    parser.add_argument("--cli", action="store_true", help="perform setup directly in the terminal")
    args = parser.parse_args()
    if not args.cli:
        return setup_window()
    try:
        app_dir, desktop = install()
    except Exception as error:
        print("Setup failed:", ascii(str(error)))
        return 2
    print("Added Falcon Check to your application menu.")
    print("App:", ascii(str(app_dir)))
    print("Launcher:", ascii(str(desktop)))
    print("Search for Falcon Check in the menu; no terminal is needed for normal use.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
