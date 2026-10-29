"""Optional GTK chooser via Zenity. Never executes selected file contents."""
import os
import shutil
import subprocess


def start_picker(title="Choose a file to inspect"):
    """Return a child process, or None when the GTK helper isn't available."""
    executable = shutil.which("zenity")
    if executable is None:
        return None
    try:
        return subprocess.Popen(
            [executable, "--file-selection", "--title=" + title],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        return None


def picker_result(process):
    """Call only after exit. None = failed; empty string = cancelled."""
    output, _ = process.communicate()
    if process.returncode == 1:
        return ""
    if process.returncode != 0:
        return None
    # Remove only Zenity's final line terminator; preserve filename whitespace.
    if output.endswith(b"\n"):
        output = output[:-1]
    return os.fsdecode(output)


def stop_picker(process):
    """Run during cleanup in a worker, so closing the window never blocks."""
    try:
        if process.poll() is None:
            process.terminate()
        try:
            process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
    except OSError:
        pass
