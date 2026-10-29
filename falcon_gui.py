"""Optional Tkinter window. Launch with python3 falcon_check.py --gui.

Only the main thread touches Tk. The worker reads data using the same scanner
as the terminal. This module can be imported without Tkinter installed.
"""
import queue
import threading
import unicodedata

import falcon_check as scanner
import falcon_picker

MODE_LABELS = {"Recommended scan": "combined", "Automatic (built-in)": "auto", "Python syntax": "python", "Text patterns": "text",
               "File details": "details", "Executable inspection": "executable",
               "Archive inventory": "archive", "Antivirus (ClamAV)": "antivirus"}
BG = "#101522"
PANEL = "#192235"
TEXT = "#e6edf8"
MUTED = "#a7b4cb"
ACCENT = "#68d9ef"
STATUS_COLORS = {"NEEDS REVIEW": "#f6bf69", "NO INDICATORS FOUND": ACCENT,
                 "NOT INSPECTED": "#d2a9f7", "BASIC INSPECTION": MUTED,
                 "PARTIAL INSPECTION": "#f6bf69", "ANTIVIRUS UNAVAILABLE": "#d2a9f7",
                 "NO THREATS REPORTED": ACCENT, "THREAT REPORTED": "#ff9b9b", "CANCELLED": MUTED}


def display_text(value):
    """Escape controls and bidi formatting while preserving readable filenames."""
    return "".join(character if not unicodedata.category(character).startswith("C")
                   else ascii(character)[1:-1] for character in str(value))


def inspect_file(path, mode, cancel=None, progress=None):
    """Return errors as explicit uninspected results, never as empty findings."""
    try:
        return scanner.scan_file(path, mode, cancel=cancel, progress=progress)
    except Exception as error:
        return {"name": path, "status": "NOT INSPECTED", "findings": [],
                "coverage": "Could not complete this scan: " + display_text(str(error)),
                "sha256": None, "size": None}


def report_text(result):
    """The readable report shown in the window and copied on request."""
    from falcon_explain import meaning, checks, evidence_kind, next_step
    lines = [meaning(result), ""]
    lines += [label + ": " + status for label, status in checks(result)]
    lines += ["", "File: " + display_text(result["name"]), "",
             "Coverage: " + result["coverage"], ""]
    for label, value in result.get("facts", []):
        lines.append(label + ": " + display_text(value))
    if result.get("facts"):
        lines.append("")
    for number, finding in enumerate(result["findings"], 1):
        location = "Line " + str(finding["line"]) if "line" in finding else finding.get("location", "Finding")
        lines += ["{}. {}  |  {}".format(number, finding["title"], location),
                  "   Evidence type: " + evidence_kind(finding),
                  "   Matched: " + display_text(finding["evidence"]),
                  "   " + finding["why"], ""]
        if finding.get("trace"):
            lines += ["   " + display_text(step) for step in finding["trace"]]
            if "resolved" in finding:
                lines.append("   Traced value: " + display_text(finding["resolved"]))
            lines.append("")
        for label, key in (("Source fact", "source_fact"), ("Inferred connection", "inference"), ("Destination", "destination"), ("Possible legitimate use", "legitimate_use"), ("Uncertainty", "uncertainty"), ("Suggested action", "remediation")):
            if finding.get(key):
                lines += ["   " + label + ": " + display_text(finding[key]), ""]
    if not result["findings"]:
        messages = {"NO INDICATORS FOUND": "No selected indicators matched.",
                    "BASIC INSPECTION": "Limited static inspection only; this is not a malware scan.",
                    "NO THREATS REPORTED": "ClamAV reported no threats within its scan coverage.",
                    "THREAT REPORTED": "ClamAV reported a detection. Review its output below."}
        lines += [messages.get(result["status"], "This file did not receive a completed analysis."), ""]
    for note in result.get("notes", []):
        lines += ["Note: " + display_text(note), ""]
    if result.get("members"):
        lines += ["ARCHIVE ENTRIES (preview)"] + [display_text(member) for member in result["members"]] + [""]
    if result.get("engine_output"):
        lines += ["CLAMAV OUTPUT"] + [display_text(line) for line in result["engine_output"].splitlines()] + [""]
    if result["size"] is not None:
        lines.append("Bytes: {:,}".format(result["size"]))
    if result["sha256"]:
        lines += ["SHA-256: " + result["sha256"],
                  "Fingerprint only; not checked against a malware database."]
    lines += ["", "Next step: " + next_step(result), "", "Findings are clues, not proof of safety or maliciousness."]
    return "\n".join(lines)


class FalconWindow:
    def __init__(self, root, tk, ttk, filedialog, initial_path="", mode="combined"):
        self.root, self.tk, self.filedialog = root, tk, filedialog
        self.busy = False
        self.closed = False
        self.after_id = None
        self.result = None
        self.picker = None
        self.cancel_event = threading.Event()
        self.messages = queue.Queue()
        self.path = tk.StringVar(value=initial_path)
        self.mode = tk.StringVar(value=next(label for label, value in MODE_LABELS.items() if value == mode))
        root.title("Falcon Check " + scanner.VERSION)
        root.geometry("{}x{}".format(min(960, root.winfo_screenwidth() - 80),
                                     min(740, root.winfo_screenheight() - 100)))
        root.minsize(720, 560)
        root.configure(bg=BG)
        root.protocol("WM_DELETE_WINDOW", self.close)

        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure("TButton", font=("DejaVu Sans", 10), padding=(14, 9),
                        background=PANEL, foreground=TEXT, borderwidth=0)
        style.map("TButton", background=[("active", "#293850")],
                  foreground=[("disabled", "#738198")])
        style.configure("Scan.TButton", background=ACCENT, foreground=BG)
        style.map("Scan.TButton", background=[("disabled", "#31445b"), ("active", "#a2ebf7")],
                  foreground=[("disabled", MUTED)])
        style.configure("TCombobox", padding=7, fieldbackground=PANEL, background=PANEL,
                        foreground=TEXT, arrowcolor=ACCENT)
        style.map("TCombobox", fieldbackground=[("readonly", PANEL)],
                  foreground=[("readonly", TEXT), ("disabled", MUTED)])
        style.configure("Horizontal.TProgressbar", background=ACCENT, troughcolor=PANEL,
                        borderwidth=0, thickness=3)

        outer = tk.Frame(root, bg=BG, padx=28, pady=22)
        outer.pack(fill="both", expand=True)
        top = tk.Frame(outer, bg=BG)
        top.pack(fill="x")
        tk.Label(top, text="FALCON CHECK", bg=BG, fg=ACCENT,
                 font=("DejaVu Sans", 11, "bold")).pack(side="left")
        self.update_button = ttk.Button(top, text="Install update…", command=self.open_update)
        self.update_button.pack(side="right")
        self.av_button = ttk.Button(top, text="Antivirus setup…", command=self.open_antivirus)
        self.av_button.pack(side="right", padx=(0, 8))
        tk.Label(outer, text="A closer look at your files.", bg=BG, fg=TEXT,
                 font=("DejaVu Sans", 24, "bold")).pack(anchor="w", pady=(7, 5))
        tk.Label(outer, text="Inspect one file locally. Scanned content is never run or uploaded.",
                 bg=BG, fg=MUTED, font=("DejaVu Sans", 10)).pack(anchor="w", pady=(0, 22))

        controls = tk.Frame(outer, bg=PANEL, padx=16, pady=15)
        controls.pack(fill="x")
        tk.Label(controls, text="FILE TO INSPECT", bg=PANEL, fg=MUTED,
                 font=("DejaVu Sans", 9, "bold")).pack(anchor="w")
        row = tk.Frame(controls, bg=PANEL)
        row.pack(fill="x", pady=(8, 12))
        self.entry = tk.Entry(row, textvariable=self.path, bg=BG, fg=TEXT,
                              insertbackground=ACCENT, relief="flat", font=("DejaVu Sans", 11))
        self.entry.pack(side="left", fill="x", expand=True, ipady=10, padx=(0, 10))
        self.browse_button = ttk.Button(row, text="Browse…", command=self.browse)
        self.browse_button.pack(side="right")
        row = tk.Frame(controls, bg=PANEL)
        row.pack(fill="x")
        tk.Label(row, text="Analysis", bg=PANEL, fg=MUTED,
                 font=("DejaVu Sans", 10)).pack(side="left", padx=(0, 10))
        self.mode_box = ttk.Combobox(row, textvariable=self.mode, values=list(MODE_LABELS),
                                     state="readonly", width=22, font=("DejaVu Sans", 10))
        self.mode_box.pack(side="left")
        self.scan_button = ttk.Button(row, text="Scan file", style="Scan.TButton", command=self.scan)
        self.scan_button.pack(side="right")
        self.demo_button = ttk.Button(row, text="Try demo", command=self.demo)
        self.demo_button.pack(side="right", padx=(8, 10))
        tk.Label(controls, text="Recommended scan runs built-in checks plus ClamAV. Use Antivirus setup if it is missing.",
                 bg=PANEL, fg=MUTED, font=("DejaVu Sans", 9)).pack(anchor="w", pady=(12, 0))

        # Reserve a small fixed gap; the activity strip is visible ONLY while
        # scanning. Percentage progress covers reading, not all analysis phases.
        activity_slot = tk.Frame(outer, bg=BG, height=28)
        activity_slot.pack(fill="x")
        activity_slot.pack_propagate(False)
        self.progress = ttk.Progressbar(activity_slot, mode="indeterminate")
        row = tk.Frame(outer, bg=BG)
        row.pack(fill="x", pady=(0, 8))
        self.status = tk.Label(row, text="READY TO INSPECT", bg=BG, fg=MUTED,
                               font=("DejaVu Sans", 14, "bold"))
        self.status.pack(side="left")
        self.copy_button = ttk.Button(row, text="Copy report", command=self.copy_report, state="disabled")
        self.copy_button.pack(side="right")
        self.cancel_button = ttk.Button(row, text="Cancel", command=self.cancel_scan, state="disabled")
        self.cancel_button.pack(side="right", padx=(0, 8))
        fix_row = tk.Frame(outer, bg=BG)
        fix_row.pack(fill="x", pady=(0, 6))
        self.fix_button = ttk.Button(fix_row, text="Preview fix…", command=self.preview_fix, state="disabled")
        self.fix_button.pack(side="right")
        body = tk.Frame(outer, bg=PANEL)
        body.pack(fill="both", expand=True)
        scrollbar = ttk.Scrollbar(body)
        scrollbar.pack(side="right", fill="y")
        self.details = tk.Text(body, wrap="word", bg=PANEL, fg=TEXT, relief="flat",
                               font=("DejaVu Sans", 10), padx=16, pady=16,
                               spacing1=2, spacing3=5, height=8, yscrollcommand=scrollbar.set)
        self.details.pack(fill="both", expand=True)
        scrollbar.configure(command=self.details.yview)
        tk.Label(outer, text="Learning prototype • A clear result is not a safety certificate.",
                 bg=BG, fg=MUTED, font=("DejaVu Sans", 9)).pack(anchor="w", pady=(12, 0))
        self.path.trace_add("write", self.selection_changed)
        self.mode.trace_add("write", self.selection_changed)
        root.bind("<Control-o>", lambda event: self.browse())
        self.entry.bind("<Return>", lambda event: self.scan())
        self.selection_changed()

    def set_details(self, text):
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    def selection_changed(self, *args):
        if self.busy:
            return
        self.result = None
        self.fix_button.configure(state="disabled")
        self.copy_button.configure(state="disabled", text="Copy report")
        self.status.configure(text="READY TO INSPECT", fg=MUTED)
        self.set_details("Choose a file or paste its path above, then click Scan file.\n\n"
                         "Recommended scan requests built-in inspection and a local ClamAV malware check. Use Antivirus setup if the engine or signatures are missing.\n\n"
                         "Try demo shows a possible sensitive-file upload trace without running the example.\n\n"
                         "Large files are read in chunks. Python syntax supports up to 2 MiB.\n\n"
                         "Executable inspection checks selected structure and embedded ASCII text. File details shows headers and a fingerprint. Archive inventory checks "
                         "supported entry names and metadata. These built-in clues do not establish whether a file contains malware.\n\n"
                         "Antivirus uses your installed ClamAV and signature database, without uploading files.")
        self.scan_button.configure(state="normal" if self.path.get().strip() else "disabled")

    def browse(self):
        if self.busy:
            return
        self.picker = falcon_picker.start_picker()
        if self.picker is not None:
            self.set_busy(True, activity=False)
            self.after_id = self.root.after(80, self.poll_picker)
        else:
            self.browse_fallback()

    def browse_fallback(self):
        filename = self.filedialog.askopenfilename(parent=self.root, title="Choose a file to inspect",
                                                   filetypes=[("All files", "*"), ("Python source", "*.py")])
        if filename:
            self.path.set(filename)
            self.entry.xview_moveto(1)

    def poll_picker(self):
        self.after_id = None
        if self.closed:
            return
        if self.picker.poll() is None:
            self.after_id = self.root.after(80, self.poll_picker)
            return
        try:
            filename = falcon_picker.picker_result(self.picker)
        except OSError:
            filename = None
        self.picker = None
        self.set_busy(False)
        if filename is None:
            self.browse_fallback()
        elif filename:
            self.path.set(filename)
            self.entry.xview_moveto(1)
        # Cancellation preserves the previous selection and result.

    def set_busy(self, busy, activity=True):
        self.busy = busy
        for widget in (self.entry, self.browse_button, self.demo_button, self.update_button, self.av_button):
            widget.configure(state="disabled" if busy else "normal")
        self.mode_box.configure(state="disabled" if busy else "readonly")
        self.scan_button.configure(state="disabled" if busy or not self.path.get().strip() else "normal")
        self.copy_button.configure(state="disabled" if busy or self.result is None else "normal")
        self.cancel_button.configure(state="normal" if busy and activity else "disabled")
        self.fix_button.configure(state="normal" if not busy and self.can_fix() else "disabled")
        if busy and activity:
            self.progress.configure(mode="indeterminate")
            self.progress.pack(fill="x", pady=(10, 10))
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress.pack_forget()

    def open_update(self):
        if not self.busy:
            from falcon_update import UpdateWindow
            UpdateWindow(self.root, scanner.VERSION, self.close)

    def open_antivirus(self):
        if not self.busy:
            from falcon_av_window import AntivirusWindow
            AntivirusWindow(self.root)

    def can_fix(self):
        return bool(self.result and self.result.get('source_is_file') and self.result.get('sha256') and
                    any(f.get('patch_span') for f in self.result['findings']))

    def preview_fix(self):
        if not self.busy and self.can_fix():
            from falcon_fix_window import FixWindow
            FixWindow(self.root, self.result)

    def scan(self):
        if self.busy or not self.path.get().strip():
            return
        # Entry accepts literal paths, not shell expressions or shell quotes.
        path, mode = self.path.get(), MODE_LABELS[self.mode.get()]
        self.cancel_event.clear()
        self.result = None
        self.set_busy(True)
        self.status.configure(text="INSPECTING…", fg=ACCENT)
        self.set_details("Reading selected file as data…")
        worker = threading.Thread(target=lambda: self.messages.put(
            inspect_file(path, mode, self.cancel_event, self.messages.put)), daemon=True)
        worker.start()
        self.after_id = self.root.after(50, self.poll)

    def poll(self):
        self.after_id = None
        if self.closed:
            return
        while True:
            try:
                result = self.messages.get_nowait()
            except queue.Empty:
                self.after_id = self.root.after(50, self.poll)
                return
            if result.get("event") != "progress":
                break
            if self.cancel_event.is_set():
                continue
            done, total = result.get("done"), result.get("total")
            if done is not None and total:
                self.progress.stop()
                self.progress.configure(mode="determinate", maximum=total, value=done)
                self.set_details("{}: {:,} / {:,} bytes ({:.0%}).\n\nThis measures the file-read phase, not all analysis.".format(
                    result["phase"], done, total, done / total))
            else:
                self.progress.configure(mode="indeterminate")
                self.progress.start(12)
                self.set_details(result["phase"] + "…")
        self.present(result)
        self.set_busy(False)

    def cancel_scan(self):
        if self.busy and self.picker is None:
            self.cancel_event.set()
            self.cancel_button.configure(state="disabled")
            self.status.configure(text="CANCELLING…", fg=MUTED)

    def present(self, result):
        self.result = result
        self.status.configure(text=result["status"], fg=STATUS_COLORS[result["status"]])
        self.set_details(report_text(result))
        self.copy_button.configure(state="normal", text="Copy report")
        self.fix_button.configure(state="normal" if self.can_fix() else "disabled")

    def demo(self):
        if not self.busy:
            result = scanner.analyze_bytes(scanner.DEMO_EVIDENCE, "In-memory evidence demo", "python")
            result.setdefault('notes', []).append('This demo exists only in memory. To try Preview fix and save a separate copy, browse to evidence-demo.txt in the extracted release and scan it using Python syntax.')
            self.present(result)

    def copy_report(self):
        if self.result is not None and not self.busy:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.result["status"] + "\n\n" + report_text(self.result))
            self.copy_button.configure(text="Copied")

    def close(self):
        self.closed = True
        self.cancel_event.set()
        if self.after_id is not None:
            self.root.after_cancel(self.after_id)
        if self.picker is not None:
            # Send the close request before Tk shuts down; reap off-thread.
            try:
                self.picker.terminate()
            except OSError:
                pass
            threading.Thread(target=falcon_picker.stop_picker, args=(self.picker,), daemon=True).start()
        self.root.destroy()


def launch(initial_path="", mode="combined"):
    try:
        import tkinter as tk
        from tkinter import ttk, filedialog
    except ImportError:
        print("The window needs Tkinter, which this Python installation is missing.")
        print("The terminal scanner still works: python3 falcon_check.py")
        print("Ask your administrator to enable Tkinter for this Python installation.")
        return 2
    try:
        root = tk.Tk(className="FalconCheck")
    except tk.TclError as error:
        print("Could not open a desktop window:", ascii(str(error)))
        print("Run from your Linux desktop session. The terminal scanner still works.")
        return 2
    FalconWindow(root, tk, ttk, filedialog, initial_path, mode)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(launch())
