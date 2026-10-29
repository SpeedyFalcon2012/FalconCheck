"""Modal preview and explicit approval for a separate reviewed source copy."""
import queue
import threading
from pathlib import Path

import falcon_remediate as fixes


class FixWindow:
    def __init__(self, parent, report):
        import tkinter as tk
        from tkinter import ttk, filedialog
        self.filedialog = filedialog
        self.report = report
        self.plan = None
        self.busy = False
        self.closed = False
        self.after_id = None
        self.events = queue.Queue()
        self.window = tk.Toplevel(parent)
        self.window.title('Falcon Check — review a proposed fix')
        self.window.geometry('880x650')
        self.window.minsize(700, 500)
        self.window.transient(parent)
        self.window.grab_set()
        self.window.protocol('WM_DELETE_WINDOW', self.close)
        frame = ttk.Frame(self.window, padding=18)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='Review before saving a separate copy', font=('DejaVu Sans', 14, 'bold')).pack(anchor='w')
        self.candidates = [f for f in fixes.upload_findings(report) if f.get('patch_span')]
        self.choice = ttk.Combobox(frame, state='readonly', values=['Upload at line ' + str(f['line']) for f in self.candidates])
        self.choice.pack(fill='x', pady=10)
        self.choice.current(0)
        self.choice.bind('<<ComboboxSelected>>', lambda event: self.preview())
        body = ttk.Frame(frame)
        body.pack(fill='both', expand=True)
        scrollbar = ttk.Scrollbar(body)
        scrollbar.pack(side='right', fill='y')
        self.output = tk.Text(body, wrap='word', font=('DejaVu Sans Mono', 10), yscrollcommand=scrollbar.set)
        self.output.pack(fill='both', expand=True)
        scrollbar.configure(command=self.output.yview)
        row = ttk.Frame(frame)
        row.pack(fill='x', pady=(12, 0))
        self.save_button = ttk.Button(row, text='Approve & save separate copy…', command=self.save, state='disabled')
        self.save_button.pack(side='left')
        ttk.Button(row, text='Close', command=self.close).pack(side='right')
        self.preview()

    def text(self, text):
        from falcon_gui import display_text
        self.output.configure(state='normal')
        self.output.delete('1.0', 'end')
        self.output.insert('1.0', '\n'.join(display_text(line) for line in text.splitlines()))
        self.output.configure(state='disabled')

    def start(self, action, kind):
        self.busy = True
        self.save_button.configure(state='disabled')
        self.choice.configure(state='disabled')
        def work():
            try:
                self.events.put((kind, action(), None))
            except Exception as error:
                self.events.put((kind, None, str(error)))
        threading.Thread(target=work, daemon=False).start()
        self.after_id = self.window.after(60, self.poll)

    def preview(self):
        if self.busy:
            return
        self.plan = None
        item = self.candidates[self.choice.current()]
        self.text('Rechecking source and preparing a diff…')
        self.start(lambda: fixes.prepare(self.report['name'], self.report['sha256'], item['id']), 'preview')

    def save(self):
        if self.busy or self.plan is None:
            return
        path = Path(self.plan.source)
        target = self.filedialog.asksaveasfilename(parent=self.window, title='Save a separate reviewed copy',
                                                  initialdir=str(path.parent), initialfile=path.stem + '.reviewed' + path.suffix)
        if target:
            self.text('Saving the approved copy and rechecking it…')
            self.start(lambda: fixes.save_copy(self.plan, target), 'save')

    def poll(self):
        self.after_id = None
        try:
            kind, result, error = self.events.get_nowait()
        except queue.Empty:
            if not self.closed:
                self.after_id = self.window.after(60, self.poll)
            return
        self.busy = False
        self.choice.configure(state='readonly')
        if error:
            self.text('Operation did not complete:\n' + error + '\n\nThe original was not overwritten. If a save was interrupted after publication, a separate output copy may exist; inspect it before using it.')
            return
        if kind == 'preview':
            self.plan = result
            self.text(fixes.preview_text(result))
            self.save_button.configure(state='normal')
        else:
            from falcon_gui import report_text
            self.text('SAVED A SEPARATE COPY. Original unchanged.\n\n' + report_text(result) +
                      '\n\nThis recheck is limited Python inspection. The copy has not been run or antivirus-scanned.')
            self.plan = None

    def close(self):
        if self.busy:
            return
        self.closed = True
        if self.after_id is not None:
            self.window.after_cancel(self.after_id)
        self.window.destroy()
