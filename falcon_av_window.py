"""User-initiated antivirus setup; network operations are explicit buttons."""
import queue
import threading

import falcon_antivirus as av


class AntivirusWindow:
    def __init__(self, parent):
        import tkinter as tk
        from tkinter import ttk
        self.cancel = threading.Event()
        self.events = queue.Queue()
        self.busy = False
        self.closed = False
        self.after_id = None
        self.window = tk.Toplevel(parent)
        self.window.title('Falcon Check — antivirus setup')
        self.window.geometry('740x560')
        self.window.minsize(720, 480)
        self.window.transient(parent)
        self.window.grab_set()
        self.window.protocol('WM_DELETE_WINDOW', self.close)
        frame = ttk.Frame(self.window, padding=20)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='Make malware scanning available', font=('DejaVu Sans', 15, 'bold')).pack(anchor='w')
        ttk.Label(frame, text='For x86-64 Linux Mint. Setup downloads verified ClamAV ' + av.ENGINE_VERSION +
                  ' (about 90 MiB) into your own account. Signatures require a separate download and additional disk space.\n\n'
                  'No sudo or system service. Only the download buttons connect to the internet; selected scan files are never uploaded.',
                  wraplength=660, justify='left').pack(anchor='w', pady=(10, 15))
        row = ttk.Frame(frame)
        row.pack(fill='x')
        self.buttons = []
        for label, action in [('Check readiness', lambda: self.start(lambda: av.readiness(self.cancel))),
                              ('Download/setup engine', lambda: self.start(lambda: av.install_engine(self.cancel, self.progress))),
                              ('Download/update signatures', lambda: self.start(lambda: av.update_signatures(self.cancel, self.progress)))]:
            button = ttk.Button(row, text=label, command=action)
            button.pack(side='left', padx=(0, 6))
            self.buttons.append(button)
        self.output = tk.Text(frame, wrap='word', height=12, padx=10, pady=10)
        self.output.pack(fill='both', expand=True, pady=12)
        row = ttk.Frame(frame)
        row.pack(fill='x')
        self.cancel_button = ttk.Button(row, text='Cancel operation', command=self.cancel.set, state='disabled')
        self.cancel_button.pack(side='left')
        ttk.Button(row, text='Close', command=self.close).pack(side='right')
        self.set_text('Click Check readiness to test an existing engine.\n\nIf missing: Download/setup engine → Download/update signatures → Check readiness.\n\nUse the signature-update button regularly; this app does not schedule background updates. Engine upgrades arrive through newer Falcon Check releases.')

    def set_text(self, text):
        from falcon_gui import display_text
        self.output.configure(state='normal')
        self.output.delete('1.0', 'end')
        self.output.insert('1.0', '\n'.join(display_text(line) for line in text.splitlines()))
        self.output.configure(state='disabled')

    def progress(self, message):
        self.events.put(('progress', message))

    def start(self, action):
        if self.busy:
            return
        self.busy = True
        self.cancel.clear()
        for button in self.buttons:
            button.configure(state='disabled')
        self.cancel_button.configure(state='normal')
        self.set_text('Working…')
        def work():
            try:
                self.events.put(('done', action()))
            except Exception as error:
                self.events.put(('done', 'Operation did not complete:\n' + str(error)))
        threading.Thread(target=work, daemon=False).start()
        self.after_id = self.window.after(80, self.poll)

    def poll(self):
        self.after_id = None
        if self.closed:
            return
        while True:
            try:
                kind, message = self.events.get_nowait()
            except queue.Empty:
                break
            self.set_text(message)
            if kind == 'done':
                self.busy = False
                for button in self.buttons:
                    button.configure(state='normal')
                self.cancel_button.configure(state='disabled')
                return
        self.after_id = self.window.after(80, self.poll)

    def close(self):
        if self.busy:
            self.cancel.set()
            self.set_text('Stopping the current operation. A network read may take up to 30 seconds to return. Close again when it finishes.')
            return
        self.closed = True
        if self.after_id is not None:
            self.window.after_cancel(self.after_id)
        self.window.destroy()
