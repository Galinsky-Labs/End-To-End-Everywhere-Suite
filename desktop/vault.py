"""Tk desktop surface for the Suite local encrypted file vault."""
import tkinter as tk
from queue import Queue
from tkinter import filedialog, messagebox, ttk

from vault_workflow import VaultWorkflow


class VaultWindow(tk.Tk, VaultWorkflow):
    messages = messagebox

    def __init__(self) -> None:
        super().__init__()
        self.title("End-To-End Everywhere • Local file vault (pre-alpha)")
        self.resizable(True, False)
        self._busy = False
        self._results = Queue()
        self._controls = []
        self.protocol("WM_DELETE_WINDOW", self.close_window)
        self.binary = tk.StringVar()
        self.state = tk.StringVar()
        self.endpoint = tk.StringVar()
        self.password = tk.StringVar()
        self.anchor = tk.StringVar()
        self.password_only = tk.BooleanVar(value=False)
        self.context = tk.StringVar(value="personal-file")
        self.source = tk.StringVar()
        self.destination = tk.StringVar()
        frame = ttk.Frame(self, padding=16)
        frame.grid(sticky="nsew")
        self.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)
        rows = [
            ("e2ee program", self.binary),
            ("Private state directory", self.state),
            ("New endpoint ID", self.endpoint),
            ("Vault passphrase", self.password),
            ("Independent anchor (optional)", self.anchor),
            ("Shared file context", self.context),
            ("Selected input file", self.source),
            ("New output file", self.destination),
        ]
        for row, (label, variable) in enumerate(rows):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=3)
            entry = ttk.Entry(frame, textvariable=variable, show="•" if variable is self.password else "")
            entry.grid(row=row, column=1, sticky="ew", padx=8, pady=3)
            self._controls.append(entry)
            if variable is self.binary:
                button = ttk.Button(frame, text="Choose", command=self.choose_program)
                button.grid(row=row, column=2)
                self._controls.append(button)
            if variable is self.source:
                button = ttk.Button(frame, text="Choose", command=self.choose_input)
                button.grid(row=row, column=2)
                self._controls.append(button)
            if variable is self.destination:
                button = ttk.Button(frame, text="Choose", command=self.choose_output)
                button.grid(row=row, column=2)
                self._controls.append(button)
        note = (
            "Files are encrypted on this device. Decrypted exports are private local "
            "files; other copies of the original remain where you saved them.\n"
            "Password-only mode has no independent identity pin or rollback protection. "
            "No native platform key store or synchronization is provided."
        )
        mode = ttk.Checkbutton(frame, text="I accept password-only mode without rollback protection",
                               variable=self.password_only)
        mode.grid(row=8, column=0, columnspan=3, sticky="w")
        self._controls.append(mode)
        ttk.Label(frame, text=note, wraplength=550).grid(
            row=9, column=0, columnspan=3, sticky="w", pady=10
        )
        actions = ttk.Frame(frame)
        actions.grid(row=10, column=0, columnspan=3, sticky="ew")
        for title, action in [("Create identity", "init"),
                              ("Encrypt to self", "seal-self-file"),
                              ("Verify and export", "open-self-file")]:
            button = ttk.Button(actions, text=title, command=lambda kind=action: self.perform(kind))
            button.pack(side="left", padx=3)
            self._controls.append(button)
        self.status = tk.StringVar(value="Ready")
        ttk.Label(frame, textvariable=self.status).grid(row=11, column=0, columnspan=3, sticky="w")

    def choose_program(self) -> None:
        selected = filedialog.askopenfilename(parent=self)
        if selected:
            self.binary.set(selected)

    def choose_input(self) -> None:
        selected = filedialog.askopenfilename(parent=self)
        if selected:
            self.source.set(selected)

    def choose_output(self) -> None:
        selected = filedialog.asksaveasfilename(parent=self, confirmoverwrite=False)
        if selected:
            self.destination.set(selected)

    def show_anchor(self, anchor: str, uncertain: bool = False) -> None:
        dialog = tk.Toplevel(self)
        dialog.title("Retain independent anchor")
        dialog.transient(self)
        guidance = ("Operation reported an error after emitting an anchor. Retain it "
                    "independently and inspect state before retrying. " if uncertain else
                    "Identity created. Copy this token to a separate trusted place. ")
        ttk.Label(dialog, text=guidance +
                  "This token protects against local archive rollback; losing it may prevent recovery.",
                  wraplength=520).pack(padx=16, pady=10)
        field = ttk.Entry(dialog, width=82)
        field.insert(0, anchor)
        field.configure(state="readonly")
        field.pack(padx=16, pady=8)
        ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=10)
        dialog.grab_set()
        self.wait_window(dialog)



if __name__ == "__main__":
    VaultWindow().mainloop()
