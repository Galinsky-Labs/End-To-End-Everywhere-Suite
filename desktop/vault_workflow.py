"""Toolkit-independent operation lifecycle for the desktop vault.

The native window supplies message dialogs, variables, controls and scheduling.
This module can be tested without importing Tk or opening a display.
"""
from queue import Empty
from threading import Thread

from vault_core import VaultError, command, execute, verify_cli


class VaultWorkflow:
    def close_window(self) -> None:
        if self._busy:
            self.messages.showwarning("Vault operation", "Wait for this file operation to finish before closing.", parent=self)
        else:
            self.destroy()

    def set_busy(self, busy: bool) -> None:
        self._busy = busy
        self.status.set("Working with local encrypted files…" if busy else "Ready")
        for control in self._controls:
            control.state(["disabled"] if busy else ["!disabled"])

    def poll_result(self) -> None:
        try:
            new_anchor, error = self._results.get_nowait()
        except Empty:
            self.after(100, self.poll_result)
            return
        self.set_busy(False)
        if error:
            self.messages.showerror("Vault operation", str(error), parent=self)
            if error.anchor:
                self.anchor.set(error.anchor)
                self.show_anchor(error.anchor, uncertain=True)
        elif new_anchor:
            self.anchor.set(new_anchor)
            self.password_only.set(False)
            self.show_anchor(new_anchor)
        else:
            self.messages.showinfo("Completed", "Operation completed. Keep the original "
                                "and exported files according to your own retention plan.",
                                parent=self)

    def perform(self, action: str) -> None:
        if self._busy:
            return
        try:
            argv = command(self.binary.get(), self.state.get(), action,
                           self.context.get(), self.source.get(),
                           self.destination.get(), self.endpoint.get(),
                           self.anchor.get(), self.password_only.get())
            if action == "open-self-file" and not self.messages.askyesno(
                "Export plaintext", "Save verified plaintext to the selected local file?",
                parent=self
            ):
                return
            password = self.password.get()
            self.password.set("")
            if action == "init" and not self.confirm_passphrase(password):
                return
            self.set_busy(True)

            def work() -> None:
                try:
                    verify_cli(argv[0])
                    self._results.put((execute(argv, password), None))
                except VaultError as exc:
                    self._results.put((None, exc))
                except Exception:
                    self._results.put((None, VaultError(
                        "Unexpected local client failure. Inspect selected files and state before retrying.")))

            try:
                Thread(target=work, daemon=True).start()
            except RuntimeError:
                self.set_busy(False)
                raise VaultError("Could not start the local operation worker. No operation was launched.")
            self.after(100, self.poll_result)
        except VaultError as exc:
            self.messages.showerror("Vault operation", str(exc), parent=self)
        finally:
            self.password.set("")

