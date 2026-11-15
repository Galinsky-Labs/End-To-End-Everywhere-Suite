"""Headless state tests for the optional Tk desktop surface."""
import queue
import unittest
from unittest.mock import Mock, patch


class Variable:
    def __init__(self, value=""):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class Control:
    def __init__(self):
        self.disabled = False

    def state(self, states):
        self.disabled = "disabled" in states


class DesktopStateTests(unittest.TestCase):
    def test_operation_handoff_blocks_overlap_and_clears_passphrase(self):
        import vault_workflow as vault

        class Window:
            set_busy = vault.VaultWorkflow.set_busy
            poll_result = vault.VaultWorkflow.poll_result
            perform = vault.VaultWorkflow.perform

            def __init__(self):
                self.messages = Mock()
                self._busy = False
                self._results = queue.Queue()
                self._controls = [Control()]
                self.status = Variable("Ready")
                self.binary = Variable("/trusted/e2ee")
                self.state = Variable("/private/state")
                self.endpoint = Variable("me")
                self.password = Variable("throwaway-test-passphrase")
                self.anchor = Variable("a" * 140)
                self.password_only = Variable(False)
                self.context = Variable("personal-file")
                self.source = Variable("/selected")
                self.destination = Variable("/new")
                self.scheduled = None

            def after(self, _milliseconds, callback):
                self.scheduled = callback

        window = Window()

        class InlineThread:
            def __init__(self, target, daemon):
                self.target = target

            def start(self):
                self.target()

        argv = ["/trusted/e2ee", "open-self-file", "context", "in", "out"]
        with patch.object(vault, "command", return_value=argv), \
             patch.object(vault, "Thread", InlineThread), \
             patch.object(vault, "verify_cli") as verify, \
             patch.object(vault, "execute", return_value=None) as execute, \
             patch.object(window.messages, "showinfo") as info:
            window.perform("seal-self-file")
            self.assertTrue(window._busy)
            self.assertTrue(window._controls[0].disabled)
            self.assertEqual(window.password.get(), "")
            window.perform("seal-self-file")
            self.assertEqual(execute.call_count, 1)
            self.assertEqual(verify.call_count, 1)
            self.assertEqual(execute.call_args.args[1], "throwaway-test-passphrase")
            window.scheduled()
            self.assertFalse(window._busy)
            self.assertFalse(window._controls[0].disabled)
            self.assertEqual(window.status.get(), "Ready")
            info.assert_called_once()


class DesktopFailureStateTests(unittest.TestCase):
    def setUp(self):
        import vault_workflow as vault
        self.vault = vault

    def window(self):
        vault = self.vault
        class Window:
            perform = vault.VaultWorkflow.perform
            poll_result = vault.VaultWorkflow.poll_result
            set_busy = vault.VaultWorkflow.set_busy
            close_window = vault.VaultWorkflow.close_window
            def __init__(self):
                self.messages = Mock()
                self._busy = False
                self._results = queue.Queue()
                self._controls = [Control()]
                self.status = Variable("Ready")
                for name, value in {
                    "binary": "/trusted/e2ee", "state": "/private/state",
                    "endpoint": "me", "password": "test-only-passphrase",
                    "anchor": "a" * 140, "password_only": False,
                    "context": "personal-file", "source": "/input",
                    "destination": "/output"
                }.items():
                    setattr(self, name, Variable(value))
                self.anchors = []
                self.scheduled = None
                self.destroyed = False
            def after(self, _milliseconds, callback):
                self.scheduled = callback
            def show_anchor(self, anchor, uncertain=False):
                self.anchors.append((anchor, uncertain))
            def destroy(self):
                self.destroyed = True
        return Window()

    def test_plaintext_confirmation_cancel_never_launches_process(self):
        vault, window = self.vault, self.window()
        with patch.object(vault, "command", return_value=["/trusted/e2ee"]), \
             patch.object(window.messages, "askyesno", return_value=False), \
             patch.object(vault, "Thread") as thread:
            window.perform("open-self-file")
            thread.assert_not_called()
            self.assertFalse(window._busy)
            self.assertEqual(window.password.get(), "")

    def test_validation_failure_clears_secret_without_launching_process(self):
        vault, window = self.vault, self.window()
        with patch.object(vault, "command", side_effect=vault.VaultError("Invalid paths")), \
             patch.object(window.messages, "showerror") as error, \
             patch.object(vault, "Thread") as thread:
            window.perform("seal-self-file")
            error.assert_called_once()
            thread.assert_not_called()
            self.assertEqual(window.password.get(), "")
            self.assertFalse(window._busy)

    def test_uncertain_result_retains_anchor_and_reenables_controls(self):
        vault, window = self.vault, self.window()
        anchor = "b" * 140
        window.set_busy(True)
        window._results.put((None, vault.VaultError("State may be committed", anchor)))
        with patch.object(window.messages, "showerror") as error, \
             patch.object(window.messages, "showinfo") as info:
            window.poll_result()
            error.assert_called_once()
            info.assert_not_called()
        self.assertEqual(window.anchor.get(), anchor)
        self.assertEqual(window.anchors, [(anchor, True)])
        self.assertFalse(window._busy)
        self.assertFalse(window._controls[0].disabled)

    def test_cancelled_identity_passphrase_confirmation_never_starts_worker(self):
        vault, window = self.vault, self.window()
        window.confirm_passphrase = Mock(return_value=False)
        with patch.object(vault, "command", return_value=["/trusted/e2ee", "init", "me"]), \
             patch.object(vault, "Thread") as thread:
            window.perform("init")
            window.confirm_passphrase.assert_called_once_with("test-only-passphrase")
            thread.assert_not_called()
        self.assertEqual(window.password.get(), "")
        self.assertFalse(window._busy)

    def test_worker_launch_failure_unlocks_controls_and_clears_secret(self):
        vault, window = self.vault, self.window()
        with patch.object(vault, "command", return_value=["/trusted/e2ee"]), \
             patch.object(vault, "Thread", side_effect=RuntimeError("cannot start new thread")), \
             patch.object(window.messages, "showerror") as error:
            window.perform("seal-self-file")
            error.assert_called_once()
        self.assertFalse(window._busy)
        self.assertFalse(window._controls[0].disabled)
        self.assertEqual(window.password.get(), "")
        self.assertIsNone(window.scheduled)

    def test_pending_result_keeps_window_locked_and_schedules_poll(self):
        window = self.window()
        window.set_busy(True)
        window.poll_result()
        self.assertTrue(window._busy)
        self.assertTrue(window._controls[0].disabled)
        self.assertIsNotNone(window.scheduled)

    def test_close_during_operation_preserves_live_window(self):
        window = self.window()
        window.set_busy(True)
        with patch.object(window.messages, "showwarning") as warning:
            window.close_window()
            warning.assert_called_once()
        self.assertFalse(window.destroyed)
        window.set_busy(False)
        window.close_window()
        self.assertTrue(window.destroyed)


if __name__ == "__main__":
    unittest.main()
