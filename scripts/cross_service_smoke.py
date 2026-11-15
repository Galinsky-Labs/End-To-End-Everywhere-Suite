#!/usr/bin/env python3
"""Cross-service Capsule smoke test using the real e2ee CLI and only dummy data.

The "carrier" is an untrusted byte-for-byte file transfer between two local
test endpoints. It deliberately does not claim to test Gmail, Slack, cloud
storage, network attacks, or a production endpoint.
"""
from __future__ import annotations

import argparse
import os
import secrets
import subprocess
import tempfile
from pathlib import Path


class SmokeFailure(RuntimeError):
    pass


def invoke(binary: Path, state: Path, password: str, args: list[str],
           *, armor: bool = False, expect_failure: bool = False) -> str:
    command = [str(binary), "--state", str(state), "--software-vault",
               "--password-only", "--password-stdin"]
    if armor:
        command.append("--armor")
    command.extend(args)
    try:
        completed = subprocess.run(
            command, input=password + "\n", text=True, capture_output=True,
            timeout=180, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SmokeFailure("CLI could not complete; inspect local test state") from exc
    if expect_failure:
        if completed.returncode == 0:
            raise SmokeFailure("Tampered or invalid delivery was unexpectedly accepted")
        return ""
    if completed.returncode != 0:
        # Do not forward tool diagnostics: these may include sensitive data.
        raise SmokeFailure("CLI rejected an expected-valid test operation")
    return completed.stdout


def verify_peer(binary: Path, observer: Path, remote: Path,
                name: str, password: str) -> None:
    card = invoke(binary, remote, password, ["card"]).strip()
    if not card.startswith("e2ec:v1:"):
        raise SmokeFailure("Invalid contact card from CLI")
    invoke(binary, observer, password, ["import", card])
    identity = invoke(binary, remote, password, ["identity"])
    fingerprint = next((line.removeprefix("Fingerprint: ") for line
                        in identity.splitlines() if line.startswith("Fingerprint: ")), "")
    if not fingerprint:
        raise SmokeFailure("Missing peer fingerprint")
    # This comparison is trustworthy only because *both test endpoints* are
    # under the harness's control. Real users must verify out of band.
    invoke(binary, observer, password, ["verify", name, fingerprint])


def test_transfer(binary: Path, root: Path, password: str, *, armor: bool,
                  is_file: bool) -> None:
    sender = root / "alice"
    receiver = root / "bob"
    suffix = "file" if is_file else "text"
    representation = "armor" if armor else "binary"
    prefix = f"{suffix}-{representation}"
    source = root / (prefix + ".source")
    envelope = root / (prefix + (".asc" if armor else ".e2ed"))
    transported = root / (prefix + ".carrier")
    output = root / (prefix + ".opened")
    wrong = root / (prefix + ".wrong")
    tampered = root / (prefix + ".tampered")
    rejected = root / (prefix + ".rejected")
    context = "test-file-v1" if is_file else "test-message-v1"
    payload = (bytes(range(256)) * 7 + b"\x00\xff" if is_file else
               b"Test-only private message: ciphertext must conceal this sentence.")
    source.write_bytes(payload)
    mode = "file" if is_file else "text"
    invoke(binary, sender, password,
           [f"seal-{mode}", "bob", context, str(source), str(envelope)],
           armor=armor)
    data = envelope.read_bytes()
    if not data or payload in data:
        raise SmokeFailure("Invalid envelope or plaintext visible in carrier")
    if armor and not data.startswith(b"-----BEGIN E2E DELIVERY-----"):
        raise SmokeFailure("Expected ASCII armored delivery")
    # Model a carrier that knows and retains the whole delivered object.
    transported.write_bytes(data)
    invoke(binary, receiver, password,
           [f"open-{mode}", "alice", "wrong-context-v1", str(transported), str(wrong)],
           armor=armor, expect_failure=True)
    if wrong.exists():
        raise SmokeFailure("Wrong-context attempt wrote plaintext")
    invoke(binary, receiver, password,
           [f"open-{mode}", "alice", context, str(transported), str(output)],
           armor=armor)
    if output.read_bytes() != payload:
        raise SmokeFailure("Authenticated round trip changed message bytes")
    if armor:
        tampered.write_bytes(data + b"APPENDED JUNK")
    else:
        changed = bytearray(data)
        changed[len(changed) // 2] ^= 1
        tampered.write_bytes(changed)
    invoke(binary, receiver, password,
           [f"open-{mode}", "alice", context, str(tampered), str(rejected)],
           armor=armor, expect_failure=True)
    if rejected.exists():
        raise SmokeFailure("Tampered delivery wrote plaintext")
    if os.name == "posix" and output.stat().st_mode & 0o077:
        raise SmokeFailure("Decrypted file permits group/other access")
    print(f"PASS: {suffix} {representation}, wrong-context and tamper rejection")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="Absolute path to a trusted locally built e2ee CLI")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise SystemExit("Error: CLI executable is unavailable")
    if os.name != "posix":
        raise SystemExit("Error: Unix/macOS private file adapter required")
    with tempfile.TemporaryDirectory(prefix="e2ee-carrier-smoke-") as temporary:
        root = Path(temporary)
        # Synthetic ephemeral password; never written to disk or logs.
        password = secrets.token_urlsafe(32)
        alice, bob = root / "alice", root / "bob"
        invoke(binary, alice, password, ["init", "alice"])
        invoke(binary, bob, password, ["init", "bob"])
        verify_peer(binary, alice, bob, "bob", password)
        verify_peer(binary, bob, alice, "alice", password)
        for armor in (False, True):
            for is_file in (False, True):
                test_transfer(binary, root, password, armor=armor, is_file=is_file)
    print("Cross-carrier local smoke passed. Real-service manual tests still required.")


if __name__ == "__main__":
    try:
        main()
    except (SmokeFailure, ValueError) as error:
        raise SystemExit(f"FAIL: {error}") from error
