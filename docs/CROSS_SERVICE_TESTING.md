# Cross-service Capsule testing (engineering build)

**Status:** pre-alpha, test data only. This is a procedure for verifying that
already-encrypted Capsule content survives ordinary carriers. It is **not**
production authorization, an external audit, forward-secret messaging, an
assurance claim against compromised endpoint software, or evidence that any
named service actually has a backdoor.

## Get the test executable

On macOS or Linux with Rust/Cargo available, build from the reviewed commit:

```sh
cargo build -p e2ee-cli --release --locked
python3 scripts/cross_service_smoke.py "$(pwd)/target/release/e2ee"
```

Alternatively use the unsigned pre-alpha CI package for your OS, inspect its
`SECURITY-NOTICE.txt` and checksums, and run
`python3 cross_service_smoke.py "$(pwd)/e2ee"` from the extracted folder.
Unsigned engineering packages and checksums from the **same untrusted source**
do not authenticate software provenance. Trust the build channel before typing
any non-test password.

The smoke script creates fresh throwaway Alice and Bob identities, independently
compares their test identities, sends text and binary files in both binary and
ASCII-armored formats through a byte-copy carrier, checks exact plaintext
recovery, and rejects incorrect contexts and tampering. It **does not** connect
to third-party services, put secrets in public paste sites, or test real network
routing. A successful run means only these local tests passed.

## Hands-on testing through real services

Set up a **separate test endpoint and state directory per participant**. Two
test identities on one machine establish transport compatibility but do not
simulate two independently trusted devices. Use different machines for a
realistic cross-device test. Use disposable data and different passphrases.

Each participant creates an identity. Choose paths in directories only that
participant controls. With an actual CLI build on the PATH:

```sh
e2ee --state "$HOME/e2ee-alice-test" --software-vault --password-only init alice
e2ee --state "$HOME/e2ee-bob-test" --software-vault --password-only init bob
```

**The two commands above are examples for distinct participants, not a
recommendation to put both participants' private state on one host.** The
`--password-only` option is deliberately weaker; for stronger rollback
protection preserve each new `ANCHOR` value **outside** the local state
and use `--anchor TOKEN` subsequently. Every state mutation can require
retaining a newer anchor. See [the full CLI documentation](cli.md).

Exchange **public** contact cards:

```sh
e2ee --state "$HOME/e2ee-alice-test" --software-vault --password-only card
e2ee --state "$HOME/e2ee-bob-test" --software-vault --password-only card
```

Each participant imports the other party's complete `e2ec:v1:` card and
then compares the complete fingerprint on a **separate trusted channel**
(in person, or another independently authenticated route). Do not blindly
verify an attacker-controlled directory result.

```sh
# Alice, using Bob's public card and independently confirmed fingerprint:
e2ee --state "$HOME/e2ee-alice-test" --software-vault --password-only import 'BOB_PUBLIC_CARD'
e2ee --state "$HOME/e2ee-alice-test" --software-vault --password-only verify bob BOB_FULL_FINGERPRINT

# Bob, using Alice's public card and independently confirmed fingerprint:
e2ee --state "$HOME/e2ee-bob-test" --software-vault --password-only import 'ALICE_PUBLIC_CARD'
e2ee --state "$HOME/e2ee-bob-test" --software-vault --password-only verify alice ALICE_FULL_FINGERPRINT
```

The single quotes above are placeholders; use the real public card and complete
fingerprint. Never send vault passphrases, private keys, independent rollback
anchors, or plaintext through the carrier being tested.

### Example A — ordinary email, messaging, or a text field

Alice creates a disposable UTF-8 message file locally and runs:

```sh
e2ee --state "$HOME/e2ee-alice-test" --software-vault --password-only --armor \
  seal-text bob cross-carrier-v1 ./dummy-message.txt ./dummy-message.asc
```

Paste the **entire** armored envelope, including BEGIN/END lines, into an email
body or messaging field. The service is *only* receiving ciphertext. Bob saves
the received body **exactly** to a local file, then runs:

```sh
e2ee --state "$HOME/e2ee-bob-test" --software-vault --password-only --armor \
  open-text alice cross-carrier-v1 ./received-message.asc ./opened-message.txt
```

The destination must not exist. Check that the dummy message matches. If the
service wraps lines, changes Unicode, truncates the body or inserts HTML,
authentication/strict format parsing should fail; the sender may instead use an
attachment.

### Example B — cloud storage, email attachments, or file shares

Alice encrypts a disposable file to Bob, uploads **only** the .e2ed file, then
sends Bob a link or attachment:

```sh
e2ee --state "$HOME/e2ee-alice-test" --software-vault --password-only \
  seal-file bob cross-file-v1 ./dummy-photo.jpg ./photo.e2ed
```

Bob downloads ciphertext and opens locally:

```sh
e2ee --state "$HOME/e2ee-bob-test" --software-vault --password-only \
  open-file alice cross-file-v1 ./photo.e2ed ./verified-photo.jpg
```

The CLI supports 32 MiB inline files, with authenticated manifests. Users must
select the output path; untrusted filenames are never executed or used directly.
Do not open untrusted received media in a privileged application without
separate safe rendering controls.

### Suggested test matrix

| Carrier | Representation | Check |
| --- | --- | --- |
| Gmail or Outlook body | ASCII armor | Exact preservation; authenticated open |
| Signal or another messenger text field | ASCII armor | Length/line-change handling |
| Slack, Teams or Discord | ASCII armor or attached .e2ed | Text handling versus attachment |
| Google Drive, Dropbox, OneDrive | Binary .e2ed | Download integrity and decrypt |
| USB drive, AirDrop or removable media | Binary .e2ed | Cross-device/offline exchange |

These are **manual test targets**, not claims of certified integration.

Repeat each success case with deliberate one-byte ciphertext corruption and
with the wrong signed application context; each must fail **without** writing
plaintext. Also try opening with an unverified or revoked contact. Record
carrier, date, source build SHA, OS, exact encoded form, result, output hashes
of **dummy** plaintext only, whether metadata was visible, and diagnostic
category. Never upload private logs, real secret data, or decrypted contents.

## Interpretation and production gate

Successful use across a third-party service demonstrates **transport
interoperability and some content confidentiality against the carrier**,
assuming correctly authenticated, uncompromised endpoints. It does not prove
anything about backdoors in that service or protect plaintext from a compromised
OS, malicious browser/extension, key theft, unauthorized endpoint code update,
screenshots, physical access, or a recipient.

Known production gaps include absent audited release provenance, platform
keystores, completed native/browser/mobile clients, secure update distribution,
forward-secret messaging and post-compromise recovery, reliable multi-device
sync and delivery, and complete E2EESA source-bound conformance testing.
These must be tested and closed **before making broad production claims**. The
current policy is in [SECURITY.md](../SECURITY.md).
