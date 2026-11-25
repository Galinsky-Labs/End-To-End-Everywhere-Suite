# Relay and sync server (pre-alpha, E2ES-054 / E2ES-055)

`crates/e2ee-relay-server` is a small HTTP service that stores **only ciphertext**:
signed Capsule deliveries in per-mailbox queues (relay) and opaque, client-encrypted
objects with compare-and-swap versions (device sync). It is not independently reviewed
and makes no certification claim.

## Identities and authentication
- **Mailbox ID** = `SHA-256("End-To-End Everywhere relay mailbox v1\0" || ed25519_public_key)`,
  base64url. No user name, email or phone number is used.
- `POST /v1/mailboxes` (body: raw 32-byte public key) registers a mailbox. It must be
  signed with that key (proof of possession) and is idempotent.
- **Owner requests** carry `X-E2EE-Timestamp` (ms), `X-E2EE-Nonce` (16 bytes) and
  `X-E2EE-Signature` (Ed25519, strict verification) over
  `domain || len(method) || method || len(path) || path || mailbox || timestamp || nonce || SHA-256(body)`
  (see `signing_input`). Skew > 5 min is rejected; nonces are stored durably and a
  reused nonce is rejected (`replayed-request`).
- **Senders** deliver with a recipient-issued delivery capability (`X-E2EE-Capability`).
  The server stores only its SHA-256; the owner can revoke it. Sender identity is not
  required by the service; the recipient authenticates the sender from the signed delivery.

## Relay (E2ES-054)
- `POST /v1/mailboxes/{id}/capabilities` / `DELETE …/capabilities/{cap_id}` (owner).
- `POST /v1/mailboxes/{id}/messages` (capability, `X-E2EE-Upload-Token`, optional
  `X-E2EE-Retention-Ms` ≤ 30 days). The body must be a canonical, **signed** delivery;
  it is never decrypted. A retry with the same token and bytes returns the original
  sequence; the same token with different bytes is `409`.
- `GET /v1/mailboxes/{id}/messages?after=&limit=` (owner) pages ciphertext.
- `POST /v1/mailboxes/{id}/acks` (owner, body `1,2,3`) deletes messages and keeps a
  fingerprint tombstone until the original expiry, so a late retry is not re-queued.
  Clients must acknowledge only after committing their own replay state.
- Per-mailbox count/byte quotas; expired messages, tombstones and nonces are purged.

## Sync (E2ES-055)
- `PUT /v1/mailboxes/{id}/objects/{name}` (owner) requires `X-E2EE-Expected-Version`
  (`0` creates). A stale version returns `409 {"current_version":N}` and nothing is
  overwritten; clients fetch, merge locally (they hold the keys) and retry.
- `GET …/objects` lists names and versions; `GET …/objects/{name}` returns ciphertext
  and `x-e2ee-version`.

## Limits and non-goals
- SQLite (WAL, `synchronous=FULL`) on one instance. On Render's free plan the disk is
  **ephemeral**: queued data is lost on restart/redeploy. Durable hosting needs a
  persistent disk or a Postgres backend (follow-up).
- No metadata privacy beyond opaque IDs (the service sees mailbox, sizes, timing, IPs).
- Abuse control is limited to capabilities and quotas. No multi-instance coordination.
- TLS is terminated by the hosting platform.

## Pre-launch password gate
While `SITE_PASSWORD` is set (non-empty) on the service, every request needs the
`site_gate` cookie issued by `/__gate` (HMAC-SHA256 of a fixed label keyed by the
password; changing the password revokes all cookies). Only `/healthz` (Render health
check) and `/__gate` are exempt. Unauthenticated browser navigations are redirected
to `/__gate`; API calls (`/v1/...`, non-HTML) get `401 {"error":"site_locked"}`. The
gate runs before, and never replaces, the relay's Ed25519 request authentication.
Unset or empty `SITE_PASSWORD` turns it off with no behaviour change. See
`src/gate.rs`.
