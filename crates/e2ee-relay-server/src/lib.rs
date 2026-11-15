//! Authenticated, ciphertext-only relay (E2ES-054) and device-sync object
//! store (E2ES-055) over a durable SQLite database.
//!
//! Security model (pre-alpha, not independently reviewed):
//! - The service never receives plaintext or content keys. Relay messages must
//!   be canonical, *signed* Capsule deliveries; framing is validated, content is
//!   never opened. Sync objects are opaque client ciphertext.
//! - A mailbox is identified by `SHA-256(domain || owner Ed25519 public key)`,
//!   never by a user name, email or phone number.
//! - Owner operations (list, acknowledge, capabilities, sync objects) require an
//!   Ed25519 signature over method, path, mailbox, timestamp, nonce and body
//!   digest. Timestamps outside a bounded skew window and reused nonces are
//!   rejected (replay protection survives restarts because nonces are durable).
//! - Senders deliver with a recipient-issued, revocable delivery capability.
//!   Only its SHA-256 is stored. The sender's identity is not required by the
//!   service; recipients authenticate the sender from the signed delivery.
//! - Upload tokens make retries idempotent; acknowledged uploads keep a
//!   fingerprint tombstone until the original expiry so a late retry cannot
//!   re-queue an acknowledged message.
//! - Sync uses compare-and-swap versions: a write with a stale expected version
//!   is a conflict (409) that returns the current version; nothing is merged or
//!   overwritten server-side.
//!
//! Not provided: transport TLS (terminated by the hosting platform), metadata
//! privacy beyond opaque identifiers, abuse controls beyond quotas, or
//! multi-instance coordination.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use e2ee_capsule::CapsuleLimits;
use e2ee_transport::Delivery;
use ed25519_dalek::{Signature, VerifyingKey};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

pub const AUTH_DOMAIN: &[u8] = b"End-To-End Everywhere relay request v1\0";
const MAILBOX_DOMAIN: &[u8] = b"End-To-End Everywhere relay mailbox v1\0";

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_skew_ms: u64,
    pub max_body_bytes: usize,
    pub max_messages_per_mailbox: u64,
    pub max_bytes_per_mailbox: u64,
    pub default_retention_ms: u64,
    pub max_retention_ms: u64,
    pub max_page: u64,
    pub max_capabilities: u64,
    pub max_objects_per_mailbox: u64,
    pub max_object_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_skew_ms: 5 * 60 * 1000,
            max_body_bytes: 1024 * 1024,
            max_messages_per_mailbox: 256,
            max_bytes_per_mailbox: 16 * 1024 * 1024,
            default_retention_ms: 7 * 24 * 3600 * 1000,
            max_retention_ms: 30 * 24 * 3600 * 1000,
            max_page: 32,
            max_capabilities: 64,
            max_objects_per_mailbox: 256,
            max_object_bytes: 256 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    /// Path without query string.
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    fn query(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

impl Response {
    fn json(status: u16, body: String) -> Self {
        Self {
            status,
            content_type: "application/json",
            headers: Vec::new(),
            body: body.into_bytes(),
        }
    }
    fn error(status: u16, code: &str) -> Self {
        Self::json(status, format!("{{\"error\":\"{code}\"}}"))
    }
}

pub fn mailbox_id(public_key: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(MAILBOX_DOMAIN);
    h.update(public_key);
    h.finalize().into()
}

/// Bytes an owner signs. Exposed so clients and tests construct it identically.
pub fn signing_input(
    method: &str,
    path: &str,
    mailbox: &[u8; 32],
    timestamp_ms: u64,
    nonce: &[u8; 16],
    body: &[u8],
) -> Vec<u8> {
    let mut out = AUTH_DOMAIN.to_vec();
    for part in [method.as_bytes(), path.as_bytes()] {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out.extend_from_slice(mailbox);
    out.extend_from_slice(&timestamp_ms.to_be_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&Sha256::digest(body));
    out
}

fn sha(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

fn decode_fixed<const N: usize>(text: &str) -> Option<[u8; N]> {
    B64.decode(text).ok()?.try_into().ok()
}

fn random<const N: usize>() -> Result<[u8; N], Response> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|_| Response::error(500, "rng-unavailable"))?;
    Ok(out)
}

pub struct Server {
    db: Connection,
    limits: Limits,
    delivery_limits: CapsuleLimits,
}

impl Server {
    pub fn open(path: &str, limits: Limits) -> rusqlite::Result<Self> {
        let db = Connection::open(path)?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS mailboxes(id BLOB PRIMARY KEY, public_key BLOB NOT NULL, created_ms INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS nonces(mailbox BLOB NOT NULL, nonce BLOB NOT NULL, expires_ms INTEGER NOT NULL, PRIMARY KEY(mailbox, nonce));
             CREATE TABLE IF NOT EXISTS capabilities(id BLOB PRIMARY KEY, mailbox BLOB NOT NULL REFERENCES mailboxes(id), token_hash BLOB NOT NULL UNIQUE);
             CREATE TABLE IF NOT EXISTS messages(seq INTEGER PRIMARY KEY AUTOINCREMENT, mailbox BLOB NOT NULL REFERENCES mailboxes(id), upload_token BLOB NOT NULL, fingerprint BLOB NOT NULL, body BLOB NOT NULL, expires_ms INTEGER NOT NULL, UNIQUE(mailbox, upload_token));
             CREATE TABLE IF NOT EXISTS tombstones(mailbox BLOB NOT NULL, upload_token BLOB NOT NULL, fingerprint BLOB NOT NULL, seq INTEGER NOT NULL, expires_ms INTEGER NOT NULL, PRIMARY KEY(mailbox, upload_token));
             CREATE TABLE IF NOT EXISTS objects(mailbox BLOB NOT NULL REFERENCES mailboxes(id), name TEXT NOT NULL, version INTEGER NOT NULL, body BLOB NOT NULL, PRIMARY KEY(mailbox, name));",
        )?;
        Ok(Self {
            db,
            limits,
            delivery_limits: CapsuleLimits::default(),
        })
    }

    pub fn handle(&mut self, req: &Request, now_ms: u64) -> Response {
        match self.route(req, now_ms) {
            Ok(r) | Err(r) => r,
        }
    }

    fn route(&mut self, req: &Request, now: u64) -> Result<Response, Response> {
        if req.body.len() > self.limits.max_body_bytes {
            return Err(Response::error(413, "body-too-large"));
        }
        self.purge(now)?;
        let parts: Vec<&str> = req.path.trim_start_matches('/').split('/').collect();
        match (req.method.as_str(), parts.as_slice()) {
            ("GET", ["healthz"]) => Ok(Response::json(200, "{\"status\":\"ok\"}".into())),
            ("POST", ["v1", "mailboxes"]) => self.register(req, now),
            ("POST", ["v1", "mailboxes", id, "capabilities"]) => {
                let mb = self.authenticate(req, id, now)?;
                self.issue_capability(&mb)
            }
            ("DELETE", ["v1", "mailboxes", id, "capabilities", cap]) => {
                let mb = self.authenticate(req, id, now)?;
                let cap: [u8; 16] =
                    decode_fixed(cap).ok_or(Response::error(400, "bad-capability-id"))?;
                let n = self
                    .db
                    .execute(
                        "DELETE FROM capabilities WHERE id=?1 AND mailbox=?2",
                        params![&cap[..], &mb[..]],
                    )
                    .map_err(db_err)?;
                Ok(Response::json(200, format!("{{\"revoked\":{}}}", n == 1)))
            }
            ("POST", ["v1", "mailboxes", id, "messages"]) => self.enqueue(req, id, now),
            ("GET", ["v1", "mailboxes", id, "messages"]) => {
                let mb = self.authenticate(req, id, now)?;
                self.list(req, &mb)
            }
            ("POST", ["v1", "mailboxes", id, "acks"]) => {
                let mb = self.authenticate(req, id, now)?;
                self.acknowledge(req, &mb)
            }
            ("GET", ["v1", "mailboxes", id, "objects"]) => {
                let mb = self.authenticate(req, id, now)?;
                self.list_objects(&mb)
            }
            ("GET", ["v1", "mailboxes", id, "objects", name]) => {
                let mb = self.authenticate(req, id, now)?;
                self.get_object(&mb, name)
            }
            ("PUT", ["v1", "mailboxes", id, "objects", name]) => {
                let mb = self.authenticate(req, id, now)?;
                self.put_object(req, &mb, name)
            }
            _ => Err(Response::error(404, "not-found")),
        }
    }

    fn purge(&mut self, now: u64) -> Result<(), Response> {
        let n = now as i64;
        for table in ["nonces", "messages", "tombstones"] {
            self.db
                .execute(
                    &format!("DELETE FROM {table} WHERE expires_ms <= ?1"),
                    params![n],
                )
                .map_err(db_err)?;
        }
        Ok(())
    }

    /// Verify an owner request. Records the nonce durably *before* acting so a
    /// replay is rejected even across restarts.
    fn authenticate(&mut self, req: &Request, id: &str, now: u64) -> Result<[u8; 32], Response> {
        let unauth = || Response::error(401, "unauthenticated");
        let mailbox: [u8; 32] = decode_fixed(id).ok_or(Response::error(400, "bad-mailbox"))?;
        let ts: u64 = req
            .header("x-e2ee-timestamp")
            .and_then(|v| v.parse().ok())
            .ok_or_else(unauth)?;
        let nonce: [u8; 16] = req
            .header("x-e2ee-nonce")
            .and_then(decode_fixed)
            .ok_or_else(unauth)?;
        let sig: [u8; 64] = req
            .header("x-e2ee-signature")
            .and_then(decode_fixed)
            .ok_or_else(unauth)?;
        if ts.abs_diff(now) > self.limits.max_skew_ms {
            return Err(Response::error(401, "stale-or-future-timestamp"));
        }
        let key: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT public_key FROM mailboxes WHERE id=?1",
                params![&mailbox[..]],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?;
        let key: [u8; 32] = key.and_then(|k| k.try_into().ok()).ok_or_else(unauth)?;
        verify(
            &key,
            &signing_input(&req.method, &req.path, &mailbox, ts, &nonce, &req.body),
            &sig,
        )
        .ok_or_else(unauth)?;
        let expires = now.saturating_add(2 * self.limits.max_skew_ms) as i64;
        let inserted = self
            .db
            .execute(
                "INSERT OR IGNORE INTO nonces(mailbox, nonce, expires_ms) VALUES(?1, ?2, ?3)",
                params![&mailbox[..], &nonce[..], expires],
            )
            .map_err(db_err)?;
        if inserted == 0 {
            return Err(Response::error(401, "replayed-request"));
        }
        Ok(mailbox)
    }

    /// Body: raw 32-byte Ed25519 public key. The request is self-signed with
    /// that key, proving possession; registration is idempotent.
    fn register(&mut self, req: &Request, now: u64) -> Result<Response, Response> {
        let key: [u8; 32] = req
            .body
            .clone()
            .try_into()
            .map_err(|_| Response::error(400, "bad-public-key"))?;
        VerifyingKey::from_bytes(&key).map_err(|_| Response::error(400, "bad-public-key"))?;
        let id = mailbox_id(&key);
        let ts: u64 = req
            .header("x-e2ee-timestamp")
            .and_then(|v| v.parse().ok())
            .ok_or(Response::error(401, "unauthenticated"))?;
        let nonce: [u8; 16] = req
            .header("x-e2ee-nonce")
            .and_then(decode_fixed)
            .ok_or(Response::error(401, "unauthenticated"))?;
        let sig: [u8; 64] = req
            .header("x-e2ee-signature")
            .and_then(decode_fixed)
            .ok_or(Response::error(401, "unauthenticated"))?;
        if ts.abs_diff(now) > self.limits.max_skew_ms
            || verify(
                &key,
                &signing_input(&req.method, &req.path, &id, ts, &nonce, &req.body),
                &sig,
            )
            .is_none()
        {
            return Err(Response::error(401, "unauthenticated"));
        }
        self.db
            .execute(
                "INSERT OR IGNORE INTO mailboxes(id, public_key, created_ms) VALUES(?1, ?2, ?3)",
                params![&id[..], &key[..], now as i64],
            )
            .map_err(db_err)?;
        Ok(Response::json(
            201,
            format!("{{\"mailbox\":\"{}\"}}", B64.encode(id)),
        ))
    }

    fn issue_capability(&mut self, mailbox: &[u8; 32]) -> Result<Response, Response> {
        let count: i64 = self
            .db
            .query_row(
                "SELECT COUNT(*) FROM capabilities WHERE mailbox=?1",
                params![&mailbox[..]],
                |r| r.get(0),
            )
            .map_err(db_err)?;
        if count as u64 >= self.limits.max_capabilities {
            return Err(Response::error(429, "capability-quota"));
        }
        let id: [u8; 16] = random()?;
        let token: [u8; 32] = random()?;
        self.db
            .execute(
                "INSERT INTO capabilities(id, mailbox, token_hash) VALUES(?1, ?2, ?3)",
                params![&id[..], &mailbox[..], sha(&token)],
            )
            .map_err(db_err)?;
        Ok(Response::json(
            201,
            format!(
                "{{\"id\":\"{}\",\"token\":\"{}\"}}",
                B64.encode(id),
                B64.encode(token)
            ),
        ))
    }

    fn enqueue(&mut self, req: &Request, id: &str, now: u64) -> Result<Response, Response> {
        let mailbox: [u8; 32] = decode_fixed(id).ok_or(Response::error(400, "bad-mailbox"))?;
        let token: [u8; 32] = req
            .header("x-e2ee-capability")
            .and_then(decode_fixed)
            .ok_or(Response::error(403, "capability-required"))?;
        let owner: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT mailbox FROM capabilities WHERE token_hash=?1",
                params![sha(&token)],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?;
        if owner.as_deref() != Some(&mailbox[..]) {
            return Err(Response::error(403, "capability-rejected"));
        }
        let upload: [u8; 16] = req
            .header("x-e2ee-upload-token")
            .and_then(decode_fixed)
            .filter(|t: &[u8; 16]| t.iter().any(|b| *b != 0))
            .ok_or(Response::error(400, "bad-upload-token"))?;
        let retention = match req.header("x-e2ee-retention-ms") {
            None => self.limits.default_retention_ms,
            Some(v) => v
                .parse()
                .map_err(|_| Response::error(400, "bad-retention"))?,
        };
        if retention == 0 || retention > self.limits.max_retention_ms {
            return Err(Response::error(400, "bad-retention"));
        }
        // Validate canonical signed delivery framing without opening content.
        let delivery = Delivery::decode(&req.body, self.delivery_limits)
            .map_err(|_| Response::error(400, "invalid-delivery"))?;
        if delivery.signature.is_none() {
            return Err(Response::error(400, "unsigned-delivery"));
        }
        if delivery
            .encode(self.delivery_limits)
            .map_err(|_| Response::error(400, "invalid-delivery"))?
            != req.body
        {
            return Err(Response::error(400, "noncanonical-delivery"));
        }
        let fp = sha(&req.body);
        let existing: Option<(Vec<u8>, i64)> = self
            .db
            .query_row(
                "SELECT fingerprint, seq FROM messages WHERE mailbox=?1 AND upload_token=?2
                 UNION ALL SELECT fingerprint, seq FROM tombstones WHERE mailbox=?1 AND upload_token=?2",
                params![&mailbox[..], &upload[..]],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db_err)?;
        if let Some((prior, seq)) = existing {
            return if prior == fp {
                Ok(Response::json(
                    200,
                    format!("{{\"sequence\":{seq},\"duplicate\":true}}"),
                ))
            } else {
                Err(Response::error(409, "upload-token-conflict"))
            };
        }
        let (count, bytes): (i64, i64) = self
            .db
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(body)),0) FROM messages WHERE mailbox=?1",
                params![&mailbox[..]],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(db_err)?;
        if count as u64 >= self.limits.max_messages_per_mailbox
            || bytes as u64 + req.body.len() as u64 > self.limits.max_bytes_per_mailbox
        {
            return Err(Response::error(429, "mailbox-quota"));
        }
        let expires = now
            .checked_add(retention)
            .ok_or(Response::error(400, "bad-retention"))? as i64;
        self.db
            .execute(
                "INSERT INTO messages(mailbox, upload_token, fingerprint, body, expires_ms) VALUES(?1, ?2, ?3, ?4, ?5)",
                params![&mailbox[..], &upload[..], fp, &req.body, expires],
            )
            .map_err(db_err)?;
        let seq = self.db.last_insert_rowid();
        Ok(Response::json(
            201,
            format!("{{\"sequence\":{seq},\"duplicate\":false}}"),
        ))
    }

    fn list(&mut self, req: &Request, mailbox: &[u8; 32]) -> Result<Response, Response> {
        let after: i64 = req
            .query("after")
            .map(|v| v.parse())
            .transpose()
            .map_err(|_| Response::error(400, "bad-after"))?
            .unwrap_or(0);
        let limit: u64 = req
            .query("limit")
            .map(|v| v.parse())
            .transpose()
            .map_err(|_| Response::error(400, "bad-limit"))?
            .unwrap_or(self.limits.max_page);
        if limit == 0 || limit > self.limits.max_page || after < 0 {
            return Err(Response::error(400, "bad-page"));
        }
        let mut stmt = self
            .db
            .prepare("SELECT seq, expires_ms, body FROM messages WHERE mailbox=?1 AND seq>?2 ORDER BY seq LIMIT ?3")
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![&mailbox[..], after, limit as i64], |r| {
                Ok(format!(
                    "{{\"sequence\":{},\"expires_ms\":{},\"delivery\":\"{}\"}}",
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    B64.encode(r.get::<_, Vec<u8>>(2)?)
                ))
            })
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;
        Ok(Response::json(
            200,
            format!("{{\"messages\":[{}]}}", rows.join(",")),
        ))
    }

    /// Body: comma-separated decimal sequence numbers. Acknowledgement only
    /// after the client committed its own replay state is a client duty.
    fn acknowledge(&mut self, req: &Request, mailbox: &[u8; 32]) -> Result<Response, Response> {
        let text = std::str::from_utf8(&req.body).map_err(|_| Response::error(400, "bad-ack"))?;
        let seqs: Vec<i64> = text
            .split(',')
            .map(|s| s.trim().parse::<i64>())
            .collect::<Result<_, _>>()
            .map_err(|_| Response::error(400, "bad-ack"))?;
        if seqs.is_empty() || seqs.len() as u64 > self.limits.max_page {
            return Err(Response::error(400, "bad-ack"));
        }
        let tx = self.db.transaction().map_err(db_err)?;
        let mut acked = 0;
        for seq in seqs {
            let moved = tx
                .execute(
                    "INSERT OR IGNORE INTO tombstones(mailbox, upload_token, fingerprint, seq, expires_ms)
                     SELECT mailbox, upload_token, fingerprint, seq, expires_ms FROM messages WHERE mailbox=?1 AND seq=?2",
                    params![&mailbox[..], seq],
                )
                .map_err(db_err)?;
            tx.execute(
                "DELETE FROM messages WHERE mailbox=?1 AND seq=?2",
                params![&mailbox[..], seq],
            )
            .map_err(db_err)?;
            acked += moved;
        }
        tx.commit().map_err(db_err)?;
        Ok(Response::json(200, format!("{{\"acknowledged\":{acked}}}")))
    }

    fn valid_name(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    }

    fn list_objects(&mut self, mailbox: &[u8; 32]) -> Result<Response, Response> {
        let mut stmt = self
            .db
            .prepare("SELECT name, version FROM objects WHERE mailbox=?1 ORDER BY name")
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![&mailbox[..]], |r| {
                Ok(format!(
                    "{{\"name\":\"{}\",\"version\":{}}}",
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?
                ))
            })
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;
        Ok(Response::json(
            200,
            format!("{{\"objects\":[{}]}}", rows.join(",")),
        ))
    }

    fn get_object(&mut self, mailbox: &[u8; 32], name: &str) -> Result<Response, Response> {
        if !Self::valid_name(name) {
            return Err(Response::error(400, "bad-name"));
        }
        let row: Option<(i64, Vec<u8>)> = self
            .db
            .query_row(
                "SELECT version, body FROM objects WHERE mailbox=?1 AND name=?2",
                params![&mailbox[..], name],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db_err)?;
        let (version, body) = row.ok_or(Response::error(404, "not-found"))?;
        Ok(Response {
            status: 200,
            content_type: "application/octet-stream",
            headers: vec![("x-e2ee-version", version.to_string())],
            body,
        })
    }

    /// Compare-and-swap: `x-e2ee-expected-version` 0 creates; otherwise it
    /// must equal the stored version. Conflicts never overwrite.
    fn put_object(
        &mut self,
        req: &Request,
        mailbox: &[u8; 32],
        name: &str,
    ) -> Result<Response, Response> {
        if !Self::valid_name(name) {
            return Err(Response::error(400, "bad-name"));
        }
        if req.body.is_empty() || req.body.len() > self.limits.max_object_bytes {
            return Err(Response::error(413, "bad-object-size"));
        }
        let expected: i64 = req
            .header("x-e2ee-expected-version")
            .and_then(|v| v.parse().ok())
            .filter(|v| *v >= 0)
            .ok_or(Response::error(428, "expected-version-required"))?;
        let tx = self.db.transaction().map_err(db_err)?;
        let current: Option<i64> = tx
            .query_row(
                "SELECT version FROM objects WHERE mailbox=?1 AND name=?2",
                params![&mailbox[..], name],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?;
        if current.unwrap_or(0) != expected {
            return Err(Response::json(
                409,
                format!(
                    "{{\"error\":\"version-conflict\",\"current_version\":{}}}",
                    current.unwrap_or(0)
                ),
            ));
        }
        if current.is_none() {
            let count: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM objects WHERE mailbox=?1",
                    params![&mailbox[..]],
                    |r| r.get(0),
                )
                .map_err(db_err)?;
            if count as u64 >= self.limits.max_objects_per_mailbox {
                return Err(Response::error(429, "object-quota"));
            }
        }
        let next = expected
            .checked_add(1)
            .ok_or(Response::error(409, "version-exhausted"))?;
        tx.execute(
            "INSERT INTO objects(mailbox, name, version, body) VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(mailbox, name) DO UPDATE SET version=excluded.version, body=excluded.body",
            params![&mailbox[..], name, next, &req.body],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        Ok(Response::json(200, format!("{{\"version\":{next}}}")))
    }
}

fn verify(key: &[u8; 32], message: &[u8], sig: &[u8; 64]) -> Option<()> {
    VerifyingKey::from_bytes(key)
        .ok()?
        .verify_strict(message, &Signature::from_bytes(sig))
        .ok()
}

fn db_err(_: rusqlite::Error) -> Response {
    Response::error(500, "storage-error")
}
