use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use e2ee_capsule::CapsuleLimits;
use e2ee_message::{encrypt_text, generate_recipient_keypair, RecipientPublicKey};
use e2ee_provenance::{sign_capsule, CapsuleSigningKey};
use e2ee_relay_server::{mailbox_id, signing_input, Limits, Request, Response, Server};
use e2ee_transport::Delivery;
use ed25519_dalek::{Signer, SigningKey};

const NOW: u64 = 1_800_000_000_000;

struct Owner {
    key: SigningKey,
    mailbox: [u8; 32],
    nonce: u8,
}

impl Owner {
    fn new(seed: u8) -> Self {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let mailbox = mailbox_id(&key.verifying_key().to_bytes());
        Self {
            key,
            mailbox,
            nonce: 0,
        }
    }
    fn id(&self) -> String {
        B64.encode(self.mailbox)
    }
    fn signed(&mut self, method: &str, path: &str, body: Vec<u8>, ts: u64) -> Request {
        self.nonce += 1;
        let nonce = [self.nonce; 16];
        let sig = self.key.sign(&signing_input(
            method,
            path,
            &self.mailbox,
            ts,
            &nonce,
            &body,
        ));
        Request {
            method: method.into(),
            path: path.into(),
            query: vec![],
            headers: vec![
                ("X-E2EE-Timestamp".into(), ts.to_string()),
                ("X-E2EE-Nonce".into(), B64.encode(nonce)),
                ("X-E2EE-Signature".into(), B64.encode(sig.to_bytes())),
            ],
            body,
        }
    }
}

fn server() -> Server {
    Server::open(":memory:", Limits::default()).unwrap()
}

fn json(r: &Response) -> String {
    String::from_utf8(r.body.clone()).unwrap()
}

fn field<'a>(body: &'a str, name: &str) -> &'a str {
    let start = body.find(&format!("\"{name}\":\"")).unwrap() + name.len() + 4;
    &body[start..start + body[start..].find('"').unwrap()]
}

fn register(s: &mut Server, o: &mut Owner) {
    let pk = o.key.verifying_key().to_bytes().to_vec();
    let req = o.signed("POST", "/v1/mailboxes", pk, NOW);
    let r = s.handle(&req, NOW);
    assert_eq!(r.status, 201, "{}", json(&r));
    assert_eq!(field(&json(&r), "mailbox"), o.id());
}

fn capability(s: &mut Server, o: &mut Owner) -> String {
    let path = format!("/v1/mailboxes/{}/capabilities", o.id());
    let r = s.handle(&o.signed("POST", &path, vec![], NOW), NOW);
    assert_eq!(r.status, 201, "{}", json(&r));
    field(&json(&r), "token").to_owned()
}

fn delivery(text: &str) -> Vec<u8> {
    let receiver = generate_recipient_keypair();
    let capsule = encrypt_text(
        &RecipientPublicKey {
            recipient_hint: vec![1; 16],
            encoded_public_key: receiver.public_key,
        },
        text,
        None,
    )
    .unwrap();
    let signer = CapsuleSigningKey::generate().unwrap();
    Delivery {
        signature: Some(
            sign_capsule(&signer, &capsule, "relay-test", CapsuleLimits::default()).unwrap(),
        ),
        capsule,
    }
    .encode(CapsuleLimits::default())
    .unwrap()
}

fn send(s: &mut Server, mailbox: &str, cap: &str, token: u8, body: Vec<u8>) -> Response {
    s.handle(
        &Request {
            method: "POST".into(),
            path: format!("/v1/mailboxes/{mailbox}/messages"),
            query: vec![],
            headers: vec![
                ("X-E2EE-Capability".into(), cap.into()),
                ("X-E2EE-Upload-Token".into(), B64.encode([token; 16])),
            ],
            body,
        },
        NOW,
    )
}

#[test]
fn signed_delivery_round_trip_with_idempotent_retry_and_post_ack_tombstone() {
    let mut s = server();
    let mut bob = Owner::new(7);
    register(&mut s, &mut bob);
    let cap = capability(&mut s, &mut bob);
    let d = delivery("hello");
    assert_eq!(send(&mut s, &bob.id(), &cap, 1, d.clone()).status, 201);
    let retry = send(&mut s, &bob.id(), &cap, 1, d.clone());
    assert_eq!(retry.status, 200);
    assert!(json(&retry).contains("\"duplicate\":true"));
    assert_eq!(
        send(&mut s, &bob.id(), &cap, 1, delivery("other")).status,
        409
    );

    let path = format!("/v1/mailboxes/{}/messages", bob.id());
    let list = s.handle(&bob.signed("GET", &path, vec![], NOW), NOW);
    assert_eq!(list.status, 200);
    assert!(json(&list).contains(&B64.encode(&d)));

    let ack_path = format!("/v1/mailboxes/{}/acks", bob.id());
    let ack = s.handle(&bob.signed("POST", &ack_path, b"1".to_vec(), NOW), NOW);
    assert!(json(&ack).contains("\"acknowledged\":1"));
    // A late retry after acknowledgement is recognised, not re-queued.
    assert_eq!(send(&mut s, &bob.id(), &cap, 1, d).status, 200);
    let list = s.handle(&bob.signed("GET", &path, vec![], NOW), NOW);
    assert_eq!(json(&list), "{\"messages\":[]}");
}

#[test]
fn delivery_requires_valid_unrevoked_capability_and_signed_canonical_framing() {
    let mut s = server();
    let mut bob = Owner::new(7);
    let mut eve = Owner::new(9);
    register(&mut s, &mut bob);
    register(&mut s, &mut eve);
    let cap = capability(&mut s, &mut bob);
    let eve_cap = capability(&mut s, &mut eve);
    assert_eq!(
        send(&mut s, &bob.id(), &B64.encode([5u8; 32]), 1, delivery("x")).status,
        403
    );
    // A capability for another mailbox does not authorise delivery here.
    assert_eq!(
        send(&mut s, &bob.id(), &eve_cap, 1, delivery("x")).status,
        403
    );
    assert_eq!(
        send(&mut s, &bob.id(), &cap, 1, b"not a delivery".to_vec()).status,
        400
    );
    let mut unsigned = Delivery::decode(&delivery("x"), CapsuleLimits::default()).unwrap();
    unsigned.signature = None;
    let unsigned = unsigned.encode(CapsuleLimits::default()).unwrap();
    assert_eq!(
        json(&send(&mut s, &bob.id(), &cap, 2, unsigned)),
        "{\"error\":\"unsigned-delivery\"}"
    );

    // Revocation stops further delivery.
    let path = format!("/v1/mailboxes/{}/capabilities", bob.id());
    let issued = s.handle(&bob.signed("POST", &path, vec![], NOW), NOW);
    let (id, tok) = (
        field(&json(&issued), "id").to_owned(),
        field(&json(&issued), "token").to_owned(),
    );
    assert_eq!(send(&mut s, &bob.id(), &tok, 3, delivery("y")).status, 201);
    let del = s.handle(
        &bob.signed("DELETE", &format!("{path}/{id}"), vec![], NOW),
        NOW,
    );
    assert!(json(&del).contains("true"));
    assert_eq!(send(&mut s, &bob.id(), &tok, 4, delivery("z")).status, 403);
}

#[test]
fn owner_requests_reject_forgery_replay_skew_and_foreign_keys() {
    let mut s = server();
    let mut bob = Owner::new(7);
    let mut eve = Owner::new(9);
    register(&mut s, &mut bob);
    register(&mut s, &mut eve);
    let path = format!("/v1/mailboxes/{}/messages", bob.id());
    let good = bob.signed("GET", &path, vec![], NOW);
    assert_eq!(s.handle(&good, NOW).status, 200);
    assert_eq!(
        json(&s.handle(&good, NOW)),
        "{\"error\":\"replayed-request\"}"
    );
    // Eve signs a request for Bob's mailbox with her own key.
    let mut forged = eve.signed("GET", &path, vec![], NOW);
    forged.path = path.clone();
    assert_eq!(s.handle(&forged, NOW).status, 401);
    // Changing the path after signing breaks the signature.
    let mut moved = bob.signed("GET", &path, vec![], NOW);
    moved.path = format!("/v1/mailboxes/{}/objects", bob.id());
    assert_eq!(s.handle(&moved, NOW).status, 401);
    let stale = bob.signed("GET", &path, vec![], NOW - 10 * 60 * 1000);
    assert_eq!(s.handle(&stale, NOW).status, 401);
    // Unregistered mailbox cannot authenticate.
    let mut ghost = Owner::new(3);
    let gpath = format!("/v1/mailboxes/{}/messages", ghost.id());
    assert_eq!(
        s.handle(&ghost.signed("GET", &gpath, vec![], NOW), NOW)
            .status,
        401
    );
}

#[test]
fn registration_requires_proof_of_possession() {
    let mut s = server();
    let mut bob = Owner::new(7);
    let eve = Owner::new(9);
    let mut req = bob.signed(
        "POST",
        "/v1/mailboxes",
        bob.key.verifying_key().to_bytes().to_vec(),
        NOW,
    );
    req.body = eve.key.verifying_key().to_bytes().to_vec();
    assert_eq!(s.handle(&req, NOW).status, 401);
}

#[test]
fn sync_objects_use_compare_and_swap_and_never_overwrite_on_conflict() {
    let mut s = server();
    let mut bob = Owner::new(7);
    register(&mut s, &mut bob);
    let path = format!("/v1/mailboxes/{}/objects/contacts.v1", bob.id());
    let put = |o: &mut Owner, s: &mut Server, expected: &str, body: &[u8]| {
        let mut r = o.signed("PUT", &path, body.to_vec(), NOW);
        r.headers
            .push(("X-E2EE-Expected-Version".into(), expected.into()));
        s.handle(&r, NOW)
    };
    assert_eq!(
        json(&put(&mut bob, &mut s, "0", b"ciphertext-a")),
        "{\"version\":1}"
    );
    // A second device that also believed version 0 gets a conflict.
    let conflict = put(&mut bob, &mut s, "0", b"ciphertext-b");
    assert_eq!(conflict.status, 409);
    assert!(json(&conflict).contains("\"current_version\":1"));
    assert_eq!(
        json(&put(&mut bob, &mut s, "1", b"ciphertext-c")),
        "{\"version\":2}"
    );
    let got = s.handle(&bob.signed("GET", &path, vec![], NOW), NOW);
    assert_eq!(got.body, b"ciphertext-c");
    assert!(got.headers.contains(&("x-e2ee-version", "2".into())));
    // Missing expected version is refused rather than treated as overwrite.
    let blind = s.handle(&bob.signed("PUT", &path, b"x".to_vec(), NOW), NOW);
    assert_eq!(blind.status, 428);
}

#[test]
fn messages_expire_and_state_survives_reopen() {
    let dir = std::env::temp_dir().join(format!("e2ee-relay-{}-{}", std::process::id(), NOW));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("relay.sqlite3");
    let db = db.to_str().unwrap();
    let mut bob = Owner::new(7);
    let cap;
    {
        let mut s = Server::open(db, Limits::default()).unwrap();
        register(&mut s, &mut bob);
        cap = capability(&mut s, &mut bob);
        let mut r = Request {
            method: "POST".into(),
            path: format!("/v1/mailboxes/{}/messages", bob.id()),
            query: vec![],
            headers: vec![
                ("X-E2EE-Capability".into(), cap.clone()),
                ("X-E2EE-Upload-Token".into(), B64.encode([1u8; 16])),
                ("X-E2EE-Retention-Ms".into(), "1000".into()),
            ],
            body: delivery("short-lived"),
        };
        assert_eq!(s.handle(&r, NOW).status, 201);
        r.headers[2].1 = "0".into();
        assert_eq!(s.handle(&r, NOW).status, 400);
    }
    let mut s = Server::open(db, Limits::default()).unwrap();
    let path = format!("/v1/mailboxes/{}/messages", bob.id());
    // Durable across reopen; the replay nonce store is durable too.
    let req = bob.signed("GET", &path, vec![], NOW + 10);
    assert!(json(&s.handle(&req, NOW + 10)).contains("\"sequence\":1"));
    let mut s2 = Server::open(db, Limits::default()).unwrap();
    assert_eq!(s2.handle(&req, NOW + 20).status, 401);
    drop(s2);
    let later = bob.signed("GET", &path, vec![], NOW + 2000);
    assert_eq!(json(&s.handle(&later, NOW + 2000)), "{\"messages\":[]}");
    std::fs::remove_dir_all(&dir).ok();
}
