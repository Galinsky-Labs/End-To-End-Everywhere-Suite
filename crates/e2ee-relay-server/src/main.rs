//! HTTP front end for the relay/sync server. TLS is terminated by the hosting
//! platform; this process only ever handles ciphertext and signed requests.
use e2ee_relay_server::{Limits, Request, Server};
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn main() {
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".into());
    let db = std::env::var("RELAY_DB_PATH").unwrap_or_else(|_| "relay.sqlite3".into());
    let limits = Limits::default();
    let mut server = Server::open(&db, limits).expect("open relay database");
    let http = tiny_http::Server::http(format!("0.0.0.0:{port}")).expect("bind HTTP listener");
    eprintln!("e2ee-relay-server listening on port {port} (database {db})");
    for mut incoming in http.incoming_requests() {
        let url = incoming.url().to_owned();
        let (path, query) = url.split_once('?').unwrap_or((url.as_str(), ""));
        let query = query
            .split('&')
            .filter(|p| !p.is_empty())
            .map(|p| {
                let (k, v) = p.split_once('=').unwrap_or((p, ""));
                (k.to_owned(), v.to_owned())
            })
            .collect();
        let headers = incoming
            .headers()
            .iter()
            .map(|h| {
                (
                    h.field.as_str().as_str().to_owned(),
                    h.value.as_str().to_owned(),
                )
            })
            .collect();
        let mut body = Vec::new();
        let read = incoming
            .as_reader()
            .take(limits.max_body_bytes as u64 + 1)
            .read_to_end(&mut body);
        let response = if read.is_err() {
            None
        } else {
            Some(server.handle(
                &Request {
                    method: incoming.method().as_str().to_owned(),
                    path: path.to_owned(),
                    query,
                    headers,
                    body,
                },
                now_ms(),
            ))
        };
        let reply = match response {
            Some(r) => {
                let mut out = tiny_http::Response::from_data(r.body).with_status_code(r.status);
                for (k, v) in std::iter::once(("Content-Type", r.content_type.to_owned()))
                    .chain(r.headers)
                    .chain([("Cache-Control", "no-store".to_owned())])
                {
                    if let Ok(h) = tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()) {
                        out.add_header(h);
                    }
                }
                out
            }
            None => tiny_http::Response::from_data(b"{\"error\":\"bad-request\"}".to_vec())
                .with_status_code(400),
        };
        let _ = incoming.respond(reply);
    }
}
