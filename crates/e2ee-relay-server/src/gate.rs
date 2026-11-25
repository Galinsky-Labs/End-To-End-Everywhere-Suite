//! Pre-launch password gate (owner-approved, temporary).
//!
//! Controlled only by the `SITE_PASSWORD` environment variable: when it is unset
//! or empty the gate is off and nothing changes. When it is set, every request
//! needs a `site_gate` cookie except the Render health check (`/healthz`) and
//! the gate's own `/__gate` routes. The cookie value is
//! `v1.` + base64url(HMAC-SHA256(key = SITE_PASSWORD, msg = "site-gate-v1")),
//! so changing the password invalidates every cookie and no server state is kept.
//!
//! The gate sits in front of the relay's own Ed25519 request authentication; it
//! never replaces it.

use crate::{Request, Response};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const COOKIE_NAME: &str = "site_gate";
pub const GATE_PATH: &str = "/__gate";
pub const HEALTH_PATH: &str = "/healthz";
const COOKIE_MSG: &[u8] = b"site-gate-v1";
const COOKIE_MAX_AGE: u64 = 34_560_000;
const MAX_TRIES: usize = 10;
const TRY_WINDOW_MS: u64 = 10 * 60 * 1000;
const ROBOTS: &str = "noindex, nofollow";

/// What the HTTP front end must do with a request.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// Pass the request to the application. `robots` asks the caller to add
    /// `X-Robots-Tag: noindex, nofollow` to the application's response.
    Pass { robots: bool },
    /// Answer with this response; `delay` asks for the ~500 ms failure delay.
    Respond { response: Response, delay: bool },
}

pub struct Gate {
    password: Option<Vec<u8>>,
    site_name: String,
    tries: HashMap<String, Vec<u64>>,
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|b| b ^ 0x36));
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(block.map(|b| b ^ 0x5c));
    outer.update(inner);
    outer.finalize().into()
}

/// Constant-time equality for equal-length inputs (length is not secret).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Expected cookie value for a password.
pub fn cookie_value(password: &[u8]) -> String {
    format!("v1.{}", B64.encode(hmac_sha256(password, COOKIE_MSG)))
}

/// Keep `next` only if it is a same-site relative path (single leading `/`).
pub fn sanitize_next(next: &str) -> String {
    let ok = next.starts_with('/')
        && !next.starts_with("//")
        && !next.contains('\\')
        && !next.chars().any(|c| c.is_control());
    if ok {
        next.to_owned()
    } else {
        "/".to_owned()
    }
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = |c: u8| (c as char).to_digit(16);
                match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 2;
                    }
                    _ => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn percent_encode(text: &str) -> String {
    text.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn form_field(pairs: &str, name: &str) -> Option<String> {
    pairs.split('&').find_map(|p| {
        let (k, v) = p.split_once('=').unwrap_or((p, ""));
        (percent_decode(k) == name).then(|| percent_decode(v))
    })
}

impl Gate {
    /// Reads `SITE_PASSWORD`; empty or unset turns the gate off.
    pub fn from_env(site_name: &str) -> Self {
        Self::new(std::env::var("SITE_PASSWORD").ok().as_deref(), site_name)
    }

    pub fn new(password: Option<&str>, site_name: &str) -> Self {
        Self {
            password: password
                .filter(|p| !p.is_empty())
                .map(|p| p.as_bytes().to_vec()),
            site_name: site_name.to_owned(),
            tries: HashMap::new(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.password.is_some()
    }

    fn has_valid_cookie(&self, password: &[u8], req: &Request) -> bool {
        let expected = cookie_value(password);
        req.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("cookie"))
            .flat_map(|(_, v)| v.split(';'))
            .filter_map(|c| c.trim().split_once('='))
            .any(|(k, v)| k == COOKIE_NAME && ct_eq(v.as_bytes(), expected.as_bytes()))
    }

    /// `client` identifies the caller for the in-memory attempt limit.
    pub fn check(&mut self, req: &Request, client: &str, now_ms: u64) -> Decision {
        let Some(password) = self.password.clone() else {
            return Decision::Pass { robots: false };
        };
        if req.path == HEALTH_PATH {
            return Decision::Pass { robots: true };
        }
        if req.path == GATE_PATH {
            return match req.method.as_str() {
                "GET" | "HEAD" => {
                    let next = req
                        .query
                        .iter()
                        .find(|(k, _)| k == "next")
                        .map(|(_, v)| percent_decode(v))
                        .unwrap_or_else(|| "/".into());
                    Decision::Respond {
                        response: self.form(200, &sanitize_next(&next), false),
                        delay: false,
                    }
                }
                "POST" => self.submit(&password, req, client, now_ms),
                _ => Decision::Respond {
                    response: locked(405, "method_not_allowed"),
                    delay: false,
                },
            };
        }
        if self.has_valid_cookie(&password, req) {
            return Decision::Pass { robots: true };
        }
        let accepts_html = req
            .header("accept")
            .is_some_and(|a| a.to_ascii_lowercase().contains("text/html"));
        let api = ["/api", "/v1"]
            .iter()
            .any(|p| req.path == *p || req.path.starts_with(&format!("{p}/")));
        if matches!(req.method.as_str(), "GET" | "HEAD") && accepts_html && !api {
            let mut original = req.path.clone();
            let query: Vec<String> = req.query.iter().map(|(k, v)| format!("{k}={v}")).collect();
            if !query.is_empty() {
                original.push('?');
                original.push_str(&query.join("&"));
            }
            let next = sanitize_next(&original);
            return Decision::Respond {
                response: Response {
                    status: 303,
                    content_type: "text/plain; charset=utf-8",
                    headers: vec![
                        (
                            "Location",
                            format!("{GATE_PATH}?next={}", percent_encode(&next)),
                        ),
                        ("X-Robots-Tag", ROBOTS.into()),
                    ],
                    body: Vec::new(),
                },
                delay: false,
            };
        }
        Decision::Respond {
            response: locked(401, "site_locked"),
            delay: false,
        }
    }

    fn submit(&mut self, password: &[u8], req: &Request, client: &str, now: u64) -> Decision {
        if self.tries.len() > 10_000 {
            self.tries
                .retain(|_, t| t.iter().any(|s| now.saturating_sub(*s) < TRY_WINDOW_MS));
        }
        let tries = self.tries.entry(client.to_owned()).or_default();
        tries.retain(|t| now.saturating_sub(*t) < TRY_WINDOW_MS);
        if tries.len() >= MAX_TRIES {
            return Decision::Respond {
                response: locked(429, "too_many_attempts"),
                delay: false,
            };
        }
        tries.push(now);
        let body = String::from_utf8_lossy(&req.body);
        let given = form_field(&body, "password").unwrap_or_default();
        let next = sanitize_next(&form_field(&body, "next").unwrap_or_else(|| "/".into()));
        // Compare fixed-length digests so the comparison time does not depend on
        // where (or whether) the inputs differ, nor on the password length.
        let ok = ct_eq(
            &hmac_sha256(b"site-gate-compare", given.as_bytes()),
            &hmac_sha256(b"site-gate-compare", password),
        );
        if ok {
            Decision::Respond {
                response: Response {
                    status: 303,
                    content_type: "text/plain; charset=utf-8",
                    headers: vec![
                        ("Location", next),
                        (
                            "Set-Cookie",
                            format!(
                                "{COOKIE_NAME}={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={COOKIE_MAX_AGE}",
                                cookie_value(password)
                            ),
                        ),
                        ("X-Robots-Tag", ROBOTS.into()),
                    ],
                    body: Vec::new(),
                },
                delay: false,
            }
        } else {
            Decision::Respond {
                response: self.form(401, &next, true),
                delay: true,
            }
        }
    }

    fn form(&self, status: u16, next: &str, failed: bool) -> Response {
        let error = if failed {
            "<p class=\"err\" role=\"alert\">Incorrect password</p>"
        } else {
            ""
        };
        let body = format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<meta name=\"robots\" content=\"noindex,nofollow\"><title>Private preview</title>\
<style>body{{font-family:system-ui,sans-serif;background:#f6f6f4;color:#1a1a1a;display:grid;place-items:center;min-height:100vh;margin:0;padding:16px;box-sizing:border-box}}\
main{{background:#fff;border:1px solid #ddd;border-radius:8px;padding:24px;width:100%;max-width:340px}}\
h1{{font-size:1.25rem;margin:0 0 12px}}label{{display:block;margin:12px 0 4px}}\
input[type=password]{{width:100%;box-sizing:border-box;padding:8px;font-size:1rem}}\
button{{margin-top:16px;padding:8px 16px;font-size:1rem}}.err{{color:#a00000}}.vh{{position:absolute;left:-9999px}}\
@media (prefers-color-scheme:dark){{body{{background:#161616;color:#eee}}main{{background:#222;border-color:#444}}.err{{color:#ff8a8a}}}}</style>\
</head><body><main><h1>Private preview</h1><p>This site is not public yet.</p>{error}\
<form method=\"post\" action=\"{GATE_PATH}\">\
<input class=\"vh\" type=\"text\" name=\"username\" autocomplete=\"username\" value=\"{site}\" tabindex=\"-1\" aria-hidden=\"true\">\
<input type=\"hidden\" name=\"next\" value=\"{next}\">\
<label for=\"password\">Password</label>\
<input id=\"password\" type=\"password\" name=\"password\" autocomplete=\"current-password\" required autofocus>\
<button type=\"submit\">Continue</button></form></main></body></html>",
            site = html_escape(&self.site_name),
            next = html_escape(next),
        );
        Response {
            status,
            content_type: "text/html; charset=utf-8",
            headers: vec![("X-Robots-Tag", ROBOTS.into())],
            body: body.into_bytes(),
        }
    }
}

fn locked(status: u16, code: &str) -> Response {
    Response {
        status,
        content_type: "application/json",
        headers: vec![("X-Robots-Tag", ROBOTS.into())],
        body: format!("{{\"error\":\"{code}\"}}").into_bytes(),
    }
}
