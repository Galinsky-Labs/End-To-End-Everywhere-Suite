use e2ee_relay_server::gate::{cookie_value, hmac_sha256, sanitize_next, Decision, Gate};
use e2ee_relay_server::{Request, Response};

const PW: &str = "correct horse";

fn req(method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Request {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    Request {
        method: method.into(),
        path: path.into(),
        query: query
            .split('&')
            .filter(|p| !p.is_empty())
            .map(|p| {
                let (k, v) = p.split_once('=').unwrap_or((p, ""));
                (k.into(), v.into())
            })
            .collect(),
        headers: headers
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect(),
        body: body.as_bytes().to_vec(),
    }
}

fn respond(d: Decision) -> (Response, bool) {
    match d {
        Decision::Respond { response, delay } => (response, delay),
        Decision::Pass { .. } => panic!("expected the gate to respond"),
    }
}

fn header<'a>(r: &'a Response, name: &str) -> Option<&'a str> {
    r.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

const HTML: (&str, &str) = ("Accept", "text/html,application/xhtml+xml");

#[test]
fn hmac_matches_rfc4231_case_2() {
    let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

#[test]
fn gate_off_when_password_unset_or_empty() {
    for pw in [None, Some("")] {
        let mut g = Gate::new(pw, "site");
        assert!(!g.enabled());
        assert_eq!(
            g.check(&req("GET", "/", &[HTML], ""), "1.1.1.1", 0),
            Decision::Pass { robots: false }
        );
        assert_eq!(
            g.check(&req("GET", "/__gate", &[HTML], ""), "1.1.1.1", 0),
            Decision::Pass { robots: false }
        );
    }
}

#[test]
fn health_is_exempt() {
    let mut g = Gate::new(Some(PW), "site");
    assert_eq!(
        g.check(&req("GET", "/healthz", &[], ""), "ip", 0),
        Decision::Pass { robots: true }
    );
}

#[test]
fn html_navigation_redirects_with_next() {
    let mut g = Gate::new(Some(PW), "site");
    let (r, _) = respond(g.check(&req("GET", "/a/b?x=1&y=2", &[HTML], ""), "ip", 0));
    assert_eq!(r.status, 303);
    assert_eq!(
        header(&r, "Location"),
        Some("/__gate?next=/a/b%3Fx%3D1%26y%3D2")
    );
    assert_eq!(header(&r, "X-Robots-Tag"), Some("noindex, nofollow"));
}

#[test]
fn api_and_non_html_requests_get_401_json() {
    let mut g = Gate::new(Some(PW), "site");
    for r in [
        req("GET", "/", &[("Accept", "application/json")], ""),
        req("GET", "/v1/mailboxes/x/messages", &[HTML], ""),
        req("GET", "/api/x", &[HTML], ""),
        req("POST", "/v1/mailboxes", &[HTML], "x"),
    ] {
        let (resp, _) = respond(g.check(&r, "ip", 0));
        assert_eq!(resp.status, 401);
        assert_eq!(resp.content_type, "application/json");
        assert_eq!(resp.body, b"{\"error\":\"site_locked\"}");
    }
}

#[test]
fn valid_cookie_passes_and_invalid_does_not() {
    let mut g = Gate::new(Some(PW), "site");
    let good = format!("other=1; site_gate={}", cookie_value(PW.as_bytes()));
    assert_eq!(
        g.check(&req("GET", "/", &[HTML, ("Cookie", &good)], ""), "ip", 0),
        Decision::Pass { robots: true }
    );
    let stale = format!("site_gate={}", cookie_value(b"old password"));
    for bad in ["site_gate=v1.nope", stale.as_str(), "site_gate="] {
        let (r, _) = respond(g.check(&req("GET", "/", &[HTML, ("Cookie", bad)], ""), "ip", 0));
        assert_eq!(r.status, 303);
    }
}

#[test]
fn form_page_is_private_and_password_manager_friendly() {
    let mut g = Gate::new(Some(PW), "e2ee-relay");
    let (r, _) = respond(g.check(
        &req("GET", "/__gate?next=%2Fx%3F%22%3E", &[HTML], ""),
        "ip",
        0,
    ));
    assert_eq!(r.status, 200);
    let html = String::from_utf8(r.body.clone()).unwrap();
    assert!(html.contains("<title>Private preview</title>"));
    assert!(html.contains("autocomplete=\"current-password\""));
    assert!(html.contains("autocomplete=\"username\" value=\"e2ee-relay\""));
    assert!(html.contains("value=\"/x?&quot;&gt;\""));
    assert_eq!(header(&r, "X-Robots-Tag"), Some("noindex, nofollow"));
}

#[test]
fn correct_password_sets_cookie_and_redirects_to_sanitised_next() {
    let mut g = Gate::new(Some(PW), "site");
    let (r, delay) = respond(g.check(
        &req(
            "POST",
            "/__gate",
            &[],
            "password=correct+horse&next=%2Fdeep%3Fq%3D1",
        ),
        "ip",
        0,
    ));
    assert!(!delay);
    assert_eq!(r.status, 303);
    assert_eq!(header(&r, "Location"), Some("/deep?q=1"));
    let cookie = header(&r, "Set-Cookie").unwrap();
    assert!(cookie.starts_with(&format!("site_gate={};", cookie_value(PW.as_bytes()))));
    for attr in [
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
        "Path=/",
        "Max-Age=34560000",
    ] {
        assert!(cookie.contains(attr), "{attr}");
    }
    let (r, _) = respond(g.check(
        &req(
            "POST",
            "/__gate",
            &[],
            "password=correct+horse&next=//evil.com",
        ),
        "ip2",
        0,
    ));
    assert_eq!(header(&r, "Location"), Some("/"));
}

#[test]
fn wrong_password_is_401_delayed_and_rate_limited() {
    let mut g = Gate::new(Some(PW), "site");
    for _ in 0..10 {
        let (r, delay) = respond(g.check(
            &req("POST", "/__gate", &[], "password=nope&next=/"),
            "ip",
            1_000,
        ));
        assert_eq!(r.status, 401);
        assert!(delay);
        assert!(String::from_utf8(r.body)
            .unwrap()
            .contains("Incorrect password"));
    }
    let (r, _) = respond(g.check(
        &req("POST", "/__gate", &[], "password=correct+horse"),
        "ip",
        2_000,
    ));
    assert_eq!(r.status, 429);
    // Another client is unaffected, and the window expires.
    let (r, _) = respond(g.check(
        &req("POST", "/__gate", &[], "password=correct+horse"),
        "other",
        2_000,
    ));
    assert_eq!(r.status, 303);
    let (r, _) = respond(g.check(
        &req("POST", "/__gate", &[], "password=correct+horse"),
        "ip",
        1_000 + 10 * 60 * 1000,
    ));
    assert_eq!(r.status, 303);
}

#[test]
fn next_sanitising() {
    assert_eq!(sanitize_next("/a?b=c"), "/a?b=c");
    for bad in [
        "//evil.com",
        "/\\evil.com",
        "https://evil.com",
        "javascript:alert(1)",
        "evil",
        "",
        "/a\nb",
    ] {
        assert_eq!(sanitize_next(bad), "/", "{bad}");
    }
}
