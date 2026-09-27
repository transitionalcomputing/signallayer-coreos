use super::*;
use crate::sessions::{tests::TestClock, KernelRandom, IDLE_TIMEOUT};
use axum::http::{Method, Request as HttpRequest};
use std::sync::Mutex;
use tower_service::Service;
use zbus::export::async_trait::async_trait;

const PASSWORD: &str = "correct horse battery";
const LOCAL_V4: &str = "192.0.2.10:8443";
const PEER_V4: &str = "192.0.2.77:51000";

#[derive(Default)]
struct FakeAuth {
    calls: Mutex<Vec<&'static str>>,
    verify: Mutex<Option<AuthFailure>>,
    pairing: Mutex<Option<AuthFailure>>,
    confirm: Mutex<Option<AuthFailure>>,
}

#[async_trait]
impl Auth for FakeAuth {
    async fn verify_password(&self, password: String) -> Result<(), AuthFailure> {
        self.calls.lock().unwrap().push("VerifyPassword");
        match *self.verify.lock().unwrap() {
            Some(failure) => Err(failure),
            None if password == PASSWORD => Ok(()),
            None => Err(AuthFailure::InvalidCredential),
        }
    }

    async fn consume_pairing(&self, _: String, _: String) -> Result<String, AuthFailure> {
        self.calls.lock().unwrap().push("ConsumePairing");
        let mut pairing = self.pairing.lock().unwrap();
        match *pairing {
            Some(failure) => Err(failure),
            None => {
                // sl-authd returns the key once; later calls find no pairing.
                *pairing = Some(AuthFailure::NoPendingPairing);
                Ok("04HMASW9NF6YZZPWQAC7CN1J20".into())
            }
        }
    }

    async fn confirm_recovery_key(&self, _: String) -> Result<(), AuthFailure> {
        self.calls.lock().unwrap().push("ConfirmRecoveryKey");
        match *self.confirm.lock().unwrap() {
            Some(failure) => Err(failure),
            None => Ok(()),
        }
    }
}

struct FakeStatus(Mutex<Result<String, ()>>);

#[async_trait]
impl StatusSource for FakeStatus {
    async fn status(&self) -> Result<String, ()> {
        self.0.lock().unwrap().clone()
    }
}

struct Harness {
    router: Router,
    auth: Arc<FakeAuth>,
    status: Arc<FakeStatus>,
    clock: TestClock,
    local: SocketAddr,
}

impl Harness {
    fn new() -> Self {
        Self::at(LOCAL_V4)
    }

    fn at(local: &str) -> Self {
        let auth = Arc::new(FakeAuth::default());
        let status = Arc::new(FakeStatus(Mutex::new(Ok(
            r#"{"schema_version":"0.4"}"#.into()
        ))));
        let clock = TestClock::default();
        let router = router(AppState {
            auth: auth.clone(),
            status: status.clone(),
            sessions: Arc::new(Sessions::new(clock.clone(), KernelRandom)),
        });
        Self {
            router,
            auth,
            status,
            clock,
            local: local.parse().unwrap(),
        }
    }

    fn endpoint(&self) -> String {
        endpoint(self.local)
    }

    fn origin(&self) -> String {
        format!("https://{}", self.endpoint())
    }

    /// A request as the connection layer delivers it, with the right Host.
    fn request(&self, method: Method, path: &str) -> axum::http::request::Builder {
        HttpRequest::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, self.endpoint())
            .extension(ConnInfo {
                local: self.local,
                peer: PEER_V4.parse().unwrap(),
            })
    }

    fn post_json(&self, path: &str, body: &str) -> HttpRequest<Body> {
        self.request(Method::POST, path)
            .header(header::ORIGIN, self.origin())
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap()
    }

    async fn send(&self, request: HttpRequest<Body>) -> (StatusCode, HeaderMap, String) {
        let response = self.router.clone().call(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, headers, String::from_utf8_lossy(&body).into_owned())
    }

    fn calls(&self) -> Vec<&'static str> {
        self.auth.calls.lock().unwrap().clone()
    }

    async fn login(&self) -> String {
        let (status, headers, _) = self
            .send(self.post_json("/api/v1/login", &format!(r#"{{"password":"{PASSWORD}"}}"#)))
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let cookie = headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
        cookie
            .split(';')
            .next()
            .unwrap()
            .strip_prefix("__Host-sl_session=")
            .unwrap()
            .to_owned()
    }

    fn status_request(&self, cookie: Option<&str>) -> HttpRequest<Body> {
        let mut builder = self.request(Method::GET, "/api/v1/status");
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        builder.body(Body::empty()).unwrap()
    }
}

fn error_code(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body).unwrap()["error"]
        .as_str()
        .unwrap()
        .to_owned()
}

// Host.

#[tokio::test]
async fn host_must_be_the_accepting_endpoint_exactly() {
    let harness = Harness::new();
    let (status, _, _) = harness
        .send(
            harness
                .request(Method::GET, "/")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    for host in [
        "192.0.2.11:8443",
        "192.0.2.10",
        "192.0.2.10:443",
        "remote.example:8443",
        "192.0.2.10:8443.",
        " 192.0.2.10:8443",
    ] {
        let request = HttpRequest::builder()
            .uri("/")
            .header(header::HOST, host)
            .extension(ConnInfo {
                local: harness.local,
                peer: PEER_V4.parse().unwrap(),
            })
            .body(Body::empty())
            .unwrap();
        let (status, _, body) = harness.send(request).await;
        assert_eq!(status, StatusCode::MISDIRECTED_REQUEST, "{host}");
        assert_eq!(error_code(&body), "misdirected");
    }
    // Missing and duplicated Host headers.
    let request = HttpRequest::builder()
        .uri("/")
        .extension(ConnInfo {
            local: harness.local,
            peer: PEER_V4.parse().unwrap(),
        })
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        harness.send(request).await.0,
        StatusCode::MISDIRECTED_REQUEST
    );
    let request = harness
        .request(Method::GET, "/")
        .header(header::HOST, harness.endpoint())
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        harness.send(request).await.0,
        StatusCode::MISDIRECTED_REQUEST
    );
    // An absolute-form URI naming another authority.
    let request = harness
        .request(Method::GET, "https://192.0.2.11:8443/")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        harness.send(request).await.0,
        StatusCode::MISDIRECTED_REQUEST
    );
    // No connection information at all.
    let request = HttpRequest::builder()
        .uri("/")
        .header(header::HOST, harness.endpoint())
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        harness.send(request).await.0,
        StatusCode::MISDIRECTED_REQUEST
    );
}

#[tokio::test]
async fn ipv6_host_is_the_canonical_bracketed_endpoint() {
    let harness = Harness::at("[2001:db8::10]:8443");
    assert_eq!(harness.endpoint(), "[2001:db8::10]:8443");
    let (status, _, _) = harness
        .send(
            harness
                .request(Method::GET, "/")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    for host in [
        "[2001:db8:0::10]:8443",
        "2001:db8::10:8443",
        "[2001:DB8::10]:8443",
    ] {
        let request = HttpRequest::builder()
            .uri("/")
            .header(header::HOST, host)
            .extension(ConnInfo {
                local: harness.local,
                peer: "[2001:db8::77]:51000".parse().unwrap(),
            })
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            harness.send(request).await.0,
            StatusCode::MISDIRECTED_REQUEST,
            "{host}"
        );
    }
    // Origin is the bracketed endpoint too.
    let (status, _, _) = harness
        .send(harness.post_json("/api/v1/login", &format!(r#"{{"password":"{PASSWORD}"}}"#)))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(harness.origin(), "https://[2001:db8::10]:8443");
}

// Headers and routes.

#[tokio::test]
async fn every_response_carries_the_security_headers() {
    let harness = Harness::new();
    for request in [
        harness
            .request(Method::GET, "/")
            .body(Body::empty())
            .unwrap(),
        harness
            .request(Method::GET, "/nope")
            .body(Body::empty())
            .unwrap(),
        harness.status_request(None),
    ] {
        let (_, headers, _) = harness.send(request).await;
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(headers[header::REFERRER_POLICY], "no-referrer");
        assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY");
        assert!(headers[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .starts_with("default-src 'self'"));
    }
}

#[tokio::test]
async fn bundled_assets_reference_nothing_external() {
    let harness = Harness::new();
    for (path, content_type) in [
        ("/", "text/html; charset=utf-8"),
        ("/app.js", "text/javascript; charset=utf-8"),
        ("/app.css", "text/css; charset=utf-8"),
    ] {
        let (status, headers, body) = harness
            .send(
                harness
                    .request(Method::GET, path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(headers[header::CONTENT_TYPE], content_type);
        assert!(
            !body.contains("http://") && !body.contains("https://"),
            "{path}"
        );
        assert!(
            !body.contains("//cdn") && !body.contains("<script>"),
            "{path}"
        );
    }
}

#[tokio::test]
async fn the_api_is_read_only_and_exactly_the_documented_routes() {
    let harness = Harness::new();
    for path in [
        "/api/v1/reboot",
        "/api/v1/update",
        "/api/v1/rollback",
        "/api/v1/enable",
        "/api/v1/disable",
        "/api/v1/reenroll",
        "/api/v1/recover",
        "/api/v1/sessions",
        "/api/v2/status",
        "/static/app.js",
    ] {
        for method in [Method::GET, Method::POST, Method::PUT, Method::DELETE] {
            let request = harness
                .request(method.clone(), path)
                .header(header::ORIGIN, harness.origin())
                .body(Body::empty())
                .unwrap();
            let (status, _, body) = harness.send(request).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}");
            assert_eq!(error_code(&body), "not_found");
        }
    }
    for (method, path) in [
        (Method::POST, "/api/v1/status"),
        (Method::GET, "/api/v1/login"),
        (Method::GET, "/api/v1/pair"),
        (Method::PUT, "/api/v1/logout"),
        (Method::DELETE, "/"),
        (Method::POST, "/app.js"),
    ] {
        let request = harness
            .request(method.clone(), path)
            .body(Body::empty())
            .unwrap();
        let (status, _, body) = harness.send(request).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method} {path}");
        assert_eq!(error_code(&body), "method_not_allowed");
    }
    assert!(harness.calls().is_empty());
}

// Origin.

#[tokio::test]
async fn state_changing_routes_require_the_exact_origin() {
    let harness = Harness::new();
    let bodies = [
        (
            "/api/v1/pair",
            r#"{"pairing_code":"04HMASW9","password":"correct horse battery"}"#,
        ),
        (
            "/api/v1/confirm",
            r#"{"recovery_key":"04HMASW9NF6YZZPWQAC7CN1J20"}"#,
        ),
        ("/api/v1/login", r#"{"password":"correct horse battery"}"#),
        ("/api/v1/logout", ""),
    ];
    for (path, body) in bodies {
        for origin in [
            None,
            Some("http://192.0.2.10:8443"),
            Some("https://192.0.2.10"),
            Some("https://192.0.2.11:8443"),
            Some("https://192.0.2.10:8443/"),
            Some("https://remote.example:8443"),
            Some("null"),
        ] {
            let mut builder = harness
                .request(Method::POST, path)
                .header(header::CONTENT_TYPE, "application/json");
            if let Some(origin) = origin {
                builder = builder.header(header::ORIGIN, origin);
            }
            let (status, _, response) = harness.send(builder.body(Body::from(body)).unwrap()).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path} {origin:?}");
            assert_eq!(error_code(&response), "forbidden_origin");
        }
        // Two Origin headers, even if one matches.
        let request = harness
            .request(Method::POST, path)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, harness.origin())
            .header(header::ORIGIN, "https://192.0.2.11:8443")
            .body(Body::from(body))
            .unwrap();
        assert_eq!(
            harness.send(request).await.0,
            StatusCode::FORBIDDEN,
            "{path}"
        );
    }
    assert!(harness.calls().is_empty(), "sl-authd is never reached");
}

#[tokio::test]
async fn read_only_gets_do_not_need_origin() {
    let harness = Harness::new();
    let id = harness.login().await;
    let request = harness.status_request(Some(&format!("__Host-sl_session={id}")));
    assert!(request.headers().get(header::ORIGIN).is_none());
    assert_eq!(harness.send(request).await.0, StatusCode::OK);
}

// Bodies and bounds.

#[tokio::test]
async fn content_type_must_be_json() {
    let harness = Harness::new();
    for content_type in [
        None,
        Some("text/plain"),
        Some("application/json; charset=latin1"),
        Some("application/x-www-form-urlencoded"),
        Some("multipart/form-data"),
    ] {
        let mut builder = harness
            .request(Method::POST, "/api/v1/login")
            .header(header::ORIGIN, harness.origin());
        if let Some(content_type) = content_type {
            builder = builder.header(header::CONTENT_TYPE, content_type);
        }
        let (status, _, body) = harness
            .send(builder.body(Body::from(r#"{"password":"x"}"#)).unwrap())
            .await;
        assert_eq!(
            status,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{content_type:?}"
        );
        assert_eq!(error_code(&body), "unsupported_media_type");
    }
    let (status, _, _) = harness
        .send(
            harness
                .request(Method::POST, "/api/v1/login")
                .header(header::ORIGIN, harness.origin())
                .header(header::CONTENT_TYPE, "Application/JSON; Charset=UTF-8")
                .body(Body::from(format!(r#"{{"password":"{PASSWORD}"}}"#)))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn bodies_are_bounded_and_strict() {
    let harness = Harness::new();
    let filler = "a".repeat(BODY_LIMIT);
    for (path, oversized) in [
        ("/api/v1/login", format!(r#"{{"password":"{filler}"}}"#)),
        (
            "/api/v1/pair",
            format!(r#"{{"pairing_code":"04HMASW9","password":"{filler}"}}"#),
        ),
        (
            "/api/v1/confirm",
            format!(r#"{{"recovery_key":"{filler}"}}"#),
        ),
    ] {
        let (status, _, body) = harness.send(harness.post_json(path, &oversized)).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{path}");
        assert_eq!(error_code(&body), "payload_too_large");
    }
    for invalid in [
        "",
        "not json",
        "[]",
        r#"{"password":"x","extra":1}"#,
        r#"{"password":"x","password":"y"}"#,
        r#"{"password":1}"#,
        r#"{}"#,
        r#"{"password":"x"} trailing"#,
    ] {
        let (status, _, body) = harness
            .send(harness.post_json("/api/v1/login", invalid))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{invalid}");
        assert_eq!(error_code(&body), "bad_request");
    }
    // Malformed UTF-8 inside a JSON string.
    let mut bytes = br#"{"password":""#.to_vec();
    bytes.extend_from_slice(&[0xff, 0xfe]);
    bytes.extend_from_slice(br#""}"#);
    let request = harness
        .request(Method::POST, "/api/v1/login")
        .header(header::ORIGIN, harness.origin())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(bytes))
        .unwrap();
    assert_eq!(harness.send(request).await.0, StatusCode::BAD_REQUEST);
    assert!(
        harness.calls().is_empty(),
        "no sl-authd work for invalid bodies"
    );
}

#[tokio::test]
async fn oversized_credentials_are_rejected_before_sl_authd() {
    let harness = Harness::new();
    for (path, body) in [
        (
            "/api/v1/login",
            format!(r#"{{"password":"{}"}}"#, "a".repeat(1025)),
        ),
        (
            "/api/v1/pair",
            format!(
                r#"{{"pairing_code":"04HMASW9","password":"{}"}}"#,
                "a".repeat(1025)
            ),
        ),
        (
            "/api/v1/pair",
            format!(r#"{{"pairing_code":"{}","password":"x"}}"#, "0".repeat(65)),
        ),
        (
            "/api/v1/confirm",
            format!(r#"{{"recovery_key":"{}"}}"#, "0".repeat(65)),
        ),
    ] {
        let (status, _, response) = harness.send(harness.post_json(path, &body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(error_code(&response), "invalid_argument");
    }
    assert!(harness.calls().is_empty());
    // The bound itself is accepted and reaches sl-authd.
    let (status, _, _) = harness
        .send(harness.post_json(
            "/api/v1/login",
            &format!(r#"{{"password":"{}"}}"#, "a".repeat(1024)),
        ))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(harness.calls(), ["VerifyPassword"]);
}

// Sessions.

#[tokio::test]
async fn protected_routes_reject_unauthenticated_requests_uniformly() {
    let harness = Harness::new();
    let valid = harness.login().await;
    harness.auth.calls.lock().unwrap().clear();
    let mut bodies = Vec::new();
    for cookie in [
        None,
        Some(String::new()),
        Some("__Host-sl_session=".into()),
        Some(format!("__Host-sl_session={}", "0".repeat(64))),
        Some(format!("__Host-sl_session={}", valid.to_ascii_uppercase())),
        Some(format!("__Host-sl_session={valid}x")),
        Some(format!("sl_session={valid}")),
        Some("__Host-sl_session=%00%ff; other=x".into()),
        Some("garbage;;;==".into()),
    ] {
        let (status, _, body) = harness
            .send(harness.status_request(cookie.as_deref()))
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{cookie:?}");
        bodies.push(body);
    }
    // A Cookie header of non-UTF-8 bytes (valid on the wire as obs-text).
    let request = harness
        .request(Method::GET, "/api/v1/status")
        .header(
            header::COOKIE,
            HeaderValue::from_bytes(b"__Host-sl_session=\xff\xfe\x80").unwrap(),
        )
        .body(Body::empty())
        .unwrap();
    let (status, _, body) = harness.send(request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    bodies.push(body);
    assert!(
        bodies.windows(2).all(|pair| pair[0] == pair[1]),
        "uniform responses"
    );
    assert_eq!(error_code(&bodies[0]), "unauthenticated");
    assert!(harness.calls().is_empty());
}

#[tokio::test]
async fn login_issues_a_fresh_session_with_the_frozen_cookie_attributes() {
    let harness = Harness::new();
    let supplied = "a".repeat(64);
    let request = harness
        .request(Method::POST, "/api/v1/login")
        .header(header::ORIGIN, harness.origin())
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("__Host-sl_session={supplied}"))
        .body(Body::from(format!(r#"{{"password":"{PASSWORD}"}}"#)))
        .unwrap();
    let (status, headers, _) = harness.send(request).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let cookie = headers[header::SET_COOKIE].to_str().unwrap();
    let id = cookie
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("__Host-sl_session=")
        .unwrap();
    assert_eq!(id.len(), 64);
    assert_ne!(id, supplied, "never upgrades a client-supplied identifier");
    for attribute in [
        "Secure",
        "HttpOnly",
        "SameSite=Strict",
        "Path=/",
        "Max-Age=28800",
    ] {
        assert!(
            cookie.split("; ").any(|part| part == attribute),
            "{attribute} in {cookie}"
        );
    }
    assert!(!cookie.contains("Domain"));
    // The supplied identifier authenticates nothing; the issued one does.
    let (status, _, _) = harness
        .send(harness.status_request(Some(&format!("__Host-sl_session={supplied}"))))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, _) = harness
        .send(harness.status_request(Some(&format!("__Host-sl_session={id}"))))
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn failed_logins_issue_no_cookie() {
    let harness = Harness::new();
    let (status, headers, body) = harness
        .send(harness.post_json("/api/v1/login", r#"{"password":"wrong password!"}"#))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(error_code(&body), "invalid_credential");
    assert!(headers.get(header::SET_COOKIE).is_none());
}

#[tokio::test]
async fn sessions_expire_on_idle_and_absolute_timeouts() {
    let harness = Harness::new();
    let id = harness.login().await;
    let cookie = format!("__Host-sl_session={id}");
    harness.clock.advance(IDLE_TIMEOUT - 1);
    assert_eq!(
        harness.send(harness.status_request(Some(&cookie))).await.0,
        StatusCode::OK
    );
    harness.clock.advance(IDLE_TIMEOUT);
    assert_eq!(
        harness.send(harness.status_request(Some(&cookie))).await.0,
        StatusCode::UNAUTHORIZED
    );
    let id = harness.login().await;
    let cookie = format!("__Host-sl_session={id}");
    for _ in 0..(ABSOLUTE_TIMEOUT / 600 - 1) {
        harness.clock.advance(600);
        assert_eq!(
            harness.send(harness.status_request(Some(&cookie))).await.0,
            StatusCode::OK
        );
    }
    harness.clock.advance(600);
    assert_eq!(
        harness.send(harness.status_request(Some(&cookie))).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn logout_invalidates_the_session_before_returning() {
    let harness = Harness::new();
    let id = harness.login().await;
    let cookie = format!("__Host-sl_session={id}");
    let request = harness
        .request(Method::POST, "/api/v1/logout")
        .header(header::ORIGIN, harness.origin())
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let (status, headers, _) = harness.send(request).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let expiring = headers[header::SET_COOKIE].to_str().unwrap();
    assert!(expiring.starts_with("__Host-sl_session=;"));
    assert!(expiring.split("; ").any(|part| part == "Max-Age=0"));
    assert_eq!(
        harness.send(harness.status_request(Some(&cookie))).await.0,
        StatusCode::UNAUTHORIZED
    );
    // Without a session, and with a body.
    let request = harness
        .request(Method::POST, "/api/v1/logout")
        .header(header::ORIGIN, harness.origin())
        .body(Body::empty())
        .unwrap();
    assert_eq!(harness.send(request).await.0, StatusCode::NO_CONTENT);
    let request = harness
        .request(Method::POST, "/api/v1/logout")
        .header(header::ORIGIN, harness.origin())
        .body(Body::from("x"))
        .unwrap();
    assert_eq!(harness.send(request).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn status_is_session1_json_unchanged_or_unavailable() {
    let harness = Harness::new();
    let id = harness.login().await;
    let cookie = format!("__Host-sl_session={id}");
    let reported = r#"{"schema_version":"0.4","remote_management":{"enabled":true,"listening":true,"enrolled":true}}"#;
    *harness.status.0.lock().unwrap() = Ok(reported.into());
    let (status, headers, body) = harness.send(harness.status_request(Some(&cookie))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "application/json");
    assert_eq!(body, reported);
    *harness.status.0.lock().unwrap() = Err(());
    let (status, _, body) = harness.send(harness.status_request(Some(&cookie))).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(&body), "unavailable");
}

// Pairing and confirmation.

#[tokio::test]
async fn the_recovery_key_is_returned_only_once() {
    let harness = Harness::new();
    let body = r#"{"pairing_code":"04hm-asw9","password":"correct horse battery"}"#;
    let (status, _, response) = harness.send(harness.post_json("/api/v1/pair", body)).await;
    assert_eq!(status, StatusCode::OK);
    let value: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(
        value,
        serde_json::json!({"recovery_key": "04HMASW9NF6YZZPWQAC7CN1J20"})
    );
    let (status, _, response) = harness.send(harness.post_json("/api/v1/pair", body)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(!response.contains("04HMASW9NF6YZZPWQAC7CN1J20"));
    assert_eq!(error_code(&response), "no_pending_pairing");
    // No other route can return it.
    let id = harness.login().await;
    for request in [
        harness
            .request(Method::GET, "/")
            .body(Body::empty())
            .unwrap(),
        harness.status_request(Some(&format!("__Host-sl_session={id}"))),
    ] {
        let (_, _, response) = harness.send(request).await;
        assert!(!response.contains("04HMASW9NF6YZZPWQAC7CN1J20"));
    }
}

#[tokio::test]
async fn confirmation_needs_no_session_and_maps_errors() {
    let harness = Harness::new();
    let body = r#"{"recovery_key":"04HMASW9NF6YZZPWQAC7CN1J20"}"#;
    assert_eq!(
        harness
            .send(harness.post_json("/api/v1/confirm", body))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    *harness.auth.confirm.lock().unwrap() = Some(AuthFailure::ConfirmationExpired);
    let (status, _, response) = harness
        .send(harness.post_json("/api/v1/confirm", body))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error_code(&response), "confirmation_expired");
}

#[tokio::test]
async fn every_auth_failure_maps_to_its_documented_response() {
    let cases = [
        (
            AuthFailure::NotEnrolled,
            StatusCode::CONFLICT,
            "not_enrolled",
        ),
        (
            AuthFailure::EnrollmentUnconfirmed,
            StatusCode::CONFLICT,
            "enrollment_unconfirmed",
        ),
        (
            AuthFailure::AlreadyEnrolled,
            StatusCode::CONFLICT,
            "already_enrolled",
        ),
        (
            AuthFailure::NoPendingPairing,
            StatusCode::CONFLICT,
            "no_pending_pairing",
        ),
        (
            AuthFailure::InvalidPairingCode,
            StatusCode::FORBIDDEN,
            "invalid_pairing_code",
        ),
        (
            AuthFailure::PairingAttemptsExhausted,
            StatusCode::FORBIDDEN,
            "pairing_attempts_exhausted",
        ),
        (
            AuthFailure::NoProvisionalEnrollment,
            StatusCode::CONFLICT,
            "no_provisional_enrollment",
        ),
        (
            AuthFailure::ConfirmationExpired,
            StatusCode::CONFLICT,
            "confirmation_expired",
        ),
        (
            AuthFailure::InvalidCredential,
            StatusCode::UNAUTHORIZED,
            "invalid_credential",
        ),
        (
            AuthFailure::PasswordRejected,
            StatusCode::UNPROCESSABLE_ENTITY,
            "password_rejected",
        ),
        (
            AuthFailure::RateLimited,
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
        ),
        (AuthFailure::Busy, StatusCode::SERVICE_UNAVAILABLE, "busy"),
        (
            AuthFailure::InvalidArgument,
            StatusCode::BAD_REQUEST,
            "invalid_argument",
        ),
        (
            AuthFailure::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
        ),
    ];
    for (failure, status, code) in cases {
        let harness = Harness::new();
        *harness.auth.verify.lock().unwrap() = Some(failure);
        let (actual, headers, body) = harness
            .send(harness.post_json("/api/v1/login", &format!(r#"{{"password":"{PASSWORD}"}}"#)))
            .await;
        assert_eq!(
            (actual, error_code(&body).as_str()),
            (status, code),
            "{failure:?}"
        );
        assert!(headers.get(header::SET_COOKIE).is_none());
    }
}

// Logging.

#[test]
fn event_lines_carry_route_source_and_outcome_only() {
    assert_eq!(
        event_line("login", "192.0.2.77".parse().unwrap(), "invalid_credential"),
        "sl-remoted: login from 192.0.2.77: invalid_credential"
    );
    assert_eq!(
        event_line("pair", "2001:db8::77".parse().unwrap(), "ok"),
        "sl-remoted: pair from 2001:db8::77: ok"
    );
}
