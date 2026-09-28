//! The read-only remote API, exactly as specified in docs/remote-api-0.0.3.md.
use crate::{
    network::endpoint,
    peers::{Auth, AuthFailure, StatusSource},
    sessions::{Sessions, ABSOLUTE_TIMEOUT, COOKIE_NAME},
};
use axum::{
    body::{Body, Bytes},
    extract::{Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

pub const BODY_LIMIT: usize = 4096;
pub const PASSWORD_MAX_BYTES: usize = 1024;
pub const CODE_MAX_BYTES: usize = 64;
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

const INDEX_HTML: &str = include_str!("../static/index.html");
const APP_JS: &str = include_str!("../static/app.js");
const APP_CSS: &str = include_str!("../static/app.css");

/// The listener endpoint that accepted the connection, and its peer.
#[derive(Debug, Clone, Copy)]
pub struct ConnInfo {
    pub local: SocketAddr,
    pub peer: SocketAddr,
}

#[derive(Clone)]
pub struct AppState {
    pub auth: Arc<dyn Auth>,
    pub status: Arc<dyn StatusSource>,
    pub sessions: Arc<Sessions>,
}

fn error(status: StatusCode, code: &'static str) -> Response {
    let mut response = (status, format!("{{\"error\":\"{code}\"}}")).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

fn auth_error(failure: AuthFailure) -> (Response, &'static str) {
    let (status, code) = match failure {
        AuthFailure::NotEnrolled => (StatusCode::CONFLICT, "not_enrolled"),
        AuthFailure::EnrollmentUnconfirmed => (StatusCode::CONFLICT, "enrollment_unconfirmed"),
        AuthFailure::AlreadyEnrolled => (StatusCode::CONFLICT, "already_enrolled"),
        AuthFailure::NoPendingPairing => (StatusCode::CONFLICT, "no_pending_pairing"),
        AuthFailure::InvalidPairingCode => (StatusCode::FORBIDDEN, "invalid_pairing_code"),
        AuthFailure::PairingAttemptsExhausted => {
            (StatusCode::FORBIDDEN, "pairing_attempts_exhausted")
        }
        AuthFailure::NoProvisionalEnrollment => (StatusCode::CONFLICT, "no_provisional_enrollment"),
        AuthFailure::ConfirmationExpired => (StatusCode::CONFLICT, "confirmation_expired"),
        AuthFailure::InvalidCredential => (StatusCode::UNAUTHORIZED, "invalid_credential"),
        AuthFailure::PasswordRejected => (StatusCode::UNPROCESSABLE_ENTITY, "password_rejected"),
        AuthFailure::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
        AuthFailure::Busy => (StatusCode::SERVICE_UNAVAILABLE, "busy"),
        AuthFailure::InvalidArgument => (StatusCode::BAD_REQUEST, "invalid_argument"),
        AuthFailure::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    };
    (error(status, code), code)
}

/// A journal line: route, source address and outcome code only. It has no
/// parameter through which a credential, code, key or session ID could pass.
pub fn event_line(route: &'static str, source: IpAddr, outcome: &'static str) -> String {
    format!("sl-remoted: {route} from {source}: {outcome}")
}

fn log(route: &'static str, conn: &ConnInfo, outcome: &'static str) {
    eprintln!("{}", event_line(route, conn.peer.ip(), outcome));
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/app.css", get(app_css))
        .route("/api/v1/pair", post(pair))
        .route("/api/v1/confirm", post(confirm))
        .route("/api/v1/login", post(login))
        .route("/api/v1/logout", post(logout))
        .route("/api/v1/status", get(status))
        .fallback(|| async { error(StatusCode::NOT_FOUND, "not_found") })
        .method_not_allowed_fallback(|| async {
            error(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed")
        })
        .layer(middleware::from_fn(host_check))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    for (name, value) in [
        (header::CACHE_CONTROL, "no-store"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    response
}

/// Host must be exactly the accepting listener's endpoint. A request without
/// connection information (never produced by the server) is refused.
async fn host_check(request: Request, next: Next) -> Response {
    let Some(conn) = request.extensions().get::<ConnInfo>().copied() else {
        return error(StatusCode::MISDIRECTED_REQUEST, "misdirected");
    };
    let expected = endpoint(conn.local);
    let hosts: Vec<&HeaderValue> = request.headers().get_all(header::HOST).iter().collect();
    let host_ok = hosts.len() == 1 && hosts[0].as_bytes() == expected.as_bytes();
    let authority_ok = request
        .uri()
        .authority()
        .is_none_or(|authority| authority.as_str() == expected);
    if !host_ok || !authority_ok {
        return error(StatusCode::MISDIRECTED_REQUEST, "misdirected");
    }
    next.run(request).await
}

fn origin_ok(headers: &HeaderMap, conn: &ConnInfo) -> bool {
    let expected = format!("https://{}", endpoint(conn.local));
    let origins: Vec<&HeaderValue> = headers.get_all(header::ORIGIN).iter().collect();
    origins.len() == 1 && origins[0].as_bytes() == expected.as_bytes()
}

fn json_content_type(headers: &HeaderMap) -> bool {
    let values: Vec<&HeaderValue> = headers.get_all(header::CONTENT_TYPE).iter().collect();
    if values.len() != 1 {
        return false;
    }
    let Ok(value) = values[0].to_str() else {
        return false;
    };
    let value = value.to_ascii_lowercase();
    value == "application/json" || value == "application/json; charset=utf-8"
}

fn conn(request_extensions: &axum::http::Extensions) -> ConnInfo {
    *request_extensions
        .get::<ConnInfo>()
        .expect("host_check guarantees connection information")
}

/// Content type first (before reading any body), then at most BODY_LIMIT
/// bytes, then strict JSON. Every failure is uniform and names no detail.
async fn parse_body<T: for<'de> Deserialize<'de>>(
    headers: &HeaderMap,
    body: Body,
) -> Result<T, Response> {
    if !json_content_type(headers) {
        return Err(error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
        ));
    }
    let body: Bytes = axum::body::to_bytes(body, BODY_LIMIT)
        .await
        .map_err(|_| error(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"))?;
    serde_json::from_slice(&body).map_err(|_| error(StatusCode::BAD_REQUEST, "bad_request"))
}

fn session_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(cookie::Cookie::split_parse)
        .filter_map(Result::ok)
        .find(|cookie| cookie.name() == COOKIE_NAME)
        .map(|cookie| cookie.value().to_owned())
}

fn set_cookie(value: &str, max_age: i64) -> HeaderValue {
    let cookie = cookie::Cookie::build((COOKIE_NAME, value))
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(cookie::SameSite::Strict)
        .max_age(cookie::time::Duration::seconds(max_age))
        .build();
    HeaderValue::from_str(&cookie.to_string()).expect("the cookie is ASCII")
}

async fn index() -> Response {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        INDEX_HTML,
    )
        .into_response()
}

async fn app_js() -> Response {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        APP_JS,
    )
        .into_response()
}

async fn app_css() -> Response {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], APP_CSS).into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PairRequest {
    pairing_code: String,
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmRequest {
    recovery_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginRequest {
    password: String,
}

async fn pair(State(state): State<AppState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let conn = conn(&parts.extensions);
    if !origin_ok(&parts.headers, &conn) {
        log("pair", &conn, "forbidden_origin");
        return error(StatusCode::FORBIDDEN, "forbidden_origin");
    }
    let request: PairRequest = match parse_body(&parts.headers, body).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    if request.password.len() > PASSWORD_MAX_BYTES || request.pairing_code.len() > CODE_MAX_BYTES {
        return error(StatusCode::BAD_REQUEST, "invalid_argument");
    }
    match state
        .auth
        .consume_pairing(request.pairing_code, request.password)
        .await
    {
        Ok(recovery_key) => {
            log("pair", &conn, "ok");
            let body = serde_json::json!({ "recovery_key": recovery_key }).to_string();
            ([(header::CONTENT_TYPE, "application/json")], body).into_response()
        }
        Err(failure) => {
            let (response, code) = auth_error(failure);
            log("pair", &conn, code);
            response
        }
    }
}

async fn confirm(State(state): State<AppState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let conn = conn(&parts.extensions);
    if !origin_ok(&parts.headers, &conn) {
        log("confirm", &conn, "forbidden_origin");
        return error(StatusCode::FORBIDDEN, "forbidden_origin");
    }
    let request: ConfirmRequest = match parse_body(&parts.headers, body).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    if request.recovery_key.len() > CODE_MAX_BYTES {
        return error(StatusCode::BAD_REQUEST, "invalid_argument");
    }
    match state.auth.confirm_recovery_key(request.recovery_key).await {
        Ok(()) => {
            log("confirm", &conn, "ok");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(failure) => {
            let (response, code) = auth_error(failure);
            log("confirm", &conn, code);
            response
        }
    }
}

async fn login(State(state): State<AppState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let conn = conn(&parts.extensions);
    if !origin_ok(&parts.headers, &conn) {
        log("login", &conn, "forbidden_origin");
        return error(StatusCode::FORBIDDEN, "forbidden_origin");
    }
    let request: LoginRequest = match parse_body(&parts.headers, body).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    if request.password.len() > PASSWORD_MAX_BYTES {
        return error(StatusCode::BAD_REQUEST, "invalid_argument");
    }
    if let Err(failure) = state.auth.verify_password(request.password).await {
        let (response, code) = auth_error(failure);
        log("login", &conn, code);
        return response;
    }
    // Always a fresh identifier; any cookie the client sent is ignored.
    let Ok(id) = state.sessions.create() else {
        log("login", &conn, "unavailable");
        return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
    };
    log("login", &conn, "ok");
    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, set_cookie(&id, ABSOLUTE_TIMEOUT as i64));
    response
}

async fn logout(State(state): State<AppState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let conn = conn(&parts.extensions);
    if !origin_ok(&parts.headers, &conn) {
        log("logout", &conn, "forbidden_origin");
        return error(StatusCode::FORBIDDEN, "forbidden_origin");
    }
    match axum::body::to_bytes(body, BODY_LIMIT).await {
        Ok(body) if body.is_empty() => {}
        _ => return error(StatusCode::BAD_REQUEST, "bad_request"),
    }
    // The server-side session is gone before the response is built.
    if let Some(id) = session_cookie(&parts.headers) {
        state.sessions.remove(&id);
    }
    log("logout", &conn, "ok");
    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, set_cookie("", 0));
    response
}

async fn status(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let authenticated = session_cookie(&headers).is_some_and(|id| state.sessions.validate(&id));
    if !authenticated {
        return error(StatusCode::UNAUTHORIZED, "unauthenticated");
    }
    match state.status.status().await {
        Ok(status) => (
            [(header::CONTENT_TYPE, "application/json")],
            Body::from(status),
        )
            .into_response(),
        Err(()) => error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    }
}

#[cfg(test)]
mod tests;
