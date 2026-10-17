//! Logs must never contain credentials (issue #436).
//!
//! Captures every tracing event at TRACE level while driving the auth, session, API-key,
//! gas-tank (server-side mnemonic), withdrawal-OTP and password-reset flows, then asserts the
//! output holds none of the secrets those flows handled: bearer tokens, API keys, OTP codes,
//! passwords, or anything shaped like a JWT, an `octo_sk_` key, or a BIP39 phrase.
//!
//! A single test owns the process-global subscriber, so no other test's output can mix in.
//! Requires Postgres via `DATABASE_URL` (skipped with a message otherwise, like `api_tests.rs`).

mod common;

use axum::body::Body;
use axum::http::Request;
use octo_api::{build_router, AppState};
use octo_store::Store;
use octo_wallet_core::StellarNetwork;
use std::io::Write;
use std::sync::{Arc, Mutex, Once, OnceLock};
use std::time::Duration;
use stellar_base::crypto::DalekKeyPair;
use stellar_base::operations::Operation;
use stellar_base::transaction::{Transaction, MIN_BASE_FEE};
use stellar_base::xdr::XDRSerialize;
use tower::ServiceExt;
use uuid::Uuid;

static LOAD_ENV: Once = Once::new();

/// Header segment every Octo JWT starts with (`{"alg":"HS256","typ":"JWT"}`).
const JWT_HEADER_B64: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
const PASSWORD: &str = "supersecret123";
const NEW_PASSWORD: &str = "evenmoresecret456";

fn database_url() -> Option<String> {
    LOAD_ENV.call_once(|| {
        let _ = dotenvy::dotenv();
    });
    std::env::var("DATABASE_URL").ok()
}

/// Everything written by the global subscriber.
fn captured() -> &'static Arc<Mutex<Vec<u8>>> {
    static BUF: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    BUF.get_or_init(|| {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let sink = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            // No timestamps: their digit runs could collide with a 6-digit OTP.
            .without_time()
            .with_writer(move || CaptureWriter(sink.clone()))
            .finish();
        tracing::subscriber::set_global_default(subscriber).expect("install capture subscriber");
        buf
    })
}

struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl Write for CaptureWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

async fn test_state() -> Option<AppState> {
    let url = database_url()?;
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");
    Some(AppState::new(
        store,
        [42u8; 32],
        StellarNetwork::Testnet,
        "https://horizon-testnet.stellar.org".into(),
        None,
        octo_email::EmailSender::new_captured(),
    ))
}

fn request(method: &str, uri: &str, token: Option<&str>, body: serde_json::Value) -> Request<Body> {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("user-agent", "log-secret-tests/1.0");
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    // `Null` means "no body", which handlers read as all-defaults.
    let body = if body.is_null() {
        Body::empty()
    } else {
        Body::from(body.to_string())
    };
    req.body(body).unwrap()
}

/// Send a request and return its JSON body (`Null` when there is none).
async fn call(
    app: &axum::Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: serde_json::Value,
) -> serde_json::Value {
    let resp = app
        .clone()
        .oneshot(request(method, uri, token, body))
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

/// The newest OTP mailed to `email` that differs from `previous`, waiting for background sends.
async fn next_otp(state: &AppState, email: &str, previous: Option<&str>) -> String {
    for _ in 0..50 {
        if let Some(code) = state.email().last_otp_for(email) {
            if Some(code.as_str()) != previous {
                return code;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no new OTP was captured for {email}");
}

fn signed_payment_xdr(kp: &DalekKeyPair, destination_g: &str) -> String {
    let dest = stellar_base::crypto::PublicKey::from_account_id(destination_g).unwrap();
    let op = Operation::new_payment()
        .with_destination(dest)
        .with_amount(stellar_base::amount::Stroops::new(100))
        .unwrap()
        .with_asset(stellar_base::asset::Asset::new_native())
        .build()
        .unwrap();
    let mut tx = Transaction::builder(kp.public_key(), 1, MIN_BASE_FEE)
        .add_operation(op)
        .into_transaction()
        .unwrap();
    tx.sign(kp.as_ref(), &stellar_base::network::Network::new_test())
        .unwrap();
    tx.into_envelope().xdr_base64().unwrap()
}

/// True if `needle` occurs in `haystack` not flanked by other digits (so a 6-digit OTP doesn't
/// match inside a longer number).
fn contains_standalone_digits(haystack: &str, needle: &str) -> bool {
    haystack.match_indices(needle).any(|(i, _)| {
        let before = haystack[..i].chars().next_back();
        let after = haystack[i + needle.len()..].chars().next();
        !before.is_some_and(|c| c.is_ascii_digit()) && !after.is_some_and(|c| c.is_ascii_digit())
    })
}

/// True if any run of 12 or 24 consecutive words in `logs` is a valid BIP39 phrase.
fn contains_mnemonic(logs: &str) -> bool {
    let words: Vec<String> = logs
        .split_whitespace()
        .map(|w| {
            w.trim_matches(|c: char| !c.is_ascii_alphabetic())
                .to_ascii_lowercase()
        })
        .collect();
    [12usize, 24].iter().any(|&n| {
        words
            .windows(n)
            .any(|w| octo_wallet_core::validate_seed_phrase(&w.join(" ")).is_ok())
    })
}

#[tokio::test]
async fn logs_never_contain_tokens_api_keys_otp_codes_or_mnemonics() {
    let buf = captured();
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: DATABASE_URL is not set");
        return;
    };
    let app = build_router(state.clone());
    let email = format!("log-secrets-{}@octo.test", Uuid::new_v4().simple());
    let mut tokens: Vec<String> = Vec::new();
    let mut otps: Vec<String> = Vec::new();

    // --- auth: signup → verify → login (good and bad password) → me → refresh → sessions.
    let signup = call(
        &app,
        "POST",
        "/v1/auth/signup",
        None,
        serde_json::json!({ "email": email, "password": PASSWORD }),
    )
    .await;
    let user_id = signup["data"]["user_id"].as_str().unwrap().to_string();
    let signup_otp = next_otp(&state, &email, None).await;
    let verified = call(
        &app,
        "POST",
        "/v1/auth/verify-email",
        None,
        serde_json::json!({ "user_id": user_id, "code": signup_otp }),
    )
    .await;
    otps.push(signup_otp);
    let token = verified["data"]["token"].as_str().unwrap().to_string();
    tokens.push(token.clone());

    call(
        &app,
        "POST",
        "/v1/auth/login",
        None,
        serde_json::json!({ "email": email, "password": "wrong-password-123" }),
    )
    .await;
    let login = call(
        &app,
        "POST",
        "/v1/auth/login",
        None,
        serde_json::json!({ "email": email, "password": PASSWORD }),
    )
    .await;
    tokens.push(login["data"]["token"].as_str().unwrap().to_string());
    call(&app, "GET", "/v1/auth/me", Some(&token), serde_json::Value::Null).await;
    let refreshed = call(
        &app,
        "POST",
        "/v1/auth/refresh",
        Some(&token),
        serde_json::Value::Null,
    )
    .await;
    let token = refreshed["data"]["token"].as_str().unwrap().to_string();
    tokens.push(token.clone());
    call(&app, "GET", "/v1/auth/sessions", Some(&token), serde_json::Value::Null).await;
    // A revoked token presented again exercises the rejection path.
    call(&app, "GET", "/v1/auth/me", Some(&tokens[0]), serde_json::Value::Null).await;

    // --- wallet + API key: issue a key, use it, and present a forged one.
    let kp = DalekKeyPair::random().unwrap();
    let wallet_body = common::wallet_body(&app, &token, &kp).await;
    let wallet = call(
        &app,
        "POST",
        "/v1/wallets",
        Some(&token),
        serde_json::from_str(&wallet_body).unwrap(),
    )
    .await;
    let wallet_id = wallet["data"]["id"].as_str().unwrap().to_string();
    let key = call(
        &app,
        "POST",
        &format!("/v1/wallets/{wallet_id}/api-key"),
        Some(&token),
        serde_json::Value::Null,
    )
    .await;
    let api_key = key["data"]["api_key"].as_str().unwrap().to_string();
    let addresses = format!("/v1/wallets/{wallet_id}/addresses");
    call(&app, "GET", &addresses, Some(&api_key), serde_json::Value::Null).await;
    call(
        &app,
        "GET",
        &addresses,
        Some("octo_sk_test_00000000000000000000000000000000"),
        serde_json::Value::Null,
    )
    .await;

    // --- gas tank: the server generates (and must drop, unlogged) a mnemonic here.
    call(
        &app,
        "POST",
        &format!("/v1/wallets/{wallet_id}/gas-tank"),
        Some(&token),
        serde_json::Value::Null,
    )
    .await;

    // --- withdrawal OTP: wrong code, then the right one (Horizon rejects the unfunded tx).
    let dest = DalekKeyPair::random().unwrap().public_key().account_id();
    let xdr = signed_payment_xdr(&kp, &dest);
    call(
        &app,
        "POST",
        &format!("/v1/wallets/{wallet_id}/withdraw/request-otp"),
        Some(&token),
        serde_json::json!({ "transaction_xdr": xdr }),
    )
    .await;
    let withdraw_otp = next_otp(&state, &email, otps.last().map(String::as_str)).await;
    let confirm = format!("/v1/wallets/{wallet_id}/withdraw/confirm");
    call(
        &app,
        "POST",
        &confirm,
        Some(&token),
        serde_json::json!({ "transaction_xdr": xdr, "code": "000000" }),
    )
    .await;
    call(
        &app,
        "POST",
        &confirm,
        Some(&token),
        serde_json::json!({ "transaction_xdr": xdr, "code": withdraw_otp }),
    )
    .await;
    otps.push(withdraw_otp);

    // --- password reset (code is mailed from a background task), then logout.
    call(
        &app,
        "POST",
        "/v1/auth/request-password-reset",
        None,
        serde_json::json!({ "email": email }),
    )
    .await;
    let reset_otp = next_otp(&state, &email, otps.last().map(String::as_str)).await;
    call(
        &app,
        "POST",
        "/v1/auth/confirm-password-reset",
        None,
        serde_json::json!({ "email": email, "code": reset_otp, "new_password": NEW_PASSWORD }),
    )
    .await;
    otps.push(reset_otp);
    call(&app, "POST", "/v1/auth/logout", Some(&token), serde_json::Value::Null).await;

    let logs = String::from_utf8_lossy(&buf.lock().unwrap()).into_owned();
    assert!(!logs.is_empty(), "the capture subscriber recorded nothing");
    for (i, t) in tokens.iter().enumerate() {
        assert!(!logs.contains(t.as_str()), "bearer token #{i} appeared in logs");
    }
    assert!(!logs.contains(JWT_HEADER_B64), "a JWT appeared in logs");
    assert!(!logs.contains(&api_key), "the issued API key appeared in logs");
    assert!(
        !logs.contains("octo_sk_test_0000"),
        "a presented (forged) API key appeared in logs"
    );
    for (i, code) in otps.iter().enumerate() {
        assert!(
            !contains_standalone_digits(&logs, code),
            "OTP code #{i} appeared in logs"
        );
    }
    for password in [PASSWORD, NEW_PASSWORD, "wrong-password-123"] {
        assert!(!logs.contains(password), "a password appeared in logs");
    }
    assert!(!contains_mnemonic(&logs), "a BIP39 mnemonic appeared in logs");
}
