//! Matrix coverage for malformed request bodies across every mutating route.
//!
//! `crate::json::parse_optional` (see `crates/api/src/json.rs`) treats an **empty** body as
//! `T::default()` and any **non-empty-but-invalid** JSON body as a clean 400. That contract was
//! only spot-checked per route in `api_tests.rs`. This file table-drives the same three malformed
//! shapes across every mutating route that parses a JSON body, so a future route addition (or a
//! regression in `parse_optional`) can't silently start panicking or 500ing on bad input.
//!
//! Require Postgres via `DATABASE_URL` (loaded from `.env`), same as `api_tests.rs`. Skipped
//! (with an early return) if no `DATABASE_URL` is configured.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use octo_api::{build_router, AppState};
use octo_store::Store;
use octo_wallet_core::StellarNetwork;
use std::sync::Once;
use tower::ServiceExt; // for `oneshot`

static LOAD_ENV: Once = Once::new();

fn database_url() -> Option<String> {
    LOAD_ENV.call_once(|| {
        let _ = dotenvy::dotenv();
    });
    std::env::var("DATABASE_URL").ok()
}

async fn test_state() -> Option<AppState> {
    let url = database_url()?;
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");
    let master_key = [42u8; 32]; // deterministic test key
    Some(AppState::new(
        store,
        master_key,
        StellarNetwork::Testnet,
        "https://horizon-testnet.stellar.org".into(),
        None,
        octo_email::EmailSender::new_captured(),
    ))
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("json")
}

/// Sign up a fresh user via the router and return its bearer token.
async fn auth_token(app: &axum::Router, state: &AppState) -> String {
    let email = format!("u-{}@octo.test", uuid::Uuid::new_v4().simple());
    common::signup_and_verify(app, state, &email).await
}

/// Build a request carrying a raw (possibly malformed) JSON body, with an optional bearer token.
fn json_request(method: &str, uri: &str, body: Vec<u8>, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    builder.body(Body::from(body)).unwrap()
}

/// One entry in the mutating-route matrix. `path_template` may contain a `{wallet}` placeholder,
/// substituted with a real wallet id before the request is sent (every wallet-scoped route
/// authorizes — which looks the wallet up — *before* it parses the body, so a fake id would 404
/// instead of exercising the malformed-body path we actually want to test).
struct RouteCase {
    method: &'static str,
    path_template: &'static str,
    needs_auth: bool,
}

/// Every mutating route under `crates/api/src/routes/` (plus dashboard auth) that parses its body
/// via `crate::json::parse_optional`. Deliberately excludes routes with no body (e.g.
/// `DELETE /v1/wallets/:id/api-key`) — there's no JSON shape to be malformed.
/// Also excludes `POST /v1/wallets/:id/withdraw`: it's a `410 Gone` tombstone (see
/// `custodial_withdraw_is_gone` in `api_tests.rs`) that never reaches `parse_optional`.
const MUTATING_ROUTES: &[RouteCase] = &[
    RouteCase {
        method: "POST",
        path_template: "/v1/auth/signup",
        needs_auth: false,
    },
    RouteCase {
        method: "POST",
        path_template: "/v1/auth/login",
        needs_auth: false,
    },
    RouteCase {
        method: "POST",
        path_template: "/v1/wallets",
        needs_auth: true,
    },
    RouteCase {
        method: "POST",
        path_template: "/v1/wallets/{wallet}/addresses",
        needs_auth: true,
    },
    RouteCase {
        method: "POST",
        path_template: "/v1/wallets/{wallet}/webhooks",
        needs_auth: true,
    },
    RouteCase {
        method: "PUT",
        path_template: "/v1/wallets/{wallet}/sponsorship",
        needs_auth: true,
    },
    RouteCase {
        method: "POST",
        path_template: "/v1/wallets/{wallet}/sponsor",
        needs_auth: true,
    },
    RouteCase {
        method: "POST",
        path_template: "/v1/wallets/{wallet}/api-key",
        needs_auth: true,
    },
];

fn resolve_path(template: &str, wallet_id: &str) -> String {
    template.replace("{wallet}", wallet_id)
}

/// Build a deterministic, moderately-large *nested* JSON object: `num_keys` distinct top-level
/// keys, each mapping to a small nested object. A few thousand keys keeps this well under a
/// second to build/parse/route while still exercising "wide, nested, but not huge" input.
///
/// Deliberately sized to stay comfortably under the router's request-body limit (64 KiB, see
/// `REQUEST_BODY_LIMIT` in `crates/api/src/lib.rs`) — this test is about malformed-*shape*
/// robustness, not the size limit, which has its own dedicated coverage in `api_tests.rs`
/// (`request_body_over_the_configured_limit_returns_413` / `test_oversized_body_returns_envelope`).
/// At 3,000 keys the body is ~55 KiB.
fn large_nested_json(num_keys: usize) -> Vec<u8> {
    let mut s = String::with_capacity(num_keys * 20);
    s.push('{');
    for i in 0..num_keys {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!("\"k{i}\":{{\"a\":{i}}}"));
    }
    s.push('}');
    s.into_bytes()
}

/// Shared fixture: a built router, a valid bearer token, and a real wallet id owned by that
/// token's user — everything the matrix needs to reach each route's `parse_optional` call instead
/// of bailing out earlier on auth or wallet-lookup.
struct Fixture {
    app: axum::Router,
    token: String,
    wallet_id: String,
}

async fn fixture() -> Option<Fixture> {
    let state = test_state().await?;
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    // Non-custodial contract: `public_key` plus a signed ownership challenge is required, so an
    // empty body now 400s.
    let kp = stellar_base::crypto::DalekKeyPair::random().unwrap();
    let body = common::wallet_body(&app, &token, &kp).await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/wallets")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "fixture wallet creation failed"
    );
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    Some(Fixture {
        app,
        token,
        wallet_id,
    })
}

#[tokio::test]
async fn truncated_json_body_returns_400_across_all_mutating_routes() {
    let Some(Fixture {
        app,
        token,
        wallet_id,
    }) = fixture().await
    else {
        return;
    };

    for case in MUTATING_ROUTES {
        let path = resolve_path(case.path_template, &wallet_id);
        let auth = case.needs_auth.then_some(token.as_str());
        let req = json_request(case.method, &path, b"{".to_vec(), auth);

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "expected 400 for truncated JSON on {} {}, got {}",
            case.method,
            path,
            resp.status()
        );
        // The response body must itself be well-formed JSON in the standard envelope shape —
        // a panic (poisoned response) or a raw error string would fail this.
        let body = body_json(resp).await;
        assert_eq!(body["statusCode"], 400);
    }
}

#[tokio::test]
async fn wrong_top_level_json_shape_returns_400_across_all_mutating_routes() {
    let Some(Fixture {
        app,
        token,
        wallet_id,
    }) = fixture().await
    else {
        return;
    };

    for case in MUTATING_ROUTES {
        let path = resolve_path(case.path_template, &wallet_id);
        let auth = case.needs_auth.then_some(token.as_str());
        // A non-empty JSON array where every one of these routes expects an object. `[]` isn't
        // used here: several request structs (e.g. `CreateAddressRequest`) have every field
        // `#[serde(default)]`, and serde accepts an empty sequence as a struct with zero elements
        // to bind — a non-empty array is unambiguously the wrong shape regardless of field
        // optionality.
        let req = json_request(case.method, &path, b"[1]".to_vec(), auth);

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "expected 400 for a top-level JSON array on {} {}, got {}",
            case.method,
            path,
            resp.status()
        );
        let body = body_json(resp).await;
        assert_eq!(body["statusCode"], 400);
    }
}

#[tokio::test]
async fn moderately_large_nested_json_does_not_panic() {
    let Some(Fixture {
        app,
        token,
        wallet_id,
    }) = fixture().await
    else {
        return;
    };

    // A few thousand keys, each with a small nested value — large enough to exercise real
    // parsing/allocation work, small enough to stay well under a second per route.
    let large_body = large_nested_json(3_000);

    for case in MUTATING_ROUTES {
        let path = resolve_path(case.path_template, &wallet_id);
        let auth = case.needs_auth.then_some(token.as_str());
        let req = json_request(case.method, &path, large_body.clone(), auth);

        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();

        // The generated object's keys ("k0", "k1", ...) never match any route's expected field
        // names, so it deserializes as either a validation failure on a required field (400) or,
        // for routes where every field is optional, a successful create/update (200/201) with the
        // unknown keys silently ignored (default serde behavior — none of these structs use
        // `deny_unknown_fields`). Either is a legitimate outcome; a 5xx or a hang is not.
        assert_ne!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "moderately-large nested JSON must never 500 on {} {}",
            case.method,
            path
        );
        assert!(
            status.is_success() || status.is_client_error(),
            "unexpected status {} for moderately-large nested JSON on {} {}",
            status,
            case.method,
            path
        );
        // The response body must still decode cleanly — proves the handler returned through the
        // normal envelope path rather than panicking partway through.
        let body = body_json(resp).await;
        assert!(body.get("statusCode").is_some());
    }
}
