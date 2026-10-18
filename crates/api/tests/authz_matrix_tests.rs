//! Cross-wallet authorization matrix for `authorize_wallet` (crates/api/src/auth.rs).
//!
//! `authorize_wallet` has two independent authorization paths — dashboard-JWT ownership and
//! API-key-implies-wallet — each of which must reject cross-tenant access on *every* route that
//! calls it. `api_tests.rs::api_key_cannot_touch_another_wallet` spot-checks a couple of routes;
//! this file exhaustively covers the full route set.
//!
//! The route list below was built by grepping `crates/api/src/auth.rs` call sites of
//! `authorize_wallet` (see `crates/api/src/routes/{webhooks,sponsorship,sponsor,addresses}.rs`
//! and `crates/api/src/routes/wallets.rs`), then cross-referencing against the router wiring in
//! `crates/api/src/lib.rs::build_router` to get the exact `(method, path)` pairs. Note that
//! `GET /v1/wallets/:id/sponsored-transactions` is deliberately excluded: it is guarded by
//! `require_login` + a manual ownership check, not by `authorize_wallet` (it does not accept API
//! keys at all), so it is out of scope for this matrix.
//!
//! Every `authorize_wallet`-guarded handler calls it *before* parsing the request body, so an
//! empty body is sufficient to exercise the authorization check on POST/PUT routes too.

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

/// Build a request with an arbitrary method and an `Authorization: Bearer <token>` header, no
/// body. Every `authorize_wallet`-guarded route runs the authz check before reading the body, so
/// this is sufficient to exercise all of them (GET/POST/PUT alike).
fn req_auth(method: &str, uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

/// POST with no body but an Authorization bearer token (mirrors `api_tests.rs::post_auth`).
fn post_auth(uri: &str, token: &str) -> Request<Body> {
    req_auth("POST", uri, token)
}

/// Sign up a fresh user via the router and return its bearer token.
async fn auth_token(app: &axum::Router, state: &AppState) -> String {
    let email = format!("u-{}@octo.test", uuid::Uuid::new_v4().simple());
    common::signup_and_verify(app, state, &email).await
}

/// Create a wallet for `token`'s user and return its id. Non-custodial: the caller generates the
/// keypair, proves ownership via a signed challenge, and sends only the public account (mirrors
/// `api_tests.rs::create_wallet_req`).
async fn create_wallet(app: &axum::Router, token: &str) -> String {
    let kp = stellar_base::crypto::DalekKeyPair::random().unwrap();
    let body = common::wallet_body(app, token, &kp).await;
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
    assert_eq!(resp.status(), StatusCode::CREATED);
    body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string()
}

/// Generate an API key for a wallet (via its owner's JWT) and return the full key string.
async fn api_key_for(app: &axum::Router, token: &str, wallet_id: &str) -> String {
    let resp = app
        .clone()
        .oneshot(post_auth(
            &format!("/v1/wallets/{wallet_id}/api-key"),
            token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    body_json(resp).await["data"]["api_key"]
        .as_str()
        .unwrap()
        .to_string()
}

/// One route guarded by `authorize_wallet`, described generically enough to build a request
/// against an arbitrary wallet id.
struct GuardedRoute {
    /// Human-readable name for assertion failure messages.
    name: &'static str,
    method: &'static str,
    /// Builds the request path for the given wallet id.
    path: fn(&str) -> String,
}

/// The exhaustive set of routes that call `authorize_wallet` (see module docs for how this list
/// was derived). Keep in sync with call sites in `crates/api/src/routes/*.rs`.
fn guarded_routes() -> Vec<GuardedRoute> {
    vec![
        GuardedRoute {
            name: "GET /v1/wallets/:id",
            method: "GET",
            path: |id| format!("/v1/wallets/{id}"),
        },
        GuardedRoute {
            name: "GET /v1/wallets/:id/balances",
            method: "GET",
            path: |id| format!("/v1/wallets/{id}/balances"),
        },
        GuardedRoute {
            name: "GET /v1/wallets/:id/transactions",
            method: "GET",
            path: |id| format!("/v1/wallets/{id}/transactions"),
        },
        GuardedRoute {
            name: "POST /v1/wallets/:id/addresses",
            method: "POST",
            path: |id| format!("/v1/wallets/{id}/addresses"),
        },
        GuardedRoute {
            name: "GET /v1/wallets/:id/addresses",
            method: "GET",
            path: |id| format!("/v1/wallets/{id}/addresses"),
        },
        GuardedRoute {
            name: "POST /v1/wallets/:id/webhooks",
            method: "POST",
            path: |id| format!("/v1/wallets/{id}/webhooks"),
        },
        GuardedRoute {
            name: "GET /v1/wallets/:id/webhooks",
            method: "GET",
            path: |id| format!("/v1/wallets/{id}/webhooks"),
        },
        GuardedRoute {
            name: "GET /v1/wallets/:id/webhooks/:endpoint_id/deliveries",
            method: "GET",
            // authorize_wallet runs before the endpoint lookup, so an arbitrary endpoint id is
            // fine here — cross-wallet rejection must happen before we'd even check it exists.
            path: |id| {
                format!(
                    "/v1/wallets/{id}/webhooks/{}/deliveries",
                    uuid::Uuid::new_v4()
                )
            },
        },
        GuardedRoute {
            name: "GET /v1/wallets/:id/gas-tank",
            method: "GET",
            path: |id| format!("/v1/wallets/{id}/gas-tank"),
        },
        GuardedRoute {
            name: "GET /v1/wallets/:id/sponsorship",
            method: "GET",
            path: |id| format!("/v1/wallets/{id}/sponsorship"),
        },
        GuardedRoute {
            name: "PUT /v1/wallets/:id/sponsorship",
            method: "PUT",
            path: |id| format!("/v1/wallets/{id}/sponsorship"),
        },
        GuardedRoute {
            name: "POST /v1/wallets/:id/sponsor",
            method: "POST",
            path: |id| format!("/v1/wallets/{id}/sponsor"),
        },
    ]
}

/// A JWT-authenticated user (not an API key) must be rejected with 404 — not 401/403, which would
/// reveal the wallet exists — from every `authorize_wallet`-guarded route when targeting a wallet
/// they don't own. Checked in both directions: A's JWT against B's wallet, and B's JWT against
/// A's wallet.
#[tokio::test]
async fn jwt_owner_of_wallet_a_is_404_on_every_guarded_route_for_wallet_b() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());

    let token_a = auth_token(&app, &state).await;
    let wallet_a = create_wallet(&app, &token_a).await;

    let token_b = auth_token(&app, &state).await;
    let wallet_b = create_wallet(&app, &token_b).await;

    for route in guarded_routes() {
        // A's JWT against B's wallet.
        let uri = (route.path)(&wallet_b);
        let resp = app
            .clone()
            .oneshot(req_auth(route.method, &uri, &token_a))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{}: user A's JWT against B's wallet must be 404, got {}",
            route.name,
            resp.status()
        );

        // Vice versa: B's JWT against A's wallet.
        let uri = (route.path)(&wallet_a);
        let resp = app
            .clone()
            .oneshot(req_auth(route.method, &uri, &token_b))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{}: user B's JWT against A's wallet must be 404, got {}",
            route.name,
            resp.status()
        );
    }
}

/// An API key minted for wallet A must be rejected with 404 (not 401/403) from every
/// `authorize_wallet`-guarded route when used against wallet B's id.
#[tokio::test]
async fn api_key_for_wallet_a_is_404_on_every_guarded_route_for_wallet_b() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());

    let token_a = auth_token(&app, &state).await;
    let wallet_a = create_wallet(&app, &token_a).await;
    let key_a = api_key_for(&app, &token_a, &wallet_a).await;

    let token_b = auth_token(&app, &state).await;
    let wallet_b = create_wallet(&app, &token_b).await;

    for route in guarded_routes() {
        let uri = (route.path)(&wallet_b);
        let resp = app
            .clone()
            .oneshot(req_auth(route.method, &uri, &key_a))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{}: wallet A's API key against B's wallet must be 404, got {}",
            route.name,
            resp.status()
        );
    }
}

// ---------------------------------------------------------------------------
// payment_links.rs — owner-authenticated routes mixed with fully public ones.
//
// Credential shapes: no credential, a stranger's login, the owner's login, the owner wallet's API
// key, and a stranger wallet's API key. Owner routes go through `authorize_wallet`; the public
// `/v1/pay/*` routes must ignore credentials entirely, so every credential must get the identical
// response. Public routes are exercised on paths that never reach Horizon (offline-deterministic).
// ---------------------------------------------------------------------------

/// A JSON-body request with an optional bearer credential.
fn req_json(method: &str, uri: &str, token: Option<&str>, body: &str) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    b.body(Body::from(body.to_string())).unwrap()
}

/// Send `req` and return `(status, body json)`.
async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or_default())
}

/// Create a payment link on `wallet_id` as its owner and return `(link_id, slug)`.
async fn create_link(app: &axum::Router, token: &str, wallet_id: &str) -> (String, String) {
    let (status, json) = send(
        app,
        req_json(
            "POST",
            &format!("/v1/wallets/{wallet_id}/payment-links"),
            Some(token),
            r#"{"name":"matrix link","amount_usdc_stroops":10000000}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    (
        json["data"]["id"].as_str().unwrap().to_string(),
        json["data"]["slug"].as_str().unwrap().to_string(),
    )
}

/// Every owner-authenticated payment-links route × every credential shape, with the exact expected
/// status in each cell.
#[tokio::test]
async fn payment_links_owner_routes_authorization_matrix() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());

    let owner = auth_token(&app, &state).await;
    let wallet = create_wallet(&app, &owner).await;
    let owner_key = api_key_for(&app, &owner, &wallet).await;
    let (link_id, _) = create_link(&app, &owner, &wallet).await;

    let stranger = auth_token(&app, &state).await;
    let stranger_wallet = create_wallet(&app, &stranger).await;
    let stranger_key = api_key_for(&app, &stranger, &stranger_wallet).await;

    let base = format!("/v1/wallets/{wallet}/payment-links");
    let one = format!("{base}/{link_id}");
    let payments = format!("{one}/payments");

    // (name, method, uri, body, success status)
    let routes: Vec<(&str, &str, &str, &str, StatusCode)> = vec![
        (
            "POST payment-links",
            "POST",
            &base,
            r#"{"name":"another","amount_usdc_stroops":5}"#,
            StatusCode::CREATED,
        ),
        ("GET payment-links", "GET", &base, "", StatusCode::OK),
        (
            "GET payment-links/:link_id",
            "GET",
            &one,
            "",
            StatusCode::OK,
        ),
        (
            "PUT payment-links/:link_id",
            "PUT",
            &one,
            r#"{"active":true}"#,
            StatusCode::OK,
        ),
        (
            "GET payment-links/:link_id/payments",
            "GET",
            &payments,
            "",
            StatusCode::OK,
        ),
    ];

    for (name, method, uri, body, ok) in routes {
        let cells: [(&str, Option<&str>, StatusCode); 5] = [
            ("no credential", None, StatusCode::UNAUTHORIZED),
            ("wrong-owner login", Some(&stranger), StatusCode::NOT_FOUND),
            (
                "wrong-wallet API key",
                Some(&stranger_key),
                StatusCode::NOT_FOUND,
            ),
            ("correct-owner login", Some(&owner), ok),
            ("correct-wallet API key", Some(&owner_key), ok),
        ];
        for (cred, token, expected) in cells {
            let (status, _) = send(&app, req_json(method, uri, token, body)).await;
            assert_eq!(status, expected, "{name} with {cred}");
        }
    }
}

/// A stranger acting through *their own* wallet id but the victim's link id must not reach the
/// victim's link — no IDOR via a mismatched (wallet, link) pair.
#[tokio::test]
async fn payment_links_owner_routes_reject_a_foreign_link_id_under_your_own_wallet() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());

    let victim = auth_token(&app, &state).await;
    let victim_wallet = create_wallet(&app, &victim).await;
    let (victim_link, _) = create_link(&app, &victim, &victim_wallet).await;

    let attacker = auth_token(&app, &state).await;
    let attacker_wallet = create_wallet(&app, &attacker).await;
    let attacker_key = api_key_for(&app, &attacker, &attacker_wallet).await;
    let one = format!("/v1/wallets/{attacker_wallet}/payment-links/{victim_link}");
    let payments = format!("{one}/payments");

    for token in [&attacker, &attacker_key] {
        for (method, uri, body) in [
            ("GET", &one, ""),
            ("PUT", &one, r#"{"active":false}"#),
            ("GET", &payments, ""),
        ] {
            let (status, _) = send(&app, req_json(method, uri, Some(token), body)).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}");
        }
    }
    // The victim's link is untouched.
    let uri = format!("/v1/wallets/{victim_wallet}/payment-links/{victim_link}");
    let (status, json) = send(&app, req_json("GET", &uri, Some(&victim), "")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["data"]["active"], true);
}

/// Every public `/v1/pay/*` route must answer identically whatever credential is presented — a
/// credential must neither be required nor change the outcome.
#[tokio::test]
async fn payment_links_public_routes_ignore_credentials() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());

    let owner = auth_token(&app, &state).await;
    let wallet = create_wallet(&app, &owner).await;
    let owner_key = api_key_for(&app, &owner, &wallet).await;
    let stranger = auth_token(&app, &state).await;
    let (_, slug) = create_link(&app, &owner, &wallet).await;
    // An inactive link makes signing-info 404 before it would ever call Horizon.
    let (inactive_id, inactive_slug) = create_link(&app, &owner, &wallet).await;
    let uri = format!("/v1/wallets/{wallet}/payment-links/{inactive_id}");
    let (status, _) = send(
        &app,
        req_json("PUT", &uri, Some(&owner), r#"{"active":false}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // A real payment intent to poll (created without a credential).
    let (status, json) = send(
        &app,
        req_json("POST", &format!("/v1/pay/{slug}/intent"), None, "{}"),
    )
    .await;
    // The link is fixed-amount, so an empty body is a valid intent.
    assert_eq!(status, StatusCode::CREATED);
    let payment_id = json["data"]["payment_id"].as_str().unwrap().to_string();

    let get_link = format!("/v1/pay/{slug}");
    let intent = format!("/v1/pay/{slug}/intent");
    let status_uri = format!("/v1/pay/{slug}/payments/{payment_id}");
    let signing = format!("/v1/pay/{inactive_slug}/signing-info");
    let submit = format!("/v1/pay/{slug}/submit-signed");

    // (name, method, uri, body, expected status)
    let routes: Vec<(&str, &str, &str, &str, StatusCode)> = vec![
        ("GET pay/:slug", "GET", &get_link, "", StatusCode::OK),
        (
            "POST pay/:slug/intent",
            "POST",
            &intent,
            "{}",
            StatusCode::CREATED,
        ),
        (
            "GET pay/:slug/payments/:id",
            "GET",
            &status_uri,
            "",
            StatusCode::OK,
        ),
        (
            "GET pay/:slug/signing-info",
            "GET",
            &signing,
            "",
            StatusCode::NOT_FOUND,
        ),
        (
            "POST pay/:slug/submit-signed",
            "POST",
            &submit,
            "{}",
            StatusCode::BAD_REQUEST,
        ),
    ];

    for (name, method, uri, body, expected) in routes {
        let creds: [(&str, Option<&str>); 4] = [
            ("no credential", None),
            ("stranger login", Some(&stranger)),
            ("owner login", Some(&owner)),
            ("owner API key", Some(&owner_key)),
        ];
        for (cred, token) in creds {
            let (status, _) = send(&app, req_json(method, uri, token, body)).await;
            assert_eq!(status, expected, "{name} with {cred}");
        }
    }
}
