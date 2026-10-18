//! Regression test asserting request-body size limits apply uniformly across every mutating route.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use octo_api::{build_router, AppState, REQUEST_BODY_LIMIT};
use octo_store::Store;
use octo_wallet_core::StellarNetwork;
use std::sync::Once;
use tower::ServiceExt;

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
    let master_key = [42u8; 32];
    Some(AppState::new(
        store,
        master_key,
        StellarNetwork::Testnet,
        "https://horizon-testnet.stellar.org".into(),
        None,
        octo_email::EmailSender::new_captured(),
    ))
}

struct MutatingRoute {
    method: &'static str,
    path: &'static str,
}

const MUTATING_ROUTES: &[MutatingRoute] = &[
    MutatingRoute {
        method: "POST",
        path: "/v1/auth/signup",
    },
    MutatingRoute {
        method: "POST",
        path: "/v1/auth/verify-email",
    },
    MutatingRoute {
        method: "POST",
        path: "/v1/auth/resend-otp",
    },
    MutatingRoute {
        method: "POST",
        path: "/v1/auth/login",
    },
    MutatingRoute {
        method: "POST",
        path: "/v1/auth/refresh",
    },
    MutatingRoute {
        method: "PATCH",
        path: "/v1/auth/me",
    },
    MutatingRoute {
        method: "POST",
        path: "/v1/wallets",
    },
    MutatingRoute {
        method: "POST",
        path: "/v1/wallets/00000000-0000-0000-0000-000000000000/addresses",
    },
    MutatingRoute {
        method: "POST",
        path: "/v1/wallets/00000000-0000-0000-0000-000000000000/webhooks",
    },
    MutatingRoute {
        method: "POST",
        path: "/v1/wallets/00000000-0000-0000-0000-000000000000/submit-signed",
    },
    MutatingRoute {
        method: "POST",
        path: "/v1/wallets/00000000-0000-0000-0000-000000000000/withdraw/request-otp",
    },
    MutatingRoute {
        method: "POST",
        path: "/v1/wallets/00000000-0000-0000-0000-000000000000/withdraw/confirm",
    },
    MutatingRoute {
        method: "POST",
        path: "/v1/wallets/00000000-0000-0000-0000-000000000000/gas-tank",
    },
    MutatingRoute {
        method: "PUT",
        path: "/v1/wallets/00000000-0000-0000-0000-000000000000/sponsorship",
    },
    MutatingRoute {
        method: "POST",
        path: "/v1/wallets/00000000-0000-0000-0000-000000000000/sponsor",
    },
    MutatingRoute {
        method: "PUT",
        path: "/v1/wallets/00000000-0000-0000-0000-000000000000/whitelist/config",
    },
    MutatingRoute {
        method: "POST",
        path: "/v1/wallets/00000000-0000-0000-0000-000000000000/whitelist",
    },
    MutatingRoute {
        method: "POST",
        path: "/v1/wallets/00000000-0000-0000-0000-000000000000/payment-links",
    },
    MutatingRoute {
        method: "PUT",
        path: "/v1/wallets/00000000-0000-0000-0000-000000000000/payment-links/00000000-0000-0000-0000-000000000000",
    },
    MutatingRoute {
        method: "POST",
        path: "/v1/pay/sample-link/intent",
    },
    MutatingRoute {
        method: "POST",
        path: "/v1/pay/sample-link/submit-signed",
    },
];

#[tokio::test]
async fn every_mutating_route_rejects_an_oversized_body_with_a_clean_413() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state);

    // Create an oversized body exceeding REQUEST_BODY_LIMIT (64 KiB).
    let oversized_body = vec![b'a'; REQUEST_BODY_LIMIT + 1024];

    for route in MUTATING_ROUTES {
        let req = Request::builder()
            .method(route.method)
            .uri(route.path)
            .header("content-type", "application/json")
            .body(Body::from(oversized_body.clone()))
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "route {} {} must reject oversized body with 413 Payload Too Large",
            route.method,
            route.path
        );

        let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        assert!(
            !bytes.is_empty(),
            "route {} {} 413 response should explain itself",
            route.method,
            route.path
        );
    }
}
