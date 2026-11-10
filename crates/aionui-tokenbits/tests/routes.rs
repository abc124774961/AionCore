use aionui_auth::{AuthIdentityMode, AuthState, JwtService, auth_middleware};
use aionui_db::{SqliteTokenBitsRepository, SqliteUserRepository, init_database_memory};
use aionui_tokenbits::{
    client::TokenBitsClient, routes::domain_routes, service::TokenBitsService, state::TokenBitsRouterState,
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware,
};
use std::sync::Arc;
use tower::ServiceExt;

const SECRET: &str = "a-test-local-secret-with-at-least-32-bytes";

async fn app(local: bool) -> (axum::Router, aionui_db::Database) {
    let db = init_database_memory().await.unwrap();
    let service = Arc::new(TokenBitsService::new(
        Arc::new(SqliteTokenBitsRepository::new(db.pool().clone())),
        [42; 32],
        TokenBitsClient::new("https://api.tokenbits.net").unwrap(),
    ));
    let auth = AuthState {
        jwt_service: Arc::new(JwtService::new("test-secret".into())),
        user_repo: Arc::new(SqliteUserRepository::new(db.pool().clone())),
        identity_mode: if local {
            AuthIdentityMode::Local
        } else {
            AuthIdentityMode::UserSession
        },
        runtime_token_verifier: None,
    };
    let router = domain_routes(TokenBitsRouterState {
        service,
        local,
        local_secret: Some(SECRET.into()),
    })
    .layer(middleware::from_fn_with_state(auth, auth_middleware));
    (router, db)
}

async fn body(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn web_requires_authentication() {
    let (app, _db) = app(false).await;
    let response = app
        .oneshot(
            Request::get("/api/integrations/tokenbits/status")
                .header("x-aionui-integration", "tokenbits")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn local_secret_and_origin_protect_account_reads_and_writes() {
    let (app, _db) = app(true).await;
    for method in ["GET", "DELETE"] {
        let path = if method == "GET" { "status" } else { "connection" };
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(format!("/api/integrations/tokenbits/{path}"))
                    .header("x-aionui-integration", "tokenbits")
                    .header("origin", "null")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(body(response).await["code"], "TOKENBITS_LOCAL_AUTH");
    }
    let response = app
        .clone()
        .oneshot(
            Request::get("/api/integrations/tokenbits/status")
                .header("x-aionui-integration", "tokenbits")
                .header("x-aionui-local-secret", SECRET)
                .header("origin", "https://evil.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body(response).await["code"], "TOKENBITS_ORIGIN");
    let response = app
        .oneshot(
            Request::get("/api/integrations/tokenbits/status")
                .header("x-aionui-integration", "tokenbits")
                .header("x-aionui-local-secret", SECRET)
                .header("origin", "null")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(body(response).await["data"]["connected"], false);
}

#[tokio::test]
async fn web_state_changes_require_csrf() {
    let (router, _db) = app(false).await;
    let router = router.layer(middleware::from_fn_with_state(
        Arc::new(aionui_auth::CookieConfig {
            secure: false,
            same_site: "Lax",
        }),
        aionui_auth::csrf_middleware,
    ));
    let response = router
        .oneshot(
            Request::post("/api/integrations/tokenbits/device-authorizations")
                .header("content-type", "application/json")
                .header("x-aionui-integration", "tokenbits")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body(response).await["code"], "CSRF_INVALID");
}

#[tokio::test]
async fn conversation_helper_headers_cannot_authenticate_integration() {
    let (app, _db) = app(false).await;
    let response = app
        .oneshot(
            Request::get("/api/integrations/tokenbits/status")
                .header("x-aionui-integration", "tokenbits")
                .header("x-aionui-runtime-token", "conversation-helper")
                .header("x-aionui-user-id", "system_default_user")
                .header("x-aionui-conversation-id", "conversation-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
