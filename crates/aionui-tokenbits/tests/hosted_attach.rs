use aionui_api_types::tokenbits::*;
use aionui_common::{decrypt_string, encrypt_string};
use aionui_db::{
    Database, ExternalUserProjection, ITokenBitsRepository, IUserRepository, SqliteTokenBitsRepository,
    SqliteUserRepository, UserStatus, UserType, init_database_memory,
};
use aionui_tokenbits::{
    client::TokenBitsClient, error::TokenBitsError, routes::hosted_routes, service::TokenBitsService,
    state::TokenBitsHostedRouterState,
};
use axum::{Router, body::Body, http::Request};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

const KEY: [u8; 32] = [42; 32];
const SECRET: &str = "hosted-fixture-bootstrap-secret-at-least-32";
const ENDPOINT: &str = "/api/integrations/tokenbits/internal/attach";

struct Fixture {
    _db: Database,
    service: Arc<TokenBitsService>,
    repo: Arc<SqliteTokenBitsRepository>,
    users: Arc<SqliteUserRepository>,
    user: String,
    external: String,
}

async fn fixture(server: &MockServer) -> Fixture {
    let db = init_database_memory().await.unwrap();
    let repo = Arc::new(SqliteTokenBitsRepository::new(db.pool().clone()));
    let users = Arc::new(SqliteUserRepository::new(db.pool().clone()));
    let external = format!("tokenbits:{:x}:42", Sha256::digest(server.uri().as_bytes()));
    let user = users
        .ensure_external_user(UserType::Aionpro, &external, ExternalUserProjection::default())
        .await
        .unwrap();
    let service = Arc::new(
        TokenBitsService::new(repo.clone(), KEY, TokenBitsClient::new(&server.uri()).unwrap())
            .with_hosted_account(42, users.clone())
            .unwrap(),
    );
    Fixture {
        _db: db,
        service,
        repo,
        users,
        user: user.id,
        external,
    }
}

fn request(f: &Fixture, device_id: i64) -> TokenBitsHostedAttachRequest {
    TokenBitsHostedAttachRequest {
        external_user_id: f.external.clone(),
        client_id: "aionui-web".into(),
        access_token: "wb_at_incoming".into(),
        refresh_token: "wb_rt_incoming".into(),
        device_id,
        expires_in: 900,
    }
}

async fn account(server: &MockServer, token: &str, id: i64) {
    Mock::given(method("GET")).and(path("/api/workbench/account")).and(header("authorization",format!("Bearer {token}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success":true,"data":{
            "account":{"id":id,"display_name":"Fixture"},"wallet_quota":0,"quota_per_unit":500000,
            "billing_preference":"wallet","subscriptions":[],"updated_at":1,"topup_url":format!("{}/console/topup",server.uri())}})))
        .mount(server).await;
}

fn app(f: &Fixture) -> Router {
    hosted_routes(TokenBitsHostedRouterState {
        service: f.service.clone(),
        bootstrap_secret: Arc::from(SECRET),
    })
}

async fn call(f: &Fixture, headers: &[(&str, &str)], value: Value) -> (u16, Value, String) {
    let mut req = Request::builder()
        .method("POST")
        .uri(ENDPOINT)
        .header("content-type", "application/json");
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    let response = app(f)
        .oneshot(req.body(Body::from(value.to_string())).unwrap())
        .await
        .unwrap();
    let code = response.status().as_u16();
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    (code, serde_json::from_str(&text).unwrap(), text)
}

#[tokio::test]
async fn private_route_rejects_browser_credentials_wrong_secret_and_unknown_fields() {
    let server = MockServer::start().await;
    let f = fixture(&server).await;
    let value = serde_json::to_value(request(&f, 7)).unwrap();
    for headers in [
        vec![],
        vec![("x-aioncore-bootstrap-secret", "wrong")],
        vec![("cookie", "aionui-session=anything")],
    ] {
        let (code, body, _) = call(&f, &headers, value.clone()).await;
        assert_eq!(code, 401);
        assert_eq!(body["code"], "INVALID_BOOTSTRAP_SECRET");
    }
    for browser_header in [
        ("origin", "https://workbench.example"),
        ("cookie", "aionui-session=anything"),
        ("sec-fetch-mode", "cors"),
    ] {
        let (code, body, _) = call(
            &f,
            &[("x-aioncore-bootstrap-secret", SECRET), browser_header],
            value.clone(),
        )
        .await;
        assert_eq!(code, 403);
        assert_eq!(body["code"], "TOKENBITS_INTERNAL_ONLY");
    }
    let mut unknown = value;
    unknown["issuer"] = json!("https://attacker.example");
    assert_eq!(
        call(&f, &[("x-aioncore-bootstrap-secret", SECRET)], unknown).await.0,
        400
    );
    assert!(server.received_requests().await.unwrap().is_empty());
    assert!(f.repo.load(&f.user).await.unwrap().is_none());
}

#[tokio::test]
async fn first_import_is_encrypted_response_is_secret_free_and_same_device_retry_is_stable() {
    let server = MockServer::start().await;
    let f = fixture(&server).await;
    account(&server, "wb_at_incoming", 42).await;
    let value = serde_json::to_value(request(&f, 7)).unwrap();
    let (code, body, text) = call(&f, &[("x-aioncore-bootstrap-secret", SECRET)], value.clone()).await;
    assert_eq!(code, 200);
    assert_eq!(body["data"]["imported"], true);
    assert_eq!(body["data"]["status"]["account"]["id"], 42);
    assert!(!text.contains("wb_at_"));
    assert!(!text.contains("wb_rt_"));
    let cipher = f.repo.load(&f.user).await.unwrap().unwrap();
    assert!(!cipher.contains("wb_rt_incoming"));
    assert!(decrypt_string(&cipher, &KEY).unwrap().contains("wb_rt_incoming"));
    assert_eq!(
        call(&f, &[("x-aioncore-bootstrap-secret", SECRET)], value).await.1["data"]["imported"],
        true
    );
    assert_eq!(f.repo.load(&f.user).await.unwrap().unwrap(), cipher);
}

#[tokio::test]
async fn other_account_or_mapping_disabled_user_and_invalid_payload_never_write() {
    let server = MockServer::start().await;
    let f = fixture(&server).await;
    account(&server, "wb_at_incoming", 99).await;
    assert!(matches!(
        f.service.attach_hosted(request(&f, 7)).await,
        Err(TokenBitsError::AccountBinding)
    ));
    let mut other = request(&f, 7);
    other.external_user_id = other.external_user_id.replace(":42", ":99");
    assert!(matches!(
        f.service.attach_hosted(other).await,
        Err(TokenBitsError::AccountBinding)
    ));
    let mut bad = request(&f, 7);
    bad.expires_in = 0;
    assert!(matches!(
        f.service.attach_hosted(bad).await,
        Err(TokenBitsError::InvalidRequest)
    ));
    f.users.set_status(&f.user, UserStatus::Disabled).await.unwrap();
    assert!(matches!(
        f.service.attach_hosted(request(&f, 7)).await,
        Err(TokenBitsError::AccountBinding)
    ));
    assert!(f.repo.load(&f.user).await.unwrap().is_none());
}

#[tokio::test]
async fn existing_other_device_is_retained_and_new_grant_is_marked_unused() {
    let server = MockServer::start().await;
    let f = fixture(&server).await;
    account(&server, "wb_at_incoming", 42).await;
    assert!(f.service.attach_hosted(request(&f, 7)).await.unwrap().imported);
    let before = f.repo.load(&f.user).await.unwrap().unwrap();
    let result = f.service.attach_hosted(request(&f, 8)).await.unwrap();
    assert!(!result.imported);
    assert_eq!(result.status.device_id, Some(7));
    assert_eq!(f.repo.load(&f.user).await.unwrap().unwrap(), before);
}

#[tokio::test]
async fn refresh_rotation_is_preserved_during_same_device_import_retry() {
    let server = MockServer::start().await;
    let f = fixture(&server).await;
    account(&server, "wb_at_incoming", 42).await;
    f.service.attach_hosted(request(&f, 7)).await.unwrap();
    // The old access token has already become invalid upstream. A lost-response
    // retry must retain the refreshed device, not attempt to import this old pair.
    server.reset().await;
    account(&server, "wb_at_rotated", 42).await;
    let mut stored: Value =
        serde_json::from_str(&decrypt_string(&f.repo.load(&f.user).await.unwrap().unwrap(), &KEY).unwrap()).unwrap();
    stored["expires_at"] = json!(0);
    f.repo
        .save(&f.user, &encrypt_string(&stored.to_string(), &KEY).unwrap())
        .await
        .unwrap();
    Mock::given(method("POST"))
        .and(path("/api/workbench/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success":true,"data":{
            "access_token":"wb_at_rotated","refresh_token":"wb_rt_rotated","device_id":7,"expires_in":900}})))
        .expect(1)
        .mount(&server)
        .await;
    assert!(f.service.attach_hosted(request(&f, 7)).await.unwrap().imported);
    let after = decrypt_string(&f.repo.load(&f.user).await.unwrap().unwrap(), &KEY).unwrap();
    assert!(after.contains("wb_rt_rotated"));
    assert!(!after.contains("wb_rt_incoming"));
}

#[tokio::test]
async fn failed_issuer_check_does_not_replace_a_connection() {
    let server = MockServer::start().await;
    let f = fixture(&server).await;
    account(&server, "wb_at_incoming", 42).await;
    f.service.attach_hosted(request(&f, 7)).await.unwrap();
    let before = f.repo.load(&f.user).await.unwrap().unwrap();
    let mut incoming = request(&f, 8);
    incoming.access_token = "unrecognized".into();
    assert!(f.service.attach_hosted(incoming).await.is_err());
    assert_eq!(f.repo.load(&f.user).await.unwrap().unwrap(), before);
    // A forged same-device request is not an exact retry of the retained pair.
    account(&server, "wb_at_other_account", 99).await;
    let mut same_device = request(&f, 7);
    same_device.access_token = "wb_at_other_account".into();
    assert!(matches!(
        f.service.attach_hosted(same_device).await,
        Err(TokenBitsError::AccountBinding)
    ));
    assert_eq!(f.repo.load(&f.user).await.unwrap().unwrap(), before);
}

#[tokio::test]
async fn explicit_disconnect_allows_a_new_import_without_automatic_reconnection() {
    let server = MockServer::start().await;
    let f = fixture(&server).await;
    account(&server, "wb_at_incoming", 42).await;
    f.service.attach_hosted(request(&f, 7)).await.unwrap();
    Mock::given(method("DELETE"))
        .and(path("/api/workbench/device"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success":true,"data":{}})))
        .expect(1)
        .mount(&server)
        .await;
    f.service.disconnect(&f.user).await.unwrap();
    assert!(!f.service.status(&f.user).await.unwrap().connected);
    assert!(f.repo.load(&f.user).await.unwrap().is_none());
    assert!(f.service.attach_hosted(request(&f, 8)).await.unwrap().imported);
    assert_eq!(f.service.status(&f.user).await.unwrap().device_id, Some(8));
}

#[tokio::test]
async fn hosted_browser_flow_rejects_a_different_account_before_persistence() {
    let server = MockServer::start().await;
    let f = fixture(&server).await;
    account(&server, "wb_at_incoming", 99).await;
    let start = f
        .service
        .start_browser_authorization(
            &f.user,
            TokenBitsBrowserAuthorizeRequest {
                client_id: "aionui-web".into(),
                device_name: "Fixture".into(),
                redirect_uri: Some("https://workbench.example/tokenbits/callback".into()),
            },
            None,
        )
        .await
        .unwrap();
    let state = reqwest::Url::parse(&start.authorization.authorization_url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    Mock::given(method("POST"))
        .and(path("/api/workbench/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success":true,"data":{
            "access_token":"wb_at_incoming","refresh_token":"wb_rt_incoming","device_id":7,"expires_in":900}})))
        .mount(&server)
        .await;
    let result = f
        .service
        .complete_browser_authorization(
            &f.user,
            TokenBitsBrowserCompleteRequest {
                flow_id: start.authorization.flow_id,
                state,
                code: "wb_bc_012345678901234567890123456789012345678901234567".into(),
            },
            start.binding_cookie.as_deref(),
        )
        .await;
    assert!(matches!(result, Err(TokenBitsError::AccountBinding)));
    assert!(f.repo.load(&f.user).await.unwrap().is_none());
}

#[tokio::test]
async fn hosted_refresh_cannot_replace_credentials_with_another_account() {
    let server = MockServer::start().await;
    let f = fixture(&server).await;
    account(&server, "wb_at_incoming", 42).await;
    f.service.attach_hosted(request(&f, 7)).await.unwrap();
    let mut stored: Value =
        serde_json::from_str(&decrypt_string(&f.repo.load(&f.user).await.unwrap().unwrap(), &KEY).unwrap()).unwrap();
    stored["expires_at"] = json!(0);
    let before = encrypt_string(&stored.to_string(), &KEY).unwrap();
    f.repo.save(&f.user, &before).await.unwrap();
    account(&server, "wb_at_wrong_account", 99).await;
    Mock::given(method("POST")).and(path("/api/workbench/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success":true,"data":{
            "access_token":"wb_at_wrong_account","refresh_token":"wb_rt_wrong_account","device_id":7,"expires_in":900}})))
        .mount(&server).await;
    assert!(matches!(
        f.service.account(&f.user).await,
        Err(TokenBitsError::AccountBinding)
    ));
    assert_eq!(f.repo.load(&f.user).await.unwrap().unwrap(), before);
}

#[tokio::test]
async fn unprovisioned_or_local_user_cannot_be_used_as_the_hosted_subject() {
    let server = MockServer::start().await;
    let db = init_database_memory().await.unwrap();
    let repo = Arc::new(SqliteTokenBitsRepository::new(db.pool().clone()));
    let users = Arc::new(SqliteUserRepository::new(db.pool().clone()));
    let service = TokenBitsService::new(repo.clone(), KEY, TokenBitsClient::new(&server.uri()).unwrap())
        .with_hosted_account(42, users)
        .unwrap();
    let req = TokenBitsHostedAttachRequest {
        external_user_id: format!("tokenbits:{:x}:42", Sha256::digest(server.uri().as_bytes())),
        client_id: "aionui-web".into(),
        access_token: "wb_at_incoming".into(),
        refresh_token: "wb_rt_incoming".into(),
        device_id: 7,
        expires_in: 900,
    };
    assert!(matches!(
        service.attach_hosted(req).await,
        Err(TokenBitsError::AccountBinding)
    ));
    assert!(matches!(
        service
            .authorize(
                "system_default_user",
                TokenBitsAuthorizeRequest {
                    client_id: "aionui-web".into(),
                    device_name: "Fixture".into(),
                }
            )
            .await,
        Err(TokenBitsError::AccountBinding)
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}
