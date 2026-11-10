use aionui_api_types::tokenbits::*;
use aionui_common::{decrypt_string, encrypt_string};
use aionui_db::{
    IProviderRepository, ITokenBitsRepository, SqliteProviderRepository, SqliteTokenBitsRepository,
    init_database_memory,
};
use aionui_tokenbits::{client::TokenBitsClient, error::TokenBitsError, service::TokenBitsService};
use serde_json::{Value, json};
use std::sync::Arc;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, method, path},
};

const USER: &str = "system_default_user";
const KEY: [u8; 32] = [42; 32];

async fn setup(
    server: &MockServer,
) -> (
    Arc<TokenBitsService>,
    Arc<SqliteTokenBitsRepository>,
    aionui_db::Database,
) {
    let db = init_database_memory().await.unwrap();
    let repo = Arc::new(SqliteTokenBitsRepository::new(db.pool().clone()));
    let service = Arc::new(TokenBitsService::new(
        repo.clone(),
        KEY,
        TokenBitsClient::new(&server.uri()).unwrap(),
    ));
    (service, repo, db)
}

fn envelope(value: Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({"success":true,"data":value}))
}
fn account(base: &str) -> Value {
    json!({"account":{"id":11,"display_name":"Alice"},"wallet_quota":42,"quota_per_unit":100,"billing_preference":"wallet_only","subscriptions":[],"updated_at":1,"topup_url":format!("{base}/console/topup")})
}
fn catalog(base: &str) -> Value {
    let model =
        json!({"id":"model-one","supported_endpoint_types":["openai"],"pricing":{"url":format!("{base}/pricing")}});
    json!({"provider":"aionui","groups":[{"id":"default","name":"Default","models":[model.clone()],"recommended_model":"model-one","recommendation_reason":"available"}],
        "group":"default","models":[model],"recommended_model":"model-one","recommendation_reason":"available","billing":{},"api_base_url":format!("{base}/v1"),"protocol":"openai"})
}

async fn seed(repo: &SqliteTokenBitsRepository, server: &MockServer, expires_at: i64) {
    let state = json!({"issuer":server.uri(),"client_id":"aionui-desktop","access_token":"wb_at_old","refresh_token":"wb_rt_old",
        "device_id":7,"expires_at":expires_at,"exchange_id":"stable-retry-id","account":null,"last_sync_at":null,"needs_reauthorization":false});
    repo.save(USER, &encrypt_string(&state.to_string(), &KEY).unwrap())
        .await
        .unwrap();
}

#[tokio::test]
async fn device_pkce_sync_encrypted_keys_and_disconnect() {
    let server = MockServer::start().await;
    let (service, repo, db) = setup(&server).await;
    Mock::given(method("POST")).and(path("/api/workbench/authorizations"))
        .respond_with(envelope(json!({"device_code":"secret-device","user_code":"ABCD","verification_uri":format!("{}/aionui/authorize",server.uri()),
            "verification_uri_complete":format!("{}/aionui/authorize?user_code=ABCD",server.uri()),"expires_in":600,"interval":1}))).expect(1).mount(&server).await;
    let flow = service
        .authorize(
            USER,
            TokenBitsAuthorizeRequest {
                client_id: "aionui-desktop".into(),
                device_name: "Test".into(),
            },
        )
        .await
        .unwrap();
    let visible = serde_json::to_string(&flow).unwrap();
    assert!(!visible.contains("secret-device"));
    assert!(matches!(
        service.poll("other-user", &flow.flow_id).await,
        Err(TokenBitsError::NotFound)
    ));
    assert_eq!(service.poll(USER, &flow.flow_id).await.unwrap().status, "slow_down");
    Mock::given(method("POST"))
        .and(path("/api/workbench/token"))
        .and(body_partial_json(
            json!({"grant_type":"device_code","device_code":"secret-device"}),
        ))
        .respond_with(envelope(
            json!({"access_token":"wb_at_secret","refresh_token":"wb_rt_secret","device_id":7,"expires_in":900}),
        ))
        .expect(1)
        .mount(&server)
        .await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert_eq!(service.poll(USER, &flow.flow_id).await.unwrap().status, "authorized");
    let requests = server.received_requests().await.unwrap();
    let auth: Value = serde_json::from_slice(&requests[0].body).unwrap();
    let token: Value = serde_json::from_slice(&requests[1].body).unwrap();
    use base64::Engine;
    use sha2::Digest;
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(
        token["code_verifier"].as_str().unwrap().as_bytes(),
    ));
    assert_eq!(auth["code_challenge"], challenge);
    assert_eq!(token["exchange_id"], flow.flow_id);
    let cipher = repo.load(USER).await.unwrap().unwrap();
    assert!(!cipher.contains("wb_at_secret"));
    assert!(decrypt_string(&cipher, &KEY).unwrap().contains("wb_rt_secret"));
    assert!(
        !serde_json::to_string(&service.status(USER).await.unwrap())
            .unwrap()
            .contains("wb_at_")
    );
    Mock::given(method("GET"))
        .and(path("/api/workbench/catalog"))
        .respond_with(envelope(catalog(&server.uri())))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/workbench/connections"))
        .respond_with(envelope(json!({"id":5,"model":"model-one","group":"default"})))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/workbench/connections/5/key"))
        .respond_with(envelope(json!({"key":"sk-single-model-secret"})))
        .expect(2)
        .mount(&server)
        .await;
    let req = || TokenBitsSyncRequest {
        group: "default".into(),
        models: vec!["model-one".into()],
    };
    let first = service.sync(USER, req()).await.unwrap();
    let second = service.sync(USER, req()).await.unwrap();
    assert_eq!(first.providers[0].provider_id, second.providers[0].provider_id);
    let providers = SqliteProviderRepository::new(db.pool().clone());
    let rows = providers.list(USER).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].credential_source, "tokenbits");
    assert_eq!(rows[0].models, "[\"model-one\"]");
    assert_eq!(
        decrypt_string(&rows[0].api_key_encrypted, &KEY).unwrap(),
        "sk-single-model-secret"
    );
    assert_eq!(providers.list("other-user").await.unwrap().len(), 0);
    assert!(matches!(
        service
            .sync(
                USER,
                TokenBitsSyncRequest {
                    group: "wrong".into(),
                    models: vec![]
                }
            )
            .await,
        Err(TokenBitsError::InvalidRequest)
    ));
    Mock::given(method("DELETE"))
        .and(path("/api/workbench/device"))
        .respond_with(envelope(json!({"revoked":true})))
        .expect(1)
        .mount(&server)
        .await;
    service.disconnect(USER).await.unwrap();
    assert!(repo.load(USER).await.unwrap().is_none());
    let rows = providers.list(USER).await.unwrap();
    assert!(!rows[0].enabled);
    assert!(rows[0].api_key_encrypted.is_empty());
}

#[tokio::test]
async fn concurrent_refresh_is_single_flight_and_rotates_ciphertext() {
    let server = MockServer::start().await;
    let (service, repo, _) = setup(&server).await;
    seed(&repo, &server, 0).await;
    Mock::given(method("POST"))
        .and(path("/api/workbench/token"))
        .and(body_partial_json(
            json!({"grant_type":"refresh_token","refresh_token":"wb_rt_old","exchange_id":"stable-retry-id"}),
        ))
        .respond_with(envelope(
            json!({"access_token":"wb_at_new","refresh_token":"wb_rt_new","device_id":7,"expires_in":900}),
        ))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/workbench/account"))
        .respond_with(envelope(account(&server.uri())))
        .expect(8)
        .mount(&server)
        .await;
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let service = service.clone();
        tasks.push(tokio::spawn(async move { service.account(USER).await.unwrap() }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap().account.id, 11);
    }
    let stored: Value =
        serde_json::from_str(&decrypt_string(&repo.load(USER).await.unwrap().unwrap(), &KEY).unwrap()).unwrap();
    assert_eq!(stored["refresh_token"], "wb_rt_new");
    assert_ne!(stored["exchange_id"], "stable-retry-id");
}

#[tokio::test]
async fn refresh_retry_keeps_exchange_identity_and_revocation_disables_models() {
    let server = MockServer::start().await;
    let (service, repo, db) = setup(&server).await;
    seed(&repo, &server, 0).await;
    repo.upsert_provider(aionui_db::ManagedProviderInput {
        group: "default",
        user_id: USER,
        connection_id: "5",
        model: "model-one",
        base_url: &format!("{}/v1", server.uri()),
        encrypted_key: &encrypt_string("sk-secret", &KEY).unwrap(),
    })
    .await
    .unwrap();
    Mock::given(path("/api/workbench/token"))
        .respond_with(
            ResponseTemplate::new(503).set_body_json(json!({"success":false,"code":"temporarily_unavailable"})),
        )
        .expect(2)
        .mount(&server)
        .await;
    for _ in 0..2 {
        assert!(matches!(service.account(USER).await, Err(TokenBitsError::Unavailable)));
    }
    for req in server.received_requests().await.unwrap() {
        let body: Value = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(body["exchange_id"], "stable-retry-id");
    }
    server.reset().await;
    Mock::given(path("/api/workbench/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"success":false,"code":"invalid_grant"})))
        .expect(1)
        .mount(&server)
        .await;
    assert!(matches!(
        service.account(USER).await,
        Err(TokenBitsError::Reauthorization)
    ));
    assert!(service.status(USER).await.unwrap().needs_reauthorization);
    assert!(
        !SqliteProviderRepository::new(db.pool().clone())
            .list(USER)
            .await
            .unwrap()[0]
            .enabled
    );
}

#[test]
fn issuer_is_fixed_origin_configuration_and_request_fields_reject_hosts() {
    assert!(TokenBitsClient::new("http://public.example").is_err());
    assert!(TokenBitsClient::new("https://user:password@example.com").is_err());
    assert!(TokenBitsClient::new("https://example.com/path").is_err());
    let client = TokenBitsClient::new("https://api.tokenbits.net").unwrap();
    assert!(client.validate_url("https://evil.example/v1").is_err());
    assert!(
        serde_json::from_value::<TokenBitsAuthorizeRequest>(
            json!({"client_id":"aionui-web","device_name":"Web","issuer":"https://evil.example"})
        )
        .is_err()
    );
}

#[tokio::test]
async fn expired_refresh_requires_reauthorization_and_unconfirmed_revoke_preserves_state() {
    let server = MockServer::start().await;
    let (service, repo, _db) = setup(&server).await;
    seed(&repo, &server, 0).await;
    Mock::given(path("/api/workbench/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"success":false,"code":"expired_token"})))
        .expect(1)
        .mount(&server)
        .await;
    assert!(matches!(
        service.account(USER).await,
        Err(TokenBitsError::Reauthorization)
    ));
    assert!(service.status(USER).await.unwrap().needs_reauthorization);
    Mock::given(method("DELETE"))
        .and(path("/api/workbench/device"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"success":false,"code":"unauthorized"})))
        .expect(1)
        .mount(&server)
        .await;
    assert!(matches!(
        service.disconnect(USER).await,
        Err(TokenBitsError::RevocationUnconfirmed)
    ));
    assert!(repo.load(USER).await.unwrap().is_some());
    server.reset().await;
    Mock::given(method("DELETE"))
        .and(path("/api/workbench/device"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"success":false,"code":"device_revoked"})))
        .expect(1)
        .mount(&server)
        .await;
    service.disconnect(USER).await.unwrap();
    assert!(repo.load(USER).await.unwrap().is_none());
}

#[tokio::test]
async fn syncing_one_group_preserves_other_managed_models() {
    let server = MockServer::start().await;
    let (_service, repo, db) = setup(&server).await;
    let key = encrypt_string("sk-key", &KEY).unwrap();
    let first = aionui_db::ManagedProviderInput {
        user_id: USER,
        connection_id: "one",
        group: "economy",
        model: "model",
        base_url: "https://api.tokenbits.net/v1",
        encrypted_key: &key,
    };
    let second = aionui_db::ManagedProviderInput {
        user_id: USER,
        connection_id: "two",
        group: "premium",
        model: "model",
        base_url: "https://api.tokenbits.net/v1",
        encrypted_key: &key,
    };
    repo.sync_providers(USER, &[first]).await.unwrap();
    repo.sync_providers(USER, &[second]).await.unwrap();
    let providers = SqliteProviderRepository::new(db.pool().clone())
        .list(USER)
        .await
        .unwrap();
    assert_eq!(providers.len(), 2);
    assert!(providers.iter().all(|p| p.enabled));
    assert!(providers.iter().any(|p| p.name.contains("economy")));
    assert!(providers.iter().any(|p| p.name.contains("premium")));
}
