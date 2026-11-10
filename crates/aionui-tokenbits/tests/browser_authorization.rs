use aionui_api_types::tokenbits::*;
use aionui_auth::{AuthIdentityMode, AuthState, CookieConfig, JwtService, auth_middleware, csrf_middleware};
use aionui_common::decrypt_string;
use aionui_db::{ITokenBitsRepository, SqliteTokenBitsRepository, SqliteUserRepository, init_database_memory};
use aionui_tokenbits::{
    client::TokenBitsClient, error::TokenBitsError, routes::domain_routes, service::TokenBitsService,
    state::TokenBitsRouterState,
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware,
};
use base64::Engine;
use serde_json::{Value, json};
use sha2::Digest;
use std::{collections::HashMap, sync::Arc};
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};
const USER: &str = "system_default_user";
const LOCAL_SECRET: &str = "browser-flow-test-local-secret-at-least-32";
const CODE: &str = "wb_bc_012345678901234567890123456789012345678901234567";
const BASE: &str = "/api/integrations/tokenbits/browser-authorizations";
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
        [42; 32],
        TokenBitsClient::new(&server.uri()).unwrap(),
    ));
    (service, repo, db)
}
fn req(web: bool) -> TokenBitsBrowserAuthorizeRequest {
    TokenBitsBrowserAuthorizeRequest {
        client_id: if web { "aionui-web" } else { "aionui-desktop" }.into(),
        device_name: "Browser fixture".into(),
        redirect_uri: Some(
            if web {
                "https://workbench.example/tokenbits/callback"
            } else {
                "http://127.0.0.1:39999/tokenbits/callback"
            }
            .into(),
        ),
    }
}
fn params(flow: &TokenBitsBrowserAuthorization) -> HashMap<String, String> {
    reqwest::Url::parse(&flow.authorization_url)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect()
}
fn complete(flow: &TokenBitsBrowserAuthorization, code: &str, state: &str) -> TokenBitsBrowserCompleteRequest {
    TokenBitsBrowserCompleteRequest {
        flow_id: flow.flow_id.clone(),
        code: code.into(),
        state: state.into(),
    }
}
async fn token_mock(server: &MockServer) {
    Mock::given(method("POST")).and(path("/api/workbench/token")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"success":true,"data":{"access_token":"wb_at_private","refresh_token":"wb_rt_private","device_id":7,"expires_in":900}}))).expect(1).mount(server).await;
}
async fn body(response: axum::response::Response) -> Value {
    serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 1024 * 1024).await.unwrap()).unwrap()
}

#[tokio::test]
async fn web_binding_pkce_isolation_replay_and_legacy_separation() {
    let server = MockServer::start().await;
    let (service, repo, _db) = setup(&server).await;
    let started = service
        .start_browser_authorization(USER, req(true), None)
        .await
        .unwrap();
    let flow = &started.authorization;
    let p = params(flow);
    let cookie = started.binding_cookie.as_deref().unwrap();
    let visible = serde_json::to_string(flow).unwrap();
    assert!(!visible.contains(cookie));
    assert!(!visible.contains("code_verifier"));
    assert_eq!(p["client_id"], "aionui-web");
    assert_eq!(p["redirect_uri"], "https://workbench.example/tokenbits/callback");
    assert_eq!(p["code_challenge_method"], "S256");
    assert!(matches!(
        service.poll(USER, &flow.flow_id).await,
        Err(TokenBitsError::NotFound)
    ));
    assert!(matches!(
        service
            .complete_browser_authorization("other-user", complete(flow, CODE, &p["state"]), Some(cookie))
            .await,
        Err(TokenBitsError::NotFound)
    ));
    for supplied in [None, Some("other-browser-cookie")] {
        assert!(matches!(
            service
                .complete_browser_authorization(USER, complete(flow, CODE, &p["state"]), supplied)
                .await,
            Err(TokenBitsError::BrowserBinding)
        ));
    }
    assert!(matches!(
        service
            .complete_browser_authorization(USER, complete(flow, CODE, "wrong-state"), Some(cookie))
            .await,
        Err(TokenBitsError::InvalidRequest)
    ));
    assert_eq!(
        service
            .browser_authorization_status(USER, &flow.flow_id)
            .await
            .unwrap()
            .status,
        "pending"
    );
    assert!(matches!(
        service
            .start_browser_authorization(USER, req(true), Some("other-browser"))
            .await,
        Err(TokenBitsError::BrowserBinding)
    ));
    let again = service
        .start_browser_authorization(USER, req(true), Some(cookie))
        .await
        .unwrap();
    assert_eq!(again.authorization.flow_id, flow.flow_id);
    assert!(again.binding_cookie.is_none());
    token_mock(&server).await;
    assert_eq!(
        service
            .complete_browser_authorization(USER, complete(flow, CODE, &p["state"]), Some(cookie))
            .await
            .unwrap()
            .status,
        "authorized"
    );
    assert_eq!(
        service
            .complete_browser_authorization(USER, complete(flow, CODE, &p["state"]), Some(cookie))
            .await
            .unwrap()
            .status,
        "authorized"
    );
    assert!(matches!(
        service
            .complete_browser_authorization(USER, complete(flow, &CODE.replace('0', "x"), &p["state"]), Some(cookie))
            .await,
        Err(TokenBitsError::InvalidRequest)
    ));
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let payload: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(payload["grant_type"], "authorization_code");
    assert_eq!(payload["code"], CODE);
    assert_eq!(payload["redirect_uri"], p["redirect_uri"]);
    assert_eq!(payload["exchange_id"], flow.flow_id);
    assert_eq!(
        p["code_challenge"],
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(
            payload["code_verifier"].as_str().unwrap().as_bytes()
        ))
    );
    let cipher = repo.load(USER).await.unwrap().unwrap();
    assert!(!cipher.contains("wb_at_private"));
    assert!(decrypt_string(&cipher, &[42; 32]).unwrap().contains("wb_rt_private"));
    assert_eq!(
        service
            .browser_authorization_status(USER, &flow.flow_id)
            .await
            .unwrap()
            .status,
        "authorized"
    );
    Mock::given(method("DELETE"))
        .and(path("/api/workbench/device"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success":true,"data":{}})))
        .mount(&server)
        .await;
    service.disconnect(USER).await.unwrap();
    assert!(repo.load(USER).await.unwrap().is_none());
    assert!(matches!(
        service
            .complete_browser_authorization(USER, complete(flow, CODE, &p["state"]), Some(cookie))
            .await,
        Err(TokenBitsError::NotFound)
    ));
}

#[tokio::test]
async fn callback_redirect_validation_and_cancel() {
    let server = MockServer::start().await;
    let (service, _repo, _db) = setup(&server).await;
    for uri in [
        "http://remote.example/tokenbits/callback",
        "https://user@ok.example/tokenbits/callback",
        "https://ok.example/tokenbits/callback?evil=1",
        "https://ok.example/elsewhere",
        "https://ok.example/tokenbits/callback#oops",
        "file:///tokenbits/callback",
        "http://127.0.0.1:0/tokenbits/callback",
    ] {
        let mut request = req(true);
        request.redirect_uri = Some(uri.into());
        assert!(
            matches!(
                service.start_browser_authorization(USER, request, None).await,
                Err(TokenBitsError::InvalidRequest)
            ),
            "{uri}"
        );
    }
    for uri in [
        "https://127.0.0.1:49999/tokenbits/callback",
        "http://localhost:49999/tokenbits/callback",
        "http://127.0.0.1/tokenbits/callback",
    ] {
        let mut request = req(false);
        request.redirect_uri = Some(uri.into());
        assert!(
            matches!(
                service.start_browser_authorization(USER, request, None).await,
                Err(TokenBitsError::InvalidRequest)
            ),
            "{uri}"
        );
    }
    let flow = service
        .start_browser_authorization(USER, req(false), None)
        .await
        .unwrap()
        .authorization;
    assert!(matches!(
        service.cancel_browser_authorization("other-user", &flow.flow_id).await,
        Err(TokenBitsError::NotFound)
    ));
    service.cancel_browser_authorization(USER, &flow.flow_id).await.unwrap();
    assert!(matches!(
        service.browser_authorization_status(USER, &flow.flow_id).await,
        Err(TokenBitsError::NotFound)
    ));
}

async fn router(server: &MockServer, local: bool) -> (axum::Router, aionui_db::Database, String) {
    let (service, _repo, db) = setup(server).await;
    let jwt = Arc::new(JwtService::new("browser-http-fixture".into()));
    let token = jwt.sign(USER, USER).unwrap();
    let auth = AuthState {
        jwt_service: jwt,
        user_repo: Arc::new(SqliteUserRepository::new(db.pool().clone())),
        identity_mode: if local {
            AuthIdentityMode::Local
        } else {
            AuthIdentityMode::UserSession
        },
        runtime_token_verifier: None,
    };
    let mut app = domain_routes(TokenBitsRouterState {
        service,
        local,
        local_secret: Some(LOCAL_SECRET.into()),
    })
    .layer(middleware::from_fn_with_state(auth, auth_middleware));
    if !local {
        app = app.layer(middleware::from_fn_with_state(
            Arc::new(CookieConfig {
                secure: true,
                same_site: "Strict",
            }),
            csrf_middleware,
        ));
    }
    (app, db, token)
}
fn http_request(
    path: &str,
    method: &str,
    token: Option<&str>,
    local: bool,
    cookie: &str,
    csrf: bool,
    origin: &str,
    payload: Value,
) -> Request<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("x-aionui-integration", "tokenbits")
        .header("content-type", "application/json")
        .header("origin", origin);
    if local {
        request = request.header("x-aionui-local-secret", LOCAL_SECRET);
    }
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    if !cookie.is_empty() {
        request = request.header("cookie", cookie);
    }
    if csrf {
        request = request.header("x-csrf-token", "csrf-fixture");
    }
    request
        .body(if method == "GET" {
            Body::empty()
        } else {
            Body::from(payload.to_string())
        })
        .unwrap()
}

#[tokio::test]
async fn web_http_auth_csrf_and_browser_cookie_are_all_required() {
    let server = MockServer::start().await;
    let (app, _db, token) = router(&server, false).await;
    let payload = json!({"client_id":"aionui-web","device_name":"Browser fixture","redirect_uri":"https://workbench.example/tokenbits/callback"});
    let csrf = "aionui-csrf-token=csrf-fixture";
    let response = app
        .clone()
        .oneshot(http_request(
            BASE,
            "POST",
            None,
            false,
            csrf,
            true,
            "https://workbench.example",
            payload.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = app
        .clone()
        .oneshot(http_request(
            BASE,
            "POST",
            Some(&token),
            false,
            csrf,
            false,
            "https://workbench.example",
            payload.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body(response).await["code"], "CSRF_INVALID");
    let response = app
        .clone()
        .oneshot(http_request(
            BASE,
            "POST",
            Some(&token),
            false,
            csrf,
            true,
            "https://attacker.example",
            payload.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body(response).await["code"], "TOKENBITS_BROWSER_BINDING");
    let response = app
        .clone()
        .oneshot(http_request(
            BASE,
            "POST",
            Some(&token),
            false,
            csrf,
            true,
            "https://workbench.example",
            payload,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let binding = response.headers()["set-cookie"].to_str().unwrap().to_owned();
    assert!(binding.contains("HttpOnly"));
    assert!(binding.contains("SameSite=Strict"));
    assert!(binding.contains("; Secure"));
    assert!(binding.contains("Path=/api/integrations/tokenbits/browser-authorizations"));
    let flow: TokenBitsBrowserAuthorization = serde_json::from_value(body(response).await["data"].clone()).unwrap();
    let p = params(&flow);
    let complete = json!({"flow_id":flow.flow_id,"code":CODE,"state":p["state"]});
    let complete_path = format!("{BASE}/complete");
    let response = app
        .clone()
        .oneshot(http_request(
            &complete_path,
            "POST",
            Some(&token),
            false,
            csrf,
            true,
            "https://workbench.example",
            complete.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body(response).await["code"], "TOKENBITS_BROWSER_BINDING");
    token_mock(&server).await;
    let cookie = format!("{csrf}; {}", binding.split(';').next().unwrap());
    let response = app
        .clone()
        .oneshot(http_request(
            &complete_path,
            "POST",
            Some(&token),
            false,
            &cookie,
            true,
            "https://workbench.example",
            complete.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers()["set-cookie"].to_str().unwrap().contains("Max-Age=0"));
    let response = body(response).await;
    assert_eq!(response["data"]["status"], "authorized");
    assert!(!response.to_string().contains("wb_at_private"));
    // A browser may receive the cookie-clearing headers but lose the response body.
    // A second complete must not bypass binding; the authenticated status endpoint
    // recovers the already completed outcome without revealing credentials.
    let response = app
        .clone()
        .oneshot(http_request(
            &complete_path,
            "POST",
            Some(&token),
            false,
            csrf,
            true,
            "https://workbench.example",
            complete,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body(response).await["code"], "TOKENBITS_BROWSER_BINDING");
    let response = app
        .oneshot(http_request(
            &format!("{BASE}/{}", flow.flow_id),
            "GET",
            Some(&token),
            false,
            csrf,
            false,
            "https://workbench.example",
            Value::Null,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body(response).await["data"]["status"], "authorized");
}

#[tokio::test]
async fn desktop_listener_requires_host_state_and_closes_after_success() {
    let server = MockServer::start().await;
    let (app, _db, _token) = router(&server, true).await;
    let response = app
        .clone()
        .oneshot(http_request(
            BASE,
            "POST",
            None,
            true,
            "",
            false,
            "null",
            json!({"client_id":"aionui-desktop","device_name":"Desktop fixture"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let flow: TokenBitsBrowserAuthorization = serde_json::from_value(body(response).await["data"].clone()).unwrap();
    let p = params(&flow);
    assert!(p["redirect_uri"].starts_with("http://127.0.0.1:"));
    let client = reqwest::Client::new();
    let callback = &p["redirect_uri"];
    let response = client
        .get(callback)
        .header("host", "evil.example")
        .query(&[("state", p["state"].as_str()), ("code", CODE)])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let response = client
        .get(callback)
        .query(&[("state", "wrong"), ("code", CODE)])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    token_mock(&server).await;
    let response = client
        .get(callback)
        .query(&[("state", p["state"].as_str()), ("code", CODE)])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.text().await.unwrap().contains(CODE));
    let response = app
        .oneshot(http_request(
            &format!("{BASE}/{}", flow.flow_id),
            "GET",
            None,
            true,
            "",
            false,
            "null",
            Value::Null,
        ))
        .await
        .unwrap();
    assert_eq!(body(response).await["data"]["status"], "authorized");
    let address = reqwest::Url::parse(callback).unwrap().socket_addrs(|| None).unwrap()[0];
    for _ in 0..20 {
        if tokio::net::TcpStream::connect(address).await.is_err() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("desktop callback listener still accepting after completion");
}

#[tokio::test]
async fn issuer_and_browser_origin_are_distinct_trusted_startup_configuration() {
    let client = TokenBitsClient::new("https://api.tokenbits.net").unwrap();
    assert_eq!(client.issuer(), "https://api.tokenbits.net");
    assert_eq!(client.browser_origin(), "https://ai.tokenbits.net");
    let url = client
        .browser_authorization_url(
            "aionui-web",
            "fixture",
            "https://workbench.example/tokenbits/callback",
            "state",
            "challenge",
        )
        .unwrap();
    assert!(url.starts_with("https://ai.tokenbits.net/aionui/connect?"));
    let local = TokenBitsClient::new("http://127.0.0.1:18955").unwrap();
    assert_eq!(local.browser_origin(), "http://127.0.0.1:18955");
    for origin in [
        "http://remote.example",
        "https://user@site.example",
        "https://site.example/path",
        "https://site.example?x=y",
        "https://site.example/#bad",
        "javascript:alert(1)",
    ] {
        assert!(
            matches!(
                TokenBitsClient::with_browser_origin("https://api.tokenbits.net", origin),
                Err(TokenBitsError::InvalidRequest)
            ),
            "{origin}"
        );
    }
    let server = MockServer::start().await;
    let (service, _, _db) = setup(&server).await;
    let status = service.status(USER).await.unwrap();
    assert_eq!(status.browser_origin, server.uri());
}

#[tokio::test]
async fn desktop_cancel_closes_listener_without_authorizing() {
    let server = MockServer::start().await;
    let (app, _db, _token) = router(&server, true).await;
    let response = app
        .clone()
        .oneshot(http_request(
            BASE,
            "POST",
            None,
            true,
            "",
            false,
            "null",
            json!({"client_id":"aionui-desktop","device_name":"Desktop fixture"}),
        ))
        .await
        .unwrap();
    let flow: TokenBitsBrowserAuthorization = serde_json::from_value(body(response).await["data"].clone()).unwrap();
    let address = reqwest::Url::parse(&params(&flow)["redirect_uri"])
        .unwrap()
        .socket_addrs(|| None)
        .unwrap()[0];
    let response = app
        .oneshot(http_request(
            &format!("{BASE}/{}", flow.flow_id),
            "DELETE",
            None,
            true,
            "",
            false,
            "null",
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    for _ in 0..20 {
        if tokio::net::TcpStream::connect(address).await.is_err() {
            assert!(server.received_requests().await.unwrap().is_empty());
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("cancelled listener stayed open");
}
