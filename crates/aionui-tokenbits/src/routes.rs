#![allow(clippy::disallowed_types)]
use crate::{
    error::TokenBitsError,
    state::{TokenBitsHostedRouterState, TokenBitsRouterState},
};
use aionui_api_types::{ApiResponse, tokenbits::*};
use aionui_auth::{CurrentUser, RateLimiter, authenticated_action_rate_limit_middleware};
use aionui_common::ApiError;
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, Request, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
};
use std::{sync::Arc, time::Duration};
use subtle::ConstantTimeEq;

impl From<TokenBitsError> for ApiError {
    fn from(error: TokenBitsError) -> Self {
        let (status, code) = match &error {
            TokenBitsError::InvalidRequest => (StatusCode::BAD_REQUEST, "TOKENBITS_INVALID_REQUEST"),
            TokenBitsError::BrowserBinding => (StatusCode::FORBIDDEN, "TOKENBITS_BROWSER_BINDING"),
            TokenBitsError::AccountBinding => (StatusCode::FORBIDDEN, "TOKENBITS_ACCOUNT_BINDING"),
            TokenBitsError::NotFound => (StatusCode::NOT_FOUND, "TOKENBITS_NOT_FOUND"),
            TokenBitsError::Reauthorization => (StatusCode::CONFLICT, "TOKENBITS_REAUTHORIZE"),
            TokenBitsError::DeviceRevoked => (StatusCode::CONFLICT, "TOKENBITS_REAUTHORIZE"),
            TokenBitsError::RevocationUnconfirmed => (StatusCode::CONFLICT, "TOKENBITS_REVOCATION_UNCONFIRMED"),
            TokenBitsError::Unavailable => (StatusCode::BAD_GATEWAY, "TOKENBITS_UNAVAILABLE"),
            TokenBitsError::Storage => (StatusCode::INTERNAL_SERVER_ERROR, "TOKENBITS_STORAGE"),
            TokenBitsError::Remote(code) => (StatusCode::CONFLICT, *code),
        };
        ApiError::coded(status, code, error.to_string(), None)
    }
}

/// Private service-to-service boundary; ambient browser credentials never authorize it.
/// The composition root registers it only for a configured hosted tenant, outside cookie CSRF.
pub fn hosted_routes(state: TokenBitsHostedRouterState) -> Router {
    let limiter = Arc::new(RateLimiter::new(30, Duration::from_secs(60)));
    limiter.start_cleanup_task(Duration::from_secs(60));
    Router::new()
        .route("/api/integrations/tokenbits/internal/attach", post(hosted_attach))
        .route_layer(middleware::from_fn_with_state(
            limiter,
            aionui_auth::api_rate_limit_middleware,
        ))
        .with_state(state)
        .layer(middleware::from_fn(no_store))
}

async fn hosted_attach(
    State(state): State<TokenBitsHostedRouterState>,
    headers: HeaderMap,
    body: Result<Json<TokenBitsHostedAttachRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<TokenBitsHostedAttachResponse>>, ApiError> {
    let provided = headers
        .get("x-aioncore-bootstrap-secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if state.bootstrap_secret.len() < 32 || !bool::from(state.bootstrap_secret.as_bytes().ct_eq(provided.as_bytes())) {
        return Err(ApiError::coded(
            StatusCode::UNAUTHORIZED,
            "INVALID_BOOTSTRAP_SECRET",
            "Internal authentication required",
            None,
        ));
    }
    if ["origin", "cookie", "sec-fetch-mode"]
        .iter()
        .any(|name| headers.contains_key(*name))
    {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "TOKENBITS_INTERNAL_ONLY",
            "Browser requests are not supported",
            None,
        ));
    }
    let Json(req) = body.map_err(ApiError::from)?;
    Ok(Json(ApiResponse::ok(state.service.attach_hosted(req).await?)))
}

/// The composition root wraps this router in Core authentication and Web CSRF.
pub fn domain_routes(state: TokenBitsRouterState) -> Router {
    let limiter = Arc::new(RateLimiter::new(60, Duration::from_secs(60)));
    limiter.start_cleanup_task(Duration::from_secs(60));
    Router::new()
        .route("/api/integrations/tokenbits/status", get(status))
        .route("/api/integrations/tokenbits/device-authorizations", post(authorize))
        .route(
            "/api/integrations/tokenbits/browser-authorizations",
            post(browser_authorize),
        )
        .route(
            "/api/integrations/tokenbits/browser-authorizations/complete",
            post(browser_complete),
        )
        .route(
            "/api/integrations/tokenbits/browser-authorizations/{id}",
            get(browser_status).delete(browser_cancel),
        )
        .route(
            "/api/integrations/tokenbits/device-authorizations/{id}/poll",
            post(poll),
        )
        .route("/api/integrations/tokenbits/device-authorizations/{id}", delete(cancel))
        .route("/api/integrations/tokenbits/account", get(account))
        .route("/api/integrations/tokenbits/catalog", get(catalog))
        .route("/api/integrations/tokenbits/sync", post(sync))
        .route("/api/integrations/tokenbits/connection", delete(disconnect))
        .route_layer(middleware::from_fn_with_state(
            limiter,
            authenticated_action_rate_limit_middleware,
        ))
        .route_layer(middleware::from_fn_with_state(state.clone(), browser_boundary))
        .with_state(state)
        .layer(middleware::from_fn(no_store))
}

async fn browser_boundary(
    State(state): State<TokenBitsRouterState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let headers = request.headers();
    if headers.get("x-aionui-integration").and_then(|h| h.to_str().ok()) != Some("tokenbits") {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "TOKENBITS_ORIGIN",
            "TokenBits client header required",
            None,
        ));
    }
    if state.local {
        let provided = headers
            .get("x-aionui-local-secret")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        let valid = state
            .local_secret
            .as_ref()
            .filter(|s| s.len() >= 32)
            .is_some_and(|expected| bool::from(expected.as_bytes().ct_eq(provided.as_bytes())));
        if !valid {
            return Err(ApiError::coded(
                StatusCode::FORBIDDEN,
                "TOKENBITS_LOCAL_AUTH",
                "Local integration authentication required",
                None,
            ));
        }
    }
    if state.local
        && let Some(origin) = headers.get("origin")
    {
        let trusted = origin.to_str().ok().is_some_and(|origin| {
            origin == "null"
                || reqwest::Url::parse(origin).is_ok_and(|url| {
                    matches!(url.scheme(), "http" | "https")
                        && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
                })
        });
        if !trusted {
            return Err(ApiError::coded(
                StatusCode::FORBIDDEN,
                "TOKENBITS_ORIGIN",
                "Untrusted TokenBits client origin",
                None,
            ));
        }
    }
    // No response from this domain may be cached, including account metadata.
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    Ok(response)
}

async fn status(
    State(s): State<TokenBitsRouterState>,
    Extension(u): Extension<CurrentUser>,
) -> Result<Json<ApiResponse<TokenBitsStatus>>, ApiError> {
    Ok(Json(ApiResponse::ok(s.service.status(&u.id).await?)))
}
async fn authorize(
    State(s): State<TokenBitsRouterState>,
    Extension(u): Extension<CurrentUser>,
    body: Result<Json<TokenBitsAuthorizeRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<TokenBitsAuthorization>>, ApiError> {
    let Json(req) = body.map_err(ApiError::from)?;
    Ok(Json(ApiResponse::ok(s.service.authorize(&u.id, req).await?)))
}
async fn poll(
    State(s): State<TokenBitsRouterState>,
    Extension(u): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<TokenBitsPollResponse>>, ApiError> {
    Ok(Json(ApiResponse::ok(s.service.poll(&u.id, &id).await?)))
}
async fn cancel(
    State(s): State<TokenBitsRouterState>,
    Extension(u): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    s.service.cancel(&u.id, &id).await?;
    Ok(Json(ApiResponse::success()))
}
async fn account(
    State(s): State<TokenBitsRouterState>,
    Extension(u): Extension<CurrentUser>,
) -> Result<Json<ApiResponse<TokenBitsAccount>>, ApiError> {
    Ok(Json(ApiResponse::ok(s.service.account(&u.id).await?)))
}
async fn catalog(
    State(s): State<TokenBitsRouterState>,
    Extension(u): Extension<CurrentUser>,
) -> Result<Json<ApiResponse<TokenBitsCatalog>>, ApiError> {
    Ok(Json(ApiResponse::ok(s.service.catalog(&u.id).await?)))
}
async fn sync(
    State(s): State<TokenBitsRouterState>,
    Extension(u): Extension<CurrentUser>,
    body: Result<Json<TokenBitsSyncRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<TokenBitsSyncResponse>>, ApiError> {
    let Json(req) = body.map_err(ApiError::from)?;
    Ok(Json(ApiResponse::ok(s.service.sync(&u.id, req).await?)))
}
async fn disconnect(
    State(s): State<TokenBitsRouterState>,
    Extension(u): Extension<CurrentUser>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    s.service.disconnect(&u.id).await?;
    Ok(Json(ApiResponse::success()))
}

/// Apply outside authentication as well so rejected integration requests cannot be cached.
pub async fn no_store(request: Request, next: Next) -> Response {
    let integration = request.uri().path().starts_with("/api/integrations/tokenbits/");
    let mut response = next.run(request).await;
    if integration {
        response
            .headers_mut()
            .insert("cache-control", HeaderValue::from_static("no-store"));
    }
    response
}

const BROWSER_COOKIE: &str = "aionui-tokenbits-browser";
const BROWSER_COOKIE_PATH: &str = "/api/integrations/tokenbits/browser-authorizations";

fn browser_cookie(value: &str, secure: bool, clear: bool) -> Result<HeaderValue, ApiError> {
    HeaderValue::from_str(&format!(
        "{BROWSER_COOKIE}={value}; Path={BROWSER_COOKIE_PATH}; HttpOnly; SameSite=Strict{}; Max-Age={}",
        if secure { "; Secure" } else { "" },
        if clear { 0 } else { 600 },
    ))
    .map_err(|_| TokenBitsError::Unavailable.into())
}

async fn browser_authorize(
    State(s): State<TokenBitsRouterState>,
    Extension(u): Extension<CurrentUser>,
    headers: HeaderMap,
    body: Result<Json<TokenBitsBrowserAuthorizeRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(mut req) = body.map_err(ApiError::from)?;
    let mut listener = None;
    let secure;
    if s.local {
        if req.client_id != "aionui-desktop" || req.redirect_uri.is_some() {
            return Err(TokenBitsError::InvalidRequest.into());
        }
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| TokenBitsError::Unavailable)?;
        let address = socket.local_addr().map_err(|_| TokenBitsError::Unavailable)?;
        req.redirect_uri = Some(format!("http://{address}/tokenbits/callback"));
        listener = Some(socket);
        secure = false;
    } else {
        if req.client_id != "aionui-web" {
            return Err(TokenBitsError::InvalidRequest.into());
        }
        let redirect = req.redirect_uri.as_deref().ok_or(TokenBitsError::InvalidRequest)?;
        let url = reqwest::Url::parse(redirect).map_err(|_| TokenBitsError::InvalidRequest)?;
        if headers.get(header::ORIGIN).and_then(|value| value.to_str().ok())
            != Some(url.origin().ascii_serialization().as_str())
        {
            return Err(TokenBitsError::BrowserBinding.into());
        }
        secure = url.scheme() == "https";
    }
    let binding = if s.local {
        None
    } else {
        aionui_auth::extract_cookie_value(&headers, BROWSER_COOKIE)
    };
    let result = s
        .service
        .start_browser_authorization(&u.id, req, binding.as_deref())
        .await?;
    if let (Some(listener), Some(shutdown)) = (listener, result.listener_shutdown) {
        launch_desktop_callback(
            listener,
            s.service.clone(),
            u.id,
            result.authorization.flow_id.clone(),
            result.authorization.expires_at,
            shutdown,
        )?;
    }
    let mut response = Json(ApiResponse::ok(result.authorization)).into_response();
    if let Some(value) = result.binding_cookie {
        response
            .headers_mut()
            .insert(header::SET_COOKIE, browser_cookie(&value, secure, false)?);
    }
    Ok(response)
}

async fn browser_complete(
    State(s): State<TokenBitsRouterState>,
    Extension(u): Extension<CurrentUser>,
    headers: HeaderMap,
    body: Result<Json<TokenBitsBrowserCompleteRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    if s.local {
        return Err(TokenBitsError::InvalidRequest.into());
    }
    let Json(req) = body.map_err(ApiError::from)?;
    let binding = aionui_auth::extract_cookie_value(&headers, BROWSER_COOKIE);
    let result = s
        .service
        .complete_browser_authorization(&u.id, req, binding.as_deref())
        .await?;
    let mut response = Json(ApiResponse::ok(result)).into_response();
    let secure = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|origin| origin.starts_with("https://"));
    response
        .headers_mut()
        .insert(header::SET_COOKIE, browser_cookie("", secure, true)?);
    Ok(response)
}

async fn browser_status(
    State(s): State<TokenBitsRouterState>,
    Extension(u): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<TokenBitsPollResponse>>, ApiError> {
    Ok(Json(ApiResponse::ok(
        s.service.browser_authorization_status(&u.id, &id).await?,
    )))
}

async fn browser_cancel(
    State(s): State<TokenBitsRouterState>,
    Extension(u): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    s.service.cancel_browser_authorization(&u.id, &id).await?;
    Ok(Json(ApiResponse::success()))
}

#[derive(Clone)]
struct DesktopCallbackState {
    service: Arc<crate::service::TokenBitsService>,
    user: String,
    flow_id: String,
    host: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DesktopCallbackQuery {
    code: String,
    state: String,
}

fn launch_desktop_callback(
    listener: tokio::net::TcpListener,
    service: Arc<crate::service::TokenBitsService>,
    user: String,
    flow_id: String,
    expires_at: i64,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), ApiError> {
    let host = listener
        .local_addr()
        .map_err(|_| TokenBitsError::Unavailable)?
        .to_string();
    let router = Router::new()
        .route("/tokenbits/callback", get(desktop_callback))
        .with_state(DesktopCallbackState {
            service,
            user,
            flow_id,
            host,
        })
        .layer(middleware::from_fn(|request: Request, next: Next| async move {
            let mut response = next.run(request).await;
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
                .headers_mut()
                .insert("referrer-policy", HeaderValue::from_static("no-referrer"));
            response.headers_mut().insert(
                "content-security-policy",
                HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
            );
            response
        }));
    let remaining = (expires_at - aionui_common::now_ms() / 1000).max(0) as u64;
    tokio::spawn(async move {
        // No tracing layer here: callback URLs contain a short-lived authorization code.
        let result = axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(remaining)) => {},
                    _ = async { while !*shutdown.borrow() { if shutdown.changed().await.is_err() { break; } } } => {},
                }
            })
            .await;
        if result.is_err() {
            tracing::warn!("TokenBits callback listener stopped with an IO error");
        }
    });
    Ok(())
}

async fn desktop_callback(
    State(state): State<DesktopCallbackState>,
    headers: HeaderMap,
    query: Result<Query<DesktopCallbackQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    if headers.get(header::HOST).and_then(|value| value.to_str().ok()) != Some(state.host.as_str()) {
        return (StatusCode::BAD_REQUEST, Html("Invalid connection callback.")).into_response();
    }
    let Ok(Query(query)) = query else {
        return (StatusCode::BAD_REQUEST, Html("Invalid connection callback.")).into_response();
    };
    let result = state
        .service
        .complete_browser_authorization(
            &state.user,
            TokenBitsBrowserCompleteRequest {
                flow_id: state.flow_id,
                code: query.code,
                state: query.state,
            },
            None,
        )
        .await;
    match result {
        Ok(_) => Html("Connected to TokenBits. You can return to AionUi.").into_response(),
        Err(_) => (
            StatusCode::BAD_REQUEST,
            Html("Connection could not be completed. Return to AionUi to retry."),
        )
            .into_response(),
    }
}
