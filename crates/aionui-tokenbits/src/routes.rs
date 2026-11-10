#![allow(clippy::disallowed_types)]
use crate::{error::TokenBitsError, state::TokenBitsRouterState};
use aionui_api_types::{ApiResponse, tokenbits::*};
use aionui_auth::{CurrentUser, RateLimiter, authenticated_action_rate_limit_middleware};
use aionui_common::ApiError;
use axum::{
    Extension, Json, Router,
    extract::{Path, Request, State, rejection::JsonRejection},
    http::{HeaderValue, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{delete, get, post},
};
use std::{sync::Arc, time::Duration};
use subtle::ConstantTimeEq;

impl From<TokenBitsError> for ApiError {
    fn from(error: TokenBitsError) -> Self {
        let (status, code) = match &error {
            TokenBitsError::InvalidRequest => (StatusCode::BAD_REQUEST, "TOKENBITS_INVALID_REQUEST"),
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

/// The composition root wraps this router in Core authentication and Web CSRF.
pub fn domain_routes(state: TokenBitsRouterState) -> Router {
    let limiter = Arc::new(RateLimiter::new(60, Duration::from_secs(60)));
    limiter.start_cleanup_task(Duration::from_secs(60));
    Router::new()
        .route("/api/integrations/tokenbits/status", get(status))
        .route("/api/integrations/tokenbits/device-authorizations", post(authorize))
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
