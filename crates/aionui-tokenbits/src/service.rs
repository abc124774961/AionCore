use crate::{client::TokenBitsClient, error::TokenBitsError};
use aionui_api_types::tokenbits::*;
use aionui_common::{decrypt_string, encrypt_string};
use aionui_db::{ITokenBitsRepository, ManagedProviderInput};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, watch};

type Result<T> = std::result::Result<T, TokenBitsError>;

#[derive(Serialize, Deserialize)]
struct StoredAccount {
    issuer: String,
    client_id: String,
    access_token: String,
    refresh_token: String,
    device_id: i64,
    expires_at: i64,
    exchange_id: String,
    account: Option<TokenBitsAccountIdentity>,
    last_sync_at: Option<i64>,
    needs_reauthorization: bool,
}

struct PendingAuthorization {
    flow_id: String,
    client_id: String,
    verifier: String,
    device_code: String,
    expires_at: i64,
    interval: u64,
    next_poll_at: i64,
}

struct PendingBrowserAuthorization {
    response: TokenBitsBrowserAuthorization,
    client_id: String,
    device_name: String,
    state: String,
    verifier: String,
    redirect_uri: String,
    binding_hash: Option<[u8; 32]>,
    completed_code_hash: Option<[u8; 32]>,
    completed_device_id: Option<i64>,
    close_listener: watch::Sender<bool>,
}

/// New flows return a listener lifetime receiver; reused flows do not start another listener.
pub struct BrowserAuthorizationStart {
    pub authorization: TokenBitsBrowserAuthorization,
    pub binding_cookie: Option<String>,
    pub listener_shutdown: Option<watch::Receiver<bool>>,
}

#[derive(Deserialize)]
struct RemoteAuthorization {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: i64,
    interval: u64,
}

#[derive(Deserialize)]
struct RemoteToken {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
    device_id: i64,
}

#[derive(Deserialize)]
struct RemoteConnection {
    id: i64,
    model: String,
    group: String,
}
#[derive(Deserialize)]
struct RemoteKey {
    key: String,
}

pub struct TokenBitsService {
    repo: Arc<dyn ITokenBitsRepository>,
    encryption_key: [u8; 32],
    client: TokenBitsClient,
    locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    pending: Mutex<HashMap<String, PendingAuthorization>>,
    browser_pending: Mutex<HashMap<String, PendingBrowserAuthorization>>,
}

impl TokenBitsService {
    pub fn new(repo: Arc<dyn ITokenBitsRepository>, encryption_key: [u8; 32], client: TokenBitsClient) -> Self {
        Self {
            repo,
            encryption_key,
            client,
            locks: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            browser_pending: Mutex::new(HashMap::new()),
        }
    }

    async fn lock(&self, user: &str) -> Arc<Mutex<()>> {
        self.locks.lock().await.entry(user.to_owned()).or_default().clone()
    }
    async fn load(&self, user: &str) -> Result<Option<StoredAccount>> {
        self.repo
            .load(user)
            .await?
            .map(|cipher| {
                let plain = decrypt_string(&cipher, &self.encryption_key)?;
                let state: StoredAccount = serde_json::from_str(&plain).map_err(|_| TokenBitsError::Storage)?;
                Ok(state)
            })
            .transpose()
    }
    async fn save(&self, user: &str, state: &StoredAccount) -> Result<()> {
        let plain = serde_json::to_string(state).map_err(|_| TokenBitsError::Storage)?;
        self.repo
            .save(user, &encrypt_string(&plain, &self.encryption_key)?)
            .await?;
        Ok(())
    }

    pub async fn status(&self, user: &str) -> Result<TokenBitsStatus> {
        let state = self.load(user).await?;
        Ok(TokenBitsStatus {
            connected: state
                .as_ref()
                .is_some_and(|s| !s.needs_reauthorization && s.issuer == self.client.issuer()),
            needs_reauthorization: state
                .as_ref()
                .is_some_and(|s| s.needs_reauthorization || s.issuer != self.client.issuer()),
            issuer: self.client.issuer(),
            browser_origin: self.client.browser_origin(),
            device_id: state.as_ref().map(|s| s.device_id),
            account: state.as_ref().and_then(|s| s.account.clone()),
            last_sync_at: state.and_then(|s| s.last_sync_at),
            provider_count: self.repo.provider_count(user).await?,
        })
    }

    pub async fn authorize(&self, user: &str, req: TokenBitsAuthorizeRequest) -> Result<TokenBitsAuthorization> {
        if !matches!(req.client_id.as_str(), "aionui-desktop" | "aionui-web")
            || req.device_name.trim().is_empty()
            || req.device_name.len() > 128
        {
            return Err(TokenBitsError::InvalidRequest);
        }
        let lock = self.lock(user).await;
        let _guard = lock.lock().await;
        if self
            .browser_pending
            .lock()
            .await
            .get(user)
            .is_some_and(|p| p.response.expires_at > now())
        {
            return Err(TokenBitsError::Remote("authorization_conflict"));
        }
        if self.load(user).await?.is_some_and(|s| !s.needs_reauthorization) {
            return Err(TokenBitsError::Remote("already_connected"));
        }
        let verifier = random_secret()?;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let remote: RemoteAuthorization = self.client.request(Method::POST, "/authorizations", None, Some(json!({
            "client_id": req.client_id, "device_name": req.device_name, "code_challenge": challenge, "code_challenge_method":"S256"
        }))).await?;
        self.client.validate_url(&remote.verification_uri)?;
        self.client.validate_url(&remote.verification_uri_complete)?;
        if remote.device_code.is_empty() || !(1..=900).contains(&remote.expires_in) {
            return Err(TokenBitsError::Unavailable);
        }
        let flow_id = random_secret()?;
        let interval = remote.interval.clamp(1, 60);
        let expires_at = now() + remote.expires_in;
        let response = TokenBitsAuthorization {
            flow_id: flow_id.clone(),
            user_code: remote.user_code,
            verification_uri: remote.verification_uri,
            verification_uri_complete: remote.verification_uri_complete,
            expires_at,
            interval,
        };
        let mut pending = self.pending.lock().await;
        pending.retain(|_, flow| flow.expires_at > now());
        pending.insert(
            user.into(),
            PendingAuthorization {
                flow_id,
                client_id: req.client_id,
                verifier,
                device_code: remote.device_code,
                expires_at,
                interval,
                next_poll_at: now() + interval as i64,
            },
        );
        tracing::info!("TokenBits device authorization started");
        Ok(response)
    }

    /// Create a proof-bound front-channel flow. HTTP handlers own any listener.
    pub async fn start_browser_authorization(
        &self,
        user: &str,
        req: TokenBitsBrowserAuthorizeRequest,
        browser_cookie: Option<&str>,
    ) -> Result<BrowserAuthorizationStart> {
        if !matches!(req.client_id.as_str(), "aionui-desktop" | "aionui-web")
            || req.device_name.trim().is_empty()
            || req.device_name.len() > 128
            || req.device_name.chars().any(char::is_control)
        {
            return Err(TokenBitsError::InvalidRequest);
        }
        let redirect_uri = req.redirect_uri.ok_or(TokenBitsError::InvalidRequest)?;
        validate_browser_redirect(&req.client_id, &redirect_uri)?;
        let lock = self.lock(user).await;
        let _guard = lock.lock().await;
        if self.load(user).await?.is_some_and(|s| !s.needs_reauthorization) {
            return Err(TokenBitsError::Remote("already_connected"));
        }
        let mut pending = self.browser_pending.lock().await;
        pending.retain(|_, flow| {
            let active = flow.response.expires_at > now();
            if !active {
                let _ = flow.close_listener.send(true);
            }
            active
        });
        if let Some(existing) = pending.get(user) {
            if existing.client_id != req.client_id
                || existing.device_name != req.device_name
                || (existing.client_id == "aionui-web" && existing.redirect_uri != redirect_uri)
            {
                return Err(TokenBitsError::Remote("authorization_conflict"));
            }
            verify_browser_binding(existing.binding_hash, browser_cookie)?;
            return Ok(BrowserAuthorizationStart {
                authorization: existing.response.clone(),
                binding_cookie: None,
                listener_shutdown: None,
            });
        }
        let state = random_secret()?;
        let verifier = random_secret()?;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let (binding_cookie, binding_hash) = if req.client_id == "aionui-web" {
            let value = random_secret()?;
            let hash = digest_secret(&value);
            (Some(value), Some(hash))
        } else {
            (None, None)
        };
        let authorization = TokenBitsBrowserAuthorization {
            flow_id: random_secret()?,
            authorization_url: self.client.browser_authorization_url(
                &req.client_id,
                &req.device_name,
                &redirect_uri,
                &state,
                &challenge,
            )?,
            expires_at: now() + 600,
            mode: if req.client_id == "aionui-desktop" {
                "desktop"
            } else {
                "web"
            }
            .into(),
        };
        let (close_listener, listener_shutdown) = watch::channel(false);
        pending.insert(
            user.into(),
            PendingBrowserAuthorization {
                response: authorization.clone(),
                client_id: req.client_id,
                device_name: req.device_name,
                state,
                verifier,
                redirect_uri,
                binding_hash,
                completed_code_hash: None,
                completed_device_id: None,
                close_listener,
            },
        );
        // A previous device-code flow cannot race this connection.
        self.pending.lock().await.remove(user);
        tracing::info!(mode = %authorization.mode, "TokenBits browser authorization started");
        Ok(BrowserAuthorizationStart {
            authorization,
            binding_cookie,
            listener_shutdown: Some(listener_shutdown),
        })
    }

    pub async fn browser_authorization_status(&self, user: &str, flow_id: &str) -> Result<TokenBitsPollResponse> {
        let pending = self.browser_pending.lock().await;
        let flow = pending
            .get(user)
            .filter(|flow| flow.response.flow_id == flow_id)
            .ok_or(TokenBitsError::NotFound)?;
        let status = if flow.response.expires_at <= now() {
            "expired"
        } else if flow.completed_device_id.is_some() {
            "authorized"
        } else {
            "pending"
        };
        Ok(poll_response(status, 2))
    }

    pub async fn complete_browser_authorization(
        &self,
        user: &str,
        req: TokenBitsBrowserCompleteRequest,
        browser_cookie: Option<&str>,
    ) -> Result<TokenBitsPollResponse> {
        let lock = self.lock(user).await;
        let _guard = lock.lock().await;
        let (client_id, verifier, redirect_uri, code_hash) = {
            let pending = self.browser_pending.lock().await;
            let flow = pending
                .get(user)
                .filter(|flow| flow.response.flow_id == req.flow_id)
                .ok_or(TokenBitsError::NotFound)?;
            if flow.response.expires_at <= now() {
                return Err(TokenBitsError::Remote("expired_token"));
            }
            if !bool::from(flow.state.as_bytes().ct_eq(req.state.as_bytes()))
                || !req.code.starts_with("wb_bc_")
                || req.code.len() != 54
                || !req
                    .code
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                return Err(TokenBitsError::InvalidRequest);
            }
            verify_browser_binding(flow.binding_hash, browser_cookie)?;
            let code_hash = digest_secret(&req.code);
            if flow.completed_code_hash.is_some_and(|known| known != code_hash) {
                return Err(TokenBitsError::InvalidRequest);
            }
            if flow.completed_device_id.is_some() {
                return Ok(poll_response("authorized", 2));
            }
            (
                flow.client_id.clone(),
                flow.verifier.clone(),
                flow.redirect_uri.clone(),
                code_hash,
            )
        };
        let token: RemoteToken = self
            .client
            .request(
                Method::POST,
                "/token",
                None,
                Some(json!({
                    "grant_type":"authorization_code", "client_id":client_id, "code":req.code,
                    "code_verifier":verifier, "redirect_uri":redirect_uri, "exchange_id":req.flow_id
                })),
            )
            .await?;
        validate_token(&token)?;
        let account = StoredAccount {
            issuer: self.client.issuer(),
            client_id,
            access_token: token.access_token,
            refresh_token: token.refresh_token,
            device_id: token.device_id,
            expires_at: now() + token.expires_in,
            exchange_id: random_secret()?,
            account: None,
            last_sync_at: None,
            needs_reauthorization: false,
        };
        self.save(user, &account).await?;
        let mut pending = self.browser_pending.lock().await;
        let flow = pending
            .get_mut(user)
            .filter(|flow| flow.response.flow_id == req.flow_id)
            .ok_or(TokenBitsError::NotFound)?;
        flow.completed_code_hash = Some(code_hash);
        flow.completed_device_id = Some(account.device_id);
        let _ = flow.close_listener.send(true);
        tracing::info!("TokenBits browser authorization completed");
        Ok(poll_response("authorized", 2))
    }

    pub async fn cancel_browser_authorization(&self, user: &str, flow_id: &str) -> Result<()> {
        let lock = self.lock(user).await;
        let _guard = lock.lock().await;
        let mut pending = self.browser_pending.lock().await;
        if pending.get(user).is_none_or(|flow| flow.response.flow_id != flow_id) {
            return Err(TokenBitsError::NotFound);
        }
        if let Some(flow) = pending.remove(user) {
            let _ = flow.close_listener.send(true);
        }
        Ok(())
    }

    pub async fn cancel(&self, user: &str, flow_id: &str) -> Result<()> {
        let lock = self.lock(user).await;
        let _guard = lock.lock().await;
        let mut pending = self.pending.lock().await;
        if pending.get(user).is_some_and(|p| p.flow_id == flow_id) {
            pending.remove(user);
            Ok(())
        } else {
            Err(TokenBitsError::NotFound)
        }
    }

    pub async fn poll(&self, user: &str, flow_id: &str) -> Result<TokenBitsPollResponse> {
        let lock = self.lock(user).await;
        let _guard = lock.lock().await;
        let (client_id, body, interval) = {
            let mut pending = self.pending.lock().await;
            let flow = pending
                .get_mut(user)
                .filter(|p| p.flow_id == flow_id)
                .ok_or(TokenBitsError::NotFound)?;
            let interval = flow.interval;
            if flow.expires_at <= now() {
                pending.remove(user);
                return Ok(poll_response("expired", interval));
            }
            if flow.next_poll_at > now() {
                return Ok(poll_response("slow_down", interval));
            }
            flow.next_poll_at = now() + interval as i64;
            (
                flow.client_id.clone(),
                json!({"grant_type":"device_code", "client_id":flow.client_id,
                "device_code":flow.device_code,"code_verifier":flow.verifier,"exchange_id":flow.flow_id}),
                interval,
            )
        };
        match self
            .client
            .request::<RemoteToken>(Method::POST, "/token", None, Some(body))
            .await
        {
            Ok(token) => {
                validate_token(&token)?;
                let state = StoredAccount {
                    issuer: self.client.issuer(),
                    client_id,
                    access_token: token.access_token,
                    refresh_token: token.refresh_token,
                    device_id: token.device_id,
                    expires_at: now() + token.expires_in,
                    exchange_id: random_secret()?,
                    account: None,
                    last_sync_at: None,
                    needs_reauthorization: false,
                };
                self.save(user, &state).await?;
                self.pending.lock().await.remove(user);
                tracing::info!("TokenBits device authorization completed");
                Ok(poll_response("authorized", interval))
            }
            Err(TokenBitsError::Remote("authorization_pending")) => Ok(poll_response("pending", interval)),
            Err(TokenBitsError::Remote("slow_down")) => {
                let interval = (interval + 5).min(60);
                if let Some(flow) = self.pending.lock().await.get_mut(user) {
                    flow.interval = interval;
                    flow.next_poll_at = now() + interval as i64;
                }
                Ok(poll_response("slow_down", interval))
            }
            Err(TokenBitsError::Remote("expired_token")) => {
                self.pending.lock().await.remove(user);
                Ok(poll_response("expired", interval))
            }
            Err(TokenBitsError::Remote("access_denied")) => {
                self.pending.lock().await.remove(user);
                Ok(poll_response("denied", interval))
            }
            Err(e) => Err(e),
        }
    }

    /// Call only with the per-user lock held. The persisted exchange identity is
    /// reused after transport/storage failure, including after a process restart.
    async fn access(&self, user: &str) -> Result<StoredAccount> {
        let mut state = self.load(user).await?.ok_or(TokenBitsError::Reauthorization)?;
        if state.needs_reauthorization || state.issuer != self.client.issuer() {
            self.repo.disable_providers(user).await?;
            return Err(TokenBitsError::Reauthorization);
        }
        if state.expires_at > now() + 60 {
            return Ok(state);
        }
        let token = self.client.request::<RemoteToken>(Method::POST, "/token", None, Some(json!({
            "grant_type":"refresh_token", "client_id":state.client_id, "refresh_token":state.refresh_token, "exchange_id":state.exchange_id
        }))).await;
        match token {
            Ok(token) => {
                validate_token(&token)?;
                if token.device_id != state.device_id {
                    return Err(TokenBitsError::Unavailable);
                }
                state.access_token = token.access_token;
                state.refresh_token = token.refresh_token;
                state.expires_at = now() + token.expires_in;
                state.exchange_id = random_secret()?;
                self.save(user, &state).await?;
                tracing::info!("TokenBits credentials refreshed");
                Ok(state)
            }
            Err(
                TokenBitsError::Reauthorization
                | TokenBitsError::DeviceRevoked
                | TokenBitsError::Remote("expired_token"),
            ) => {
                state.needs_reauthorization = true;
                self.save(user, &state).await?;
                self.repo.disable_providers(user).await?;
                tracing::warn!("TokenBits requires reauthorization");
                Err(TokenBitsError::Reauthorization)
            }
            Err(e) => Err(e),
        }
    }

    async fn handle_remote<T>(&self, user: &str, result: Result<T>) -> Result<T> {
        if matches!(
            result,
            Err(TokenBitsError::Reauthorization | TokenBitsError::DeviceRevoked)
        ) {
            if let Some(mut state) = self.load(user).await? {
                state.needs_reauthorization = true;
                self.save(user, &state).await?;
            }
            self.repo.disable_providers(user).await?;
        }
        result
    }

    pub async fn account(&self, user: &str) -> Result<TokenBitsAccount> {
        let lock = self.lock(user).await;
        let _guard = lock.lock().await;
        let mut state = self.access(user).await?;
        let result = self
            .client
            .request::<TokenBitsAccount>(Method::GET, "/account", Some(&state.access_token), None)
            .await;
        let account = self.handle_remote(user, result).await?;
        self.client.validate_url(&account.topup_url)?;
        state.account = Some(account.account.clone());
        self.save(user, &state).await?;
        Ok(account)
    }

    async fn catalog_with_token(&self, user: &str, token: &str) -> Result<TokenBitsCatalog> {
        let result = self
            .client
            .request::<TokenBitsCatalog>(Method::GET, "/catalog", Some(token), None)
            .await;
        let catalog = self.handle_remote(user, result).await?;
        self.client.validate_url(&catalog.api_base_url)?;
        if catalog.protocol != "openai" {
            return Err(TokenBitsError::Unavailable);
        }
        Ok(catalog)
    }
    pub async fn catalog(&self, user: &str) -> Result<TokenBitsCatalog> {
        let lock = self.lock(user).await;
        let _guard = lock.lock().await;
        let state = self.access(user).await?;
        self.catalog_with_token(user, &state.access_token).await
    }

    pub async fn sync(&self, user: &str, req: TokenBitsSyncRequest) -> Result<TokenBitsSyncResponse> {
        if req.group.is_empty() || req.group.len() > 128 || req.models.len() > 20 {
            return Err(TokenBitsError::InvalidRequest);
        }
        let lock = self.lock(user).await;
        let _guard = lock.lock().await;
        let mut state = self.access(user).await?;
        let catalog = self.catalog_with_token(user, &state.access_token).await?;
        let group = catalog
            .groups
            .iter()
            .find(|g| g.id == req.group)
            .ok_or(TokenBitsError::InvalidRequest)?;
        let mut models = if req.models.is_empty() {
            vec![group.recommended_model.clone()]
        } else {
            req.models
        };
        models.sort();
        models.dedup();
        if models
            .iter()
            .any(|m| !group.models.iter().any(|candidate| &candidate.id == m))
        {
            return Err(TokenBitsError::InvalidRequest);
        }
        let mut staged = Vec::new();
        for model in models {
            let identity =
                serde_json::to_vec(&json!([state.device_id, req.group, model])).map_err(|_| TokenBitsError::Storage)?;
            let key = URL_SAFE_NO_PAD.encode(Sha256::digest(identity));
            let result = self
                .client
                .request::<RemoteConnection>(
                    Method::POST,
                    "/connections",
                    Some(&state.access_token),
                    Some(json!({"model": model,"group":req.group,"idempotency_key":key})),
                )
                .await;
            let connection = self.handle_remote(user, result).await?;
            if connection.model != model || connection.group != req.group || connection.id <= 0 {
                return Err(TokenBitsError::Unavailable);
            }
            let result = self
                .client
                .request::<RemoteKey>(
                    Method::POST,
                    &format!("/connections/{}/key", connection.id),
                    Some(&state.access_token),
                    Some(json!({})),
                )
                .await;
            let key = self.handle_remote(user, result).await?;
            if key.key.is_empty() {
                return Err(TokenBitsError::Unavailable);
            }
            let encrypted_key = encrypt_string(&key.key, &self.encryption_key)?;
            staged.push((connection.id.to_string(), model, encrypted_key));
        }
        let inputs: Vec<_> = staged
            .iter()
            .map(|(id, model, key)| ManagedProviderInput {
                group: &req.group,
                user_id: user,
                connection_id: id,
                model,
                base_url: &catalog.api_base_url,
                encrypted_key: key,
            })
            .collect();
        let ids = self.repo.sync_providers(user, &inputs).await?;
        let providers: Vec<_> = ids
            .into_iter()
            .zip(staged)
            .map(|(provider_id, (_, model, _))| TokenBitsSyncedProvider {
                provider_id,
                model,
                group: req.group.clone(),
            })
            .collect();
        let last_sync_at = now();
        state.last_sync_at = Some(last_sync_at);
        self.save(user, &state).await?;
        tracing::info!(models = providers.len(), "TokenBits models synchronized");
        Ok(TokenBitsSyncResponse {
            synced: providers.len(),
            providers,
            last_sync_at,
        })
    }

    pub async fn disconnect(&self, user: &str) -> Result<()> {
        let lock = self.lock(user).await;
        let _guard = lock.lock().await;
        self.pending.lock().await.remove(user);
        if let Some(flow) = self.browser_pending.lock().await.remove(user) {
            let _ = flow.close_listener.send(true);
        }
        if let Some(original) = self.load(user).await? {
            if original.issuer != self.client.issuer() {
                return Err(TokenBitsError::RevocationUnconfirmed);
            }
            let state = match self.access(user).await {
                Ok(state) => state,
                Err(TokenBitsError::Reauthorization | TokenBitsError::DeviceRevoked) => original,
                Err(e) => return Err(e),
            };
            let result = self
                .client
                .request::<serde_json::Value>(Method::DELETE, "/device", Some(&state.access_token), None)
                .await;
            match result {
                Ok(_) | Err(TokenBitsError::DeviceRevoked) => {}
                Err(TokenBitsError::Reauthorization | TokenBitsError::Remote("expired_token")) => {
                    return Err(TokenBitsError::RevocationUnconfirmed);
                }
                Err(e) => return Err(e),
            }
        }
        self.repo.clear(user).await?;
        tracing::info!("TokenBits disconnected and local credentials cleared");
        Ok(())
    }
}

fn digest_secret(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}
fn verify_browser_binding(expected: Option<[u8; 32]>, provided: Option<&str>) -> Result<()> {
    match expected {
        Some(expected) if !provided.is_some_and(|value| bool::from(expected.ct_eq(&digest_secret(value)))) => {
            Err(TokenBitsError::BrowserBinding)
        }
        None if provided.is_some() => Err(TokenBitsError::BrowserBinding),
        _ => Ok(()),
    }
}
fn validate_browser_redirect(client_id: &str, value: &str) -> Result<()> {
    let url = reqwest::Url::parse(value).map_err(|_| TokenBitsError::InvalidRequest)?;
    if value.len() > 2048
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/tokenbits/callback"
        || url.host_str().is_none()
        || url.port() == Some(0)
    {
        return Err(TokenBitsError::InvalidRequest);
    }
    let allowed = if client_id == "aionui-desktop" {
        url.scheme() == "http" && url.host_str() == Some("127.0.0.1") && url.port().is_some()
    } else {
        url.scheme() == "https"
            || url.scheme() == "http" && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
    };
    if allowed {
        Ok(())
    } else {
        Err(TokenBitsError::InvalidRequest)
    }
}

fn now() -> i64 {
    aionui_common::now_ms() / 1000
}
fn random_secret() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| TokenBitsError::Unavailable)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
fn validate_token(token: &RemoteToken) -> Result<()> {
    if token.access_token.is_empty()
        || token.refresh_token.is_empty()
        || token.device_id <= 0
        || !(1..=86400).contains(&token.expires_in)
    {
        Err(TokenBitsError::Unavailable)
    } else {
        Ok(())
    }
}
fn poll_response(status: &str, interval: u64) -> TokenBitsPollResponse {
    TokenBitsPollResponse {
        status: status.into(),
        interval,
    }
}

#[cfg(test)]
mod browser_expiry_tests {
    use super::*;
    use aionui_db::{SqliteTokenBitsRepository, init_database_memory};

    #[tokio::test]
    async fn expired_flow_is_not_exchanged_and_can_be_restarted() {
        let db = init_database_memory().await.unwrap();
        let service = TokenBitsService::new(
            Arc::new(SqliteTokenBitsRepository::new(db.pool().clone())),
            [42; 32],
            TokenBitsClient::new("http://127.0.0.1:1").unwrap(),
        );
        let request = || TokenBitsBrowserAuthorizeRequest {
            client_id: "aionui-web".into(),
            device_name: "Expiry fixture".into(),
            redirect_uri: Some("https://web.example/tokenbits/callback".into()),
        };
        let started = service
            .start_browser_authorization("system_default_user", request(), None)
            .await
            .unwrap();
        let state = {
            let mut pending = service.browser_pending.lock().await;
            let flow = pending.get_mut("system_default_user").unwrap();
            flow.response.expires_at = now() - 1;
            flow.state.clone()
        };
        assert_eq!(
            service
                .browser_authorization_status("system_default_user", &started.authorization.flow_id)
                .await
                .unwrap()
                .status,
            "expired"
        );
        let error = service
            .complete_browser_authorization(
                "system_default_user",
                TokenBitsBrowserCompleteRequest {
                    flow_id: started.authorization.flow_id.clone(),
                    code: format!("wb_bc_{}", "x".repeat(48)),
                    state,
                },
                started.binding_cookie.as_deref(),
            )
            .await;
        assert!(matches!(error, Err(TokenBitsError::Remote("expired_token"))));
        let restarted = service
            .start_browser_authorization("system_default_user", request(), None)
            .await
            .unwrap();
        assert_ne!(started.authorization.flow_id, restarted.authorization.flow_id);
    }
}
