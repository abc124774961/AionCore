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
use tokio::sync::Mutex;

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
}

impl TokenBitsService {
    pub fn new(repo: Arc<dyn ITokenBitsRepository>, encryption_key: [u8; 32], client: TokenBitsClient) -> Self {
        Self {
            repo,
            encryption_key,
            client,
            locks: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
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
