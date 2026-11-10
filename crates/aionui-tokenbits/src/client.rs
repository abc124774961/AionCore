use crate::error::{TokenBitsError, remote_error};
use reqwest::{Client, Method, Url};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;
use std::time::Duration;

pub const DEFAULT_ISSUER: &str = "https://api.tokenbits.net";
const RESPONSE_LIMIT: usize = 2 * 1024 * 1024;

#[derive(Clone)]
pub struct TokenBitsClient {
    issuer: Url,
    http: Client,
}

#[derive(Deserialize)]
struct Envelope<T> {
    success: bool,
    data: Option<T>,
    code: Option<String>,
}

impl TokenBitsClient {
    /// Issuer configuration is supplied by the composition root, never a request.
    pub fn new(issuer: &str) -> Result<Self, TokenBitsError> {
        let issuer = Url::parse(issuer).map_err(|_| TokenBitsError::InvalidRequest)?;
        let loopback = matches!(issuer.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        if !(issuer.scheme() == "https" || issuer.scheme() == "http" && loopback)
            || issuer.host_str().is_none()
            || !issuer.username().is_empty()
            || issuer.password().is_some()
            || issuer.query().is_some()
            || issuer.fragment().is_some()
            || issuer.path() != "/"
        {
            return Err(TokenBitsError::InvalidRequest);
        }
        let http = Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("aioncore-tokenbits/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| TokenBitsError::Unavailable)?;
        Ok(Self { issuer, http })
    }
    pub fn issuer(&self) -> String {
        self.issuer.as_str().trim_end_matches('/').to_owned()
    }
    pub fn validate_url(&self, value: &str) -> Result<(), TokenBitsError> {
        let url = Url::parse(value).map_err(|_| TokenBitsError::Unavailable)?;
        if url.origin() != self.issuer.origin() || !url.username().is_empty() || url.password().is_some() {
            return Err(TokenBitsError::Unavailable);
        }
        Ok(())
    }
    pub async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> Result<T, TokenBitsError> {
        let url = self
            .issuer
            .join(&format!("/api/workbench{path}"))
            .map_err(|_| TokenBitsError::InvalidRequest)?;
        let mut req = self.http.request(method, url);
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }
        if let Some(body) = body {
            req = req.json(&body);
        }
        let mut response = req.send().await.map_err(|_| TokenBitsError::Unavailable)?;
        let status = response.status();
        if response.content_length().is_some_and(|n| n > RESPONSE_LIMIT as u64) {
            return Err(TokenBitsError::Unavailable);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| TokenBitsError::Unavailable)? {
            if bytes.len() + chunk.len() > RESPONSE_LIMIT {
                return Err(TokenBitsError::Unavailable);
            }
            bytes.extend_from_slice(&chunk);
        }
        let envelope: Envelope<T> = serde_json::from_slice(&bytes).map_err(|_| TokenBitsError::Unavailable)?;
        if !status.is_success() || !envelope.success {
            return Err(remote_error(
                envelope.code.as_deref().unwrap_or("temporarily_unavailable"),
            ));
        }
        envelope
            .data
            .or_else(|| serde_json::from_value(Value::Null).ok())
            .ok_or(TokenBitsError::Unavailable)
    }
}
