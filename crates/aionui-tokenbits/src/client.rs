use crate::error::{TokenBitsError, remote_error};
use reqwest::{Client, Method, Url};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;
use std::time::Duration;

pub const DEFAULT_ISSUER: &str = "https://api.tokenbits.net";
pub const DEFAULT_BROWSER_ORIGIN: &str = "https://ai.tokenbits.net";
const RESPONSE_LIMIT: usize = 2 * 1024 * 1024;

#[derive(Clone)]
pub struct TokenBitsClient {
    issuer: Url,
    browser_origin: Url,
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
        Self::with_browser_origin(
            issuer,
            if issuer.trim_end_matches('/') == DEFAULT_ISSUER {
                DEFAULT_BROWSER_ORIGIN
            } else {
                issuer
            },
        )
    }
    /// Only the composition root may override the browser origin at startup.
    pub fn with_browser_origin(issuer: &str, browser_origin: &str) -> Result<Self, TokenBitsError> {
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
        let browser_origin = Url::parse(browser_origin).map_err(|_| TokenBitsError::InvalidRequest)?;
        let browser_loopback = matches!(browser_origin.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        if !(browser_origin.scheme() == "https" || browser_origin.scheme() == "http" && browser_loopback)
            || browser_origin.host_str().is_none()
            || !browser_origin.username().is_empty()
            || browser_origin.password().is_some()
            || browser_origin.query().is_some()
            || browser_origin.fragment().is_some()
            || browser_origin.path() != "/"
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
        Ok(Self {
            issuer,
            browser_origin,
            http,
        })
    }
    pub fn issuer(&self) -> String {
        self.issuer.as_str().trim_end_matches('/').to_owned()
    }
    pub fn browser_origin(&self) -> String {
        self.browser_origin.as_str().trim_end_matches('/').to_owned()
    }
    pub fn browser_authorization_url(
        &self,
        client_id: &str,
        device_name: &str,
        redirect_uri: &str,
        state: &str,
        challenge: &str,
    ) -> Result<String, TokenBitsError> {
        let mut url = self
            .browser_origin
            .join("/aionui/connect")
            .map_err(|_| TokenBitsError::InvalidRequest)?;
        url.query_pairs_mut()
            .append_pair("client_id", client_id)
            .append_pair("device_name", device_name)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("state", state)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(url.into())
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
