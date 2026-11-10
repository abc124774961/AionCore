use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenBitsAccountIdentity {
    pub id: i64,
    pub display_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenBitsStatus {
    pub connected: bool,
    pub needs_reauthorization: bool,
    pub issuer: String,
    pub device_id: Option<i64>,
    pub account: Option<TokenBitsAccountIdentity>,
    pub last_sync_at: Option<i64>,
    pub provider_count: i64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenBitsAuthorizeRequest {
    pub client_id: String,
    pub device_name: String,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct TokenBitsAuthorization {
    pub flow_id: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_at: i64,
    pub interval: u64,
}

#[derive(Deserialize, Serialize)]
pub struct TokenBitsPollResponse {
    pub status: String,
    pub interval: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenBitsSyncRequest {
    pub group: String,
    #[serde(default)]
    pub models: Vec<String>,
}

#[derive(Deserialize, Serialize)]
pub struct TokenBitsSyncedProvider {
    pub provider_id: String,
    pub model: String,
    pub group: String,
}

#[derive(Deserialize, Serialize)]
pub struct TokenBitsSyncResponse {
    pub providers: Vec<TokenBitsSyncedProvider>,
    pub synced: usize,
    pub last_sync_at: i64,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct TokenBitsAccount {
    pub account: TokenBitsAccountIdentity,
    pub wallet_quota: i64,
    pub quota_per_unit: f64,
    pub billing_preference: String,
    #[serde(default, deserialize_with = "null_default")]
    pub subscriptions: Vec<serde_json::Value>,
    pub updated_at: i64,
    pub topup_url: String,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct TokenBitsCatalogModel {
    pub id: String,
    pub supported_endpoint_types: Vec<String>,
    pub pricing: std::collections::HashMap<String, String>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct TokenBitsCatalogGroup {
    pub id: String,
    pub name: String,
    #[serde(default, deserialize_with = "null_default")]
    pub models: Vec<TokenBitsCatalogModel>,
    pub recommended_model: String,
    pub recommendation_reason: String,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct TokenBitsCatalog {
    pub provider: String,
    #[serde(default, deserialize_with = "null_default")]
    pub groups: Vec<TokenBitsCatalogGroup>,
    pub group: String,
    #[serde(default, deserialize_with = "null_default")]
    pub models: Vec<TokenBitsCatalogModel>,
    pub recommended_model: String,
    pub recommendation_reason: String,
    pub billing: serde_json::Value,
    pub api_base_url: String,
    pub protocol: String,
}

fn null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}
