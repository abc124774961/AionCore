#[derive(Debug, thiserror::Error)]
pub enum TokenBitsError {
    #[error("Invalid TokenBits request")]
    InvalidRequest,
    #[error("TokenBits authorization belongs to another browser")]
    BrowserBinding,
    #[error("TokenBits authorization not found")]
    NotFound,
    #[error("Reconnect your TokenBits account")]
    Reauthorization,
    #[error("TokenBits device has been revoked")]
    DeviceRevoked,
    #[error("Remote revocation could not be confirmed; revoke this device in TokenBits")]
    RevocationUnconfirmed,
    #[error("TokenBits is temporarily unavailable")]
    Unavailable,
    #[error("TokenBits storage is unavailable")]
    Storage,
    #[error("TokenBits request failed: {0}")]
    Remote(&'static str),
}

impl From<aionui_db::DbError> for TokenBitsError {
    fn from(_: aionui_db::DbError) -> Self {
        Self::Storage
    }
}

impl From<aionui_common::CryptoError> for TokenBitsError {
    fn from(_: aionui_common::CryptoError) -> Self {
        Self::Storage
    }
}

pub(crate) fn remote_error(code: &str) -> TokenBitsError {
    use TokenBitsError::*;
    match code {
        "authorization_pending" => Remote("authorization_pending"),
        "slow_down" => Remote("slow_down"),
        "access_denied" => Remote("access_denied"),
        "expired_token" => Remote("expired_token"),
        "device_revoked" => DeviceRevoked,
        "invalid_grant" | "unauthorized" | "account_disabled" => Reauthorization,
        "model_unavailable" => Remote("model_unavailable"),
        "connection_inactive" => Remote("connection_inactive"),
        "token_limit" => Remote("token_limit"),
        "idempotency_conflict" => Remote("idempotency_conflict"),
        "invalid_request" => InvalidRequest,
        "not_found" => NotFound,
        _ => Unavailable,
    }
}
