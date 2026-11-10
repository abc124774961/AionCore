use crate::service::TokenBitsService;
use std::sync::Arc;

#[derive(Clone)]
pub struct TokenBitsRouterState {
    pub service: Arc<TokenBitsService>,
    pub local: bool,
    pub local_secret: Option<String>,
}

#[derive(Clone)]
pub struct TokenBitsHostedRouterState {
    pub service: Arc<TokenBitsService>,
    pub bootstrap_secret: Arc<str>,
}
