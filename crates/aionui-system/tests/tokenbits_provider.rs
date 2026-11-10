use aionui_api_types::UpdateProviderRequest;
use aionui_common::encrypt_string;
use aionui_db::{
    ITokenBitsRepository, ManagedProviderInput, SqliteProviderRepository, SqliteTokenBitsRepository,
    init_database_memory,
};
use aionui_system::{ProviderService, SystemError};
use std::sync::Arc;

#[tokio::test]
async fn managed_keys_never_serialize_and_generic_mutations_are_rejected() {
    let db = init_database_memory().await.unwrap();
    let repo = SqliteTokenBitsRepository::new(db.pool().clone());
    let key = [42; 32];
    let id = repo
        .upsert_provider(ManagedProviderInput {
            group: "default",
            user_id: "system_default_user",
            connection_id: "7",
            model: "one",
            base_url: "https://api.tokenbits.net/v1",
            encrypted_key: &encrypt_string("sk-secret-only-core", &key).unwrap(),
        })
        .await
        .unwrap();
    let service = ProviderService::new(Arc::new(SqliteProviderRepository::new(db.pool().clone())), key);
    let response = service.list("system_default_user").await.unwrap();
    assert_eq!(response[0].credential_source, "tokenbits");
    assert_eq!(response[0].api_key, "");
    assert!(
        !serde_json::to_string(&response)
            .unwrap()
            .contains("sk-secret-only-core")
    );
    assert!(service.list("other-user").await.unwrap().is_empty());
    assert!(matches!(
        service
            .update(
                "system_default_user",
                &id,
                UpdateProviderRequest {
                    base_url: Some("https://evil.example".into()),
                    ..Default::default()
                }
            )
            .await,
        Err(SystemError::Conflict(_))
    ));
    assert!(matches!(
        service.delete("system_default_user", &id).await,
        Err(SystemError::Conflict(_))
    ));
}
