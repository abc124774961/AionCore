use crate::{DbError, SqlitePool};

pub struct ManagedProviderInput<'a> {
    pub user_id: &'a str,
    pub connection_id: &'a str,
    pub group: &'a str,
    pub model: &'a str,
    pub base_url: &'a str,
    pub encrypted_key: &'a str,
}

#[async_trait::async_trait]
pub trait ITokenBitsRepository: Send + Sync {
    async fn load(&self, user_id: &str) -> Result<Option<String>, DbError>;
    async fn save(&self, user_id: &str, encrypted: &str) -> Result<(), DbError>;
    async fn clear(&self, user_id: &str) -> Result<(), DbError>;
    async fn upsert_provider(&self, input: ManagedProviderInput<'_>) -> Result<String, DbError>;
    async fn sync_providers(&self, user_id: &str, inputs: &[ManagedProviderInput<'_>]) -> Result<Vec<String>, DbError>;
    async fn disable_providers(&self, user_id: &str) -> Result<(), DbError>;
    async fn provider_count(&self, user_id: &str) -> Result<i64, DbError>;
}

pub struct SqliteTokenBitsRepository {
    pool: SqlitePool,
}

impl SqliteTokenBitsRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl ITokenBitsRepository for SqliteTokenBitsRepository {
    async fn load(&self, user_id: &str) -> Result<Option<String>, DbError> {
        Ok(
            sqlx::query_scalar("SELECT state_encrypted FROM tokenbits_accounts WHERE user_id = ?")
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }
    async fn save(&self, user_id: &str, encrypted: &str) -> Result<(), DbError> {
        sqlx::query("INSERT INTO tokenbits_accounts(user_id,state_encrypted,updated_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET state_encrypted=excluded.state_encrypted,updated_at=excluded.updated_at")
            .bind(user_id).bind(encrypted).bind(aionui_common::now_ms()).execute(&self.pool).await?;
        Ok(())
    }
    async fn clear(&self, user_id: &str) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "UPDATE providers SET enabled=0,api_key_encrypted='' WHERE user_id=? AND credential_source='tokenbits'",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM tokenbits_accounts WHERE user_id=?")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
    async fn upsert_provider(&self, input: ManagedProviderInput<'_>) -> Result<String, DbError> {
        let mut tx = self.pool.begin().await?;
        let id = upsert_in_transaction(&mut tx, &input).await?;
        tx.commit().await?;
        Ok(id)
    }
    async fn sync_providers(&self, user_id: &str, inputs: &[ManagedProviderInput<'_>]) -> Result<Vec<String>, DbError> {
        let mut tx = self.pool.begin().await?;
        let mut ids = Vec::new();
        for input in inputs {
            if input.user_id != user_id {
                return Err(DbError::Init("Managed provider owner mismatch".into()));
            }
            ids.push(upsert_in_transaction(&mut tx, input).await?);
        }
        tx.commit().await?;
        Ok(ids)
    }
    async fn disable_providers(&self, user_id: &str) -> Result<(), DbError> {
        sqlx::query("UPDATE providers SET enabled=0 WHERE user_id=? AND credential_source='tokenbits'")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    async fn provider_count(&self, user_id: &str) -> Result<i64, DbError> {
        Ok(sqlx::query_scalar(
            "SELECT COUNT(*) FROM providers WHERE user_id=? AND credential_source='tokenbits' AND enabled=1",
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?)
    }
}

async fn upsert_in_transaction(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    input: &ManagedProviderInput<'_>,
) -> Result<String, DbError> {
    let existing: Option<String> =
        sqlx::query_scalar("SELECT provider_id FROM tokenbits_provider_bindings WHERE user_id=? AND connection_id=?")
            .bind(input.user_id)
            .bind(input.connection_id)
            .fetch_optional(&mut **tx)
            .await?;
    let id = existing.unwrap_or_else(|| aionui_common::generate_prefixed_id("prov"));
    let models = serde_json::to_string(&vec![input.model]).map_err(|e| DbError::Init(e.to_string()))?;
    let settings = serde_json::json!({input.model: {"openai_api_mode": "chat_completions"}}).to_string();
    sqlx::query("INSERT INTO providers(id,user_id,platform,name,base_url,api_key_encrypted,models,enabled,capabilities,model_settings,credential_source,created_at,updated_at) VALUES(?,?,'openai',?,?,?,?,1,'[{\"type\":\"text\"}]',?,'tokenbits',?,?) ON CONFLICT(id) DO UPDATE SET base_url=excluded.base_url,api_key_encrypted=excluded.api_key_encrypted,models=excluded.models,model_settings=excluded.model_settings,enabled=1,updated_at=excluded.updated_at")
            .bind(&id).bind(input.user_id).bind(format!("TokenBits · {} · {}", input.group, input.model)).bind(input.base_url)
            .bind(input.encrypted_key).bind(models).bind(settings).bind(aionui_common::now_ms()).bind(aionui_common::now_ms())
            .execute(&mut **tx).await?;
    sqlx::query("INSERT INTO tokenbits_provider_bindings(provider_id,user_id,connection_id,model_group) VALUES(?,?,?,?) ON CONFLICT(user_id,connection_id) DO NOTHING")
            .bind(&id).bind(input.user_id).bind(input.connection_id).bind(input.group).execute(&mut **tx).await?;
    Ok(id)
}
