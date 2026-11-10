ALTER TABLE providers ADD COLUMN credential_source TEXT NOT NULL DEFAULT 'manual';
CREATE TABLE IF NOT EXISTS tokenbits_accounts (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 state_encrypted TEXT NOT NULL,
 updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tokenbits_provider_bindings (
 provider_id TEXT PRIMARY KEY REFERENCES providers(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 connection_id TEXT NOT NULL,
 model_group TEXT NOT NULL,
 UNIQUE(user_id, connection_id)
);
