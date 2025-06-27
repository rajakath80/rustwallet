-- enable pgcrypto for gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- users table - id, email, created_at
CREATE TABLE users ( id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT UNIQUE, created_at TIMESTAMPTZ NOT NULL DEFAULT now() );

-- frost_server_shares table - user_id, encrypted_share, created_at
CREATE TABLE frost_server_shares ( user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, encrypted_share BYTEA NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now() );

-- wallet_backups table - user_id, encrypted_backup, created_at
CREATE TABLE wallet_backups ( user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, encrypted_backup BYTEA NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now() );