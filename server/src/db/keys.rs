//! Helper module for DB > frost_server_shares table CRUD

use anyhow::{Context, Result};
use sqlx::PgPool;
use uuid::Uuid;

/// Upsert an user's frost_server_shares
/// #Parameters
/// 1. pool: Postgres Pool
/// 2. user_id (Uuis): user id
/// 3. encrypted_key: frost private key share
pub async fn store_server_share(pool: &PgPool, user_id: Uuid, encrypted_key: &[u8]) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO frost_server_shares(user_id, encrypted_share) 
        VALUES ($1, $2) 
        ON CONFLICT (user_id) 
        DO UPDATE SET encrypted_share = EXCLUDED.encrypted_share
        "#,
        user_id,
        encrypted_key
    )
    .execute(pool)
    .await
    .context("DB insert failed")?;
    Ok(())
}
