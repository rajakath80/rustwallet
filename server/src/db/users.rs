//! Helper module for DB > Users table CRUD
use anyhow::{Context, Result};
use sqlx::PgPool;
use uuid::Uuid;

/// Upsert an user based on email
/// #Parameters
/// 1. pool: Postgres Pool
/// 2. email: user email
pub async fn get_or_create_user(pool: &PgPool, email: &str) -> Result<Uuid> {
    let rec = sqlx::query!(
        r#"
    INSERT INTO users(email) 
    VALUES ($1) 
    ON CONFLICT (email)
    DO UPDATE SET email = users.email 
    RETURNING id
    "#,
        email
    )
    .fetch_one(pool)
    .await
    .context("Failed to upsert user")?;
    Ok(rec.id)
}
