//! Module `wallet`
//! This module provides the `/wallet/create` endpoint to initialize a new threshold wallet for a user.
//! - Upserts or creates a user record by email.
//! - Performs FROST dealer setup to split a private key into threshold shares.
//! - Encrypts the server's share using AWS KMS and persists it.
//! - Returns the client shares and public-key package for local storage.

use actix_web::{
    Error, HttpResponse, Responder,
    error::ErrorInternalServerError,
    post,
    web::{Data, Json},
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::instrument;
use wallet_core::{Identifier, KeyProvider, KmsKeyProvider, dealer_setup};

use crate::db::{keys::store_server_share, users::get_or_create_user};

/// CreateWalletRequest
/// #Elements
/// email: user email
/// password: user password
/// threshold: FROST threshold x out of y (total)
/// total: FROST total share
#[derive(Serialize, Deserialize, Debug)]
pub struct CreateWalletRequest {
    pub email: String,
    pub password: String,
    pub threshold: u16,
    pub total: u16,
}

/// CreateWalletResponse
/// client_shares: FROST client share
/// public_key_package: public key package
#[derive(Serialize)]
pub struct CreateWalletResponse {
    user_id: String,
    client_shares: Vec<(wallet_core::Identifier, Vec<u8>)>,
    public_key_package: Vec<u8>,
}

/// Wallet enumeration with
/// Eth
///     private_key
///     public_key
///     address: ETH looking address 0x
/// Sol
///     private_key
///     public_key
#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "wallet", rename_all = "lowercase")]
pub enum Wallet {
    Eth {
        private_key: String,
        public_key: String,
        address: String,
    },
    Sol {
        private_key: String,
        public_key: String,
    },
}

/// Handles wallet initialization:
/// 1. Upserts the user by email and retrieves their UUID.
/// 2. Runs FROST dealer setup to generate threshold key shares.
/// 3. Splits out the server's share and encrypts it via AWS KMS.
/// 4. Persists the encrypted share and returns the client shares.
#[post("/wallet/create")]
#[instrument(name = "create_wallet", skip(pool, kms_provider, req))]
async fn create_wallet(
    pool: Data<PgPool>,
    kms_provider: Data<KmsKeyProvider>,
    req: Json<CreateWalletRequest>,
) -> Result<impl Responder, Error> {
    let user_id = get_or_create_user(&pool, &req.email)
        .await
        .map_err(|_| ErrorInternalServerError("Could not create or update user"))?;

    tracing::debug!("User created or updated: {:?}", user_id);

    // 1. Dealer setup: generate all shares and public key package
    let (all_shares, pk_pkg) =
        dealer_setup(req.threshold, req.total).map_err(ErrorInternalServerError)?;

    // 2. Split server vs client shares
    let server_id = Identifier::new(1u16.into()).map_err(ErrorInternalServerError)?;

    let mut client_shares = Vec::new();
    let mut server_share_bytes = None;
    for (id, share_bytes) in all_shares {
        if id == server_id {
            server_share_bytes = Some(share_bytes);
        } else {
            client_shares.push((id, share_bytes))
        }
    }
    let server_bytes = server_share_bytes
        .ok_or_else(|| ErrorInternalServerError("Could not find server share for user"))?;

    // 3. Wrap server share with KMS
    let encrypted = kms_provider
        .wrap_key(&server_bytes)
        .await
        .map_err(|_| ErrorInternalServerError("Could not encrypt key"))?;

    // 4. Persist server share to DB
    let _ = store_server_share(pool.get_ref(), user_id, &encrypted)
        .await
        .map_err(|_| ErrorInternalServerError("Could not save to database"));

    tracing::debug!(
        "Wallet created with client shares: {:?} and pub key package: {:?}",
        client_shares,
        pk_pkg
    );

    Ok(HttpResponse::Ok().json(CreateWalletResponse {
        user_id: user_id.to_string(),
        client_shares,
        public_key_package: pk_pkg,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, http, test, web::Data};
    use serde_json::json;
    use sqlx::postgres::PgPoolOptions;
    // use std::time::Duration;
    use wallet_core::ProviderError;

    struct TestKeyProvider;

    /// Test Key Provider implementation
    #[async_trait::async_trait]
    impl KeyProvider for TestKeyProvider {
        async fn wrap_key(&self, dek: &[u8]) -> Result<Vec<u8>, ProviderError> {
            let mut v = dek.to_vec();
            v.reverse();
            Ok(v)
        }
        async fn unwrap_key(&self, blob: &[u8]) -> Result<Vec<u8>, ProviderError> {
            let mut v = blob.to_vec();
            v.reverse();
            Ok(v)
        }
    }

    #[actix_web::test]
    async fn invalid_threshold_returns_500() {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://invalid/doesnotexist");
        let kms = TestKeyProvider;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(pool))
                .app_data(Data::new(kms))
                .service(create_wallet),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/wallet/create")
            .set_json(&json!({
                "email": "test@test.com",
                "password": "pass",
                "threshold": 3,
                "total": 2
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[actix_web::test]
    async fn valid_threshold_returns_db_500() {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://invalid/doesnotexist");
        let kms = TestKeyProvider;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(pool))
                .app_data(Data::new(kms))
                .service(create_wallet),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/wallet/create")
            .set_json(&json!({
                "email": "test@test.com",
                "password": "pass",
                "threshold": 1,
                "total": 2
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    // todo
    // Mockall for integration testing
}
