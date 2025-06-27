//! Actix server backend to receive API calls
//! Entrypoint for frontend connections

use actix_cors::Cors;
use actix_web::{App, HttpServer, http, web::Data};
use anyhow::{Context, Result};
use sqlx::PgPool;
use tracing_actix_web::TracingLogger;
use tracing_subscriber::{EnvFilter, Registry, fmt, layer::SubscriberExt};
use wallet_core::KmsKeyProvider;

use crate::routes::wallet::create_wallet;

mod routes {
    pub mod wallet;
}

mod db;

/// Main entry point for the Uniwallet server.
/// - Loads env vars (`SERVER`, `PORT`, `KMS_KEY_ID`, `DATABASE_URL`).
/// - Initializes tracing subscriber (EnvFilter + fmt).
/// - Connects to Postgres and initializes KMS provider.
/// - Launches the Actix HTTP server with configured routes.
#[actix_web::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    let server = std::env::var("SERVER").expect("SERVER env var is required.");
    let port = std::env::var("PORT")
        .expect("SERVER env variable is required.")
        .parse::<u16>()
        .unwrap();

    let kms_key_id = std::env::var("KMS_KEY_ID").expect("KMS KEY ID env var is required");
    let database_url = std::env::var("DATABASE_URL").expect("KMS KEY ID env var is required");

    let filter_layer = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt_layer = fmt::layer().with_target(false);

    let subscriber = Registry::default().with(filter_layer).with(fmt_layer);
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set global tracing subscriber");

    let pool = PgPool::connect(&database_url)
        .await
        .context("Failed to connect to DB")?;
    let kms_provider = KmsKeyProvider::new(kms_key_id).await;

    HttpServer::new(move || {
        App::new()
            .wrap(
                Cors::default()
                    .allowed_origin("http://localhost:3000")
                    .allowed_methods(vec!["POST", "GET", "PUT", "OPTIONS"])
                    .allowed_headers(vec![http::header::CONTENT_TYPE])
                    .max_age(3600),
            )
            .wrap(TracingLogger::default())
            .app_data(Data::new(pool.clone()))
            .app_data(Data::new(kms_provider.clone()))
            .service(create_wallet)
    })
    .bind((server, port))?
    .run()
    .await?;
    Ok(())
}
