//! # Wallet Dealer Demo Example Code
//! 1. Test dealer setup
//! 2. Test AWS KMS key setup
//! 3. Wrap key
//! 4. Unwrap key
use anyhow::Result;
use wallet_core::{KeyProvider, KmsKeyProvider, dealer_setup};

/// Example dealer demo test main entrypoint
#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();

    // 1. Test dealer setup
    let threshold = 2;
    let total = 3;
    let (shares, pk_blob) = dealer_setup(threshold, total)?;
    println!("Generated {} shares", shares.len());
    println!("PublicKeyPackage (first 16 bytes): {:02x?}", &pk_blob[..16]);

    // 2. Test AWS KMS setup
    let alias = std::env::var("KMS_KEY_ID").unwrap();
    let provider = KmsKeyProvider::new(alias).await;
    let dek = b"my-32-byte-symmetric-key-0123456789";

    // 3. Wrap
    let wrapped = provider.wrap_key(dek).await?;
    println!("KMS wrapped {} bytes to {} bytes", dek.len(), wrapped.len());

    // 4. Unwrap
    let unwrapped = provider.unwrap_key(&wrapped).await?;
    assert_eq!(unwrapped, dek, "unwrap must round-trip");
    println!("KMS unwrap round-trip successful");

    Ok(())
}
