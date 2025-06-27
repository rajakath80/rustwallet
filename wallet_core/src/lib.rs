//! # Uniwallet Core
//! This crate implements the core cryptographic and key-management flows for
//! a threshold-based wallet:
//! - FROST threshold key generation: Dealer setup to split private key into shares
//! - AWS KMS envelope encryption: Secure server-share custody under a customer-managed CMK
//! - Solana address derivation: Extract group public key and compute Solana pubkey
//! - Share serialization & distribution: Serialize shares for client-side storage and WebAuthn-locked flows

use anyhow::Result;
use async_trait::async_trait;
use aws_config::{BehaviorVersion, meta::region::RegionProviderChain};
use aws_sdk_kms::{
    Client as KmsClient,
    operation::{decrypt::DecryptError, encrypt::EncryptError},
    primitives::Blob,
};
use aws_smithy_runtime_api::{client::result::SdkError, http::Response};
use frost::keys::{IdentifierList, generate_with_dealer};
use frost_ristretto255::{self as frost, keys::PublicKeyPackage};
use rand::rngs::OsRng;
use solana_sdk::pubkey::Pubkey;
use thiserror::Error;
use tracing::instrument;
use zeroize::Zeroize;

type KmsEncryptError = SdkError<EncryptError, Response>;
type KmsDecryptError = SdkError<DecryptError, Response>;

/// Re-export the FROST Identifier type for downstream crates:
pub use frost::Identifier;

/// Errors for provider operations
#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("KMS error: {0}")]
    Kms(#[from] aws_sdk_kms::Error),
    // #[error("Serialization error: {0}")]
    // Serialize(#[from] EncodeError),
    #[error("Encrypt error: {0}")]
    KmsEncrypt(#[from] KmsEncryptError),
    #[error("Decrypt error: {0}")]
    KmsDecrypt(#[from] KmsDecryptError),
}

/// Generic interface for wrapping/unwrapping Data Encryption Keys (DEK).
#[async_trait]
pub trait KeyProvider: Send + Sync {
    /// Encrypt key
    async fn wrap_key(&self, dek: &[u8]) -> Result<Vec<u8>, ProviderError>;
    /// Decrypt key
    async fn unwrap_key(&self, blob: &[u8]) -> Result<Vec<u8>, ProviderError>;
}

/// AWS KMS implementation pub struct KmsKeyProvider
#[derive(Debug, Clone)]
pub struct KmsKeyProvider {
    /// KMS client
    client: KmsClient,
    /// KMS key_id (arn)
    key_id: String,
}

impl KmsKeyProvider {
    /// New provider construction.
    /// Use AWS config (.env) to load AWS SDK and Get Client
    pub async fn new(key_id: impl Into<String>) -> Self {
        let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");
        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(region_provider)
            .load()
            .await;
        let client = KmsClient::new(&config);
        Self {
            client,
            key_id: key_id.into(),
        }
    }
}

/// Implementations for KmsKeyProvider
#[async_trait]
impl KeyProvider for KmsKeyProvider {
    /// Wraps a data encryption key (DEK) using AWS KMS.
    /// This function calls the AWS KMS Encrypt API to wrap (encrypt) the provided plaintext DEK
    /// under the configured Customer Master Key (CMK). It returns the ciphertext blob, which
    /// can be safely stored in persistent storage (e.g., your database) for later decryption.
    /// # Parameters
    /// * dek - A byte slice containing the plaintext data encryption key to wrap.
    /// # Returns
    /// A Vec<u8> containing the KMS-encrypted ciphertext blob on success.
    /// # Errors
    /// Returns ProviderError::Kms if the underlying AWS KMS Encrypt API call fails,
    /// or if the response from KMS does not include a valid ciphertext.
    #[instrument(level = "debug", skip(self, dek))]
    async fn wrap_key(&self, dek: &[u8]) -> Result<Vec<u8>, ProviderError> {
        let response = self
            .client
            .encrypt()
            .key_id(&self.key_id)
            .plaintext(Blob::new(dek))
            .send()
            .await?;
        Ok(response
            .ciphertext_blob
            .expect("Could not encrypt")
            .as_ref()
            .to_vec())
    }

    /// Calls the AWS KMS Decrypt API to retrieve the plaintext DEK corresponding to the provided ciphertext blob.
    /// Internally zeroizes the decrypted buffer after cloning the plaintext to prevent residual data in memory.
    /// # Parameters
    /// * blob – A byte slice containing the KMS-encrypted ciphertext blob produced by wrap_key.
    /// # Returns
    /// Returns a Vec<u8> holding the decrypted plaintext DEK on success.
    /// # Errors
    /// Returns ProviderError::Kms if the AWS KMS Decrypt API call fails or the response does not contain valid plaintext.
    #[instrument(level = "debug", skip(self, blob))]
    async fn unwrap_key(&self, blob: &[u8]) -> Result<Vec<u8>, ProviderError> {
        //decrypt via KMS
        let response = self
            .client
            .decrypt()
            .ciphertext_blob(Blob::new(blob))
            .send()
            .await?;
        let mut pt = response.plaintext.unwrap().into_inner();
        //clone before zeroize
        let response = pt.clone();
        // zeroize original buffer for hygiene
        pt.zeroize();
        Ok(response)
    }
}

/// Generate FROST shares via trusted dealer
/// Returns:
/// 1. Vec of (Identifier, serialized_share) for each share
/// 2. Serialized PublicKeyPackage blob (group public key + signer pubkeys)
/// Generate FROST threshold key shares via a trusted-dealer setup.
/// Performs the one-time dealer setup phase of the FROST threshold Schnorr protocol,
/// producing total key shares of which any threshold can later jointly sign.
/// Each share and the combined public-key package are serialized for storage and distribution.
/// # Parameters
/// * threshold – The minimum number of shares required to create a valid signature.
/// * total – The total number of shares to generate in the dealer setup.
/// # Returns
/// On success, returns a tuple containing:
/// 1. A Vec<(Identifier, Vec<u8>)> of each node’s serialized secret share.
/// 2. A Vec<u8> containing the serialized PublicKeyPackage (group public key + verification shares).
/// # Errors
/// Returns an error if key generation fails or share/package serialization errors occur.
#[instrument(level = "debug", skip_all)]
pub fn dealer_setup(threshold: u16, total: u16) -> Result<(Vec<(Identifier, Vec<u8>)>, Vec<u8>)> {
    let identifiers = IdentifierList::Default;
    let (shares_map, pk_pkg) = generate_with_dealer(total, threshold, identifiers, &mut OsRng)?;
    let mut serialized_shares = Vec::with_capacity(shares_map.len());
    for (id, share) in shares_map {
        let ser: Vec<u8> = share.serialize()?;
        serialized_shares.push((id, ser));
    }

    // serialize pub key package
    let pub_pkg: Vec<u8> = pk_pkg.serialize()?;
    Ok((serialized_shares, pub_pkg))
}

/// Create a Solana wallet using FROST shares
/// Performs dealer setup, serializes shares and public-key package,
/// derives the Solana address from the group public key.
/// Create a new Solana wallet using FROST threshold keys.
/// Invokes dealer_setup to generate FROST shares, then derives the Solana address
/// from the group public key contained in the PublicKeyPackage.
/// # Parameters
/// * threshold – Minimum number of shares required to sign transactions.
/// * total – Total number of shares to generate.
/// # Returns
/// Returns a tuple of:
/// 1. The Solana address as a Base58-encoded String.
/// 2. A Vec<(Identifier, Vec<u8>)> of all serialized secret shares.
/// 3. A Vec<u8> of the serialized PublicKeyPackage.
/// # Errors
/// Returns an error if key generation, serialization, or address derivation fails.
pub fn create_solana_wallet(
    threshold: u16,
    total: u16,
) -> Result<String, Vec<(Identifier, Vec<u8>)>> {
    // generate shares
    let (shares, pk_blob) = dealer_setup(threshold, total).map_err(|_| Vec::new())?;

    //deserialize package to extract group pub key
    let pkg = PublicKeyPackage::deserialize(&pk_blob).map_err(|_| shares.clone())?;

    let group_bytes = pkg.verifying_key().to_element().compress().to_bytes();
    let sol_pk = Pubkey::new_from_array(group_bytes);
    Ok(sol_pk.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_ristretto255::keys::{PublicKeyPackage, SecretShare};

    struct TestKeyProvider;

    /// Test Key Provider implementation
    #[async_trait]
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

    /// Kms wrap and unwrap test
    #[tokio::test]
    async fn kms_wrap_unwrap_roundtrip() {
        let provider = TestKeyProvider;
        let dek = b"supersecretkey";
        let blob = provider.wrap_key(dek).await.unwrap();
        let pt = provider.unwrap_key(&blob).await.unwrap();
        assert_eq!(pt, dek);
    }

    /// Dealer setup test
    #[test]
    fn dealer_setup_success() {
        let (shares, pk_blob) = dealer_setup(2, 3).unwrap();
        assert_eq!(shares.len(), 3, "Expected 3 shares");
        assert!(
            !pk_blob.is_empty(),
            "PublicKeyPackage blob should not be empty"
        );
    }

    /// Dealer shares serialize and deserialize
    #[test]
    fn share_serialize_deserialize_roundtrip() {
        let (shares, _) = dealer_setup(2, 4).unwrap();
        for (id, ser) in shares {
            let share: SecretShare = SecretShare::deserialize(&ser).unwrap();
            let ser2 = share.serialize().unwrap();
            assert_eq!(ser, ser2, "Serialized share mismatch for id {:?}", id);
        }
    }

    /// Public keys serialize and deserialize test
    #[test]
    fn package_serialize_deserialize_roundtrip() {
        let (_, pk_blob) = dealer_setup(3, 5).unwrap();
        let pkg: PublicKeyPackage = PublicKeyPackage::deserialize(&pk_blob).unwrap();
        let pk2 = pkg.serialize().unwrap();
        assert_eq!(pk_blob, pk2, "PublicKeyPackage serialization mismatch");
    }

    /// Create solana wallet test
    #[test]
    fn test_create_solana_wallet_success() {
        let addr = create_solana_wallet(2, 3).expect("should generate a solana address");

        //ensure valid base58 and 32 bytes
        let pk = addr.parse::<Pubkey>().unwrap();
        assert_eq!(pk.to_bytes().len(), 32);
    }
}
