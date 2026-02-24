//! KMS provider abstraction and implementations.
//!
//! The [`KmsProvider`] trait defines the interface for envelope encryption
//! operations.  Concrete implementations live in sub-modules; at build time
//! only the mock is unconditional -- cloud providers will be feature-gated
//! in a future work-front.

pub mod aws;
pub mod azure;
pub mod config;
pub mod gcp;
#[cfg(any(test, feature = "mock"))]
pub mod mock;

use crate::GenesisError;

/// Abstraction over a Key Management Service (KMS) provider.
///
/// Implementations encrypt and decrypt data encryption keys (DEKs) using
/// a customer-managed key (CMK) stored in the KMS.  The operator never
/// sees the CMK -- only the wrapped/unwrapped DEK bytes.
///
/// Implementations must be `Send + Sync` for use from async reconcile loops.
pub trait KmsProvider: Send + Sync {
    /// Encrypt `plaintext` (a DEK) using the configured CMK.
    ///
    /// Returns the ciphertext blob that can only be decrypted by calling
    /// [`decrypt`](KmsProvider::decrypt) with the same CMK.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, GenesisError>;

    /// Decrypt a previously-encrypted `ciphertext` blob back to the
    /// original DEK plaintext.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, GenesisError>;

    /// Human-readable provider name for audit trails (e.g. `"aws-kms"`,
    /// `"oci-vault"`, `"mock"`).
    fn provider_name(&self) -> &str;
}

/// A no-op KMS provider for testing that returns plaintext unchanged.
///
/// **Never use in production** -- this provides zero encryption.
#[cfg(any(test, feature = "mock"))]
pub struct NullKmsProvider;

#[cfg(any(test, feature = "mock"))]
impl KmsProvider for NullKmsProvider {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, GenesisError> {
        Ok(plaintext.to_vec())
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, GenesisError> {
        Ok(ciphertext.to_vec())
    }

    fn provider_name(&self) -> &str {
        "null-dev"
    }
}
