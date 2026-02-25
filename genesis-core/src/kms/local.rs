//! Local KMS provider using a file-based master key.
//!
//! For bare-metal and local deployments where no cloud KMS is available.
//! The master key is stored on-disk as a hybrid envelope (V2), encrypted
//! to the operator's identity keys. On init, the operator provides their
//! identity; the provider decrypts the master key into memory ([`KeyMaterial`])
//! and uses it for all encrypt/decrypt ops.
//!
//! This eliminates the cloud KMS dependency while preserving the envelope
//! encryption pattern (master key wraps DEKs, DEKs wrap secrets).

use std::path::Path;

use crate::envelope::hybrid::HybridEnvelope;
use crate::kms::KmsProvider;
use crate::zeroize_mem::KeyMaterial;
use crate::GenesisError;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

/// Local KMS provider using a file-based master key.
///
/// The master key lives in Rust memory as [`KeyMaterial`] and is used
/// for symmetric envelope operations (ChaCha20-Poly1305).
pub struct LocalKmsProvider {
    master_key: KeyMaterial,
}

impl LocalKmsProvider {
    /// Initialize from a master key envelope file.
    ///
    /// The file contains a [`HybridEnvelope`] wrapping the 32-byte master key.
    pub fn from_envelope(
        envelope_path: &Path,
        age_identity: &KeyMaterial,
        mlkem_private_key: &KeyMaterial,
    ) -> Result<Self, GenesisError> {
        let data = std::fs::read(envelope_path)
            .map_err(|e| GenesisError::KmsCallFailed(format!("read envelope: {e}")))?;

        let envelope = HybridEnvelope::from_bytes(&data)?;
        let master_key_bytes = envelope.open(age_identity, mlkem_private_key)?;

        Ok(Self {
            master_key: KeyMaterial::new(master_key_bytes),
        })
    }

    /// Generate a new master key and write the envelope to disk.
    ///
    /// Returns a provider initialized with the new master key.
    pub fn generate(
        envelope_path: &Path,
        age_recipient: &str,
        mlkem_public_key: &[u8],
        signing_key: &KeyMaterial,
    ) -> Result<Self, GenesisError> {
        // Generate random 32-byte master key
        let mut master_key_bytes = vec![0u8; 32];
        getrandom::fill(&mut master_key_bytes)
            .map_err(|e| GenesisError::PqKeyGenFailed(format!("RNG: {e}")))?;

        // Seal it in a hybrid envelope
        let envelope = HybridEnvelope::seal(
            &master_key_bytes,
            age_recipient,
            mlkem_public_key,
            signing_key,
        )?;

        // Write to disk
        let bytes = envelope.to_bytes();
        std::fs::write(envelope_path, &bytes)
            .map_err(|e| GenesisError::KmsCallFailed(format!("write envelope: {e}")))?;

        Ok(Self {
            master_key: KeyMaterial::new(master_key_bytes),
        })
    }

    /// Create from an already-decrypted master key (for testing).
    #[cfg(any(test, feature = "mock"))]
    pub fn from_key(master_key: KeyMaterial) -> Self {
        Self { master_key }
    }
}

impl KmsProvider for LocalKmsProvider {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, GenesisError> {
        let cipher = ChaCha20Poly1305::new(self.master_key.as_bytes().into());

        let mut nonce_bytes = [0u8; 12];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|e| GenesisError::KmsCallFailed(format!("RNG: {e}")))?;
        let nonce = Nonce::from(nonce_bytes);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| GenesisError::KmsCallFailed(format!("encrypt: {e}")))?;

        // Prepend nonce
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, GenesisError> {
        if ciphertext.len() < 12 {
            return Err(GenesisError::KmsCallFailed("ciphertext too short".into()));
        }

        let cipher = ChaCha20Poly1305::new(self.master_key.as_bytes().into());
        let nonce = Nonce::from_slice(&ciphertext[..12]);

        cipher
            .decrypt(nonce, &ciphertext[12..])
            .map_err(|e| GenesisError::KmsCallFailed(format!("decrypt: {e}")))
    }

    fn provider_name(&self) -> &str {
        "local"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{age, pq};

    fn generate_test_keys() -> (String, KeyMaterial, Vec<u8>, KeyMaterial, KeyMaterial) {
        let (age_rcpt, age_id) = age::generate_keypair().unwrap();
        let (mlkem_pk, mlkem_sk) = pq::mlkem_generate_keypair().unwrap();
        let (_signing_pk, signing_sk) = pq::mldsa_generate_keypair().unwrap();
        (age_rcpt, age_id, mlkem_pk, mlkem_sk, signing_sk)
    }

    #[test]
    fn local_kms_roundtrip() {
        let master_key = KeyMaterial::new(vec![0x42u8; 32]);
        let kms = LocalKmsProvider::from_key(master_key);

        let plaintext = b"local KMS test secret";
        let ct = kms.encrypt(plaintext).unwrap();
        assert_ne!(&ct[..], plaintext);
        let pt = kms.decrypt(&ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn local_kms_persist_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master-key.enc");

        let (age_rcpt, age_id, mlkem_pk, mlkem_sk, signing_sk) = generate_test_keys();

        // Generate and persist
        let kms1 = LocalKmsProvider::generate(&path, &age_rcpt, &mlkem_pk, &signing_sk).unwrap();
        let ct = kms1.encrypt(b"persist test").unwrap();

        // Reload from disk
        let kms2 = LocalKmsProvider::from_envelope(&path, &age_id, &mlkem_sk).unwrap();
        let pt = kms2.decrypt(&ct).unwrap();
        assert_eq!(pt, b"persist test");
    }

    #[test]
    fn local_kms_wrong_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master-key.enc");

        let (age_rcpt, _age_id, mlkem_pk, mlkem_sk, signing_sk) = generate_test_keys();

        LocalKmsProvider::generate(&path, &age_rcpt, &mlkem_pk, &signing_sk).unwrap();

        // Try loading with wrong age identity
        let (_wrong_rcpt, wrong_id) = age::generate_keypair().unwrap();
        let result = LocalKmsProvider::from_envelope(&path, &wrong_id, &mlkem_sk);
        assert!(result.is_err());
    }

    #[test]
    fn local_kms_wrong_mlkem_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master-key.enc");

        let (age_rcpt, age_id, mlkem_pk, _mlkem_sk, signing_sk) = generate_test_keys();

        LocalKmsProvider::generate(&path, &age_rcpt, &mlkem_pk, &signing_sk).unwrap();

        // Try loading with wrong ML-KEM key
        let (_wrong_pk, wrong_sk) = pq::mlkem_generate_keypair().unwrap();
        let result = LocalKmsProvider::from_envelope(&path, &age_id, &wrong_sk);
        assert!(result.is_err());
    }

    #[test]
    fn local_kms_provider_name() {
        let kms = LocalKmsProvider::from_key(KeyMaterial::new(vec![0u8; 32]));
        assert_eq!(kms.provider_name(), "local");
    }

    #[test]
    fn local_kms_empty_plaintext() {
        let kms = LocalKmsProvider::from_key(KeyMaterial::new(vec![0x11u8; 32]));
        let ct = kms.encrypt(b"").unwrap();
        let pt = kms.decrypt(&ct).unwrap();
        assert_eq!(pt, b"");
    }
}
