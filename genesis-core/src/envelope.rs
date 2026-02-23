//! Envelope encryption / decryption.
//!
//! Envelope encryption wraps key material with a KMS-managed key so that
//! the raw secret never leaves the operator's memory unprotected.  The
//! ciphertext (the "envelope") can be safely persisted in etcd / a
//! Kubernetes Secret because only the KMS can unwrap it.

use crate::kms::KmsProvider;
use crate::GenesisError;

/// Wrap `key_bytes` using the given KMS provider.
///
/// The returned ciphertext is opaque to the caller and can only be
/// recovered via [`envelope_decrypt`] with the same KMS key.
pub fn envelope_encrypt(kms: &dyn KmsProvider, key_bytes: &[u8]) -> Result<Vec<u8>, GenesisError> {
    kms.encrypt(key_bytes)
}

/// Unwrap a previously-wrapped ciphertext using the given KMS provider.
///
/// Returns the original key bytes.
pub fn envelope_decrypt(kms: &dyn KmsProvider, ciphertext: &[u8]) -> Result<Vec<u8>, GenesisError> {
    kms.decrypt(ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kms::mock::MockKmsProvider;

    #[test]
    fn roundtrip() {
        let kms = MockKmsProvider::new();
        let secret = b"AGE-SECRET-KEY-1EXAMPLE";
        let envelope = envelope_encrypt(&kms, secret).expect("wrap should succeed");
        assert_ne!(&envelope[..], secret);
        let recovered = envelope_decrypt(&kms, &envelope).expect("unwrap should succeed");
        assert_eq!(recovered, secret);
    }

    #[test]
    fn empty_key_roundtrip() {
        let kms = MockKmsProvider::new();
        let envelope = envelope_encrypt(&kms, b"").expect("wrap empty should succeed");
        let recovered = envelope_decrypt(&kms, &envelope).expect("unwrap empty should succeed");
        assert_eq!(recovered, b"");
    }

    #[test]
    fn encrypt_with_failing_kms() {
        let kms = MockKmsProvider::new_failing("HSM unavailable".into());
        let result = envelope_encrypt(&kms, b"secret");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("HSM unavailable"));
    }

    #[test]
    fn decrypt_with_failing_kms() {
        let kms = MockKmsProvider::new_failing("vault sealed".into());
        let result = envelope_decrypt(&kms, b"ciphertext");
        assert!(result.is_err());
    }

    #[test]
    fn large_key_material() {
        let kms = MockKmsProvider::new();
        let large_key = vec![0x42u8; 4096];
        let envelope = envelope_encrypt(&kms, &large_key).expect("wrap large should succeed");
        let recovered = envelope_decrypt(&kms, &envelope).expect("unwrap large should succeed");
        assert_eq!(recovered, large_key);
    }
}
