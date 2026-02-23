//! In-memory mock KMS provider for testing.
//!
//! Uses a simple reversible XOR transform with a fixed pad so that
//! `decrypt(encrypt(x)) == x` without any external service.  An optional
//! "fail mode" makes every call return an error, useful for testing error
//! paths.

use crate::GenesisError;

use super::KmsProvider;

/// Fixed 32-byte XOR pad used by the mock.  Not secret -- this is a test
/// helper, not a real KMS.
const XOR_PAD: [u8; 32] = [
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78,
];

/// In-memory mock that applies a reversible XOR transform.
pub struct MockKmsProvider {
    /// If `Some`, every call to `encrypt`/`decrypt` returns this error.
    fail_msg: Option<String>,
}

impl MockKmsProvider {
    /// Create a mock that succeeds on every operation.
    pub fn new() -> Self {
        Self { fail_msg: None }
    }

    /// Create a mock that fails with `error_msg` on every operation.
    pub fn new_failing(error_msg: String) -> Self {
        Self {
            fail_msg: Some(error_msg),
        }
    }

    /// XOR `data` against the repeating pad.  Applying twice yields the
    /// original input.
    fn xor_transform(data: &[u8]) -> Vec<u8> {
        data.iter()
            .enumerate()
            .map(|(i, byte)| byte ^ XOR_PAD[i % XOR_PAD.len()])
            .collect()
    }
}

impl Default for MockKmsProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl KmsProvider for MockKmsProvider {
    fn provider_name(&self) -> &str {
        "mock"
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, GenesisError> {
        if let Some(msg) = &self.fail_msg {
            return Err(GenesisError::KmsCallFailed(msg.clone()));
        }
        Ok(Self::xor_transform(plaintext))
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, GenesisError> {
        if let Some(msg) = &self.fail_msg {
            return Err(GenesisError::KmsCallFailed(msg.clone()));
        }
        Ok(Self::xor_transform(ciphertext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let kms = MockKmsProvider::new();
        let plaintext = b"genesis secret key material";
        let ciphertext = kms.encrypt(plaintext).expect("encrypt should succeed");
        assert_ne!(&ciphertext[..], plaintext);
        let decrypted = kms.decrypt(&ciphertext).expect("decrypt should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn empty_data_roundtrip() {
        let kms = MockKmsProvider::new();
        let ciphertext = kms.encrypt(b"").expect("encrypt empty should succeed");
        let decrypted = kms
            .decrypt(&ciphertext)
            .expect("decrypt empty should succeed");
        assert_eq!(decrypted, b"");
    }

    #[test]
    fn failing_provider_encrypt() {
        let kms = MockKmsProvider::new_failing("simulated KMS outage".into());
        let result = kms.encrypt(b"data");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("simulated KMS outage"));
    }

    #[test]
    fn failing_provider_decrypt() {
        let kms = MockKmsProvider::new_failing("vault sealed".into());
        let result = kms.decrypt(b"data");
        assert!(result.is_err());
    }

    #[test]
    fn provider_name() {
        let kms = MockKmsProvider::new();
        assert_eq!(kms.provider_name(), "mock");
    }

    #[test]
    fn default_impl() {
        let kms = MockKmsProvider::default();
        let ciphertext = kms.encrypt(b"test").expect("default should succeed");
        let decrypted = kms.decrypt(&ciphertext).expect("default should succeed");
        assert_eq!(decrypted, b"test");
    }
}
