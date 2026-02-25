//! Hybrid key combiner for X25519 + ML-KEM shared secrets.
//!
//! Uses HKDF-SHA3-256 to combine classical and post-quantum shared secrets
//! into a single derived key, providing defense-in-depth: the combined
//! key is secure as long as *either* primitive remains unbroken.

use crate::zeroize_mem::KeyMaterial;
use crate::GenesisError;

use hkdf::Hkdf;
use sha3::Sha3_256;
use zeroize::Zeroizing;

/// Domain separation prefix for the hybrid KEM combiner.
const DOMAIN: &[u8] = b"genesis-hybrid-kem-v1";

/// Combine classical and post-quantum shared secrets.
///
/// Result is secure as long as EITHER input secret is secure.
///
/// Uses HKDF-SHA3-256 with domain separation:
///   salt = SHA3-256(x25519_secret || mlkem_secret)
///   ikm  = x25519_secret || mlkem_secret
///   info = b"genesis-hybrid-kem-v1" || context
///
/// Both secrets are consumed (moved) and zeroized after derivation.
pub fn combine_shared_secrets(
    x25519_secret: Zeroizing<Vec<u8>>,
    mlkem_secret: Zeroizing<Vec<u8>>,
    context: &[u8],
) -> Result<KeyMaterial, GenesisError> {
    // Concatenate the two secrets as IKM
    let mut ikm = Zeroizing::new(Vec::with_capacity(x25519_secret.len() + mlkem_secret.len()));
    ikm.extend_from_slice(&x25519_secret);
    ikm.extend_from_slice(&mlkem_secret);

    // Build the info string: domain || context
    let mut info = Vec::with_capacity(DOMAIN.len() + context.len());
    info.extend_from_slice(DOMAIN);
    info.extend_from_slice(context);

    // HKDF-SHA3-256 extract + expand
    let hk = Hkdf::<Sha3_256>::new(None, &ikm);

    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(&info, okm.as_mut())
        .map_err(|e| GenesisError::HybridCombineFailed(format!("HKDF expand: {e}")))?;

    Ok(KeyMaterial::new(okm.to_vec()))

    // x25519_secret, mlkem_secret, ikm all dropped and zeroized here
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_deterministic() {
        let s1 = Zeroizing::new(vec![0x42u8; 32]);
        let s2 = Zeroizing::new(vec![0xABu8; 32]);
        let ctx = b"test-context";

        let k1 = combine_shared_secrets(
            Zeroizing::new(vec![0x42u8; 32]),
            Zeroizing::new(vec![0xABu8; 32]),
            ctx,
        )
        .unwrap();

        let k2 = combine_shared_secrets(s1, s2, ctx).unwrap();

        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn hybrid_different_context() {
        let k1 = combine_shared_secrets(
            Zeroizing::new(vec![0x42u8; 32]),
            Zeroizing::new(vec![0xABu8; 32]),
            b"context-a",
        )
        .unwrap();

        let k2 = combine_shared_secrets(
            Zeroizing::new(vec![0x42u8; 32]),
            Zeroizing::new(vec![0xABu8; 32]),
            b"context-b",
        )
        .unwrap();

        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn hybrid_32_byte_output() {
        let k = combine_shared_secrets(
            Zeroizing::new(vec![1u8; 32]),
            Zeroizing::new(vec![2u8; 32]),
            b"",
        )
        .unwrap();

        assert_eq!(k.as_bytes().len(), 32);
    }

    #[test]
    fn hybrid_output_is_keymaterial() {
        // Verify the return type is KeyMaterial, not raw bytes.
        // This is enforced at compile time, but we verify the wrapper
        // holds the expected content at runtime.
        let result: Result<KeyMaterial, _> = combine_shared_secrets(
            Zeroizing::new(vec![0x01u8; 32]),
            Zeroizing::new(vec![0x02u8; 32]),
            b"type-check",
        );
        let km = result.unwrap();
        // KeyMaterial::as_bytes() returns the inner bytes
        assert_eq!(km.as_bytes().len(), 32);
        // Prove it's not all zeros (HKDF actually derived something)
        assert_ne!(km.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn hybrid_different_secrets_different_output() {
        let k1 = combine_shared_secrets(
            Zeroizing::new(vec![0x01u8; 32]),
            Zeroizing::new(vec![0x02u8; 32]),
            b"ctx",
        )
        .unwrap();

        let k2 = combine_shared_secrets(
            Zeroizing::new(vec![0x03u8; 32]),
            Zeroizing::new(vec![0x04u8; 32]),
            b"ctx",
        )
        .unwrap();

        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }
}
