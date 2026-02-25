//! Post-quantum cryptographic primitives.
//!
//! This module is feature-gated behind `pq` and provides ML-KEM-1024
//! (FIPS 203 key encapsulation) and ML-DSA-87 (FIPS 204 digital signatures).
//!
//! All private key material is wrapped in [`KeyMaterial`] and never exposed
//! as raw `&[u8]`.

use crate::zeroize_mem::KeyMaterial;
use crate::GenesisError;

// ── ML-KEM-1024 (FIPS 203) ──────────────────────────────────────────

/// Generate an ML-KEM-1024 keypair.
///
/// Returns `(encapsulation_key_bytes, decapsulation_key_material)`.
/// The encapsulation (public) key is returned as plain bytes; the
/// decapsulation (private) key seed (64 bytes) is wrapped in [`KeyMaterial`].
pub fn mlkem_generate_keypair() -> Result<(Vec<u8>, KeyMaterial), GenesisError> {
    use ml_kem::kem::{Kem, KeyExport};
    use ml_kem::MlKem1024;

    let (dk, ek) = MlKem1024::generate_keypair();
    let ek_bytes = KeyExport::to_bytes(&ek).to_vec();
    let dk_seed = dk
        .to_seed()
        .ok_or_else(|| GenesisError::PqKeyGenFailed("seed not available".into()))?;
    Ok((ek_bytes, KeyMaterial::new(dk_seed.to_vec())))
}

/// Encapsulate a shared secret using an ML-KEM-1024 public key.
///
/// Returns `(ciphertext, shared_secret)`. The ciphertext is sent to the
/// key owner; the shared secret is used locally for key derivation.
pub fn mlkem_encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), GenesisError> {
    use ml_kem::kem::Encapsulate;
    use ml_kem::EncapsulationKey1024;

    let ek_key = public_key.try_into().map_err(|_| {
        GenesisError::PqEncapsulateFailed(format!(
            "invalid encapsulation key length: got {}",
            public_key.len()
        ))
    })?;
    let ek = EncapsulationKey1024::new(ek_key)
        .map_err(|_| GenesisError::PqEncapsulateFailed("invalid encapsulation key".into()))?;

    let (ct, ss) = ek.encapsulate();
    let ct_bytes: Vec<u8> = ct.to_vec();
    let ss_bytes: Vec<u8> = ss.to_vec();
    Ok((ct_bytes, ss_bytes))
}

/// Decapsulate a shared secret using an ML-KEM-1024 private key.
///
/// The private key must be provided as [`KeyMaterial`] containing the
/// 64-byte seed — raw `&[u8]` is not accepted to enforce the security
/// invariant.
pub fn mlkem_decapsulate(
    private_key: &KeyMaterial,
    ciphertext: &[u8],
) -> Result<Vec<u8>, GenesisError> {
    use ml_kem::kem::Decapsulate;
    use ml_kem::DecapsulationKey1024;

    let seed = private_key.as_bytes().try_into().map_err(|_| {
        GenesisError::PqDecapsulateFailed(format!(
            "invalid decapsulation key seed length: expected 64, got {}",
            private_key.as_bytes().len()
        ))
    })?;
    let dk = DecapsulationKey1024::from_seed(seed);

    let ct = ciphertext.try_into().map_err(|_| {
        GenesisError::PqDecapsulateFailed(format!(
            "invalid ciphertext length: got {}",
            ciphertext.len()
        ))
    })?;

    let ss = dk.decapsulate(ct);
    Ok(ss.to_vec())
}

// ── ML-DSA-87 (FIPS 204) ────────────────────────────────────────────

/// Generate an ML-DSA-87 keypair.
///
/// Returns `(verifying_key_bytes, signing_key_seed_material)`.
/// The verifying (public) key is returned as plain bytes; the
/// signing (private) key seed (32 bytes) is wrapped in [`KeyMaterial`].
pub fn mldsa_generate_keypair() -> Result<(Vec<u8>, KeyMaterial), GenesisError> {
    use getrandom::{rand_core::UnwrapErr, SysRng};
    use ml_dsa::{KeyGen, MlDsa87};

    let mut rng = UnwrapErr(SysRng);
    let kp = MlDsa87::key_gen(&mut rng);
    let vk_bytes = kp.verifying_key().encode().to_vec();
    let seed = kp.to_seed();
    Ok((vk_bytes, KeyMaterial::new(seed.to_vec())))
}

/// Sign a message using an ML-DSA-87 private key.
///
/// The private key must be provided as [`KeyMaterial`] containing the
/// 32-byte seed.
pub fn mldsa_sign(private_key: &KeyMaterial, message: &[u8]) -> Result<Vec<u8>, GenesisError> {
    use ml_dsa::signature::Signer;
    use ml_dsa::SigningKey;

    let seed: &ml_dsa::Seed = private_key.as_bytes().try_into().map_err(|_| {
        GenesisError::PqSignFailed(format!(
            "invalid signing key seed length: expected 32, got {}",
            private_key.as_bytes().len()
        ))
    })?;
    let sk = SigningKey::<ml_dsa::MlDsa87>::from_seed(seed);
    let sig = sk.sign(message);
    Ok(sig.encode().to_vec())
}

/// Verify an ML-DSA-87 signature.
///
/// Returns `true` if the signature is valid, `false` otherwise.
pub fn mldsa_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, GenesisError> {
    use ml_dsa::signature::Verifier;
    use ml_dsa::{MlDsa87, Signature, VerifyingKey};

    let vk_enc = public_key.try_into().map_err(|_| {
        GenesisError::PqVerifyFailed(format!(
            "invalid verifying key length: got {}",
            public_key.len()
        ))
    })?;
    let vk = VerifyingKey::<MlDsa87>::decode(vk_enc);

    let sig = Signature::<MlDsa87>::try_from(signature)
        .map_err(|e| GenesisError::PqVerifyFailed(format!("signature decode: {e}")))?;

    Ok(vk.verify(message, &sig).is_ok())
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mlkem_roundtrip() {
        let (ek_bytes, dk) = mlkem_generate_keypair().unwrap();
        let (ct, ss_sender) = mlkem_encapsulate(&ek_bytes).unwrap();
        let ss_receiver = mlkem_decapsulate(&dk, &ct).unwrap();
        assert_eq!(ss_sender, ss_receiver);
    }

    #[test]
    fn mlkem_wrong_key_fails() {
        let (ek_bytes, _dk1) = mlkem_generate_keypair().unwrap();
        let (_ek2, dk2) = mlkem_generate_keypair().unwrap();
        let (ct, ss_sender) = mlkem_encapsulate(&ek_bytes).unwrap();
        let ss_wrong = mlkem_decapsulate(&dk2, &ct).unwrap();
        // ML-KEM is IND-CCA2: wrong key produces a different (implicit reject) secret
        assert_ne!(ss_sender, ss_wrong);
    }

    #[test]
    fn mlkem_keypair_sizes() {
        let (ek_bytes, dk) = mlkem_generate_keypair().unwrap();
        assert_eq!(ek_bytes.len(), 1568, "ML-KEM-1024 encapsulation key");
        // Private key stored as 64-byte seed
        assert_eq!(
            dk.as_bytes().len(),
            64,
            "ML-KEM-1024 decapsulation key seed"
        );
    }

    #[test]
    fn mlkem_ciphertext_and_secret_sizes() {
        let (ek_bytes, _dk) = mlkem_generate_keypair().unwrap();
        let (ct, ss) = mlkem_encapsulate(&ek_bytes).unwrap();
        assert_eq!(ct.len(), 1568, "ML-KEM-1024 ciphertext");
        assert_eq!(ss.len(), 32, "ML-KEM-1024 shared secret");
    }

    #[test]
    fn mldsa_sign_verify() {
        let (vk_bytes, sk) = mldsa_generate_keypair().unwrap();
        let msg = b"test message for signing";
        let sig = mldsa_sign(&sk, msg).unwrap();
        let valid = mldsa_verify(&vk_bytes, msg, &sig).unwrap();
        assert!(valid);
    }

    #[test]
    fn mldsa_wrong_key_rejects() {
        let (_vk1, sk1) = mldsa_generate_keypair().unwrap();
        let (vk2, _sk2) = mldsa_generate_keypair().unwrap();
        let msg = b"test message";
        let sig = mldsa_sign(&sk1, msg).unwrap();
        let valid = mldsa_verify(&vk2, msg, &sig).unwrap();
        assert!(!valid);
    }

    #[test]
    fn mldsa_tampered_rejects() {
        let (vk_bytes, sk) = mldsa_generate_keypair().unwrap();
        let msg = b"original message";
        let sig = mldsa_sign(&sk, msg).unwrap();
        let tampered = b"tampered message";
        let valid = mldsa_verify(&vk_bytes, tampered, &sig).unwrap();
        assert!(!valid);
    }

    #[test]
    fn mldsa_keypair_sizes() {
        let (vk_bytes, sk) = mldsa_generate_keypair().unwrap();
        assert_eq!(vk_bytes.len(), 2592, "ML-DSA-87 verifying key");
        // Private key stored as 32-byte seed
        assert_eq!(sk.as_bytes().len(), 32, "ML-DSA-87 signing key seed");
    }
}
