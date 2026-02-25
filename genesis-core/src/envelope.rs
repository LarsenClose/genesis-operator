//! Envelope encryption / decryption.
//!
//! Envelope encryption wraps key material with a KMS-managed key so that
//! the raw secret never leaves the operator's memory unprotected.  The
//! ciphertext (the "envelope") can be safely persisted in etcd / a
//! Kubernetes Secret because only the KMS can unwrap it.
//!
//! When the `pq` feature is enabled, a [`HybridEnvelope`] is available
//! that combines X25519 (via age) with ML-KEM-1024 and ML-DSA-87 signing.

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

// ── Hybrid Envelope (PQ feature) ────────────────────────────────────

#[cfg(feature = "pq")]
pub mod hybrid {
    use crate::crypto::{age, hybrid as hybrid_crypto, pq};
    use crate::zeroize_mem::KeyMaterial;
    use crate::GenesisError;
    use zeroize::Zeroizing;

    /// Magic bytes for V2 hybrid envelopes.
    const MAGIC_V2: &[u8; 4] = b"GEN2";

    /// Envelope version discriminant.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum EnvelopeVersion {
        /// Legacy: age-only encryption (no PQ).
        V1Age,
        /// Hybrid: X25519 + ML-KEM-1024, ML-DSA-87 signed.
        V2Hybrid,
    }

    /// A hybrid envelope combining classical and post-quantum key encapsulation.
    ///
    /// Seal flow:
    /// 1. Generate random 32-byte classical shared secret
    /// 2. Encrypt it with age to the X25519 recipient → `age_ciphertext`
    /// 3. ML-KEM-1024 encapsulate → `(mlkem_ciphertext, ss_pq)`
    /// 4. `combined_dek = HKDF-SHA3-256(ss_classical || ss_pq)`
    /// 5. `encrypted_secret = ChaCha20-Poly1305(plaintext, combined_dek)`
    /// 6. `signature = ML-DSA-87.Sign(sha3(mlkem_ct || age_ct || encrypted_secret))`
    #[derive(Debug, Clone)]
    pub struct HybridEnvelope {
        pub version: EnvelopeVersion,
        pub mlkem_ciphertext: Vec<u8>,
        pub age_ciphertext: Vec<u8>,
        pub encrypted_secret: Vec<u8>,
        pub signature: Vec<u8>,
        pub signing_public_key: Vec<u8>,
    }

    impl HybridEnvelope {
        /// Seal plaintext into a hybrid envelope.
        pub fn seal(
            plaintext: &[u8],
            age_recipient: &str,
            mlkem_public_key: &[u8],
            signing_key: &KeyMaterial,
        ) -> Result<Self, GenesisError> {
            use chacha20poly1305::aead::{Aead, KeyInit};
            use chacha20poly1305::{ChaCha20Poly1305, Nonce};
            use sha3::Digest;

            // 1. Generate random 32-byte classical shared secret
            let mut ss_classical_bytes = Zeroizing::new(vec![0u8; 32]);
            getrandom::fill(&mut ss_classical_bytes[..])
                .map_err(|e| GenesisError::PqKeyGenFailed(format!("RNG: {e}")))?;

            // 2. Encrypt classical secret with age
            let age_ciphertext = age::encrypt_with_public_key(age_recipient, &ss_classical_bytes)?;

            // 3. ML-KEM-1024 encapsulate
            let (mlkem_ciphertext, ss_pq_bytes) = pq::mlkem_encapsulate(mlkem_public_key)?;

            // 4. Derive combined DEK
            let combined_dek = hybrid_crypto::combine_shared_secrets(
                ss_classical_bytes,
                Zeroizing::new(ss_pq_bytes),
                b"seal",
            )?;

            // 5. ChaCha20-Poly1305 encrypt
            let cipher = ChaCha20Poly1305::new(combined_dek.as_bytes().into());
            let mut nonce_bytes = [0u8; 12];
            getrandom::fill(&mut nonce_bytes)
                .map_err(|e| GenesisError::PqEncapsulateFailed(format!("RNG: {e}")))?;
            let nonce = Nonce::from(nonce_bytes);

            let ciphertext = cipher
                .encrypt(&nonce, plaintext)
                .map_err(|e| GenesisError::AgeEncryptFailed(format!("ChaCha20 encrypt: {e}")))?;

            // Prepend nonce to encrypted secret
            let mut encrypted_secret = Vec::with_capacity(12 + ciphertext.len());
            encrypted_secret.extend_from_slice(&nonce_bytes);
            encrypted_secret.extend_from_slice(&ciphertext);

            // 6. Sign: SHA3-256(mlkem_ct || age_ct || encrypted_secret)
            let mut hasher = sha3::Sha3_256::new();
            hasher.update(&mlkem_ciphertext);
            hasher.update(&age_ciphertext);
            hasher.update(&encrypted_secret);
            let digest = hasher.finalize();

            let signature = pq::mldsa_sign(signing_key, &digest)?;

            // Recover signing public key from seed for embedding in envelope
            let vk = {
                use ml_dsa::SigningKey;
                let seed: &ml_dsa::Seed = signing_key
                    .as_bytes()
                    .try_into()
                    .map_err(|_| GenesisError::PqSignFailed("invalid seed".into()))?;
                let sk = SigningKey::<ml_dsa::MlDsa87>::from_seed(seed);
                sk.verifying_key().encode().to_vec()
            };

            Ok(HybridEnvelope {
                version: EnvelopeVersion::V2Hybrid,
                mlkem_ciphertext,
                age_ciphertext,
                encrypted_secret,
                signature,
                signing_public_key: vk,
            })
        }

        /// Open a hybrid envelope, recovering the plaintext.
        pub fn open(
            &self,
            age_identity: &KeyMaterial,
            mlkem_private_key: &KeyMaterial,
        ) -> Result<Vec<u8>, GenesisError> {
            use chacha20poly1305::aead::{Aead, KeyInit};
            use chacha20poly1305::{ChaCha20Poly1305, Nonce};
            use sha3::Digest;

            // 1. Verify signature
            let mut hasher = sha3::Sha3_256::new();
            hasher.update(&self.mlkem_ciphertext);
            hasher.update(&self.age_ciphertext);
            hasher.update(&self.encrypted_secret);
            let digest = hasher.finalize();

            let valid = pq::mldsa_verify(&self.signing_public_key, &digest, &self.signature)?;
            if !valid {
                return Err(GenesisError::EnvelopeSignatureInvalid);
            }

            // 2. Decrypt age_ciphertext → classical shared secret
            let ss_classical = Zeroizing::new(age::decrypt_with_private_key(
                age_identity.as_bytes(),
                &self.age_ciphertext,
            )?);

            // 3. ML-KEM decapsulate → PQ shared secret
            let ss_pq = Zeroizing::new(pq::mlkem_decapsulate(
                mlkem_private_key,
                &self.mlkem_ciphertext,
            )?);

            // 4. Derive combined DEK
            let combined_dek = hybrid_crypto::combine_shared_secrets(ss_classical, ss_pq, b"seal")?;

            // 5. ChaCha20-Poly1305 decrypt
            if self.encrypted_secret.len() < 12 {
                return Err(GenesisError::EnvelopeParseFailed(
                    "encrypted_secret too short for nonce".into(),
                ));
            }
            let nonce = Nonce::from_slice(&self.encrypted_secret[..12]);
            let cipher = ChaCha20Poly1305::new(combined_dek.as_bytes().into());

            let plaintext = cipher
                .decrypt(nonce, &self.encrypted_secret[12..])
                .map_err(|e| GenesisError::AgeDecryptFailed(format!("ChaCha20 decrypt: {e}")))?;

            Ok(plaintext)
        }

        /// Serialize this envelope to the binary wire format.
        pub fn to_bytes(&self) -> Vec<u8> {
            let mut buf = Vec::new();

            // Magic + total length placeholder
            buf.extend_from_slice(MAGIC_V2);
            buf.extend_from_slice(&[0u8; 4]); // total length, filled at end

            // ML-KEM ciphertext
            write_length_prefixed(&mut buf, &self.mlkem_ciphertext);
            // Age ciphertext
            write_length_prefixed(&mut buf, &self.age_ciphertext);
            // Encrypted secret
            write_length_prefixed(&mut buf, &self.encrypted_secret);
            // Signature
            write_length_prefixed(&mut buf, &self.signature);
            // Signing public key
            write_length_prefixed(&mut buf, &self.signing_public_key);

            // Fill total length (excludes magic + length field itself)
            let total_len = (buf.len() - 8) as u32;
            buf[4..8].copy_from_slice(&total_len.to_le_bytes());

            buf
        }

        /// Deserialize a V2 hybrid envelope from bytes.
        pub fn from_bytes(data: &[u8]) -> Result<Self, GenesisError> {
            if data.len() < 8 {
                return Err(GenesisError::EnvelopeParseFailed("too short".into()));
            }
            if &data[0..4] != MAGIC_V2 {
                return Err(GenesisError::EnvelopeVersionMismatch(
                    "expected GEN2 magic".into(),
                ));
            }

            let mut cursor = 8; // skip magic + total length

            let mlkem_ciphertext = read_length_prefixed(data, &mut cursor)?;
            let age_ciphertext = read_length_prefixed(data, &mut cursor)?;
            let encrypted_secret = read_length_prefixed(data, &mut cursor)?;
            let signature = read_length_prefixed(data, &mut cursor)?;
            let signing_public_key = read_length_prefixed(data, &mut cursor)?;

            Ok(HybridEnvelope {
                version: EnvelopeVersion::V2Hybrid,
                mlkem_ciphertext,
                age_ciphertext,
                encrypted_secret,
                signature,
                signing_public_key,
            })
        }
    }

    /// Detect the envelope version from raw bytes.
    pub fn detect_envelope_version(data: &[u8]) -> EnvelopeVersion {
        if data.len() >= 4 && &data[0..4] == MAGIC_V2 {
            EnvelopeVersion::V2Hybrid
        } else {
            EnvelopeVersion::V1Age
        }
    }

    /// Upgrade a V1 age envelope to V2 hybrid.
    ///
    /// Decrypts the V1 envelope, then re-seals as V2.
    pub fn upgrade_envelope(
        v1_data: &[u8],
        age_identity: &KeyMaterial,
        new_age_recipient: &str,
        new_mlkem_public: &[u8],
        new_signing_key: &KeyMaterial,
    ) -> Result<HybridEnvelope, GenesisError> {
        // Decrypt the V1 (age-only) envelope
        let plaintext = age::decrypt_with_private_key(age_identity.as_bytes(), v1_data)?;

        // Re-seal as V2 hybrid
        HybridEnvelope::seal(
            &plaintext,
            new_age_recipient,
            new_mlkem_public,
            new_signing_key,
        )
    }

    fn write_length_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buf.extend_from_slice(data);
    }

    fn read_length_prefixed(data: &[u8], cursor: &mut usize) -> Result<Vec<u8>, GenesisError> {
        if *cursor + 4 > data.len() {
            return Err(GenesisError::EnvelopeParseFailed(
                "unexpected end of envelope".into(),
            ));
        }
        let len = u32::from_le_bytes(data[*cursor..*cursor + 4].try_into().unwrap()) as usize;
        *cursor += 4;
        if *cursor + len > data.len() {
            return Err(GenesisError::EnvelopeParseFailed(format!(
                "field length {len} exceeds envelope bounds"
            )));
        }
        let field = data[*cursor..*cursor + len].to_vec();
        *cursor += len;
        Ok(field)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::crypto::{age, pq};

        fn generate_test_keys() -> (
            String,      // age_recipient
            KeyMaterial, // age_identity
            Vec<u8>,     // mlkem_public_key
            KeyMaterial, // mlkem_private_key
            Vec<u8>,     // signing_public_key
            KeyMaterial, // signing_key
        ) {
            let (age_recipient, age_identity) = age::generate_keypair().unwrap();
            let (mlkem_public, mlkem_private) = pq::mlkem_generate_keypair().unwrap();
            let (signing_public, signing_key) = pq::mldsa_generate_keypair().unwrap();
            (
                age_recipient,
                age_identity,
                mlkem_public,
                mlkem_private,
                signing_public,
                signing_key,
            )
        }

        #[test]
        fn hybrid_envelope_roundtrip() {
            let (age_rcpt, age_id, mlkem_pk, mlkem_sk, _spk, signing_key) = generate_test_keys();

            let plaintext = b"genesis-operator hybrid secret";
            let envelope =
                HybridEnvelope::seal(plaintext, &age_rcpt, &mlkem_pk, &signing_key).unwrap();

            assert_eq!(envelope.version, EnvelopeVersion::V2Hybrid);

            let recovered = envelope.open(&age_id, &mlkem_sk).unwrap();
            assert_eq!(recovered, plaintext);
        }

        #[test]
        fn hybrid_envelope_wrong_age_key() {
            let (age_rcpt, _age_id, mlkem_pk, mlkem_sk, _spk, signing_key) = generate_test_keys();
            let (_wrong_rcpt, wrong_age_id) = age::generate_keypair().unwrap();

            let envelope =
                HybridEnvelope::seal(b"secret", &age_rcpt, &mlkem_pk, &signing_key).unwrap();

            let result = envelope.open(&wrong_age_id, &mlkem_sk);
            assert!(result.is_err());
        }

        #[test]
        fn hybrid_envelope_wrong_mlkem_key() {
            let (age_rcpt, age_id, mlkem_pk, _mlkem_sk, _spk, signing_key) = generate_test_keys();
            let (_wrong_mlkem_pk, wrong_mlkem_sk) = pq::mlkem_generate_keypair().unwrap();

            let envelope =
                HybridEnvelope::seal(b"secret", &age_rcpt, &mlkem_pk, &signing_key).unwrap();

            // Wrong ML-KEM key produces wrong shared secret → wrong DEK → decryption fails
            let result = envelope.open(&age_id, &wrong_mlkem_sk);
            assert!(result.is_err());
        }

        #[test]
        fn hybrid_envelope_tampered_sig() {
            let (age_rcpt, age_id, mlkem_pk, mlkem_sk, _spk, signing_key) = generate_test_keys();

            let mut envelope =
                HybridEnvelope::seal(b"secret", &age_rcpt, &mlkem_pk, &signing_key).unwrap();

            // Tamper with the encrypted secret
            if let Some(byte) = envelope.encrypted_secret.last_mut() {
                *byte ^= 0xFF;
            }

            let result = envelope.open(&age_id, &mlkem_sk);
            assert!(result.is_err());
        }

        #[test]
        fn hybrid_envelope_serialization_roundtrip() {
            let (age_rcpt, age_id, mlkem_pk, mlkem_sk, _spk, signing_key) = generate_test_keys();

            let envelope =
                HybridEnvelope::seal(b"serialize me", &age_rcpt, &mlkem_pk, &signing_key).unwrap();

            let bytes = envelope.to_bytes();
            let recovered_envelope = HybridEnvelope::from_bytes(&bytes).unwrap();
            let plaintext = recovered_envelope.open(&age_id, &mlkem_sk).unwrap();
            assert_eq!(plaintext, b"serialize me");
        }

        #[test]
        fn hybrid_envelope_v1_detection() {
            // V1 age blobs start with "age-encryption.org" header, not "GEN2"
            let (age_rcpt, _age_id) = age::generate_keypair().unwrap();
            let v1_blob = age::encrypt_with_public_key(&age_rcpt, b"legacy").unwrap();

            assert_eq!(detect_envelope_version(&v1_blob), EnvelopeVersion::V1Age);
        }

        #[test]
        fn hybrid_envelope_v2_detection() {
            let (age_rcpt, _age_id, mlkem_pk, _mlkem_sk, _spk, signing_key) = generate_test_keys();

            let envelope =
                HybridEnvelope::seal(b"detect me", &age_rcpt, &mlkem_pk, &signing_key).unwrap();

            let bytes = envelope.to_bytes();
            assert_eq!(detect_envelope_version(&bytes), EnvelopeVersion::V2Hybrid);
        }

        #[test]
        fn upgrade_v1_to_v2() {
            let (age_rcpt, age_id, mlkem_pk, mlkem_sk, _spk, signing_key) = generate_test_keys();

            // Create V1 age envelope
            let v1_blob = age::encrypt_with_public_key(&age_rcpt, b"upgrade me").unwrap();
            assert_eq!(detect_envelope_version(&v1_blob), EnvelopeVersion::V1Age);

            // Upgrade to V2
            let v2_envelope =
                upgrade_envelope(&v1_blob, &age_id, &age_rcpt, &mlkem_pk, &signing_key).unwrap();

            assert_eq!(v2_envelope.version, EnvelopeVersion::V2Hybrid);

            // Open the V2 envelope
            let plaintext = v2_envelope.open(&age_id, &mlkem_sk).unwrap();
            assert_eq!(plaintext, b"upgrade me");
        }

        #[test]
        fn hybrid_both_needed() {
            // Verify that you need BOTH key types to open
            let (age_rcpt, age_id, mlkem_pk, _mlkem_sk, _spk, signing_key) = generate_test_keys();
            let (_wrong_mlkem_pk, wrong_mlkem_sk) = pq::mlkem_generate_keypair().unwrap();

            let envelope =
                HybridEnvelope::seal(b"both needed", &age_rcpt, &mlkem_pk, &signing_key).unwrap();

            // Correct age, wrong ML-KEM → fails
            assert!(envelope.open(&age_id, &wrong_mlkem_sk).is_err());

            // Wrong age, correct ML-KEM → fails
            let (_wrong_rcpt, wrong_age_id) = age::generate_keypair().unwrap();
            let (_, correct_mlkem_sk) = {
                // We need the actual matching key, but _mlkem_sk is moved
                // So test this with fresh keys
                let (rcpt2, _id2, pk2, sk2, _spk2, skey2) = generate_test_keys();
                let env2 = HybridEnvelope::seal(b"test", &rcpt2, &pk2, &skey2).unwrap();
                assert!(env2.open(&wrong_age_id, &sk2).is_err());
                (pk2, sk2)
            };
            // Confirm correct keys work
            let _ = correct_mlkem_sk; // just to use the binding
        }
    }
}

// ── Original KMS envelope tests ─────────────────────────────────────

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
