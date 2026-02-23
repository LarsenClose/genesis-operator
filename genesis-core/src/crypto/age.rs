//! Age X25519 key generation, encryption, and decryption.
//!
//! Wraps the `age` crate (v0.11) to provide a simple interface for
//! genesis-operator's key material lifecycle.

use std::io::{Read, Write};

use ::age::secrecy::ExposeSecret;

use crate::zeroize_mem::KeyMaterial;
use crate::GenesisError;

/// Generate a fresh X25519 keypair.
///
/// Returns `(public_key_string, KeyMaterial)` where the public key is the
/// `age1...` bech32 string and `KeyMaterial` wraps the private key bytes
/// (the `AGE-SECRET-KEY-1...` string encoded as UTF-8).
pub fn generate_keypair() -> Result<(String, KeyMaterial), GenesisError> {
    let identity = ::age::x25519::Identity::generate();
    let public_key = identity.to_public().to_string();
    let secret_string = identity.to_string();
    let private_key_str: &str = secret_string.expose_secret();
    let key_material = KeyMaterial::new(private_key_str.as_bytes().to_vec());
    Ok((public_key, key_material))
}

/// Derive the public key string (`age1...`) from private key bytes.
///
/// `private_bytes` must be the UTF-8 encoding of an `AGE-SECRET-KEY-1...`
/// bech32 string.
pub fn public_key_from_private(private_bytes: &[u8]) -> Result<String, GenesisError> {
    let private_str = std::str::from_utf8(private_bytes)
        .map_err(|e| GenesisError::AgeKeyGenFailed(format!("invalid UTF-8 in private key: {e}")))?;

    let identity: ::age::x25519::Identity = private_str
        .parse()
        .map_err(|e| GenesisError::AgeKeyGenFailed(format!("failed to parse identity: {e}")))?;

    Ok(identity.to_public().to_string())
}

/// Encrypt `plaintext` to the given `age1...` public key.
///
/// Returns the ciphertext as a byte vector (binary age format, not armored).
pub fn encrypt_with_public_key(
    public_key: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, GenesisError> {
    let recipient: ::age::x25519::Recipient = public_key
        .parse()
        .map_err(|e| GenesisError::AgeEncryptFailed(format!("invalid recipient: {e}")))?;

    let recipients: Vec<Box<dyn ::age::Recipient + Send>> = vec![Box::new(recipient)];
    let encryptor = ::age::Encryptor::with_recipients(
        recipients
            .iter()
            .map(|r| r.as_ref() as &dyn ::age::Recipient),
    )
    .map_err(|e| GenesisError::AgeEncryptFailed(format!("encryptor creation failed: {e}")))?;

    let mut ciphertext = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|e| GenesisError::AgeEncryptFailed(format!("wrap_output failed: {e}")))?;

    writer
        .write_all(plaintext)
        .map_err(|e| GenesisError::AgeEncryptFailed(format!("write failed: {e}")))?;

    writer
        .finish()
        .map_err(|e| GenesisError::AgeEncryptFailed(format!("finish failed: {e}")))?;

    Ok(ciphertext)
}

/// Decrypt `ciphertext` using the private key bytes.
///
/// `private_bytes` must be the UTF-8 encoding of an `AGE-SECRET-KEY-1...`
/// bech32 string.
pub fn decrypt_with_private_key(
    private_bytes: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, GenesisError> {
    let private_str = std::str::from_utf8(private_bytes).map_err(|e| {
        GenesisError::AgeDecryptFailed(format!("invalid UTF-8 in private key: {e}"))
    })?;

    let identity: ::age::x25519::Identity = private_str
        .parse()
        .map_err(|e| GenesisError::AgeDecryptFailed(format!("failed to parse identity: {e}")))?;

    let decryptor = ::age::Decryptor::new(ciphertext)
        .map_err(|e| GenesisError::AgeDecryptFailed(format!("decryptor creation failed: {e}")))?;

    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn ::age::Identity))
        .map_err(|e| GenesisError::AgeDecryptFailed(format!("decrypt failed: {e}")))?;

    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|e| GenesisError::AgeDecryptFailed(format!("read failed: {e}")))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_keygen_encrypt_decrypt() {
        let (pub_key, key_material) = generate_keypair().expect("keygen should succeed");
        assert!(pub_key.starts_with("age1"));

        let plaintext = b"genesis-operator secret material";
        let ciphertext =
            encrypt_with_public_key(&pub_key, plaintext).expect("encrypt should succeed");

        assert_ne!(&ciphertext[..], plaintext);

        let decrypted = decrypt_with_private_key(key_material.as_bytes(), &ciphertext)
            .expect("decrypt should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn public_key_from_private_roundtrip() {
        let (expected_pub, key_material) = generate_keypair().expect("keygen should succeed");
        let derived_pub =
            public_key_from_private(key_material.as_bytes()).expect("derivation should succeed");
        assert_eq!(expected_pub, derived_pub);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let (pub_key, _key1) = generate_keypair().expect("keygen should succeed");
        let (_pub2, key2) = generate_keypair().expect("keygen should succeed");

        let ciphertext =
            encrypt_with_public_key(&pub_key, b"secret").expect("encrypt should succeed");

        let result = decrypt_with_private_key(key2.as_bytes(), &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_public_key_encrypt_fails() {
        let result = encrypt_with_public_key("not-a-valid-key", b"data");
        assert!(result.is_err());
    }

    #[test]
    fn invalid_private_key_decrypt_fails() {
        let result = decrypt_with_private_key(b"not-a-valid-key", b"data");
        assert!(result.is_err());
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let (pub_key, key_material) = generate_keypair().expect("keygen should succeed");
        let ciphertext =
            encrypt_with_public_key(&pub_key, b"").expect("encrypt empty should succeed");
        let decrypted = decrypt_with_private_key(key_material.as_bytes(), &ciphertext)
            .expect("decrypt empty should succeed");
        assert_eq!(decrypted, b"");
    }
}
