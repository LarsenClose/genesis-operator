//! Envelope encryption integration tests.
//!
//! These tests exercise the `genesis_core::envelope` module in combination
//! with `MockKmsProvider` and the age crypto layer, verifying that the
//! envelope-encrypt/decrypt roundtrip preserves key material integrity.

use genesis_core::envelope::{envelope_decrypt, envelope_encrypt};
use genesis_core::kms::mock::MockKmsProvider;

// ── Basic roundtrip ──────────────────────────────────────────────────

/// Encrypt then decrypt via MockKmsProvider -- output matches input.
#[test]
fn test_envelope_roundtrip_mock_kms() {
    let kms = MockKmsProvider::new();

    let secret = b"AGE-SECRET-KEY-1QTDQ5HG3GR7ZFJQP3W5XQKV4N5GASED5SE8GS";
    let envelope = envelope_encrypt(&kms, secret).expect("encrypt should succeed");

    // XOR transform means envelope differs from plaintext.
    assert_ne!(
        &envelope[..],
        &secret[..],
        "envelope ciphertext must differ from plaintext"
    );

    let recovered = envelope_decrypt(&kms, &envelope).expect("decrypt should succeed");
    assert_eq!(
        recovered, secret,
        "decrypted envelope must match original secret"
    );
}

/// Empty key material roundtrips correctly.
#[test]
fn test_envelope_empty_key_roundtrip() {
    let kms = MockKmsProvider::new();
    let envelope = envelope_encrypt(&kms, b"").expect("encrypt empty");
    let recovered = envelope_decrypt(&kms, &envelope).expect("decrypt empty");
    assert_eq!(recovered, b"");
}

/// Large key material roundtrips correctly.
#[test]
fn test_envelope_large_key_roundtrip() {
    let kms = MockKmsProvider::new();
    let large = vec![0x55u8; 4096];
    let envelope = envelope_encrypt(&kms, &large).expect("encrypt large");
    let recovered = envelope_decrypt(&kms, &envelope).expect("decrypt large");
    assert_eq!(recovered, large);
}

// ── Failing KMS ──────────────────────────────────────────────────────

/// MockKmsProvider::new_failing returns error on encrypt.
#[test]
fn test_envelope_failing_kms_encrypt() {
    let kms = MockKmsProvider::new_failing("HSM unavailable".to_string());

    let result = envelope_encrypt(&kms, b"secret-key-material");
    assert!(result.is_err(), "failing KMS must return error on encrypt");

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("HSM unavailable"),
        "error message must propagate: {}",
        err_msg
    );
}

/// MockKmsProvider::new_failing returns error on decrypt.
#[test]
fn test_envelope_failing_kms_decrypt() {
    let kms = MockKmsProvider::new_failing("vault sealed".to_string());

    let result = envelope_decrypt(&kms, b"some-ciphertext");
    assert!(result.is_err(), "failing KMS must return error on decrypt");

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("vault sealed"),
        "error message must propagate: {}",
        err_msg
    );
}

/// Different error messages are preserved in the KMS error.
#[test]
fn test_envelope_failing_kms_error_message_fidelity() {
    let msg = "connection timeout after 30s to kms.us-east-1.amazonaws.com";
    let kms = MockKmsProvider::new_failing(msg.to_string());

    let result = envelope_encrypt(&kms, b"data");
    let err = result.unwrap_err();

    assert_eq!(err.error_code(), 300, "KMS errors have code 300");
    assert!(
        err.to_string().contains(msg),
        "full error message must be preserved"
    );
}

// ── Full age + envelope roundtrip ────────────────────────────────────

/// End-to-end: generate an age keypair, envelope-encrypt the private key,
/// envelope-decrypt it, and use the recovered private key to decrypt data
/// that was encrypted with the public key.
#[test]
fn test_full_envelope_age_roundtrip() {
    use genesis_core::audit::NullAuditSink;
    use genesis_core::kms::NullKmsProvider;
    use genesis_core::state::{Genesis, GenesisConfig};

    let kms = NullKmsProvider;

    // 1. Generate keypair via the state machine (which envelope-encrypts
    //    the private key with the KMS).
    let g = Genesis::new(
        GenesisConfig {
            provider_type: "null-dev".to_string(),
            provider_config: serde_json::json!({}),
            public_key: None,
            envelope_ciphertext: None,
        },
        Box::new(NullAuditSink),
    );

    let (initialized, artifacts) = g.init(&kms).expect("init should succeed");

    // 2. Seal some data with the public key.
    let plaintext = b"database-connection-string: postgres://user:pass@host:5432/db";
    let sealed_data = initialized.seal(plaintext).expect("seal should succeed");

    // 3. The envelope_ciphertext in artifacts is the KMS-encrypted private key.
    //    With NullKms, this is the raw private key bytes.
    //    Verify we can envelope-decrypt it.
    let recovered_private = envelope_decrypt(&kms, &artifacts.envelope_ciphertext)
        .expect("envelope decrypt should succeed");

    // 4. Use the recovered private key to decrypt the sealed data.
    let decrypted =
        genesis_core::crypto::age::decrypt_with_private_key(&recovered_private, &sealed_data)
            .expect("age decrypt should succeed");

    assert_eq!(
        decrypted, plaintext,
        "full envelope+age roundtrip must recover original plaintext"
    );
}

/// Envelope encrypt with MockKmsProvider, then decrypt and use for age operations.
#[test]
fn test_full_envelope_mock_kms_age_roundtrip() {
    use genesis_core::crypto::age;

    let mock_kms = MockKmsProvider::new();

    // 1. Generate a raw age keypair via the crypto module.
    //    We cannot access KeyMaterial::as_bytes() from an integration test,
    //    so we generate via the state machine with MockKmsProvider.
    use genesis_core::audit::NullAuditSink;
    use genesis_core::state::{Genesis, GenesisConfig};

    let g = Genesis::new(
        GenesisConfig {
            provider_type: "mock".to_string(),
            provider_config: serde_json::json!({}),
            public_key: None,
            envelope_ciphertext: None,
        },
        Box::new(NullAuditSink),
    );

    let (initialized, artifacts) = g.init(&mock_kms).expect("init with mock KMS");

    // 2. The envelope_ciphertext was encrypted by MockKmsProvider (XOR).
    //    Envelope-decrypt it to get the raw private key bytes.
    let recovered_private = envelope_decrypt(&mock_kms, &artifacts.envelope_ciphertext)
        .expect("envelope decrypt should succeed");

    // 3. Verify the recovered private key derives the same public key.
    let derived_pub =
        age::public_key_from_private(&recovered_private).expect("derivation should succeed");
    assert_eq!(
        derived_pub, artifacts.public_key,
        "derived public key must match the original"
    );

    // 4. Seal data via the state machine, then decrypt with the recovered key.
    let plaintext = b"helm-values-secret: true";
    let sealed = initialized.seal(plaintext).expect("seal");
    let decrypted = age::decrypt_with_private_key(&recovered_private, &sealed).expect("decrypt");
    assert_eq!(decrypted, plaintext);
}

/// Verify that envelope_encrypt and envelope_decrypt are deterministic
/// for a given KMS provider (MockKmsProvider uses XOR, which is deterministic).
#[test]
fn test_envelope_deterministic_with_mock() {
    let kms = MockKmsProvider::new();
    let secret = b"deterministic-test-data";

    let envelope1 = envelope_encrypt(&kms, secret).expect("encrypt 1");
    let envelope2 = envelope_encrypt(&kms, secret).expect("encrypt 2");

    // MockKmsProvider uses XOR which is deterministic.
    assert_eq!(
        envelope1, envelope2,
        "MockKmsProvider (XOR) is deterministic"
    );
}
