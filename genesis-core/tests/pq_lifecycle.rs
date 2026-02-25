//! PQ integration tests — full lifecycle and cloud KMS interop.
//!
//! These tests exercise the complete PQ workflow end-to-end:
//! key generation, hybrid envelope seal/open, key rotation, migration,
//! and interaction with mock cloud KMS providers.

#![cfg(feature = "pq")]

use genesis_core::crypto::{age, pq};
use genesis_core::envelope::hybrid::{
    detect_envelope_version, upgrade_envelope, EnvelopeVersion, HybridEnvelope,
};
use genesis_core::kms::local::LocalKmsProvider;
use genesis_core::kms::KmsProvider;
use genesis_core::GenesisKeySet;

// ── Helpers ─────────────────────────────────────────────────────────

fn generate_full_keyset() -> GenesisKeySet {
    GenesisKeySet::generate().expect("keyset generation should succeed")
}

// ── Full PQ lifecycle ───────────────────────────────────────────────

/// Spec 5.1: Init → seal → verify sig → open → rotate → seal new → verify new.
#[test]
fn full_pq_lifecycle() {
    // 1. Generate initial keyset (standalone mode)
    let keyset = generate_full_keyset();

    // Verify public keys are extractable as JSON
    let public_json = keyset.public_keys_json().expect("public keys JSON");
    let parsed: serde_json::Value = serde_json::from_str(&public_json).unwrap();
    assert!(parsed["age_recipient"].is_string());
    assert!(parsed["mlkem_public_key"].is_string());
    assert!(parsed["signing_public_key"].is_string());

    // 2. Seal a secret using hybrid envelope
    let plaintext = b"database-connection-string: postgres://user:pass@host:5432/db";
    let envelope = HybridEnvelope::seal(
        plaintext,
        &keyset.age_recipient,
        &keyset.mlkem_public_key,
        &keyset.signing_key,
    )
    .expect("seal should succeed");

    assert_eq!(envelope.version, EnvelopeVersion::V2Hybrid);

    // 3. Verify envelope serialization roundtrips
    let bytes = envelope.to_bytes();
    assert_eq!(detect_envelope_version(&bytes), EnvelopeVersion::V2Hybrid);
    let deserialized = HybridEnvelope::from_bytes(&bytes).expect("deserialize");

    // 4. Open envelope, recover plaintext
    let recovered = deserialized
        .open(&keyset.age_identity, &keyset.mlkem_private_key)
        .expect("open should succeed");
    assert_eq!(recovered, plaintext);

    // 5. Rotate keys — generate a new keyset
    let keyset2 = generate_full_keyset();

    // Old envelope still opens with OLD keys (it was sealed to them)
    let recovered_again = envelope
        .open(&keyset.age_identity, &keyset.mlkem_private_key)
        .expect("old envelope still opens with old keys");
    assert_eq!(recovered_again, plaintext);

    // Old envelope does NOT open with NEW keys
    assert!(envelope
        .open(&keyset2.age_identity, &keyset2.mlkem_private_key)
        .is_err());

    // 6. Seal new secret with rotated keys
    let new_plaintext = b"rotated secret value";
    let new_envelope = HybridEnvelope::seal(
        new_plaintext,
        &keyset2.age_recipient,
        &keyset2.mlkem_public_key,
        &keyset2.signing_key,
    )
    .expect("seal with rotated keys");

    let new_recovered = new_envelope
        .open(&keyset2.age_identity, &keyset2.mlkem_private_key)
        .expect("open with rotated keys");
    assert_eq!(new_recovered, new_plaintext);
}

/// Spec 5.1: PQ lifecycle with local KMS for standalone mode.
#[test]
fn full_pq_lifecycle_with_local_kms() {
    let dir = tempfile::tempdir().unwrap();
    let envelope_path = dir.path().join("master-key.enc");

    let keyset = generate_full_keyset();

    // 1. Generate local KMS provider (creates master key envelope on disk)
    let kms = LocalKmsProvider::generate(
        &envelope_path,
        &keyset.age_recipient,
        &keyset.mlkem_public_key,
        &keyset.signing_key,
    )
    .expect("local KMS generate");

    assert_eq!(kms.provider_name(), "local");

    // 2. Use local KMS to wrap a DEK
    let dek = b"data-encryption-key-32-bytes!!!!"; // 32 bytes
    let wrapped = kms.encrypt(dek).expect("encrypt DEK");
    assert_ne!(&wrapped[..], &dek[..]);

    // 3. Unwrap the DEK
    let unwrapped = kms.decrypt(&wrapped).expect("decrypt DEK");
    assert_eq!(unwrapped, dek);

    // 4. Drop and reload from disk
    drop(kms);
    let kms2 = LocalKmsProvider::from_envelope(
        &envelope_path,
        &keyset.age_identity,
        &keyset.mlkem_private_key,
    )
    .expect("reload local KMS");

    // 5. Unwrap the same DEK with reloaded provider
    let unwrapped2 = kms2.decrypt(&wrapped).expect("decrypt after reload");
    assert_eq!(unwrapped2, dek);
}

// ── PQ with mock cloud KMS ──────────────────────────────────────────

/// Spec 5.1: Cloud KMS wraps DEK, PQ hybrid wraps the secret.
/// Verifies that cloud KMS and PQ hybrid work together.
#[cfg(feature = "mock")]
#[test]
fn pq_with_mock_cloud_kms() {
    use genesis_core::kms::mock::MockKmsProvider;

    let keyset = generate_full_keyset();
    let mock_kms = MockKmsProvider::new();

    // 1. Seal a secret in a hybrid envelope
    let plaintext = b"secret-for-cloud-kms-wrapped-dek";
    let envelope = HybridEnvelope::seal(
        plaintext,
        &keyset.age_recipient,
        &keyset.mlkem_public_key,
        &keyset.signing_key,
    )
    .expect("seal");

    // 2. The envelope bytes can be wrapped by cloud KMS for storage
    let envelope_bytes = envelope.to_bytes();
    let kms_wrapped = mock_kms
        .encrypt(&envelope_bytes)
        .expect("KMS wrap envelope");

    // 3. Unwrap with KMS, then open hybrid envelope
    let kms_unwrapped = mock_kms.decrypt(&kms_wrapped).expect("KMS unwrap envelope");
    let recovered_envelope =
        HybridEnvelope::from_bytes(&kms_unwrapped).expect("deserialize envelope");
    let recovered = recovered_envelope
        .open(&keyset.age_identity, &keyset.mlkem_private_key)
        .expect("open hybrid envelope");

    assert_eq!(recovered, plaintext);
}

// ── V1 to V2 migration with mock KMS ───────────────────────────────

/// Verify that V1 age-only envelopes can be migrated to V2 hybrid.
#[test]
fn migration_v1_to_v2_lifecycle() {
    // Create a V1 (age-only) envelope
    let (age_rcpt, age_id) = age::generate_keypair().unwrap();
    let v1_blob = age::encrypt_with_public_key(&age_rcpt, b"legacy secret").unwrap();
    assert_eq!(detect_envelope_version(&v1_blob), EnvelopeVersion::V1Age);

    // Generate PQ keys for V2
    let (mlkem_pk, mlkem_sk) = pq::mlkem_generate_keypair().unwrap();
    let (_signing_pk, signing_key) = pq::mldsa_generate_keypair().unwrap();

    // Upgrade V1 → V2
    let v2 = upgrade_envelope(&v1_blob, &age_id, &age_rcpt, &mlkem_pk, &signing_key)
        .expect("upgrade should succeed");

    assert_eq!(v2.version, EnvelopeVersion::V2Hybrid);

    // Verify the V2 envelope contains the original plaintext
    let recovered = v2.open(&age_id, &mlkem_sk).expect("open V2");
    assert_eq!(recovered, b"legacy secret");

    // Verify V2 serialization
    let v2_bytes = v2.to_bytes();
    assert_eq!(
        detect_envelope_version(&v2_bytes),
        EnvelopeVersion::V2Hybrid
    );
}

// ── Keyset invariants ───────────────────────────────────────────────

/// All private keys in the keyset are KeyMaterial (compile-time enforcement).
/// Since as_bytes() is pub(crate), we verify indirectly by checking that
/// the keyset can seal and open an envelope (proving keys are functional).
#[test]
fn keyset_private_keys_are_functional() {
    let keyset = generate_full_keyset();

    // Private keys work: seal and open a hybrid envelope
    let plaintext = b"functional key test";
    let envelope = HybridEnvelope::seal(
        plaintext,
        &keyset.age_recipient,
        &keyset.mlkem_public_key,
        &keyset.signing_key,
    )
    .expect("private signing key works");

    let recovered = envelope
        .open(&keyset.age_identity, &keyset.mlkem_private_key)
        .expect("private age + mlkem keys work");

    assert_eq!(recovered, plaintext);
}

/// Public keys in the keyset have expected sizes.
#[test]
fn keyset_public_key_sizes() {
    let keyset = generate_full_keyset();

    // Age recipient is "age1..." string
    assert!(keyset.age_recipient.starts_with("age1"));

    // ML-KEM-1024 encapsulation key: 1568 bytes
    assert_eq!(
        keyset.mlkem_public_key.len(),
        1568,
        "ML-KEM-1024 public key should be 1568 bytes"
    );

    // ML-DSA-87 verifying key: 2592 bytes
    assert_eq!(
        keyset.signing_public_key.len(),
        2592,
        "ML-DSA-87 public key should be 2592 bytes"
    );
}

/// Multiple keyset generations produce distinct keys.
#[test]
fn keyset_uniqueness() {
    let ks1 = generate_full_keyset();
    let ks2 = generate_full_keyset();

    assert_ne!(ks1.age_recipient, ks2.age_recipient);
    assert_ne!(ks1.mlkem_public_key, ks2.mlkem_public_key);
    assert_ne!(ks1.signing_public_key, ks2.signing_public_key);
}

/// Hybrid envelope with empty plaintext roundtrips correctly.
#[test]
fn hybrid_envelope_empty_plaintext() {
    let keyset = generate_full_keyset();

    let envelope = HybridEnvelope::seal(
        b"",
        &keyset.age_recipient,
        &keyset.mlkem_public_key,
        &keyset.signing_key,
    )
    .expect("seal empty");

    let recovered = envelope
        .open(&keyset.age_identity, &keyset.mlkem_private_key)
        .expect("open empty");

    assert_eq!(recovered, b"");
}

/// Hybrid envelope with large payload roundtrips correctly.
#[test]
fn hybrid_envelope_large_payload() {
    let keyset = generate_full_keyset();
    let large = vec![0xABu8; 65_536]; // 64 KB

    let envelope = HybridEnvelope::seal(
        &large,
        &keyset.age_recipient,
        &keyset.mlkem_public_key,
        &keyset.signing_key,
    )
    .expect("seal large");

    let recovered = envelope
        .open(&keyset.age_identity, &keyset.mlkem_private_key)
        .expect("open large");

    assert_eq!(recovered, large);
}

// ── State machine integration tests ─────────────────────────────────

/// Full standalone lifecycle: Genesis state machine driven by a PQ-backed
/// LocalKmsProvider. Exercises every state transition through rotation.
///
/// Flow: Uninitialized -> init() -> Initialized -> seal/unseal/verify ->
///       begin_bootstrap -> inject_secret -> Active ->
///       begin_rotation -> complete_rotation -> Active (new key).
#[test]
fn init_standalone_full_lifecycle() {
    use genesis_core::audit::NullAuditSink;
    use genesis_core::k8s::MockSecretInjector;
    use genesis_core::state::{Genesis, GenesisConfig};

    // 1. Generate a full PQ keyset for the LocalKmsProvider's envelope.
    let keyset = generate_full_keyset();

    // 2. Create a LocalKmsProvider backed by a PQ hybrid envelope on disk.
    let dir = tempfile::tempdir().unwrap();
    let envelope_path = dir.path().join("master-key.enc");
    let kms = LocalKmsProvider::generate(
        &envelope_path,
        &keyset.age_recipient,
        &keyset.mlkem_public_key,
        &keyset.signing_key,
    )
    .expect("LocalKmsProvider::generate");

    // 3. Create Genesis in Uninitialized state.
    let config = GenesisConfig {
        provider_type: "local".to_string(),
        provider_config: serde_json::json!({"envelope_path": envelope_path.display().to_string()}),
        public_key: None,
        envelope_ciphertext: None,
    };
    let genesis = Genesis::new(config, Box::new(NullAuditSink));

    // 4. init() -> Initialized: generates age keypair, wraps private key via LocalKms.
    let (initialized, artifacts) = genesis.init(&kms).expect("init should succeed");
    assert!(artifacts.public_key.starts_with("age1"));
    assert!(!artifacts.envelope_ciphertext.is_empty());
    assert!(artifacts.sops_config.contains(&artifacts.public_key));

    // 5. seal() -> encrypt data with the age public key.
    let plaintext = b"database-password: hunter2";
    let ciphertext = initialized.seal(plaintext).expect("seal should succeed");
    assert_ne!(&ciphertext[..], &plaintext[..]);

    // 6. unseal() -> decrypt via LocalKms (unwraps age private key from envelope).
    let recovered = initialized
        .unseal(&kms, &ciphertext)
        .expect("unseal should succeed");
    assert_eq!(recovered, plaintext);

    // 7. verify() -> confirm the public key matches the KMS-wrapped private key.
    let verify_result = initialized.verify(&kms).expect("verify should succeed");
    assert!(verify_result.public_key_matches);
    assert_eq!(verify_result.public_key, artifacts.public_key);

    // 8. begin_bootstrap() -> Bootstrapping: decrypts envelope, holds key in memory.
    let bootstrapping = initialized
        .begin_bootstrap(&kms)
        .expect("begin_bootstrap should succeed");

    // 9. inject_secret() -> Active: pushes key material into mock K8s secret.
    let injector = MockSecretInjector::new();
    let active = bootstrapping
        .inject_secret(&injector, "genesis-key", "genesis-system", "age.key")
        .expect("inject_secret should succeed");
    assert!(injector.was_injected("genesis-key"));

    let status = active.status();
    assert_eq!(status.state, genesis_core::state::StateTag::Active,);
    assert!(status.has_envelope);

    // 10. begin_rotation() -> Rotating.
    let old_public_key = artifacts.public_key.clone();
    let rotating = active.begin_rotation();

    // 11. complete_rotation() -> Active with a new keypair.
    let (new_active, new_artifacts) = rotating
        .complete_rotation(&kms, &injector, "genesis-key", "genesis-system", "age.key")
        .expect("complete_rotation should succeed");

    // 12. Verify the rotated key differs from the original.
    assert_ne!(old_public_key, new_artifacts.public_key);
    assert!(new_artifacts.public_key.starts_with("age1"));

    let new_status = new_active.status();
    assert_eq!(new_status.state, genesis_core::state::StateTag::Active,);
    assert_eq!(
        new_status.public_key.as_deref(),
        Some(new_artifacts.public_key.as_str()),
    );
}

/// Cloud KMS simulation: MockKmsProvider wraps the age private key (DEK)
/// during state machine init, then seal/unseal roundtrips through the
/// mock. A separate HybridEnvelope seal demonstrates PQ crypto working
/// alongside the state machine's age-based envelope encryption.
#[cfg(feature = "mock")]
#[test]
fn init_cloud_kms_with_pq() {
    use genesis_core::audit::NullAuditSink;
    use genesis_core::kms::mock::MockKmsProvider;
    use genesis_core::state::{Genesis, GenesisConfig};

    // 1. Create Genesis in Uninitialized state with MockKmsProvider config.
    let config = GenesisConfig {
        provider_type: "mock".to_string(),
        provider_config: serde_json::json!({"region": "test-region-1"}),
        public_key: None,
        envelope_ciphertext: None,
    };
    let genesis = Genesis::new(config, Box::new(NullAuditSink));

    // 2. init() with MockKmsProvider: generates age keypair, XOR-wraps private key.
    let mock_kms = MockKmsProvider::new();
    let (initialized, artifacts) = genesis.init(&mock_kms).expect("init should succeed");

    assert!(artifacts.public_key.starts_with("age1"));
    // MockKms uses XOR, so the envelope is non-empty and differs from any plaintext.
    assert!(!artifacts.envelope_ciphertext.is_empty());

    // 3. seal() data with the age public key.
    let plaintext = b"cloud-kms-wrapped secret: api-key-12345";
    let ciphertext = initialized.seal(plaintext).expect("seal should succeed");
    assert_ne!(&ciphertext[..], &plaintext[..]);

    // 4. unseal() with MockKmsProvider: XOR-unwraps the envelope to get the age
    //    private key, then decrypts the ciphertext.
    let recovered = initialized
        .unseal(&mock_kms, &ciphertext)
        .expect("unseal should succeed");
    assert_eq!(recovered, plaintext);

    // 5. verify() confirms the roundtrip is consistent.
    let verify_result = initialized
        .verify(&mock_kms)
        .expect("verify should succeed");
    assert!(verify_result.public_key_matches);

    // 6. Separately demonstrate PQ hybrid envelope sealing with a GenesisKeySet.
    //    This proves both layers (state machine age + PQ hybrid) can coexist.
    let keyset = generate_full_keyset();
    let pq_plaintext = b"pq-hybrid-secret: quantum-safe-value";

    let hybrid_envelope = HybridEnvelope::seal(
        pq_plaintext,
        &keyset.age_recipient,
        &keyset.mlkem_public_key,
        &keyset.signing_key,
    )
    .expect("hybrid seal should succeed");

    // The hybrid envelope bytes can be further wrapped by the "cloud KMS".
    let envelope_bytes = hybrid_envelope.to_bytes();
    let kms_wrapped = mock_kms
        .encrypt(&envelope_bytes)
        .expect("KMS wrap hybrid envelope");

    // Unwrap via KMS, then open the PQ hybrid envelope.
    let kms_unwrapped = mock_kms
        .decrypt(&kms_wrapped)
        .expect("KMS unwrap hybrid envelope");
    let recovered_envelope =
        HybridEnvelope::from_bytes(&kms_unwrapped).expect("deserialize hybrid envelope");
    let pq_recovered = recovered_envelope
        .open(&keyset.age_identity, &keyset.mlkem_private_key)
        .expect("open hybrid envelope");

    assert_eq!(pq_recovered, pq_plaintext);
}
