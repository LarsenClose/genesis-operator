//! Integration tests for the full state machine lifecycle.
//!
//! These tests exercise the public API of `genesis_core::state` through
//! realistic multi-step sequences, verifying that the typestate transitions
//! produce the correct observable side effects.

use genesis_core::audit::NullAuditSink;
use genesis_core::k8s::MockSecretInjector;
use genesis_core::kms::NullKmsProvider;
use genesis_core::state::{Genesis, GenesisConfig, StateTag, Uninitialized};

// ── Helpers ──────────────────────────────────────────────────────────

fn test_config() -> GenesisConfig {
    GenesisConfig {
        provider_type: "null-dev".to_string(),
        provider_config: serde_json::json!({}),
        public_key: None,
        envelope_ciphertext: None,
    }
}

fn null_audit() -> Box<dyn genesis_core::AuditSink> {
    Box::new(NullAuditSink)
}

fn new_genesis() -> Genesis<Uninitialized> {
    Genesis::new(test_config(), null_audit())
}

// ── Tests ────────────────────────────────────────────────────────────

/// Full happy-path lifecycle:
/// Uninitialized -> init -> Initialized -> begin_bootstrap -> inject_secret -> Active
#[test]
fn test_full_lifecycle() {
    let g = new_genesis();
    let kms = NullKmsProvider;

    // Uninitialized -> Initialized
    let (initialized, artifacts) = g.init(&kms).expect("init should succeed");
    assert!(
        artifacts.public_key.starts_with("age1"),
        "public key must be an age1... bech32 string"
    );
    assert!(
        !artifacts.envelope_ciphertext.is_empty(),
        "envelope ciphertext must not be empty"
    );
    assert!(
        artifacts.sops_config.contains(&artifacts.public_key),
        "SOPS config must embed the public key"
    );
    assert_eq!(
        initialized.public_key(),
        Some(artifacts.public_key.as_str()),
        "config must store the public key"
    );

    // Initialized -> Bootstrapping
    let bootstrapping = initialized
        .begin_bootstrap(&kms)
        .expect("begin_bootstrap should succeed");

    // Bootstrapping -> Active (via inject_secret)
    let injector = MockSecretInjector::new();
    let active = bootstrapping
        .inject_secret(&injector, "genesis-key", "genesis-system", "age.key")
        .expect("inject_secret should succeed");

    assert!(
        injector.was_injected("genesis-key"),
        "secret must appear in mock injector"
    );

    let status = active.status();
    assert_eq!(status.state, StateTag::Active);
    assert!(status.has_envelope);
    assert!(status.public_key.is_some());
}

/// Rotation lifecycle:
/// Active -> begin_rotation -> complete_rotation -> Active (with new key)
#[test]
fn test_rotation_lifecycle() {
    let g = new_genesis();
    let kms = NullKmsProvider;
    let injector = MockSecretInjector::new();

    // Fast-forward to Active.
    let (initialized, old_artifacts) = g.init(&kms).expect("init");
    let bootstrapping = initialized.begin_bootstrap(&kms).expect("bootstrap");
    let active = bootstrapping
        .inject_secret(&injector, "genesis-key", "genesis-system", "age.key")
        .expect("inject");

    let old_pub = old_artifacts.public_key.clone();

    // Active -> Rotating
    let rotating = active.begin_rotation();

    // Rotating -> Active (with new key)
    let (new_active, new_artifacts) = rotating
        .complete_rotation(&kms, &injector, "genesis-key", "genesis-system", "age.key")
        .expect("rotation should succeed");

    assert_ne!(
        old_pub, new_artifacts.public_key,
        "rotation must produce a different key"
    );
    assert!(new_artifacts.public_key.starts_with("age1"));

    let status = new_active.status();
    assert_eq!(status.state, StateTag::Active);
    assert_eq!(
        status.public_key.as_deref(),
        Some(new_artifacts.public_key.as_str()),
        "status must reflect the rotated key"
    );
}

/// Bootstrap abort: begin_bootstrap -> abort -> back to Initialized
#[test]
fn test_bootstrap_abort() {
    let g = new_genesis();
    let kms = NullKmsProvider;

    let (initialized, _) = g.init(&kms).expect("init");
    let bootstrapping = initialized.begin_bootstrap(&kms).expect("bootstrap");

    // Abort returns to Initialized.
    let re_initialized = bootstrapping.abort();

    // Verify the key material is still valid after abort.
    let result = re_initialized
        .verify(&kms)
        .expect("verify should succeed after abort");
    assert!(
        result.public_key_matches,
        "public key must still match after abort"
    );
}

/// Rotation abort: begin_rotation -> abort_rotation -> back to Active
#[test]
fn test_rotation_abort() {
    let g = new_genesis();
    let kms = NullKmsProvider;
    let injector = MockSecretInjector::new();

    // Fast-forward to Active.
    let (initialized, artifacts) = g.init(&kms).expect("init");
    let bootstrapping = initialized.begin_bootstrap(&kms).expect("bootstrap");
    let active = bootstrapping
        .inject_secret(&injector, "genesis-key", "genesis-system", "age.key")
        .expect("inject");

    let original_pub = artifacts.public_key.clone();

    // Active -> Rotating -> abort -> Active
    let rotating = active.begin_rotation();
    let active_again = rotating.abort_rotation();

    let status = active_again.status();
    assert_eq!(status.state, StateTag::Active);
    assert_eq!(
        status.public_key.as_deref(),
        Some(original_pub.as_str()),
        "abort must preserve the original key"
    );
}

/// Verify succeeds immediately after init.
#[test]
fn test_verify_after_init() {
    let g = new_genesis();
    let kms = NullKmsProvider;

    let (initialized, artifacts) = g.init(&kms).expect("init");

    let result = initialized.verify(&kms).expect("verify should succeed");
    assert!(result.public_key_matches);
    assert_eq!(result.public_key, artifacts.public_key);
}

/// Seal then unseal roundtrip: the decrypted output matches the original input.
#[test]
fn test_seal_unseal_roundtrip() {
    let g = new_genesis();
    let kms = NullKmsProvider;

    let (initialized, _) = g.init(&kms).expect("init");

    let plaintext = b"top-secret-database-password-42";
    let ciphertext = initialized.seal(plaintext).expect("seal should succeed");

    // Ciphertext must differ from plaintext (age encryption is randomized).
    assert_ne!(
        &ciphertext[..],
        &plaintext[..],
        "ciphertext must not equal plaintext"
    );

    let decrypted = initialized
        .unseal(&kms, &ciphertext)
        .expect("unseal should succeed");
    assert_eq!(
        decrypted, plaintext,
        "decrypted data must match original plaintext"
    );
}

/// Seal with various data sizes.
#[test]
fn test_seal_unseal_various_sizes() {
    let g = new_genesis();
    let kms = NullKmsProvider;
    let (initialized, _) = g.init(&kms).expect("init");

    // Empty payload.
    let empty_ct = initialized.seal(b"").expect("seal empty");
    let empty_pt = initialized.unseal(&kms, &empty_ct).expect("unseal empty");
    assert_eq!(empty_pt, b"");

    // Single byte.
    let one_ct = initialized.seal(b"x").expect("seal single byte");
    let one_pt = initialized
        .unseal(&kms, &one_ct)
        .expect("unseal single byte");
    assert_eq!(one_pt, b"x");

    // Larger payload.
    let large = vec![0xABu8; 8192];
    let large_ct = initialized.seal(&large).expect("seal large");
    let large_pt = initialized.unseal(&kms, &large_ct).expect("unseal large");
    assert_eq!(large_pt, large);
}

/// Load transitions directly to Initialized without a KMS call.
#[test]
fn test_load_to_initialized() {
    let g = new_genesis();
    let initialized = g.load("age1testpubkey".to_string(), vec![1, 2, 3]);

    assert_eq!(initialized.public_key(), Some("age1testpubkey"));
}

/// Multiple rotations in sequence produce distinct keys each time.
#[test]
fn test_multiple_rotations() {
    let g = new_genesis();
    let kms = NullKmsProvider;
    let injector = MockSecretInjector::new();

    let (initialized, artifacts) = g.init(&kms).expect("init");
    let bootstrapping = initialized.begin_bootstrap(&kms).expect("bootstrap");
    let mut active = bootstrapping
        .inject_secret(&injector, "genesis-key", "genesis-system", "age.key")
        .expect("inject");

    let mut seen_keys = vec![artifacts.public_key];

    for _ in 0..3 {
        let rotating = active.begin_rotation();
        let (new_active, new_artifacts) = rotating
            .complete_rotation(&kms, &injector, "genesis-key", "genesis-system", "age.key")
            .expect("rotation");

        // Each rotation must produce a key we haven't seen before.
        assert!(
            !seen_keys.contains(&new_artifacts.public_key),
            "rotated key must be unique"
        );
        seen_keys.push(new_artifacts.public_key);
        active = new_active;
    }

    assert_eq!(seen_keys.len(), 4, "init + 3 rotations = 4 distinct keys");
}

/// Injector snapshot contains the correct compound key after injection.
#[test]
fn test_injector_receives_key_material() {
    let g = new_genesis();
    let kms = NullKmsProvider;

    let (initialized, _) = g.init(&kms).expect("init");
    let bootstrapping = initialized.begin_bootstrap(&kms).expect("bootstrap");

    let injector = MockSecretInjector::new();
    let _active = bootstrapping
        .inject_secret(&injector, "my-secret", "my-ns", "private.key")
        .expect("inject");

    let snapshot = injector.snapshot();
    assert!(
        snapshot.contains_key("my-ns/my-secret/private.key"),
        "snapshot must contain the compound key"
    );
    let stored = &snapshot["my-ns/my-secret/private.key"];
    assert!(
        !stored.is_empty(),
        "injected key material must not be empty"
    );
}

/// GenesisConfig roundtrips through JSON serialization.
#[test]
fn test_config_serialization_roundtrip() {
    let config = GenesisConfig {
        provider_type: "oci-vault".to_string(),
        provider_config: serde_json::json!({"vault_ocid": "ocid1.vault.oc1..example"}),
        public_key: Some("age1abc".to_string()),
        envelope_ciphertext: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
    };

    let json = serde_json::to_string(&config).expect("serialize");
    let recovered: GenesisConfig = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(recovered.provider_type, "oci-vault");
    assert_eq!(recovered.public_key, Some("age1abc".to_string()));
    assert_eq!(
        recovered.envelope_ciphertext,
        Some(vec![0xDE, 0xAD, 0xBE, 0xEF])
    );
}

/// StateTag values are stable for FFI (repr(C)).
#[test]
fn test_state_tag_repr_values() {
    assert_eq!(StateTag::Uninitialized as u32, 0);
    assert_eq!(StateTag::Initialized as u32, 1);
    assert_eq!(StateTag::Bootstrapping as u32, 2);
    assert_eq!(StateTag::Active as u32, 3);
    assert_eq!(StateTag::Rotating as u32, 4);
    assert_eq!(StateTag::Degraded as u32, 5);
}

/// GenesisStatus serializes correctly to JSON.
#[test]
fn test_status_serialization() {
    let g = new_genesis();
    let kms = NullKmsProvider;
    let injector = MockSecretInjector::new();

    let (initialized, _) = g.init(&kms).expect("init");
    let bootstrapping = initialized.begin_bootstrap(&kms).expect("bootstrap");
    let active = bootstrapping
        .inject_secret(&injector, "s", "ns", "k")
        .expect("inject");

    let status = active.status();
    let json = serde_json::to_string(&status).expect("serialize status");

    assert!(json.contains("\"state\":\"active\""));
    assert!(json.contains("\"has_envelope\":true"));
    assert!(json.contains("\"public_key\":\"age1"));
}
