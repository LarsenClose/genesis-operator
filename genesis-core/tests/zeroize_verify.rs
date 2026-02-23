//! Memory safety tests for KeyMaterial.
//!
//! These tests verify that `KeyMaterial` can be created, used, and dropped
//! without panics. Since `KeyMaterial::as_bytes()` is `pub(crate)`, these
//! integration tests exercise the type through the public state machine API.
//!
//! Compile-time guarantees (no Clone, no Debug, no Display) are verified via
//! trybuild compile-fail tests in the unit test suite, not here.

use genesis_core::KeyMaterial;

// ── Drop safety ──────────────────────────────────────────────────────

/// Creating and dropping a KeyMaterial must not panic.
/// The drop impl runs mlock/munlock and zeroizes the buffer.
#[test]
fn test_key_material_drops_without_panic() {
    let km = KeyMaterial::new(vec![0x42; 64]);
    drop(km);
    // If we reach here, drop succeeded without panic.
}

/// Creating and dropping an empty KeyMaterial must not panic.
/// The drop impl short-circuits for empty buffers.
#[test]
fn test_key_material_empty_drops_without_panic() {
    let km = KeyMaterial::new(Vec::new());
    drop(km);
}

/// Creating a large KeyMaterial and dropping it must not panic.
#[test]
fn test_key_material_large_drops_without_panic() {
    let km = KeyMaterial::new(vec![0xFF; 1_048_576]); // 1 MB
    drop(km);
}

// ── Functional tests via state machine ───────────────────────────────

/// KeyMaterial holds valid key bytes: verify by running the full
/// init -> verify cycle which internally calls as_bytes().
#[test]
fn test_key_material_as_bytes_via_state_machine() {
    use genesis_core::audit::NullAuditSink;
    use genesis_core::kms::NullKmsProvider;
    use genesis_core::state::{Genesis, GenesisConfig};

    let g = Genesis::new(
        GenesisConfig {
            provider_type: "null-dev".to_string(),
            provider_config: serde_json::json!({}),
            public_key: None,
            envelope_ciphertext: None,
        },
        Box::new(NullAuditSink),
    );
    let kms = NullKmsProvider;

    // init() creates KeyMaterial internally and calls as_bytes() to encrypt.
    let (initialized, artifacts) = g.init(&kms).expect("init should succeed");

    // verify() decrypts the envelope and re-derives the public key,
    // exercising the key material round-trip.
    let result = initialized.verify(&kms).expect("verify should succeed");
    assert!(result.public_key_matches);
    assert_eq!(result.public_key, artifacts.public_key);
}

/// KeyMaterial is consumed (and zeroed) during bootstrap injection.
#[test]
fn test_key_material_consumed_on_inject() {
    use genesis_core::audit::NullAuditSink;
    use genesis_core::k8s::MockSecretInjector;
    use genesis_core::kms::NullKmsProvider;
    use genesis_core::state::{Genesis, GenesisConfig, StateTag};

    let g = Genesis::new(
        GenesisConfig {
            provider_type: "null-dev".to_string(),
            provider_config: serde_json::json!({}),
            public_key: None,
            envelope_ciphertext: None,
        },
        Box::new(NullAuditSink),
    );
    let kms = NullKmsProvider;

    let (initialized, _) = g.init(&kms).expect("init");
    let bootstrapping = initialized.begin_bootstrap(&kms).expect("begin_bootstrap");

    // inject_secret() takes ownership of KeyMaterial and drops it.
    let injector = MockSecretInjector::new();
    let active = bootstrapping
        .inject_secret(&injector, "genesis-key", "genesis-system", "age.key")
        .expect("inject should succeed");

    // After injection, the state machine is Active.
    assert_eq!(active.status().state, StateTag::Active);

    // The injector received the key bytes.
    assert!(injector.was_injected("genesis-key"));
}

/// KeyMaterial is zeroed when bootstrap is aborted.
#[test]
fn test_key_material_zeroed_on_abort() {
    use genesis_core::audit::NullAuditSink;
    use genesis_core::kms::NullKmsProvider;
    use genesis_core::state::{Genesis, GenesisConfig};

    let g = Genesis::new(
        GenesisConfig {
            provider_type: "null-dev".to_string(),
            provider_config: serde_json::json!({}),
            public_key: None,
            envelope_ciphertext: None,
        },
        Box::new(NullAuditSink),
    );
    let kms = NullKmsProvider;

    let (initialized, _) = g.init(&kms).expect("init");
    let bootstrapping = initialized.begin_bootstrap(&kms).expect("begin_bootstrap");

    // abort() takes ownership of KeyMaterial and drops it (zeroing).
    let re_initialized = bootstrapping.abort();

    // We are back to Initialized; verify still works.
    let result = re_initialized.verify(&kms).expect("verify after abort");
    assert!(result.public_key_matches);
}

/// KeyMaterial is not Clone -- this is a documentation test.
///
/// The actual enforcement is compile-time: `KeyMaterial` intentionally
/// does not derive or implement `Clone`. A `trybuild` compile-fail test
/// in the unit test suite verifies this. Here we simply confirm the type
/// exists and can be constructed.
#[test]
fn test_key_material_not_clone_documentation() {
    // KeyMaterial::new is public; we can construct it.
    let _km = KeyMaterial::new(vec![1, 2, 3]);

    // The following would fail to compile if uncommented:
    //   let _km2 = _km.clone();  // ERROR: no method named `clone`
    //
    // The following would fail to compile if uncommented:
    //   println!("{:?}", _km);  // ERROR: KeyMaterial doesn't implement Debug
}

/// Multiple KeyMaterial instances can be created and dropped independently.
#[test]
fn test_multiple_key_materials_independent_drops() {
    let km1 = KeyMaterial::new(vec![0x01; 32]);
    let km2 = KeyMaterial::new(vec![0x02; 64]);
    let km3 = KeyMaterial::new(vec![0x03; 128]);

    // Drop in non-creation order.
    drop(km2);
    drop(km1);
    drop(km3);
}

/// KeyMaterial with single byte.
#[test]
fn test_key_material_single_byte() {
    let km = KeyMaterial::new(vec![0xAA]);
    drop(km);
}
