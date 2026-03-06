//! Typestate machine for the genesis-operator lifecycle.
//!
//! The [`Genesis`] struct is parameterised by a state type that enforces
//! valid transitions at compile time.  Only the methods appropriate for
//! the current state are available; calling an invalid transition is a
//! type error, not a runtime error.
//!
//! ## State graph
//!
//! ```text
//!   Uninitialized ──init()──▶ Initialized ──begin_bootstrap()──▶ Bootstrapping
//!        │                        ▲   │                              │
//!        │                        │   │──seal()                      │──inject_secret()
//!        └──load()────────────────┘   │──unseal()                    │       │
//!                                     │──verify()                    ▼       ▼
//!                                     │                          [abort]   Active
//!                                     │◀─────────────────────────────┘       │
//!                                                                            │
//!                                     Active ──begin_rotation()──▶ Rotating  │
//!                                       ▲                            │       │
//!                                       │──complete_rotation()───────┘       │
//!                                       │──abort_rotation()──────────┘       │
//!                                                                            │
//!                                     Degraded ──retry()──▶ Active           │
//! ```

use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use crate::audit::{AuditEvent, AuditSink};
use crate::crypto::age;
use crate::k8s::SecretInjector;
use crate::kms::KmsProvider;
use crate::zeroize_mem::KeyMaterial;
use crate::{GenesisError, GenesisStatus, PublicArtifacts, VerifyResult};

// ── Sealed trait pattern ─────────────────────────────────────────────

mod private {
    pub trait Sealed {}
}

/// Marker trait for genesis-operator lifecycle states.
///
/// Sealed so that external crates cannot add new states.
pub trait State: private::Sealed {}

// ── State types ──────────────────────────────────────────────────────

/// No key material has been generated or loaded.
pub struct Uninitialized;
impl private::Sealed for Uninitialized {}
impl State for Uninitialized {}

/// A keypair exists (public key + KMS-encrypted envelope).
pub struct Initialized;
impl private::Sealed for Initialized {}
impl State for Initialized {}

/// Key material has been decrypted and is being injected into Kubernetes.
pub struct Bootstrapping;
impl private::Sealed for Bootstrapping {}
impl State for Bootstrapping {}

/// Secret has been successfully injected; steady state.
pub struct Active;
impl private::Sealed for Active {}
impl State for Active {}

/// Key rotation is in progress.
pub struct Rotating;
impl private::Sealed for Rotating {}
impl State for Rotating {}

/// An error occurred; operator is awaiting manual or automated recovery.
pub struct Degraded;
impl private::Sealed for Degraded {}
impl State for Degraded {}

// ── StateTag (runtime mirror) ────────────────────────────────────────

/// Runtime-inspectable tag that mirrors the typestate variants.
///
/// Usable in status subresources, audit events, and FFI where generics
/// are not available. Stable `repr(C)` numbering for the Go host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(C)]
pub enum StateTag {
    Uninitialized = 0,
    Initialized = 1,
    Bootstrapping = 2,
    Active = 3,
    Rotating = 4,
    Degraded = 5,
}

// ── GenesisConfig ────────────────────────────────────────────────────

/// Configuration for a genesis-operator instance.
///
/// Serialisable so it can be persisted in a ConfigMap or status subresource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    /// KMS provider identifier (e.g. `"aws-kms"`, `"oci-vault"`, `"local-dev"`).
    pub provider_type: String,

    /// Provider-specific configuration (key ARN, vault OCID, etc.).
    pub provider_config: serde_json::Value,

    /// Age public key (`age1...`), populated after init or load.
    pub public_key: Option<String>,

    /// KMS-encrypted private key envelope, populated after init or load.
    pub envelope_ciphertext: Option<Vec<u8>>,
}

// ── Genesis<S> ───────────────────────────────────────────────────────

/// Core state machine for the genesis-operator lifecycle.
///
/// Generic over a [`State`] type parameter that governs which methods are
/// callable.  Transitions consume `self` (move semantics) to guarantee
/// exactly-once progression through the lifecycle.
pub struct Genesis<S: State> {
    config: GenesisConfig,
    audit: Box<dyn AuditSink>,
    _state: PhantomData<S>,
}

// -- Uninitialized ────────────────────────────────────────────────────

impl Genesis<Uninitialized> {
    /// Create a new genesis-operator instance in the `Uninitialized` state.
    pub fn new(config: GenesisConfig, audit: Box<dyn AuditSink>) -> Self {
        Self {
            config,
            audit,
            _state: PhantomData,
        }
    }

    /// Generate a fresh keypair, encrypt the private key with the KMS
    /// provider, and transition to `Initialized`.
    ///
    /// Returns the initialized machine and the public artifacts (public
    /// key + encrypted envelope) that are safe to persist externally.
    pub fn init(
        mut self,
        kms: &dyn KmsProvider,
    ) -> Result<(Genesis<Initialized>, PublicArtifacts), GenesisError> {
        // Generate X25519 keypair via age.
        let (public_key, key_material) = age::generate_keypair()?;

        // Encrypt the private key with the KMS provider.
        let envelope_ciphertext = kms.encrypt(key_material.as_bytes())?;

        // Build SOPS-compatible age config string.
        let sops_config = format!("creation_rules:\n  - age: \"{}\"\n", public_key);

        let artifacts = PublicArtifacts {
            public_key: public_key.clone(),
            envelope_ciphertext: envelope_ciphertext.clone(),
            sops_config,
        };

        // Persist in config.
        self.config.public_key = Some(public_key.clone());
        self.config.envelope_ciphertext = Some(envelope_ciphertext);

        // Audit.
        self.audit.emit(AuditEvent::Init {
            public_key,
            kms_provider: Some(kms.provider_name().to_string()),
        });

        Ok((
            Genesis {
                config: self.config,
                audit: self.audit,
                _state: PhantomData,
            },
            artifacts,
        ))
    }

    /// Load a previously-persisted keypair (public key + encrypted envelope)
    /// and transition directly to `Initialized`.
    ///
    /// No KMS call is made; the envelope is stored as-is.
    pub fn load(
        mut self,
        public_key: String,
        envelope_ciphertext: Vec<u8>,
    ) -> Genesis<Initialized> {
        self.config.public_key = Some(public_key);
        self.config.envelope_ciphertext = Some(envelope_ciphertext);

        Genesis {
            config: self.config,
            audit: self.audit,
            _state: PhantomData,
        }
    }
}

// -- Initialized ──────────────────────────────────────────────────────

impl Genesis<Initialized> {
    /// Verify the stored envelope by decrypting it and re-deriving the
    /// public key.  Returns whether the derived key matches the stored one.
    pub fn verify(&self, kms: &dyn KmsProvider) -> Result<VerifyResult, GenesisError> {
        let envelope = self
            .config
            .envelope_ciphertext
            .as_ref()
            .ok_or(GenesisError::NoEnvelope)?;

        let expected_pub = self
            .config
            .public_key
            .as_ref()
            .ok_or(GenesisError::NoPublicKey)?;

        // Decrypt envelope to get raw private key bytes.
        let private_bytes = kms.decrypt(envelope)?;

        // Derive public key from the decrypted private key.
        let derived_pub = age::public_key_from_private(&private_bytes)?;

        let matches = &derived_pub == expected_pub;

        self.audit.emit(AuditEvent::Verify { success: matches });

        Ok(VerifyResult {
            public_key_matches: matches,
            public_key: derived_pub,
        })
    }

    /// Encrypt `plaintext` using the stored public key.
    ///
    /// This is a public-key-only operation; no KMS call or private key
    /// access is required.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, GenesisError> {
        let public_key = self
            .config
            .public_key
            .as_ref()
            .ok_or(GenesisError::NoPublicKey)?;

        self.audit.emit(AuditEvent::Seal {
            plaintext_len: plaintext.len(),
        });

        age::encrypt_with_public_key(public_key, plaintext)
    }

    /// Decrypt `ciphertext` using the private key (recovered via KMS).
    pub fn unseal(
        &self,
        kms: &dyn KmsProvider,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, GenesisError> {
        let envelope = self
            .config
            .envelope_ciphertext
            .as_ref()
            .ok_or(GenesisError::NoEnvelope)?;

        // Decrypt the envelope to get the raw private key.
        let private_bytes = kms.decrypt(envelope)?;

        self.audit.emit(AuditEvent::Unseal {
            ciphertext_len: ciphertext.len(),
        });

        age::decrypt_with_private_key(&private_bytes, ciphertext)
    }

    /// Decrypt the envelope and transition to `Bootstrapping`, holding
    /// the decrypted key material in memory.
    pub fn begin_bootstrap(
        self,
        kms: &dyn KmsProvider,
    ) -> Result<GenesisBootstrapping, GenesisError> {
        let envelope = self
            .config
            .envelope_ciphertext
            .as_ref()
            .ok_or(GenesisError::NoEnvelope)?;

        let private_bytes = kms.decrypt(envelope)?;
        let key_material = KeyMaterial::new(private_bytes);

        self.audit.emit(AuditEvent::BeginBootstrap {
            key_material_present: true,
        });

        Ok(GenesisBootstrapping {
            inner: Some(Genesis {
                config: self.config,
                audit: self.audit,
                _state: PhantomData,
            }),
            key_material: Some(key_material),
        })
    }

    /// Borrow the config (read-only).
    pub fn config(&self) -> &GenesisConfig {
        &self.config
    }

    /// Borrow the public key, if present.
    pub fn public_key(&self) -> Option<&str> {
        self.config.public_key.as_deref()
    }
}

// ── GenesisBootstrapping ─────────────────────────────────────────────

/// Transitional wrapper that holds decrypted key material during secret
/// injection.
///
/// Consuming `inject_secret` or `abort` is the only way to leave this
/// state.  If the struct is dropped without either call, the `Drop` impl
/// emits a `BootstrappingDropped` audit event as a safety-net alert.
pub struct GenesisBootstrapping {
    /// Wrapped in `Option` so consuming transitions can `.take()` without
    /// conflicting with the `Drop` impl.
    inner: Option<Genesis<Bootstrapping>>,
    key_material: Option<KeyMaterial>,
}

impl GenesisBootstrapping {
    /// Inject the decrypted key material into a Kubernetes secret and
    /// transition to `Active`.
    ///
    /// Consumes `self`; the key material is zeroed when `KeyMaterial` drops.
    pub fn inject_secret(
        self,
        injector: &dyn SecretInjector,
        name: &str,
        ns: &str,
        key: &str,
    ) -> Result<Genesis<Active>, GenesisError> {
        self.inject_secret_with_metadata(injector, name, ns, key, None)
    }

    /// Inject with optional metadata for labels/annotations on the K8s Secret.
    pub fn inject_secret_with_metadata(
        mut self,
        injector: &dyn SecretInjector,
        name: &str,
        ns: &str,
        key: &str,
        metadata: Option<&crate::k8s::SecretMetadata>,
    ) -> Result<Genesis<Active>, GenesisError> {
        let key_material = self.key_material.take().ok_or(GenesisError::NoEnvelope)?;

        injector.inject(key_material.as_bytes(), name, ns, key, metadata)?;

        let inner = self
            .inner
            .take()
            .expect("inner consumed before inject_secret");

        inner.audit.emit(AuditEvent::InjectSecret {
            target_name: name.to_string(),
            target_namespace: ns.to_string(),
            key_material_zeroed: true,
        });

        // key_material drops here, zeroing the bytes.

        Ok(Genesis {
            config: inner.config,
            audit: inner.audit,
            _state: PhantomData,
        })
    }

    /// Inject the decrypted key material into multiple Kubernetes secrets
    /// and transition to `Active`.
    ///
    /// This enables `AdditionalNamespaces` support: the same key material
    /// is injected into each (name, namespace, key) target before the
    /// transition consumes the key material.
    ///
    /// Consumes `self`; the key material is zeroed when `KeyMaterial` drops.
    /// If any injection fails, the error is returned and remaining targets
    /// are skipped. The key material is still zeroed on drop.
    pub fn inject_secrets_multi(
        mut self,
        injector: &dyn SecretInjector,
        targets: &[(String, String, String)], // (name, namespace, key)
        metadata: Option<&crate::k8s::SecretMetadata>,
    ) -> Result<Genesis<Active>, GenesisError> {
        if targets.is_empty() {
            return Err(GenesisError::InvalidInput(
                "inject_secrets_multi requires at least one target".to_string(),
            ));
        }

        let key_material = self.key_material.take().ok_or(GenesisError::NoEnvelope)?;

        for (name, ns, key) in targets {
            injector.inject(key_material.as_bytes(), name, ns, key, metadata)?;
        }

        let inner = self
            .inner
            .take()
            .expect("inner consumed before inject_secrets_multi");

        for (i, (name, ns, _)) in targets.iter().enumerate() {
            inner.audit.emit(AuditEvent::InjectSecret {
                target_name: name.clone(),
                target_namespace: ns.clone(),
                key_material_zeroed: i == targets.len() - 1,
            });
        }

        // key_material drops here, zeroing the bytes.

        Ok(Genesis {
            config: inner.config,
            audit: inner.audit,
            _state: PhantomData,
        })
    }

    /// Borrow the config from the inner state (read-only).
    ///
    /// Used by FFI callers to extract metadata (provider_type, public_key)
    /// for secret enrichment.
    pub fn config_ref(&self) -> &GenesisConfig {
        &self
            .inner
            .as_ref()
            .expect("inner consumed before config_ref")
            .config
    }

    /// Emit an audit event through the inner state machine's audit sink.
    ///
    /// Useful for FFI callers that need to log warnings before calling
    /// `inject_secret` (e.g. mock injector fallback in debug builds).
    pub fn emit_audit(&self, event: AuditEvent) {
        if let Some(ref inner) = self.inner {
            inner.audit.emit(event);
        }
    }

    /// Abort the bootstrap and return to `Initialized` without injecting
    /// any secret.  Key material is zeroed on drop.
    pub fn abort(mut self) -> Genesis<Initialized> {
        // Take the key material so Drop doesn't emit BootstrappingDropped.
        let _km = self.key_material.take();

        let inner = self.inner.take().expect("inner consumed before abort");

        inner.audit.emit(AuditEvent::AbortBootstrap);

        Genesis {
            config: inner.config,
            audit: inner.audit,
            _state: PhantomData,
        }
    }
}

impl Drop for GenesisBootstrapping {
    fn drop(&mut self) {
        // If key_material is still Some, this was an abnormal drop
        // (e.g. panic unwinding or forgotten instance).
        if self.key_material.is_some() {
            if let Some(ref inner) = self.inner {
                inner.audit.emit(AuditEvent::BootstrappingDropped);
            }
        }
    }
}

// -- Active ───────────────────────────────────────────────────────────

impl Genesis<Active> {
    /// Return a snapshot of the current operator status.
    pub fn status(&self) -> GenesisStatus {
        GenesisStatus {
            state: StateTag::Active,
            public_key: self.config.public_key.clone(),
            has_envelope: self.config.envelope_ciphertext.is_some(),
        }
    }

    /// Begin a key rotation cycle, transitioning to `Rotating`.
    pub fn begin_rotation(self) -> Genesis<Rotating> {
        self.audit.emit(AuditEvent::BeginRotation);

        Genesis {
            config: self.config,
            audit: self.audit,
            _state: PhantomData,
        }
    }

    /// Borrow the config (read-only).
    pub fn config(&self) -> &GenesisConfig {
        &self.config
    }
}

// -- Rotating ─────────────────────────────────────────────────────────

impl Genesis<Rotating> {
    /// Complete the rotation: generate a new keypair, re-encrypt with KMS,
    /// inject the new key, and transition back to `Active`.
    pub fn complete_rotation(
        self,
        kms: &dyn KmsProvider,
        injector: &dyn SecretInjector,
        name: &str,
        ns: &str,
        key: &str,
    ) -> Result<(Genesis<Active>, PublicArtifacts), GenesisError> {
        // Generate new keypair.
        let (new_public_key, new_key_material) = age::generate_keypair()?;

        // Encrypt new private key with KMS.
        let new_envelope = kms.encrypt(new_key_material.as_bytes())?;

        // Build metadata for secret enrichment during rotation.
        let metadata = crate::k8s::SecretMetadata {
            provider_type: Some(self.config.provider_type.clone()),
            public_key: Some(new_public_key.clone()),
        };

        // Inject new private key into K8s.
        injector.inject(new_key_material.as_bytes(), name, ns, key, Some(&metadata))?;

        let sops_config = format!("creation_rules:\n  - age: \"{}\"\n", new_public_key);

        let artifacts = PublicArtifacts {
            public_key: new_public_key.clone(),
            envelope_ciphertext: new_envelope.clone(),
            sops_config,
        };

        self.audit.emit(AuditEvent::CompleteRotation {
            new_public_key: new_public_key.clone(),
        });

        let mut config = self.config;
        config.public_key = Some(new_public_key);
        config.envelope_ciphertext = Some(new_envelope);

        Ok((
            Genesis {
                config,
                audit: self.audit,
                _state: PhantomData,
            },
            artifacts,
        ))
    }

    /// Abort the rotation and return to `Active` with the original key.
    pub fn abort_rotation(self) -> Genesis<Active> {
        self.audit.emit(AuditEvent::AbortRotation);

        Genesis {
            config: self.config,
            audit: self.audit,
            _state: PhantomData,
        }
    }
}

// -- Degraded ─────────────────────────────────────────────────────────

impl Genesis<Degraded> {
    /// Transitions from Degraded back to Active by verifying KMS connectivity.
    ///
    /// Design decision: Degraded transitions directly to Active (not Bootstrapping)
    /// because the secret was already injected before degradation occurred.
    /// Re-bootstrapping would be unnecessary -- we only need to confirm the system
    /// can still decrypt the envelope via KMS.
    ///
    /// Verifies that the KMS can still decrypt the envelope and, if
    /// successful, transitions to `Active`.
    pub fn retry(self, kms: &dyn KmsProvider) -> Result<Genesis<Active>, GenesisError> {
        let envelope = self
            .config
            .envelope_ciphertext
            .as_ref()
            .ok_or(GenesisError::NoEnvelope)?;

        // Verify KMS connectivity by attempting a decrypt.
        let _private_bytes = kms.decrypt(envelope)?;

        self.audit.emit(AuditEvent::RecoverFromDegraded);

        Ok(Genesis {
            config: self.config,
            audit: self.audit,
            _state: PhantomData,
        })
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::NullAuditSink;
    use crate::k8s::MockSecretInjector;
    use crate::kms::NullKmsProvider;

    fn test_config() -> GenesisConfig {
        GenesisConfig {
            provider_type: "null-dev".to_string(),
            provider_config: serde_json::json!({}),
            public_key: None,
            envelope_ciphertext: None,
        }
    }

    fn null_audit() -> Box<dyn AuditSink> {
        Box::new(NullAuditSink)
    }

    #[test]
    fn new_creates_uninitialized() {
        let _g: Genesis<Uninitialized> = Genesis::new(test_config(), null_audit());
    }

    #[test]
    fn init_transitions_to_initialized() {
        let g = Genesis::new(test_config(), null_audit());
        let kms = NullKmsProvider;
        let (initialized, artifacts) = g.init(&kms).expect("init should succeed");

        assert!(artifacts.public_key.starts_with("age1"));
        assert!(!artifacts.envelope_ciphertext.is_empty());
        assert!(artifacts.sops_config.contains(&artifacts.public_key));

        // Verify config was updated.
        assert_eq!(
            initialized.config().public_key.as_deref(),
            Some(artifacts.public_key.as_str())
        );
    }

    #[test]
    fn load_transitions_to_initialized() {
        let g = Genesis::new(test_config(), null_audit());
        let initialized = g.load("age1test".to_string(), vec![1, 2, 3]);

        assert_eq!(initialized.public_key(), Some("age1test"));
    }

    #[test]
    fn verify_succeeds_with_matching_key() {
        let g = Genesis::new(test_config(), null_audit());
        let kms = NullKmsProvider;
        let (initialized, _artifacts) = g.init(&kms).expect("init should succeed");

        let result = initialized.verify(&kms).expect("verify should succeed");
        assert!(result.public_key_matches);
    }

    #[test]
    fn seal_and_unseal_roundtrip() {
        let g = Genesis::new(test_config(), null_audit());
        let kms = NullKmsProvider;
        let (initialized, _artifacts) = g.init(&kms).expect("init should succeed");

        let plaintext = b"sensitive configuration data";
        let ciphertext = initialized.seal(plaintext).expect("seal should succeed");

        assert_ne!(&ciphertext[..], &plaintext[..]);

        let decrypted = initialized
            .unseal(&kms, &ciphertext)
            .expect("unseal should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn begin_bootstrap_and_inject() {
        let g = Genesis::new(test_config(), null_audit());
        let kms = NullKmsProvider;
        let (initialized, _) = g.init(&kms).expect("init should succeed");

        let bootstrapping = initialized
            .begin_bootstrap(&kms)
            .expect("begin_bootstrap should succeed");

        let injector = MockSecretInjector::new();
        let active = bootstrapping
            .inject_secret(&injector, "genesis-key", "genesis-system", "age.key")
            .expect("inject should succeed");

        assert!(injector.was_injected("genesis-key"));

        let status = active.status();
        assert_eq!(status.state, StateTag::Active);
        assert!(status.has_envelope);
    }

    #[test]
    fn bootstrap_abort_returns_to_initialized() {
        let g = Genesis::new(test_config(), null_audit());
        let kms = NullKmsProvider;
        let (initialized, _) = g.init(&kms).expect("init should succeed");

        let bootstrapping = initialized
            .begin_bootstrap(&kms)
            .expect("begin_bootstrap should succeed");

        let re_initialized = bootstrapping.abort();
        // We're back to Initialized -- verify still works.
        let result = re_initialized
            .verify(&kms)
            .expect("verify should succeed after abort");
        assert!(result.public_key_matches);
    }

    #[test]
    fn rotation_complete_produces_new_key() {
        let g = Genesis::new(test_config(), null_audit());
        let kms = NullKmsProvider;
        let (initialized, old_artifacts) = g.init(&kms).expect("init should succeed");

        let bootstrapping = initialized
            .begin_bootstrap(&kms)
            .expect("begin_bootstrap should succeed");

        let injector = MockSecretInjector::new();
        let active = bootstrapping
            .inject_secret(&injector, "genesis-key", "genesis-system", "age.key")
            .expect("inject should succeed");

        let rotating = active.begin_rotation();

        let (new_active, new_artifacts) = rotating
            .complete_rotation(&kms, &injector, "genesis-key", "genesis-system", "age.key")
            .expect("rotation should succeed");

        // New key should differ from old key.
        assert_ne!(old_artifacts.public_key, new_artifacts.public_key);
        assert!(new_artifacts.public_key.starts_with("age1"));

        let status = new_active.status();
        assert_eq!(status.state, StateTag::Active);
        assert_eq!(
            status.public_key.as_deref(),
            Some(new_artifacts.public_key.as_str())
        );
    }

    #[test]
    fn rotation_abort_returns_to_active() {
        let g = Genesis::new(test_config(), null_audit());
        let kms = NullKmsProvider;
        let (initialized, _) = g.init(&kms).expect("init should succeed");

        let bootstrapping = initialized
            .begin_bootstrap(&kms)
            .expect("begin_bootstrap should succeed");

        let injector = MockSecretInjector::new();
        let active = bootstrapping
            .inject_secret(&injector, "genesis-key", "genesis-system", "age.key")
            .expect("inject should succeed");

        let rotating = active.begin_rotation();
        let active_again = rotating.abort_rotation();

        let status = active_again.status();
        assert_eq!(status.state, StateTag::Active);
    }

    #[test]
    fn degraded_retry_succeeds() {
        // Manually construct a Degraded genesis (normally reached via error paths).
        let mut config = test_config();

        // We need a valid envelope for retry to work with NullKmsProvider.
        // With NullKms, encrypt/decrypt are identity, so we need valid
        // age private key bytes as the "envelope".
        let (pub_key, km) = age::generate_keypair().expect("keygen");
        config.public_key = Some(pub_key);
        config.envelope_ciphertext = Some(km.as_bytes().to_vec());

        let degraded: Genesis<Degraded> = Genesis {
            config,
            audit: null_audit(),
            _state: PhantomData,
        };

        let kms = NullKmsProvider;
        let active = degraded.retry(&kms).expect("retry should succeed");
        assert_eq!(active.status().state, StateTag::Active);
    }

    #[test]
    fn seal_without_public_key_fails() {
        let g = Genesis::new(test_config(), null_audit());
        // Load with empty public key to get to Initialized without a real key.
        // Actually, load sets the public key, so let's test via a config without one.
        // We can construct directly for testing:
        let initialized: Genesis<Initialized> = Genesis {
            config: GenesisConfig {
                provider_type: "null-dev".to_string(),
                provider_config: serde_json::json!({}),
                public_key: None,
                envelope_ciphertext: None,
            },
            audit: null_audit(),
            _state: PhantomData,
        };
        let _ = g; // suppress unused warning

        let result = initialized.seal(b"data");
        assert!(result.is_err());
    }

    #[test]
    fn unseal_without_envelope_fails() {
        let initialized: Genesis<Initialized> = Genesis {
            config: GenesisConfig {
                provider_type: "null-dev".to_string(),
                provider_config: serde_json::json!({}),
                public_key: Some("age1test".to_string()),
                envelope_ciphertext: None,
            },
            audit: null_audit(),
            _state: PhantomData,
        };

        let kms = NullKmsProvider;
        let result = initialized.unseal(&kms, b"ciphertext");
        assert!(result.is_err());
    }

    #[test]
    fn verify_without_envelope_fails() {
        let initialized: Genesis<Initialized> = Genesis {
            config: GenesisConfig {
                provider_type: "null-dev".to_string(),
                provider_config: serde_json::json!({}),
                public_key: Some("age1test".to_string()),
                envelope_ciphertext: None,
            },
            audit: null_audit(),
            _state: PhantomData,
        };

        let kms = NullKmsProvider;
        let result = initialized.verify(&kms);
        assert!(result.is_err());
    }

    #[test]
    fn genesis_config_serialization_roundtrip() {
        let config = GenesisConfig {
            provider_type: "aws-kms".to_string(),
            provider_config: serde_json::json!({"key_arn": "arn:aws:kms:us-east-1:123:key/abc"}),
            public_key: Some("age1abcdef".to_string()),
            envelope_ciphertext: Some(vec![0xDE, 0xAD]),
        };

        let json = serde_json::to_string(&config).expect("serialize");
        let deserialized: GenesisConfig = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.provider_type, "aws-kms");
        assert_eq!(deserialized.public_key, Some("age1abcdef".to_string()));
    }

    #[test]
    fn state_tag_values() {
        assert_eq!(StateTag::Uninitialized as u8, 0);
        assert_eq!(StateTag::Initialized as u8, 1);
        assert_eq!(StateTag::Bootstrapping as u8, 2);
        assert_eq!(StateTag::Active as u8, 3);
        assert_eq!(StateTag::Rotating as u8, 4);
        assert_eq!(StateTag::Degraded as u8, 5);
    }

    #[test]
    fn inject_secrets_multi_succeeds() {
        let g = Genesis::new(test_config(), null_audit());
        let kms = NullKmsProvider;
        let (initialized, _) = g.init(&kms).expect("init should succeed");

        let bootstrapping = initialized
            .begin_bootstrap(&kms)
            .expect("begin_bootstrap should succeed");

        let injector = MockSecretInjector::new();
        let targets = vec![
            (
                "genesis-key".to_string(),
                "genesis-system".to_string(),
                "age.key".to_string(),
            ),
            (
                "genesis-key".to_string(),
                "app-namespace".to_string(),
                "age.key".to_string(),
            ),
            (
                "genesis-key".to_string(),
                "monitoring".to_string(),
                "age.key".to_string(),
            ),
        ];

        let active = bootstrapping
            .inject_secrets_multi(&injector, &targets, None)
            .expect("inject_secrets_multi should succeed");

        // Verify all targets were injected.
        assert!(injector.was_injected("genesis-key"));
        let snap = injector.snapshot();
        assert!(snap.contains_key("genesis-system/genesis-key/age.key"));
        assert!(snap.contains_key("app-namespace/genesis-key/age.key"));
        assert!(snap.contains_key("monitoring/genesis-key/age.key"));

        let status = active.status();
        assert_eq!(status.state, StateTag::Active);
        assert!(status.has_envelope);
    }

    #[test]
    fn inject_secrets_multi_empty_targets_returns_error() {
        let g = Genesis::new(test_config(), null_audit());
        let kms = NullKmsProvider;
        let (initialized, _) = g.init(&kms).expect("init should succeed");

        let bootstrapping = initialized
            .begin_bootstrap(&kms)
            .expect("begin_bootstrap should succeed");

        let injector = MockSecretInjector::new();
        let targets: Vec<(String, String, String)> = vec![];

        let result = bootstrapping.inject_secrets_multi(&injector, &targets, None);
        match result {
            Err(ref e) => assert_eq!(e.error_code(), 103), // InvalidInput
            Ok(_) => panic!("expected InvalidInput error for empty targets"),
        }
    }

    #[test]
    fn inject_secrets_multi_all_targets_receive_same_key_material() {
        let g = Genesis::new(test_config(), null_audit());
        let kms = NullKmsProvider;
        let (initialized, _) = g.init(&kms).expect("init should succeed");

        let bootstrapping = initialized
            .begin_bootstrap(&kms)
            .expect("begin_bootstrap should succeed");

        let injector = MockSecretInjector::new();
        let targets = vec![
            (
                "secret-a".to_string(),
                "ns-1".to_string(),
                "data".to_string(),
            ),
            (
                "secret-b".to_string(),
                "ns-2".to_string(),
                "data".to_string(),
            ),
        ];

        let _active = bootstrapping
            .inject_secrets_multi(&injector, &targets, None)
            .expect("inject_secrets_multi should succeed");

        let snap = injector.snapshot();
        let val_a = snap
            .get("ns-1/secret-a/data")
            .expect("target a should exist");
        let val_b = snap
            .get("ns-2/secret-b/data")
            .expect("target b should exist");
        // Both targets should receive identical key material.
        assert_eq!(val_a, val_b);
        assert!(!val_a.is_empty());
    }

    #[test]
    fn inject_secrets_multi_with_metadata() {
        let g = Genesis::new(test_config(), null_audit());
        let kms = NullKmsProvider;
        let (initialized, _) = g.init(&kms).expect("init should succeed");

        let bootstrapping = initialized
            .begin_bootstrap(&kms)
            .expect("begin_bootstrap should succeed");

        let injector = MockSecretInjector::new();
        let meta = crate::k8s::SecretMetadata {
            provider_type: Some("null-dev".to_string()),
            public_key: Some("age1testkey1234".to_string()),
        };
        let targets = vec![
            (
                "genesis-key".to_string(),
                "ns-1".to_string(),
                "age.key".to_string(),
            ),
            (
                "genesis-key".to_string(),
                "ns-2".to_string(),
                "age.key".to_string(),
            ),
        ];

        let _active = bootstrapping
            .inject_secrets_multi(&injector, &targets, Some(&meta))
            .expect("inject_secrets_multi should succeed");

        let meta_snap = injector.metadata_snapshot();
        let meta_1 = meta_snap.get("ns-1/genesis-key").expect("meta for ns-1");
        let meta_2 = meta_snap.get("ns-2/genesis-key").expect("meta for ns-2");
        assert_eq!(meta_1.provider_type.as_deref(), Some("null-dev"));
        assert_eq!(meta_2.provider_type.as_deref(), Some("null-dev"));
    }
}
