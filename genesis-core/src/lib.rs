#![deny(unsafe_code)]

#[allow(unsafe_code)]
pub mod audit;
pub mod crypto;
pub mod envelope;
#[allow(unsafe_code)]
pub mod ffi;
pub mod k8s;
pub mod kms;
pub mod state;
#[allow(unsafe_code)]
pub mod zeroize_mem;

use serde::{Deserialize, Serialize};

// ── Error type ────────────────────────────────────────────────────────

/// Unified error type for every fallible operation in genesis-core.
///
/// Each variant carries enough context for structured logging and maps to
/// a stable numeric code via [`GenesisError::error_code`] for FFI consumers.
#[derive(Debug, thiserror::Error)]
pub enum GenesisError {
    // State (100s)
    #[error("no envelope present")]
    NoEnvelope,

    #[error("no public key present")]
    NoPublicKey,

    #[error("invalid state transition from {from} to {to}")]
    InvalidTransition { from: String, to: String },

    // Crypto / Age (200s)
    #[error("age key generation failed: {0}")]
    AgeKeyGenFailed(String),

    #[error("age encryption failed: {0}")]
    AgeEncryptFailed(String),

    #[error("age decryption failed: {0}")]
    AgeDecryptFailed(String),

    #[error("public key mismatch: expected {expected}, got {got}")]
    PublicKeyMismatch { expected: String, got: String },

    // PQ Crypto (210s)
    #[error("PQ key generation failed: {0}")]
    PqKeyGenFailed(String),

    #[error("PQ encapsulation failed: {0}")]
    PqEncapsulateFailed(String),

    #[error("PQ decapsulation failed: {0}")]
    PqDecapsulateFailed(String),

    #[error("PQ signing failed: {0}")]
    PqSignFailed(String),

    #[error("PQ verification failed: {0}")]
    PqVerifyFailed(String),

    #[error("hybrid key combine failed: {0}")]
    HybridCombineFailed(String),

    // Envelope (220s)
    #[error("envelope version mismatch: {0}")]
    EnvelopeVersionMismatch(String),

    #[error("envelope signature invalid")]
    EnvelopeSignatureInvalid,

    #[error("envelope parse failed: {0}")]
    EnvelopeParseFailed(String),

    // KMS (300s)
    #[error("KMS call failed: {0}")]
    KmsCallFailed(String),

    #[error("KMS response invalid")]
    KmsResponseInvalid,

    #[error("KMS not configured")]
    KmsNotConfigured,

    // K8s (400s)
    #[error("K8s auth failed: {0}")]
    K8sAuthFailed(String),

    #[error("K8s secret injection failed: {0}")]
    K8sInjectFailed(String),

    #[error("K8s secret check failed: {0}")]
    K8sCheckFailed(String),

    // Serialization (500)
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl GenesisError {
    /// Stable numeric code for FFI and structured logging.
    ///
    /// Ranges:
    /// - 100-199  state errors
    /// - 200-299  crypto / age errors
    /// - 300-399  KMS errors
    /// - 400-499  K8s errors
    /// - 500      serialization
    pub fn error_code(&self) -> u32 {
        match self {
            GenesisError::NoEnvelope => 100,
            GenesisError::NoPublicKey => 101,
            GenesisError::InvalidTransition { .. } => 102,

            GenesisError::AgeKeyGenFailed(_) => 200,
            GenesisError::AgeEncryptFailed(_) => 201,
            GenesisError::AgeDecryptFailed(_) => 202,
            GenesisError::PublicKeyMismatch { .. } => 203,

            GenesisError::PqKeyGenFailed(_) => 210,
            GenesisError::PqEncapsulateFailed(_) => 211,
            GenesisError::PqDecapsulateFailed(_) => 212,
            GenesisError::PqSignFailed(_) => 213,
            GenesisError::PqVerifyFailed(_) => 214,
            GenesisError::HybridCombineFailed(_) => 215,

            GenesisError::EnvelopeVersionMismatch(_) => 220,
            GenesisError::EnvelopeSignatureInvalid => 221,
            GenesisError::EnvelopeParseFailed(_) => 222,

            GenesisError::KmsCallFailed(_) => 300,
            GenesisError::KmsResponseInvalid => 301,
            GenesisError::KmsNotConfigured => 302,

            GenesisError::K8sAuthFailed(_) => 400,
            GenesisError::K8sInjectFailed(_) => 401,
            GenesisError::K8sCheckFailed(_) => 402,

            GenesisError::Json(_) => 500,
        }
    }
}

// ── Public result / report types ──────────────────────────────────────

/// Artifacts produced by a successful bootstrap that are safe to persist
/// outside the operator's memory (no secret material).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicArtifacts {
    pub public_key: String,
    pub envelope_ciphertext: Vec<u8>,
    pub sops_config: String,
}

/// Full PQ keypair set generated during hybrid init.
///
/// All private keys are wrapped in [`KeyMaterial`] and never leave
/// Rust's memory model. Public keys can be stored in the
/// GenesisBootstrap CRD status.
///
/// **Intentionally not Clone** -- private keys must not be duplicated.
#[cfg(feature = "pq")]
pub struct GenesisKeySet {
    /// X25519 private key (age format, UTF-8 `AGE-SECRET-KEY-1...`).
    pub age_identity: KeyMaterial,
    /// X25519 public key (age format, `age1...`).
    pub age_recipient: String,
    /// ML-KEM-1024 decapsulation key seed (64 bytes).
    pub mlkem_private_key: KeyMaterial,
    /// ML-KEM-1024 encapsulation key (1568 bytes).
    pub mlkem_public_key: Vec<u8>,
    /// ML-DSA-87 signing key seed (32 bytes).
    pub signing_key: KeyMaterial,
    /// ML-DSA-87 verifying key (2592 bytes).
    pub signing_public_key: Vec<u8>,
}

#[cfg(feature = "pq")]
impl GenesisKeySet {
    /// Generate a complete PQ keypair set.
    pub fn generate() -> Result<Self, GenesisError> {
        let (age_recipient, age_identity) = crypto::age::generate_keypair()?;
        let (mlkem_public_key, mlkem_private_key) = crypto::pq::mlkem_generate_keypair()?;
        let (signing_public_key, signing_key) = crypto::pq::mldsa_generate_keypair()?;

        Ok(GenesisKeySet {
            age_identity,
            age_recipient,
            mlkem_private_key,
            mlkem_public_key,
            signing_key,
            signing_public_key,
        })
    }

    /// Extract the public-only components as JSON for CRD storage.
    pub fn public_keys_json(&self) -> Result<String, GenesisError> {
        let value = serde_json::json!({
            "age_recipient": self.age_recipient,
            "mlkem_public_key": base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &self.mlkem_public_key
            ),
            "signing_public_key": base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &self.signing_public_key
            ),
        });
        serde_json::to_string(&value).map_err(GenesisError::from)
    }
}

/// Result of verifying the current key material against a stored envelope.
#[derive(Debug, Clone, Serialize)]
pub struct VerifyResult {
    pub public_key_matches: bool,
    pub public_key: String,
}

/// Outcome of a reconcile loop iteration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ReconcileResult {
    /// The target secret already exists with correct content.
    AlreadyPresent,
    /// The secret was missing or stale and has been re-injected.
    Reinjected,
}

/// Snapshot of the operator's current state for status subresource / health
/// endpoints.
#[derive(Debug, Clone, Serialize)]
pub struct GenesisStatus {
    pub state: state::StateTag,
    pub public_key: Option<String>,
    pub has_envelope: bool,
}

/// Placeholder for a full diagnostic bundle (expanded in later work-fronts).
#[derive(Debug, Clone, Default, Serialize)]
pub struct DiagnosticReport {
    _placeholder: (),
}

// ── Re-exports ────────────────────────────────────────────────────────

pub use audit::{AuditEvent, AuditSink};
pub use state::StateTag;
pub use zeroize_mem::KeyMaterial;
