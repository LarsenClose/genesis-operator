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
