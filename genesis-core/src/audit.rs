//! Structured audit trail for every security-relevant operation.
//!
//! All lifecycle events flow through an [`AuditSink`] implementation.
//! Two sinks are provided out of the box:
//!
//! - [`FfiAuditSink`] -- forwards serialised JSON to an `extern "C"` callback
//!   so the Go host can ingest events.
//! - [`NullAuditSink`] -- silently discards events (useful in unit tests).

use serde::Serialize;

// ── AuditEvent ────────────────────────────────────────────────────────

/// Every variant corresponds to one auditable action in the operator
/// lifecycle. New variants are append-only (never renumber or remove).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditEvent {
    Init {
        public_key: String,
        kms_provider: Option<String>,
    },
    Verify {
        success: bool,
    },
    Seal {
        plaintext_len: usize,
    },
    Unseal {
        ciphertext_len: usize,
    },
    BeginBootstrap {
        key_material_present: bool,
    },
    InjectSecret {
        target_name: String,
        target_namespace: String,
        key_material_zeroed: bool,
    },
    AbortBootstrap,
    BootstrappingDropped,
    ReconcileNoop,
    ReconcileReinjected {
        target_name: String,
        target_namespace: String,
    },
    BeginRotation,
    CompleteRotation {
        new_public_key: String,
    },
    AbortRotation,
    RecoverFromDegraded,
    Warning {
        message: String,
    },
}

impl AuditEvent {
    /// Returns `true` when the event implies that key material is (or was)
    /// present in operator memory. Useful for conditional scrubbing or
    /// escalated alerting.
    pub fn key_material_present(&self) -> bool {
        matches!(
            self,
            AuditEvent::BeginBootstrap {
                key_material_present: true
            } | AuditEvent::Seal { .. }
                | AuditEvent::Unseal { .. }
                | AuditEvent::InjectSecret { .. }
                | AuditEvent::BeginRotation
                | AuditEvent::CompleteRotation { .. }
        )
    }
}

// ── AuditSink trait ───────────────────────────────────────────────────

/// Trait for consuming audit events.
///
/// Implementations must be `Send + Sync` because the operator runtime may
/// emit events from multiple async tasks.
pub trait AuditSink: Send + Sync {
    fn emit(&self, event: AuditEvent);
}

// ── FfiAuditSink ──────────────────────────────────────────────────────

/// Forwards events as JSON bytes to an `extern "C"` callback provided by
/// the Go (or other FFI) host.
///
/// The callback receives a pointer to a UTF-8 JSON string and its length.
/// The callee must **copy** the data if it needs to outlive the call.
pub struct FfiAuditSink {
    callback: unsafe extern "C" fn(*const u8, usize),
}

impl FfiAuditSink {
    pub fn new(callback: unsafe extern "C" fn(*const u8, usize)) -> Self {
        Self { callback }
    }
}

// Safety: extern "C" fn pointers are inherently Send + Sync (they are just
// code addresses), so FfiAuditSink auto-derives both traits and no manual
// unsafe impls are required.

impl AuditSink for FfiAuditSink {
    fn emit(&self, event: AuditEvent) {
        let record = AuditRecord::new(event);
        if let Ok(json) = serde_json::to_string(&record) {
            // Safety: caller guarantees the callback is a valid function pointer
            // registered by the Go host via genesis_new.
            unsafe {
                (self.callback)(json.as_ptr(), json.len());
            }
        }
    }
}

// ── NullAuditSink ─────────────────────────────────────────────────────

/// Discards all events. Intended for unit tests and benchmarks where audit
/// output is irrelevant.
pub struct NullAuditSink;

impl AuditSink for NullAuditSink {
    fn emit(&self, _event: AuditEvent) {}
}

// ── AuditRecord ───────────────────────────────────────────────────────

/// Timestamped wrapper around an [`AuditEvent`], used as the serialisation
/// envelope for the FFI callback and any future persistence layer.
#[derive(Debug, Clone, Serialize)]
pub struct AuditRecord {
    /// ISO-8601 timestamp (UTC) captured at record creation.
    pub timestamp: String,
    #[serde(flatten)]
    pub event: AuditEvent,
}

impl AuditRecord {
    pub fn new(event: AuditEvent) -> Self {
        // Minimal ISO-8601 without pulling in chrono: seconds since epoch
        // formatted via std. This is intentionally low-fidelity; the Go
        // host will attach its own high-resolution timestamp.
        let duration = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let timestamp = format!("{}Z", duration.as_secs());
        Self { timestamp, event }
    }
}
