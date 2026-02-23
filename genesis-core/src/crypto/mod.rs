//! Cryptographic primitives for genesis-operator.
//!
//! - [`age`] -- X25519 key generation, encrypt, decrypt (always available).
//! - [`pq`]  -- ML-KEM-1024 / ML-DSA-87 (Phase 2, feature `pq`).
//! - [`hybrid`] -- HKDF combiner for X25519 + ML-KEM shared secrets (Phase 2).

pub mod age;

#[cfg(feature = "pq")]
pub mod pq;

#[cfg(feature = "pq")]
pub mod hybrid;
