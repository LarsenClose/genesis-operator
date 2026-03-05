//! Kubernetes secret injection helpers.
//!
//! - [`inject`] -- [`SecretInjector`] trait and implementations for
//!   creating/updating K8s `Secret` resources.
//! - [`auth`]   -- Kubeconfig parsing utilities (stub, completed in WF-4).

pub mod auth;
pub mod inject;

// Re-export the main trait and implementations at the k8s module level
// for ergonomic imports: `use genesis_core::k8s::SecretInjector;`
pub use inject::MockSecretInjector;
pub use inject::SecretInjector;
pub use inject::SecretMetadata;
pub use inject::UreqSecretInjector;
