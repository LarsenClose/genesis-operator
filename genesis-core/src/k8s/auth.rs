//! Kubeconfig parsing and authentication helpers.
//!
//! Provides utilities for extracting cluster credentials from a kubeconfig
//! file, primarily for out-of-cluster operation during local development
//! and CI.

/// Parse a kubeconfig file and return the API server URL, bearer token,
/// and CA certificate bundle for the current context.
///
/// # Panics
///
/// This function is a placeholder for WF-4 and will panic if called.
pub fn from_kubeconfig(_path: &str) -> (String, String, Vec<u8>) {
    todo!("kubeconfig parsing will be implemented in WF-4")
}
