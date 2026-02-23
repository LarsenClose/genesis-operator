//! Kubernetes secret injection trait and implementations.
//!
//! [`SecretInjector`] is the core abstraction for creating and updating
//! Kubernetes `Secret` resources.  Two implementations are provided:
//!
//! - [`UreqSecretInjector`] -- production implementation that talks to the
//!   Kubernetes API server via `ureq` HTTP calls with Bearer token auth.
//! - [`MockSecretInjector`] -- in-memory fake for unit and integration tests.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine as _;

use crate::GenesisError;

// ── SecretInjector trait ─────────────────────────────────────────────

/// Abstraction over Kubernetes secret creation / update.
///
/// Implementations must be `Send + Sync` because the operator runtime may
/// inject secrets from multiple async tasks or reconcile loops.
pub trait SecretInjector: Send + Sync {
    /// Create or update a Kubernetes `Secret` resource with the provided
    /// key material.
    ///
    /// - `key_bytes`        -- raw secret data to store
    /// - `secret_name`      -- metadata.name of the Secret
    /// - `secret_namespace` -- metadata.namespace of the Secret
    /// - `secret_key`       -- key within the Secret's `data` map
    ///
    /// On conflict (HTTP 409), the implementation should retry with a PUT
    /// (update) instead of POST (create).
    fn inject(
        &self,
        key_bytes: &[u8],
        secret_name: &str,
        secret_namespace: &str,
        secret_key: &str,
    ) -> Result<(), GenesisError>;

    /// Check whether a Kubernetes `Secret` with the given name already
    /// exists in the specified namespace.
    fn secret_exists(
        &self,
        secret_name: &str,
        secret_namespace: &str,
    ) -> Result<bool, GenesisError>;
}

// ── MockSecretInjector ───────────────────────────────────────────────

/// In-memory fake for testing secret injection without a real cluster.
///
/// Tracks every injected secret in a `Mutex<HashMap<String, Vec<u8>>>`.
/// The map key is `"{namespace}/{name}/{key}"`.
pub struct MockSecretInjector {
    secrets: Mutex<HashMap<String, Vec<u8>>>,
}

impl MockSecretInjector {
    /// Create a new empty mock injector.
    pub fn new() -> Self {
        Self {
            secrets: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `true` if a secret with the given compound key was injected.
    ///
    /// The compound key format is `"{namespace}/{name}/{key}"`.
    pub fn was_injected(&self, name: &str) -> bool {
        let secrets = self.secrets.lock().expect("mock lock poisoned");
        secrets.keys().any(|k| k.contains(name))
    }

    /// Return a snapshot of all injected secrets for test assertions.
    pub fn snapshot(&self) -> HashMap<String, Vec<u8>> {
        self.secrets.lock().expect("mock lock poisoned").clone()
    }

    /// Compound key used for internal storage.
    fn compound_key(secret_namespace: &str, secret_name: &str, secret_key: &str) -> String {
        format!("{secret_namespace}/{secret_name}/{secret_key}")
    }
}

impl Default for MockSecretInjector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretInjector for MockSecretInjector {
    fn inject(
        &self,
        key_bytes: &[u8],
        secret_name: &str,
        secret_namespace: &str,
        secret_key: &str,
    ) -> Result<(), GenesisError> {
        let key = Self::compound_key(secret_namespace, secret_name, secret_key);
        self.secrets
            .lock()
            .expect("mock lock poisoned")
            .insert(key, key_bytes.to_vec());
        Ok(())
    }

    fn secret_exists(
        &self,
        secret_name: &str,
        secret_namespace: &str,
    ) -> Result<bool, GenesisError> {
        let secrets = self.secrets.lock().expect("mock lock poisoned");
        let prefix = format!("{secret_namespace}/{secret_name}/");
        Ok(secrets.keys().any(|k| k.starts_with(&prefix)))
    }
}

// ── UreqSecretInjector ───────────────────────────────────────────────

/// Production implementation that talks to the Kubernetes API server
/// using `ureq` with Bearer token authentication.
///
/// Supports both in-cluster (service account) and out-of-cluster
/// (kubeconfig) configurations.
pub struct UreqSecretInjector {
    /// Kubernetes API server base URL, e.g. `https://kubernetes.default.svc`.
    api_server: String,
    /// Bearer token for authentication.
    token: String,
    /// PEM-encoded CA certificate bundle for TLS verification.
    /// Used for custom TLS configuration in WF-4.
    #[allow(dead_code)]
    ca_cert: Vec<u8>,
}

impl UreqSecretInjector {
    /// Create an injector configured for in-cluster operation.
    ///
    /// Reads the service account token and CA certificate from the standard
    /// mounted paths under `/var/run/secrets/kubernetes.io/serviceaccount/`.
    ///
    /// # Errors
    ///
    /// Returns `GenesisError::K8sAuthFailed` if the service account files
    /// cannot be read.
    pub fn in_cluster() -> Result<Self, GenesisError> {
        const SA_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

        let token = std::fs::read_to_string(format!("{SA_PATH}/token"))
            .map_err(|e| GenesisError::K8sAuthFailed(format!("failed to read SA token: {e}")))?;

        let ca_cert = std::fs::read(format!("{SA_PATH}/ca.crt"))
            .map_err(|e| GenesisError::K8sAuthFailed(format!("failed to read CA cert: {e}")))?;

        Ok(Self {
            api_server: "https://kubernetes.default.svc".to_string(),
            token,
            ca_cert,
        })
    }

    /// Create an injector with explicit credentials (for out-of-cluster or
    /// testing).
    pub fn new(api_server: String, token: String, ca_cert: Vec<u8>) -> Self {
        Self {
            api_server,
            token,
            ca_cert,
        }
    }

    /// Build the URL for a namespaced Secret resource.
    fn secret_url(&self, namespace: &str, name: &str) -> String {
        format!(
            "{}/api/v1/namespaces/{}/secrets/{}",
            self.api_server, namespace, name
        )
    }

    /// Build the URL for the secrets collection in a namespace.
    fn secrets_collection_url(&self, namespace: &str) -> String {
        format!(
            "{}/api/v1/namespaces/{}/secrets",
            self.api_server, namespace
        )
    }

    /// Build the JSON body for a Kubernetes Secret resource.
    fn secret_body(
        &self,
        key_bytes: &[u8],
        secret_name: &str,
        secret_namespace: &str,
        secret_key: &str,
    ) -> serde_json::Value {
        let encoded = base64::engine::general_purpose::STANDARD.encode(key_bytes);
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": secret_name,
                "namespace": secret_namespace
            },
            "type": "Opaque",
            "data": {
                secret_key: encoded
            }
        })
    }
}

impl SecretInjector for UreqSecretInjector {
    fn inject(
        &self,
        key_bytes: &[u8],
        secret_name: &str,
        secret_namespace: &str,
        secret_key: &str,
    ) -> Result<(), GenesisError> {
        let body = self.secret_body(key_bytes, secret_name, secret_namespace, secret_key);
        let url = self.secrets_collection_url(secret_namespace);

        // Attempt POST (create).
        let response = ureq::post(&url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("Content-Type", "application/json")
            .send_string(&body.to_string());

        match response {
            Ok(_) => Ok(()),
            Err(ureq::Error::Status(409, _)) => {
                // Conflict -- secret already exists; update with PUT.
                let put_url = self.secret_url(secret_namespace, secret_name);
                ureq::put(&put_url)
                    .set("Authorization", &format!("Bearer {}", self.token))
                    .set("Content-Type", "application/json")
                    .send_string(&body.to_string())
                    .map_err(|e| {
                        GenesisError::K8sInjectFailed(format!("PUT update failed: {e}"))
                    })?;
                Ok(())
            }
            Err(e) => Err(GenesisError::K8sInjectFailed(format!(
                "POST create failed: {e}"
            ))),
        }
    }

    fn secret_exists(
        &self,
        secret_name: &str,
        secret_namespace: &str,
    ) -> Result<bool, GenesisError> {
        let url = self.secret_url(secret_namespace, secret_name);
        let response = ureq::get(&url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .call();

        match response {
            Ok(_) => Ok(true),
            Err(ureq::Error::Status(404, _)) => Ok(false),
            Err(e) => Err(GenesisError::K8sCheckFailed(format!(
                "secret existence check failed: {e}"
            ))),
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_inject_and_check() {
        let mock = MockSecretInjector::new();

        assert!(!mock.was_injected("my-secret"));
        assert!(!mock
            .secret_exists("my-secret", "default")
            .expect("should succeed"));

        mock.inject(b"super-secret-key", "my-secret", "default", "tls.key")
            .expect("inject should succeed");

        assert!(mock.was_injected("my-secret"));
        assert!(mock
            .secret_exists("my-secret", "default")
            .expect("should succeed"));
    }

    #[test]
    fn mock_inject_multiple_keys() {
        let mock = MockSecretInjector::new();

        mock.inject(b"key1", "secret-a", "ns1", "data")
            .expect("inject should succeed");
        mock.inject(b"key2", "secret-b", "ns2", "data")
            .expect("inject should succeed");

        assert!(mock.was_injected("secret-a"));
        assert!(mock.was_injected("secret-b"));
        assert!(!mock.was_injected("secret-c"));
    }

    #[test]
    fn mock_overwrite_existing_secret() {
        let mock = MockSecretInjector::new();

        mock.inject(b"old-value", "my-secret", "default", "key")
            .expect("inject should succeed");
        mock.inject(b"new-value", "my-secret", "default", "key")
            .expect("inject should succeed");

        let snap = mock.snapshot();
        let stored = snap.get("default/my-secret/key").expect("should exist");
        assert_eq!(stored, b"new-value");
    }

    #[test]
    fn mock_default_impl() {
        let mock = MockSecretInjector::default();
        assert!(!mock.was_injected("anything"));
    }

    #[test]
    fn mock_secret_exists_checks_namespace() {
        let mock = MockSecretInjector::new();

        mock.inject(b"data", "my-secret", "ns-a", "key")
            .expect("inject should succeed");

        assert!(mock
            .secret_exists("my-secret", "ns-a")
            .expect("should succeed"));
        assert!(!mock
            .secret_exists("my-secret", "ns-b")
            .expect("should succeed"));
    }
}
