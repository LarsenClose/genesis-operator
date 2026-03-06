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

// ── SecretMetadata ───────────────────────────────────────────────────

/// Optional metadata to attach to injected Kubernetes Secrets.
///
/// When provided, the injector adds standard labels and annotations for
/// ownership tracking and operational visibility.
#[derive(Debug, Clone, Default)]
pub struct SecretMetadata {
    /// KMS provider type (e.g. `"aws-kms"`, `"oci-vault"`).
    pub provider_type: Option<String>,
    /// Age public key (`age1...`), used to derive a fingerprint annotation.
    pub public_key: Option<String>,
}

impl SecretMetadata {
    /// Standard Kubernetes labels for genesis-managed secrets.
    pub fn labels(&self) -> HashMap<String, String> {
        let mut labels = HashMap::new();
        labels.insert(
            "app.kubernetes.io/managed-by".to_string(),
            "genesis-operator".to_string(),
        );
        labels.insert(
            "app.kubernetes.io/part-of".to_string(),
            "genesis".to_string(),
        );
        if let Some(ref provider) = self.provider_type {
            labels.insert("genesis.io/provider".to_string(), provider.clone());
        }
        labels
    }

    /// Annotations for genesis-managed secrets.
    pub fn annotations(&self) -> HashMap<String, String> {
        let mut annotations = HashMap::new();
        if let Some(ref pk) = self.public_key {
            let fingerprint: String = pk.chars().take(12).collect();
            annotations.insert("genesis.io/public-key-fingerprint".to_string(), fingerprint);
        }
        annotations
    }
}

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
    /// - `metadata`         -- optional labels/annotations to attach
    ///
    /// On conflict (HTTP 409), the implementation should retry with a PUT
    /// (update) instead of POST (create).
    fn inject(
        &self,
        key_bytes: &[u8],
        secret_name: &str,
        secret_namespace: &str,
        secret_key: &str,
        metadata: Option<&SecretMetadata>,
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
    metadata_log: Mutex<HashMap<String, SecretMetadata>>,
}

impl MockSecretInjector {
    /// Create a new empty mock injector.
    pub fn new() -> Self {
        Self {
            secrets: Mutex::new(HashMap::new()),
            metadata_log: Mutex::new(HashMap::new()),
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

    /// Return a snapshot of all logged metadata for test assertions.
    /// Key format: `"{namespace}/{name}"`.
    pub fn metadata_snapshot(&self) -> HashMap<String, SecretMetadata> {
        self.metadata_log
            .lock()
            .expect("mock lock poisoned")
            .clone()
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
        metadata: Option<&SecretMetadata>,
    ) -> Result<(), GenesisError> {
        let key = Self::compound_key(secret_namespace, secret_name, secret_key);
        self.secrets
            .lock()
            .expect("mock lock poisoned")
            .insert(key, key_bytes.to_vec());
        if let Some(meta) = metadata {
            let meta_key = format!("{secret_namespace}/{secret_name}");
            self.metadata_log
                .lock()
                .expect("mock lock poisoned")
                .insert(meta_key, meta.clone());
        }
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
/// (kubeconfig) configurations. When a CA certificate is provided,
/// it is used for TLS verification against the API server.
pub struct UreqSecretInjector {
    /// Kubernetes API server base URL, e.g. `https://kubernetes.default.svc`.
    api_server: String,
    /// Bearer token for authentication.
    token: String,
    /// Shared ureq agent with TLS configuration.
    agent: ureq::Agent,
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

        let agent = Self::build_agent(&ca_cert)?;

        Ok(Self {
            api_server: "https://kubernetes.default.svc".to_string(),
            token,
            agent,
        })
    }

    /// Create an injector with explicit credentials (for out-of-cluster or
    /// testing).
    pub fn new(api_server: String, token: String, ca_cert: Vec<u8>) -> Self {
        let agent = Self::build_agent(&ca_cert).unwrap_or_else(|_| ureq::Agent::new());
        Self {
            api_server,
            token,
            agent,
        }
    }

    /// Build a ureq agent configured with the provided CA certificate.
    ///
    /// Uses `AgentBuilder::tls_config()` to inject a custom rustls
    /// `ClientConfig` that trusts the cluster's CA. The agent is reused
    /// across requests for connection pooling.
    fn build_agent(ca_cert_pem: &[u8]) -> Result<ureq::Agent, GenesisError> {
        if ca_cert_pem.is_empty() {
            return Ok(ureq::AgentBuilder::new().build());
        }

        let tls_config = Self::build_tls_config(ca_cert_pem)?;
        Ok(ureq::AgentBuilder::new()
            .tls_config(std::sync::Arc::new(tls_config))
            .build())
    }

    /// Build a rustls ClientConfig with the provided PEM CA certificate.
    fn build_tls_config(ca_cert_pem: &[u8]) -> Result<rustls::ClientConfig, GenesisError> {
        let mut root_store = rustls::RootCertStore::empty();

        let mut reader = std::io::BufReader::new(ca_cert_pem);
        let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
            .filter_map(|r| r.ok())
            .collect();

        if certs.is_empty() {
            return Err(GenesisError::K8sAuthFailed(
                "no valid PEM certificates found in CA bundle".to_string(),
            ));
        }

        for cert in certs {
            root_store
                .add(cert)
                .map_err(|e| GenesisError::K8sAuthFailed(format!("failed to add CA cert: {e}")))?;
        }

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(config)
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
        metadata: Option<&SecretMetadata>,
    ) -> serde_json::Value {
        let encoded = base64::engine::general_purpose::STANDARD.encode(key_bytes);
        let mut meta = serde_json::json!({
            "name": secret_name,
            "namespace": secret_namespace
        });

        if let Some(m) = metadata {
            let labels = m.labels();
            if !labels.is_empty() {
                meta["labels"] = serde_json::to_value(&labels).unwrap_or_default();
            }
            let annotations = m.annotations();
            if !annotations.is_empty() {
                meta["annotations"] = serde_json::to_value(&annotations).unwrap_or_default();
            }
        }

        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": meta,
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
        metadata: Option<&SecretMetadata>,
    ) -> Result<(), GenesisError> {
        let body = self.secret_body(
            key_bytes,
            secret_name,
            secret_namespace,
            secret_key,
            metadata,
        );
        let url = self.secrets_collection_url(secret_namespace);

        // Attempt POST (create).
        let response = self
            .agent
            .post(&url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("Content-Type", "application/json")
            .send_string(&body.to_string());

        match response {
            Ok(_) => Ok(()),
            Err(ureq::Error::Status(409, _)) => {
                // Conflict -- secret already exists; update with PUT.
                let put_url = self.secret_url(secret_namespace, secret_name);
                self.agent
                    .put(&put_url)
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
        let response = self
            .agent
            .get(&url)
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

        mock.inject(b"super-secret-key", "my-secret", "default", "tls.key", None)
            .expect("inject should succeed");

        assert!(mock.was_injected("my-secret"));
        assert!(mock
            .secret_exists("my-secret", "default")
            .expect("should succeed"));
    }

    #[test]
    fn mock_inject_multiple_keys() {
        let mock = MockSecretInjector::new();

        mock.inject(b"key1", "secret-a", "ns1", "data", None)
            .expect("inject should succeed");
        mock.inject(b"key2", "secret-b", "ns2", "data", None)
            .expect("inject should succeed");

        assert!(mock.was_injected("secret-a"));
        assert!(mock.was_injected("secret-b"));
        assert!(!mock.was_injected("secret-c"));
    }

    #[test]
    fn mock_overwrite_existing_secret() {
        let mock = MockSecretInjector::new();

        mock.inject(b"old-value", "my-secret", "default", "key", None)
            .expect("inject should succeed");
        mock.inject(b"new-value", "my-secret", "default", "key", None)
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

        mock.inject(b"data", "my-secret", "ns-a", "key", None)
            .expect("inject should succeed");

        assert!(mock
            .secret_exists("my-secret", "ns-a")
            .expect("should succeed"));
        assert!(!mock
            .secret_exists("my-secret", "ns-b")
            .expect("should succeed"));
    }

    #[test]
    fn mock_inject_with_metadata() {
        let mock = MockSecretInjector::new();
        let meta = SecretMetadata {
            provider_type: Some("aws-kms".to_string()),
            public_key: Some("age1abcdefghij".to_string()),
        };

        mock.inject(b"secret", "my-secret", "default", "key", Some(&meta))
            .expect("inject should succeed");

        let meta_snap = mock.metadata_snapshot();
        let stored = meta_snap
            .get("default/my-secret")
            .expect("metadata should exist");
        assert_eq!(stored.provider_type.as_deref(), Some("aws-kms"));
        assert_eq!(stored.public_key.as_deref(), Some("age1abcdefghij"));
    }

    #[test]
    fn secret_metadata_labels() {
        let meta = SecretMetadata {
            provider_type: Some("oci-vault".to_string()),
            public_key: None,
        };
        let labels = meta.labels();
        assert_eq!(
            labels.get("app.kubernetes.io/managed-by").unwrap(),
            "genesis-operator"
        );
        assert_eq!(labels.get("app.kubernetes.io/part-of").unwrap(), "genesis");
        assert_eq!(labels.get("genesis.io/provider").unwrap(), "oci-vault");
    }

    #[test]
    fn secret_metadata_annotations() {
        let meta = SecretMetadata {
            provider_type: None,
            public_key: Some("age1abcdefghijklmnop".to_string()),
        };
        let annotations = meta.annotations();
        assert_eq!(
            annotations
                .get("genesis.io/public-key-fingerprint")
                .unwrap(),
            "age1abcdefgh"
        );
    }

    #[test]
    fn secret_metadata_default_has_no_provider_label() {
        let meta = SecretMetadata::default();
        let labels = meta.labels();
        assert!(!labels.contains_key("genesis.io/provider"));
        assert_eq!(
            labels.get("app.kubernetes.io/managed-by").unwrap(),
            "genesis-operator"
        );
    }
}
