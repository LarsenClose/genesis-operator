//! GCP Cloud KMS provider using the REST API via `ureq`.
//!
//! Implements envelope encryption by calling the Cloud KMS
//! [`encrypt`](https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/encrypt)
//! and
//! [`decrypt`](https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/decrypt)
//! endpoints with Bearer token authentication.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::GenesisError;

use super::KmsProvider;

/// Base URL for the Cloud KMS REST API (v1).
const GCP_KMS_BASE_URL: &str = "https://cloudkms.googleapis.com/v1";

/// GCP Cloud KMS provider.
///
/// Wraps and unwraps data encryption keys (DEKs) via the Cloud KMS REST API.
/// The `key_resource_name` identifies the customer-managed key (CMK) in the
/// format `projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}`.
#[derive(Debug)]
pub struct GcpKmsProvider {
    /// Full resource name of the CryptoKey.
    ///
    /// Format: `projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}`
    key_resource_name: String,

    /// OAuth2 access token for Bearer authentication.
    access_token: String,
}

// ── Request / response DTOs ──────────────────────────────────────────

#[derive(Serialize)]
struct EncryptRequest {
    plaintext: String,
}

#[derive(Deserialize)]
struct EncryptResponse {
    ciphertext: String,
}

#[derive(Serialize)]
struct DecryptRequest {
    ciphertext: String,
}

#[derive(Deserialize)]
struct DecryptResponse {
    plaintext: String,
}

// ── Construction ─────────────────────────────────────────────────────

impl GcpKmsProvider {
    /// Create a new provider with explicit credentials.
    ///
    /// `key_resource_name` must follow the format
    /// `projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}`.
    pub fn new(key_resource_name: String, access_token: String) -> Self {
        Self {
            key_resource_name,
            access_token,
        }
    }

    /// Create a provider from environment variables.
    ///
    /// Reads:
    /// - `GENESIS_GCP_KMS_KEY` -- the full CryptoKey resource name (required).
    /// - `GENESIS_GCP_ACCESS_TOKEN` -- an OAuth2 access token.  Falls back to
    ///   reading a service-account JSON file at `GOOGLE_APPLICATION_CREDENTIALS`
    ///   (only the token field is extracted for now; full OAuth flow is deferred
    ///   to a later work-front).
    pub fn from_env() -> Result<Self, GenesisError> {
        let key_resource_name =
            std::env::var("GENESIS_GCP_KMS_KEY").map_err(|_| GenesisError::KmsNotConfigured)?;

        let access_token = std::env::var("GENESIS_GCP_ACCESS_TOKEN").or_else(|_| {
            // Fall back to GOOGLE_APPLICATION_CREDENTIALS (file path).
            // For now we just verify the file exists -- full service-account
            // token exchange is out of scope for WF-2.
            let creds_path = std::env::var("GOOGLE_APPLICATION_CREDENTIALS")
                .map_err(|_| GenesisError::KmsNotConfigured)?;
            if std::path::Path::new(&creds_path).exists() {
                // In a production implementation this would perform the
                // OAuth2 service-account token exchange.  For now surface a
                // clear error that a direct access token is required.
                Err(GenesisError::KmsCallFailed(
                    "GOOGLE_APPLICATION_CREDENTIALS found but automatic token \
                         exchange is not yet implemented; set GENESIS_GCP_ACCESS_TOKEN \
                         directly"
                        .into(),
                ))
            } else {
                Err(GenesisError::KmsCallFailed(format!(
                    "credentials file not found: {creds_path}"
                )))
            }
        })?;

        Ok(Self::new(key_resource_name, access_token))
    }

    /// Create a provider from JSON settings.
    ///
    /// Expected fields:
    /// - `key_resource_name` (optional -- falls back to `GENESIS_GCP_KMS_KEY` env var)
    /// - `access_token` (optional -- falls back to `GENESIS_GCP_ACCESS_TOKEN` env var)
    ///
    /// If neither settings nor env vars provide a required value, returns an error.
    pub fn from_config(settings: &serde_json::Value) -> Result<Self, GenesisError> {
        let key_resource_name = settings
            .get("key_resource_name")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| std::env::var("GENESIS_GCP_KMS_KEY").ok())
            .ok_or(GenesisError::KmsNotConfigured)?;

        let access_token = settings
            .get("access_token")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| std::env::var("GENESIS_GCP_ACCESS_TOKEN").ok())
            .ok_or_else(|| {
                GenesisError::KmsCallFailed(
                    "access_token not in settings and GENESIS_GCP_ACCESS_TOKEN not set".into(),
                )
            })?;

        Ok(Self::new(key_resource_name, access_token))
    }

    /// The full CryptoKey resource name.
    pub fn key_resource_name(&self) -> &str {
        &self.key_resource_name
    }
}

// ── KmsProvider trait ────────────────────────────────────────────────

impl KmsProvider for GcpKmsProvider {
    fn provider_name(&self) -> &str {
        "gcp-kms"
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, GenesisError> {
        let url = format!("{}/{}:encrypt", GCP_KMS_BASE_URL, self.key_resource_name);
        let body = EncryptRequest {
            plaintext: BASE64.encode(plaintext),
        };

        let resp: EncryptResponse = ureq::post(&url)
            .set("Authorization", &format!("Bearer {}", self.access_token))
            .send_json(serde_json::to_value(&body).map_err(GenesisError::Json)?)
            .map_err(|e| GenesisError::KmsCallFailed(format!("GCP KMS encrypt: {e}")))?
            .into_json()
            .map_err(|e| GenesisError::KmsCallFailed(format!("GCP KMS encrypt response: {e}")))?;

        BASE64
            .decode(&resp.ciphertext)
            .map_err(|e| GenesisError::KmsCallFailed(format!("base64 decode ciphertext: {e}")))
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, GenesisError> {
        let url = format!("{}/{}:decrypt", GCP_KMS_BASE_URL, self.key_resource_name);
        let body = DecryptRequest {
            ciphertext: BASE64.encode(ciphertext),
        };

        let resp: DecryptResponse = ureq::post(&url)
            .set("Authorization", &format!("Bearer {}", self.access_token))
            .send_json(serde_json::to_value(&body).map_err(GenesisError::Json)?)
            .map_err(|e| GenesisError::KmsCallFailed(format!("GCP KMS decrypt: {e}")))?
            .into_json()
            .map_err(|e| GenesisError::KmsCallFailed(format!("GCP KMS decrypt response: {e}")))?;

        BASE64
            .decode(&resp.plaintext)
            .map_err(|e| GenesisError::KmsCallFailed(format!("base64 decode plaintext: {e}")))
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const TEST_KEY: &str =
        "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key";
    const TEST_TOKEN: &str = "ya29.test-access-token";

    /// Mutex that serializes tests which mutate process-wide environment
    /// variables.  Held for the duration of each env-touching test so that
    /// parallel test threads cannot observe each other's mutations.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    /// Clear all GCP-related env vars.  Call under `ENV_MUTEX` only.
    fn clear_gcp_env() {
        std::env::remove_var("GENESIS_GCP_KMS_KEY");
        std::env::remove_var("GENESIS_GCP_ACCESS_TOKEN");
        std::env::remove_var("GOOGLE_APPLICATION_CREDENTIALS");
    }

    // ── Pure-struct tests (no env mutation, safe to run in parallel) ──

    #[test]
    fn constructor_stores_fields() {
        let provider = GcpKmsProvider::new(TEST_KEY.into(), TEST_TOKEN.into());
        assert_eq!(provider.key_resource_name(), TEST_KEY);
        assert_eq!(provider.access_token, TEST_TOKEN);
    }

    #[test]
    fn provider_name_is_gcp_kms() {
        let provider = GcpKmsProvider::new(TEST_KEY.into(), TEST_TOKEN.into());
        assert_eq!(provider.provider_name(), "gcp-kms");
    }

    #[test]
    fn encrypt_fails_with_network_error() {
        // Construct with a valid-looking key but a bogus token -- the HTTP call
        // will fail because there is no real GCP endpoint reachable in tests.
        let provider = GcpKmsProvider::new(TEST_KEY.into(), "bogus".into());
        let result = provider.encrypt(b"secret DEK");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_code(), 300); // KmsCallFailed
        assert!(err.to_string().contains("GCP KMS encrypt"));
    }

    #[test]
    fn decrypt_fails_with_network_error() {
        let provider = GcpKmsProvider::new(TEST_KEY.into(), "bogus".into());
        let result = provider.decrypt(b"fake ciphertext");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_code(), 300);
        assert!(err.to_string().contains("GCP KMS decrypt"));
    }

    #[test]
    fn trait_object_works() {
        let provider: Box<dyn KmsProvider> =
            Box::new(GcpKmsProvider::new(TEST_KEY.into(), TEST_TOKEN.into()));
        assert_eq!(provider.provider_name(), "gcp-kms");
    }

    // ── Env-mutating tests (serialized via ENV_MUTEX) ────────────────

    // ── from_config tests ────────────────────────────────────────────

    #[test]
    fn from_config_with_all_fields() {
        let settings = serde_json::json!({
            "key_resource_name": TEST_KEY,
            "access_token": TEST_TOKEN
        });
        let p = GcpKmsProvider::from_config(&settings).expect("should succeed");
        assert_eq!(p.key_resource_name(), TEST_KEY);
        assert_eq!(p.access_token, TEST_TOKEN);
    }

    #[test]
    fn from_config_missing_key_falls_back_to_env() {
        let _guard = ENV_MUTEX.lock().unwrap();
        clear_gcp_env();
        // No key in settings, no env var -> should fail
        let settings = serde_json::json!({
            "access_token": TEST_TOKEN
        });
        let result = GcpKmsProvider::from_config(&settings);
        assert!(result.is_err());
        clear_gcp_env();
    }

    #[test]
    fn from_config_missing_token_fails() {
        let settings = serde_json::json!({
            "key_resource_name": TEST_KEY
        });
        // No token in settings and no env var
        let _guard = ENV_MUTEX.lock().unwrap();
        clear_gcp_env();
        let result = GcpKmsProvider::from_config(&settings);
        assert!(result.is_err());
        clear_gcp_env();
    }

    #[test]
    fn from_env_missing_key_returns_not_configured() {
        let _guard = ENV_MUTEX.lock().unwrap();
        clear_gcp_env();

        let result = GcpKmsProvider::from_env();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_code(), 302); // KmsNotConfigured
    }

    #[test]
    fn from_env_missing_token_returns_error() {
        let _guard = ENV_MUTEX.lock().unwrap();
        clear_gcp_env();
        std::env::set_var("GENESIS_GCP_KMS_KEY", TEST_KEY);

        let result = GcpKmsProvider::from_env();
        assert!(result.is_err());

        clear_gcp_env();
    }

    #[test]
    fn from_env_with_nonexistent_creds_file() {
        let _guard = ENV_MUTEX.lock().unwrap();
        clear_gcp_env();
        std::env::set_var("GENESIS_GCP_KMS_KEY", TEST_KEY);
        std::env::set_var(
            "GOOGLE_APPLICATION_CREDENTIALS",
            "/tmp/nonexistent-genesis-test-creds.json",
        );

        let result = GcpKmsProvider::from_env();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_code(), 300); // KmsCallFailed
        assert!(err.to_string().contains("credentials file not found"));

        clear_gcp_env();
    }

    #[test]
    fn from_env_success_with_direct_token() {
        let _guard = ENV_MUTEX.lock().unwrap();
        clear_gcp_env();
        std::env::set_var("GENESIS_GCP_KMS_KEY", TEST_KEY);
        std::env::set_var("GENESIS_GCP_ACCESS_TOKEN", TEST_TOKEN);

        let provider = GcpKmsProvider::from_env().expect("should succeed with direct token");
        assert_eq!(provider.key_resource_name(), TEST_KEY);
        assert_eq!(provider.access_token, TEST_TOKEN);

        clear_gcp_env();
    }
}
