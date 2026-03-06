//! Azure Key Vault KMS provider.
//!
//! Implements [`KmsProvider`] using the Azure Key Vault REST API (api-version
//! 7.4) for envelope encryption of data encryption keys (DEKs).
//!
//! Authentication uses a pre-obtained Bearer token (e.g. from
//! `az account get-access-token` or workload identity federation).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::GenesisError;

use super::KmsProvider;

/// Azure Key Vault envelope encryption provider.
///
/// Wraps / unwraps DEKs using an RSA key stored in Azure Key Vault via the
/// REST `encrypt` and `decrypt` endpoints with `RSA-OAEP-256`.
#[derive(Debug)]
pub struct AzureKeyVaultProvider {
    /// Vault base URL, e.g. `https://myvault.vault.azure.net`.
    vault_url: String,
    /// Name of the key in Key Vault.
    key_name: String,
    /// Optional key version.  When `None`, the API uses the latest version.
    key_version: Option<String>,
    /// OAuth2 Bearer token for Key Vault access.
    access_token: String,
}

/// JSON request body for the Key Vault encrypt / decrypt operations.
#[derive(Serialize)]
struct KeyOperationRequest {
    alg: &'static str,
    value: String,
}

/// JSON response from Key Vault encrypt / decrypt operations.
#[derive(Deserialize)]
struct KeyOperationResponse {
    value: Option<String>,
}

/// JSON error response from Key Vault.
#[derive(Deserialize)]
struct KeyVaultErrorResponse {
    error: Option<KeyVaultErrorBody>,
}

/// Inner error body returned by Key Vault.
#[derive(Deserialize)]
struct KeyVaultErrorBody {
    message: Option<String>,
}

impl AzureKeyVaultProvider {
    /// Create a new Azure Key Vault provider with explicit credentials.
    pub fn new(
        vault_url: String,
        key_name: String,
        key_version: Option<String>,
        access_token: String,
    ) -> Self {
        // Strip trailing slash from vault_url for consistent URL building.
        let vault_url = vault_url.trim_end_matches('/').to_string();

        Self {
            vault_url,
            key_name,
            key_version,
            access_token,
        }
    }

    /// Create a provider from environment variables.
    ///
    /// Required variables:
    /// - `AZURE_KEY_VAULT_URL` -- vault base URL
    /// - `AZURE_KEY_NAME` -- key name
    /// - `AZURE_ACCESS_TOKEN` -- OAuth2 Bearer token
    ///
    /// Optional:
    /// - `AZURE_KEY_VERSION` -- specific key version (defaults to latest)
    pub fn from_env() -> Result<Self, GenesisError> {
        let vault_url = std::env::var("AZURE_KEY_VAULT_URL")
            .map_err(|_| GenesisError::KmsCallFailed("AZURE_KEY_VAULT_URL not set".into()))?;
        let key_name = std::env::var("AZURE_KEY_NAME")
            .map_err(|_| GenesisError::KmsCallFailed("AZURE_KEY_NAME not set".into()))?;
        let key_version = std::env::var("AZURE_KEY_VERSION").ok();
        let access_token = std::env::var("AZURE_ACCESS_TOKEN")
            .map_err(|_| GenesisError::KmsCallFailed("AZURE_ACCESS_TOKEN not set".into()))?;

        Ok(Self::new(vault_url, key_name, key_version, access_token))
    }

    /// Create a provider from JSON settings.
    ///
    /// Expected fields:
    /// - `vault_url` (optional -- falls back to `AZURE_KEY_VAULT_URL` env var)
    /// - `key_name` (optional -- falls back to `AZURE_KEY_NAME` env var)
    /// - `key_version` (optional -- falls back to `AZURE_KEY_VERSION` env var)
    /// - `access_token` (optional -- falls back to `AZURE_ACCESS_TOKEN` env var)
    ///
    /// If neither settings nor env vars provide a required value, returns an error.
    pub fn from_config(settings: &serde_json::Value) -> Result<Self, GenesisError> {
        let vault_url = settings
            .get("vault_url")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| std::env::var("AZURE_KEY_VAULT_URL").ok())
            .ok_or_else(|| GenesisError::KmsCallFailed("vault_url not configured".into()))?;

        let key_name = settings
            .get("key_name")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| std::env::var("AZURE_KEY_NAME").ok())
            .ok_or_else(|| GenesisError::KmsCallFailed("key_name not configured".into()))?;

        let key_version = settings
            .get("key_version")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| std::env::var("AZURE_KEY_VERSION").ok());

        let access_token = settings
            .get("access_token")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| std::env::var("AZURE_ACCESS_TOKEN").ok())
            .ok_or_else(|| GenesisError::KmsCallFailed("access_token not configured".into()))?;

        Ok(Self::new(vault_url, key_name, key_version, access_token))
    }

    /// Build the URL for the encrypt or decrypt operation.
    fn operation_url(&self, operation: &str) -> String {
        let version_segment = self.key_version.as_deref().unwrap_or("");

        if version_segment.is_empty() {
            format!(
                "{}/keys/{}/{}?api-version=7.4",
                self.vault_url, self.key_name, operation
            )
        } else {
            format!(
                "{}/keys/{}/{}/{}?api-version=7.4",
                self.vault_url, self.key_name, version_segment, operation
            )
        }
    }

    /// Execute an encrypt or decrypt operation against Key Vault.
    fn key_operation(&self, operation: &str, data: &[u8]) -> Result<Vec<u8>, GenesisError> {
        let url = self.operation_url(operation);
        let encoded_value = URL_SAFE_NO_PAD.encode(data);

        let request_body = KeyOperationRequest {
            alg: "RSA-OAEP-256",
            value: encoded_value,
        };

        let response = ureq::post(&url)
            .set("Authorization", &format!("Bearer {}", self.access_token))
            .set("Content-Type", "application/json")
            .send_json(serde_json::to_value(&request_body).map_err(|e| {
                GenesisError::KmsCallFailed(format!("request serialization failed: {e}"))
            })?)
            .map_err(|e| {
                GenesisError::KmsCallFailed(format!(
                    "Azure Key Vault {operation} request failed: {e}"
                ))
            })?;

        let response_body: serde_json::Value = response.into_json().map_err(|e| {
            GenesisError::KmsCallFailed(format!("failed to read response body: {e}"))
        })?;

        // Check for error response.
        if let Ok(err_resp) = serde_json::from_value::<KeyVaultErrorResponse>(response_body.clone())
        {
            if let Some(error) = err_resp.error {
                let msg = error
                    .message
                    .unwrap_or_else(|| "unknown Azure Key Vault error".into());
                return Err(GenesisError::KmsCallFailed(msg));
            }
        }

        // Extract the value field.
        let op_resp: KeyOperationResponse =
            serde_json::from_value(response_body).map_err(|_| GenesisError::KmsResponseInvalid)?;

        let result_b64 = op_resp.value.ok_or(GenesisError::KmsResponseInvalid)?;

        URL_SAFE_NO_PAD
            .decode(&result_b64)
            .map_err(|e| GenesisError::KmsCallFailed(format!("base64url decode failed: {e}")))
    }
}

impl KmsProvider for AzureKeyVaultProvider {
    fn provider_name(&self) -> &str {
        "azure-keyvault"
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, GenesisError> {
        self.key_operation("encrypt", plaintext)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, GenesisError> {
        self.key_operation("decrypt", ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_basic() {
        let provider = AzureKeyVaultProvider::new(
            "https://myvault.vault.azure.net".into(),
            "my-key".into(),
            Some("abc123".into()),
            "eyJ0eXAiOi...".into(),
        );
        assert_eq!(provider.vault_url, "https://myvault.vault.azure.net");
        assert_eq!(provider.key_name, "my-key");
        assert_eq!(provider.key_version.as_deref(), Some("abc123"));
        assert_eq!(provider.access_token, "eyJ0eXAiOi...");
    }

    #[test]
    fn construction_trailing_slash_stripped() {
        let provider = AzureKeyVaultProvider::new(
            "https://myvault.vault.azure.net/".into(),
            "my-key".into(),
            None,
            "token".into(),
        );
        assert_eq!(provider.vault_url, "https://myvault.vault.azure.net");
    }

    #[test]
    fn construction_no_version() {
        let provider = AzureKeyVaultProvider::new(
            "https://myvault.vault.azure.net".into(),
            "my-key".into(),
            None,
            "token".into(),
        );
        assert!(provider.key_version.is_none());
    }

    #[test]
    fn provider_name_returns_azure_keyvault() {
        let provider = AzureKeyVaultProvider::new(
            "https://v.vault.azure.net".into(),
            "k".into(),
            None,
            "t".into(),
        );
        assert_eq!(provider.provider_name(), "azure-keyvault");
    }

    #[test]
    fn operation_url_with_version() {
        let provider = AzureKeyVaultProvider::new(
            "https://myvault.vault.azure.net".into(),
            "my-key".into(),
            Some("v1".into()),
            "token".into(),
        );
        let url = provider.operation_url("encrypt");
        assert_eq!(
            url,
            "https://myvault.vault.azure.net/keys/my-key/v1/encrypt?api-version=7.4"
        );
    }

    #[test]
    fn operation_url_without_version() {
        let provider = AzureKeyVaultProvider::new(
            "https://myvault.vault.azure.net".into(),
            "my-key".into(),
            None,
            "token".into(),
        );
        let url = provider.operation_url("decrypt");
        assert_eq!(
            url,
            "https://myvault.vault.azure.net/keys/my-key/decrypt?api-version=7.4"
        );
    }

    #[test]
    fn encrypt_fails_with_unreachable_host() {
        let provider = AzureKeyVaultProvider::new(
            "https://nonexistent-vault-12345.vault.azure.net".into(),
            "my-key".into(),
            Some("v1".into()),
            "fake-token".into(),
        );
        let result = provider.encrypt(b"test data");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, GenesisError::KmsCallFailed(_)),
            "expected KmsCallFailed, got: {err:?}"
        );
    }

    #[test]
    fn decrypt_fails_with_unreachable_host() {
        let provider = AzureKeyVaultProvider::new(
            "https://nonexistent-vault-12345.vault.azure.net".into(),
            "my-key".into(),
            None,
            "fake-token".into(),
        );
        let result = provider.decrypt(b"ciphertext");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, GenesisError::KmsCallFailed(_)),
            "expected KmsCallFailed, got: {err:?}"
        );
    }

    /// All `from_env` tests are consolidated into a single test function
    /// because `std::env::set_var` / `remove_var` mutate process-global
    /// state and would race when the test harness runs in parallel.
    #[test]
    fn from_env_scenarios() {
        // Helper to clear all Azure env vars.
        fn clear_env() {
            std::env::remove_var("AZURE_KEY_VAULT_URL");
            std::env::remove_var("AZURE_KEY_NAME");
            std::env::remove_var("AZURE_ACCESS_TOKEN");
            std::env::remove_var("AZURE_KEY_VERSION");
        }

        // --- missing AZURE_KEY_VAULT_URL ---
        clear_env();
        let result = AzureKeyVaultProvider::from_env();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("AZURE_KEY_VAULT_URL"),
            "error should mention AZURE_KEY_VAULT_URL: {err}"
        );

        // --- missing AZURE_KEY_NAME ---
        clear_env();
        std::env::set_var("AZURE_KEY_VAULT_URL", "https://test.vault.azure.net");
        let result = AzureKeyVaultProvider::from_env();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("AZURE_KEY_NAME"),
            "error should mention AZURE_KEY_NAME: {err}"
        );

        // --- missing AZURE_ACCESS_TOKEN ---
        clear_env();
        std::env::set_var("AZURE_KEY_VAULT_URL", "https://test.vault.azure.net");
        std::env::set_var("AZURE_KEY_NAME", "test-key");
        let result = AzureKeyVaultProvider::from_env();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("AZURE_ACCESS_TOKEN"),
            "error should mention AZURE_ACCESS_TOKEN: {err}"
        );

        // --- success without version ---
        clear_env();
        std::env::set_var("AZURE_KEY_VAULT_URL", "https://test.vault.azure.net");
        std::env::set_var("AZURE_KEY_NAME", "test-key");
        std::env::set_var("AZURE_ACCESS_TOKEN", "token123");
        let provider = AzureKeyVaultProvider::from_env().expect("from_env should succeed");
        assert_eq!(provider.vault_url, "https://test.vault.azure.net");
        assert_eq!(provider.key_name, "test-key");
        assert!(provider.key_version.is_none());
        assert_eq!(provider.access_token, "token123");

        // --- success with version ---
        clear_env();
        std::env::set_var("AZURE_KEY_VAULT_URL", "https://test.vault.azure.net");
        std::env::set_var("AZURE_KEY_NAME", "test-key");
        std::env::set_var("AZURE_ACCESS_TOKEN", "token123");
        std::env::set_var("AZURE_KEY_VERSION", "v2");
        let provider = AzureKeyVaultProvider::from_env().expect("from_env should succeed");
        assert_eq!(provider.key_version.as_deref(), Some("v2"));

        // Final cleanup.
        clear_env();
    }

    // ── from_config tests ────────────────────────────────────────────

    #[test]
    fn from_config_with_all_fields() {
        let settings = serde_json::json!({
            "vault_url": "https://myvault.vault.azure.net",
            "key_name": "my-key",
            "key_version": "v1",
            "access_token": "config-token"
        });
        let p = AzureKeyVaultProvider::from_config(&settings).expect("should succeed");
        assert_eq!(p.vault_url, "https://myvault.vault.azure.net");
        assert_eq!(p.key_name, "my-key");
        assert_eq!(p.key_version.as_deref(), Some("v1"));
        assert_eq!(p.access_token, "config-token");
    }

    #[test]
    fn from_config_without_version() {
        let settings = serde_json::json!({
            "vault_url": "https://myvault.vault.azure.net",
            "key_name": "my-key",
            "access_token": "token"
        });
        std::env::remove_var("AZURE_KEY_VERSION");
        let p = AzureKeyVaultProvider::from_config(&settings).expect("should succeed");
        assert!(p.key_version.is_none());
    }

    #[test]
    fn from_config_missing_vault_url_fails() {
        std::env::remove_var("AZURE_KEY_VAULT_URL");
        let settings = serde_json::json!({
            "key_name": "my-key",
            "access_token": "token"
        });
        let result = AzureKeyVaultProvider::from_config(&settings);
        assert!(result.is_err());
    }

    #[test]
    fn from_config_missing_access_token_fails() {
        std::env::remove_var("AZURE_ACCESS_TOKEN");
        let settings = serde_json::json!({
            "vault_url": "https://myvault.vault.azure.net",
            "key_name": "my-key"
        });
        let result = AzureKeyVaultProvider::from_config(&settings);
        assert!(result.is_err());
    }

    #[test]
    fn base64url_encoding_used() {
        // Verify we are using URL_SAFE_NO_PAD (no + / = characters).
        let data: Vec<u8> = (0..=255).collect();
        let encoded = URL_SAFE_NO_PAD.encode(&data);
        assert!(!encoded.contains('+'), "should not contain '+'");
        assert!(!encoded.contains('/'), "should not contain '/'");
        assert!(!encoded.contains('='), "should not contain '='");
    }
}
