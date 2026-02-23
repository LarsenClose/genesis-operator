//! KMS provider configuration and factory.
//!
//! [`KmsConfig`] is a serializable description of which KMS backend to use
//! and how to connect to it.  The [`create_provider`] factory turns a config
//! into a boxed [`KmsProvider`] trait object.

use serde::{Deserialize, Serialize};

use crate::GenesisError;

use super::mock::MockKmsProvider;
use super::KmsProvider;

/// Serializable KMS configuration.
///
/// `provider_type` selects the backend (`"mock"`, and in the future `"aws"`,
/// `"gcp"`, `"azure"`).  `settings` carries provider-specific configuration
/// (region, key ARN, project ID, etc.) as an opaque JSON value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmsConfig {
    /// Backend selector: `"mock"`, `"aws"`, `"gcp"`, `"azure"`.
    pub provider_type: String,

    /// Provider-specific settings (key ARN, region, vault URL, etc.).
    #[serde(default)]
    pub settings: serde_json::Value,
}

/// Construct a [`KmsProvider`] from a [`KmsConfig`].
///
/// Supported provider types: `"mock"`, `"aws"`, `"gcp"`, `"azure"`.
pub fn create_provider(config: &KmsConfig) -> Result<Box<dyn KmsProvider>, GenesisError> {
    match config.provider_type.as_str() {
        "mock" => Ok(Box::new(MockKmsProvider::new())),
        "aws" => Ok(Box::new(super::aws::AwsKmsProvider::from_env()?)),
        "gcp" => Ok(Box::new(super::gcp::GcpKmsProvider::from_env()?)),
        "azure" => Ok(Box::new(super::azure::AzureKeyVaultProvider::from_env()?)),
        _ => Err(GenesisError::KmsNotConfigured),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_mock_provider() {
        let config = KmsConfig {
            provider_type: "mock".into(),
            settings: serde_json::Value::Null,
        };
        let provider = create_provider(&config).expect("mock provider should be created");
        assert_eq!(provider.provider_name(), "mock");

        // Verify it actually works.
        let ct = provider.encrypt(b"hello").expect("encrypt");
        let pt = provider.decrypt(&ct).expect("decrypt");
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn unknown_provider_fails() {
        let config = KmsConfig {
            provider_type: "doesnotexist".into(),
            settings: serde_json::Value::Null,
        };
        let result = create_provider(&config);
        assert!(result.is_err());
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = KmsConfig {
            provider_type: "aws".into(),
            settings: serde_json::json!({
                "region": "us-east-1",
                "key_arn": "arn:aws:kms:us-east-1:123456789012:key/example"
            }),
        };
        let json = serde_json::to_string(&config).expect("serialize");
        let parsed: KmsConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.provider_type, "aws");
        assert_eq!(parsed.settings["region"], "us-east-1");
    }
}
