//! AWS KMS provider using ureq + SigV4 signing.
//!
//! Implements the [`KmsProvider`] trait by calling the AWS KMS Encrypt and
//! Decrypt APIs via HTTPS.  Request authentication uses SigV4 signing from
//! the [`aws_sigv4`] crate.
//!
//! # Usage
//!
//! ```no_run
//! use genesis_core::kms::aws::AwsKmsProvider;
//! use genesis_core::kms::KmsProvider;
//!
//! let provider = AwsKmsProvider::new(
//!     "arn:aws:kms:us-east-1:123456789012:key/example-key-id".into(),
//!     "us-east-1".into(),
//!     "AKIAIOSFODNN7EXAMPLE".into(),
//!     "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
//!     None,
//! );
//!
//! let ciphertext = provider.encrypt(b"my secret DEK").unwrap();
//! let plaintext  = provider.decrypt(&ciphertext).unwrap();
//! assert_eq!(plaintext, b"my secret DEK");
//! ```
//!
//! # Environment constructor
//!
//! [`AwsKmsProvider::from_env`] reads credentials from the standard AWS
//! environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
//! `AWS_SESSION_TOKEN`, `AWS_DEFAULT_REGION`) plus the genesis-specific
//! `GENESIS_AWS_KMS_KEY_ARN`.

use std::env;
use std::time::SystemTime;

use aws_credential_types::Credentials;
use aws_sigv4::http_request::{sign, SignableBody, SignableRequest, SigningSettings};
use aws_sigv4::sign::v4;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::Value;

use super::KmsProvider;
use crate::GenesisError;

/// AWS KMS provider that calls the Encrypt / Decrypt APIs over HTTPS.
///
/// All requests are authenticated with SigV4 signing.  The provider is
/// `Send + Sync` and can be shared across threads.
pub struct AwsKmsProvider {
    /// Full ARN of the AWS KMS key (CMK).
    key_arn: String,
    /// AWS region (e.g. `us-east-1`).
    region: String,
    /// IAM access key ID.
    access_key_id: String,
    /// IAM secret access key.
    secret_access_key: String,
    /// Optional session token (for temporary credentials / STS).
    session_token: Option<String>,
}

impl AwsKmsProvider {
    /// Create a new AWS KMS provider with explicit credentials.
    pub fn new(
        key_arn: String,
        region: String,
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
    ) -> Self {
        Self {
            key_arn,
            region,
            access_key_id,
            secret_access_key,
            session_token,
        }
    }

    /// Create a new AWS KMS provider from environment variables.
    ///
    /// Required:
    /// - `AWS_ACCESS_KEY_ID`
    /// - `AWS_SECRET_ACCESS_KEY`
    /// - `AWS_DEFAULT_REGION`
    /// - `GENESIS_AWS_KMS_KEY_ARN`
    ///
    /// Optional:
    /// - `AWS_SESSION_TOKEN`
    pub fn from_env() -> Result<Self, GenesisError> {
        Self::from_env_vars(
            env::var("AWS_ACCESS_KEY_ID").ok(),
            env::var("AWS_SECRET_ACCESS_KEY").ok(),
            env::var("AWS_DEFAULT_REGION").ok(),
            env::var("GENESIS_AWS_KMS_KEY_ARN").ok(),
            env::var("AWS_SESSION_TOKEN").ok(),
        )
    }

    /// Create a new AWS KMS provider from JSON settings.
    ///
    /// Expected fields:
    /// - `key_arn` (required)
    /// - `region` (required)
    /// - `access_key_id` (required)
    /// - `secret_access_key` (required)
    /// - `session_token` (optional)
    ///
    /// Falls back to `from_env()` if credentials are not present in settings.
    pub fn from_config(settings: &serde_json::Value) -> Result<Self, GenesisError> {
        let key_arn = settings
            .get("key_arn")
            .and_then(|v| v.as_str())
            .map(String::from);
        let region = settings
            .get("region")
            .and_then(|v| v.as_str())
            .map(String::from);
        let access_key_id = settings
            .get("access_key_id")
            .and_then(|v| v.as_str())
            .map(String::from);
        let secret_access_key = settings
            .get("secret_access_key")
            .and_then(|v| v.as_str())
            .map(String::from);
        let session_token = settings
            .get("session_token")
            .and_then(|v| v.as_str())
            .map(String::from);

        // If credentials are present in settings, use them directly.
        if access_key_id.is_some() && secret_access_key.is_some() {
            return Self::from_env_vars(
                access_key_id,
                secret_access_key,
                region,
                key_arn,
                session_token,
            );
        }

        // Fall back to env vars, using key_arn/region from settings if available.
        Self::from_env_vars(
            env::var("AWS_ACCESS_KEY_ID").ok(),
            env::var("AWS_SECRET_ACCESS_KEY").ok(),
            region.or_else(|| env::var("AWS_DEFAULT_REGION").ok()),
            key_arn.or_else(|| env::var("GENESIS_AWS_KMS_KEY_ARN").ok()),
            env::var("AWS_SESSION_TOKEN").ok(),
        )
    }

    /// Internal constructor from explicit `Option` values, used by
    /// [`from_env`](Self::from_env) and testable without touching the
    /// process environment.
    fn from_env_vars(
        access_key_id: Option<String>,
        secret_access_key: Option<String>,
        region: Option<String>,
        key_arn: Option<String>,
        session_token: Option<String>,
    ) -> Result<Self, GenesisError> {
        let access_key_id = access_key_id.ok_or(GenesisError::KmsNotConfigured)?;
        let secret_access_key = secret_access_key.ok_or(GenesisError::KmsNotConfigured)?;
        let region = region.ok_or(GenesisError::KmsNotConfigured)?;
        let key_arn = key_arn.ok_or(GenesisError::KmsNotConfigured)?;

        Ok(Self::new(
            key_arn,
            region,
            access_key_id,
            secret_access_key,
            session_token,
        ))
    }

    /// Return the KMS endpoint URL for this region.
    fn endpoint(&self) -> String {
        format!("https://kms.{}.amazonaws.com/", self.region)
    }

    /// Perform a signed POST to the KMS API.
    ///
    /// `target` is the `X-Amz-Target` value (e.g. `TrentService.Encrypt`).
    /// `body` is the JSON request payload.
    ///
    /// Returns the parsed JSON response body.
    fn call(&self, target: &str, body: &str) -> Result<Value, GenesisError> {
        let endpoint = self.endpoint();
        let host = format!("kms.{}.amazonaws.com", self.region);

        // -- Build AWS credentials for SigV4 signing -----------------------
        let credentials = Credentials::new(
            &self.access_key_id,
            &self.secret_access_key,
            self.session_token.clone(),
            None, // no expiry
            "genesis-core",
        );
        let identity = credentials.into();

        // -- Construct the signing parameters ------------------------------
        let signing_settings = SigningSettings::default();
        let signing_params = v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.region)
            .name("kms")
            .time(SystemTime::now())
            .settings(signing_settings)
            .build()
            .map_err(|e| GenesisError::KmsCallFailed(format!("SigV4 params: {e}")))?;
        let signing_params = signing_params.into();

        // -- Headers that are part of the canonical request ----------------
        let headers: Vec<(&str, &str)> = vec![
            ("host", &host),
            ("content-type", "application/x-amz-json-1.1"),
            ("x-amz-target", target),
        ];

        // -- Sign the request ----------------------------------------------
        let signable = SignableRequest::new(
            "POST",
            &endpoint,
            headers.iter().copied(),
            SignableBody::Bytes(body.as_bytes()),
        )
        .map_err(|e| GenesisError::KmsCallFailed(format!("signable request: {e}")))?;

        let signing_output = sign(signable, &signing_params)
            .map_err(|e| GenesisError::KmsCallFailed(format!("SigV4 sign: {e}")))?;

        let (signing_headers, _signature) = signing_output.into_parts();

        // -- Build and send the ureq request --------------------------------
        let mut req = ureq::post(&endpoint)
            .set("host", &host)
            .set("content-type", "application/x-amz-json-1.1")
            .set("x-amz-target", target);

        // Apply signing headers (authorization, x-amz-date, x-amz-security-token, etc.)
        for header in signing_headers.headers() {
            let (name, value) = header;
            req = req.set(name, value);
        }

        let response = req
            .send_string(body)
            .map_err(|e| GenesisError::KmsCallFailed(format!("HTTP request failed: {e}")))?;

        let status = response.status();
        let response_body: Value = response
            .into_json()
            .map_err(|e| GenesisError::KmsCallFailed(format!("response parse: {e}")))?;

        if status != 200 {
            let msg = response_body
                .get("__type")
                .and_then(|v| v.as_str())
                .unwrap_or("UnknownError");
            let detail = response_body
                .get("message")
                .or_else(|| response_body.get("Message"))
                .and_then(|v| v.as_str())
                .unwrap_or("no detail");
            return Err(GenesisError::KmsCallFailed(format!(
                "AWS KMS {msg}: {detail}"
            )));
        }

        Ok(response_body)
    }
}

impl KmsProvider for AwsKmsProvider {
    fn provider_name(&self) -> &str {
        "aws-kms"
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, GenesisError> {
        let b64_plaintext = B64.encode(plaintext);
        let body = serde_json::json!({
            "KeyId": self.key_arn,
            "Plaintext": b64_plaintext,
        })
        .to_string();

        let resp = self.call("TrentService.Encrypt", &body)?;

        let ciphertext_b64 = resp
            .get("CiphertextBlob")
            .and_then(|v| v.as_str())
            .ok_or(GenesisError::KmsResponseInvalid)?;

        B64.decode(ciphertext_b64)
            .map_err(|e| GenesisError::KmsCallFailed(format!("base64 decode: {e}")))
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, GenesisError> {
        let b64_ciphertext = B64.encode(ciphertext);
        let body = serde_json::json!({
            "CiphertextBlob": b64_ciphertext,
        })
        .to_string();

        let resp = self.call("TrentService.Decrypt", &body)?;

        let plaintext_b64 = resp
            .get("Plaintext")
            .and_then(|v| v.as_str())
            .ok_or(GenesisError::KmsResponseInvalid)?;

        B64.decode(plaintext_b64)
            .map_err(|e| GenesisError::KmsCallFailed(format!("base64 decode: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Construction tests ───────────────────────────────────────────

    #[test]
    fn new_creates_provider_with_all_fields() {
        let p = AwsKmsProvider::new(
            "arn:aws:kms:us-east-1:111122223333:key/abcd".into(),
            "us-east-1".into(),
            "AKIAIOSFODNN7EXAMPLE".into(),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            Some("FwoGZXIvYXdzEBY".into()),
        );
        assert_eq!(p.key_arn, "arn:aws:kms:us-east-1:111122223333:key/abcd");
        assert_eq!(p.region, "us-east-1");
        assert_eq!(p.access_key_id, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(
            p.secret_access_key,
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
        assert_eq!(p.session_token.as_deref(), Some("FwoGZXIvYXdzEBY"));
    }

    #[test]
    fn new_without_session_token() {
        let p = AwsKmsProvider::new(
            "arn:aws:kms:eu-west-1:000000000000:key/0000".into(),
            "eu-west-1".into(),
            "AK".into(),
            "SK".into(),
            None,
        );
        assert!(p.session_token.is_none());
    }

    #[test]
    fn provider_name_returns_aws_kms() {
        let p = AwsKmsProvider::new(
            "arn".into(),
            "us-east-1".into(),
            "ak".into(),
            "sk".into(),
            None,
        );
        assert_eq!(p.provider_name(), "aws-kms");
    }

    #[test]
    fn endpoint_uses_region() {
        let p = AwsKmsProvider::new(
            "arn".into(),
            "ap-southeast-2".into(),
            "ak".into(),
            "sk".into(),
            None,
        );
        assert_eq!(p.endpoint(), "https://kms.ap-southeast-2.amazonaws.com/");
    }

    // ── from_env_vars tests (deterministic, no shared env state) ────

    type EnvVars = (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );

    /// Helper: all env vars present.
    fn all_vars() -> EnvVars {
        (
            Some("test-ak".into()),
            Some("test-sk".into()),
            Some("us-west-2".into()),
            Some("arn:aws:kms:us-west-2:123:key/k".into()),
            Some("tok123".into()),
        )
    }

    #[test]
    fn from_env_vars_succeeds_with_all_fields() {
        let (ak, sk, region, arn, token) = all_vars();
        let p = AwsKmsProvider::from_env_vars(ak, sk, region, arn, token).expect("should succeed");
        assert_eq!(p.access_key_id, "test-ak");
        assert_eq!(p.secret_access_key, "test-sk");
        assert_eq!(p.region, "us-west-2");
        assert_eq!(p.key_arn, "arn:aws:kms:us-west-2:123:key/k");
        assert_eq!(p.session_token.as_deref(), Some("tok123"));
    }

    #[test]
    fn from_env_vars_without_session_token() {
        let (ak, sk, region, arn, _) = all_vars();
        let p = AwsKmsProvider::from_env_vars(ak, sk, region, arn, None).expect("should succeed");
        assert!(p.session_token.is_none());
    }

    #[test]
    fn from_env_vars_missing_access_key_returns_error() {
        let (_, sk, region, arn, token) = all_vars();
        let result = AwsKmsProvider::from_env_vars(None, sk, region, arn, token);
        assert!(result.is_err());
    }

    #[test]
    fn from_env_vars_missing_secret_key_returns_error() {
        let (ak, _, region, arn, token) = all_vars();
        let result = AwsKmsProvider::from_env_vars(ak, None, region, arn, token);
        assert!(result.is_err());
    }

    #[test]
    fn from_env_vars_missing_region_returns_error() {
        let (ak, sk, _, arn, token) = all_vars();
        let result = AwsKmsProvider::from_env_vars(ak, sk, None, arn, token);
        assert!(result.is_err());
    }

    #[test]
    fn from_env_vars_missing_key_arn_returns_error() {
        let (ak, sk, region, _, token) = all_vars();
        let result = AwsKmsProvider::from_env_vars(ak, sk, region, None, token);
        assert!(result.is_err());
    }

    // ── Request body format tests ────────────────────────────────────

    #[test]
    fn encrypt_request_body_format() {
        let plaintext = b"hello world";
        let b64 = B64.encode(plaintext);
        let body = serde_json::json!({
            "KeyId": "arn:aws:kms:us-east-1:123:key/abc",
            "Plaintext": b64,
        });
        assert_eq!(body["KeyId"], "arn:aws:kms:us-east-1:123:key/abc");
        assert_eq!(body["Plaintext"], B64.encode(b"hello world"));
    }

    #[test]
    fn decrypt_request_body_format() {
        let ciphertext = b"\x00\x01\x02\x03";
        let b64 = B64.encode(ciphertext);
        let body = serde_json::json!({
            "CiphertextBlob": b64,
        });
        assert_eq!(body["CiphertextBlob"], B64.encode(b"\x00\x01\x02\x03"));
    }

    // ── SigV4 signing plumbing tests (no real AWS calls) ─────────────

    #[test]
    fn sigv4_signing_produces_authorization_header() {
        // Verify that our signing plumbing produces the expected SigV4 headers
        // without making a real AWS call.
        let credentials = Credentials::new(
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            None,
            None,
            "test",
        );
        let identity = credentials.into();

        let signing_settings = SigningSettings::default();
        let signing_params = v4::SigningParams::builder()
            .identity(&identity)
            .region("us-east-1")
            .name("kms")
            .time(SystemTime::UNIX_EPOCH) // deterministic time
            .settings(signing_settings)
            .build()
            .expect("signing params should build");
        let signing_params = signing_params.into();

        let body = r#"{"KeyId":"arn:test","Plaintext":"aGVsbG8="}"#;
        let headers = vec![
            ("host", "kms.us-east-1.amazonaws.com"),
            ("content-type", "application/x-amz-json-1.1"),
            ("x-amz-target", "TrentService.Encrypt"),
        ];

        let signable = SignableRequest::new(
            "POST",
            "https://kms.us-east-1.amazonaws.com/",
            headers.into_iter(),
            SignableBody::Bytes(body.as_bytes()),
        )
        .expect("signable request");

        let output = sign(signable, &signing_params).expect("sign should succeed");
        let (instructions, signature) = output.into_parts();

        // Verify the signature is a 64-char hex string (SHA-256 HMAC).
        assert_eq!(signature.len(), 64);
        assert!(signature.chars().all(|c| c.is_ascii_hexdigit()));

        // Verify that authorization and x-amz-date headers are present.
        let header_names: Vec<&str> = instructions.headers().map(|(name, _)| name).collect();
        assert!(
            header_names.contains(&"authorization"),
            "expected authorization header, got: {:?}",
            header_names
        );
        assert!(
            header_names.contains(&"x-amz-date"),
            "expected x-amz-date header, got: {:?}",
            header_names
        );

        // Verify the authorization header contains the expected prefix.
        for (name, value) in instructions.headers() {
            if name == "authorization" {
                assert!(
                    value.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"),
                    "unexpected authorization value: {value}"
                );
                assert!(
                    value.contains("SignedHeaders="),
                    "missing SignedHeaders in: {value}"
                );
                assert!(
                    value.contains("Signature="),
                    "missing Signature in: {value}"
                );
            }
        }
    }

    #[test]
    fn sigv4_signing_with_session_token() {
        let credentials =
            Credentials::new("AKID", "SECRET", Some("SESSION_TOKEN".into()), None, "test");
        let identity = credentials.into();

        let signing_settings = SigningSettings::default();
        let signing_params = v4::SigningParams::builder()
            .identity(&identity)
            .region("eu-west-1")
            .name("kms")
            .time(SystemTime::UNIX_EPOCH)
            .settings(signing_settings)
            .build()
            .expect("params");
        let signing_params = signing_params.into();

        let signable = SignableRequest::new(
            "POST",
            "https://kms.eu-west-1.amazonaws.com/",
            std::iter::empty(),
            SignableBody::Bytes(b"{}"),
        )
        .expect("signable");

        let output = sign(signable, &signing_params).expect("sign");
        let (instructions, _) = output.into_parts();

        let header_names: Vec<&str> = instructions.headers().map(|(name, _)| name).collect();
        assert!(
            header_names.contains(&"x-amz-security-token"),
            "expected x-amz-security-token header for STS credentials, got: {:?}",
            header_names
        );
    }

    // ── Trait object tests ───────────────────────────────────────────

    #[test]
    fn implements_kms_provider_trait() {
        let p: Box<dyn KmsProvider> = Box::new(AwsKmsProvider::new(
            "arn".into(),
            "us-east-1".into(),
            "ak".into(),
            "sk".into(),
            None,
        ));
        assert_eq!(p.provider_name(), "aws-kms");
    }

    #[test]
    fn is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AwsKmsProvider>();
    }

    // ── from_config tests ───────────────────────────────────────────

    #[test]
    fn from_config_with_all_fields() {
        let settings = serde_json::json!({
            "key_arn": "arn:aws:kms:us-west-2:123:key/abc",
            "region": "us-west-2",
            "access_key_id": "AKID_FROM_CONFIG",
            "secret_access_key": "SK_FROM_CONFIG",
            "session_token": "TOK_FROM_CONFIG"
        });
        let p = AwsKmsProvider::from_config(&settings).expect("should succeed");
        assert_eq!(p.access_key_id, "AKID_FROM_CONFIG");
        assert_eq!(p.secret_access_key, "SK_FROM_CONFIG");
        assert_eq!(p.region, "us-west-2");
        assert_eq!(p.key_arn, "arn:aws:kms:us-west-2:123:key/abc");
        assert_eq!(p.session_token.as_deref(), Some("TOK_FROM_CONFIG"));
    }

    #[test]
    fn from_config_without_session_token() {
        let settings = serde_json::json!({
            "key_arn": "arn:aws:kms:eu-west-1:456:key/def",
            "region": "eu-west-1",
            "access_key_id": "AKID",
            "secret_access_key": "SK"
        });
        let p = AwsKmsProvider::from_config(&settings).expect("should succeed");
        assert!(p.session_token.is_none());
        assert_eq!(p.region, "eu-west-1");
    }

    #[test]
    fn from_config_missing_credentials_falls_back_to_env() {
        // Only key_arn and region in settings, no credentials.
        // Without env vars set, this should fail with KmsNotConfigured.
        let settings = serde_json::json!({
            "key_arn": "arn:aws:kms:us-east-1:789:key/ghi",
            "region": "us-east-1"
        });
        let result = AwsKmsProvider::from_config(&settings);
        // Should fail because env vars are not set in test environment.
        assert!(result.is_err());
    }

    #[test]
    fn from_config_missing_key_arn_fails() {
        let settings = serde_json::json!({
            "region": "us-east-1",
            "access_key_id": "AKID",
            "secret_access_key": "SK"
        });
        let result = AwsKmsProvider::from_config(&settings);
        assert!(result.is_err());
    }
}
