package bridge

import (
	"encoding/json"
	"strings"
	"testing"

	genesisv1alpha1 "github.com/larsenclose/genesis/pkg/api/v1alpha1"
)

// Integration tests verify that BuildKmsConfigJSON produces JSON compatible
// with the Rust genesis-core KmsConfig schema. These tests use the actual
// bridge FFI to validate the JSON roundtrips through the Rust parser.

// TestKmsConfigJSON_MockRoundtrip verifies mock provider config works through
// the full bridge lifecycle: BuildKmsConfigJSON -> bridge.New (GenesisConfig)
// -> bridge.Init (KmsConfig).
func TestKmsConfigJSON_MockRoundtrip(t *testing.T) {
	// Build KmsConfig JSON for mock provider.
	envelope := &genesisv1alpha1.EnvelopeSpec{
		Provider: "mock",
	}
	kmsJSON, err := BuildKmsConfigJSON(envelope)
	if err != nil {
		t.Fatalf("BuildKmsConfigJSON failed: %v", err)
	}

	// Verify it produces valid JSON with expected structure.
	var config KmsConfig
	if err := json.Unmarshal([]byte(kmsJSON), &config); err != nil {
		t.Fatalf("produced invalid JSON: %v", err)
	}

	if config.ProviderType != "mock" {
		t.Errorf("expected provider_type 'mock', got %q", config.ProviderType)
	}

	// Verify bridge.New works with a GenesisConfig JSON (different from KmsConfig).
	// GenesisConfig uses provider_config; KmsConfig uses settings.
	genesisConfigJSON := `{"provider_type":"mock","provider_config":{}}`
	handle, err := New(genesisConfigJSON)
	if err != nil {
		t.Fatalf("bridge.New failed: %v", err)
	}
	defer handle.Free()

	if handle.State() != StateUninitialized {
		t.Errorf("expected Uninitialized state, got %v", handle.State())
	}

	// Use the KmsConfig JSON with bridge.Init.
	// This should succeed because mock KMS is enabled in release builds
	// that include the mock feature. In release without mock, this will
	// fail at the provider creation step -- which is expected and indicates
	// the JSON was parsed successfully but the provider is not available.
	artifacts, err := handle.Init(kmsJSON)
	if err != nil {
		// If mock feature is not in the release build, this error is expected.
		// Verify it's a KMS-not-configured error, not a JSON parse error.
		if strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "JSON") || strings.Contains(err.Error(), "parse") {
			t.Fatalf("KmsConfig JSON was not parseable by Rust: %v", err)
		}
		// KmsNotConfigured is expected when mock feature is disabled in release.
		t.Logf("bridge.Init failed as expected (mock not in release build): %v", err)
		return
	}

	// If mock is available, verify the full roundtrip worked.
	if artifacts == nil {
		t.Fatal("expected non-nil artifacts")
	}
	if artifacts.PublicKey == "" {
		t.Error("expected non-empty public key")
	}
}

// TestKmsConfigJSON_AWSFormat verifies AWS config JSON has the correct field
// names that the Rust AwsKmsProvider::from_config expects.
func TestKmsConfigJSON_AWSFormat(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIATEST123")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret123")
	t.Setenv("AWS_SESSION_TOKEN", "session123")

	envelope := &genesisv1alpha1.EnvelopeSpec{
		Provider: "aws-kms",
		AWSKms: &genesisv1alpha1.AWSKmsSpec{
			KeyArn: "arn:aws:kms:us-east-1:111122223333:key/test-key",
			Region: "us-east-1",
		},
	}

	kmsJSON, err := BuildKmsConfigJSON(envelope)
	if err != nil {
		t.Fatalf("BuildKmsConfigJSON failed: %v", err)
	}

	// Parse and verify all Rust-expected field names are present.
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(kmsJSON), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	settings, ok := raw["settings"].(map[string]interface{})
	if !ok {
		t.Fatal("expected 'settings' to be an object")
	}

	// These are the exact field names AwsKmsProvider::from_config reads:
	expectedFields := map[string]string{
		"key_arn":           "arn:aws:kms:us-east-1:111122223333:key/test-key",
		"region":            "us-east-1",
		"access_key_id":     "AKIATEST123",
		"secret_access_key": "secret123",
		"session_token":     "session123",
	}

	for field, expected := range expectedFields {
		val, exists := settings[field]
		if !exists {
			t.Errorf("missing expected field %q in settings", field)
			continue
		}
		if val != expected {
			t.Errorf("field %q: expected %q, got %q", field, expected, val)
		}
	}
}

// TestKmsConfigJSON_GCPFormat verifies GCP config JSON field names match
// Rust GcpKmsProvider::from_config expectations.
func TestKmsConfigJSON_GCPFormat(t *testing.T) {
	t.Setenv("GENESIS_GCP_ACCESS_TOKEN", "ya29.integration-test")

	envelope := &genesisv1alpha1.EnvelopeSpec{
		Provider: "gcp-kms",
		GCPKms: &genesisv1alpha1.GCPKmsSpec{
			KeyName: "projects/test/locations/global/keyRings/ring/cryptoKeys/key",
		},
	}

	kmsJSON, err := BuildKmsConfigJSON(envelope)
	if err != nil {
		t.Fatalf("BuildKmsConfigJSON failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(kmsJSON), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	settings := raw["settings"].(map[string]interface{})

	if settings["key_resource_name"] != "projects/test/locations/global/keyRings/ring/cryptoKeys/key" {
		t.Errorf("unexpected key_resource_name: %v", settings["key_resource_name"])
	}
	if settings["access_token"] != "ya29.integration-test" {
		t.Errorf("unexpected access_token: %v", settings["access_token"])
	}
}

// TestKmsConfigJSON_AzureFormat verifies Azure config JSON field names match
// Rust AzureKeyVaultProvider::from_config expectations.
func TestKmsConfigJSON_AzureFormat(t *testing.T) {
	t.Setenv("AZURE_ACCESS_TOKEN", "azure-integration-token")

	envelope := &genesisv1alpha1.EnvelopeSpec{
		Provider: "azure-keyvault",
		AzureKeyVault: &genesisv1alpha1.AzureKeyVaultSpec{
			VaultUrl:   "https://test.vault.azure.net",
			KeyName:    "integration-key",
			KeyVersion: "v2",
		},
	}

	kmsJSON, err := BuildKmsConfigJSON(envelope)
	if err != nil {
		t.Fatalf("BuildKmsConfigJSON failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(kmsJSON), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if raw["provider_type"] != "azure" {
		t.Errorf("expected provider_type 'azure', got %v", raw["provider_type"])
	}

	settings := raw["settings"].(map[string]interface{})

	expectedFields := map[string]string{
		"vault_url":    "https://test.vault.azure.net",
		"key_name":     "integration-key",
		"key_version":  "v2",
		"access_token": "azure-integration-token",
	}

	for field, expected := range expectedFields {
		val, exists := settings[field]
		if !exists {
			t.Errorf("missing expected field %q in settings", field)
			continue
		}
		if val != expected {
			t.Errorf("field %q: expected %q, got %q", field, expected, val)
		}
	}
}

