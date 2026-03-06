package bridge

import (
	"encoding/json"
	"testing"

	genesisv1alpha1 "github.com/larsenclose/genesis/pkg/api/v1alpha1"
)

func TestBuildKmsConfigJSON_AWS(t *testing.T) {
	envelope := &genesisv1alpha1.EnvelopeSpec{
		Provider: "aws-kms",
		AWSKms: &genesisv1alpha1.AWSKmsSpec{
			KeyArn: "arn:aws:kms:us-east-1:123456789012:key/test",
			Region: "us-east-1",
		},
	}

	// Set env vars for credential resolution.
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "SECRET_TEST")
	t.Setenv("AWS_SESSION_TOKEN", "SESSION_TEST")

	result, err := BuildKmsConfigJSON(envelope)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var config KmsConfig
	if err := json.Unmarshal([]byte(result), &config); err != nil {
		t.Fatalf("failed to parse result JSON: %v", err)
	}

	if config.ProviderType != "aws" {
		t.Errorf("expected provider_type 'aws', got %q", config.ProviderType)
	}
	if config.Settings["key_arn"] != "arn:aws:kms:us-east-1:123456789012:key/test" {
		t.Errorf("unexpected key_arn: %v", config.Settings["key_arn"])
	}
	if config.Settings["region"] != "us-east-1" {
		t.Errorf("unexpected region: %v", config.Settings["region"])
	}
	if config.Settings["access_key_id"] != "AKIATEST" {
		t.Errorf("unexpected access_key_id: %v", config.Settings["access_key_id"])
	}
	if config.Settings["secret_access_key"] != "SECRET_TEST" {
		t.Errorf("unexpected secret_access_key: %v", config.Settings["secret_access_key"])
	}
	if config.Settings["session_token"] != "SESSION_TEST" {
		t.Errorf("unexpected session_token: %v", config.Settings["session_token"])
	}
}

func TestBuildKmsConfigJSON_AWS_RegionFallback(t *testing.T) {
	envelope := &genesisv1alpha1.EnvelopeSpec{
		Provider: "aws-kms",
		AWSKms: &genesisv1alpha1.AWSKmsSpec{
			KeyArn: "arn:aws:kms:eu-west-1:123:key/k",
		},
	}
	t.Setenv("AWS_DEFAULT_REGION", "eu-west-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "AK")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "SK")

	result, err := BuildKmsConfigJSON(envelope)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var config KmsConfig
	if err := json.Unmarshal([]byte(result), &config); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if config.Settings["region"] != "eu-west-1" {
		t.Errorf("expected region from env fallback, got %v", config.Settings["region"])
	}
}

func TestBuildKmsConfigJSON_GCP(t *testing.T) {
	envelope := &genesisv1alpha1.EnvelopeSpec{
		Provider: "gcp-kms",
		GCPKms: &genesisv1alpha1.GCPKmsSpec{
			KeyName: "projects/p/locations/l/keyRings/r/cryptoKeys/k",
		},
	}
	t.Setenv("GENESIS_GCP_ACCESS_TOKEN", "ya29.test")

	result, err := BuildKmsConfigJSON(envelope)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var config KmsConfig
	if err := json.Unmarshal([]byte(result), &config); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if config.ProviderType != "gcp" {
		t.Errorf("expected provider_type 'gcp', got %q", config.ProviderType)
	}
	if config.Settings["key_resource_name"] != "projects/p/locations/l/keyRings/r/cryptoKeys/k" {
		t.Errorf("unexpected key_resource_name: %v", config.Settings["key_resource_name"])
	}
	if config.Settings["access_token"] != "ya29.test" {
		t.Errorf("unexpected access_token: %v", config.Settings["access_token"])
	}
}

func TestBuildKmsConfigJSON_Azure(t *testing.T) {
	envelope := &genesisv1alpha1.EnvelopeSpec{
		Provider: "azure-keyvault",
		AzureKeyVault: &genesisv1alpha1.AzureKeyVaultSpec{
			VaultUrl:   "https://myvault.vault.azure.net",
			KeyName:    "my-key",
			KeyVersion: "v1",
		},
	}
	t.Setenv("AZURE_ACCESS_TOKEN", "azure-token")

	result, err := BuildKmsConfigJSON(envelope)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var config KmsConfig
	if err := json.Unmarshal([]byte(result), &config); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if config.ProviderType != "azure" {
		t.Errorf("expected provider_type 'azure', got %q", config.ProviderType)
	}
	if config.Settings["vault_url"] != "https://myvault.vault.azure.net" {
		t.Errorf("unexpected vault_url: %v", config.Settings["vault_url"])
	}
	if config.Settings["key_name"] != "my-key" {
		t.Errorf("unexpected key_name: %v", config.Settings["key_name"])
	}
	if config.Settings["key_version"] != "v1" {
		t.Errorf("unexpected key_version: %v", config.Settings["key_version"])
	}
	if config.Settings["access_token"] != "azure-token" {
		t.Errorf("unexpected access_token: %v", config.Settings["access_token"])
	}
}

func TestBuildKmsConfigJSON_Mock(t *testing.T) {
	envelope := &genesisv1alpha1.EnvelopeSpec{
		Provider: "mock",
	}

	result, err := BuildKmsConfigJSON(envelope)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var config KmsConfig
	if err := json.Unmarshal([]byte(result), &config); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if config.ProviderType != "mock" {
		t.Errorf("expected provider_type 'mock', got %q", config.ProviderType)
	}
}

func TestBuildKmsConfigJSON_NilEnvelope(t *testing.T) {
	_, err := BuildKmsConfigJSON(nil)
	if err == nil {
		t.Fatal("expected error for nil envelope")
	}
}

func TestBuildKmsConfigJSON_MissingAWSSpec(t *testing.T) {
	envelope := &genesisv1alpha1.EnvelopeSpec{
		Provider: "aws-kms",
	}
	_, err := BuildKmsConfigJSON(envelope)
	if err == nil {
		t.Fatal("expected error for missing AWS spec")
	}
}

func TestBuildKmsConfigJSON_MissingGCPSpec(t *testing.T) {
	envelope := &genesisv1alpha1.EnvelopeSpec{
		Provider: "gcp-kms",
	}
	_, err := BuildKmsConfigJSON(envelope)
	if err == nil {
		t.Fatal("expected error for missing GCP spec")
	}
}

func TestBuildKmsConfigJSON_MissingAzureSpec(t *testing.T) {
	envelope := &genesisv1alpha1.EnvelopeSpec{
		Provider: "azure-keyvault",
	}
	_, err := BuildKmsConfigJSON(envelope)
	if err == nil {
		t.Fatal("expected error for missing Azure spec")
	}
}

func TestBuildKmsConfigJSON_UnsupportedProvider(t *testing.T) {
	envelope := &genesisv1alpha1.EnvelopeSpec{
		Provider: "oci-vault",
	}
	_, err := BuildKmsConfigJSON(envelope)
	if err == nil {
		t.Fatal("expected error for unsupported provider")
	}
}

func TestMapProviderName(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"aws-kms", "aws"},
		{"gcp-kms", "gcp"},
		{"azure-keyvault", "azure"},
		{"mock", "mock"},
		{"unknown", "unknown"},
	}
	for _, tc := range cases {
		got := mapProviderName(tc.input)
		if got != tc.expected {
			t.Errorf("mapProviderName(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}
