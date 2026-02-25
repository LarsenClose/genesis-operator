package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/larsenclose/genesis/internal/config"
	"github.com/larsenclose/genesis/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBootstrapConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  config.BootstrapConfig
		wantErr bool
	}{
		{
			name: "valid aws-kms config",
			config: config.BootstrapConfig{
				APIVersion: config.APIVersion,
				Kind:       config.KindBootstrap,
				Spec: config.BootstrapSpec{
					Envelope: config.EnvelopeSpec{
						Provider: kms.ProviderAWSKMS,
						AWSKMS: &config.AWSKMSSpec{
							KeyArn: "arn:aws:kms:us-west-2:123456789012:key/test",
							Region: "us-west-2",
						},
						Ciphertext: "dGVzdA==",
					},
					Output: config.OutputSpec{
						SecretName:      "sops-age",
						SecretNamespace: "flux-system",
						SecretKey:       "age.agekey",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing api version",
			config: config.BootstrapConfig{
				Kind: config.KindBootstrap,
			},
			wantErr: true,
		},
		{
			name: "missing kind",
			config: config.BootstrapConfig{
				APIVersion: config.APIVersion,
			},
			wantErr: true,
		},
		{
			name: "missing provider",
			config: config.BootstrapConfig{
				APIVersion: config.APIVersion,
				Kind:       config.KindBootstrap,
				Spec: config.BootstrapSpec{
					Envelope: config.EnvelopeSpec{
						Ciphertext: "dGVzdA==",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "aws-kms missing key arn",
			config: config.BootstrapConfig{
				APIVersion: config.APIVersion,
				Kind:       config.KindBootstrap,
				Spec: config.BootstrapSpec{
					Envelope: config.EnvelopeSpec{
						Provider:   kms.ProviderAWSKMS,
						Ciphertext: "dGVzdA==",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "missing ciphertext",
			config: config.BootstrapConfig{
				APIVersion: config.APIVersion,
				Kind:       config.KindBootstrap,
				Spec: config.BootstrapSpec{
					Envelope: config.EnvelopeSpec{
						Provider: kms.ProviderAWSKMS,
						AWSKMS: &config.AWSKMSSpec{
							KeyArn: "arn:aws:kms:us-west-2:123456789012:key/test",
							Region: "us-west-2",
						},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestBootstrapConfigLoadSave(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "genesis-bootstrap.yaml")

	original := &config.BootstrapConfig{
		APIVersion: config.APIVersion,
		Kind:       config.KindBootstrap,
		Metadata: config.Metadata{
			Name: "test-bootstrap",
		},
		Spec: config.BootstrapSpec{
			Envelope: config.EnvelopeSpec{
				Provider:  kms.ProviderAWSKMS,
				PublicKey: "age1testkey",
				AWSKMS: &config.AWSKMSSpec{
					KeyArn: "arn:aws:kms:us-west-2:123456789012:key/test",
					Region: "us-west-2",
				},
				Ciphertext: "dGVzdGNpcGhlcnRleHQ=",
			},
			Output: config.OutputSpec{
				SecretName:      "sops-age",
				SecretNamespace: "flux-system",
				SecretKey:       "age.agekey",
			},
		},
	}

	err := config.Save(configPath, original)
	require.NoError(t, err)

	_, err = os.Stat(configPath)
	require.NoError(t, err)

	loaded, err := config.Load(configPath)
	require.NoError(t, err)
	assert.Equal(t, original.APIVersion, loaded.APIVersion)
	assert.Equal(t, original.Kind, loaded.Kind)
	assert.Equal(t, original.Metadata.Name, loaded.Metadata.Name)
	assert.Equal(t, original.Spec.Envelope.Provider, loaded.Spec.Envelope.Provider)
	assert.Equal(t, original.Spec.Envelope.PublicKey, loaded.Spec.Envelope.PublicKey)
	assert.Equal(t, original.Spec.Envelope.Ciphertext, loaded.Spec.Envelope.Ciphertext)
}

func TestBootstrapConfigLoadNotFound(t *testing.T) {
	_, err := config.Load("/nonexistent/path/config.yaml")
	assert.Error(t, err)
}

func TestSOPSConfigGenerate(t *testing.T) {
	publicKey := "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
	sopsConfig := config.NewSOPSConfig(publicKey)

	assert.Len(t, sopsConfig.CreationRules, 1)
	assert.Equal(t, publicKey, sopsConfig.CreationRules[0].Age)
	assert.Equal(t, "*.enc.yaml", sopsConfig.CreationRules[0].PathRegex)
}

func TestSOPSConfigSave(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".sops.yaml")
	publicKey := "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"

	sopsConfig := config.NewSOPSConfig(publicKey)
	err := sopsConfig.Save(configPath)
	require.NoError(t, err)

	data, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), publicKey)
	assert.Contains(t, string(data), "creation_rules")
}

// Additional validation tests for all provider types
func TestBootstrapConfigValidationAllProviders(t *testing.T) {
	tests := []struct {
		name    string
		config  config.BootstrapConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid gcp-kms config",
			config: config.BootstrapConfig{
				APIVersion: config.APIVersion,
				Kind:       config.KindBootstrap,
				Spec: config.BootstrapSpec{
					Envelope: config.EnvelopeSpec{
						Provider: kms.ProviderGCPKMS,
						GCPKMS: &config.GCPKMSSpec{
							KeyName: "projects/test/locations/global/keyRings/test/cryptoKeys/test",
						},
						Ciphertext: "dGVzdA==",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "gcp-kms missing key name",
			config: config.BootstrapConfig{
				APIVersion: config.APIVersion,
				Kind:       config.KindBootstrap,
				Spec: config.BootstrapSpec{
					Envelope: config.EnvelopeSpec{
						Provider:   kms.ProviderGCPKMS,
						Ciphertext: "dGVzdA==",
					},
				},
			},
			wantErr: true,
			errMsg:  "gcpKms.keyName is required",
		},
		{
			name: "gcp-kms with empty key name",
			config: config.BootstrapConfig{
				APIVersion: config.APIVersion,
				Kind:       config.KindBootstrap,
				Spec: config.BootstrapSpec{
					Envelope: config.EnvelopeSpec{
						Provider: kms.ProviderGCPKMS,
						GCPKMS: &config.GCPKMSSpec{
							KeyName: "",
						},
						Ciphertext: "dGVzdA==",
					},
				},
			},
			wantErr: true,
			errMsg:  "gcpKms.keyName is required",
		},
		{
			name: "valid azure-keyvault config",
			config: config.BootstrapConfig{
				APIVersion: config.APIVersion,
				Kind:       config.KindBootstrap,
				Spec: config.BootstrapSpec{
					Envelope: config.EnvelopeSpec{
						Provider: kms.ProviderAzureKeyVault,
						AzureKeyVault: &config.AzureKVSpec{
							VaultURL:   "https://test.vault.azure.net",
							KeyName:    "my-key",
							KeyVersion: "v1",
						},
						Ciphertext: "dGVzdA==",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "azure-keyvault missing vault url",
			config: config.BootstrapConfig{
				APIVersion: config.APIVersion,
				Kind:       config.KindBootstrap,
				Spec: config.BootstrapSpec{
					Envelope: config.EnvelopeSpec{
						Provider:   kms.ProviderAzureKeyVault,
						Ciphertext: "dGVzdA==",
					},
				},
			},
			wantErr: true,
			errMsg:  "azureKeyVault.vaultUrl is required",
		},
		{
			name: "azure-keyvault with empty vault url",
			config: config.BootstrapConfig{
				APIVersion: config.APIVersion,
				Kind:       config.KindBootstrap,
				Spec: config.BootstrapSpec{
					Envelope: config.EnvelopeSpec{
						Provider: kms.ProviderAzureKeyVault,
						AzureKeyVault: &config.AzureKVSpec{
							VaultURL: "",
							KeyName:  "my-key",
						},
						Ciphertext: "dGVzdA==",
					},
				},
			},
			wantErr: true,
			errMsg:  "azureKeyVault.vaultUrl is required",
		},
		{
			name: "valid yubikey config",
			config: config.BootstrapConfig{
				APIVersion: config.APIVersion,
				Kind:       config.KindBootstrap,
				Spec: config.BootstrapSpec{
					Envelope: config.EnvelopeSpec{
						Provider: kms.ProviderYubiKey,
						YubiKey: &config.YubiKeySpec{
							Slot:                 "9a",
							PublicKeyFingerprint: "SHA256:abc",
						},
						Ciphertext: "dGVzdA==",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "yubikey with no config (uses defaults)",
			config: config.BootstrapConfig{
				APIVersion: config.APIVersion,
				Kind:       config.KindBootstrap,
				Spec: config.BootstrapSpec{
					Envelope: config.EnvelopeSpec{
						Provider:   kms.ProviderYubiKey,
						Ciphertext: "dGVzdA==",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid tpm config",
			config: config.BootstrapConfig{
				APIVersion: config.APIVersion,
				Kind:       config.KindBootstrap,
				Spec: config.BootstrapSpec{
					Envelope: config.EnvelopeSpec{
						Provider: kms.ProviderTPM,
						TPM: &config.TPMSpec{
							DevicePath: "/dev/tpmrm0",
							PCRSelection: &config.PCRSelectionSpec{
								Hash: "sha256",
								PCRs: []int{0, 1, 2, 3, 7},
							},
						},
						Ciphertext: "dGVzdA==",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "tpm with no config (uses defaults)",
			config: config.BootstrapConfig{
				APIVersion: config.APIVersion,
				Kind:       config.KindBootstrap,
				Spec: config.BootstrapSpec{
					Envelope: config.EnvelopeSpec{
						Provider:   kms.ProviderTPM,
						Ciphertext: "dGVzdA==",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid mock provider config",
			config: config.BootstrapConfig{
				APIVersion: config.APIVersion,
				Kind:       config.KindBootstrap,
				Spec: config.BootstrapSpec{
					Envelope: config.EnvelopeSpec{
						Provider:   kms.ProviderMock,
						Ciphertext: "dGVzdA==",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "unsupported provider",
			config: config.BootstrapConfig{
				APIVersion: config.APIVersion,
				Kind:       config.KindBootstrap,
				Spec: config.BootstrapSpec{
					Envelope: config.EnvelopeSpec{
						Provider:   "unknown-provider",
						Ciphertext: "dGVzdA==",
					},
				},
			},
			wantErr: true,
			errMsg:  "unsupported provider",
		},
		{
			name: "invalid api version",
			config: config.BootstrapConfig{
				APIVersion: "v1",
				Kind:       config.KindBootstrap,
				Spec: config.BootstrapSpec{
					Envelope: config.EnvelopeSpec{
						Provider:   kms.ProviderAWSKMS,
						AWSKMS:     &config.AWSKMSSpec{KeyArn: "arn:aws:kms:us-west-2:123:key/test"},
						Ciphertext: "dGVzdA==",
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid apiVersion",
		},
		{
			name: "invalid kind",
			config: config.BootstrapConfig{
				APIVersion: config.APIVersion,
				Kind:       "WrongKind",
				Spec: config.BootstrapSpec{
					Envelope: config.EnvelopeSpec{
						Provider:   kms.ProviderAWSKMS,
						AWSKMS:     &config.AWSKMSSpec{KeyArn: "arn:aws:kms:us-west-2:123:key/test"},
						Ciphertext: "dGVzdA==",
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid kind",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Test config load with invalid YAML
func TestBootstrapConfigLoadInvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.yaml")

	// Write invalid YAML
	err := os.WriteFile(configPath, []byte("not: valid: yaml: content: ["), 0644)
	require.NoError(t, err)

	_, err = config.Load(configPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse config")
}

// Test config save to read-only directory
func TestBootstrapConfigSaveReadOnlyDir(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("Test cannot run as root")
	}

	tmpDir := t.TempDir()
	// Make directory read-only
	err := os.Chmod(tmpDir, 0555)
	require.NoError(t, err)
	defer func() { _ = os.Chmod(tmpDir, 0755) }()

	cfg := &config.BootstrapConfig{
		APIVersion: config.APIVersion,
		Kind:       config.KindBootstrap,
	}

	configPath := filepath.Join(tmpDir, "genesis-bootstrap.yaml")
	err = config.Save(configPath, cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write config file")
}

// Test SOPS config load with invalid YAML
func TestSOPSConfigLoadInvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".sops.yaml")

	// Write invalid YAML
	err := os.WriteFile(configPath, []byte("invalid: yaml: ["), 0644)
	require.NoError(t, err)

	_, err = config.LoadSOPSConfig(configPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse SOPS config")
}

// Test SOPS config load nonexistent file
func TestSOPSConfigLoadNotFound(t *testing.T) {
	_, err := config.LoadSOPSConfig("/nonexistent/path/.sops.yaml")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read SOPS config")
}

// Test SOPS config save to read-only directory
func TestSOPSConfigSaveReadOnlyDir(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("Test cannot run as root")
	}

	tmpDir := t.TempDir()
	// Make directory read-only
	err := os.Chmod(tmpDir, 0555)
	require.NoError(t, err)
	defer func() { _ = os.Chmod(tmpDir, 0755) }()

	sopsConfig := config.NewSOPSConfig("age1testkey")
	configPath := filepath.Join(tmpDir, ".sops.yaml")
	err = sopsConfig.Save(configPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write SOPS config")
}

// Test config with all fields populated
func TestBootstrapConfigFullSaveLoad(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "full-config.yaml")

	original := &config.BootstrapConfig{
		APIVersion: config.APIVersion,
		Kind:       config.KindBootstrap,
		Metadata: config.Metadata{
			Name:      "test-bootstrap",
			Namespace: "test-namespace",
		},
		Spec: config.BootstrapSpec{
			Envelope: config.EnvelopeSpec{
				Provider:  kms.ProviderAWSKMS,
				PublicKey: "age1publickey",
				AWSKMS: &config.AWSKMSSpec{
					KeyArn: "arn:aws:kms:us-west-2:123456789012:key/test",
					Region: "us-west-2",
				},
				Ciphertext: "dGVzdGNpcGhlcnRleHQ=",
			},
			Output: config.OutputSpec{
				SecretName:           "sops-age",
				SecretNamespace:      "flux-system",
				SecretKey:            "age.agekey",
				AdditionalNamespaces: []string{"production", "staging"},
			},
		},
	}

	err := config.Save(configPath, original)
	require.NoError(t, err)

	loaded, err := config.Load(configPath)
	require.NoError(t, err)

	// Verify all fields
	assert.Equal(t, original.APIVersion, loaded.APIVersion)
	assert.Equal(t, original.Kind, loaded.Kind)
	assert.Equal(t, original.Metadata.Name, loaded.Metadata.Name)
	assert.Equal(t, original.Metadata.Namespace, loaded.Metadata.Namespace)
	assert.Equal(t, original.Spec.Envelope.Provider, loaded.Spec.Envelope.Provider)
	assert.Equal(t, original.Spec.Envelope.PublicKey, loaded.Spec.Envelope.PublicKey)
	assert.Equal(t, original.Spec.Envelope.AWSKMS.KeyArn, loaded.Spec.Envelope.AWSKMS.KeyArn)
	assert.Equal(t, original.Spec.Envelope.AWSKMS.Region, loaded.Spec.Envelope.AWSKMS.Region)
	assert.Equal(t, original.Spec.Output.SecretName, loaded.Spec.Output.SecretName)
	assert.Equal(t, original.Spec.Output.SecretNamespace, loaded.Spec.Output.SecretNamespace)
	assert.Equal(t, original.Spec.Output.SecretKey, loaded.Spec.Output.SecretKey)
	assert.Equal(t, original.Spec.Output.AdditionalNamespaces, loaded.Spec.Output.AdditionalNamespaces)
}

// Test SOPS config path regex
func TestSOPSConfigPathRegex(t *testing.T) {
	publicKey := "age1testkey"
	sopsConfig := config.NewSOPSConfig(publicKey)

	require.Len(t, sopsConfig.CreationRules, 1)
	assert.Equal(t, "*.enc.yaml", sopsConfig.CreationRules[0].PathRegex)
	assert.Equal(t, publicKey, sopsConfig.CreationRules[0].Age)
}

// ── Local Provider Validation Tests ─────────────────────────────────

func TestBootstrapConfigValidateLocalProvider(t *testing.T) {
	t.Run("valid local config", func(t *testing.T) {
		cfg := config.BootstrapConfig{
			APIVersion: config.APIVersion,
			Kind:       config.KindBootstrap,
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider:     kms.ProviderLocal,
					PublicKey:    "age1testkey",
					EnvelopePath: "/tmp/test.enc",
				},
				Output: config.OutputSpec{
					SecretName:      "sops-age",
					SecretNamespace: "flux-system",
					SecretKey:       "age.agekey",
				},
			},
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("local missing envelope path", func(t *testing.T) {
		cfg := config.BootstrapConfig{
			APIVersion: config.APIVersion,
			Kind:       config.KindBootstrap,
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider:  kms.ProviderLocal,
					PublicKey: "age1testkey",
				},
			},
		}
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "envelopePath")
	})

	t.Run("local does not require ciphertext", func(t *testing.T) {
		cfg := config.BootstrapConfig{
			APIVersion: config.APIVersion,
			Kind:       config.KindBootstrap,
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider:     kms.ProviderLocal,
					PublicKey:    "age1testkey",
					EnvelopePath: "/tmp/test.enc",
					Ciphertext:   "", // intentionally empty
				},
			},
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})
}

// ── PQ Field Save/Load Roundtrip ────────────────────────────────────

func TestBootstrapConfigSaveLoadLocalPQFields(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "bootstrap.yaml")

	original := &config.BootstrapConfig{
		APIVersion: config.APIVersion,
		Kind:       config.KindBootstrap,
		Metadata: config.Metadata{
			Name:      "test",
			Namespace: "test",
		},
		Spec: config.BootstrapSpec{
			Envelope: config.EnvelopeSpec{
				Provider:        kms.ProviderLocal,
				PublicKey:       "age1testkey",
				MLKEMPublicKey:  "mlkem-test-data",
				SigningPublicKey: "mldsa-test-data",
				EnvelopePath:    "/tmp/envelope.enc",
			},
			Output: config.OutputSpec{
				SecretName:      "sops-age",
				SecretNamespace: "flux-system",
				SecretKey:       "age.agekey",
			},
		},
	}

	err := config.Save(configPath, original)
	require.NoError(t, err)

	loaded, err := config.Load(configPath)
	require.NoError(t, err)

	assert.Equal(t, kms.ProviderLocal, loaded.Spec.Envelope.Provider)
	assert.Equal(t, "mlkem-test-data", loaded.Spec.Envelope.MLKEMPublicKey)
	assert.Equal(t, "mldsa-test-data", loaded.Spec.Envelope.SigningPublicKey)
	assert.Equal(t, "/tmp/envelope.enc", loaded.Spec.Envelope.EnvelopePath)
	assert.Equal(t, "age1testkey", loaded.Spec.Envelope.PublicKey)
}

// ── OCI Vault Validation Tests (fills pre-existing gap) ─────────────

func TestBootstrapConfigValidateOCIVault(t *testing.T) {
	t.Run("valid oci-vault config", func(t *testing.T) {
		cfg := config.BootstrapConfig{
			APIVersion: config.APIVersion,
			Kind:       config.KindBootstrap,
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider: kms.ProviderOCIVault,
					OCIVault: &config.OCIVaultSpec{
						KeyOCID:        "ocid1.key.oc1..test",
						CryptoEndpoint: "https://vault-crypto.kms.us-east-1.oraclecloud.com",
					},
					Ciphertext: "dGVzdA==",
				},
			},
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("oci-vault missing key ocid", func(t *testing.T) {
		cfg := config.BootstrapConfig{
			APIVersion: config.APIVersion,
			Kind:       config.KindBootstrap,
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider:   kms.ProviderOCIVault,
					Ciphertext: "dGVzdA==",
				},
			},
		}
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ociVault.keyOcid")
	})

	t.Run("oci-vault missing crypto endpoint", func(t *testing.T) {
		cfg := config.BootstrapConfig{
			APIVersion: config.APIVersion,
			Kind:       config.KindBootstrap,
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider: kms.ProviderOCIVault,
					OCIVault: &config.OCIVaultSpec{
						KeyOCID: "ocid1.key.oc1..test",
					},
					Ciphertext: "dGVzdA==",
				},
			},
		}
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cryptoEndpoint")
	})
}
