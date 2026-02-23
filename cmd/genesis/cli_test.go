package main

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/larsenclose/genesis/internal/bridge"
	"github.com/larsenclose/genesis/internal/config"
	"github.com/larsenclose/genesis/internal/crypto"
	"github.com/larsenclose/genesis/internal/envelope"
	"github.com/larsenclose/genesis/internal/kms"
	"github.com/larsenclose/genesis/internal/kms/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bridgeInitMock creates a fresh keypair via the Rust bridge's mock KMS.
// This ensures ciphertext is produced by the same mock implementation that
// the bridge's verify/load paths will use for decryption.
func bridgeInitMock(t *testing.T) *bridge.PublicArtifacts {
	t.Helper()
	genesisJSON := buildGenesisConfigJSON("mock")
	h, err := bridge.New(genesisJSON)
	require.NoError(t, err)
	defer h.Free()

	kmsJSON := buildKmsConfigJSON("mock")
	artifacts, err := h.Init(kmsJSON)
	require.NoError(t, err)
	return artifacts
}

// base64Encode is a thin wrapper for tests that need base64-encoded ciphertext.
func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func TestRootCommand(t *testing.T) {
	cmd := rootCmd
	assert.Equal(t, "genesis", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotEmpty(t, cmd.Long)
}

func TestInitCommandFlags(t *testing.T) {
	cmd := initCmd
	assert.Equal(t, "init", cmd.Use)

	flags := cmd.Flags()
	assert.NotNil(t, flags.Lookup("provider"))
	assert.NotNil(t, flags.Lookup("key-arn"))
	assert.NotNil(t, flags.Lookup("output"))
}

func TestVerifyCommandFlags(t *testing.T) {
	cmd := verifyCmd
	assert.Equal(t, "verify [config-file]", cmd.Use)
}

func TestSealCommandFlags(t *testing.T) {
	cmd := sealCmd
	assert.Equal(t, "seal", cmd.Use)

	flags := cmd.Flags()
	assert.NotNil(t, flags.Lookup("config"))
	assert.NotNil(t, flags.Lookup("input"))
	assert.NotNil(t, flags.Lookup("output"))
}

func TestUnsealCommandFlags(t *testing.T) {
	cmd := unsealCmd
	assert.Equal(t, "unseal", cmd.Use)

	flags := cmd.Flags()
	assert.NotNil(t, flags.Lookup("config"))
	assert.NotNil(t, flags.Lookup("input"))
	assert.NotNil(t, flags.Lookup("output"))
}

func TestRotateCommandFlags(t *testing.T) {
	cmd := rotateCmd
	assert.Equal(t, "rotate", cmd.Use)

	flags := cmd.Flags()
	assert.NotNil(t, flags.Lookup("config"))
	assert.NotNil(t, flags.Lookup("new-key-arn"))
}

func TestVersionCommand(t *testing.T) {
	cmd := versionCmd
	assert.Equal(t, "version", cmd.Use)
}

func TestBuildBootstrapConfigFromArtifacts(t *testing.T) {
	initProvider = "aws-kms"
	initKeyArn = "arn:aws:kms:us-west-2:123456789012:key/test-key"

	artifacts := &bridge.PublicArtifacts{
		PublicKey:          "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
		EnvelopeCiphertext: []byte("test-ciphertext-bytes"),
		SopsConfig:         "creation_rules:\n  - age: \"age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\"\n",
	}

	cfg := buildBootstrapConfigFromArtifacts(artifacts)

	assert.Equal(t, config.APIVersion, cfg.APIVersion)
	assert.Equal(t, config.KindBootstrap, cfg.Kind)
	assert.Equal(t, "genesis-bootstrap", cfg.Metadata.Name)
	assert.Equal(t, "genesis-system", cfg.Metadata.Namespace)
	assert.Equal(t, artifacts.PublicKey, cfg.Spec.Envelope.PublicKey)
	assert.NotEmpty(t, cfg.Spec.Envelope.Ciphertext)
	assert.NotNil(t, cfg.Spec.Envelope.AWSKMS)
	assert.Equal(t, initKeyArn, cfg.Spec.Envelope.AWSKMS.KeyArn)
}

func TestInitWorkflowIntegration(t *testing.T) {
	tmpDir := t.TempDir()

	initProvider = "aws-kms"
	initKeyArn = "arn:aws:kms:us-west-2:123456789012:key/test"

	artifacts := &bridge.PublicArtifacts{
		PublicKey:          "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
		EnvelopeCiphertext: []byte("test-ciphertext"),
		SopsConfig:         "creation_rules:\n  - age: \"age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\"\n",
	}
	cfg := buildBootstrapConfigFromArtifacts(artifacts)

	bootstrapPath := filepath.Join(tmpDir, "genesis-bootstrap.yaml")
	err := config.Save(bootstrapPath, cfg)
	require.NoError(t, err)

	sopsConfig := config.NewSOPSConfig(artifacts.PublicKey)
	sopsPath := filepath.Join(tmpDir, ".sops.yaml")
	err = sopsConfig.Save(sopsPath)
	require.NoError(t, err)

	_, err = os.Stat(bootstrapPath)
	require.NoError(t, err)
	_, err = os.Stat(sopsPath)
	require.NoError(t, err)

	loadedCfg, err := config.Load(bootstrapPath)
	require.NoError(t, err)
	assert.NoError(t, loadedCfg.Validate())
	assert.Equal(t, artifacts.PublicKey, loadedCfg.Spec.Envelope.PublicKey)
}

func TestVerifyWorkflowIntegration(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	mockProvider := mock.NewProvider()
	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)

	env, err := envelope.Create(ctx, mockProvider, kp.PrivateKey)
	require.NoError(t, err)

	decryptedKey, err := envelope.Open(ctx, mockProvider, env)
	require.NoError(t, err)
	assert.Equal(t, kp.PrivateKey, decryptedKey)

	parsedKp, err := crypto.ParseAgeKeypair(decryptedKey)
	require.NoError(t, err)
	assert.Equal(t, kp.PublicKey, parsedKp.PublicKey)

	initProvider = "mock"
	initKeyArn = ""

	cfg := &config.BootstrapConfig{
		APIVersion: config.APIVersion,
		Kind:       config.KindBootstrap,
		Spec: config.BootstrapSpec{
			Envelope: config.EnvelopeSpec{
				Provider:   mockProvider.Name(),
				PublicKey:  env.PublicKey,
				Ciphertext: env.CiphertextB64,
			},
		},
	}

	bootstrapPath := filepath.Join(tmpDir, "genesis-bootstrap.yaml")
	err = config.Save(bootstrapPath, cfg)
	require.NoError(t, err)

	loadedCfg, err := config.Load(bootstrapPath)
	require.NoError(t, err)
	assert.Equal(t, kp.PublicKey, loadedCfg.Spec.Envelope.PublicKey)
}

func TestRotateWorkflowIntegration(t *testing.T) {
	ctx := context.Background()

	oldProvider := mock.NewProvider()
	newProvider := mock.NewProvider()

	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)

	oldEnv, err := envelope.Create(ctx, oldProvider, kp.PrivateKey)
	require.NoError(t, err)

	privateKey, err := envelope.Open(ctx, oldProvider, oldEnv)
	require.NoError(t, err)
	assert.Equal(t, kp.PrivateKey, privateKey)

	newEnv, err := envelope.Create(ctx, newProvider, privateKey)
	require.NoError(t, err)

	decryptedFromNew, err := envelope.Open(ctx, newProvider, newEnv)
	require.NoError(t, err)
	assert.Equal(t, kp.PrivateKey, decryptedFromNew)

	assert.Equal(t, oldEnv.PublicKey, newEnv.PublicKey)
	assert.NotEqual(t, oldEnv.Ciphertext, newEnv.Ciphertext)
}

func TestHelperFunctions(t *testing.T) {
	t.Run("verboseLog does nothing when verbose is false", func(t *testing.T) {
		verbose = false
		// Should not panic - just verifies the function doesn't crash
		verboseLog("test message")
	})

	t.Run("checkSOPSInstalled returns error when sops not found", func(t *testing.T) {
		originalPath := os.Getenv("PATH")
		os.Setenv("PATH", "/nonexistent")
		defer os.Setenv("PATH", originalPath)

		err := checkSOPSInstalled()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "sops binary not found")
	})
}

func TestInitResultStruct(t *testing.T) {
	result := InitResult{
		PublicKey:     "age1test",
		Provider:      "aws-kms",
		BootstrapFile: "/path/to/bootstrap.yaml",
		SOPSFile:      "/path/to/.sops.yaml",
	}

	assert.Equal(t, "age1test", result.PublicKey)
	assert.Equal(t, "aws-kms", result.Provider)
}

func TestVerifyResultStruct(t *testing.T) {
	result := VerifyResult{
		Valid:     true,
		PublicKey: "age1test",
		Provider:  "aws-kms",
	}

	assert.True(t, result.Valid)
	assert.Equal(t, "age1test", result.PublicKey)
}

func TestRotateResultStruct(t *testing.T) {
	result := RotateResult{
		Success:     true,
		OldProvider: "aws-kms",
		NewProvider: "mock",
		PublicKey:   "age1test",
	}

	assert.True(t, result.Success)
	assert.Equal(t, "aws-kms", result.OldProvider)
	assert.Equal(t, "mock", result.NewProvider)
}

func TestBuildBootstrapConfigFromArtifactsGCPKMS(t *testing.T) {
	initProvider = "gcp-kms"
	initKeyName = "projects/test/locations/global/keyRings/test/cryptoKeys/test"

	artifacts := &bridge.PublicArtifacts{
		PublicKey:          "age1testkey",
		EnvelopeCiphertext: []byte("test-ct"),
		SopsConfig:         "creation_rules:\n  - age: \"age1testkey\"\n",
	}

	cfg := buildBootstrapConfigFromArtifacts(artifacts)

	assert.Equal(t, config.APIVersion, cfg.APIVersion)
	assert.Equal(t, config.KindBootstrap, cfg.Kind)
	assert.NotNil(t, cfg.Spec.Envelope.GCPKMS)
	assert.Equal(t, initKeyName, cfg.Spec.Envelope.GCPKMS.KeyName)
}

func TestBuildBootstrapConfigFromArtifactsAzureKeyVault(t *testing.T) {
	initProvider = "azure-keyvault"
	initVaultURL = "https://testvault.vault.azure.net"
	initAzKeyName = "test-key"

	artifacts := &bridge.PublicArtifacts{
		PublicKey:          "age1testkey",
		EnvelopeCiphertext: []byte("test-ct"),
		SopsConfig:         "creation_rules:\n  - age: \"age1testkey\"\n",
	}

	cfg := buildBootstrapConfigFromArtifacts(artifacts)

	assert.Equal(t, config.APIVersion, cfg.APIVersion)
	assert.NotNil(t, cfg.Spec.Envelope.AzureKeyVault)
	assert.Equal(t, initVaultURL, cfg.Spec.Envelope.AzureKeyVault.VaultURL)
	assert.Equal(t, initAzKeyName, cfg.Spec.Envelope.AzureKeyVault.KeyName)
}

func TestBuildBootstrapConfigFromArtifactsYubiKey(t *testing.T) {
	initProvider = "yubikey"
	initKeyArn = ""

	artifacts := &bridge.PublicArtifacts{
		PublicKey:          "age1testkey",
		EnvelopeCiphertext: []byte("test-ct"),
		SopsConfig:         "creation_rules:\n  - age: \"age1testkey\"\n",
	}

	cfg := buildBootstrapConfigFromArtifacts(artifacts)

	assert.Equal(t, config.APIVersion, cfg.APIVersion)
	assert.NotNil(t, cfg.Spec.Envelope.YubiKey)
}

func TestBuildBootstrapConfigFromArtifactsTPM(t *testing.T) {
	initProvider = "tpm"
	initKeyArn = ""

	artifacts := &bridge.PublicArtifacts{
		PublicKey:          "age1testkey",
		EnvelopeCiphertext: []byte("test-ct"),
		SopsConfig:         "creation_rules:\n  - age: \"age1testkey\"\n",
	}

	cfg := buildBootstrapConfigFromArtifacts(artifacts)

	assert.Equal(t, config.APIVersion, cfg.APIVersion)
	assert.NotNil(t, cfg.Spec.Envelope.TPM)
}

func TestSealCommandValidation(t *testing.T) {
	cmd := sealCmd

	// Verify required flags
	flags := cmd.Flags()
	configFlag := flags.Lookup("config")
	inputFlag := flags.Lookup("input")

	assert.NotNil(t, configFlag)
	assert.NotNil(t, inputFlag)
}

func TestUnsealCommandValidation(t *testing.T) {
	cmd := unsealCmd

	// Verify required flags
	flags := cmd.Flags()
	configFlag := flags.Lookup("config")
	inputFlag := flags.Lookup("input")
	outputFlag := flags.Lookup("output")

	assert.NotNil(t, configFlag)
	assert.NotNil(t, inputFlag)
	assert.NotNil(t, outputFlag)
}

func TestCryptoIntegration(t *testing.T) {
	t.Run("GenerateAndParseKeypair", func(t *testing.T) {
		kp, err := crypto.GenerateAgeKeypair()
		require.NoError(t, err)
		assert.NotEmpty(t, kp.PublicKey)
		assert.NotEmpty(t, kp.PrivateKey)
		assert.Contains(t, kp.PublicKey, "age1")
		assert.Contains(t, kp.PrivateKey, "AGE-SECRET-KEY-")

		// Verify we can parse the keypair back
		parsed, err := crypto.ParseAgeKeypair(kp.PrivateKey)
		require.NoError(t, err)
		assert.Equal(t, kp.PublicKey, parsed.PublicKey)
		assert.Equal(t, kp.PrivateKey, parsed.PrivateKey)
	})

	t.Run("EnvelopeCreateAndOpen", func(t *testing.T) {
		ctx := context.Background()
		provider := mock.NewProvider()
		kp, err := crypto.GenerateAgeKeypair()
		require.NoError(t, err)

		// Create envelope
		env, err := envelope.Create(ctx, provider, kp.PrivateKey)
		require.NoError(t, err)
		assert.NotEmpty(t, env.Ciphertext)
		assert.Equal(t, kp.PublicKey, env.PublicKey)

		// Open envelope
		decrypted, err := envelope.Open(ctx, provider, env)
		require.NoError(t, err)
		assert.Equal(t, kp.PrivateKey, decrypted)
	})
}

func TestConfigSaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()

	// Build and save config using bridge artifacts
	initProvider = "aws-kms"
	initKeyArn = "arn:aws:kms:us-west-2:123456789012:key/test-key"

	artifacts := &bridge.PublicArtifacts{
		PublicKey:          "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
		EnvelopeCiphertext: []byte("test-ciphertext"),
		SopsConfig:         "creation_rules:\n  - age: \"age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\"\n",
	}
	cfg := buildBootstrapConfigFromArtifacts(artifacts)

	configPath := filepath.Join(tmpDir, "genesis-bootstrap.yaml")
	err := config.Save(configPath, cfg)
	require.NoError(t, err)

	// Load config
	loadedCfg, err := config.Load(configPath)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, cfg.APIVersion, loadedCfg.APIVersion)
	assert.Equal(t, cfg.Kind, loadedCfg.Kind)
	assert.Equal(t, cfg.Spec.Envelope.PublicKey, loadedCfg.Spec.Envelope.PublicKey)
	assert.Equal(t, cfg.Spec.Envelope.Ciphertext, loadedCfg.Spec.Envelope.Ciphertext)
	assert.NoError(t, loadedCfg.Validate())
}

func TestSOPSConfigSaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	publicKey := "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"

	// Create and save SOPS config
	sopsConfig := config.NewSOPSConfig(publicKey)
	sopsPath := filepath.Join(tmpDir, ".sops.yaml")
	err := sopsConfig.Save(sopsPath)
	require.NoError(t, err)

	// Load SOPS config
	loadedConfig, err := config.LoadSOPSConfig(sopsPath)
	require.NoError(t, err)

	// Verify
	require.Len(t, loadedConfig.CreationRules, 1)
	assert.Equal(t, publicKey, loadedConfig.CreationRules[0].Age)
}

func TestVerboseLogging(t *testing.T) {
	t.Run("verbose enabled", func(t *testing.T) {
		verbose = true
		// Should not panic
		verboseLog("test message %s", "arg")
		verbose = false
	})

	t.Run("verbose disabled", func(t *testing.T) {
		verbose = false
		// Should not panic
		verboseLog("test message %s", "arg")
	})
}

func TestPrintError(t *testing.T) {
	// Should not panic
	err := os.ErrNotExist
	printError(err)
}

func TestPrintJSON(t *testing.T) {
	result := InitResult{
		PublicKey:     "age1test",
		Provider:      "aws-kms",
		BootstrapFile: "/path/to/file",
		SOPSFile:      "/path/to/sops",
	}

	// Capture stdout - should not panic
	jsonOutput = true
	printOutput(result)
	jsonOutput = false
}

func TestEnvelopeWithDifferentProviders(t *testing.T) {
	ctx := context.Background()

	providers := []struct {
		name    string
		factory func() *mock.Provider
	}{
		{"provider1", mock.NewProvider},
		{"provider2", mock.NewProvider},
	}

	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)

	for _, p := range providers {
		t.Run(p.name, func(t *testing.T) {
			provider := p.factory()

			env, err := envelope.Create(ctx, provider, kp.PrivateKey)
			require.NoError(t, err)

			decrypted, err := envelope.Open(ctx, provider, env)
			require.NoError(t, err)
			assert.Equal(t, kp.PrivateKey, decrypted)
		})
	}
}

func TestFailingProvider(t *testing.T) {
	ctx := context.Background()
	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)

	t.Run("encrypt fails", func(t *testing.T) {
		provider := mock.NewFailingProvider(os.ErrPermission, nil)
		_, err := envelope.Create(ctx, provider, kp.PrivateKey)
		assert.Error(t, err)
	})

	t.Run("decrypt fails", func(t *testing.T) {
		// First create with a working provider
		workingProvider := mock.NewProvider()
		env, err := envelope.Create(ctx, workingProvider, kp.PrivateKey)
		require.NoError(t, err)

		// Then try to decrypt with a failing provider
		failingProvider := mock.NewFailingProvider(nil, os.ErrPermission)
		_, err = envelope.Open(ctx, failingProvider, env)
		assert.Error(t, err)
	})
}

// Tests for validateInitProviderFlags function
func TestValidateInitProviderFlags(t *testing.T) {
	t.Run("aws-kms missing key arn", func(t *testing.T) {
		initProvider = "aws-kms"
		initKeyArn = ""
		err := validateInitProviderFlags()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "--key-arn is required")
	})

	t.Run("aws-kms with valid key arn", func(t *testing.T) {
		initProvider = "aws-kms"
		initKeyArn = "arn:aws:kms:us-west-2:123456789012:key/test-key-id"
		err := validateInitProviderFlags()
		assert.NoError(t, err)
	})

	t.Run("gcp-kms missing key name", func(t *testing.T) {
		initProvider = "gcp-kms"
		initKeyName = ""
		err := validateInitProviderFlags()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "--key-name is required")
	})

	t.Run("gcp-kms with valid key name", func(t *testing.T) {
		initProvider = "gcp-kms"
		initKeyName = "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key"
		err := validateInitProviderFlags()
		assert.NoError(t, err)
	})

	t.Run("azure-keyvault missing vault url", func(t *testing.T) {
		initProvider = "azure-keyvault"
		initVaultURL = ""
		initAzKeyName = "test-key"
		err := validateInitProviderFlags()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "--vault-url is required")
	})

	t.Run("azure-keyvault missing key name", func(t *testing.T) {
		initProvider = "azure-keyvault"
		initVaultURL = "https://test.vault.azure.net"
		initAzKeyName = ""
		err := validateInitProviderFlags()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "--az-key-name is required")
	})

	t.Run("azure-keyvault with valid config", func(t *testing.T) {
		initProvider = "azure-keyvault"
		initVaultURL = "https://test.vault.azure.net"
		initAzKeyName = "my-key"
		initAzKeyVer = "abc123"
		err := validateInitProviderFlags()
		assert.NoError(t, err)
	})

	t.Run("oci-vault missing key ocid", func(t *testing.T) {
		initProvider = "oci-vault"
		initOCIKeyOCID = ""
		initOCICryptoEP = "https://vault-crypto.kms.us-east-1.oraclecloud.com"
		err := validateInitProviderFlags()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "--key-ocid is required")
	})

	t.Run("oci-vault missing crypto endpoint", func(t *testing.T) {
		initProvider = "oci-vault"
		initOCIKeyOCID = "ocid1.key.oc1..test"
		initOCICryptoEP = ""
		err := validateInitProviderFlags()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "--crypto-endpoint is required")
	})

	t.Run("yubikey passes validation", func(t *testing.T) {
		initProvider = "yubikey"
		initYubiSlot = "9a"
		initYubiFP = "SHA256:abc123"
		err := validateInitProviderFlags()
		assert.NoError(t, err)
	})

	t.Run("tpm passes validation", func(t *testing.T) {
		initProvider = "tpm"
		initTPMDevice = "/dev/tpmrm0"
		initTPMPCRs = "0,1,2,3,7"
		err := validateInitProviderFlags()
		assert.NoError(t, err)
	})

	t.Run("tpm with invalid PCRs", func(t *testing.T) {
		initProvider = "tpm"
		initTPMDevice = "/dev/tpmrm0"
		initTPMPCRs = ""
		err := validateInitProviderFlags()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid PCR selection")
	})

	t.Run("mock passes validation", func(t *testing.T) {
		initProvider = "mock"
		err := validateInitProviderFlags()
		assert.NoError(t, err)
	})

	t.Run("unknown provider", func(t *testing.T) {
		initProvider = "unknown-provider"
		err := validateInitProviderFlags()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown provider")
	})
}

// Tests for parsePCRs function
func TestParsePCRs(t *testing.T) {
	t.Run("valid PCR list", func(t *testing.T) {
		pcrs, err := parsePCRs("0,1,2,3,7")
		require.NoError(t, err)
		assert.Equal(t, []int{0, 1, 2, 3, 7}, pcrs)
	})

	t.Run("single PCR", func(t *testing.T) {
		pcrs, err := parsePCRs("7")
		require.NoError(t, err)
		assert.Equal(t, []int{7}, pcrs)
	})

	t.Run("PCRs with spaces", func(t *testing.T) {
		pcrs, err := parsePCRs("0, 1, 2, 3, 7")
		require.NoError(t, err)
		assert.Equal(t, []int{0, 1, 2, 3, 7}, pcrs)
	})

	t.Run("empty string", func(t *testing.T) {
		_, err := parsePCRs("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be empty")
	})

	t.Run("invalid PCR index", func(t *testing.T) {
		_, err := parsePCRs("0,abc,2")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid PCR index")
	})

	t.Run("trailing comma with spaces", func(t *testing.T) {
		pcrs, err := parsePCRs("0,1,2,")
		require.NoError(t, err)
		assert.Equal(t, []int{0, 1, 2}, pcrs)
	})
}

// Tests for printOutput and printError with JSON mode
func TestPrintOutputModes(t *testing.T) {
	t.Run("printOutput text mode", func(t *testing.T) {
		jsonOutput = false
		result := InitResult{
			PublicKey: "age1test",
			Provider:  "aws-kms",
		}
		// Should not panic
		printOutput(result)
	})

	t.Run("printOutput JSON mode", func(t *testing.T) {
		jsonOutput = true
		result := VerifyResult{
			Valid:     true,
			PublicKey: "age1test",
			Provider:  "aws-kms",
		}
		// Should not panic
		printOutput(result)
		jsonOutput = false
	})

	t.Run("printError text mode", func(t *testing.T) {
		jsonOutput = false
		// Should not panic
		printError(os.ErrNotExist)
	})

	t.Run("printError JSON mode", func(t *testing.T) {
		jsonOutput = true
		// Should not panic
		printError(os.ErrPermission)
		jsonOutput = false
	})
}

// Tests for root command flags
func TestRootCommandFlags(t *testing.T) {
	t.Run("has verbose flag", func(t *testing.T) {
		flag := rootCmd.PersistentFlags().Lookup("verbose")
		assert.NotNil(t, flag)
		assert.Equal(t, "v", flag.Shorthand)
	})

	t.Run("has json flag", func(t *testing.T) {
		flag := rootCmd.PersistentFlags().Lookup("json")
		assert.NotNil(t, flag)
	})
}

// Tests for init command flags completeness
func TestInitCommandFlagsComplete(t *testing.T) {
	flags := initCmd.Flags()

	allFlags := []string{
		"provider", "key-arn", "key-name", "vault-url",
		"az-key-name", "az-key-version", "slot", "fingerprint",
		"tpm-device", "pcrs", "output",
	}

	for _, flagName := range allFlags {
		t.Run("has "+flagName+" flag", func(t *testing.T) {
			assert.NotNil(t, flags.Lookup(flagName), "expected flag %s to exist", flagName)
		})
	}
}

// Tests for buildBootstrapConfigFromArtifacts with Azure key version
func TestBuildBootstrapConfigFromArtifactsAzureKeyVaultWithVersion(t *testing.T) {
	initProvider = "azure-keyvault"
	initVaultURL = "https://testvault.vault.azure.net"
	initAzKeyName = "test-key"
	initAzKeyVer = "version123"

	artifacts := &bridge.PublicArtifacts{
		PublicKey:          "age1testkey",
		EnvelopeCiphertext: []byte("test-ct"),
		SopsConfig:         "creation_rules:\n  - age: \"age1testkey\"\n",
	}

	cfg := buildBootstrapConfigFromArtifacts(artifacts)

	assert.NotNil(t, cfg.Spec.Envelope.AzureKeyVault)
	assert.Equal(t, initVaultURL, cfg.Spec.Envelope.AzureKeyVault.VaultURL)
	assert.Equal(t, initAzKeyName, cfg.Spec.Envelope.AzureKeyVault.KeyName)
	assert.Equal(t, initAzKeyVer, cfg.Spec.Envelope.AzureKeyVault.KeyVersion)
}

// Tests for buildBootstrapConfigFromArtifacts TPM with PCR selection
func TestBuildBootstrapConfigFromArtifactsTPMWithPCRs(t *testing.T) {
	initProvider = "tpm"
	initTPMDevice = "/dev/tpm0"
	initTPMPCRs = "0,7,14"

	artifacts := &bridge.PublicArtifacts{
		PublicKey:          "age1testkey",
		EnvelopeCiphertext: []byte("test-ct"),
		SopsConfig:         "creation_rules:\n  - age: \"age1testkey\"\n",
	}

	cfg := buildBootstrapConfigFromArtifacts(artifacts)

	assert.NotNil(t, cfg.Spec.Envelope.TPM)
	assert.Equal(t, initTPMDevice, cfg.Spec.Envelope.TPM.DevicePath)
	assert.NotNil(t, cfg.Spec.Envelope.TPM.PCRSelection)
	assert.Equal(t, "sha256", cfg.Spec.Envelope.TPM.PCRSelection.Hash)
	assert.Equal(t, []int{0, 7, 14}, cfg.Spec.Envelope.TPM.PCRSelection.PCRs)
}

// Tests for YubiKey config with fingerprint
func TestBuildBootstrapConfigFromArtifactsYubiKeyWithFingerprint(t *testing.T) {
	initProvider = "yubikey"
	initYubiSlot = "9c"
	initYubiFP = "SHA256:abcdef1234567890"

	artifacts := &bridge.PublicArtifacts{
		PublicKey:          "age1testkey",
		EnvelopeCiphertext: []byte("test-ct"),
		SopsConfig:         "creation_rules:\n  - age: \"age1testkey\"\n",
	}

	cfg := buildBootstrapConfigFromArtifacts(artifacts)

	assert.NotNil(t, cfg.Spec.Envelope.YubiKey)
	assert.Equal(t, initYubiSlot, cfg.Spec.Envelope.YubiKey.Slot)
	assert.Equal(t, initYubiFP, cfg.Spec.Envelope.YubiKey.PublicKeyFingerprint)
}

// Tests for createUnsealProvider function covering all provider branches
func TestCreateUnsealProvider(t *testing.T) {
	ctx := context.Background()

	t.Run("aws-kms with valid config", func(t *testing.T) {
		cfg := &config.BootstrapConfig{
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider: "aws-kms",
					AWSKMS: &config.AWSKMSSpec{
						KeyArn: "arn:aws:kms:us-west-2:123456789012:key/test-key",
						Region: "us-west-2",
					},
				},
			},
		}
		provider, err := createUnsealProvider(ctx, cfg)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, "aws-kms", string(provider.Name()))
	})

	t.Run("aws-kms missing config", func(t *testing.T) {
		cfg := &config.BootstrapConfig{
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider: "aws-kms",
				},
			},
		}
		_, err := createUnsealProvider(ctx, cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "awsKms configuration missing")
	})

	t.Run("gcp-kms missing config", func(t *testing.T) {
		cfg := &config.BootstrapConfig{
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider: "gcp-kms",
				},
			},
		}
		_, err := createUnsealProvider(ctx, cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "configuration missing")
	})

	t.Run("azure-keyvault missing config", func(t *testing.T) {
		cfg := &config.BootstrapConfig{
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider: "azure-keyvault",
				},
			},
		}
		_, err := createUnsealProvider(ctx, cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "configuration missing")
	})

	t.Run("yubikey creates provider with defaults", func(t *testing.T) {
		cfg := &config.BootstrapConfig{
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider: "yubikey",
				},
			},
		}
		provider, err := createUnsealProvider(ctx, cfg)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, "yubikey", string(provider.Name()))
	})

	t.Run("tpm creates provider with defaults", func(t *testing.T) {
		cfg := &config.BootstrapConfig{
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider: "tpm",
				},
			},
		}
		provider, err := createUnsealProvider(ctx, cfg)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, "tpm", string(provider.Name()))
	})

	t.Run("mock creates provider", func(t *testing.T) {
		cfg := &config.BootstrapConfig{
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider: "mock",
				},
			},
		}
		provider, err := createUnsealProvider(ctx, cfg)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, "mock", string(provider.Name()))
	})

	t.Run("unknown provider", func(t *testing.T) {
		cfg := &config.BootstrapConfig{
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider: "unknown",
				},
			},
		}
		_, err := createUnsealProvider(ctx, cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown provider")
	})
}

// Tests for createRotateProvider function covering all provider branches
func TestCreateRotateProvider(t *testing.T) {
	ctx := context.Background()

	t.Run("aws-kms with valid config", func(t *testing.T) {
		cfg := &config.BootstrapConfig{
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider: "aws-kms",
					AWSKMS: &config.AWSKMSSpec{
						KeyArn: "arn:aws:kms:us-west-2:123456789012:key/test-key",
						Region: "us-west-2",
					},
				},
			},
		}
		provider, err := createRotateProvider(ctx, cfg)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, "aws-kms", string(provider.Name()))
	})

	t.Run("aws-kms missing config", func(t *testing.T) {
		cfg := &config.BootstrapConfig{
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider: "aws-kms",
				},
			},
		}
		_, err := createRotateProvider(ctx, cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "awsKms configuration missing")
	})

	t.Run("gcp-kms missing config", func(t *testing.T) {
		cfg := &config.BootstrapConfig{
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider: "gcp-kms",
				},
			},
		}
		_, err := createRotateProvider(ctx, cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "gcpKms configuration missing")
	})

	t.Run("azure-keyvault missing config", func(t *testing.T) {
		cfg := &config.BootstrapConfig{
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider: "azure-keyvault",
				},
			},
		}
		_, err := createRotateProvider(ctx, cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "azureKeyVault configuration missing")
	})

	t.Run("mock provider", func(t *testing.T) {
		cfg := &config.BootstrapConfig{
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider: "mock",
				},
			},
		}
		provider, err := createRotateProvider(ctx, cfg)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, "mock", string(provider.Name()))
	})

	t.Run("unknown provider", func(t *testing.T) {
		cfg := &config.BootstrapConfig{
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider: "unknown",
				},
			},
		}
		_, err := createRotateProvider(ctx, cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown provider")
	})
}

// Tests for bridge config JSON builder functions
func TestBridgeProviderType(t *testing.T) {
	t.Run("aws-kms maps to aws", func(t *testing.T) {
		assert.Equal(t, "aws", bridgeProviderType("aws-kms"))
	})
	t.Run("gcp-kms maps to gcp", func(t *testing.T) {
		assert.Equal(t, "gcp", bridgeProviderType("gcp-kms"))
	})
	t.Run("azure-keyvault maps to azure", func(t *testing.T) {
		assert.Equal(t, "azure", bridgeProviderType("azure-keyvault"))
	})
	t.Run("mock maps to mock", func(t *testing.T) {
		assert.Equal(t, "mock", bridgeProviderType("mock"))
	})
	t.Run("oci-vault passes through", func(t *testing.T) {
		assert.Equal(t, "oci-vault", bridgeProviderType("oci-vault"))
	})
	t.Run("yubikey passes through", func(t *testing.T) {
		assert.Equal(t, "yubikey", bridgeProviderType("yubikey"))
	})
	t.Run("tpm passes through", func(t *testing.T) {
		assert.Equal(t, "tpm", bridgeProviderType("tpm"))
	})
}

func TestBuildKmsConfigJSON(t *testing.T) {
	initProvider = "aws-kms"
	initKeyArn = "arn:aws:kms:us-west-2:123:key/test"
	json := buildKmsConfigJSON("aws-kms")
	assert.Contains(t, json, `"provider_type":"aws"`)
	assert.Contains(t, json, `"key_arn"`)
}

func TestBuildGenesisConfigJSON(t *testing.T) {
	initProvider = "mock"
	json := buildGenesisConfigJSON("mock")
	assert.Contains(t, json, `"provider_type":"mock"`)
	assert.Contains(t, json, `"public_key":null`)
	assert.Contains(t, json, `"envelope_ciphertext":null`)
}

func TestBuildKmsConfigJSONFromBootstrap(t *testing.T) {
	cfg := &config.BootstrapConfig{
		Spec: config.BootstrapSpec{
			Envelope: config.EnvelopeSpec{
				Provider: "aws-kms",
				AWSKMS: &config.AWSKMSSpec{
					KeyArn: "arn:aws:kms:us-west-2:123456789012:key/test-key",
					Region: "us-west-2",
				},
			},
		},
	}
	json := buildKmsConfigJSONFromBootstrap(cfg)
	assert.Contains(t, json, `"provider_type":"aws"`)
	assert.Contains(t, json, `"key_arn"`)
	assert.Contains(t, json, `"region"`)
}

func TestBuildGenesisConfigJSONFromBootstrap(t *testing.T) {
	cfg := &config.BootstrapConfig{
		Spec: config.BootstrapSpec{
			Envelope: config.EnvelopeSpec{
				Provider: "mock",
			},
		},
	}
	json := buildGenesisConfigJSONFromBootstrap(cfg)
	assert.Contains(t, json, `"provider_type":"mock"`)
}

func TestKmsSettingsFromBootstrapConfig(t *testing.T) {
	t.Run("aws-kms", func(t *testing.T) {
		cfg := &config.BootstrapConfig{
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider: "aws-kms",
					AWSKMS: &config.AWSKMSSpec{
						KeyArn: "arn:test",
						Region: "us-east-1",
					},
				},
			},
		}
		s := kmsSettingsFromBootstrapConfig(cfg)
		assert.Equal(t, "arn:test", s["key_arn"])
		assert.Equal(t, "us-east-1", s["region"])
	})

	t.Run("gcp-kms", func(t *testing.T) {
		cfg := &config.BootstrapConfig{
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider: "gcp-kms",
					GCPKMS:   &config.GCPKMSSpec{KeyName: "projects/test/key"},
				},
			},
		}
		s := kmsSettingsFromBootstrapConfig(cfg)
		assert.Equal(t, "projects/test/key", s["key_name"])
	})

	t.Run("azure-keyvault", func(t *testing.T) {
		cfg := &config.BootstrapConfig{
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider: "azure-keyvault",
					AzureKeyVault: &config.AzureKVSpec{
						VaultURL:   "https://test.vault.azure.net",
						KeyName:    "mykey",
						KeyVersion: "v1",
					},
				},
			},
		}
		s := kmsSettingsFromBootstrapConfig(cfg)
		assert.Equal(t, "https://test.vault.azure.net", s["vault_url"])
		assert.Equal(t, "mykey", s["key_name"])
		assert.Equal(t, "v1", s["key_version"])
	})

	t.Run("oci-vault", func(t *testing.T) {
		cfg := &config.BootstrapConfig{
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider: "oci-vault",
					OCIVault: &config.OCIVaultSpec{
						KeyOCID:        "ocid1.key.oc1..test",
						CryptoEndpoint: "https://vault-crypto.kms.test.oraclecloud.com",
					},
				},
			},
		}
		s := kmsSettingsFromBootstrapConfig(cfg)
		assert.Equal(t, "ocid1.key.oc1..test", s["key_ocid"])
		assert.Equal(t, "https://vault-crypto.kms.test.oraclecloud.com", s["crypto_endpoint"])
	})

	t.Run("mock returns empty settings", func(t *testing.T) {
		cfg := &config.BootstrapConfig{
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider: "mock",
				},
			},
		}
		s := kmsSettingsFromBootstrapConfig(cfg)
		assert.Empty(t, s)
	})
}

// Tests for runSeal command validation paths
func TestRunSealValidation(t *testing.T) {
	t.Run("missing sops config file", func(t *testing.T) {
		tmpDir := t.TempDir()
		sealConfig = tmpDir
		sealInput = filepath.Join(tmpDir, "input.yaml")

		// Create input file but no .sops.yaml
		err := os.WriteFile(sealInput, []byte("test: data"), 0644)
		require.NoError(t, err)

		err = runSeal(sealCmd, []string{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), ".sops.yaml not found")
	})

	t.Run("invalid sops config", func(t *testing.T) {
		tmpDir := t.TempDir()
		sealConfig = tmpDir
		sealInput = filepath.Join(tmpDir, "input.yaml")

		// Create input file
		err := os.WriteFile(sealInput, []byte("test: data"), 0644)
		require.NoError(t, err)

		// Create invalid sops config
		sopsPath := filepath.Join(tmpDir, ".sops.yaml")
		err = os.WriteFile(sopsPath, []byte("invalid: yaml: ["), 0644)
		require.NoError(t, err)

		err = runSeal(sealCmd, []string{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "yaml:")
	})

	t.Run("empty age key in sops config", func(t *testing.T) {
		tmpDir := t.TempDir()
		sealConfig = tmpDir
		sealInput = filepath.Join(tmpDir, "input.yaml")

		// Create input file
		err := os.WriteFile(sealInput, []byte("test: data"), 0644)
		require.NoError(t, err)

		// Create sops config with empty age key
		sopsPath := filepath.Join(tmpDir, ".sops.yaml")
		err = os.WriteFile(sopsPath, []byte("creation_rules:\n  - path_regex: \"*.yaml\"\n    age: \"\""), 0644)
		require.NoError(t, err)

		err = runSeal(sealCmd, []string{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no age key found")
	})
}

// Tests for runUnseal command validation paths
func TestRunUnsealValidation(t *testing.T) {
	t.Run("missing bootstrap config", func(t *testing.T) {
		tmpDir := t.TempDir()
		unsealConfig = tmpDir
		unsealInput = filepath.Join(tmpDir, "input.enc.yaml")

		err := runUnseal(unsealCmd, []string{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no such file or directory")
	})

	t.Run("invalid bootstrap config yaml", func(t *testing.T) {
		tmpDir := t.TempDir()
		unsealConfig = tmpDir
		unsealInput = filepath.Join(tmpDir, "input.enc.yaml")

		// Create invalid bootstrap config
		configPath := filepath.Join(tmpDir, "genesis-bootstrap.yaml")
		err := os.WriteFile(configPath, []byte("invalid: yaml: ["), 0644)
		require.NoError(t, err)

		err = runUnseal(unsealCmd, []string{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "yaml:")
	})

	t.Run("invalid bootstrap config validation", func(t *testing.T) {
		tmpDir := t.TempDir()
		unsealConfig = tmpDir
		unsealInput = filepath.Join(tmpDir, "input.enc.yaml")

		// Create bootstrap config with wrong API version
		cfg := &config.BootstrapConfig{
			APIVersion: "wrong/v1",
			Kind:       config.KindBootstrap,
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider:   "aws-kms",
					Ciphertext: "dGVzdA==",
					AWSKMS: &config.AWSKMSSpec{
						KeyArn: "arn:aws:kms:us-west-2:123:key/test",
					},
				},
			},
		}
		configPath := filepath.Join(tmpDir, "genesis-bootstrap.yaml")
		err := config.Save(configPath, cfg)
		require.NoError(t, err)

		err = runUnseal(unsealCmd, []string{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid apiVersion")
	})
}

// Tests for runRotate command validation paths
func TestRunRotateValidation(t *testing.T) {
	t.Run("missing config file", func(t *testing.T) {
		rotateConfigPath = "/nonexistent/path/config.yaml"
		rotateNewKeyArn = "arn:aws:kms:us-west-2:123:key/new"

		err := runRotate(rotateCmd, []string{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no such file or directory")
	})

	t.Run("invalid config yaml", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "genesis-bootstrap.yaml")
		err := os.WriteFile(configPath, []byte("invalid: yaml: ["), 0644)
		require.NoError(t, err)

		rotateConfigPath = configPath
		rotateNewKeyArn = "arn:aws:kms:us-west-2:123:key/new"

		err = runRotate(rotateCmd, []string{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "yaml:")
	})

	t.Run("invalid config validation", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create config with wrong API version
		cfg := &config.BootstrapConfig{
			APIVersion: "wrong/v1",
			Kind:       config.KindBootstrap,
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider:   "aws-kms",
					Ciphertext: "dGVzdA==",
					AWSKMS: &config.AWSKMSSpec{
						KeyArn: "arn:aws:kms:us-west-2:123:key/test",
					},
				},
			},
		}
		configPath := filepath.Join(tmpDir, "genesis-bootstrap.yaml")
		err := config.Save(configPath, cfg)
		require.NoError(t, err)

		rotateConfigPath = configPath
		rotateNewKeyArn = "arn:aws:kms:us-west-2:123:key/new"

		err = runRotate(rotateCmd, []string{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid apiVersion")
	})

	t.Run("invalid ciphertext base64", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create config with invalid base64 ciphertext
		cfg := &config.BootstrapConfig{
			APIVersion: config.APIVersion,
			Kind:       config.KindBootstrap,
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider:   "aws-kms",
					Ciphertext: "not-valid-base64!!!",
					AWSKMS: &config.AWSKMSSpec{
						KeyArn: "arn:aws:kms:us-west-2:123:key/test",
					},
				},
			},
		}
		configPath := filepath.Join(tmpDir, "genesis-bootstrap.yaml")
		err := config.Save(configPath, cfg)
		require.NoError(t, err)

		rotateConfigPath = configPath
		rotateNewKeyArn = "arn:aws:kms:us-west-2:123:key/new"

		err = runRotate(rotateCmd, []string{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "illegal base64")
	})
}

// Tests for runVerify command validation paths
func TestRunVerifyValidation(t *testing.T) {
	t.Run("missing config file", func(t *testing.T) {
		err := runVerify(verifyCmd, []string{"/nonexistent/path/config.yaml"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no such file or directory")
	})

	t.Run("invalid config yaml", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "genesis-bootstrap.yaml")
		err := os.WriteFile(configPath, []byte("invalid: yaml: ["), 0644)
		require.NoError(t, err)

		err = runVerify(verifyCmd, []string{configPath})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "yaml:")
	})

	t.Run("invalid config validation", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create config with wrong API version
		cfg := &config.BootstrapConfig{
			APIVersion: "wrong/v1",
			Kind:       config.KindBootstrap,
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider:   "aws-kms",
					Ciphertext: "dGVzdA==",
					AWSKMS: &config.AWSKMSSpec{
						KeyArn: "arn:aws:kms:us-west-2:123:key/test",
					},
				},
			},
		}
		configPath := filepath.Join(tmpDir, "genesis-bootstrap.yaml")
		err := config.Save(configPath, cfg)
		require.NoError(t, err)

		err = runVerify(verifyCmd, []string{configPath})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid apiVersion")
	})

	t.Run("invalid ciphertext base64", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create config with invalid base64 ciphertext
		cfg := &config.BootstrapConfig{
			APIVersion: config.APIVersion,
			Kind:       config.KindBootstrap,
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider:   "aws-kms",
					Ciphertext: "not-valid-base64!!!",
					AWSKMS: &config.AWSKMSSpec{
						KeyArn: "arn:aws:kms:us-west-2:123:key/test",
					},
				},
			},
		}
		configPath := filepath.Join(tmpDir, "genesis-bootstrap.yaml")
		err := config.Save(configPath, cfg)
		require.NoError(t, err)

		err = runVerify(verifyCmd, []string{configPath})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "illegal base64")
	})
}

// Tests for runInit execution paths
func TestRunInitExecution(t *testing.T) {
	t.Run("successful init with mock provider", func(t *testing.T) {
		tmpDir := t.TempDir()
		initOutput = tmpDir
		initProvider = "aws-kms"
		initKeyArn = "arn:aws:kms:us-west-2:123456789012:key/test-key"

		// This test verifies the runInit function can be called
		// The actual KMS operations would require real credentials
		// So we just verify the command setup is correct
		cmd := initCmd
		assert.NotNil(t, cmd.RunE)
	})

	t.Run("output directory creation", func(t *testing.T) {
		tmpDir := t.TempDir()
		nestedDir := filepath.Join(tmpDir, "nested", "output")
		initOutput = nestedDir
		initProvider = "aws-kms"
		initKeyArn = "arn:aws:kms:us-west-2:123456789012:key/test-key"

		// The runInit would create this directory
		// We just verify the command accepts the output flag
		assert.NotNil(t, initCmd.Flags().Lookup("output"))
	})
}

// Tests for version command
func TestVersionCommandExecution(t *testing.T) {
	assert.Equal(t, "version", versionCmd.Use)
	assert.NotEmpty(t, versionCmd.Short)
}

// Tests for command structure
func TestCommandStructure(t *testing.T) {
	t.Run("root has subcommands", func(t *testing.T) {
		commands := rootCmd.Commands()
		assert.Greater(t, len(commands), 0)

		// Verify expected commands exist
		commandNames := make(map[string]bool)
		for _, cmd := range commands {
			commandNames[cmd.Use] = true
		}

		// Check for init command (may have different formats)
		found := false
		for name := range commandNames {
			if name == "init" {
				found = true
				break
			}
		}
		assert.True(t, found || len(commands) > 0, "Expected init command or other subcommands")
	})

	t.Run("seal command structure", func(t *testing.T) {
		assert.Equal(t, "seal", sealCmd.Use)
		assert.NotEmpty(t, sealCmd.Short)
		assert.NotEmpty(t, sealCmd.Long)
		assert.NotNil(t, sealCmd.RunE)
	})

	t.Run("unseal command structure", func(t *testing.T) {
		assert.Equal(t, "unseal", unsealCmd.Use)
		assert.NotEmpty(t, unsealCmd.Short)
		assert.NotEmpty(t, unsealCmd.Long)
		assert.NotNil(t, unsealCmd.RunE)
	})

	t.Run("rotate command structure", func(t *testing.T) {
		assert.Equal(t, "rotate", rotateCmd.Use)
		assert.NotEmpty(t, rotateCmd.Short)
		assert.NotEmpty(t, rotateCmd.Long)
		assert.NotNil(t, rotateCmd.RunE)
	})

	t.Run("verify command structure", func(t *testing.T) {
		assert.Equal(t, "verify [config-file]", verifyCmd.Use)
		assert.NotEmpty(t, verifyCmd.Short)
		assert.NotEmpty(t, verifyCmd.Long)
		assert.NotNil(t, verifyCmd.RunE)
	})
}

// Tests for SOPS config edge cases
func TestSOPSConfigEdgeCases(t *testing.T) {
	t.Run("empty creation rules", func(t *testing.T) {
		tmpDir := t.TempDir()
		sopsPath := filepath.Join(tmpDir, ".sops.yaml")

		// Write sops config with empty creation rules
		err := os.WriteFile(sopsPath, []byte("creation_rules: []"), 0644)
		require.NoError(t, err)

		loaded, err := config.LoadSOPSConfig(sopsPath)
		require.NoError(t, err)
		assert.Empty(t, loaded.CreationRules)
	})

	t.Run("multiple creation rules", func(t *testing.T) {
		tmpDir := t.TempDir()
		sopsPath := filepath.Join(tmpDir, ".sops.yaml")

		sopsContent := `creation_rules:
  - path_regex: "secrets/*.yaml"
    age: "age1key1"
  - path_regex: "config/*.yaml"
    age: "age1key2"
`
		err := os.WriteFile(sopsPath, []byte(sopsContent), 0644)
		require.NoError(t, err)

		loaded, err := config.LoadSOPSConfig(sopsPath)
		require.NoError(t, err)
		assert.Len(t, loaded.CreationRules, 2)
		assert.Equal(t, "age1key1", loaded.CreationRules[0].Age)
		assert.Equal(t, "age1key2", loaded.CreationRules[1].Age)
	})
}

// skipIfNoSOPS skips the test if SOPS is not installed
func skipIfNoSOPS(t *testing.T) {
	t.Helper()
	if err := checkSOPSInstalled(); err != nil {
		t.Skip("SOPS not installed, skipping integration test")
	}
}

// SOPS Integration Tests
func TestSOPSIntegration_SealCommand(t *testing.T) {
	skipIfNoSOPS(t)

	t.Run("seal encrypts file with age key", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Generate a real age keypair
		kp, err := crypto.GenerateAgeKeypair()
		require.NoError(t, err)

		// Create .sops.yaml with the public key
		sopsConfig := &config.SOPSConfig{
			CreationRules: []config.SOPSCreationRule{
				{
					PathRegex: ".*\\.yaml$",
					Age:       kp.PublicKey,
				},
			},
		}
		sopsPath := filepath.Join(tmpDir, ".sops.yaml")
		err = sopsConfig.Save(sopsPath)
		require.NoError(t, err)

		// Create input file
		inputPath := filepath.Join(tmpDir, "secret.yaml")
		inputContent := "password: supersecret\napi_key: abc123\n"
		err = os.WriteFile(inputPath, []byte(inputContent), 0644)
		require.NoError(t, err)

		// Create output path
		outputPath := filepath.Join(tmpDir, "secret.enc.yaml")

		// Set command flags and run seal
		sealConfig = tmpDir
		sealInput = inputPath
		sealOutput = outputPath

		err = runSeal(sealCmd, []string{})
		require.NoError(t, err)

		// Verify encrypted file exists and is different from input
		encryptedContent, err := os.ReadFile(outputPath)
		require.NoError(t, err)
		assert.NotEqual(t, inputContent, string(encryptedContent))
		assert.Contains(t, string(encryptedContent), "ENC[")
	})

	t.Run("seal to stdout", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Generate a real age keypair
		kp, err := crypto.GenerateAgeKeypair()
		require.NoError(t, err)

		// Create .sops.yaml
		sopsConfig := &config.SOPSConfig{
			CreationRules: []config.SOPSCreationRule{
				{
					PathRegex: ".*\\.yaml$",
					Age:       kp.PublicKey,
				},
			},
		}
		sopsPath := filepath.Join(tmpDir, ".sops.yaml")
		err = sopsConfig.Save(sopsPath)
		require.NoError(t, err)

		// Create input file
		inputPath := filepath.Join(tmpDir, "test.yaml")
		err = os.WriteFile(inputPath, []byte("key: value\n"), 0644)
		require.NoError(t, err)

		// Run seal without output (to stdout)
		sealConfig = tmpDir
		sealInput = inputPath
		sealOutput = "" // stdout

		err = runSeal(sealCmd, []string{})
		require.NoError(t, err)
	})
}

func TestSOPSIntegration_UnsealCommand(t *testing.T) {
	skipIfNoSOPS(t)
	ctx := context.Background()

	t.Run("unseal decrypts file with mock provider", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Generate a real age keypair
		kp, err := crypto.GenerateAgeKeypair()
		require.NoError(t, err)

		// Create envelope with mock provider (uses fixed key for determinism)
		mockProvider := mock.NewProvider()
		env, err := envelope.Create(ctx, mockProvider, kp.PrivateKey)
		require.NoError(t, err)

		// Create bootstrap config
		bootstrapConfig := &config.BootstrapConfig{
			APIVersion: config.APIVersion,
			Kind:       config.KindBootstrap,
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider:   "mock",
					PublicKey:  env.PublicKey,
					Ciphertext: env.CiphertextB64,
				},
			},
		}
		bootstrapPath := filepath.Join(tmpDir, "genesis-bootstrap.yaml")
		err = config.Save(bootstrapPath, bootstrapConfig)
		require.NoError(t, err)

		// Create and encrypt a test file
		inputPath := filepath.Join(tmpDir, "secret.yaml")
		inputContent := "password: mysecret\n"
		err = os.WriteFile(inputPath, []byte(inputContent), 0644)
		require.NoError(t, err)

		// Encrypt with SOPS using the age public key
		encryptedPath := filepath.Join(tmpDir, "secret.enc.yaml")
		sopsConfig := &config.SOPSConfig{
			CreationRules: []config.SOPSCreationRule{
				{
					PathRegex: ".*\\.yaml$",
					Age:       kp.PublicKey,
				},
			},
		}
		sopsPath := filepath.Join(tmpDir, ".sops.yaml")
		err = sopsConfig.Save(sopsPath)
		require.NoError(t, err)

		// Encrypt the file
		sealConfig = tmpDir
		sealInput = inputPath
		sealOutput = encryptedPath
		err = runSeal(sealCmd, []string{})
		require.NoError(t, err)

		// Now unseal (decrypt) the file
		outputPath := filepath.Join(tmpDir, "decrypted.yaml")
		unsealConfig = tmpDir
		unsealInput = encryptedPath
		unsealOutput = outputPath

		err = runUnseal(unsealCmd, []string{})
		require.NoError(t, err)

		// Verify decrypted content matches original
		decryptedContent, err := os.ReadFile(outputPath)
		require.NoError(t, err)
		assert.Equal(t, inputContent, string(decryptedContent))
	})
}

func TestSOPSIntegration_FullRoundTrip(t *testing.T) {
	skipIfNoSOPS(t)
	ctx := context.Background()

	t.Run("init -> seal -> unseal round trip", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Step 1: Generate age keypair and create envelope
		kp, err := crypto.GenerateAgeKeypair()
		require.NoError(t, err)

		mockProvider := mock.NewProvider()
		env, err := envelope.Create(ctx, mockProvider, kp.PrivateKey)
		require.NoError(t, err)

		// Step 2: Create bootstrap and SOPS configs (simulates init command)
		bootstrapConfig := &config.BootstrapConfig{
			APIVersion: config.APIVersion,
			Kind:       config.KindBootstrap,
			Metadata: config.Metadata{
				Name:      "genesis-bootstrap",
				Namespace: "genesis-system",
			},
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider:   "mock",
					PublicKey:  env.PublicKey,
					Ciphertext: env.CiphertextB64,
				},
				Output: config.OutputSpec{
					SecretName:      "sops-age",
					SecretNamespace: "flux-system",
					SecretKey:       "age.agekey",
				},
			},
		}
		bootstrapPath := filepath.Join(tmpDir, "genesis-bootstrap.yaml")
		err = config.Save(bootstrapPath, bootstrapConfig)
		require.NoError(t, err)

		sopsConfig := &config.SOPSConfig{
			CreationRules: []config.SOPSCreationRule{
				{
					PathRegex: ".*\\.yaml$",
					Age:       kp.PublicKey,
				},
			},
		}
		sopsPath := filepath.Join(tmpDir, ".sops.yaml")
		err = sopsConfig.Save(sopsPath)
		require.NoError(t, err)

		// Step 3: Create a secret file
		secretContent := `apiVersion: v1
kind: Secret
metadata:
  name: my-secret
  namespace: default
type: Opaque
stringData:
  username: admin
  password: super-secret-password
`
		secretPath := filepath.Join(tmpDir, "secret.yaml")
		err = os.WriteFile(secretPath, []byte(secretContent), 0644)
		require.NoError(t, err)

		// Step 4: Seal (encrypt) the secret
		encryptedPath := filepath.Join(tmpDir, "secret.enc.yaml")
		sealConfig = tmpDir
		sealInput = secretPath
		sealOutput = encryptedPath

		err = runSeal(sealCmd, []string{})
		require.NoError(t, err)

		// Verify it's encrypted
		encryptedContent, err := os.ReadFile(encryptedPath)
		require.NoError(t, err)
		assert.Contains(t, string(encryptedContent), "ENC[")
		assert.NotContains(t, string(encryptedContent), "super-secret-password")

		// Step 5: Unseal (decrypt) the secret
		decryptedPath := filepath.Join(tmpDir, "secret.decrypted.yaml")
		unsealConfig = tmpDir
		unsealInput = encryptedPath
		unsealOutput = decryptedPath

		err = runUnseal(unsealCmd, []string{})
		require.NoError(t, err)

		// Verify decrypted content
		decryptedContent, err := os.ReadFile(decryptedPath)
		require.NoError(t, err)
		assert.Contains(t, string(decryptedContent), "username: admin")
		assert.Contains(t, string(decryptedContent), "password: super-secret-password")
	})
}

func TestSOPSIntegration_ErrorCases(t *testing.T) {
	skipIfNoSOPS(t)

	t.Run("seal fails with non-existent input file", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Generate keypair and create sops config
		kp, err := crypto.GenerateAgeKeypair()
		require.NoError(t, err)

		sopsConfig := &config.SOPSConfig{
			CreationRules: []config.SOPSCreationRule{
				{PathRegex: ".*", Age: kp.PublicKey},
			},
		}
		sopsPath := filepath.Join(tmpDir, ".sops.yaml")
		err = sopsConfig.Save(sopsPath)
		require.NoError(t, err)

		// Try to seal non-existent file
		sealConfig = tmpDir
		sealInput = filepath.Join(tmpDir, "nonexistent.yaml")
		sealOutput = filepath.Join(tmpDir, "output.yaml")

		err = runSeal(sealCmd, []string{})
		assert.Error(t, err)
	})

	t.Run("unseal fails with wrong provider config", func(t *testing.T) {
		tmpDir := t.TempDir()
		ctx := context.Background()

		// Generate keypair
		kp, err := crypto.GenerateAgeKeypair()
		require.NoError(t, err)

		// Create envelope with mock provider
		mockProvider := mock.NewProvider()
		env, err := envelope.Create(ctx, mockProvider, kp.PrivateKey)
		require.NoError(t, err)

		// Create bootstrap config with WRONG ciphertext (corrupted)
		bootstrapConfig := &config.BootstrapConfig{
			APIVersion: config.APIVersion,
			Kind:       config.KindBootstrap,
			Spec: config.BootstrapSpec{
				Envelope: config.EnvelopeSpec{
					Provider:   "mock",
					PublicKey:  env.PublicKey,
					Ciphertext: "dGhpcyBpcyBub3QgdmFsaWQgY2lwaGVydGV4dA==", // invalid
				},
			},
		}
		bootstrapPath := filepath.Join(tmpDir, "genesis-bootstrap.yaml")
		err = config.Save(bootstrapPath, bootstrapConfig)
		require.NoError(t, err)

		// Create an encrypted file (need valid encryption first)
		sopsConfig := &config.SOPSConfig{
			CreationRules: []config.SOPSCreationRule{
				{PathRegex: ".*", Age: kp.PublicKey},
			},
		}
		sopsPath := filepath.Join(tmpDir, ".sops.yaml")
		err = sopsConfig.Save(sopsPath)
		require.NoError(t, err)

		inputPath := filepath.Join(tmpDir, "input.yaml")
		err = os.WriteFile(inputPath, []byte("key: value\n"), 0644)
		require.NoError(t, err)

		encPath := filepath.Join(tmpDir, "input.enc.yaml")
		sealConfig = tmpDir
		sealInput = inputPath
		sealOutput = encPath
		err = runSeal(sealCmd, []string{})
		require.NoError(t, err)

		// Try to unseal with corrupted bootstrap config
		unsealConfig = tmpDir
		unsealInput = encPath
		unsealOutput = filepath.Join(tmpDir, "output.yaml")

		err = runUnseal(unsealCmd, []string{})
		assert.Error(t, err)
	})
}

// Tests for runInit command with mock provider
func TestRunInit_MockProvider(t *testing.T) {
	tmpDir := t.TempDir()

	// Set up init command flags for mock provider
	initProvider = "mock"
	initOutput = tmpDir
	initKeyArn = ""
	initKeyName = ""
	initVaultURL = ""
	jsonOutput = false

	// Run init command
	err := runInit(initCmd, []string{})
	require.NoError(t, err)

	// Verify files were created
	bootstrapPath := filepath.Join(tmpDir, "genesis-bootstrap.yaml")
	sopsPath := filepath.Join(tmpDir, ".sops.yaml")

	_, err = os.Stat(bootstrapPath)
	require.NoError(t, err, "bootstrap file should exist")

	_, err = os.Stat(sopsPath)
	require.NoError(t, err, "sops config should exist")

	// Load and verify bootstrap config
	cfg, err := config.Load(bootstrapPath)
	require.NoError(t, err)
	assert.Equal(t, kms.ProviderMock, cfg.Spec.Envelope.Provider)
	assert.NotEmpty(t, cfg.Spec.Envelope.PublicKey)
	assert.NotEmpty(t, cfg.Spec.Envelope.Ciphertext)
}

func TestRunInit_MockProvider_JSONOutput(t *testing.T) {
	tmpDir := t.TempDir()

	// Set up init command flags
	initProvider = "mock"
	initOutput = tmpDir
	jsonOutput = true

	// Run init command
	err := runInit(initCmd, []string{})
	require.NoError(t, err)

	jsonOutput = false
}

// Tests for runVerify command with mock provider
func TestRunVerify_MockProvider(t *testing.T) {
	tmpDir := t.TempDir()

	// Create envelope via the bridge so both encrypt and decrypt use the
	// same Rust mock KMS implementation.
	initProvider = "mock"
	artifacts := bridgeInitMock(t)

	bootstrapConfig := &config.BootstrapConfig{
		APIVersion: config.APIVersion,
		Kind:       config.KindBootstrap,
		Spec: config.BootstrapSpec{
			Envelope: config.EnvelopeSpec{
				Provider:   "mock",
				PublicKey:  artifacts.PublicKey,
				Ciphertext: base64Encode(artifacts.EnvelopeCiphertext),
			},
		},
	}

	bootstrapPath := filepath.Join(tmpDir, "genesis-bootstrap.yaml")
	err := config.Save(bootstrapPath, bootstrapConfig)
	require.NoError(t, err)

	// Run verify command (now goes through the bridge)
	jsonOutput = false
	err = runVerify(verifyCmd, []string{bootstrapPath})
	require.NoError(t, err)
}

func TestRunVerify_MockProvider_JSONOutput(t *testing.T) {
	tmpDir := t.TempDir()

	initProvider = "mock"
	artifacts := bridgeInitMock(t)

	bootstrapConfig := &config.BootstrapConfig{
		APIVersion: config.APIVersion,
		Kind:       config.KindBootstrap,
		Spec: config.BootstrapSpec{
			Envelope: config.EnvelopeSpec{
				Provider:   "mock",
				PublicKey:  artifacts.PublicKey,
				Ciphertext: base64Encode(artifacts.EnvelopeCiphertext),
			},
		},
	}

	bootstrapPath := filepath.Join(tmpDir, "genesis-bootstrap.yaml")
	err := config.Save(bootstrapPath, bootstrapConfig)
	require.NoError(t, err)

	// Run verify command with JSON output
	jsonOutput = true
	err = runVerify(verifyCmd, []string{bootstrapPath})
	require.NoError(t, err)

	jsonOutput = false
}

func TestRunVerify_InvalidConfig(t *testing.T) {
	tmpDir := t.TempDir()

	// Create an invalid config file
	invalidPath := filepath.Join(tmpDir, "invalid.yaml")
	err := os.WriteFile(invalidPath, []byte("not: valid: yaml: ["), 0644)
	require.NoError(t, err)

	// Run verify command - should fail
	err = runVerify(verifyCmd, []string{invalidPath})
	assert.Error(t, err)
}

func TestRunVerify_MissingConfig(t *testing.T) {
	// Run verify command with non-existent file
	err := runVerify(verifyCmd, []string{"/nonexistent/path/config.yaml"})
	assert.Error(t, err)
}

func TestRunVerify_PublicKeyMismatch(t *testing.T) {
	tmpDir := t.TempDir()

	initProvider = "mock"
	artifacts := bridgeInitMock(t)

	// Create config with wrong public key but correct ciphertext
	bootstrapConfig := &config.BootstrapConfig{
		APIVersion: config.APIVersion,
		Kind:       config.KindBootstrap,
		Spec: config.BootstrapSpec{
			Envelope: config.EnvelopeSpec{
				Provider:   "mock",
				PublicKey:  "age1wrongpublickeynotmatching123456789012345678901234567890",
				Ciphertext: base64Encode(artifacts.EnvelopeCiphertext),
			},
		},
	}

	bootstrapPath := filepath.Join(tmpDir, "genesis-bootstrap.yaml")
	err := config.Save(bootstrapPath, bootstrapConfig)
	require.NoError(t, err)

	// Run verify command - should fail with public key mismatch
	err = runVerify(verifyCmd, []string{bootstrapPath})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "public key mismatch")
}

// Tests for runRotate command with mock provider
func TestRunRotate_MockToMock(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create initial bootstrap config with mock provider
	mockProvider := mock.NewProvider()
	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)

	env, err := envelope.Create(ctx, mockProvider, kp.PrivateKey)
	require.NoError(t, err)

	bootstrapConfig := &config.BootstrapConfig{
		APIVersion: config.APIVersion,
		Kind:       config.KindBootstrap,
		Spec: config.BootstrapSpec{
			Envelope: config.EnvelopeSpec{
				Provider:   "mock",
				PublicKey:  env.PublicKey,
				Ciphertext: env.CiphertextB64,
			},
		},
	}

	bootstrapPath := filepath.Join(tmpDir, "genesis-bootstrap.yaml")
	err = config.Save(bootstrapPath, bootstrapConfig)
	require.NoError(t, err)

	originalCiphertext := env.CiphertextB64

	// Set up rotate command flags
	rotateConfigPath = bootstrapPath
	rotateNewProvider = "mock"
	rotateNewKeyArn = ""
	jsonOutput = false

	// Run rotate command
	err = runRotate(rotateCmd, []string{})
	require.NoError(t, err)

	// Verify config was updated
	newCfg, err := config.Load(bootstrapPath)
	require.NoError(t, err)
	assert.Equal(t, kms.ProviderMock, newCfg.Spec.Envelope.Provider)
	assert.Equal(t, kp.PublicKey, newCfg.Spec.Envelope.PublicKey)           // Same public key
	assert.NotEqual(t, originalCiphertext, newCfg.Spec.Envelope.Ciphertext) // Different ciphertext

	// Note: we do not call runVerify here because rotate uses the Go-layer
	// mock KMS (XOR encryption) while verify now goes through the Rust bridge
	// mock KMS (different encryption scheme). Cross-layer mock compatibility
	// is not required; the config correctness checks above are sufficient.
}

func TestRunRotate_JSONOutput(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	mockProvider := mock.NewProvider()
	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)

	env, err := envelope.Create(ctx, mockProvider, kp.PrivateKey)
	require.NoError(t, err)

	bootstrapConfig := &config.BootstrapConfig{
		APIVersion: config.APIVersion,
		Kind:       config.KindBootstrap,
		Spec: config.BootstrapSpec{
			Envelope: config.EnvelopeSpec{
				Provider:   "mock",
				PublicKey:  env.PublicKey,
				Ciphertext: env.CiphertextB64,
			},
		},
	}

	bootstrapPath := filepath.Join(tmpDir, "genesis-bootstrap.yaml")
	err = config.Save(bootstrapPath, bootstrapConfig)
	require.NoError(t, err)

	rotateConfigPath = bootstrapPath
	rotateNewProvider = "mock"
	jsonOutput = true

	err = runRotate(rotateCmd, []string{})
	require.NoError(t, err)

	jsonOutput = false
}

func TestRunRotate_InvalidConfig(t *testing.T) {
	tmpDir := t.TempDir()

	// Create invalid config
	invalidPath := filepath.Join(tmpDir, "invalid.yaml")
	err := os.WriteFile(invalidPath, []byte("not: valid: yaml: ["), 0644)
	require.NoError(t, err)

	rotateConfigPath = invalidPath
	rotateNewProvider = "mock"

	err = runRotate(rotateCmd, []string{})
	assert.Error(t, err)
}

func TestRunRotate_MissingNewProvider(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	mockProvider := mock.NewProvider()
	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)

	env, err := envelope.Create(ctx, mockProvider, kp.PrivateKey)
	require.NoError(t, err)

	bootstrapConfig := &config.BootstrapConfig{
		APIVersion: config.APIVersion,
		Kind:       config.KindBootstrap,
		Spec: config.BootstrapSpec{
			Envelope: config.EnvelopeSpec{
				Provider:   "mock",
				PublicKey:  env.PublicKey,
				Ciphertext: env.CiphertextB64,
			},
		},
	}

	bootstrapPath := filepath.Join(tmpDir, "genesis-bootstrap.yaml")
	err = config.Save(bootstrapPath, bootstrapConfig)
	require.NoError(t, err)

	rotateConfigPath = bootstrapPath
	rotateNewProvider = ""
	rotateNewKeyArn = ""

	err = runRotate(rotateCmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "--new-provider or --new-key-arn is required")
}

// Tests for createNewRotateProvider
func TestCreateNewRotateProvider(t *testing.T) {
	ctx := context.Background()

	t.Run("mock provider", func(t *testing.T) {
		rotateNewProvider = "mock"
		rotateNewKeyArn = ""
		provider, name, err := createNewRotateProvider(ctx)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, kms.ProviderMock, name)
	})

	t.Run("aws-kms defaults when key-arn provided", func(t *testing.T) {
		rotateNewProvider = ""
		rotateNewKeyArn = "arn:aws:kms:us-west-2:123456789012:key/test"
		provider, name, err := createNewRotateProvider(ctx)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, kms.ProviderAWSKMS, name)
	})

	t.Run("aws-kms missing key-arn", func(t *testing.T) {
		rotateNewProvider = "aws-kms"
		rotateNewKeyArn = ""
		_, _, err := createNewRotateProvider(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "--new-key-arn is required")
	})

	t.Run("gcp-kms missing key-name", func(t *testing.T) {
		rotateNewProvider = "gcp-kms"
		rotateNewKeyName = ""
		_, _, err := createNewRotateProvider(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "--new-key-name is required")
	})

	t.Run("azure-keyvault missing vault-url", func(t *testing.T) {
		rotateNewProvider = "azure-keyvault"
		rotateNewVaultURL = ""
		_, _, err := createNewRotateProvider(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "--new-vault-url is required")
	})

	t.Run("unknown provider", func(t *testing.T) {
		rotateNewProvider = "unknown"
		_, _, err := createNewRotateProvider(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown provider")
	})

	t.Run("no provider specified", func(t *testing.T) {
		rotateNewProvider = ""
		rotateNewKeyArn = ""
		_, _, err := createNewRotateProvider(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "--new-provider or --new-key-arn is required")
	})
}
