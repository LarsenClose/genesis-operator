package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/larsenclose/genesis/internal/bridge"
	"github.com/larsenclose/genesis/internal/config"
	"github.com/larsenclose/genesis/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── runInitLocal integration tests ──────────────────────────────────

func TestRunInitLocal(t *testing.T) {
	tmpDir := t.TempDir()
	envPath := filepath.Join(tmpDir, "master-key.enc")

	origProvider := initProvider
	origEnvPath := initEnvelopePath
	origOutput := initOutput
	origJSON := jsonOutput
	defer func() {
		initProvider = origProvider
		initEnvelopePath = origEnvPath
		initOutput = origOutput
		jsonOutput = origJSON
	}()

	initProvider = "local"
	initEnvelopePath = envPath
	initOutput = tmpDir
	jsonOutput = false

	err := runInitLocal()
	require.NoError(t, err)

	// Verify bootstrap config was written and is valid
	bootstrapPath := filepath.Join(tmpDir, "genesis-bootstrap.yaml")
	cfg, err := config.Load(bootstrapPath)
	require.NoError(t, err)
	assert.Equal(t, kms.ProviderLocal, cfg.Spec.Envelope.Provider)
	assert.True(t, strings.HasPrefix(cfg.Spec.Envelope.PublicKey, "age1"))
	assert.NotEmpty(t, cfg.Spec.Envelope.MLKEMPublicKey)
	assert.NotEmpty(t, cfg.Spec.Envelope.SigningPublicKey)
	assert.Equal(t, envPath, cfg.Spec.Envelope.EnvelopePath)
	assert.NoError(t, cfg.Validate())

	// Verify SOPS config
	sopsPath := filepath.Join(tmpDir, ".sops.yaml")
	sopsConfig, err := config.LoadSOPSConfig(sopsPath)
	require.NoError(t, err)
	require.Len(t, sopsConfig.CreationRules, 1)
	assert.Equal(t, cfg.Spec.Envelope.PublicKey, sopsConfig.CreationRules[0].Age)

	// Verify envelope file
	info, err := os.Stat(envPath)
	require.NoError(t, err)
	assert.Greater(t, info.Size(), int64(0))

	// Verify identity file
	identityPath := filepath.Join(tmpDir, "genesis-identity.key")
	idData, err := os.ReadFile(identityPath)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(strings.TrimSpace(string(idData)), "AGE-SECRET-KEY-1"))

	// Verify file permissions (0600)
	idInfo, err := os.Stat(identityPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), idInfo.Mode().Perm())
}

func TestRunInitLocalJSONOutput(t *testing.T) {
	tmpDir := t.TempDir()
	envPath := filepath.Join(tmpDir, "master-key.enc")

	origProvider := initProvider
	origEnvPath := initEnvelopePath
	origOutput := initOutput
	origJSON := jsonOutput
	defer func() {
		initProvider = origProvider
		initEnvelopePath = origEnvPath
		initOutput = origOutput
		jsonOutput = origJSON
	}()

	initProvider = "local"
	initEnvelopePath = envPath
	initOutput = tmpDir
	jsonOutput = true

	err := runInitLocal()
	require.NoError(t, err)

	// Verify all files were still created
	_, err = os.Stat(filepath.Join(tmpDir, "genesis-bootstrap.yaml"))
	assert.NoError(t, err)
	_, err = os.Stat(filepath.Join(tmpDir, ".sops.yaml"))
	assert.NoError(t, err)
	_, err = os.Stat(filepath.Join(tmpDir, "genesis-identity.key"))
	assert.NoError(t, err)
}

// ── runInit dispatches to local provider ────────────────────────────

func TestRunInitDispatchesLocal(t *testing.T) {
	tmpDir := t.TempDir()
	envPath := filepath.Join(tmpDir, "master-key.enc")

	origProvider := initProvider
	origEnvPath := initEnvelopePath
	origOutput := initOutput
	origJSON := jsonOutput
	defer func() {
		initProvider = origProvider
		initEnvelopePath = origEnvPath
		initOutput = origOutput
		jsonOutput = origJSON
	}()

	initProvider = "local"
	initEnvelopePath = envPath
	initOutput = tmpDir
	jsonOutput = false

	// runInit should dispatch to runInitLocal for local provider
	err := runInit(nil, nil)
	require.NoError(t, err)

	cfg, err := config.Load(filepath.Join(tmpDir, "genesis-bootstrap.yaml"))
	require.NoError(t, err)
	assert.Equal(t, kms.ProviderLocal, cfg.Spec.Envelope.Provider)
}

// ── buildLocalBootstrapConfig ───────────────────────────────────────

func TestBuildLocalBootstrapConfig(t *testing.T) {
	keys := &bridge.HybridPublicKeys{
		AgeRecipient:    "age1testkey",
		MLKEMPublicKey:  "mlkem-hex-data",
		SigningPublicKey: "mldsa-hex-data",
	}
	cfg := buildLocalBootstrapConfig(keys, "/tmp/envelope.enc")

	assert.Equal(t, config.APIVersion, cfg.APIVersion)
	assert.Equal(t, config.KindBootstrap, cfg.Kind)
	assert.Equal(t, "genesis-bootstrap", cfg.Metadata.Name)
	assert.Equal(t, "genesis-system", cfg.Metadata.Namespace)
	assert.Equal(t, kms.ProviderLocal, cfg.Spec.Envelope.Provider)
	assert.Equal(t, "age1testkey", cfg.Spec.Envelope.PublicKey)
	assert.Equal(t, "mlkem-hex-data", cfg.Spec.Envelope.MLKEMPublicKey)
	assert.Equal(t, "mldsa-hex-data", cfg.Spec.Envelope.SigningPublicKey)
	assert.Equal(t, "/tmp/envelope.enc", cfg.Spec.Envelope.EnvelopePath)
	assert.Equal(t, "sops-age", cfg.Spec.Output.SecretName)
	assert.Equal(t, "flux-system", cfg.Spec.Output.SecretNamespace)
	assert.Equal(t, "age.agekey", cfg.Spec.Output.SecretKey)

	// Validate the generated config
	assert.NoError(t, cfg.Validate())
}

// ── truncate ────────────────────────────────────────────────────────

func TestTruncate(t *testing.T) {
	tests := []struct {
		input string
		n     int
		want  string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is a longer string", 10, "this is a "},
		{"", 5, ""},
		{"ab", 1, "a"},
		{"hello", 5, "hello"},
	}
	for _, tt := range tests {
		got := truncate(tt.input, tt.n)
		assert.Equal(t, tt.want, got, "truncate(%q, %d)", tt.input, tt.n)
	}
}

// ── readLocalIdentity ───────────────────────────────────────────────

func TestReadLocalIdentityFromFlag(t *testing.T) {
	dir := t.TempDir()
	idPath := filepath.Join(dir, "id.txt")
	require.NoError(t, os.WriteFile(idPath, []byte("AGE-SECRET-KEY-1TESTKEY\n"), 0600))

	origIdentity := unsealIdentity
	defer func() { unsealIdentity = origIdentity }()
	unsealIdentity = idPath

	result, err := readLocalIdentity()
	require.NoError(t, err)
	assert.Equal(t, "AGE-SECRET-KEY-1TESTKEY", result)
}

func TestReadLocalIdentityFromEnv(t *testing.T) {
	origIdentity := unsealIdentity
	defer func() { unsealIdentity = origIdentity }()
	unsealIdentity = ""

	t.Setenv("SOPS_AGE_KEY", "AGE-SECRET-KEY-1ENVKEY")

	result, err := readLocalIdentity()
	require.NoError(t, err)
	assert.Equal(t, "AGE-SECRET-KEY-1ENVKEY", result)
}

func TestReadLocalIdentityFromEnvFile(t *testing.T) {
	dir := t.TempDir()
	idPath := filepath.Join(dir, "id.txt")
	require.NoError(t, os.WriteFile(idPath, []byte("AGE-SECRET-KEY-1FILEKEY\n"), 0600))

	origIdentity := unsealIdentity
	defer func() { unsealIdentity = origIdentity }()
	unsealIdentity = ""

	t.Setenv("SOPS_AGE_KEY", "")
	t.Setenv("SOPS_AGE_KEY_FILE", idPath)

	result, err := readLocalIdentity()
	require.NoError(t, err)
	assert.Equal(t, "AGE-SECRET-KEY-1FILEKEY", result)
}

func TestReadLocalIdentityMissing(t *testing.T) {
	origIdentity := unsealIdentity
	defer func() { unsealIdentity = origIdentity }()
	unsealIdentity = ""

	t.Setenv("SOPS_AGE_KEY", "")
	t.Setenv("SOPS_AGE_KEY_FILE", "")

	_, err := readLocalIdentity()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "local provider requires")
}

func TestReadLocalIdentityBadFile(t *testing.T) {
	origIdentity := unsealIdentity
	defer func() { unsealIdentity = origIdentity }()
	unsealIdentity = "/nonexistent/path/identity.txt"

	_, err := readLocalIdentity()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read identity file")
}

func TestReadLocalIdentityBadEnvFile(t *testing.T) {
	origIdentity := unsealIdentity
	defer func() { unsealIdentity = origIdentity }()
	unsealIdentity = ""

	t.Setenv("SOPS_AGE_KEY", "")
	t.Setenv("SOPS_AGE_KEY_FILE", "/nonexistent/path/identity.txt")

	_, err := readLocalIdentity()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read SOPS_AGE_KEY_FILE")
}

// ── validateInitProviderFlags local cases ───────────────────────────

func TestValidateInitProviderFlagsLocal(t *testing.T) {
	t.Run("local with valid envelope path", func(t *testing.T) {
		origProvider := initProvider
		origEnvPath := initEnvelopePath
		defer func() {
			initProvider = origProvider
			initEnvelopePath = origEnvPath
		}()

		initProvider = "local"
		initEnvelopePath = "/tmp/master.enc"
		err := validateInitProviderFlags()
		assert.NoError(t, err)
	})

	t.Run("local missing envelope path", func(t *testing.T) {
		origProvider := initProvider
		origEnvPath := initEnvelopePath
		defer func() {
			initProvider = origProvider
			initEnvelopePath = origEnvPath
		}()

		initProvider = "local"
		initEnvelopePath = ""
		err := validateInitProviderFlags()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "--envelope-path is required")
	})
}

// ── bridgeProviderType local case ───────────────────────────────────

func TestBridgeProviderTypeLocal(t *testing.T) {
	assert.Equal(t, "local", bridgeProviderType("local"))
}

// ── New flag existence checks ───────────────────────────────────────

func TestInitCommandHasEnvelopePathFlag(t *testing.T) {
	flags := initCmd.Flags()
	assert.NotNil(t, flags.Lookup("envelope-path"))
}

func TestUnsealCommandHasIdentityFlag(t *testing.T) {
	flags := unsealCmd.Flags()
	assert.NotNil(t, flags.Lookup("identity"))
}

// ── InitResult with IdentityFile field ──────────────────────────────

func TestInitResultLocalFields(t *testing.T) {
	result := InitResult{
		PublicKey:     "age1test",
		Provider:      "local",
		BootstrapFile: "/path/to/bootstrap.yaml",
		SOPSFile:      "/path/to/.sops.yaml",
		IdentityFile:  "/path/to/genesis-identity.key",
	}
	assert.Equal(t, "local", result.Provider)
	assert.Equal(t, "/path/to/genesis-identity.key", result.IdentityFile)
}

// ── OCI Vault case in buildBootstrapConfigFromArtifacts ─────────────

func TestBuildBootstrapConfigFromArtifactsOCIVault(t *testing.T) {
	origProvider := initProvider
	origOCIKeyOCID := initOCIKeyOCID
	origOCICryptoEP := initOCICryptoEP
	defer func() {
		initProvider = origProvider
		initOCIKeyOCID = origOCIKeyOCID
		initOCICryptoEP = origOCICryptoEP
	}()

	initProvider = "oci-vault"
	initOCIKeyOCID = "ocid1.key.oc1..test"
	initOCICryptoEP = "https://vault-crypto.kms.us-east-1.oraclecloud.com"

	artifacts := &bridge.PublicArtifacts{
		PublicKey:          "age1testkey",
		EnvelopeCiphertext: []byte("test-ct"),
		SopsConfig:         "creation_rules:\n  - age: \"age1testkey\"\n",
	}
	cfg := buildBootstrapConfigFromArtifacts(artifacts)

	assert.NotNil(t, cfg.Spec.Envelope.OCIVault)
	assert.Equal(t, "ocid1.key.oc1..test", cfg.Spec.Envelope.OCIVault.KeyOCID)
	assert.Equal(t, "https://vault-crypto.kms.us-east-1.oraclecloud.com", cfg.Spec.Envelope.OCIVault.CryptoEndpoint)
}

// ── OCI Vault valid case in validateInitProviderFlags ────────────────

func TestValidateInitProviderFlagsOCIVault(t *testing.T) {
	origProvider := initProvider
	origOCIKeyOCID := initOCIKeyOCID
	origOCICryptoEP := initOCICryptoEP
	defer func() {
		initProvider = origProvider
		initOCIKeyOCID = origOCIKeyOCID
		initOCICryptoEP = origOCICryptoEP
	}()

	initProvider = "oci-vault"
	initOCIKeyOCID = "ocid1.key.oc1..test"
	initOCICryptoEP = "https://vault-crypto.kms.us-east-1.oraclecloud.com"
	err := validateInitProviderFlags()
	assert.NoError(t, err)
}

// ── buildKmsSettings exercises different providers ──────────────────

func TestBuildKmsSettingsLocal(t *testing.T) {
	s := buildKmsSettings("local")
	assert.Empty(t, s, "local provider should return empty settings")
}

func TestBuildKmsSettingsOCIVault(t *testing.T) {
	origOCIKeyOCID := initOCIKeyOCID
	origOCICryptoEP := initOCICryptoEP
	defer func() {
		initOCIKeyOCID = origOCIKeyOCID
		initOCICryptoEP = origOCICryptoEP
	}()

	initOCIKeyOCID = "ocid1.key.oc1..test"
	initOCICryptoEP = "https://vault-crypto.kms.us-east-1.oraclecloud.com"

	s := buildKmsSettings("oci-vault")
	assert.Equal(t, "ocid1.key.oc1..test", s["key_ocid"])
	assert.Equal(t, "https://vault-crypto.kms.us-east-1.oraclecloud.com", s["crypto_endpoint"])
}

func TestBuildKmsSettingsYubiKey(t *testing.T) {
	origSlot := initYubiSlot
	origFP := initYubiFP
	defer func() {
		initYubiSlot = origSlot
		initYubiFP = origFP
	}()

	initYubiSlot = "9c"
	initYubiFP = "SHA256:abc123"

	s := buildKmsSettings("yubikey")
	assert.Equal(t, "9c", s["slot"])
	assert.Equal(t, "SHA256:abc123", s["fingerprint"])
}

func TestBuildKmsSettingsTPM(t *testing.T) {
	origDevice := initTPMDevice
	origPCRs := initTPMPCRs
	defer func() {
		initTPMDevice = origDevice
		initTPMPCRs = origPCRs
	}()

	initTPMDevice = "/dev/tpmrm0"
	initTPMPCRs = "0,1,7"

	s := buildKmsSettings("tpm")
	assert.Equal(t, "/dev/tpmrm0", s["device_path"])
	assert.Equal(t, "0,1,7", s["pcrs"])
}

func TestBuildKmsSettingsGCPKMS(t *testing.T) {
	origKeyName := initKeyName
	defer func() {
		initKeyName = origKeyName
	}()

	initKeyName = "projects/test/locations/global/keyRings/test/cryptoKeys/key"

	s := buildKmsSettings("gcp-kms")
	assert.Equal(t, initKeyName, s["key_name"])
}

func TestBuildKmsSettingsAzureKeyVault(t *testing.T) {
	origVaultURL := initVaultURL
	origAzKeyName := initAzKeyName
	origAzKeyVer := initAzKeyVer
	defer func() {
		initVaultURL = origVaultURL
		initAzKeyName = origAzKeyName
		initAzKeyVer = origAzKeyVer
	}()

	initVaultURL = "https://testvault.vault.azure.net"
	initAzKeyName = "mykey"
	initAzKeyVer = "v1"

	s := buildKmsSettings("azure-keyvault")
	assert.Equal(t, "https://testvault.vault.azure.net", s["vault_url"])
	assert.Equal(t, "mykey", s["key_name"])
	assert.Equal(t, "v1", s["key_version"])
}

func TestBuildKmsSettingsAzureKeyVaultNoVersion(t *testing.T) {
	origVaultURL := initVaultURL
	origAzKeyName := initAzKeyName
	origAzKeyVer := initAzKeyVer
	defer func() {
		initVaultURL = origVaultURL
		initAzKeyName = origAzKeyName
		initAzKeyVer = origAzKeyVer
	}()

	initVaultURL = "https://testvault.vault.azure.net"
	initAzKeyName = "mykey"
	initAzKeyVer = ""

	s := buildKmsSettings("azure-keyvault")
	assert.Equal(t, "https://testvault.vault.azure.net", s["vault_url"])
	assert.Equal(t, "mykey", s["key_name"])
	_, hasVersion := s["key_version"]
	assert.False(t, hasVersion, "should not include key_version when empty")
}
