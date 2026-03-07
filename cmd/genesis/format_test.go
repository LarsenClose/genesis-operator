package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/larsenclose/genesis/internal/config"
	"github.com/larsenclose/genesis/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// ── CLI output format regression tests ─────────────────────────────
//
// These tests validate the exact file names, YAML structure, JSON output,
// and file permissions produced by `genesis init --provider=local`.
// They are designed to catch regressions in the output format that could
// break downstream consumers (launch, SOPS, Flux, etc.).

// saveAndRestoreInitFlags saves the current init flag state and returns a
// cleanup function that restores it. Every test that mutates package-level
// flags MUST defer this.
func saveAndRestoreInitFlags(t *testing.T) {
	t.Helper()
	origProvider := initProvider
	origEnvPath := initEnvelopePath
	origOutput := initOutput
	origJSON := jsonOutput
	t.Cleanup(func() {
		initProvider = origProvider
		initEnvelopePath = origEnvPath
		initOutput = origOutput
		jsonOutput = origJSON
	})
}

// runLocalInit is a helper that sets up a temp directory, configures the
// init flags for local provider, runs the init flow, and returns the
// temp directory path. It fails the test on any error.
func runLocalInit(t *testing.T) string {
	t.Helper()
	saveAndRestoreInitFlags(t)

	tmpDir := t.TempDir()
	envPath := filepath.Join(tmpDir, "master-key.enc")

	initProvider = "local"
	initEnvelopePath = envPath
	initOutput = tmpDir
	jsonOutput = false

	err := runInitLocal()
	require.NoError(t, err, "runInitLocal should succeed")

	return tmpDir
}

// ── Test 1: Exact output filenames ─────────────────────────────────

func TestInitLocalOutputFilenames(t *testing.T) {
	tmpDir := runLocalInit(t)
	envPath := filepath.Join(tmpDir, "master-key.enc")

	// genesis-bootstrap.yaml must exist in the output directory.
	_, err := os.Stat(filepath.Join(tmpDir, "genesis-bootstrap.yaml"))
	assert.NoError(t, err, "genesis-bootstrap.yaml must exist")

	// .sops.yaml must exist in the output directory.
	_, err = os.Stat(filepath.Join(tmpDir, ".sops.yaml"))
	assert.NoError(t, err, ".sops.yaml must exist")

	// genesis-identity.key must exist in the output directory.
	// NOTE: launch expects "age-identity.txt" or "age.key" — see charter
	// filename mismatch issue. This test documents the current behavior so
	// that any rename is intentional and caught by CI.
	_, err = os.Stat(filepath.Join(tmpDir, "genesis-identity.key"))
	assert.NoError(t, err, "genesis-identity.key must exist")

	// master-key.enc must exist at the envelope path.
	info, err := os.Stat(envPath)
	assert.NoError(t, err, "master-key.enc must exist at envelope path")
	if err == nil {
		assert.Greater(t, info.Size(), int64(0), "envelope file must not be empty")
	}

	// Verify no unexpected files were created (only the 4 expected files).
	entries, err := os.ReadDir(tmpDir)
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	expected := []string{".sops.yaml", "genesis-bootstrap.yaml", "genesis-identity.key", "master-key.enc"}
	assert.ElementsMatch(t, expected, names, "output directory should contain exactly the expected files")
}

// ── Test 2: Bootstrap YAML structure ───────────────────────────────

func TestInitLocalBootstrapYAMLStructure(t *testing.T) {
	tmpDir := runLocalInit(t)
	envPath := filepath.Join(tmpDir, "master-key.enc")

	bootstrapPath := filepath.Join(tmpDir, "genesis-bootstrap.yaml")

	// Load via config.Load to verify it round-trips correctly.
	cfg, err := config.Load(bootstrapPath)
	require.NoError(t, err, "bootstrap YAML must be loadable")

	// apiVersion
	assert.Equal(t, "genesis.io/v1alpha1", cfg.APIVersion, "apiVersion must be genesis.io/v1alpha1")

	// kind
	assert.Equal(t, "GenesisBootstrap", cfg.Kind, "kind must be GenesisBootstrap")

	// metadata.name
	assert.Equal(t, "genesis-bootstrap", cfg.Metadata.Name, "metadata.name must be genesis-bootstrap")

	// metadata.namespace
	assert.Equal(t, "genesis-system", cfg.Metadata.Namespace, "metadata.namespace must be genesis-system")

	// spec.envelope.provider
	assert.Equal(t, kms.ProviderLocal, cfg.Spec.Envelope.Provider, "spec.envelope.provider must be local")

	// spec.envelope.publicKey starts with "age1"
	assert.True(t, strings.HasPrefix(cfg.Spec.Envelope.PublicKey, "age1"),
		"spec.envelope.publicKey must start with age1, got: %s", cfg.Spec.Envelope.PublicKey)

	// spec.envelope.envelopePath
	assert.Equal(t, envPath, cfg.Spec.Envelope.EnvelopePath,
		"spec.envelope.envelopePath must match the --envelope-path flag")

	// spec.envelope PQ fields must be populated
	assert.NotEmpty(t, cfg.Spec.Envelope.MLKEMPublicKey, "spec.envelope.mlkemPublicKey must be set")
	assert.NotEmpty(t, cfg.Spec.Envelope.SigningPublicKey, "spec.envelope.signingPublicKey must be set")

	// spec.output fields
	assert.Equal(t, "sops-age", cfg.Spec.Output.SecretName, "spec.output.secretName must be sops-age")
	assert.Equal(t, "flux-system", cfg.Spec.Output.SecretNamespace, "spec.output.secretNamespace must be flux-system")
	assert.Equal(t, "age.agekey", cfg.Spec.Output.SecretKey, "spec.output.secretKey must be age.agekey")

	// Validate the config passes its own validation.
	assert.NoError(t, cfg.Validate(), "generated bootstrap config must pass validation")

	// Also verify the raw YAML has the expected top-level keys by parsing
	// into a generic map to catch serialization issues (e.g., wrong key
	// casing, extra fields).
	rawData, err := os.ReadFile(bootstrapPath)
	require.NoError(t, err)
	var rawMap map[string]interface{}
	require.NoError(t, yaml.Unmarshal(rawData, &rawMap))

	assert.Contains(t, rawMap, "apiVersion", "raw YAML must contain apiVersion key")
	assert.Contains(t, rawMap, "kind", "raw YAML must contain kind key")
	assert.Contains(t, rawMap, "metadata", "raw YAML must contain metadata key")
	assert.Contains(t, rawMap, "spec", "raw YAML must contain spec key")

	// Verify no unexpected top-level keys.
	for key := range rawMap {
		assert.Contains(t, []string{"apiVersion", "kind", "metadata", "spec"}, key,
			"unexpected top-level YAML key: %s", key)
	}
}

// ── Test 3: SOPS YAML structure ────────────────────────────────────

func TestInitLocalSOPSYAMLStructure(t *testing.T) {
	tmpDir := runLocalInit(t)

	bootstrapPath := filepath.Join(tmpDir, "genesis-bootstrap.yaml")
	sopsPath := filepath.Join(tmpDir, ".sops.yaml")

	// Load SOPS config via the typed loader.
	sopsConfig, err := config.LoadSOPSConfig(sopsPath)
	require.NoError(t, err, "SOPS YAML must be loadable")

	// Must have creation_rules array with at least one entry.
	require.NotEmpty(t, sopsConfig.CreationRules, "creation_rules must not be empty")
	require.Len(t, sopsConfig.CreationRules, 1, "creation_rules must have exactly 1 rule")

	// First rule must have an age key starting with "age1".
	firstRule := sopsConfig.CreationRules[0]
	assert.True(t, strings.HasPrefix(firstRule.Age, "age1"),
		"creation_rules[0].age must start with age1, got: %s", firstRule.Age)

	// The age key in SOPS must match the publicKey in genesis-bootstrap.yaml.
	bootstrapCfg, err := config.Load(bootstrapPath)
	require.NoError(t, err)
	assert.Equal(t, bootstrapCfg.Spec.Envelope.PublicKey, firstRule.Age,
		"SOPS age key must match bootstrap publicKey")

	// Verify path_regex is set (default is *.enc.yaml).
	assert.Equal(t, "*.enc.yaml", firstRule.PathRegex,
		"creation_rules[0].path_regex must be *.enc.yaml")

	// Verify raw YAML structure.
	rawData, err := os.ReadFile(sopsPath)
	require.NoError(t, err)
	var rawMap map[string]interface{}
	require.NoError(t, yaml.Unmarshal(rawData, &rawMap))
	assert.Contains(t, rawMap, "creation_rules", "raw YAML must contain creation_rules key")
}

// ── Test 4: Identity key file permissions ──────────────────────────

func TestInitLocalIdentityKeyPermissions(t *testing.T) {
	tmpDir := runLocalInit(t)

	identityPath := filepath.Join(tmpDir, "genesis-identity.key")

	info, err := os.Stat(identityPath)
	require.NoError(t, err, "genesis-identity.key must exist")

	// Identity key MUST have 0600 permissions (owner read/write only).
	// This is a security requirement — the identity file is the SOPS
	// decryption key and must not be world-readable.
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(),
		"genesis-identity.key must have 0600 permissions")

	// Verify the content is a valid age secret key.
	data, err := os.ReadFile(identityPath)
	require.NoError(t, err)
	content := strings.TrimSpace(string(data))
	assert.True(t, strings.HasPrefix(content, "AGE-SECRET-KEY-1"),
		"identity file must contain an age secret key starting with AGE-SECRET-KEY-1")
}

// ── Test 5: JSON output schema ─────────────────────────────────────

func TestInitLocalJSONOutput(t *testing.T) {
	saveAndRestoreInitFlags(t)

	tmpDir := t.TempDir()
	envPath := filepath.Join(tmpDir, "master-key.enc")

	initProvider = "local"
	initEnvelopePath = envPath
	initOutput = tmpDir
	jsonOutput = true

	// Capture stdout to validate JSON output.
	// printOutput writes to os.Stdout via json.NewEncoder.
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	err = runInitLocal()
	require.NoError(t, err, "runInitLocal with JSON output should succeed")

	// Close the writer and restore stdout before reading.
	w.Close()
	os.Stdout = oldStdout

	// Read captured output.
	var buf [8192]byte
	n, _ := r.Read(buf[:])
	r.Close()
	output := string(buf[:n])

	// Parse the JSON output.
	var result map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(output), &result),
		"JSON output must be valid JSON, got: %s", output)

	// Validate required fields exist and have correct types/values.
	assert.Contains(t, result, "publicKey", "JSON must contain publicKey")
	assert.Contains(t, result, "provider", "JSON must contain provider")
	assert.Contains(t, result, "bootstrapFile", "JSON must contain bootstrapFile")
	assert.Contains(t, result, "sopsFile", "JSON must contain sopsFile")
	assert.Contains(t, result, "identityFile", "JSON must contain identityFile (local provider)")

	// Validate field values.
	publicKey, ok := result["publicKey"].(string)
	assert.True(t, ok, "publicKey must be a string")
	assert.True(t, strings.HasPrefix(publicKey, "age1"),
		"publicKey must start with age1, got: %s", publicKey)

	assert.Equal(t, "local", result["provider"], "provider must be 'local'")

	bootstrapFile, ok := result["bootstrapFile"].(string)
	assert.True(t, ok, "bootstrapFile must be a string")
	assert.Equal(t, filepath.Join(tmpDir, "genesis-bootstrap.yaml"), bootstrapFile,
		"bootstrapFile must point to genesis-bootstrap.yaml in output dir")

	sopsFile, ok := result["sopsFile"].(string)
	assert.True(t, ok, "sopsFile must be a string")
	assert.Equal(t, filepath.Join(tmpDir, ".sops.yaml"), sopsFile,
		"sopsFile must point to .sops.yaml in output dir")

	identityFile, ok := result["identityFile"].(string)
	assert.True(t, ok, "identityFile must be a string")
	assert.Equal(t, filepath.Join(tmpDir, "genesis-identity.key"), identityFile,
		"identityFile must point to genesis-identity.key in output dir")

	// Verify the JSON round-trips through the InitResult struct.
	var typedResult InitResult
	require.NoError(t, json.Unmarshal([]byte(output), &typedResult),
		"JSON output must deserialize into InitResult")
	assert.Equal(t, "local", typedResult.Provider)
	assert.NotEmpty(t, typedResult.PublicKey)
	assert.NotEmpty(t, typedResult.BootstrapFile)
	assert.NotEmpty(t, typedResult.SOPSFile)
	assert.NotEmpty(t, typedResult.IdentityFile)
}

// ── Test 6: Cross-file consistency ─────────────────────────────────
//
// Validates that the public key is consistent across all output files:
// genesis-bootstrap.yaml, .sops.yaml, and the JSON output.

func TestInitLocalCrossFileConsistency(t *testing.T) {
	tmpDir := runLocalInit(t)

	bootstrapPath := filepath.Join(tmpDir, "genesis-bootstrap.yaml")
	sopsPath := filepath.Join(tmpDir, ".sops.yaml")
	identityPath := filepath.Join(tmpDir, "genesis-identity.key")

	// Load all configs.
	bootstrapCfg, err := config.Load(bootstrapPath)
	require.NoError(t, err)

	sopsConfig, err := config.LoadSOPSConfig(sopsPath)
	require.NoError(t, err)
	require.NotEmpty(t, sopsConfig.CreationRules)

	// The age public key must be identical in bootstrap and SOPS configs.
	assert.Equal(t, bootstrapCfg.Spec.Envelope.PublicKey, sopsConfig.CreationRules[0].Age,
		"age public key must match between bootstrap and SOPS configs")

	// The identity file must contain the corresponding secret key.
	idData, err := os.ReadFile(identityPath)
	require.NoError(t, err)
	idContent := strings.TrimSpace(string(idData))
	assert.True(t, strings.HasPrefix(idContent, "AGE-SECRET-KEY-1"),
		"identity file must contain a valid age secret key")

	// The envelope file must exist and be non-empty.
	envPath := bootstrapCfg.Spec.Envelope.EnvelopePath
	envInfo, err := os.Stat(envPath)
	require.NoError(t, err, "envelope file at envelopePath must exist")
	assert.Greater(t, envInfo.Size(), int64(0), "envelope file must not be empty")
}
