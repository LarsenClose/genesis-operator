//go:build genesis_mock

package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/larsenclose/genesis/internal/bridge"
	"github.com/larsenclose/genesis/internal/config"
	"github.com/larsenclose/genesis/internal/kms"
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
