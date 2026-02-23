package bridge

import (
	"encoding/json"
	"testing"
)

func TestNewAndFree(t *testing.T) {
	configJSON := `{"provider_type":"mock","provider_config":{}}`
	h, err := New(configJSON)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer h.Free()

	if h.State() != StateUninitialized {
		t.Errorf("expected Uninitialized, got %v", h.State())
	}
}

func TestStateString(t *testing.T) {
	tests := []struct {
		s    State
		want string
	}{
		{StateUninitialized, "Uninitialized"},
		{StateInitialized, "Initialized"},
		{StateBootstrapping, "Bootstrapping"},
		{StateActive, "Active"},
		{StateRotating, "Rotating"},
		{StateDegraded, "Degraded"},
		{State(99), "Unknown(99)"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("State(%d).String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}

func TestInitWithMockKMS(t *testing.T) {
	configJSON := `{"provider_type":"mock","provider_config":{}}`
	h, err := New(configJSON)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer h.Free()

	kmsJSON := `{"provider_type":"mock"}`
	artifacts, err := h.Init(kmsJSON)
	if err != nil {
		t.Fatalf("Init() failed: %v", err)
	}

	if h.State() != StateInitialized {
		t.Errorf("expected Initialized, got %v", h.State())
	}

	if artifacts.PublicKey == "" {
		t.Error("expected non-empty public key")
	}
	if len(artifacts.EnvelopeCiphertext) == 0 {
		t.Error("expected non-empty envelope ciphertext")
	}
	if artifacts.SopsConfig == "" {
		t.Error("expected non-empty SOPS config")
	}

	t.Logf("public key: %s", artifacts.PublicKey)
	t.Logf("sops config: %s", artifacts.SopsConfig)
}

func TestFullLifecycle(t *testing.T) {
	configJSON := `{"provider_type":"mock","provider_config":{}}`
	kmsJSON := `{"provider_type":"mock"}`

	// 1. New -> Uninitialized
	h, err := New(configJSON)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer h.Free()

	// 2. Init -> Initialized
	artifacts, err := h.Init(kmsJSON)
	if err != nil {
		t.Fatalf("Init() failed: %v", err)
	}
	if h.State() != StateInitialized {
		t.Fatalf("expected Initialized, got %v", h.State())
	}
	_ = artifacts

	// 3. BeginBootstrap -> Bootstrapping
	if err := h.BeginBootstrap(kmsJSON); err != nil {
		t.Fatalf("BeginBootstrap() failed: %v", err)
	}
	if h.State() != StateBootstrapping {
		t.Fatalf("expected Bootstrapping, got %v", h.State())
	}

	// 4. InjectSecret -> Active
	if err := h.InjectSecret("test-secret", "default", "age-key"); err != nil {
		t.Fatalf("InjectSecret() failed: %v", err)
	}
	if h.State() != StateActive {
		t.Fatalf("expected Active, got %v", h.State())
	}

	// 5. Status (using simple version without out-param)
	status, err := h.Status()
	if err != nil {
		t.Fatalf("Status() failed: %v", err)
	}
	if !status.HasEnvelope {
		t.Error("expected has_envelope to be true")
	}
	if status.PublicKey == nil {
		t.Error("expected public_key to be set")
	}

	// 6. BeginRotation -> Rotating
	if err := h.BeginRotation(); err != nil {
		t.Fatalf("BeginRotation() failed: %v", err)
	}
	if h.State() != StateRotating {
		t.Fatalf("expected Rotating, got %v", h.State())
	}

	// 7. CompleteRotation -> Active (with new key)
	newArtifacts, err := h.CompleteRotation(kmsJSON, "new-secret", "default", "age-key")
	if err != nil {
		t.Fatalf("CompleteRotation() failed: %v", err)
	}
	if h.State() != StateActive {
		t.Fatalf("expected Active after rotation, got %v", h.State())
	}
	if newArtifacts.PublicKey == artifacts.PublicKey {
		t.Error("expected rotation to produce a different public key")
	}
}

func TestLoadAndVerify(t *testing.T) {
	configJSON := `{"provider_type":"mock","provider_config":{}}`
	kmsJSON := `{"provider_type":"mock"}`

	// Init to get artifacts
	h1, err := New(configJSON)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	artifacts, err := h1.Init(kmsJSON)
	if err != nil {
		t.Fatalf("Init() failed: %v", err)
	}
	h1.Free()

	// Load from persisted artifacts
	h2, err := New(configJSON)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer h2.Free()

	if err := h2.Load(artifacts.PublicKey, artifacts.EnvelopeCiphertext); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if h2.State() != StateInitialized {
		t.Fatalf("expected Initialized after Load, got %v", h2.State())
	}

	// Verify
	vr, err := h2.Verify(kmsJSON)
	if err != nil {
		t.Fatalf("Verify() failed: %v", err)
	}
	if !vr.PublicKeyMatches {
		t.Error("expected public key to match")
	}
	if vr.PublicKey != artifacts.PublicKey {
		t.Errorf("expected public key %q, got %q", artifacts.PublicKey, vr.PublicKey)
	}
}

func TestNewWithInvalidJSON(t *testing.T) {
	_, err := New("not-json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestWrongStateError(t *testing.T) {
	configJSON := `{"provider_type":"mock","provider_config":{}}`
	h, err := New(configJSON)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer h.Free()

	// Try to begin bootstrap from Uninitialized (wrong state)
	err = h.BeginBootstrap(`{"provider_type":"mock"}`)
	if err == nil {
		t.Fatal("expected error for wrong state")
	}
}

func TestArtifactsJSONRoundtrip(t *testing.T) {
	a := PublicArtifacts{
		PublicKey:          "age1test...",
		EnvelopeCiphertext: []byte{1, 2, 3},
		SopsConfig:         "creation_rules:\n  - age: 'age1test...'\n",
	}
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var a2 PublicArtifacts
	if err := json.Unmarshal(b, &a2); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if a2.PublicKey != a.PublicKey {
		t.Errorf("PublicKey mismatch: %q != %q", a2.PublicKey, a.PublicKey)
	}
}
