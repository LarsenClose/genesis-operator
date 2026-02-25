package bridge

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

// ── PQ Hybrid Keyset Tests ──────────────────────────────────────────

func TestGenerateKeySet(t *testing.T) {
	ks, pubKeys, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet() failed: %v", err)
	}
	defer FreeKeySet(ks)

	if ks.ptr == nil {
		t.Fatal("expected non-nil keyset pointer")
	}
	if pubKeys.AgeRecipient == "" {
		t.Error("expected non-empty age_recipient")
	}
	if !strings.HasPrefix(pubKeys.AgeRecipient, "age1") {
		t.Errorf("expected age1 prefix, got %q", pubKeys.AgeRecipient)
	}
	if pubKeys.MLKEMPublicKey == "" {
		t.Error("expected non-empty mlkem_public_key")
	}
	if pubKeys.SigningPublicKey == "" {
		t.Error("expected non-empty signing_public_key")
	}

	t.Logf("age recipient: %s", pubKeys.AgeRecipient)
	t.Logf("ML-KEM public key length: %d", len(pubKeys.MLKEMPublicKey))
	t.Logf("ML-DSA signing key length: %d", len(pubKeys.SigningPublicKey))
}

func TestGetPublicKeys(t *testing.T) {
	ks, pubKeys1, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet() failed: %v", err)
	}
	defer FreeKeySet(ks)

	pubKeys2, err := GetPublicKeys(ks)
	if err != nil {
		t.Fatalf("GetPublicKeys() failed: %v", err)
	}

	if pubKeys1.AgeRecipient != pubKeys2.AgeRecipient {
		t.Errorf("age recipient mismatch: %q vs %q", pubKeys1.AgeRecipient, pubKeys2.AgeRecipient)
	}
	if pubKeys1.MLKEMPublicKey != pubKeys2.MLKEMPublicKey {
		t.Error("ML-KEM public key mismatch")
	}
	if pubKeys1.SigningPublicKey != pubKeys2.SigningPublicKey {
		t.Error("signing public key mismatch")
	}
}

func TestExportAgeIdentity(t *testing.T) {
	ks, _, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet() failed: %v", err)
	}
	defer FreeKeySet(ks)

	identity, err := ExportAgeIdentity(ks)
	if err != nil {
		t.Fatalf("ExportAgeIdentity() failed: %v", err)
	}

	if !strings.HasPrefix(identity, "AGE-SECRET-KEY-1") {
		t.Errorf("expected AGE-SECRET-KEY-1 prefix, got %q", identity[:20])
	}
	t.Logf("age identity: %s...%s", identity[:20], identity[len(identity)-4:])
}

func TestSealOpenHybrid(t *testing.T) {
	ks, _, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet() failed: %v", err)
	}
	defer FreeKeySet(ks)

	plaintext := []byte("hello, post-quantum world!")

	sealed, err := SealHybrid(ks, plaintext)
	if err != nil {
		t.Fatalf("SealHybrid() failed: %v", err)
	}
	if len(sealed) == 0 {
		t.Fatal("expected non-empty sealed output")
	}
	if bytes.Equal(sealed, plaintext) {
		t.Error("sealed output should differ from plaintext")
	}

	// Verify V2 magic header (GEN2)
	if !bytes.HasPrefix(sealed, []byte("GEN2")) {
		t.Errorf("expected GEN2 magic, got %q", sealed[:4])
	}

	opened, err := OpenHybrid(ks, sealed)
	if err != nil {
		t.Fatalf("OpenHybrid() failed: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Errorf("roundtrip mismatch: got %q, want %q", opened, plaintext)
	}
}

func TestSealOpenWrongKey(t *testing.T) {
	ks1, _, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet() #1 failed: %v", err)
	}
	defer FreeKeySet(ks1)

	ks2, _, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet() #2 failed: %v", err)
	}
	defer FreeKeySet(ks2)

	plaintext := []byte("secret data")
	sealed, err := SealHybrid(ks1, plaintext)
	if err != nil {
		t.Fatalf("SealHybrid() failed: %v", err)
	}

	// Opening with wrong key should fail
	_, err = OpenHybrid(ks2, sealed)
	if err == nil {
		t.Fatal("expected error when opening with wrong key")
	}
}

func TestGenerateLocalAndLoad(t *testing.T) {
	dir := t.TempDir()
	envelopePath := filepath.Join(dir, "master-key.enc")

	ks, _, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet() failed: %v", err)
	}
	defer FreeKeySet(ks)

	// Generate local KMS (creates master key envelope on disk)
	lk, err := GenerateLocal(ks, envelopePath)
	if err != nil {
		t.Fatalf("GenerateLocal() failed: %v", err)
	}
	FreeLocalKms(lk)

	// Verify envelope file exists
	info, err := os.Stat(envelopePath)
	if err != nil {
		t.Fatalf("envelope file not found: %v", err)
	}
	if info.Size() == 0 {
		t.Error("envelope file is empty")
	}
	t.Logf("envelope file size: %d bytes", info.Size())

	// Reload from disk
	lk2, err := LoadLocal(ks, envelopePath)
	if err != nil {
		t.Fatalf("LoadLocal() failed: %v", err)
	}
	FreeLocalKms(lk2)
}

func TestFreeKeySetNil(t *testing.T) {
	// Should be safe no-ops
	FreeKeySet(nil)
	FreeKeySet(&KeySetHandle{ptr: nil})
}

func TestFreeLocalKmsNil(t *testing.T) {
	FreeLocalKms(nil)
	FreeLocalKms(&LocalKmsHandle{ptr: nil})
}

func TestGetPublicKeysNilHandle(t *testing.T) {
	_, err := GetPublicKeys(nil)
	if err == nil {
		t.Error("expected error for nil handle")
	}
}

func TestExportAgeIdentityNilHandle(t *testing.T) {
	_, err := ExportAgeIdentity(nil)
	if err == nil {
		t.Error("expected error for nil handle")
	}
}

// ── PQ Error Path Tests ─────────────────────────────────────────────

func TestSealHybridNilKeyset(t *testing.T) {
	_, err := SealHybrid(nil, []byte("test"))
	if err == nil {
		t.Fatal("expected error for nil keyset")
	}
}

func TestSealHybridNilPtr(t *testing.T) {
	_, err := SealHybrid(&KeySetHandle{ptr: nil}, []byte("test"))
	if err == nil {
		t.Fatal("expected error for nil ptr keyset")
	}
}

func TestOpenHybridNilKeyset(t *testing.T) {
	_, err := OpenHybrid(nil, []byte("test"))
	if err == nil {
		t.Fatal("expected error for nil keyset")
	}
}

func TestOpenHybridNilPtr(t *testing.T) {
	_, err := OpenHybrid(&KeySetHandle{ptr: nil}, []byte("test"))
	if err == nil {
		t.Fatal("expected error for nil ptr keyset")
	}
}

func TestOpenHybridEmptyEnvelope(t *testing.T) {
	ks, _, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet() failed: %v", err)
	}
	defer FreeKeySet(ks)

	_, err = OpenHybrid(ks, []byte{})
	if err == nil {
		t.Fatal("expected error for empty envelope")
	}
}

func TestOpenHybridGarbageInput(t *testing.T) {
	ks, _, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet() failed: %v", err)
	}
	defer FreeKeySet(ks)

	_, err = OpenHybrid(ks, []byte("not-a-valid-envelope-data-here"))
	if err == nil {
		t.Fatal("expected error for garbage input")
	}
}

func TestGenerateLocalNilKeyset(t *testing.T) {
	_, err := GenerateLocal(nil, "/tmp/test.enc")
	if err == nil {
		t.Fatal("expected error for nil keyset")
	}
}

func TestGenerateLocalNilPtr(t *testing.T) {
	_, err := GenerateLocal(&KeySetHandle{ptr: nil}, "/tmp/test.enc")
	if err == nil {
		t.Fatal("expected error for nil ptr keyset")
	}
}

func TestLoadLocalNilKeyset(t *testing.T) {
	_, err := LoadLocal(nil, "/tmp/test.enc")
	if err == nil {
		t.Fatal("expected error for nil keyset")
	}
}

func TestLoadLocalNilPtr(t *testing.T) {
	_, err := LoadLocal(&KeySetHandle{ptr: nil}, "/tmp/test.enc")
	if err == nil {
		t.Fatal("expected error for nil ptr keyset")
	}
}

func TestLoadLocalBadPath(t *testing.T) {
	ks, _, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet() failed: %v", err)
	}
	defer FreeKeySet(ks)

	_, err = LoadLocal(ks, "/nonexistent/path/envelope.enc")
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestGetPublicKeysNilPtr(t *testing.T) {
	_, err := GetPublicKeys(&KeySetHandle{ptr: nil})
	if err == nil {
		t.Error("expected error for nil ptr handle")
	}
}

func TestExportAgeIdentityNilPtr(t *testing.T) {
	_, err := ExportAgeIdentity(&KeySetHandle{ptr: nil})
	if err == nil {
		t.Error("expected error for nil ptr handle")
	}
}

// ── Wrong-state tests: trigger Rust error paths via state machine ────

func TestStatusWrongState(t *testing.T) {
	configJSON := `{"provider_type":"mock","provider_config":{}}`
	h, err := New(configJSON)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer h.Free()

	// Status from Uninitialized state should fail
	_, err = h.Status()
	if err == nil {
		t.Error("expected error calling Status from Uninitialized state")
	}
}

func TestInitDoubleInit(t *testing.T) {
	configJSON := `{"provider_type":"mock","provider_config":{}}`
	kmsJSON := `{"provider_type":"mock"}`
	h, err := New(configJSON)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer h.Free()

	_, err = h.Init(kmsJSON)
	if err != nil {
		t.Fatalf("first Init() failed: %v", err)
	}

	// Second Init from Initialized state should fail
	_, err = h.Init(kmsJSON)
	if err == nil {
		t.Error("expected error for double init")
	}
}

func TestVerifyWrongState(t *testing.T) {
	configJSON := `{"provider_type":"mock","provider_config":{}}`
	kmsJSON := `{"provider_type":"mock"}`
	h, err := New(configJSON)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer h.Free()

	// Verify from Uninitialized state should fail
	_, err = h.Verify(kmsJSON)
	if err == nil {
		t.Error("expected error calling Verify from Uninitialized state")
	}
}

func TestBeginRotationWrongState(t *testing.T) {
	configJSON := `{"provider_type":"mock","provider_config":{}}`
	h, err := New(configJSON)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer h.Free()

	// BeginRotation from Uninitialized state should fail
	err = h.BeginRotation()
	if err == nil {
		t.Error("expected error calling BeginRotation from Uninitialized state")
	}
}

func TestCompleteRotationWrongState(t *testing.T) {
	configJSON := `{"provider_type":"mock","provider_config":{}}`
	kmsJSON := `{"provider_type":"mock"}`
	h, err := New(configJSON)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer h.Free()

	// CompleteRotation from Uninitialized state should fail
	_, err = h.CompleteRotation(kmsJSON, "secret", "ns", "key")
	if err == nil {
		t.Error("expected error calling CompleteRotation from Uninitialized state")
	}
}

func TestInjectSecretWrongState(t *testing.T) {
	configJSON := `{"provider_type":"mock","provider_config":{}}`
	h, err := New(configJSON)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer h.Free()

	// InjectSecret from Uninitialized state should fail
	err = h.InjectSecret("test", "ns", "key")
	if err == nil {
		t.Error("expected error calling InjectSecret from Uninitialized state")
	}
}

// ── FFI error path tests (bad input triggers Rust errors) ───────────

// TestGenerateLocalBadDir triggers the Rust-side error path when the
// target directory does not exist (file creation fails).
func TestGenerateLocalBadDir(t *testing.T) {
	ks, _, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet() failed: %v", err)
	}
	defer FreeKeySet(ks)

	_, err = GenerateLocal(ks, "/nonexistent/dir/envelope.enc")
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

// TestSealOpenHybridLargePayload verifies roundtrip with a non-trivial payload.
func TestSealOpenHybridLargePayload(t *testing.T) {
	ks, _, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet() failed: %v", err)
	}
	defer FreeKeySet(ks)

	plaintext := make([]byte, 64*1024) // 64 KiB
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	sealed, err := SealHybrid(ks, plaintext)
	if err != nil {
		t.Fatalf("SealHybrid(large) failed: %v", err)
	}
	if len(sealed) < len(plaintext) {
		t.Errorf("sealed size %d < plaintext size %d", len(sealed), len(plaintext))
	}

	opened, err := OpenHybrid(ks, sealed)
	if err != nil {
		t.Fatalf("OpenHybrid(large) failed: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Error("large payload roundtrip mismatch")
	}
}

// TestGenerateLocalRoundtripWithReload creates a local KMS, frees it,
// then loads from the same envelope with the same keyset.
func TestGenerateLocalRoundtripWithReload(t *testing.T) {
	ks, _, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet() failed: %v", err)
	}
	defer FreeKeySet(ks)

	dir := t.TempDir()
	envPath := filepath.Join(dir, "master.enc")

	// Generate
	lk, err := GenerateLocal(ks, envPath)
	if err != nil {
		t.Fatalf("GenerateLocal() failed: %v", err)
	}
	FreeLocalKms(lk)

	// Reload with same keyset
	lk2, err := LoadLocal(ks, envPath)
	if err != nil {
		t.Fatalf("LoadLocal() failed: %v", err)
	}
	FreeLocalKms(lk2)
}
