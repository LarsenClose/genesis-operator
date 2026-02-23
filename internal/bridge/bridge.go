// Package bridge provides a Go interface to the genesis-core Rust library
// via CGO FFI. All cryptographic operations (key generation, envelope
// encrypt/decrypt, K8s secret injection) happen in Rust memory. Go never
// touches raw key material.
//
// The bridge uses opaque handles and JSON-serialised data exchange.
// Every Handle must be freed with Free() when no longer needed.
package bridge

/*
#cgo LDFLAGS: -L${SRCDIR}/../../genesis-core/target/release -lgenesis_core -lm -lpthread
#cgo darwin LDFLAGS: -framework Security -framework CoreFoundation
#cgo linux LDFLAGS: -ldl
#include "genesis_core.h"
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"unsafe"
)

// State mirrors the Rust StateTag enum.
type State int

const (
	StateUninitialized State = 0
	StateInitialized   State = 1
	StateBootstrapping State = 2
	StateActive        State = 3
	StateRotating      State = 4
	StateDegraded      State = 5
)

func (s State) String() string {
	names := [...]string{
		"Uninitialized", "Initialized", "Bootstrapping",
		"Active", "Rotating", "Degraded",
	}
	if int(s) >= 0 && int(s) < len(names) {
		return names[s]
	}
	return fmt.Sprintf("Unknown(%d)", s)
}

// Handle wraps an opaque pointer to the Rust genesis-core state machine.
// It must be freed with Free() when no longer needed.
type Handle struct {
	inner C.struct_GenesisHandle
}

// State returns the current state of the genesis-core state machine.
func (h *Handle) State() State {
	return State(h.inner.state)
}

// PublicArtifacts contains the public outputs of a genesis init or rotation.
type PublicArtifacts struct {
	PublicKey          string `json:"public_key"`
	EnvelopeCiphertext []byte `json:"envelope_ciphertext"`
	SopsConfig         string `json:"sops_config"`
}

// VerifyResult contains the outcome of a genesis verify operation.
type VerifyResult struct {
	PublicKeyMatches bool   `json:"public_key_matches"`
	PublicKey        string `json:"public_key"`
}

// GenesisStatus contains a status snapshot from an Active genesis instance.
type GenesisStatus struct {
	State       string  `json:"state"`
	PublicKey   *string `json:"public_key"`
	HasEnvelope bool    `json:"has_envelope"`
}

// resultToError converts a C GenesisResult into a Go Handle and error.
// It frees error_message and data_json C strings as needed.
// On error, the returned Handle may be non-nil if the Rust side preserved
// the handle for recovery (callers should update h.inner from it).
func resultToError(r C.struct_GenesisResult) (*Handle, string, error) {
	if r.success {
		h := &Handle{inner: r.handle}
		var dataJSON string
		if r.data_json != nil {
			dataJSON = C.GoString(r.data_json)
			C.genesis_free_string(r.data_json)
		}
		return h, dataJSON, nil
	}

	var msg string
	if r.error_message != nil {
		msg = C.GoString(r.error_message)
		C.genesis_free_string(r.error_message)
	} else {
		msg = fmt.Sprintf("genesis error code %d", r.error_code)
	}
	// Free data_json even on error (should be nil, but defensive)
	if r.data_json != nil {
		C.genesis_free_string(r.data_json)
	}

	// If the error result carries a non-null handle, return it
	// so callers can recover the state machine.
	var h *Handle
	if r.handle.ptr != nil {
		h = &Handle{inner: r.handle}
	}
	return h, "", fmt.Errorf("genesis: %s", msg)
}

// New creates a new genesis-core instance in the Uninitialized state.
// configJSON should be a JSON object with provider_type and provider_config.
func New(configJSON string) (*Handle, error) {
	cConfig := C.CString(configJSON)
	defer C.free(unsafe.Pointer(cConfig))

	result := C.genesis_new(cConfig, nil)
	h, _, err := resultToError(result)
	return h, err
}

// NewWithAudit creates a new genesis-core instance with an audit callback.
// The callback receives JSON-encoded audit events.
// NOTE: The callback function pointer must remain valid for the lifetime
// of the handle. In practice, use a package-level Go function.
func NewWithAudit(configJSON string, callback C.AuditCallback) (*Handle, error) {
	cConfig := C.CString(configJSON)
	defer C.free(unsafe.Pointer(cConfig))

	result := C.genesis_new(cConfig, callback)
	h, _, err := resultToError(result)
	return h, err
}

// recoverHandle updates h.inner from a result handle if available.
// This ensures the handle is not left dangling after an error.
func (h *Handle) recoverHandle(newH *Handle) {
	if newH != nil {
		h.inner = newH.inner
	}
}

// Init generates a new age keypair, KMS-encrypts the private key, and
// transitions from Uninitialized to Initialized.
// Returns the public artifacts (public key, encrypted envelope, SOPS config).
func (h *Handle) Init(kmsConfigJSON string) (*PublicArtifacts, error) {
	cKms := C.CString(kmsConfigJSON)
	defer C.free(unsafe.Pointer(cKms))

	result := C.genesis_init(h.inner, cKms)
	newH, dataJSON, err := resultToError(result)
	h.recoverHandle(newH)
	if err != nil {
		return nil, err
	}

	var artifacts PublicArtifacts
	if err := json.Unmarshal([]byte(dataJSON), &artifacts); err != nil {
		return nil, fmt.Errorf("genesis: failed to parse artifacts: %w", err)
	}
	return &artifacts, nil
}

// Load loads a previously-persisted keypair and transitions from
// Uninitialized to Initialized.
func (h *Handle) Load(publicKey string, envelopeCiphertext []byte) error {
	cPub := C.CString(publicKey)
	defer C.free(unsafe.Pointer(cPub))

	var envPtr *C.uint8_t
	if len(envelopeCiphertext) > 0 {
		envPtr = (*C.uint8_t)(unsafe.Pointer(&envelopeCiphertext[0]))
	}

	result := C.genesis_load(
		h.inner,
		cPub,
		envPtr,
		C.uintptr_t(len(envelopeCiphertext)),
	)
	newH, _, err := resultToError(result)
	h.recoverHandle(newH)
	return err
}

// Verify decrypts the envelope, re-derives the public key, and checks
// that it matches the stored public key.
func (h *Handle) Verify(kmsConfigJSON string) (*VerifyResult, error) {
	cKms := C.CString(kmsConfigJSON)
	defer C.free(unsafe.Pointer(cKms))

	result := C.genesis_verify(h.inner, cKms, nil)
	newH, dataJSON, err := resultToError(result)
	h.recoverHandle(newH)
	if err != nil {
		return nil, err
	}

	var vr VerifyResult
	if err := json.Unmarshal([]byte(dataJSON), &vr); err != nil {
		return nil, fmt.Errorf("genesis: failed to parse verify result: %w", err)
	}
	return &vr, nil
}

// BeginBootstrap decrypts the envelope and transitions from Initialized
// to Bootstrapping. The decrypted key material is held in Rust memory.
func (h *Handle) BeginBootstrap(kmsConfigJSON string) error {
	cKms := C.CString(kmsConfigJSON)
	defer C.free(unsafe.Pointer(cKms))

	result := C.genesis_begin_bootstrap(h.inner, cKms)
	newH, _, err := resultToError(result)
	h.recoverHandle(newH)
	return err
}

// InjectSecret writes the decrypted key material into a Kubernetes secret
// and transitions from Bootstrapping to Active.
func (h *Handle) InjectSecret(name, namespace, key string) error {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	cNs := C.CString(namespace)
	defer C.free(unsafe.Pointer(cNs))
	cKey := C.CString(key)
	defer C.free(unsafe.Pointer(cKey))

	result := C.genesis_inject_secret(h.inner, cName, cNs, cKey)
	newH, _, err := resultToError(result)
	h.recoverHandle(newH)
	return err
}

// Status returns a status snapshot from an Active genesis instance.
func (h *Handle) Status() (*GenesisStatus, error) {
	result := C.genesis_status(h.inner, nil)
	newH, dataJSON, err := resultToError(result)
	h.recoverHandle(newH)
	if err != nil {
		return nil, err
	}

	var gs GenesisStatus
	if err := json.Unmarshal([]byte(dataJSON), &gs); err != nil {
		return nil, fmt.Errorf("genesis: failed to parse status: %w", err)
	}
	return &gs, nil
}

// BeginRotation transitions from Active to Rotating.
func (h *Handle) BeginRotation() error {
	result := C.genesis_begin_rotation(h.inner)
	newH, _, err := resultToError(result)
	h.recoverHandle(newH)
	return err
}

// CompleteRotation generates a new keypair, re-encrypts, injects the new
// secret, and transitions from Rotating back to Active.
func (h *Handle) CompleteRotation(kmsConfigJSON, secretName, secretNamespace, secretKey string) (*PublicArtifacts, error) {
	cKms := C.CString(kmsConfigJSON)
	defer C.free(unsafe.Pointer(cKms))
	cName := C.CString(secretName)
	defer C.free(unsafe.Pointer(cName))
	cNs := C.CString(secretNamespace)
	defer C.free(unsafe.Pointer(cNs))
	cKey := C.CString(secretKey)
	defer C.free(unsafe.Pointer(cKey))

	result := C.genesis_complete_rotation(h.inner, cKms, cName, cNs, cKey)
	newH, dataJSON, err := resultToError(result)
	h.recoverHandle(newH)
	if err != nil {
		return nil, err
	}

	var artifacts PublicArtifacts
	if err := json.Unmarshal([]byte(dataJSON), &artifacts); err != nil {
		return nil, fmt.Errorf("genesis: failed to parse rotation artifacts: %w", err)
	}
	return &artifacts, nil
}

// Free releases all resources associated with the handle.
// After Free(), the handle must not be used.
func (h *Handle) Free() {
	if h != nil {
		C.genesis_free(h.inner)
		h.inner.ptr = nil
	}
}

